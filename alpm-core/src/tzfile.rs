// the local zone as glibc's localtime sees it (glibc 2.44 time/tzset.c
// tzset_internal, __tzset_parse_tz, __tz_compute; time/tzfile.c
// __tzfile_read, __tzfile_default, __tzfile_compute): tm_isdst, tm_zone
// and tm_gmtoff of a second. strftime's %Z needs the zone abbreviation,
// which time's local offset does not give; log.rs takes tm_gmtoff
// from here too.
//
// TZ unset is /etc/localtime, empty is "Universal", a leading ':' is
// dropped. the value is a TZif file first (relative to TZDIR or
// /usr/share/zoneinfo), else a POSIX rule string; with no file and no
// TZ (or TZ naming /etc/localtime) the zone is UTC. a rule string with
// a DST name but no rules takes posixrules' transitions.
//
// translation:
// - the file is read once, here with std's reads of the same sizes
// - a TZif zone name runs to its nul or the end of the names (the C
//   reads on into the next data)
// - the transition search is a binary search; the C's guess-then-scan
//   gives the same index on sorted transitions
// - a failed month rule (M0 or M13) is not computed: the C indexes past
//   its month table there; the port takes January
// - the C caches each rule's change per year and starts unparsed rules
//   at year 0, so a process whose first lookup falls in year 0 sees a
//   change at second 0; the port always computes it
// - leap seconds (right/ zones) are leap_correct and leap_hit, which the
//   C applies to the broken-down time (strftime::Tm::local)

use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

use crate::util::until_nul;

const TZDEFAULT: &[u8] = b"/etc/localtime";
const TZDIR: &[u8] = b"/usr/share/zoneinfo";
const TZDEFRULES: &[u8] = b"posixrules";
const SECSPERDAY: i64 = 86_400;

// what localtime(3) sets besides the date
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Local {
	pub isdst: bool,
	// tm_zone
	pub zone: Vec<u8>,
	// tm_gmtoff
	pub gmtoff: i64,
	// seconds the leap second records take off the local time, and the
	// leap seconds t sits on (tm_sec 60 and on)
	pub leap_correct: i64,
	pub leap_hit: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleKind {
	// Jn: 1..365, February 29 never counted
	J1,
	// n: 0..365
	J0,
	// Mm.n.d
	M,
}

// tz_rule
#[derive(Clone, Debug)]
struct Rule {
	name: Vec<u8>,
	kind: RuleKind,
	m: u16,
	n: u16,
	d: u16,
	secs: i32,
	offset: i32,
}

impl Rule {
	// the memset state __tzset_parse_tz starts from
	fn zero() -> Rule {
		Rule {
			name: Vec::new(),
			kind: RuleKind::J0,
			m: 0,
			n: 0,
			d: 0,
			secs: 0,
			offset: 0,
		}
	}
}

// __mon_yday: days before each month, normal and leap years
const MON_YDAY: [[u16; 13]; 2] = [
	[0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365],
	[0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366],
];

fn is_leap(y: i64) -> bool {
	y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

// compute_change: the second the rule takes effect in year. the C
// starts every year before 1971 at 1970-01-01
fn compute_change(rule: &Rule, year: i64) -> i64 {
	let mut t = if year > 1970 {
		((year - 1970) * 365 + ((year - 1) / 4 - 1970 / 4)
			- ((year - 1) / 100 - 1970 / 100)
			+ ((year - 1) / 400 - 1970 / 400))
			* SECSPERDAY
	} else {
		0
	};
	let leap = usize::from(is_leap(year));
	match rule.kind {
		RuleKind::J1 => {
			t += (i64::from(rule.d) - 1) * SECSPERDAY;
			if rule.d >= 60 && leap == 1 {
				t += SECSPERDAY;
			}
		}
		RuleKind::J0 => t += i64::from(rule.d) * SECSPERDAY,
		RuleKind::M => {
			let m = usize::from(rule.m).clamp(1, 12);
			let (before, end) =
				(MON_YDAY[leap][m - 1], MON_YDAY[leap][m]);
			t += i64::from(before) * SECSPERDAY;
			// Zeller's congruence: weekday of the month's first day
			let m1 = (m as i64 + 9) % 12 + 1;
			let yy0 = if m <= 2 { year - 1 } else { year };
			let (yy1, yy2) = (yy0 / 100, yy0 % 100);
			let mut dow = ((26 * m1 - 2) / 10
				+ 1 + yy2 + yy2 / 4 + yy1 / 4
				- 2 * yy1) % 7;
			if dow < 0 {
				dow += 7;
			}
			let mut d = i64::from(rule.d) - dow;
			if d < 0 {
				d += 7;
			}
			for _ in 1..rule.n {
				if d + 7 >= i64::from(end - before) {
					break;
				}
				d += 7;
			}
			t += d * SECSPERDAY;
		}
	}
	t - i64::from(rule.offset) + i64::from(rule.secs)
}

// a POSIX TZ string: standard and DST rules
#[derive(Clone, Debug)]
struct Posix {
	rules: [Rule; 2],
}

impl Posix {
	fn utc() -> Posix {
		let mut r = Rule::zero();
		r.name = b"UTC".to_vec();
		Posix {
			rules: [r.clone(), r],
		}
	}

	// __tz_compute, the year being t's in UTC
	fn local(&self, t: i64) -> Option<Local> {
		let year = utc_year(t)?;
		let c0 = compute_change(&self.rules[0], year);
		let c1 = compute_change(&self.rules[1], year);
		// southern zones: DST runs over the new year
		let isdst = if c0 > c1 {
			t < c1 || t >= c0
		} else {
			t >= c0 && t < c1
		};
		let r = &self.rules[usize::from(isdst)];
		Some(Local {
			isdst,
			zone: r.name.clone(),
			gmtoff: i64::from(r.offset),
			leap_correct: 0,
			leap_hit: 0,
		})
	}
}

// __offtime's year of t in UTC, None where tm_year leaves int
fn utc_year(t: i64) -> Option<i64> {
	let days = t.div_euclid(SECSPERDAY);
	// civil_from_days (H. Hinnant)
	let z = days + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z.rem_euclid(146_097);
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let y = yoe + era * 400 + i64::from(mp >= 10);
	i32::try_from(y - 1900).ok()?;
	Some(y)
}

// sscanf's %hu at s: white space, a sign, digits (strtoul, saturated,
// then cut to unsigned short). the value and the bytes consumed
fn scan_hu(s: &[u8]) -> Option<(u16, usize)> {
	let ws =
		s.iter().take_while(|c| {
			matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
		})
		.count();
	let mut i = ws;
	let neg = match s.get(i) {
		Some(b'-') => {
			i += 1;
			true
		}
		Some(b'+') => {
			i += 1;
			false
		}
		_ => false,
	};
	let digits = s[i..].iter().take_while(|c| c.is_ascii_digit()).count();
	if digits == 0 {
		return None;
	}
	let mut v: u64 = 0;
	for &c in &s[i..i + digits] {
		v = v.saturating_mul(10).saturating_add(u64::from(c - b'0'));
	}
	if neg {
		v = v.wrapping_neg();
	}
	Some((v as u16, i + digits))
}

// sscanf(s, "%hu%n:%hu%n:%hu%n"): hh, mm, ss as far as they parse and
// the bytes up to the last one. None if hh does not parse
fn scan_hms(s: &[u8]) -> Option<([u16; 3], usize)> {
	let mut v = [0; 3];
	let mut consumed = 0;
	for (i, slot) in v.iter_mut().enumerate() {
		if i > 0 && s.get(consumed) != Some(&b':') {
			break;
		}
		let at = consumed + usize::from(i > 0);
		let Some((n, len)) = scan_hu(&s[at..]) else {
			if i == 0 {
				return None;
			}
			break;
		};
		*slot = n;
		consumed = at + len;
	}
	Some((v, consumed))
}

// what parse_* reads: the string and where it is
struct Parser<'a> {
	s: &'a [u8],
	at: usize,
	rules: [Rule; 2],
}

impl Parser<'_> {
	fn peek(&self) -> Option<u8> {
		self.s.get(self.at).copied()
	}

	// parse_tzname: 3+ letters, or <3+ of [A-Za-z0-9+-]>
	fn tzname(&mut self, which: usize) -> bool {
		let rest = &self.s[self.at..];
		let alpha = rest
			.iter()
			.take_while(|c| c.is_ascii_alphabetic())
			.count();
		if alpha >= 3 {
			self.rules[which].name = rest[..alpha].to_vec();
			self.at += alpha;
			return true;
		}
		if rest.first() != Some(&b'<') {
			return false;
		}
		let ok = |c: &u8| {
			c.is_ascii_alphanumeric() || *c == b'+' || *c == b'-'
		};
		let len = rest[1..].iter().take_while(|c| ok(c)).count();
		if rest.get(1 + len) != Some(&b'>') || len < 3 {
			return false;
		}
		self.rules[which].name = rest[1..1 + len].to_vec();
		self.at += len + 2;
		true
	}

	// parse_offset: [+-]hh[:mm[:ss]], west positive in the string
	fn offset(&mut self, which: usize) -> bool {
		let c = self.peek();
		let digit = c.is_some_and(|c| c.is_ascii_digit());
		if which == 0 && !(c == Some(b'+') || c == Some(b'-') || digit)
		{
			return false;
		}
		let mut sign = -1;
		if c == Some(b'-') || c == Some(b'+') {
			sign = if c == Some(b'-') { 1 } else { -1 };
			self.at += 1;
		}
		match scan_hms(&self.s[self.at..]) {
			Some(([hh, mm, ss], n)) => {
				let off = u32::from(ss.min(59))
					+ u32::from(mm.min(59)) * 60
					+ u32::from(hh.min(24)) * 3600;
				self.rules[which].offset = sign * off as i32;
				self.at += n;
				true
			}
			// standard time defaults to 0, DST to an hour later
			None if which == 0 => {
				self.rules[0].offset = 0;
				false
			}
			None => {
				self.rules[1].offset =
					self.rules[0].offset + 3600;
				true
			}
		}
	}

	// parse_rule: ",date[/time]"; what parsed stays set when it fails
	fn rule(&mut self, which: usize) -> bool {
		let mut r = self.rules[which].clone();
		let ok = self.rule_into(&mut r, which);
		self.rules[which] = r;
		ok
	}

	fn rule_into(&mut self, r: &mut Rule, which: usize) -> bool {
		if self.peek() == Some(b',') {
			self.at += 1;
		}
		let c = self.peek();
		if c == Some(b'J') || c.is_some_and(|c| c.is_ascii_digit()) {
			r.kind = if c == Some(b'J') {
				RuleKind::J1
			} else {
				RuleKind::J0
			};
			if r.kind == RuleKind::J1 {
				self.at += 1;
				if !self.s
					.get(self.at)
					.is_some_and(u8::is_ascii_digit)
				{
					return false;
				}
			}
			// strtoul: digits only here, saturated
			let rest = &self.s[self.at..];
			let n = rest
				.iter()
				.take_while(|c| c.is_ascii_digit())
				.count();
			let d = rest[..n].iter().fold(0u64, |v, &c| {
				v.saturating_mul(10)
					.saturating_add(u64::from(c - b'0'))
			});
			if d > 365 || (r.kind == RuleKind::J1 && d == 0) {
				return false;
			}
			r.d = d as u16;
			self.at += n;
		} else if c == Some(b'M') {
			r.kind = RuleKind::M;
			// sscanf(tz, "M%hu.%hu.%hu%n"): fields stored as parsed
			let mut at = self.at + 1;
			let mut fields = 0;
			for i in 0..3 {
				if i > 0 {
					if self.s.get(at) != Some(&b'.') {
						break;
					}
					at += 1;
				}
				let Some((v, n)) = scan_hu(&self.s[at..])
				else {
					break;
				};
				match i {
					0 => r.m = v,
					1 => r.n = v,
					_ => r.d = v,
				}
				at += n;
				fields += 1;
			}
			if fields != 3
				|| !(1..=12).contains(&r.m) || !(1..=5)
				.contains(&r.n) || r.d > 6
			{
				return false;
			}
			self.at = at;
		} else if c.is_none() {
			// the US rules of the Energy Policy Act of 2005
			r.kind = RuleKind::M;
			(r.m, r.n, r.d) =
				if which == 0 { (3, 2, 0) } else { (11, 1, 0) };
		} else {
			return false;
		}
		match self.peek() {
			None | Some(b',') => r.secs = 2 * 3600,
			Some(b'/') => {
				self.at += 1;
				if self.peek().is_none() {
					return false;
				}
				let neg = self.peek() == Some(b'-');
				self.at += usize::from(neg);
				let (v, n) = scan_hms(&self.s[self.at..])
					.unwrap_or(([2, 0, 0], 0));
				self.at += n;
				let secs = i32::from(v[0]) * 3600
					+ i32::from(v[1]) * 60 + i32::from(
					v[2],
				);
				r.secs = if neg { -secs } else { secs };
			}
			_ => return false,
		}
		true
	}
}

// what __tzset_parse_tz makes of a TZ string
enum Parsed {
	Posix(Posix),
	// a DST name without rules: posixrules with these names, offsets
	Default(Rule, Rule),
}

fn parse_tz(s: &[u8]) -> Parsed {
	let mut p = Parser {
		s,
		at: 0,
		rules: [Rule::zero(), Rule::zero()],
	};
	if p.tzname(0) && p.offset(0) {
		if p.peek().is_some() {
			if p.tzname(1) {
				p.offset(1);
				let rest = &p.s[p.at..];
				if rest.is_empty() || rest == b"," {
					let [std, dst] = p.rules.clone();
					return Parsed::Default(std, dst);
				}
			}
			if p.rule(0) {
				p.rule(1);
			}
		} else {
			p.rules[1].name = p.rules[0].name.clone();
			p.rules[1].offset = p.rules[0].offset;
		}
	}
	Parsed::Posix(Posix { rules: p.rules })
}

// struct ttinfo
#[derive(Clone, Debug)]
struct TType {
	offset: i32,
	isdst: bool,
	idx: usize,
	isstd: bool,
	isgmt: bool,
}

// a TZif file as __tzfile_read leaves it
#[derive(Clone, Debug)]
struct TzFile {
	transitions: Vec<i64>,
	type_idxs: Vec<u8>,
	types: Vec<TType>,
	names: Vec<u8>,
	// transition, correction
	leaps: Vec<(i64, i64)>,
	tzspec: Option<Vec<u8>>,
	// rule_stdoff after the read
	rule_stdoff: i64,
}

fn be32(b: &[u8]) -> u32 {
	u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn read_n(r: &mut impl Read, n: usize) -> Option<Vec<u8>> {
	let mut buf = vec![0; n];
	r.read_exact(&mut buf).ok()?;
	Some(buf)
}

// __tzfile_read: the version 2+ (64-bit) data when there is one, the
// counts and indices checked like the C
fn tzfile_read(
	file: &[u8],
	getenv: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Option<TzFile> {
	if file.is_empty() {
		return None;
	}
	let path = if file[0] == b'/' {
		file.to_vec()
	} else {
		let dir = getenv("TZDIR")
			.filter(|d| !d.is_empty())
			.unwrap_or_else(|| TZDIR.to_vec());
		[&dir[..], b"/", file].concat()
	};
	let f = File::open(OsStr::from_bytes(&path)).ok()?;
	let size = f.metadata().ok()?.len();
	let mut r = BufReader::new(f);
	let mut width = 4;
	let mut pos: u64 = 0;
	let counts = loop {
		let head = read_n(&mut r, 44)?;
		pos += 44;
		if &head[..4] != b"TZif" {
			return None;
		}
		let c: Vec<usize> = (0..6)
			.map(|i| be32(&head[20 + 4 * i..]) as usize)
			.collect();
		// ttisutcnt, ttisstdcnt, leapcnt, timecnt, typecnt, charcnt
		let (isgmt, isstd, leaps, trans, types, chars) =
			(c[0], c[1], c[2], c[3], c[4], c[5]);
		if isstd > types || isgmt > types {
			return None;
		}
		if width == 4 && head[4] != 0 {
			width = 8;
			let skip = trans * 5
				+ types * 6 + chars + leaps * 8
				+ isstd + isgmt;
			r.seek_relative(skip as i64).ok()?;
			pos += skip as u64;
			continue;
		}
		break (isgmt, isstd, leaps, trans, types, chars);
	};
	let (num_isgmt, num_isstd, num_leaps, num_trans, num_types, chars) =
		counts;
	// the TZ string after the data, 64-bit files only
	let mut tzspec_len = 0;
	if width == 8 {
		let rem = size.checked_sub(pos)? as usize;
		let fixed = num_trans * 9 + num_types * 6 + chars;
		let mut l = rem.checked_sub(fixed)?;
		l = l.checked_sub(num_leaps * 12)?;
		l = l.checked_sub(num_isstd)?;
		if l == 0 || l - 1 < num_isgmt {
			return None;
		}
		l -= num_isgmt + 1;
		if l == 0 {
			return None;
		}
		tzspec_len = l;
	}
	let raw = read_n(&mut r, num_trans * width)?;
	let transitions: Vec<i64> = raw
		.chunks_exact(width)
		.map(|b| match width {
			4 => i64::from(be32(b) as i32),
			_ => i64::from_be_bytes([
				b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
			]),
		})
		.collect();
	let type_idxs = read_n(&mut r, num_trans)?;
	if type_idxs.iter().any(|&t| usize::from(t) >= num_types) {
		return None;
	}
	let mut types = Vec::with_capacity(num_types);
	for _ in 0..num_types {
		let b = read_n(&mut r, 6)?;
		if b[4] > 1 || usize::from(b[5]) > chars {
			return None;
		}
		types.push(TType {
			offset: be32(&b) as i32,
			isdst: b[4] == 1,
			idx: usize::from(b[5]),
			isstd: false,
			isgmt: false,
		});
	}
	let names = read_n(&mut r, chars)?;
	let raw = read_n(&mut r, num_leaps * (width + 4))?;
	let leaps = raw
		.chunks_exact(width + 4)
		.map(|b| {
			let at = match width {
				4 => i64::from(be32(b) as i32),
				_ => i64::from_be_bytes(
					b[..8].try_into().unwrap(),
				),
			};
			(at, i64::from(be32(&b[width..]) as i32))
		})
		.collect();
	for t in types.iter_mut().take(num_isstd) {
		t.isstd = read_n(&mut r, 1)?[0] != 0;
	}
	for t in types.iter_mut().take(num_isgmt) {
		t.isgmt = read_n(&mut r, 1)?[0] != 0;
	}
	let mut tzspec = None;
	if tzspec_len > 0 {
		let nl = read_n(&mut r, 1);
		if nl.as_deref() == Some(b"\n")
			&& let Some(s) = read_n(&mut r, tzspec_len - 1)
		{
			tzspec = Some(until_nul(&s).to_vec());
		}
	}
	let tzspec = tzspec.filter(|s| !s.is_empty());
	// no types: the C reads types[0] all the same
	if types.is_empty() {
		return None;
	}
	// rule_stdoff: the last standard type transitioned to
	let mut stdoff = 0;
	if transitions.is_empty() {
		stdoff = i64::from(types[0].offset);
	} else if let Some(&i) = type_idxs
		.iter()
		.rev()
		.find(|&&i| !types[usize::from(i)].isdst)
	{
		stdoff = i64::from(types[usize::from(i)].offset);
	}
	Some(TzFile {
		transitions,
		type_idxs,
		types,
		names,
		leaps,
		tzspec,
		rule_stdoff: stdoff,
	})
}

impl TzFile {
	fn name(&self, idx: usize) -> Vec<u8> {
		until_nul(self.names.get(idx..).unwrap_or_default()).to_vec()
	}

	fn of_type(&self, i: usize) -> Local {
		let t = &self.types[i];
		Local {
			isdst: t.isdst,
			zone: self.name(t.idx),
			gmtoff: i64::from(t.offset),
			leap_correct: 0,
			leap_hit: 0,
		}
	}

	// __tzfile_compute for localtime, the zone then the leap seconds
	fn local(&self, t: i64) -> Option<Local> {
		let mut l = self.zone_at(t)?;
		let Some(i) = self.leaps.iter().rposition(|&(at, _)| t >= at)
		else {
			return Some(l);
		};
		l.leap_correct = self.leaps[i].1;
		let before = if i == 0 { 0 } else { self.leaps[i - 1].1 };
		if t == self.leaps[i].0 && self.leaps[i].1 > before {
			l.leap_hit = 1;
			let mut i = i;
			while i > 0
				&& self.leaps[i].0 == self.leaps[i - 1].0 + 1
				&& self.leaps[i].1 == self.leaps[i - 1].1 + 1
			{
				l.leap_hit += 1;
				i -= 1;
			}
		}
		Some(l)
	}

	fn zone_at(&self, t: i64) -> Option<Local> {
		let n = self.transitions.len();
		if n == 0 || t < self.transitions[0] {
			// the first standard type, or the first of all
			let i = self
				.types
				.iter()
				.position(|ty| !ty.isdst)
				.unwrap_or(0);
			return Some(self.of_type(i));
		}
		if t >= self.transitions[n - 1] {
			let last = usize::from(self.type_idxs[n - 1]);
			let Some(spec) = &self.tzspec else {
				return Some(self.of_type(last));
			};
			// the footer's own names and offsets, also under
			// posixrules (the C's override test never holds)
			let Parsed::Posix(p) = parse_tz(spec) else {
				return Some(self.of_type(last));
			};
			return p.local(t).or_else(|| Some(self.of_type(last)));
		}
		let i = self.transitions.partition_point(|&x| x <= t);
		Some(self.of_type(usize::from(self.type_idxs[i - 1])))
	}

	// __tzfile_default: posixrules' transitions moved to the user's
	// offsets with the C's signs, names and offsets of types 0 and 1
	// replaced. localtime reruns this on every call with rule_dstoff
	// left at the previous run's dstoff, so DST ends stay where
	// posixrules has them; the process's first localtime (and every
	// localtime_r) has 0 there, which is not modelled
	fn with_default(mut self, std: &Rule, dst: &Rule) -> Option<TzFile> {
		if self.types.len() < 2 {
			return None;
		}
		let stdoff = i64::from(std.offset);
		let mut isdst = false;
		for i in 0..self.transitions.len() {
			let ty = self.types[usize::from(self.type_idxs[i])]
				.clone();
			self.type_idxs[i] = u8::from(ty.isdst);
			// UTC transitions stay; so do DST ends, corrected by
			// dstoff - rule_dstoff, the previous run's dstoff
			if !ty.isgmt && !(isdst && !ty.isstd) {
				self.transitions[i] +=
					stdoff - self.rule_stdoff;
			}
			isdst = ty.isdst;
		}
		self.types.truncate(2);
		self.names =
			[&std.name[..], b"\0", &dst.name[..], b"\0"].concat();
		self.types[0] = TType {
			offset: std.offset,
			isdst: false,
			idx: 0,
			isstd: self.types[0].isstd,
			isgmt: self.types[0].isgmt,
		};
		self.types[1] = TType {
			offset: dst.offset,
			isdst: true,
			idx: std.name.len() + 1,
			isstd: self.types[1].isstd,
			isgmt: self.types[1].isgmt,
		};
		self.rule_stdoff = stdoff;
		Some(self)
	}
}

// the zone of a process: TZ read once like localtime_r
#[derive(Clone, Debug)]
pub struct Zone(Kind);

#[derive(Clone, Debug)]
enum Kind {
	File(TzFile),
	Posix(Posix),
}

impl Zone {
	// tzset_internal
	pub fn from_env(getenv: &dyn Fn(&str) -> Option<Vec<u8>>) -> Zone {
		let mut tz = getenv("TZ");
		if tz.as_deref() == Some(b"") {
			tz = Some(b"Universal".to_vec());
		}
		if let Some(t) = &mut tz
			&& t.first() == Some(&b':')
		{
			t.remove(0);
		}
		let tz = tz.unwrap_or_else(|| TZDEFAULT.to_vec());
		if let Some(f) = tzfile_read(&tz, getenv) {
			return Zone(Kind::File(f));
		}
		if tz.is_empty() || tz == TZDEFAULT {
			return Zone(Kind::Posix(Posix::utc()));
		}
		match parse_tz(&tz) {
			Parsed::Posix(p) => Zone(Kind::Posix(p)),
			Parsed::Default(std, dst) => {
				let file = tzfile_read(TZDEFRULES, getenv)
					.and_then(|f| {
						f.with_default(&std, &dst)
					});
				match file {
					Some(f) => Zone(Kind::File(f)),
					// no posixrules: the names with the US rules
					None => {
						let mut p = Parser {
							s: b"",
							at: 0,
							rules: [std, dst],
						};
						p.rule(0);
						p.rule(1);
						Zone(Kind::Posix(Posix {
							rules: p.rules,
						}))
					}
				}
			}
		}
	}

	// localtime(&t)'s zone fields. a file zone checks only the local
	// year (past its footer a UTC year out of int falls back on the
	// last transition), a rule zone the UTC year first
	pub fn local(&self, t: i64) -> Option<Local> {
		let l = match &self.0 {
			Kind::File(f) => f.local(t),
			Kind::Posix(p) => p.local(t),
		}?;
		utc_year(t.checked_add(l.gmtoff - l.leap_correct)?)?;
		Some(l)
	}
}

fn process_env(name: &str) -> Option<Vec<u8>> {
	std::env::var_os(name).map(|v| v.into_encoded_bytes())
}

// the process's zone, read on first use
pub fn current() -> &'static Zone {
	static ZONE: OnceLock<Zone> = OnceLock::new();
	ZONE.get_or_init(|| Zone::from_env(&process_env))
}
