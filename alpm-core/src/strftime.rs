// glibc 2.44's strftime (time/strftime_l.c, its era and alternative
// digit lookups time/era.c, time/alt_digit.c) on a locale read by
// setlocale.rs. pacman formats dates with strftime(buf, 50, "%c",
// localtime(&t)): %c is the locale's d_t_fmt, which can hold any
// conversion, so all of them are here with glibc's flags (_ - 0 ^ #),
// field widths and E/O modifiers.
//
// translation:
// - the C writes into the buffer as it goes and returns 0 when a piece
//   does not fit (what fit stays, without its nul); None here, the
//   caller knows what its buffer held
// - a subformat (%c, %x, %EY, ...) is measured first like the C's, so it
//   goes in whole or not at all
// - %s is mktime(tm): tm comes from localtime here, so it is the second
//   tm was made from
// - %Z with an empty tm_zone takes tzname after tzset() in the C; the
//   names a zone gives come from the same data, the port keeps it empty

use crate::setlocale::{
	ABALTMON_1, ABDAY_1, ABMON_1, ALTMON_1, AM_STR, D_FMT, D_T_FMT, DAY_1,
	ERA_D_FMT, ERA_D_T_FMT, ERA_T_FMT, Era, Locale, MON_1, PM_STR, T_FMT,
	T_FMT_AMPM, era_date_le,
};
use crate::util::until_nul;

// struct tm as localtime fills it, and the second it came from (%s)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tm {
	pub sec: i32,
	pub min: i32,
	pub hour: i32,
	pub mday: i32,
	// 0..11
	pub mon: i32,
	// years since 1900
	pub year: i32,
	// 0 is Sunday
	pub wday: i32,
	pub yday: i32,
	pub isdst: i32,
	pub gmtoff: i64,
	pub zone: Vec<u8>,
	pub t: i64,
}

impl Tm {
	// the broken-down time of t at gmtoff seconds east of UTC (__offtime),
	// None where tm_year leaves int
	pub fn at(t: i64, gmtoff: i64, isdst: bool, zone: &[u8]) -> Option<Tm> {
		let local = t.checked_add(gmtoff)?;
		let days = local.div_euclid(86_400);
		let rem = local.rem_euclid(86_400);
		// civil_from_days (H. Hinnant), March-based years
		let z = days + 719_468;
		let era = z.div_euclid(146_097);
		let doe = z.rem_euclid(146_097);
		let yoe =
			(doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
		let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
		let mp = (5 * doy + 2) / 153;
		let mday = doy - (153 * mp + 2) / 5 + 1;
		let mon = if mp < 10 { mp + 2 } else { mp - 10 };
		let y = yoe + era * 400 + i64::from(mon <= 1);
		let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
		const BEFORE: [i64; 12] =
			[0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
		let yday = BEFORE[mon as usize] + mday - 1
			+ i64::from(leap && mon > 1);
		Some(Tm {
			sec: (rem % 60) as i32,
			min: (rem / 60 % 60) as i32,
			hour: (rem / 3600) as i32,
			mday: mday as i32,
			mon: mon as i32,
			year: i32::try_from(y - 1900).ok()?,
			// 1970-01-01 was a Thursday
			wday: (days + 4).rem_euclid(7) as i32,
			yday: yday as i32,
			isdst: i32::from(isdst),
			gmtoff,
			zone: zone.to_vec(),
			t,
		})
	}
}

// the C's p and i: output so far (none when only measuring) and its
// length against maxsize
struct Out {
	buf: Option<Vec<u8>>,
	i: usize,
	max: usize,
}

// the per-conversion state of __strftime_internal
#[derive(Clone, Copy)]
struct Spec {
	pad: u8,
	width: i32,
	upcase: bool,
	lowcase: bool,
}

impl Out {
	fn room(&self) -> usize {
		self.max - self.i
	}

	// add(n, f): f's n bytes after padding to width, '0' or ' '. the C
	// does this in int
	fn put(
		&mut self,
		s: &Spec,
		n: usize,
		f: impl FnOnce(&mut Vec<u8>),
	) -> Option<()> {
		let n = n as i32;
		let delta = s.width.wrapping_sub(n);
		let incr = n.wrapping_add(delta.max(0));
		if incr as isize as usize >= self.room() {
			return None;
		}
		if let Some(b) = &mut self.buf {
			let fill = if s.pad == b'0' { b'0' } else { b' ' };
			b.extend(std::iter::repeat_n(
				fill,
				delta.max(0) as usize,
			));
			f(b);
		}
		self.i += incr as usize;
		Some(())
	}

	fn add(&mut self, s: &Spec, bytes: &[u8]) -> Option<()> {
		self.put(s, bytes.len(), |b| b.extend_from_slice(bytes))
	}

	// cpy: add with the case flags applied per byte
	fn cpy(&mut self, s: &Spec, bytes: &[u8], loc: &Locale) -> Option<()> {
		if !(s.lowcase || s.upcase) || self.buf.is_none() {
			return self.add(s, bytes);
		}
		let mapped: Vec<u8> = bytes
			.iter()
			.map(|&c| match s.lowcase {
				true => loc.tolower(c),
				false => loc.toupper(c),
			})
			.collect();
		self.add(s, &mapped)
	}
}

fn is_leap(y: i32) -> bool {
	y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

// iso_week_days: days since the first day of yday's ISO week 1
fn iso_week_days(yday: i32, wday: i32) -> i32 {
	let big_enough_multiple_of_7 = (366 / 7 + 2) * 7;
	yday - (yday - wday + 4 + big_enough_multiple_of_7) % 7 + 4 - 1
}

// _nl_get_era_entry: the first era holding the date, either way round
fn era_of<'a>(loc: &'a Locale, tm: &Tm) -> Option<&'a Era> {
	let d = [tm.year, tm.mon, tm.mday];
	loc.time.eras.iter().find(|e| {
		(era_date_le(e.start, d) && era_date_le(d, e.stop))
			|| (era_date_le(e.stop, d) && era_date_le(d, e.start))
	})
}

// _nl_get_alt_digit
fn alt_digit(loc: &Locale, n: i32) -> Option<&[u8]> {
	let digits = &loc.time.alt_digits;
	let i = usize::try_from(n).ok().filter(|&i| i < 100)?;
	digits.get(i).map(Vec::as_slice)
}

// strftime(s, max, fmt, tm): None where the C returns 0
pub fn strftime(
	max: usize,
	fmt: &[u8],
	tm: &Tm,
	loc: &Locale,
) -> Option<Vec<u8>> {
	let mut out = Out {
		buf: Some(Vec::new()),
		i: 0,
		max,
	};
	internal(&mut out, until_nul(fmt), tm, 0, loc)?;
	out.buf
}

// __strftime_internal
fn internal(
	out: &mut Out,
	fmt: &[u8],
	tm: &Tm,
	yr_spec: u8,
	loc: &Locale,
) -> Option<()> {
	// %EY's flag reaches %Ey in its era format, and in the C every later
	// conversion of this format too (the parameter is reassigned)
	let mut yr_spec = yr_spec;
	let lt = &loc.time;
	let hour12 = match tm.hour {
		h if h > 12 => h - 12,
		0 => 12,
		h => h,
	};
	let wday = usize::try_from(tm.wday).ok().filter(|&w| w < 7);
	let mon = usize::try_from(tm.mon).ok().filter(|&m| m < 12);
	let name = |base: usize, i: Option<usize>| -> &[u8] {
		i.map_or(b"?", |i| lt.item(base + i))
	};
	let mut f = 0;
	while f < fmt.len() {
		let plain = Spec {
			pad: 0,
			width: -1,
			upcase: false,
			lowcase: false,
		};
		if fmt[f] != b'%' {
			out.add(&plain, &fmt[f..=f])?;
			f += 1;
			continue;
		}
		let start = f;
		let mut s = plain;
		let mut change_case = false;
		loop {
			f += 1;
			match fmt.get(f) {
				Some(&c @ (b'_' | b'-' | b'0')) => s.pad = c,
				Some(b'^') => s.upcase = true,
				Some(b'#') => change_case = true,
				_ => break,
			}
		}
		if fmt.get(f).is_some_and(u8::is_ascii_digit) {
			s.width = 0;
			while let Some(&c) =
				fmt.get(f).filter(|c| c.is_ascii_digit())
			{
				let d = i32::from(c - b'0');
				s.width = match s
					.width
					.checked_mul(10)
					.and_then(|w| w.checked_add(d))
				{
					Some(w) => w,
					None => i32::MAX,
				};
				f += 1;
			}
		}
		let modifier = match fmt.get(f) {
			Some(&c @ (b'E' | b'O')) => {
				f += 1;
				c
			}
			_ => 0,
		};
		let c = fmt.get(f).copied();
		// what the conversion does: bytes, a number or a subformat
		enum Act<'a> {
			Bytes(&'a [u8]),
			Nothing,
			Seconds(Vec<u8>),
			Number(i32, i32),
			SpaceNumber(i32, i32),
			Sub(&'a [u8]),
			Bad,
		}
		let case_up = |s: &mut Spec, change: bool| {
			if change {
				s.upcase = true;
				s.lowcase = false;
			}
		};
		let act = match c {
			Some(b'%') if modifier == 0 => Act::Bytes(b"%"),
			Some(b'a') if modifier == 0 => {
				case_up(&mut s, change_case);
				Act::Bytes(name(ABDAY_1, wday))
			}
			Some(b'A') if modifier == 0 => {
				case_up(&mut s, change_case);
				Act::Bytes(name(DAY_1, wday))
			}
			Some(b'b' | b'h') if modifier != b'E' => {
				case_up(&mut s, change_case);
				match modifier {
					b'O' => Act::Bytes(name(
						ABALTMON_1, mon,
					)),
					_ => Act::Bytes(name(ABMON_1, mon)),
				}
			}
			Some(b'B') if modifier != b'E' => {
				case_up(&mut s, change_case);
				match modifier {
					b'O' => Act::Bytes(name(ALTMON_1, mon)),
					_ => Act::Bytes(name(MON_1, mon)),
				}
			}
			Some(b'c') if modifier != b'O' => {
				let e = lt.item(ERA_D_T_FMT);
				match modifier == b'E' && !e.is_empty() {
					true => Act::Sub(e),
					false => Act::Sub(lt.item(D_T_FMT)),
				}
			}
			Some(b'C') => match era_of(loc, tm)
				.filter(|_| modifier == b'E')
			{
				Some(e) => Act::Bytes(&e.name),
				None => {
					let year = tm.year.wrapping_add(1900);
					let v = year / 100
						- i32::from(year % 100 < 0);
					Act::Number(1, v)
				}
			},
			Some(b'x') if modifier != b'O' => {
				let e = lt.item(ERA_D_FMT);
				match modifier == b'E' && !e.is_empty() {
					true => Act::Sub(e),
					false => Act::Sub(lt.item(D_FMT)),
				}
			}
			Some(b'D') if modifier == 0 => Act::Sub(b"%m/%d/%y"),
			Some(b'd') if modifier != b'E' => {
				Act::Number(2, tm.mday)
			}
			Some(b'e') if modifier != b'E' => {
				Act::SpaceNumber(2, tm.mday)
			}
			Some(b'F') if modifier == 0 => Act::Sub(b"%Y-%m-%d"),
			Some(b'H') if modifier != b'E' => {
				Act::Number(2, tm.hour)
			}
			Some(b'I') if modifier != b'E' => {
				Act::Number(2, hour12)
			}
			Some(b'k') if modifier != b'E' => {
				Act::SpaceNumber(2, tm.hour)
			}
			Some(b'l') if modifier != b'E' => {
				Act::SpaceNumber(2, hour12)
			}
			Some(b'j') if modifier != b'E' => {
				Act::Number(3, tm.yday.wrapping_add(1))
			}
			Some(b'M') if modifier != b'E' => {
				Act::Number(2, tm.min)
			}
			Some(b'm') if modifier != b'E' => {
				Act::Number(2, tm.mon.wrapping_add(1))
			}
			Some(b'n') => Act::Bytes(b"\n"),
			Some(b'P' | b'p') => {
				// lower case wins over '^' in cpy
				if c == Some(b'P') || change_case {
					s.lowcase = true;
				}
				let item = if tm.hour > 11 {
					PM_STR
				} else {
					AM_STR
				};
				Act::Bytes(lt.item(item))
			}
			Some(b'R') => Act::Sub(b"%H:%M"),
			Some(b'r') => {
				let r = lt.item(T_FMT_AMPM);
				Act::Sub(if r.is_empty() {
					b"%I:%M:%S %p"
				} else {
					r
				})
			}
			Some(b'S') if modifier != b'E' => {
				Act::Number(2, tm.sec)
			}
			Some(b's') => {
				Act::Seconds(tm.t.to_string().into_bytes())
			}
			Some(b'X') if modifier != b'O' => {
				let e = lt.item(ERA_T_FMT);
				match modifier == b'E' && !e.is_empty() {
					true => Act::Sub(e),
					false => Act::Sub(lt.item(T_FMT)),
				}
			}
			Some(b'T') => Act::Sub(b"%H:%M:%S"),
			Some(b't') => Act::Bytes(b"\t"),
			Some(b'u') => Act::Number(1, (tm.wday - 1 + 7) % 7 + 1),
			Some(b'U') if modifier != b'E' => {
				Act::Number(2, (tm.yday - tm.wday + 7) / 7)
			}
			Some(v @ (b'V' | b'g' | b'G')) if modifier != b'E' => {
				let mut year = tm.year.wrapping_add(1900);
				let mut days = iso_week_days(tm.yday, tm.wday);
				if days < 0 {
					// the previous year's last ISO week
					year -= 1;
					let len =
						365 + i32::from(is_leap(year));
					days = iso_week_days(
						tm.yday + len,
						tm.wday,
					);
				} else {
					let len =
						365 + i32::from(is_leap(year));
					let d = iso_week_days(
						tm.yday - len,
						tm.wday,
					);
					if d >= 0 {
						year += 1;
						days = d;
					}
				}
				match v {
					b'g' => Act::Number(
						2,
						(year % 100 + 100) % 100,
					),
					b'G' => Act::Number(1, year),
					_ => Act::Number(2, days / 7 + 1),
				}
			}
			Some(b'W') if modifier != b'E' => Act::Number(
				2,
				(tm.yday - (tm.wday - 1 + 7) % 7 + 7) / 7,
			),
			Some(b'w') if modifier != b'E' => {
				Act::Number(1, tm.wday)
			}
			Some(b'Y') => match era_of(loc, tm)
				.filter(|_| modifier == b'E')
			{
				Some(e) => {
					if s.pad != 0 {
						yr_spec = s.pad;
					}
					Act::Sub(&e.format)
				}
				None if modifier == b'O' => Act::Bad,
				None => Act::Number(
					1,
					tm.year.wrapping_add(1900),
				),
			},
			Some(b'y') => match era_of(loc, tm)
				.filter(|_| modifier == b'E')
			{
				Some(e) => {
					let delta = tm
						.year
						.wrapping_sub(e.start[0]);
					if yr_spec != 0 {
						s.pad = yr_spec;
					}
					let v = delta.wrapping_mul(
						e.absolute_direction,
					);
					Act::Number(2, e.offset.wrapping_add(v))
				}
				None => Act::Number(
					2,
					(tm.year % 100 + 100) % 100,
				),
			},
			Some(b'Z') => {
				if change_case {
					s.upcase = false;
					s.lowcase = true;
				}
				Act::Bytes(&tm.zone)
			}
			Some(b'z') if tm.isdst < 0 => Act::Nothing,
			Some(b'z') => {
				let mut diff = tm.gmtoff as i32;
				let sign: &[u8] = if diff < 0 {
					diff = diff.wrapping_neg();
					b"-"
				} else {
					b"+"
				};
				out.add(&s, sign)?;
				diff /= 60;
				Act::Number(4, (diff / 60) * 100 + diff % 60)
			}
			_ => Act::Bad,
		};
		match act {
			Act::Bytes(b) => out.cpy(&s, b, loc)?,
			Act::Nothing => {}
			Act::Seconds(b) => number_out(out, &mut s, &b, 1, loc)?,
			Act::Number(d, v) => {
				number(out, &mut s, modifier, d, v, loc)?
			}
			Act::SpaceNumber(d, v) => {
				if s.pad != b'0' && s.pad != b'-' {
					s.pad = b'_';
				}
				number(out, &mut s, modifier, d, v, loc)?
			}
			Act::Sub(sub) => {
				// measured and written in one go: the C's second
				// call is given room for what the first measured
				let mut inner = Out {
					buf: out.buf
						.as_ref()
						.map(|_| Vec::new()),
					i: 0,
					max: usize::MAX,
				};
				internal(
					&mut inner,
					until_nul(sub),
					tm,
					yr_spec,
					loc,
				)?;
				let text = inner.buf.unwrap_or_default();
				let before =
					out.buf.as_ref().map_or(0, Vec::len);
				let plain = Spec {
					upcase: false,
					lowcase: false,
					..s
				};
				out.put(&plain, inner.i, |b| {
					b.extend_from_slice(&text)
				})?;
				if s.upcase
					&& let Some(b) = &mut out.buf
				{
					for x in &mut b[before..] {
						*x = loc.toupper(*x);
					}
				}
			}
			Act::Bad => {
				// the format from its '%' up to here; a '%' at the
				// end of the format is that '%' and its flags
				let end = if c.is_none() { f } else { f + 1 };
				out.cpy(&s, &fmt[start..end], loc)?;
				f = end;
				continue;
			}
		}
		f += 1;
	}
	Some(())
}

// do_number: an alternative digit for O when the locale has one, else
// decimal digits
fn number(
	out: &mut Out,
	s: &mut Spec,
	modifier: u8,
	d: i32,
	v: i32,
	loc: &Locale,
) -> Option<()> {
	let digits = d.max(s.width);
	if modifier == b'O'
		&& v >= 0 && let Some(alt) =
		alt_digit(loc, v).filter(|a| !a.is_empty())
	{
		return out.cpy(s, alt, loc);
	}
	let text = if v < 0 {
		format!("-{}", (v as i64).unsigned_abs())
	} else {
		v.to_string()
	};
	number_out(out, s, text.as_bytes(), digits, loc)
}

// do_number_sign_and_padding: '_' pads with spaces before the number,
// otherwise zeros go between the sign and the digits; '-' pads nothing
// here (add still pads to the width)
fn number_out(
	out: &mut Out,
	s: &mut Spec,
	text: &[u8],
	digits: i32,
	loc: &Locale,
) -> Option<()> {
	let mut text = text;
	if s.pad != b'-' {
		let padding = digits.wrapping_sub(text.len() as i32);
		if padding > 0 {
			if s.pad == b'_' {
				if padding as usize >= out.room() {
					return None;
				}
				if let Some(b) = &mut out.buf {
					b.extend(std::iter::repeat_n(
						b' ',
						padding as usize,
					));
				}
				out.i += padding as usize;
				s.width = if s.width > padding {
					s.width - padding
				} else {
					0
				};
			} else {
				if digits as usize >= out.room() {
					return None;
				}
				if text.first() == Some(&b'-') {
					text = &text[1..];
					if let Some(b) = &mut out.buf {
						b.push(b'-');
					}
					out.i += 1;
				}
				if let Some(b) = &mut out.buf {
					b.extend(std::iter::repeat_n(
						b'0',
						padding as usize,
					));
				}
				out.i += padding as usize;
				s.width = 0;
			}
		}
	}
	out.cpy(s, text, loc)
}
