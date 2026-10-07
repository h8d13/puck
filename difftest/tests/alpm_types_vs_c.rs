// alpm-types versions and relations against the C (alpm_pkg_vercmp,
// alpm_dep_from_string), on the inputs alpm-types parses
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::str::FromStr;

use alpm_core::deps::{DepMod, Depend};
use alpm_types::{
	FullVersion, OptionalDependency, PackageRelation, Version,
	VersionComparison, VersionRequirement,
};
use difftest::{Rng, c_dep_from_string, c_vercmp, iters};

const DIGITS: &[u8] = b"0012399";
const PKGVER: &[u8] = b"0012399abzAZ.._+~";
// what the C special-cases, for the noise inputs
const NOISE: &[u8] = b"0012399abzAZ..--::_~+ ";

fn pick(rng: &mut Rng, s: &[u8]) -> char {
	char::from(s[rng.below(s.len())])
}

fn run(rng: &mut Rng, s: &[u8], max: usize) -> String {
	(0..rng.below(max)).map(|_| pick(rng, s)).collect()
}

// [epoch:]pkgver[-pkgrel], each part sometimes empty or odd
fn version(rng: &mut Rng) -> String {
	if rng.below(5) == 0 {
		return run(rng, NOISE, 12);
	}
	let mut v = String::new();
	if rng.below(3) == 0 {
		v += &run(rng, DIGITS, 3);
		v.push(':');
	}
	v.push(pick(rng, b"0123abZ"));
	v += &run(rng, PKGVER, 8);
	if rng.below(3) != 0 {
		v.push('-');
		v += &run(rng, DIGITS, 3);
		if rng.below(4) == 0 {
			v.push('.');
			v += &run(rng, DIGITS, 2);
		}
	}
	v
}

// small edit of a, so pairs share prefixes
fn mutate(rng: &mut Rng, a: &str) -> String {
	let mut b: Vec<char> = a.chars().collect();
	let c = pick(rng, NOISE);
	let i = rng.below(b.len() + 1);
	match rng.below(3) {
		0 => b.insert(i, c),
		1 if i < b.len() => b[i] = c,
		_ if i < b.len() => {
			b.remove(i);
		}
		_ => b.push(c),
	}
	b.into_iter().collect()
}

fn sign(o: Ordering) -> i32 {
	o as i32
}

// compared inputs, agreeing ones and disagreements by class with the
// first examples
#[derive(Default, Debug)]
struct Tally {
	compared: usize,
	agree: usize,
	classes: BTreeMap<&'static str, (usize, Vec<String>)>,
}

impl Tally {
	fn add(&mut self, classes: &[&'static str], what: impl Fn() -> String) {
		self.compared += 1;
		if classes.is_empty() {
			self.agree += 1;
		}
		for &k in classes {
			let (n, ex) = self.classes.entry(k).or_default();
			*n += 1;
			if ex.len() < 3 {
				ex.push(what());
			}
		}
	}

	// min: compared per 1000 inputs, agreeing per 1000 compared. no
	// class but the known ones
	fn finish(
		&self,
		what: &str,
		n: usize,
		min: (usize, usize),
		known: &[&str],
	) {
		println!(
			"{what}: {} of {} agree ({n} inputs)",
			self.agree, self.compared
		);
		for (k, (count, ex)) in &self.classes {
			println!("  {k}: {count}, e.g. {ex:?}");
			assert!(known.contains(k), "{what}: {k} {ex:?}");
		}
		assert!(
			self.compared * 1000 >= n * min.0,
			"{what}: {} compared",
			self.compared
		);
		assert!(
			self.agree * 1000 >= self.compared * min.1,
			"{what}: {} agree",
			self.agree
		);
	}
}

const EPOCH0: &str = "explicit epoch 0";
const PKGREL1: &str = "pkgrel on one side";

// why Version/FullVersion order a against b unlike the C: "0:" counts as
// an epoch (the C treats it as none), a pkgrel present on one side only
// counts (the C skips the release then)
fn vercmp_classes(
	(ea, eb): (Option<usize>, Option<usize>),
	(ra, rb): (bool, bool),
	same: bool,
) -> Vec<&'static str> {
	if same {
		return Vec::new();
	}
	let mut out = Vec::new();
	if matches!((ea, eb), (Some(0), None) | (None, Some(0))) {
		out.push(EPOCH0);
	}
	if ra != rb {
		out.push(PKGREL1);
	}
	if out.is_empty() {
		out.push("other");
	}
	out
}

fn epoch(e: Option<alpm_types::Epoch>) -> Option<usize> {
	e.map(|e| e.0)
}

#[test]
fn vercmp_against_c() {
	let mut rng = Rng::new(0xa1b2);
	let n = iters();
	let (mut generic, mut full) = (Tally::default(), Tally::default());
	for _ in 0..n {
		let a = version(&mut rng);
		let b = if rng.below(2) == 0 {
			mutate(&mut rng, &a)
		} else {
			version(&mut rng)
		};
		let c = c_vercmp(Some(a.as_bytes()), Some(b.as_bytes()));
		let (sa, sb) = (&a, &b);
		let show = |r: i32| {
			move || format!("{sa:?} {sb:?} c={c} alpm={r}")
		};
		if let (Ok(x), Ok(y)) =
			(Version::from_str(&a), Version::from_str(&b))
		{
			let r = i32::from(Version::vercmp(&x, &y));
			let rel = (x.pkgrel.is_some(), y.pkgrel.is_some());
			let k = vercmp_classes(
				(epoch(x.epoch), epoch(y.epoch)),
				rel,
				r == c,
			);
			generic.add(&k, show(r));
		}
		if let (Ok(x), Ok(y)) =
			(FullVersion::from_str(&a), FullVersion::from_str(&b))
		{
			let r = sign(x.cmp(&y));
			let k = vercmp_classes(
				(epoch(x.epoch), epoch(y.epoch)),
				(true, true),
				r == c,
			);
			full.add(&k, show(r));
		}
	}
	// measured with 200000: Version 985 per 1000 agree, FullVersion 988
	generic.finish("Version", n, (260, 980), &[EPOCH0, PKGREL1]);
	full.finish("FullVersion", n, (80, 980), &[EPOCH0]);
}

#[test]
fn vercmp_pinned() {
	// (a, b, C, Version, FullVersion where both parse as one)
	let cases: &[(&str, &str, i32, i32, Option<i32>)] = &[
		("1.0", "1.0", 0, 0, None),
		("1.0a", "1.0", -1, -1, None),
		("1.0-2", "1.0-10", -1, -1, Some(-1)),
		("1:0.1", "2.0", 1, 1, None),
		// '~' is a plain separator in the C, no pre-release
		("1.0~rc1-1", "1.0-1", 1, 1, Some(1)),
		("01.0", "1.0", 0, 0, None),
		// EPOCH0
		("0:1.0", "1.0", 0, 1, None),
		("0:1.0-1", "1.0-1", 0, 1, Some(1)),
		("0:2", "1:1", -1, -1, None),
		// PKGREL1
		("1.0", "1.0-1", 0, -1, None),
		("1.0-5", "1.0", 0, 1, None),
	];
	for &(a, b, c, g, f) in cases {
		let what = format!("{a:?} {b:?}");
		assert_eq!(
			c_vercmp(Some(a.as_bytes()), Some(b.as_bytes())),
			c,
			"{what}"
		);
		let (x, y) = (
			Version::from_str(a).unwrap(),
			Version::from_str(b).unwrap(),
		);
		assert_eq!(i32::from(Version::vercmp(&x, &y)), g, "{what}");
		let full = FullVersion::from_str(a)
			.and_then(|x| Ok((x, FullVersion::from_str(b)?)));
		assert_eq!(
			full.ok().map(|(x, y)| sign(x.cmp(&y))),
			f,
			"{what}"
		);
	}
}

const NAME: &[u8] = b"ab09@._+-";
const OPS: [&str; 10] = ["", "=", "<", ">", "<=", ">=", "==", "=<", "<>", ">>"];

// name[op version][: description], or noise
fn relation(rng: &mut Rng) -> String {
	if rng.below(5) == 0 {
		return run(rng, b"ab09@._+-<>=: 1", 12);
	}
	let mut s = String::new();
	s.push(pick(rng, b"ab09@_+"));
	s += &run(rng, NAME, 6);
	let op = OPS[rng.below(OPS.len())];
	s += op;
	if !op.is_empty() || rng.below(4) == 0 {
		s += &version(rng);
	}
	if rng.below(2) == 0 {
		s += [": ", ":", ": ", " : "][rng.below(4)];
		s += &run(rng, b"ab :\t", 6);
	}
	s
}

fn depmod(c: Option<&VersionComparison>) -> DepMod {
	match c {
		None => DepMod::Any,
		Some(VersionComparison::Equal) => DepMod::Eq,
		Some(VersionComparison::GreaterOrEqual) => DepMod::Ge,
		Some(VersionComparison::LessOrEqual) => DepMod::Le,
		Some(VersionComparison::Greater) => DepMod::Gt,
		Some(VersionComparison::Less) => DepMod::Lt,
	}
}

const VERSION_TEXT: &str = "version text normalized";
const DESC_TRIM: &str = "description trimmed";
const DESC_DELIM: &str = "':' + whitespace starts the description";

// the C fields against the ALPM ones: name, operator, version as
// alpm-types prints it (what be_local/be_sync pass on), description
type Fields = (Vec<u8>, DepMod, Option<Vec<u8>>, Option<Vec<u8>>);

// ALPM starts the description at ':' + any whitespace, the C at the
// first ": "
fn earlier_delimiter(s: &str) -> bool {
	let b = s.as_bytes();
	let alpm = b
		.windows(2)
		.position(|w| w[0] == b':' && w[1].is_ascii_whitespace());
	alpm.is_some() && alpm != s.find(": ")
}

fn relation_classes(s: &str, c: &Depend, r: &Fields) -> Vec<&'static str> {
	let c_fields =
		(c.name.clone(), c.depmod, c.version.clone(), c.desc.clone());
	if &c_fields == r {
		return Vec::new();
	}
	if earlier_delimiter(s) {
		return vec![DESC_DELIM];
	}
	let mut out = Vec::new();
	if c.name != r.0 {
		out.push("name");
	}
	if c.depmod != r.1 {
		out.push("operator");
	}
	match (&c.version, &r.2) {
		(a, b) if a == b => {}
		// same version, other text: leading zeros of the pkgrel
		(Some(a), Some(b)) if c_vercmp(Some(a), Some(b)) == 0 => {
			out.push(VERSION_TEXT);
		}
		_ => out.push("version"),
	}
	if c.desc != r.3 {
		let trimmed = c.desc.as_deref().map(<[u8]>::trim_ascii);
		let trimmed = trimmed.filter(|d| !d.is_empty());
		if c.desc.is_some() && trimmed == r.3.as_deref() {
			out.push(DESC_TRIM);
		} else {
			out.push("description");
		}
	}
	out
}

fn requirement(r: Option<&VersionRequirement>) -> (DepMod, Option<Vec<u8>>) {
	(
		depmod(r.map(|q| &q.comparison)),
		r.map(|q| q.version.to_string().into_bytes()),
	)
}

fn show(d: &Depend) -> String {
	let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
	format!(
		"{:?} {:?} {:?} {:?}",
		s(&d.name),
		d.depmod,
		d.version.as_deref().map(s),
		d.desc.as_deref().map(s)
	)
}

#[test]
fn relation_against_c() {
	let mut rng = Rng::new(0x4e1a);
	let n = iters();
	let (mut rel, mut opt) = (Tally::default(), Tally::default());
	for _ in 0..n {
		let s = relation(&mut rng);
		let c = c_dep_from_string(s.as_bytes());
		if let Ok(r) = PackageRelation::from_str(&s) {
			let (m, v) =
				requirement(r.version_requirement.as_ref());
			let got = (r.name.to_string().into_bytes(), m, v, None);
			let k = relation_classes(&s, &c, &got);
			rel.add(&k, || {
				format!("{s:?} c={} alpm={r}", show(&c))
			});
		}
		if let Ok(r) = OptionalDependency::from_str(&s) {
			let (m, v) =
				requirement(r.version_requirement().as_ref());
			let desc =
				r.description().clone().map(String::into_bytes);
			let got =
				(r.name().to_string().into_bytes(), m, v, desc);
			let k = relation_classes(&s, &c, &got);
			opt.add(&k, || {
				format!("{s:?} c={} alpm={r:?}", show(&c))
			});
		}
	}
	// measured with 200000: PackageRelation 958 per 1000 agree,
	// OptionalDependency 748
	rel.finish("PackageRelation", n, (130, 950), &[VERSION_TEXT]);
	opt.finish(
		"OptionalDependency",
		n,
		(200, 740),
		&[VERSION_TEXT, DESC_TRIM, DESC_DELIM],
	);
}

#[test]
fn relation_pinned() {
	// (input, C name/op/version/desc, ALPM display)
	type CDep = (
		&'static str,
		DepMod,
		Option<&'static str>,
		Option<&'static str>,
	);
	let cases: &[(&str, CDep, &str)] = &[
		("foo", ("foo", DepMod::Any, None, None), "foo"),
		(
			"foo>=1.0-1",
			("foo", DepMod::Ge, Some("1.0-1"), None),
			"foo>=1.0-1",
		),
		(
			"foo: bar",
			("foo", DepMod::Any, None, Some("bar")),
			"foo: bar",
		),
		// VERSION_TEXT
		(
			"foo=1.0-01",
			("foo", DepMod::Eq, Some("1.0-01"), None),
			"foo=1.0-1",
		),
		(
			"foo<2-1.01",
			("foo", DepMod::Lt, Some("2-1.01"), None),
			"foo<2-1.1",
		),
		// DESC_TRIM
		(
			"foo:  bar ",
			("foo", DepMod::Any, None, Some(" bar ")),
			"foo: bar",
		),
		("foo: ", ("foo", DepMod::Any, None, Some("")), "foo"),
		// DESC_DELIM
		(
			"foo:\tbar",
			("foo:\tbar", DepMod::Any, None, None),
			"foo: bar",
		),
		(
			"foo>1:\tbar",
			("foo", DepMod::Gt, Some("1:\tbar"), None),
			"foo>1: bar",
		),
	];
	for &(s, (name, depmod, version, desc), alpm) in cases {
		let c = c_dep_from_string(s.as_bytes());
		let want = Depend {
			name: name.as_bytes().to_vec(),
			version: version.map(|v| v.as_bytes().to_vec()),
			desc: desc.map(|d| d.as_bytes().to_vec()),
			name_hash: c.name_hash,
			depmod,
		};
		assert_eq!(c, want, "{s:?}");
		let r = OptionalDependency::from_str(s).unwrap();
		assert_eq!(r.to_string(), alpm, "{s:?}");
	}
}
