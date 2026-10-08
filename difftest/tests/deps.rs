// alpm_core::deps against deps.c: alpm_dep_from_string,
// alpm_dep_compute_string, dep_vercmp via _alpm_depcmp_provides,
// _alpm_depcmp(_literal) and alpm_find_satisfier on mirror packages
use alpm_core::deps::{
	DepMod, Depend, dep_compute_string, dep_from_string, depcmp,
	depcmp_literal, depcmp_provides, find_satisfier,
};
use alpm_core::package::Package;
use alpm_core::util::hash_sdbm;
use difftest::{
	Rng, c_dep_compute_string, c_dep_compute_string_null,
	c_dep_compute_string_raw, c_dep_from_string, c_dep_from_string_null,
	c_depcmp, c_depcmp_literal, c_depcmp_provides, c_find_satisfier, iters,
};

// operators, ": " pieces, epoch ':', a byte >= 0x80
const DEP_ALPHABET: &[u8] = b"ab1.-<<>>==:: \x80";
const VER_ALPHABET: &[u8] = b"0119a.-:";
const MODS: [DepMod; 6] = [
	DepMod::Any,
	DepMod::Eq,
	DepMod::Ge,
	DepMod::Le,
	DepMod::Gt,
	DepMod::Lt,
];

fn show(s: &[u8]) -> String {
	String::from_utf8_lossy(s).into_owned()
}

fn check_parse(s: &[u8]) {
	let c = c_dep_from_string(s);
	assert_eq!(c, dep_from_string(s), "{:?}", show(s));
	// round trip through both printers
	assert_eq!(
		c_dep_compute_string(&c),
		dep_compute_string(&c),
		"{:?}",
		show(s)
	);
}

#[test]
fn parse_edges() {
	for s in [
		&b""[..],
		b"a",
		b"a=",
		b"a<",
		b"a<=",
		b"a>",
		b"a>=",
		b"<=1",
		b"a=1:2",
		b"a>=1:2-3: why",
		b"a: ",
		b": ",
		b"a<: x",
		b"a<=: x",
		b"a=>1",
		b"a=<1",
		b"a>=1<2",
		b"a:b=1",
		b"a: b<=1",
		b"a==1",
		b"a<<=1",
		b"a: b: c",
	] {
		check_parse(s);
	}
}

#[test]
fn parse_fuzz() {
	let mut rng = Rng::new(0xde95);
	for _ in 0..iters() {
		let s = rng.bytes(DEP_ALPHABET, 14);
		check_parse(&s);
	}
}

fn opt_bytes(rng: &mut Rng, alphabet: &[u8], max: usize) -> Option<Vec<u8>> {
	(rng.below(4) != 0).then(|| rng.bytes(alphabet, max))
}

fn random_dep(rng: &mut Rng) -> Depend {
	let name = rng.bytes(b"ab", 2);
	let name_hash = hash_sdbm(&name);
	Depend {
		name: name.into(),
		version: opt_bytes(rng, VER_ALPHABET, 6).map(Box::from),
		desc: opt_bytes(rng, b"x: ", 4).map(Box::from),
		name_hash,
		depmod: MODS[rng.below(MODS.len())],
	}
}

// hand-built structs: Any with a version, versioned mods without one
#[test]
fn compute_fuzz() {
	let mut rng = Rng::new(0xc0de);
	for _ in 0..iters() {
		let d = random_dep(&mut rng);
		assert_eq!(
			c_dep_compute_string(&d),
			dep_compute_string(&d),
			"{d:?}"
		);
	}
}

// C ABI contract for a future shim, not modelled in the Rust API
#[test]
fn c_null_contract() {
	assert_eq!(c_dep_from_string_null(), None);
	assert_eq!(c_dep_compute_string_null(), None);
	assert_eq!(c_dep_compute_string_raw(None, Some(b"1"), None, 2), b"=1");
	assert_eq!(
		c_dep_compute_string_raw(Some(b"a"), Some(b"1"), None, 0),
		b"a1"
	);
	assert_eq!(
		c_dep_compute_string_raw(Some(b"a"), Some(b"1"), None, 7),
		b"a1"
	);
}

// dep_vercmp is static in C, _alpm_depcmp_provides reaches it for an Eq
// provision with the same name
#[test]
fn provides_fuzz() {
	let mut rng = Rng::new(0x9e0f);
	let (mut vercmp_hits, mut matched) = (0usize, 0usize);
	let n = iters();
	for _ in 0..n {
		let dep = random_dep(&mut rng);
		let provs: Vec<Depend> = (0..rng.below(5))
			.map(|_| random_dep(&mut rng))
			.collect();
		let c = c_depcmp_provides(&dep, &provs);
		assert_eq!(
			c,
			depcmp_provides(&dep, &provs),
			"{dep:?} in {provs:?}"
		);
		vercmp_hits += usize::from(
			dep.depmod != DepMod::Any
				&& provs.iter().any(|p| {
					p.depmod == DepMod::Eq
						&& p.name == dep.name
				}),
		);
		matched += usize::from(c);
	}
	assert!(
		vercmp_hits >= n / 20,
		"dep_vercmp reached {vercmp_hits}/{n}"
	);
	assert!(matched >= n / 20, "matched {matched}/{n}");
}

// parsed strings, as libalpm feeds them in practice
#[test]
fn provides_parsed() {
	let mut rng = Rng::new(0x9a55);
	let alphabet = b"a<>=1:.-";
	for _ in 0..iters() {
		let dep = dep_from_string(&rng.bytes(alphabet, 6));
		let provs: Vec<Depend> = (0..rng.below(3))
			.map(|_| dep_from_string(&rng.bytes(alphabet, 6)))
			.collect();
		assert_eq!(
			c_depcmp_provides(&dep, &provs),
			depcmp_provides(&dep, &provs),
			"{dep:?} in {provs:?}"
		);
	}
}

// names from the dep alphabet, a stale name_hash now and then (the C
// compares hashes first), random provisions
fn random_pkg(rng: &mut Rng) -> Package {
	let name = rng.bytes(b"ab", 3);
	let name_hash = match rng.below(8) {
		0 => hash_sdbm(&rng.bytes(b"ab", 3)),
		_ => hash_sdbm(&name),
	};
	Package {
		name_hash,
		name: Some(name.into()),
		version: opt_bytes(rng, VER_ALPHABET, 6).map(Box::from),
		provides: (0..rng.below(4)).map(|_| random_dep(rng)).collect(),
		..Package::default()
	}
}

#[test]
fn depcmp_fuzz() {
	let mut rng = Rng::new(0xdc4b);
	let n = iters();
	let (mut literal, mut provided) = (0usize, 0usize);
	for _ in 0..n {
		let pkg = random_pkg(&mut rng);
		let dep = random_dep(&mut rng);
		let lit = c_depcmp_literal(&pkg, &dep);
		assert_eq!(lit, depcmp_literal(&pkg, &dep), "{pkg:?} {dep:?}");
		let any = c_depcmp(&pkg, &dep);
		assert_eq!(any, depcmp(&pkg, &dep), "{pkg:?} {dep:?}");
		literal += usize::from(lit);
		provided += usize::from(any && !lit);
	}
	assert!(literal >= n / 20, "literal {literal}/{n}");
	assert!(provided >= n / 20, "provided {provided}/{n}");
}

// first satisfier in list order: duplicates by name and provisions make
// several candidates
#[test]
fn find_satisfier_fuzz() {
	let mut rng = Rng::new(0x5a71);
	let n = iters() / 10;
	let (mut found, mut later) = (0usize, 0usize);
	for _ in 0..n {
		let pkgs: Vec<Package> = (0..rng.below(6))
			.map(|_| random_pkg(&mut rng))
			.collect();
		let s = rng.bytes(DEP_ALPHABET, 8);
		let c = c_find_satisfier(&pkgs, &s);
		let r = find_satisfier(&pkgs, &s);
		let r = r.map(|p| pkgs.iter().position(|q| std::ptr::eq(p, q)));
		assert_eq!(c, r.flatten(), "{:?} in {pkgs:?}", show(&s));
		found += usize::from(c.is_some());
		later += usize::from(c.is_some_and(|i| i > 0));
	}
	assert!(found >= n / 10 && later >= n / 20, "{found} {later}/{n}");
}
