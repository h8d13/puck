// alpm_core::internals::package against the C in package.c
use std::ptr;

use alpm_core::filelist::{File, FileList};
use alpm_core::internals::backup::Backup;
use alpm_core::internals::deps::{DepMod, Depend};
use alpm_core::internals::package::{
	Package, PkgFrom, PkgReason, PkgXData, pkg_cmp, pkg_compare_versions,
	pkg_find,
};
use alpm_core::internals::util::hash_sdbm;
use difftest::{
	Rng, c_pkg_cmp, c_pkg_compare_versions, c_pkg_dup, c_pkg_find,
	c_pkg_getters, c_pkg_roundtrip, iters,
};

// 0xc3 sorts last for strcmp, '-' and '.' below letters
const NAME_ALPHABET: &[u8] = b"ab-.\xc3";
const VER_ALPHABET: &[u8] = b"0119a.-:";
const TEXT_ALPHABET: &[u8] = b"ab =\t/\xc3";
const MODS: [DepMod; 6] = [
	DepMod::Any,
	DepMod::Eq,
	DepMod::Ge,
	DepMod::Le,
	DepMod::Gt,
	DepMod::Lt,
];
const REASONS: [PkgReason; 3] =
	[PkgReason::Explicit, PkgReason::Depend, PkgReason::Unknown];

fn show(p: &Package) -> String {
	let s = |s: &Option<Box<[u8]>>| {
		s.as_deref()
			.map(|s| String::from_utf8_lossy(s).into_owned())
	};
	format!("{:?}-{:?} hash {}", s(&p.name), s(&p.version), p.name_hash)
}

fn opt(rng: &mut Rng, alphabet: &[u8], max: usize) -> Option<Vec<u8>> {
	(rng.below(4) != 0).then(|| rng.bytes(alphabet, max))
}

fn some_of<T>(rng: &mut Rng, f: impl Fn(&mut Rng) -> T) -> Vec<T> {
	(0..rng.below(4)).map(|_| f(rng)).collect()
}

fn random_dep(rng: &mut Rng) -> Depend {
	let name = rng.bytes(NAME_ALPHABET, 6);
	Depend {
		name_hash: hash_sdbm(&name),
		name: name.into(),
		version: opt(rng, VER_ALPHABET, 5).map(Box::from),
		desc: opt(rng, TEXT_ALPHABET, 5).map(Box::from),
		depmod: MODS[rng.below(MODS.len())],
	}
}

fn deps(rng: &mut Rng) -> Vec<Depend> {
	some_of(rng, random_dep)
}

fn strs(rng: &mut Rng) -> Vec<Box<[u8]>> {
	some_of(rng, |r| r.bytes(TEXT_ALPHABET, 6).into())
}

fn random_origin(rng: &mut Rng) -> Option<PkgFrom> {
	match rng.below(4) {
		0 => None,
		1 => Some(PkgFrom::File(rng.bytes(TEXT_ALPHABET, 8).into())),
		2 => Some(PkgFrom::LocalDb),
		_ => Some(PkgFrom::SyncDb),
	}
}

// every field drawn, NULL strings included
fn random_pkg(rng: &mut Rng) -> Package {
	let files = some_of(rng, |r| {
		let name = r.bytes(TEXT_ALPHABET, 6);
		File::new(name, r.next_u64() as i64, r.next_u64() as u32)
	});
	Package {
		name_hash: rng.next_u64(),
		filename: opt(rng, TEXT_ALPHABET, 6).map(Box::from),
		base: opt(rng, NAME_ALPHABET, 6).map(Box::from),
		name: opt(rng, NAME_ALPHABET, 6).map(Box::from),
		version: opt(rng, VER_ALPHABET, 6).map(Box::from),
		desc: opt(rng, TEXT_ALPHABET, 6).map(Box::from),
		url: opt(rng, TEXT_ALPHABET, 6).map(Box::from),
		packager: opt(rng, TEXT_ALPHABET, 6).map(Box::from),
		sha256sum: opt(rng, TEXT_ALPHABET, 6).map(Box::from),
		base64_sig: opt(rng, TEXT_ALPHABET, 6).map(Box::from),
		arch: opt(rng, TEXT_ALPHABET, 6).map(Box::from),
		builddate: rng.next_u64() as i64,
		installdate: rng.next_u64() as i64,
		size: rng.next_u64() as i64,
		isize: rng.next_u64() as i64,
		download_size: rng.next_u64() as i64,
		licenses: strs(rng).into(),
		replaces: deps(rng).into(),
		groups: strs(rng).into(),
		backup: some_of(rng, |r| Backup {
			name: r.bytes(TEXT_ALPHABET, 6).into(),
			hash: opt(r, TEXT_ALPHABET, 6).map(Box::from),
		})
		.into(),
		depends: deps(rng).into(),
		optdepends: deps(rng).into(),
		checkdepends: deps(rng).into(),
		makedepends: deps(rng).into(),
		conflicts: deps(rng).into(),
		provides: deps(rng).into(),
		files: FileList { files },
		origin: random_origin(rng),
		reason: REASONS[rng.below(REASONS.len())],
		scriptlet: rng.next_u64() as i32,
		xdata: some_of(rng, |r| PkgXData {
			name: r.bytes(TEXT_ALPHABET, 5).into(),
			value: r.bytes(TEXT_ALPHABET, 5).into(),
		})
		.into(),
		infolevel: rng.next_u64() as i32,
		validation: rng.next_u64() as i32,
	}
}

// what the C getters can see: no getter for these fields
fn gettable(p: &Package) -> Package {
	let origin = match &p.origin {
		Some(PkgFrom::File(_)) => {
			Some(PkgFrom::File(Vec::new().into()))
		}
		o => o.clone(),
	};
	Package {
		name_hash: 0,
		download_size: 0,
		infolevel: 0,
		origin,
		..p.clone()
	}
}

fn check_model(p: &Package) {
	assert_eq!(&c_pkg_roundtrip(p), p, "roundtrip {}", show(p));
	assert_eq!(c_pkg_getters(p), gettable(p), "getters {}", show(p));
	assert_eq!(c_pkg_dup(p), p.dup(), "dup {}", show(p));
}

fn named(name: &[u8]) -> Package {
	Package {
		name_hash: hash_sdbm(name),
		name: Some(name.into()),
		..Package::default()
	}
}

#[test]
fn model_edge_cases() {
	check_model(&Package::default());
	let file = Package {
		origin: Some(PkgFrom::File(b"/tmp/a.pkg.tar.zst"[..].into())),
		..named(b"a")
	};
	check_model(&file);
	// empty strings stay distinct from NULL, dup drops the uncopied ones
	let empty = Package {
		base64_sig: Some(Box::default()),
		xdata: vec![PkgXData::default()].into(),
		download_size: 7,
		..file
	};
	check_model(&empty);
}

#[test]
fn model_fuzz() {
	let mut rng = Rng::new(0x9a7a6e);
	for _ in 0..iters() {
		check_model(&random_pkg(&mut rng));
	}
}

#[test]
fn cmp_fuzz() {
	let mut rng = Rng::new(0xc3c3);
	for _ in 0..iters() {
		let a = named(&rng.bytes(NAME_ALPHABET, 5));
		let b = named(&rng.bytes(NAME_ALPHABET, 5));
		assert_eq!(
			c_pkg_cmp(&a, &b),
			pkg_cmp(&a, &b),
			"{} {}",
			show(&a),
			show(&b)
		);
	}
}

#[test]
fn compare_versions_fuzz() {
	let mut rng = Rng::new(0x7e75);
	for _ in 0..iters() {
		let a = Package {
			version: opt(&mut rng, VER_ALPHABET, 7).map(Box::from),
			..Package::default()
		};
		let b = Package {
			version: opt(&mut rng, VER_ALPHABET, 7).map(Box::from),
			..Package::default()
		};
		assert_eq!(
			c_pkg_compare_versions(&a, &b),
			pkg_compare_versions(&a, &b),
			"{} {}",
			show(&a),
			show(&b)
		);
	}
}

// names from a tiny alphabet so lookups hit, some hashes stale so the
// hash check before strcmp matters
fn haystack(rng: &mut Rng) -> Vec<Package> {
	let mut pkgs: Vec<Package> = (0..rng.below(7))
		.map(|_| named(&rng.bytes(b"ab", 3)))
		.collect();
	for i in 0..pkgs.len() {
		match rng.below(5) {
			0 => pkgs[i].name_hash = rng.next_u64(),
			1 => {
				pkgs[i].name_hash =
					pkgs[rng.below(i + 1)].name_hash
			}
			_ => {}
		}
	}
	pkgs
}

fn rust_find(pkgs: &[Package], needle: &[u8]) -> Option<usize> {
	let found = pkg_find(pkgs, needle)?;
	pkgs.iter().position(|p| ptr::eq(p, found))
}

#[test]
fn find_fuzz() {
	let mut rng = Rng::new(0xf1d);
	for _ in 0..iters() {
		let pkgs = haystack(&mut rng);
		let needle = rng.bytes(b"ab", 4);
		let refs: Vec<Option<&Package>> =
			pkgs.iter().map(Some).collect();
		assert_eq!(
			c_pkg_find(&refs, Some(&needle)),
			rust_find(&pkgs, &needle),
			"{:?} in {:?}",
			String::from_utf8_lossy(&needle),
			pkgs.iter().map(show).collect::<Vec<_>>()
		);
	}
}

// contract the future C ABI shim has to keep
#[test]
fn c_null_contract() {
	// NULL needle and empty list find nothing, NULL entries are skipped
	let a = named(b"a");
	assert_eq!(c_pkg_find(&[Some(&a)], None), None);
	assert_eq!(c_pkg_find(&[], Some(b"a")), None);
	assert_eq!(c_pkg_find(&[None, Some(&a)], Some(b"a")), Some(1));
}
