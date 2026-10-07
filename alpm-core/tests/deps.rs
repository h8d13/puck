// unit tests for alpm_core::deps
use alpm_core::deps::*;
use alpm_core::util::hash_sdbm;
use alpm_core::version::vercmp;

fn dep(
	name: &[u8],
	depmod: DepMod,
	version: Option<&[u8]>,
	desc: Option<&[u8]>,
) -> Depend {
	Depend {
		name: name.to_vec(),
		version: version.map(<[u8]>::to_vec),
		desc: desc.map(<[u8]>::to_vec),
		name_hash: hash_sdbm(name),
		depmod,
	}
}

#[test]
fn from_string_cases() {
	use DepMod::*;
	let cases: [(&[u8], Depend); 9] = [
		(b"glibc", dep(b"glibc", Any, None, None)),
		(b"sh=5.2", dep(b"sh", Eq, Some(b"5.2"), None)),
		(b"a>=1:2-3", dep(b"a", Ge, Some(b"1:2-3"), None)),
		(b"a<=1", dep(b"a", Le, Some(b"1"), None)),
		(b"a<1", dep(b"a", Lt, Some(b"1"), None)),
		(b"a>1", dep(b"a", Gt, Some(b"1"), None)),
		(b"a=", dep(b"a", Eq, Some(b""), None)),
		(b"a<=: why", dep(b"a", Le, Some(b""), Some(b"why"))),
		// '<' wins over an earlier '>'
		(b"a>1<2", dep(b"a>1", Lt, Some(b"2"), None)),
	];
	for (s, want) in cases {
		assert_eq!(dep_from_string(s), want, "{:?}", s);
	}
	let d = dep_from_string(b"python: for the scripts: really");
	assert_eq!(d.desc.as_deref(), Some(&b"for the scripts: really"[..]));
	assert_eq!(dep_from_string(b"a=1\0junk"), dep_from_string(b"a=1"));
}

#[test]
fn compute_string_cases() {
	use DepMod::*;
	let s = |d: Depend| dep_compute_string(&d);
	assert_eq!(s(dep(b"a", Ge, Some(b"1"), Some(b"x"))), b"a>=1: x");
	assert_eq!(s(dep(b"a", Any, Some(b"1"), None)), b"a");
	assert_eq!(s(dep(b"a", Lt, None, None)), b"a<");
	assert_eq!(s(dep(b"a", Eq, Some(b""), Some(b""))), b"a=: ");
	for t in [&b"a"[..], b"a<=1:2", b"a>1: why", b"a=: "] {
		assert_eq!(dep_compute_string(&dep_from_string(t)), t);
	}
}

// dep_vercmp is static in C: check it against vercmp semantics directly
#[test]
fn dep_vercmp_semantics() {
	use DepMod::*;
	let vs: [&[u8]; 5] = [b"1", b"1.0", b"1:0.5", b"2-1", b"1.0a"];
	for a in vs {
		for b in vs {
			let ord = vercmp(a, b);
			let (a, b) = (Some(a), Some(b));
			assert!(dep_vercmp(a, Any, b));
			assert_eq!(dep_vercmp(a, Eq, b), ord.is_eq());
			assert_eq!(dep_vercmp(a, Ge, b), ord.is_ge());
			assert_eq!(dep_vercmp(a, Le, b), ord.is_le());
			assert_eq!(dep_vercmp(a, Gt, b), ord.is_gt());
			assert_eq!(dep_vercmp(a, Lt, b), ord.is_lt());
		}
	}
	// NULL sorts first, as in alpm_pkg_vercmp
	assert!(dep_vercmp(None, Lt, Some(b"0")));
	assert!(dep_vercmp(None, Eq, None));
}

#[test]
fn provides_cases() {
	let p = [dep_from_string(b"sh=5.2"), dep_from_string(b"libfoo.so")];
	assert!(depcmp_provides(&dep_from_string(b"sh>=5"), &p));
	assert!(!depcmp_provides(&dep_from_string(b"sh<5"), &p));
	assert!(depcmp_provides(&dep_from_string(b"libfoo.so"), &p));
	// unversioned provision never satisfies a versioned dep
	assert!(!depcmp_provides(&dep_from_string(b"libfoo.so>=1"), &p));
	assert!(!depcmp_provides(&dep_from_string(b"sh"), &[]));
}
