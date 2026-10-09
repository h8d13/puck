// unit tests for alpm_core::internals::version
use alpm_core::internals::version::*;

// vectors from test/util/vercmptest.sh
const CASES: &[(&str, &str, i8)] = &[
	("1.5.0", "1.5.0", 0),
	("1.5.1", "1.5.0", 1),
	("1.5.1", "1.5", 1),
	("1.5.0-1", "1.5.0-1", 0),
	("1.5.0-1", "1.5.0-2", -1),
	("1.5.0-1", "1.5.1-1", -1),
	("1.5.0-2", "1.5.1-1", -1),
	("1.5-1", "1.5.1-1", -1),
	("1.5-2", "1.5.1-1", -1),
	("1.5-2", "1.5.1-2", -1),
	("1.5", "1.5-1", 0),
	("1.5-1", "1.5", 0),
	("1.1-1", "1.1", 0),
	("1.0-1", "1.1", -1),
	("1.1-1", "1.0", 1),
	("1.5b-1", "1.5-1", -1),
	("1.5b", "1.5", -1),
	("1.5b-1", "1.5", -1),
	("1.5b", "1.5.1", -1),
	("1.0a", "1.0alpha", -1),
	("1.0alpha", "1.0b", -1),
	("1.0b", "1.0beta", -1),
	("1.0beta", "1.0rc", -1),
	("1.0rc", "1.0", -1),
	("1.5.a", "1.5", 1),
	("1.5.b", "1.5.a", 1),
	("1.5.1", "1.5.b", 1),
	("1.5.b-1", "1.5.b", 0),
	("1.5-1", "1.5.b", -1),
	("2.0", "2_0", 0),
	("2.0_a", "2_0.a", 0),
	("2.0a", "2.0.a", -1),
	("2___a", "2_a", 1),
	("0:1.0", "0:1.0", 0),
	("0:1.0", "0:1.1", -1),
	("1:1.0", "0:1.0", 1),
	("1:1.0", "0:1.1", 1),
	("1:1.0", "2:1.1", -1),
	("1:1.0", "0:1.0-1", 1),
	("1:1.0-1", "0:1.1-1", 1),
	("0:1.0", "1.0", 0),
	("0:1.0", "1.1", -1),
	("0:1.1", "1.0", 1),
	("1:1.0", "1.0", 1),
	("1:1.0", "1.1", 1),
	("1:1.1", "1.1", 1),
];

#[test]
fn vercmptest_vectors() {
	for &(a, b, exp) in CASES {
		let exp = exp.cmp(&0);
		let (a, b) = (a.as_bytes(), b.as_bytes());
		assert_eq!(vercmp(a, b), exp, "{a:?} {b:?}");
		// mirror case, like the shell suite
		assert_eq!(vercmp(b, a), exp.reverse(), "{b:?} {a:?}");
	}
}

// epoch/version/release split, seen through comparisons
#[test]
fn evr_split() {
	use std::cmp::Ordering::*;
	// empty epoch is 0
	assert_eq!(vercmp(b":2.0", b"0:2.0"), Equal);
	assert_eq!(vercmp(b":2.0", b"2.0"), Equal);
	// release starts after the last '-'
	assert_eq!(vercmp(b"2.0-1-2", b"2.0-1-3"), Less);
	assert_eq!(vercmp(b"2.0-1-2", b"2.0-2-1"), Less);
	// trailing nul ends the string like in C
	assert_eq!(vercmp(b"1.0\0junk", b"1.0"), Equal);
}
