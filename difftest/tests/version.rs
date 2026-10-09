// alpm_core::internals::version::vercmp against C alpm_pkg_vercmp
use alpm_core::internals::version::vercmp;
use difftest::{Rng, c_vercmp};

// separators, epoch/release markers, a non-ascii byte (separator in C locale)
const ALPHABET: &[u8] = b"0012399abzAZ..--:_~+\xc3";

fn rust_vercmp(a: &[u8], b: &[u8]) -> i32 {
	vercmp(a, b) as i32
}

fn random_ver(rng: &mut Rng) -> Vec<u8> {
	let len = rng.below(12);
	(0..len).map(|_| ALPHABET[rng.below(ALPHABET.len())])
		.collect()
}

// small edit of a, so pairs often share a prefix and reach deep branches
fn mutate(rng: &mut Rng, a: &[u8]) -> Vec<u8> {
	let mut b = a.to_vec();
	let c = ALPHABET[rng.below(ALPHABET.len())];
	let i = rng.below(b.len() + 1);
	match rng.below(3) {
		0 => b.insert(i, c),
		1 if i < b.len() => b[i] = c,
		_ if i < b.len() => {
			b.remove(i);
		}
		_ => b.push(c),
	}
	b
}

fn assert_same(a: &[u8], b: &[u8]) {
	let (c, r) = (c_vercmp(Some(a), Some(b)), rust_vercmp(a, b));
	assert_eq!(
		c,
		r,
		"{:?} vs {:?}",
		String::from_utf8_lossy(a),
		String::from_utf8_lossy(b)
	);
}

#[test]
fn fuzz_against_c() {
	let iters = std::env::var("DIFFTEST_ITERS")
		.map_or(200_000, |s| s.parse().unwrap());
	let mut rng = Rng::new(0x5eed);
	for _ in 0..iters {
		let a = random_ver(&mut rng);
		let b = if rng.below(2) == 0 {
			mutate(&mut rng, &a)
		} else {
			random_ver(&mut rng)
		};
		assert_same(&a, &b);
		assert_same(&b, &a);
	}
}

#[test]
fn edge_cases_against_c() {
	let cases: &[(&[u8], &[u8])] = &[
		(b"", b""),
		(b"", b"1"),
		(b":", b"0:"),
		(b"-", b""),
		(b"1-", b"1"),
		(b"a", b"1"),
		(b"000", b"0"),
		(b"1.0.", b"1.0"),
		(b"1..0", b"1.0"),
		(b"99999999999999999999999", b"1"),
		(b"1:", b"2"),
		(b"1:1-1-1", b"1:1-1"),
		(b"\xff1", b"1"),
	];
	for &(a, b) in cases {
		assert_same(a, b);
		assert_same(b, a);
	}
}

// contract the future C ABI shim has to keep
#[test]
fn c_null_contract() {
	assert_eq!(c_vercmp(None, None), 0);
	assert_eq!(c_vercmp(None, Some(b"1")), -1);
	assert_eq!(c_vercmp(Some(b"1"), None), 1);
}
