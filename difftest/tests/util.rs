// alpm_core::util helpers against their C counterparts in util.c
use alpm_core::util::{
	get_fullpath, hash_sdbm, parsedate, splitname, strip_newline, strtoofft,
};
use difftest::{
	Rng, c_get_fullpath, c_hash_sdbm, c_parsedate, c_splitname,
	c_strip_newline, c_strtoofft,
};

fn iters() -> usize {
	std::env::var("DIFFTEST_ITERS").map_or(200_000, |s| s.parse().unwrap())
}

fn random_from(rng: &mut Rng, alphabet: &[u8], max: usize) -> Vec<u8> {
	(0..rng.below(max))
		.map(|_| alphabet[rng.below(alphabet.len())])
		.collect()
}

fn show(s: &[u8]) -> String {
	String::from_utf8_lossy(s).into_owned()
}

#[test]
fn strip_newline_fullpath_hash() {
	let alphabet = b"ab/.-\n\n\r \x80\xff";
	let mut rng = Rng::new(0x5717);
	for _ in 0..iters() {
		let a = random_from(&mut rng, alphabet, 12);
		let b = random_from(&mut rng, alphabet, 6);
		let c = random_from(&mut rng, alphabet, 4);
		assert_eq!(
			c_strip_newline(&a),
			strip_newline(&a),
			"{}",
			show(&a)
		);
		assert_eq!(
			c_get_fullpath(&a, &b, &c),
			get_fullpath(&a, &b, &c)
		);
		assert_eq!(c_hash_sdbm(&a), hash_sdbm(&a), "{}", show(&a));
	}
}

// C off_t: -1 on error, values past i64::MAX wrap negative
fn rust_strtoofft(s: &[u8]) -> i64 {
	strtoofft(s).map_or(-1, |v| v as i64)
}

#[test]
fn numbers() {
	let alphabet = b"0123456789990 \t\n+-x";
	let mut rng = Rng::new(0xda7e);
	let check = |s: &[u8]| {
		assert_eq!(c_strtoofft(s), rust_strtoofft(s), "{}", show(s));
		assert_eq!(
			c_parsedate(s),
			parsedate(s).unwrap_or(0),
			"{}",
			show(s)
		);
	};
	for s in [
		&b""[..],
		b"0",
		b"9223372036854775807",
		b"9223372036854775808",
		b"18446744073709551615",
		b"18446744073709551616",
		b"-9223372036854775808",
		b"-9223372036854775809",
		b"\x0b\x0c\r 42",
		b"+",
		b"-0",
		b"1 ",
	] {
		check(s);
	}
	for _ in 0..iters() {
		check(&random_from(&mut rng, alphabet, 24));
	}
}

#[test]
fn splitname_where_c_is_in_bounds() {
	let alphabet = b"ab1.--/_+";
	let mut rng = Rng::new(0x5911);
	let mut compared = 0;
	for _ in 0..iters() {
		let t = random_from(&mut rng, alphabet, 14);
		let end = t.iter().position(|&c| c == b'/').unwrap_or(t.len());
		if t[..end].iter().filter(|&&c| c == b'-').count() < 2 {
			continue;
		}
		compared += 1;
		let r = splitname(&t)
			.map(|(n, v)| (n.to_vec(), v.to_vec(), hash_sdbm(n)));
		assert_eq!(c_splitname(&t), r, "{}", show(&t));
	}
	// guard against the filter silently skipping everything
	assert!(compared > iters() / 10, "only {compared} compared");
}
