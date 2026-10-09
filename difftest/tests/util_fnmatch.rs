// alpm_core::internals::util::{fnmatch, fnmatch_patterns} against glibc fnmatch(3)
// through _alpm_fnmatch and _alpm_fnmatch_patterns
use alpm_core::internals::util::{fnmatch, fnmatch_patterns};
use difftest::{Rng, c_fnmatch, c_fnmatch_patterns, iters};

fn show(s: &[u8]) -> String {
	String::from_utf8_lossy(s).into_owned()
}

// glibc reads POSIXLY_CORRECT once per process, it turns '^' literal
fn ensure_default_env() {
	assert!(
		std::env::var_os("POSIXLY_CORRECT").is_none(),
		"unset POSIXLY_CORRECT, the port assumes '^' negates"
	);
}

fn check(p: &[u8], s: &[u8]) {
	assert_eq!(
		c_fnmatch(p, s) == 0,
		fnmatch(p, s),
		"pattern {:?} string {:?}",
		show(p),
		show(s)
	);
}

// pieces the C parses specially, plus plain bytes
const TOKENS: &[&[u8]] = &[
	b"a",
	b"b",
	b"z",
	b"y",
	b"A",
	b"0",
	b".",
	b"/",
	b" ",
	b"\xe9",
	b"*",
	b"?",
	b"[",
	b"]",
	b"!",
	b"^",
	b"-",
	b"\\",
	b":",
	b"=",
	b"[:",
	b":]",
	b"[:alpha:]",
	b"[:digit:]",
	b"[:space:]",
	b"[:upper:]",
	b"[:punct:]",
	b"[:xdigit:]",
	b"[:blank:]",
	b"[:foo:]",
	b"[:Alpha:]",
	b"[::]",
	b"[:alnum:]",
	b"[:cntrl:]",
	b"[:graph:]",
	b"[:lower:]",
	b"[:print:]",
	b"[=",
	b"=]",
	b"[=a=]",
	b"[==]",
	b"[.",
	b".]",
	b"[.a.]",
	b"[.-.]",
	b"[..]",
	b"[.ab.]",
	b"[:z:]",
	b"[:az:]",
	b"a-z",
	b"z-a",
	b"[!",
	b"[^",
	b"[]",
	b"\\]",
];

const STRING_BYTES: &[u8] = b"abzyA0./ \t\x0b\xe9*?[]!^-\\:=_{}~\x7f\x01Zm9";

fn pattern(rng: &mut Rng, max: usize) -> Vec<u8> {
	(0..rng.below(max))
		.flat_map(|_| TOKENS[rng.below(TOKENS.len())].iter().copied())
		.collect()
}

#[test]
fn fixed_cases() {
	ensure_default_env();
	let cases: &[(&[u8], &[u8])] = &[
		(b"", b""),
		(b"", b"a"),
		(b"*", b""),
		(b"*", b"/a/.b"),
		(b"?", b"/"),
		(b"\\", b"\\"),
		(b"\\\\", b"\\"),
		(b"*\\", b"a\\"),
		(b"[a", b"a"),
		(b"[a", b"[a"),
		(b"[]", b"]"),
		(b"[]", b"[]"),
		(b"[]a]", b"]"),
		(b"[!]a]", b"b"),
		(b"[^a]", b"b"),
		(b"[a-]", b"-"),
		(b"[a-c]", b"b"),
		(b"[c-a]", b"b"),
		(b"[\\a-c]", b"b"),
		(b"[a-\\c]", b"b"),
		(b"[[:alpha:]]", b"q"),
		(b"[[:alpha:]-z]", b"-"),
		(b"[[:z:]]", b"z"),
		(b"[[:z:]]", b"z]"),
		(b"[[:az:]]", b":]"),
		(b"[a[:z:]]", b"a]"),
		(b"[[:alpha]", b"["),
		(b"[[:foo:]]", b"f"),
		(b"[[=a=]]", b"a"),
		(b"[[=a]", b"="),
		(b"[[.a.]-c]", b"b"),
		(b"[[.-.]]", b"-"),
		(b"[[.a.]-]", b"a"),
		(b"[[.a.]-]", b"-"),
		(b"[a-[.c.]]", b"b"),
		(b"[[.ab.]]", b"a"),
		(b"[a[:]", b"a"),
		(b"[a[:x]", b"a"),
		(b"[[:space:]]", b"\x0b"),
		(b"[[:print:]]", b"\xe9"),
		(b"[\xe0-\xef]", b"\xe9"),
		(b"*a*b*c", b"xaybzcxc"),
		(b"*[a", b"x[a"),
		(b"a*?", b"a"),
		(b"a*??*", b"abc"),
		// malformed tails, string equal to the pattern tells a hard
		// failure apart from a literal '['
		(b"[a[=b]", b"a"),
		(b"[a[.b]", b"a"),
		(b"[[.a", b"[[.a"),
		(b"[b-", b"[b-"),
		(b"[a-[.b", b"[a-[.b"),
		(b"[a-[.bc.]]", b"b"),
		(b"[[:foo:]", b"[[:foo:]"),
		(b"[[[=", b"[[[="),
		(b"[[[=a", b"[[[=a"),
		(b"[[[=a=", b"[[[=a="),
		(b"[[[.", b"[[[."),
		(b"[[[.a.", b"[[[.a."),
		(b"[[[:", b"[[[:"),
		(b"[[[:a", b"[[[:a"),
		(b"[[[:a:", b"[[[:a:"),
		(b"[[\\", b"[[\\"),
	];
	for (p, s) in cases {
		check(p, s);
	}
	// glibc caps class names, past the cap the pattern fails
	let mut long = b"[[:".to_vec();
	long.extend(std::iter::repeat_n(b'a', 2100));
	long.extend(b":]]");
	check(&long, b"a");
	let mut long = b"[a[:".to_vec();
	long.extend(std::iter::repeat_n(b'b', 2100));
	long.extend(b":]]");
	check(&long, b"a");
}

#[test]
fn fuzz_fnmatch() {
	ensure_default_env();
	let mut rng = Rng::new(0xf47a);
	let mut matched = 0;
	for _ in 0..iters() {
		let p = pattern(&mut rng, 10);
		let s = rng.bytes(STRING_BYTES, 8);
		check(&p, &s);
		matched += usize::from(fnmatch(&p, &s));
	}
	assert!(matched > iters() / 100, "only {matched} matches");
}

// pattern-shaped strings: brackets matched as literals after a failed parse
#[test]
fn fuzz_pattern_like_strings() {
	ensure_default_env();
	let mut rng = Rng::new(0x5e1f);
	let mut matched = 0;
	for _ in 0..iters() {
		let p = pattern(&mut rng, 6);
		let s = if rng.below(2) == 0 {
			p.clone()
		} else {
			pattern(&mut rng, 4)
		};
		check(&p, &s);
		matched += usize::from(fnmatch(&p, &s));
	}
	assert!(matched > iters() / 100, "only {matched} matches");
}

fn rust_patterns(patterns: &[Vec<u8>], s: &[u8]) -> i32 {
	match fnmatch_patterns(patterns, s) {
		None => -1,
		Some(inverted) => i32::from(inverted),
	}
}

#[test]
fn patterns_order_and_inversion() {
	ensure_default_env();
	let fixed: &[(&[&[u8]], &[u8])] = &[
		(&[], b"a"),
		(&[b"a"], b"a"),
		(&[b"!a"], b"a"),
		(&[b"a", b"!a"], b"a"),
		(&[b"!a", b"a"], b"a"),
		(&[b"\\!a"], b"!a"),
		(&[b"\\a"], b"a"),
		(&[b"!"], b""),
		(&[b""], b""),
		(&[b"!*", b"b*"], b"bc"),
	];
	for (pats, s) in fixed {
		let pats: Vec<Vec<u8>> =
			pats.iter().map(|p| p.to_vec()).collect();
		assert_eq!(
			c_fnmatch_patterns(&pats, s),
			rust_patterns(&pats, s),
			"{pats:?} {s:?}"
		);
	}
	let mut rng = Rng::new(0x9a77);
	let prefixes: &[&[u8]] = &[b"", b"", b"!", b"\\", b"!!", b"\\!"];
	let mut counts = [0usize; 3];
	for _ in 0..iters() / 4 {
		let pats: Vec<Vec<u8>> = (0..rng.below(5))
			.map(|_| {
				let pre = prefixes[rng.below(prefixes.len())];
				[pre, &pattern(&mut rng, 3)].concat()
			})
			.collect();
		let s = rng.bytes(STRING_BYTES, 4);
		let r = rust_patterns(&pats, &s);
		assert_eq!(c_fnmatch_patterns(&pats, &s), r, "{pats:?} {s:?}");
		counts[(r + 1) as usize] += 1;
	}
	// every outcome exercised
	assert!(counts.iter().all(|&n| n > iters() / 1000), "{counts:?}");
}

// raw bytes from the bracket syntax, no token structure
#[test]
fn fuzz_raw_syntax() {
	ensure_default_env();
	let alphabet = b"[[[]]!^-\\:.=*?azy";
	let mut rng = Rng::new(0xb7ac);
	let mut matched = 0;
	for _ in 0..iters() {
		let p = rng.bytes(alphabet, 12);
		let s = if rng.below(3) == 0 {
			p.clone()
		} else {
			rng.bytes(alphabet, 6)
		};
		check(&p, &s);
		matched += usize::from(fnmatch(&p, &s));
	}
	assert!(matched > iters() / 100, "only {matched} matches");
}
