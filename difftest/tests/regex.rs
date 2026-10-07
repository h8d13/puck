// alpm_core::regex against glibc regcomp/regexec in C.UTF-8
//
// pattern sizes stay small (a few tokens, {m,n} bounds up to 3): glibc's
// back-reference matcher and its node duplication grow fast, the fuzz
// keeps out of the inputs where glibc itself takes seconds or gigabytes
use std::ffi::c_int;

use alpm_core::regex::{Flags, Regex};
use difftest::{
	REG_EXTENDED, REG_ICASE, REG_NEWLINE, REG_NOSUB, Rng, c_iswctype,
	c_regex, c_towupper, iters,
};

// pacman's two flag sets first (db.c/files.c, remove.c)
const FLAGS: [Flags; 4] = [
	Flags {
		icase: true,
		newline: true,
	},
	Flags {
		icase: false,
		newline: true,
	},
	Flags {
		icase: true,
		newline: false,
	},
	Flags {
		icase: false,
		newline: false,
	},
];

fn show(s: &[u8]) -> String {
	s.escape_ascii().to_string()
}

fn cflags(f: Flags, nosub: bool) -> c_int {
	let mut c = REG_EXTENDED;
	if f.icase {
		c |= REG_ICASE;
	}
	if f.newline {
		c |= REG_NEWLINE;
	}
	if nosub {
		c |= REG_NOSUB;
	}
	c
}

fn rust(p: &[u8], f: Flags, texts: &[&[u8]]) -> Result<Vec<bool>, c_int> {
	let re = Regex::new(p, f).map_err(|e| e.code())?;
	Ok(texts.iter().map(|t| re.is_match(t)).collect())
}

// compile result and every match compared. always REG_NOSUB: without it
// (remove.c) glibc keeps unreferenced groups as nodes, which changes
// whether an anchor in a {m,n} copy counts (see Compiler in the port)
fn check(p: &[u8], f: Flags, texts: &[&[u8]]) -> Result<Vec<bool>, c_int> {
	let c = c_regex(p, cflags(f, true), texts);
	let r = rust(p, f, texts);
	assert_eq!(
		c,
		r,
		"pattern {} {f:?} texts {:?}",
		show(p),
		texts.iter().map(|t| show(t)).collect::<Vec<_>>()
	);
	r
}

fn check_all(p: &[u8], texts: &[&[u8]]) {
	for f in FLAGS {
		let _ = check(p, f, texts);
	}
}

#[test]
fn compile_errors() {
	let cases: &[(&[u8], c_int)] = &[
		(b"", 0),
		(b"[", 2),
		(b"[^", 2),
		(b"[]", 7),
		(b"[a", 7),
		(b"a{1", 9),
		(b"a{", 9),
		(b"a{1,", 9),
		(b"a{1,2", 9),
		(b"a{x}", 10),
		(b"a{}", 10),
		(b"a{,}", 0),
		(b"a{,,}", 10),
		(b"a{1,2,3}", 10),
		(b"a{2,1}", 10),
		(b"a{1\\,2}", 0),
		(b"a{1x", 9),
		(b"a{32767}", 0),
		(b"a{32768}", 15),
		(b"a{1,32768}", 15),
		(b"a{40000,5}", 10),
		(b"a{99999999999}", 15),
		(b"\\", 5),
		(b"a\\", 5),
		(b"[\\]", 0),
		(b"*a", 13),
		(b"a|*b", 13),
		(b"(*a)", 13),
		(b"(+a)", 13),
		(b"{1}", 13),
		(b"a|{1}", 13),
		(b"^*", 13),
		(b"$*", 13),
		(b"x$*", 13),
		(b"\\<+", 13),
		(b"\\b?", 13),
		(b"a**", 0),
		(b"a+*?{2}", 0),
		(b"a)", 0),
		(b"(a", 8),
		(b"(a))", 0),
		(b"((a)", 8),
		(b"()", 0),
		(b"(|)", 0),
		(b"\\1", 6),
		(b"(a)\\1", 0),
		(b"(a\\1)", 6),
		(b"(a)|\\1", 6),
		(b"(a)|b\\1", 6),
		(b"(a){0}\\1", 0),
		(b"()()()()()()()()()\\9", 0),
		(b"()()()()()()()()()()\\9", 0),
		(b"[[:alpha:]]", 0),
		(b"[[:alpha:]", 7),
		(b"[[:foo:]]", 4),
		(b"[[:foo:]", 4),
		(b"[[:ALPHA:]]", 4),
		(b"[[::]]", 4),
		(b"[[:alpha]", 7),
		(b"[[=a=]]", 0),
		(b"[[=ab=]]", 3),
		(b"[[==]]", 3),
		(b"[[.a.]]", 0),
		(b"[[.ab.]]", 3),
		(b"[[..]]", 3),
		(b"[[.space.]]", 3),
		(b"[[.\xc3\xa9.]]", 3),
		(b"[[.\xe9.]]", 0),
		(b"[a-z]", 0),
		(b"[z-a]", 11),
		(b"[a-a]", 0),
		(b"[a-\xc3\xa9]", 3),
		(b"[\xc3\xa0-\xc3\xa9]", 3),
		(b"[a-\xff]", 0),
		(b"[[.a.]-z]", 0),
		(b"[[.ab.]-z]", 3),
		(b"[a-[.z.]]", 0),
		(b"[a-[:alpha:]]", 11),
		(b"[a-[=z=]]", 11),
		(b"[[:alpha:]-z]", 11),
		(b"[[:alpha:]-]", 0),
		(b"[a-z-0]", 11),
		(b"[--a]", 0),
		(b"[!--]", 0),
		(b"[a-]", 0),
		(b"[]a]", 0),
		(b"[^]a]", 0),
		(b"[a]]", 0),
		(b"[[.]", 7),
		(b"[[.].]]", 0),
		(b"[[=", 7),
		(b"[[", 7),
		(b"[Z-a]", 0),
		(b"[_-a]", 0),
	];
	for &(p, want) in cases {
		let got = check(p, FLAGS[1], &[]).err().unwrap_or(0);
		assert_eq!(got, want, "pattern {}", show(p));
		check_all(p, &[]);
	}
	// class and symbol names stop at 32 bytes
	for n in [30, 31, 32, 33] {
		for (open, close) in
			[(b"[[:", b":]]"), (b"[[.", b".]]"), (b"[[=", b"=]]")]
		{
			let mut p = open.to_vec();
			p.extend(std::iter::repeat_n(b'a', n));
			p.extend(close);
			check_all(&p, &[b"a"]);
		}
	}
}

#[test]
fn fixed_matches() {
	let cases: &[(&[u8], &[&[u8]])] = &[
		(b"", &[b"", b"a"]),
		(b"a|b", &[b"a", b"b", b"c"]),
		(b"ab|cd", &[b"ab", b"ad", b"cd", b"acd"]),
		(b"^(ab|a)c$", &[b"abc", b"ac", b"abbc"]),
		(b"a{2,3}", &[b"a", b"aa", b"aaaa"]),
		(b"^a{2,3}$", &[b"a", b"aa", b"aaa", b"aaaa"]),
		(b"^(a|bc){2}$", &[b"abc", b"bcbc", b"aa", b"a"]),
		(b"^a{,2}$", &[b"", b"aa", b"aaa"]),
		(b"x(a){0}y", &[b"xy", b"xay"]),
		(b"^$", &[b"", b"\n", b"a\n", b"\na"]),
		(b"a$", &[b"a", b"a\n", b"a\nb", b"ab"]),
		(b"^b", &[b"b", b"a\nb", b"ab"]),
		// anchors mid-pattern next to a newline, REG_NEWLINE or not
		(b"a$\nb", &[b"a\nb"]),
		(b"a\n^b", &[b"a\nb"]),
		(b"a.b", &[b"axb", b"a\nb", b"a\xc3\xa9b", b"a\xe9b"]),
		(b"a[^x]b", &[b"a\nb", b"ayb", b"a\xc3\xa9b", b"a\xe9b"]),
		(b"a\\Wb", &[b"a\nb", b"a b", b"a\xc3\xa9b"]),
		(b"a\\Sb", &[b"a\nb", b"axb", b"a\xe2\x80\x83b"]),
		(b"\\w", &[b"_", b"\xc3\xa9", b"\xe9", b" "]),
		(b"\\bx\\b", &[b"x", b"ax", b"\xc3\xa9x", b"-x-"]),
		(b"\\Bx", &[b"ax", b"x", b"\xc3\xa9x"]),
		(b"\\<x", &[b"x", b"ax", b" x", b"\xe9x"]),
		(b"x\\>", &[b"x", b"xa", b"x ", b"x\xc3\xa9"]),
		(b"\\`a", &[b"a", b"\na", b"ba"]),
		(b"a\\'", &[b"a", b"a\n"]),
		(b"[[:upper:]]", &[b"A", b"a", b"\xc3\x89", b"\xc3\xa9"]),
		(b"[[:lower:]]", &[b"A", b"a", b"\xc3\x89", b"\xc3\xa9"]),
		(
			b"[[:alpha:]]",
			&[b"1", b"\xe9", b"\xc3\xa9", b"\xe2\x82\xac"],
		),
		(b"[[:punct:]]", &[b"!", b"\xe2\x82\xac", b"\xc2\xa7"]),
		(b"[[:space:]]", &[b"\xe3\x80\x80", b"\xc2\xa0", b"\t"]),
		(b"[a-\xff]", &[b"b", b"\xc3\xa9", b"\xff", b"\xc4\x80"]),
		(b"[\xe9]", &[b"\xe9", b"\xc3\xa9"]),
		(b"[^\xe9]", &[b"\xe9", b"\xc3\xa9"]),
		(b"[[.\xe9.]]", &[b"\xe9"]),
		(b"\xe9", &[b"\xe9", b"\xc3\xa9"]),
		(b"\xc3", &[b"\xc3\xa9", b"\xc3"]),
		(b"\xa9", &[b"\xc3\xa9", b"\xa9"]),
		(b"\xe2.", &[b"\xe2\x82\xac"]),
		(
			b".",
			&[
				b"\xed\xa0\x80",
				b"\xf8\x88\x80\x80\x80",
				b"\xf4\x90\x80\x80",
			],
		),
		(
			b"[^a]",
			&[
				b"\xed\xa0\x80",
				b"\xf4\x90\x80\x80",
				b"\xf0\x80\x80\x80",
			],
		),
		(b"\xc3\xa9", &[b"\xc3\x89", b"\xc3\xa9"]),
		(b"\xc3\x89", &[b"\xc3\x89", b"\xc3\xa9"]),
		(b"\xc3\x9f", &[b"\xe1\xba\x9e", b"ss", b"\xc3\x9f"]),
		(b"\xc4\xb1", &[b"i", b"I", b"\xc4\xb1"]),
		(b"\xc5\xbf", &[b"s", b"S", b"\xc5\xbf"]),
		(b"\\a", &[b"a", b"A"]),
		(b"\\A", &[b"a", b"A"]),
		(b"\\d", &[b"d", b"D", b"1"]),
		(b"\\\xc5\xbf", &[b"\xc5\xbf", b" ", b"x"]),
		(b"\\\xc3\xa9", &[b"\xc3\xa9", b"\xc3\x89"]),
		(b"[[.a.]]", &[b"a", b"A"]),
		(b"[[=a=]]", &[b"a", b"A"]),
		(b"[\xc3\xa9]", &[b"\xc3\xa9", b"\xc3\x89"]),
		(b"(a)\\1", &[b"aa", b"aA", b"ab"]),
		(b"(a*)*\\1", &[b"b", b"aab"]),
		(b"^(a|b)*\\1$", &[b"abb", b"aba", b"ab"]),
		(b"(a|ab)(c|bcd)(d*)\\3", &[b"abcd", b"abcdd"]),
		(b"()\\1", &[b"x", b""]),
		(b"(a|)\\1b", &[b"b", b"aab", b"ab"]),
		(b"(a){0}\\1", &[b"a", b""]),
		(
			b"(\xc3\xa9)\\1",
			&[b"\xc3\xa9\xc3\x89", b"\xc3\xa9\xc3\xa9"],
		),
		(b"\\(", &[b"(", b"a"]),
		// anchors in {m,n} copies
		(b"(^a?){2}b", &[b"aab", b"ab", b"xab"]),
		(b"(^a)+b", &[b"aab", b"ab", b"b"]),
		(b"(a^){2}", &[b"aa", b"a"]),
		(b"(a?^)+b", &[b"aab", b"b"]),
		(b"x(\\<a?){2,3}b", &[b"xaab", b"x ab"]),
		(b"(^()a){2}", &[b"aa"]),
		(b"(^(a)){2}\\2", &[b"aaa", b"aa"]),
		// a character cut by the end: icase keeps its state
		(b"\xe9\\B", &[b"\xe9\xa9", b"*]\xe9\xa9", b"\xe9\xa9x"]),
		(b"\xa9$", &[b"\xe9\xa9\xa9", b"\xe9\xa9"]),
		(b"\xe9.", &[b"\xe9\xa9", b"\xf0\x90\x80"]),
		(b"a{0}", &[b"", b"b"]),
		(
			b"^\\.pacsave\\.([[:digit:]]+)$",
			&[b".pacsave.12", b".pacsave."],
		),
	];
	for (p, texts) in cases {
		check_all(p, texts);
	}
}

// glibc behaviour worth pinning on the port alone, so a change on either
// side shows up here and not just as a fuzz mismatch
#[test]
fn pinned_quirks() {
	let icase = Flags {
		icase: true,
		newline: true,
	};
	let plain = Flags {
		icase: false,
		newline: false,
	};
	let m = |p: &[u8], f: Flags, t: &[u8]| {
		Regex::new(p, f).unwrap().is_match(t)
	};
	// escaped letters keep their case, the text is upper-cased
	assert!(!m(b"\\d", icase, b"d"));
	assert!(!m(b"\\d", icase, b"D"));
	assert!(m(b"\\D", icase, b"d"));
	// long s upper-cases to S first, then escapes to \S
	assert!(m(b"\\\xc5\xbf", icase, b"x"));
	assert!(!m(b"\\\xc5\xbf", icase, b" "));
	// '$' and '^' around a newline in the pattern without REG_NEWLINE
	assert!(m(b"a$\nb", plain, b"a\nb"));
	assert!(m(b"a\n^b", plain, b"a\nb"));
	assert!(!m(b"a$", plain, b"a\nb"));
	// single-byte mode '.' only checks UTF-8 shape
	assert!(m(b"^.$", plain, b"\xed\xa0\x80"));
	assert!(!m(b"^.$", icase, b"\xed\xa0\x80"));
	// matches may start inside a character in single-byte mode
	assert!(m(b"\xa9", plain, b"\xc3\xa9"));
	assert!(!m(b"\xa9", icase, b"\xc3\xa9"));
	// non-ASCII range ends have no collation value in C.UTF-8
	let e = Regex::new(b"[\xc3\xa0-\xc3\xbc]", icase).unwrap_err();
	assert_eq!(e.code(), 3);
	// reference to a group skipped by {0}
	assert!(!m(b"(a){0}\\1", plain, b"a"));
	// anchors inside {m,n} copies only count in the first instance
	assert!(m(b"(^a)+b", plain, b"aab"));
	assert!(!m(b"(^a)(^a)b", plain, b"aab"));
	// under icase, bytes after a character cut by the end complete it
	assert!(m(b"\xe9\\B", icase, b"\xe9\xa9"));
	assert!(!m(b"\xe9\\B", plain, b"\xe9\xa9"));
}

// glibc's back-reference matcher misses matches when the referenced group
// is repeated; the port takes any assignment that works. the fuzz skips
// these patterns (repeated_backref)
#[test]
fn divergence_repeated_group_backref() {
	let f = Flags {
		icase: false,
		newline: false,
	};
	for (p, t) in [
		(&b"x(a|){2}\\1"[..], &b"xaa"[..]),
		(b"(){2}x\\1", b"x"),
		(b"a(){2}\\1", b"a"),
	] {
		assert_eq!(c_regex(p, cflags(f, true), &[t]), Ok(vec![false]));
		assert!(Regex::new(p, f).unwrap().is_match(t));
	}
}

// glibc regexec with REG_ICASE loses matches in texts holding characters
// whose upper case has another UTF-8 length (U+0131 -> I, U+0250 ->
// U+2C6F): its offset bookkeeping between raw and upper-cased buffer
// goes wrong. the port matches as on the upper-cased text; the fuzz keeps
// these characters out of REG_ICASE texts
#[test]
fn divergence_icase_resized_upper() {
	let f = Flags {
		icase: true,
		newline: true,
	};
	for (p, t) in [
		(&b"B"[..], &b"\xc9\x90b"[..]),
		(b"b$", b"\xc9\x90b"),
		(b"B", b"\xc8\xbf\xc8\xbf\xc8\xbfbxx"),
		(b"[^[:alpha:]]", b"\xe1\xb2\x80\xe2\x82\xac\xc3"),
	] {
		assert_eq!(c_regex(p, cflags(f, true), &[t]), Ok(vec![false]));
		assert!(Regex::new(p, f).unwrap().is_match(t));
	}
	// found when the match starts at the first character
	let _ = check(b"B|\xc9\x90", f, &[b"\xc9\x90b"]);
}

// wide classes code point by code point, through [[:class:]]
#[test]
fn classes_exhaustive() {
	let names: &[&[u8]] = &[
		b"alnum", b"alpha", b"blank", b"cntrl", b"digit", b"graph",
		b"lower", b"print", b"punct", b"space", b"upper", b"xdigit",
	];
	let wcs: Vec<u32> = (1..0x11_0000)
		.filter(|wc| !(0xd800..=0xdfff).contains(wc))
		.collect();
	let texts: Vec<Vec<u8>> = wcs.iter().map(|&wc| utf8(wc)).collect();
	let refs: Vec<&[u8]> = texts.iter().map(|t| &t[..]).collect();
	let plain = Flags {
		icase: false,
		newline: false,
	};
	for name in names {
		let p = [&b"[[:"[..], name, b":]]"].concat();
		let r = rust(&p, plain, &refs).unwrap();
		for (i, &wc) in wcs.iter().enumerate() {
			assert_eq!(
				r[i],
				c_iswctype(name, wc),
				"{} U+{wc:04X}",
				show(name)
			);
		}
		// and the C regex agrees with iswctype
		let c = c_regex(&p, cflags(plain, true), &refs).unwrap();
		assert_eq!(c, r, "{}", show(name));
	}
	// iswctype is false past U+10FFFF, 4 to 6 byte forms there
	for wc in [0x11_0000, 0x1f_ffff, 0x20_0000, 0x400_0000, 0x7fff_ffff] {
		for name in names {
			assert!(!c_iswctype(name, wc));
		}
		let t = utf8(wc);
		check_all(b"[^a]", &[&t]);
		check_all(b"[[:alpha:]]", &[&t]);
	}
}

// towupper code point by code point: a REG_ICASE pattern of the expected
// upper-case bytes, kept apart by "()" so they are not decoded again,
// must match the character exactly
#[test]
fn towupper_exhaustive() {
	let f = Flags {
		icase: true,
		newline: false,
	};
	let mut mapped = 0;
	for wc in 1..0x11_0000 {
		if (0xd800..=0xdfff).contains(&wc) {
			continue;
		}
		let up = c_towupper(wc);
		mapped += usize::from(up != wc);
		let t = utf8(wc);
		let mut p = b"^".to_vec();
		let lit = utf8(up);
		if lit[0].is_ascii_punctuation() && !b"<>`'".contains(&lit[0]) {
			p.push(b'\\');
		}
		for (i, &b) in lit.iter().enumerate() {
			if i > 0 {
				p.extend(b"()");
			}
			p.push(b);
		}
		p.push(b'$');
		let re = Regex::new(&p, f).unwrap();
		assert!(re.is_match(&t), "U+{wc:04X} -> U+{up:04X}");
	}
	assert!(mapped > 1000, "{mapped}");
	for wc in [0x11_0000, 0x7fff_ffff] {
		assert_eq!(c_towupper(wc), wc);
	}
}

// glibc UTF-8, 5 and 6 byte forms included
fn utf8(wc: u32) -> Vec<u8> {
	if wc < 0x80 {
		return vec![wc as u8];
	}
	let n = match wc {
		0x80..0x800 => 2,
		0x800..0x1_0000 => 3,
		0x1_0000..0x20_0000 => 4,
		0x20_0000..0x400_0000 => 5,
		_ => 6,
	};
	let lead = [0, 0, 0xc0u8, 0xe0, 0xf0, 0xf8, 0xfc][n];
	let mut v = vec![lead | (wc >> (6 * (n - 1))) as u8];
	for k in (0..n - 1).rev() {
		v.push(0x80 | (wc >> (6 * k) & 0x3f) as u8);
	}
	v
}

// pattern pieces the C parses specially, plus multibyte, invalid and
// case-changing characters
const TOKENS: &[&[u8]] = &[
	b"a",
	b"b",
	b"A",
	b"B",
	b"x",
	b"_",
	b"0",
	b"1",
	b" ",
	b"\n",
	b"-",
	b",",
	b":",
	b"=",
	b"\xc3\xa9",
	b"\xc3\x89",
	b"\xc3\x9f",
	b"\xc4\xb1",
	b"\xc5\xbf",
	b"\xe2\x82\xac",
	b"\xe9",
	b"\xc3",
	b"\xa9",
	b"\xff",
	b"\xed\xa0\x80",
	b".",
	b"*",
	b"+",
	b"?",
	b"|",
	b"(",
	b")",
	b"()",
	b"^",
	b"$",
	b"{",
	b"}",
	b"{0}",
	b"{1}",
	b"{2}",
	b"{0,1}",
	b"{1,2}",
	b"{,2}",
	b"{2,}",
	b"{1,3}",
	b"[",
	b"]",
	b"[^",
	b"[a-z]",
	b"[^a]",
	b"[ab]",
	b"[]a]",
	b"[^]",
	b"[a-]",
	b"[:alpha:]",
	b"[:upper:]",
	b"[:lower:]",
	b"[:space:]",
	b"[:punct:]",
	b"[:digit:]",
	b"[:alnum:]",
	b"[[:alpha:]]",
	b"[[:upper:]]",
	b"[[:lower:]]",
	b"[^[:alpha:]]",
	b"[=a=]",
	b"[.a.]",
	b"[.-.]",
	b"[\xc3\xa9]",
	b"[^\xc3\xa9]",
	b"[a-\xff]",
	b"\\",
	b"\\1",
	b"\\2",
	b"\\w",
	b"\\W",
	b"\\s",
	b"\\S",
	b"\\b",
	b"\\B",
	b"\\<",
	b"\\>",
	b"\\`",
	b"\\'",
	b"\\.",
	b"\\a",
	b"\\A",
	b"\\(",
	b"\\{",
	b"\\,",
	b"\\\xc3\xa9",
	b"(a)",
	b"(a|b)",
	b"(.)",
	b"(a*)",
];

// text characters: the pattern literals, their other cases, specials.
// REG_ICASE texts leave out RESIZED (see the divergence test above)
const TEXT_TOKENS: &[&[u8]] = &[
	b"a",
	b"b",
	b"A",
	b"B",
	b"x",
	b"X",
	b"_",
	b"0",
	b"1",
	b" ",
	b"\n",
	b"\t",
	b"-",
	b",",
	b".",
	b"(",
	b"[",
	b"]",
	b"*",
	b"\\",
	b"\xc3\xa9",
	b"\xc3\x89",
	b"\xc3\x9f",
	b"\xe1\xba\x9e",
	b"i",
	b"I",
	b"s",
	b"S",
	b"\xe2\x82\xac",
	b"\xe9",
	b"\xc3",
	b"\xa9",
	b"\xff",
	b"\xed\xa0\x80",
	b"\xe3\x80\x80",
	b"\xc2\xa0",
	b"\xc2\xa7",
	b"\xf4\x90\x80\x80",
	b"\xf8\x88\x80\x80\x80",
];

// upper case changes the UTF-8 length: dotless i, long s, U+1C80, U+1FBE,
// U+2C65, U+0250, U+023F
const RESIZED: &[&[u8]] = &[
	b"\xc4\xb1",
	b"\xc5\xbf",
	b"\xe1\xb2\x80",
	b"\xe1\xbe\xbe",
	b"\xe2\xb1\xa5",
	b"\xc9\x90",
	b"\xc8\xbf",
];

fn join(rng: &mut Rng, tokens: &[&[u8]], max: usize) -> Vec<u8> {
	(0..rng.below(max))
		.flat_map(|_| tokens[rng.below(tokens.len())].iter().copied())
		.collect()
}

// one pattern against several texts per flag set, counts compiled
// patterns and matches so a broken generator shows
fn fuzz(seed: u64, gen_pattern: impl Fn(&mut Rng) -> Vec<u8>) {
	let mut rng = Rng::new(seed);
	let (mut compiled, mut matched, mut texts_run) = (0, 0, 0);
	let text_tokens: Vec<&[u8]> = TEXT_TOKENS.to_vec();
	let plain_tokens: Vec<&[u8]> = [TEXT_TOKENS, RESIZED].concat();
	let mut i = 0;
	while i < iters() / 4 {
		let p = gen_pattern(&mut rng);
		let f = FLAGS[i % 4];
		if repeated_backref(&p) || !f.newline && newline_backref(&p) {
			continue;
		}
		i += 1;
		let tokens = if f.icase { &text_tokens } else { &plain_tokens };
		let mut texts: Vec<Vec<u8>> =
			(0..4).map(|_| join(&mut rng, tokens, 7)).collect();
		// the pattern itself, minus what an icase text may not hold
		if !f.icase || !RESIZED.iter().any(|g| contains(&p, g)) {
			texts.push(p.clone());
		}
		let refs: Vec<&[u8]> = texts.iter().map(|t| &t[..]).collect();
		if let Ok(r) = check(&p, f, &refs) {
			compiled += 1;
			texts_run += r.len();
			matched += r.iter().filter(|&&m| m).count();
		}
	}
	let n = iters() / 4;
	assert!(compiled > n / 10, "only {compiled} of {n} compiled");
	assert!(
		matched > texts_run / 20,
		"only {matched} of {texts_run} matched"
	);
	assert!(
		matched < texts_run * 19 / 20,
		"{matched} of {texts_run} matched"
	);
}

// glibc's back-reference matcher misbehaves under repetition: a
// reference under stacked repetitions recurses without bound ("(a*)\\1+*"
// overflows the stack) or turns exponential ("(.)**{1,2}\\1"), and
// references to a repeated group miss matches ("x(a|){2}\\1" against
// "xaa"). patterns with a reference and a repeated group or stacked
// repetitions are skipped
fn repeated_backref(p: &[u8]) -> bool {
	let backref =
		p.windows(2).any(|w| w[0] == b'\\' && w[1].is_ascii_digit());
	let mut reps = 0;
	let mut after_group = false;
	let mut i = 0;
	while i < p.len() {
		let c = p[i];
		match c {
			b'\\' => {
				reps = 0;
				i += 1;
			}
			b')' => {}
			b'*' | b'+' | b'?' | b'{' => {
				reps += 1;
				if after_group && backref {
					return true;
				}
				if c == b'{' {
					let n = p[i..]
						.iter()
						.position(|&c| c == b'}');
					i += n.unwrap_or(0);
				}
			}
			_ => reps = 0,
		}
		after_group = c == b')' || after_group && reps > 0;
		if backref && reps >= 2 {
			return true;
		}
		i += 1;
	}
	false
}

// without REG_NEWLINE an anchor after a '\n' byte holds through glibc's
// transition table but not where back-reference processing re-derives
// the state; the port only follows the simple cases of this, so
// back-references next to '^' or '$' are compared under REG_NEWLINE only
fn newline_backref(p: &[u8]) -> bool {
	let backref =
		p.windows(2).any(|w| w[0] == b'\\' && w[1].is_ascii_digit());
	backref && (p.contains(&b'^') || p.contains(&b'$'))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
	hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn fuzz_tokens() {
	fuzz(0x7e6e, |rng| join(rng, TOKENS, 7));
}

// raw syntax bytes, mostly the error paths
#[test]
fn fuzz_raw_syntax() {
	let alphabet: &[&[u8]] = &[
		b"(",
		b")",
		b"[",
		b"]",
		b"{",
		b"}",
		b"|",
		b"*",
		b"+",
		b"?",
		b".",
		b"^",
		b"$",
		b"\\",
		b"-",
		b",",
		b"0",
		b"1",
		b"2",
		b":",
		b"=",
		b"a",
		b"b",
		b"\xc3\xa9",
	];
	fuzz(0x5a11, |rng| join(rng, alphabet, 10));
}

// bracket expressions built piece by piece
#[test]
fn fuzz_brackets() {
	let inner: &[&[u8]] = &[
		b"a",
		b"z",
		b"A",
		b"Z",
		b"-",
		b"]",
		b"^",
		b"[",
		b"\\",
		b"_",
		b"0",
		b"9",
		b"\n",
		b".",
		b":",
		b"=",
		b"\xc3\xa9",
		b"\xc3\x89",
		b"\xe9",
		b"\xff",
		b"\xe2\x82\xac",
		b"a-z",
		b"A-Z",
		b"0-9",
		b"a-\xff",
		b"\x7f-\xff",
		b"z-a",
		b"[:alpha:]",
		b"[:upper:]",
		b"[:lower:]",
		b"[:space:]",
		b"[:punct:]",
		b"[:print:]",
		b"[:graph:]",
		b"[:cntrl:]",
		b"[:blank:]",
		b"[:xdigit:]",
		b"[:alnum:]",
		b"[:digit:]",
		b"[:foo:]",
		b"[=a=]",
		b"[=\xe9=]",
		b"[.a.]",
		b"[.-.]",
		b"[.].]",
		b"[.ab.]",
		b"[.",
		b"[=",
		b"[:",
	];
	let outer: &[&[u8]] = &[b"", b"", b"a", b"^", b"$", b"*", b"+", b"{2}"];
	fuzz(0xb4ac, |rng| {
		let mut p = outer[rng.below(outer.len())].to_vec();
		p.push(b'[');
		if rng.below(3) == 0 {
			p.push(b'^');
		}
		p.extend(join(rng, inner, 5));
		if rng.below(6) != 0 {
			p.push(b']');
		}
		p.extend(outer[rng.below(outer.len())]);
		p
	});
}

// groups, alternation and back-references, short so glibc stays fast
#[test]
fn fuzz_backrefs() {
	let pieces: &[&[u8]] = &[
		b"(",
		b")",
		b"|",
		b"a",
		b"b",
		b"A",
		b"\xc3\xa9",
		b".",
		b"*",
		b"+",
		b"?",
		b"{1,2}",
		b"\\1",
		b"\\2",
		b"^",
		b"$",
		b"\n",
		b"()",
		b"(a)",
		b"(a|b)",
		b"(a*)",
		b"(.)",
		b"\\b",
		b"\\<",
		b"[^a]",
	];
	fuzz(0xbac7, |rng| {
		let mut p = join(rng, pieces, 6);
		// at least one reference most of the time
		if rng.below(4) != 0 {
			let at = rng.below(p.len() + 1);
			p.splice(at..at, *b"\\1");
		}
		p
	});
}
