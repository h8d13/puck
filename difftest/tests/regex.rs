// alpm_core::regex against glibc regcomp/regexec in C.UTF-8
//
// pattern sizes stay small (a few tokens, {m,n} bounds up to 3): glibc's
// back-reference matcher and its node duplication grow fast, the fuzz
// keeps out of the inputs where glibc itself takes seconds or gigabytes
use std::collections::HashMap;
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
		(b"[[:space:]]", &[b"\xe3\x80\x80", b"\xc2\xa7", b"\t"]),
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

const CLASSES: [&[u8]; 12] = [
	b"alnum", b"alpha", b"blank", b"cntrl", b"digit", b"graph", b"lower",
	b"print", b"punct", b"space", b"upper", b"xdigit",
];

const PLAIN: Flags = Flags {
	icase: false,
	newline: false,
};

const ICASE: Flags = Flags {
	icase: true,
	newline: false,
};

// glibc 2.44 C.UTF-8 iswctype against the port's std classes over every
// code point, through [[:class:]] in the port. counts are the measured
// ones and may only shrink, any other difference is a new class
struct ClassDiv {
	class: &'static [u8],
	glibc: bool,
	measured: usize,
	example: u32,
}

const fn div(
	class: &'static [u8],
	glibc: bool,
	measured: usize,
	example: u32,
) -> ClassDiv {
	ClassDiv {
		class,
		glibc,
		measured,
		example,
	}
}

const CLASS_DIVERGENCE: &[ClassDiv] = &[
	// decimal digits past ASCII (Nd, U+0660 ...): alpha in glibc, not
	// Alphabetic in std
	div(b"alpha", true, 760, 0x660),
	div(b"alnum", true, 760, 0x660),
	// no-break spaces U+00A0, U+2007, U+202F: White_Space in std, graph
	// and punct in glibc
	div(b"blank", false, 3, 0xa0),
	div(b"graph", true, 3, 0xa0),
	div(b"punct", true, 3, 0x202f),
	// the no-break spaces and U+0085 (NEL, White_Space)
	div(b"space", false, 4, 0x85),
	// unassigned code points: std has no general category, the port
	// takes them as graph (so print, and punct as they are not alnum)
	div(b"graph", false, 814_730, 0x378),
	div(b"print", false, 814_730, 0x10_fffe),
	// the unassigned ones and the Nd digits (graph, not alnum)
	div(b"punct", false, 815_490, 0x660),
	// U+2028/2029 (Zl, Zp): cntrl in glibc, not Cc
	div(b"cntrl", true, 2, 0x2029),
	// titlecase letters (Lt, U+01C5, U+1F88 ...): upper in glibc, lower
	// too for the four Latin digraphs, neither in std
	div(b"upper", true, 31, 0x1f88),
	div(b"lower", true, 4, 0x1c5),
];

// every character as one-character texts, the C string end left out
fn all_chars() -> (Vec<u32>, Vec<Vec<u8>>) {
	let wcs: Vec<u32> = (1..0x11_0000)
		.filter(|wc| !(0xd800..=0xdfff).contains(wc))
		.collect();
	let texts = wcs.iter().map(|&wc| utf8(wc)).collect();
	(wcs, texts)
}

fn class_pattern(name: &[u8]) -> Vec<u8> {
	[&b"[[:"[..], name, b":]]"].concat()
}

#[test]
fn class_divergence() {
	let (wcs, texts) = all_chars();
	let refs: Vec<&[u8]> = texts.iter().map(|t| &t[..]).collect();
	let mut counts = vec![0usize; CLASS_DIVERGENCE.len()];
	for name in CLASSES {
		let p = class_pattern(name);
		let r = rust(&p, PLAIN, &refs).unwrap();
		for (i, &wc) in wcs.iter().enumerate() {
			let glibc = c_iswctype(name, wc);
			if r[i] == glibc {
				continue;
			}
			assert!(wc >= 0x80, "{} U+{wc:04X}", show(name));
			let k = CLASS_DIVERGENCE
				.iter()
				.position(|d| {
					d.class == name && d.glibc == glibc
				})
				.unwrap_or_else(|| {
					panic!(
						"{} U+{wc:04X}: glibc {glibc}",
						show(name)
					)
				});
			counts[k] += 1;
		}
		// the C regex takes iswctype, the reference above
		let c = c_regex(&p, cflags(PLAIN, true), &refs).unwrap();
		for (i, &wc) in wcs.iter().enumerate() {
			assert_eq!(c[i], c_iswctype(name, wc), "U+{wc:04X}");
		}
	}
	for (d, n) in CLASS_DIVERGENCE.iter().zip(counts) {
		let what = format!("{} glibc {}", show(d.class), d.glibc);
		println!("{what}: {n} (measured {})", d.measured);
		assert!(n <= d.measured, "{what}: {n} > {}", d.measured);
		let t = utf8(d.example);
		let r = rust(&class_pattern(d.class), PLAIN, &[&t]).unwrap();
		assert_eq!(c_iswctype(d.class, d.example), d.glibc, "{what}");
		assert_eq!(r, [!d.glibc], "{what} U+{:04X}", d.example);
	}
	// iswctype is false past U+10FFFF, 4 to 6 byte forms there
	for wc in [0x11_0000, 0x1f_ffff, 0x20_0000, 0x400_0000, 0x7fff_ffff] {
		for name in CLASSES {
			assert!(!c_iswctype(name, wc));
		}
		let t = utf8(wc);
		check_all(b"[^a]", &[&t]);
		check_all(b"[[:alpha:]]", &[&t]);
	}
}

// a REG_ICASE pattern of the upper-case bytes, kept apart by "()" so they
// are not decoded (and upper-cased) again: matches the character exactly
// when the port upper-cases it to up
fn upper_pattern(up: u32) -> Vec<u8> {
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
	p
}

fn port_upper_is(wc: u32, up: u32) -> bool {
	Regex::new(&upper_pattern(up), ICASE)
		.unwrap()
		.is_match(&utf8(wc))
}

// towupper against the port code point by code point. glibc takes the
// simple mapping where std's full upper case is several chars and the
// port keeps the char: the Greek letters with ypogegrammeni (U+1F80-1FAF
// lowercase, U+1FB3, U+1FC3, U+1FF3 -> U+1FBC ...). ß, ŉ, ǰ and the
// ligatures have no simple mapping, unchanged on both sides
const UPPER_MULTI: usize = 27;

#[test]
fn towupper_divergence() {
	let (mut mapped, mut multi) = (0, 0);
	for wc in all_chars().0 {
		let up = c_towupper(wc);
		mapped += usize::from(up != wc);
		if port_upper_is(wc, up) {
			continue;
		}
		let c = char::from_u32(wc).unwrap();
		assert!(
			port_upper_is(wc, wc) && c.to_uppercase().len() > 1,
			"U+{wc:04X}: glibc U+{up:04X}, new class"
		);
		multi += 1;
	}
	println!("towupper: {multi} (measured {UPPER_MULTI})");
	assert!(multi <= UPPER_MULTI, "{multi} > {UPPER_MULTI}");
	assert!(mapped > 1000, "{mapped}");
	assert_eq!(c_towupper(0x1fb3), 0x1fbc);
	assert!(port_upper_is(0x1fb3, 0x1fb3));
	for wc in [0x11_0000, 0x7fff_ffff] {
		assert_eq!(c_towupper(wc), wc);
	}
}

// the divergent classes in regexes: the C on glibc's tables, the port on
// std's. the fuzz keeps these characters out where the pattern asks
#[test]
fn divergence_classes_pinned() {
	// pattern, flags, text, glibc's match; the port's is the opposite
	let cases: &[(&[u8], Flags, &str, bool)] = &[
		(b"[[:alpha:]]", PLAIN, "\u{660}", true),
		(b"\\w", PLAIN, "\u{660}", true),
		(b"\\bx", PLAIN, "\u{660}x", false),
		(b"[[:punct:]]", PLAIN, "\u{660}", false),
		(b"[[:space:]]", PLAIN, "\u{a0}", false),
		(b"\\s", ICASE, "\u{202f}", false),
		(b"[[:blank:]]", PLAIN, "\u{2007}", false),
		(b"[[:punct:]]", PLAIN, "\u{a0}", true),
		(b"[[:space:]]", PLAIN, "\u{85}", false),
		(b"[[:graph:]]", PLAIN, "\u{378}", false),
		(b"[^[:print:]]", PLAIN, "\u{378}", true),
		(b"[[:cntrl:]]", PLAIN, "\u{2028}", true),
		(b"[[:upper:]]", PLAIN, "\u{1c5}", true),
		(b"[[:lower:]]", PLAIN, "\u{1c8}", true),
		(b"[[:upper:]]", PLAIN, "\u{1fbc}", true),
		(b"\xe1\xbe\xbc", ICASE, "\u{1fb3}", true),
		(b"\xe1\xbe\xb3", ICASE, "\u{1fbc}", true),
	];
	for &(p, f, t, c) in cases {
		let t = t.as_bytes();
		let what = format!("{} {f:?} {}", show(p), show(t));
		assert_eq!(
			c_regex(p, cflags(f, true), &[t]),
			Ok(vec![c]),
			"{what}"
		);
		assert_eq!(rust(p, f, &[t]), Ok(vec![!c]), "{what}");
	}
	// U+1F80 keeps its case in the port, so still matches itself
	let _ = check("\u{1f80}".as_bytes(), ICASE, &["\u{1f80}".as_bytes()]);
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
	b"\xd9\xa0",
	b"\xe1\xbe\xb3",
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
	// classes or towupper differ (class_divergence, towupper_divergence):
	// U+0660, U+0085, U+2028, U+0378, U+01C5, U+1FB3, U+1FBC
	b"\xd9\xa0",
	b"\xc2\x85",
	b"\xe2\x80\xa8",
	b"\xcd\xb8",
	b"\xc7\x85",
	b"\xe1\xbe\xb3",
	b"\xe1\xbe\xbc",
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

// per character, cached: the port and glibc agree on every class (of the
// character and of its glibc upper case) and on towupper. lone invalid
// bytes are left out: classes only take characters of 2 bytes or more,
// and as word context the Latin-1 values agree (U+0085, U+00A0 are no
// word characters on either side)
#[derive(Default)]
struct Agree {
	seen: HashMap<u32, (bool, bool)>,
	compared: usize,
	skipped: usize,
}

impl Agree {
	fn char(&mut self, wc: u32) -> (bool, bool) {
		*self.seen.entry(wc).or_insert_with(|| {
			let up = c_towupper(wc);
			let classes = [wc, up].iter().all(|&w| {
				let t = utf8(w);
				CLASSES.iter().all(|name| {
					let p = class_pattern(name);
					rust(&p, PLAIN, &[&t]).unwrap()[0]
						== c_iswctype(name, w)
				})
			});
			(classes, port_upper_is(wc, up))
		})
	}

	// what p asks of the characters of s: classes where it names one or
	// has an escape (\w \s \b, or an escaped long s, upper-cased to \S),
	// towupper under REG_ICASE
	fn holds(&mut self, p: &[u8], f: Flags, s: &[u8]) -> bool {
		let classes = contains(p, b"[:") || p.contains(&b'\\');
		String::from_utf8_lossy(s).chars().all(|c| {
			let (cl, up) = self.char(u32::from(c));
			(cl || !classes) && (up || !f.icase)
		})
	}

	// the texts p may be compared on, the pattern's own characters first
	fn filter(&mut self, p: &[u8], f: Flags, texts: &mut Vec<Vec<u8>>) {
		let n = texts.len();
		if self.holds(p, f, p) {
			texts.retain(|t| self.holds(p, f, t));
		} else {
			texts.clear();
		}
		self.compared += texts.len();
		self.skipped += n - texts.len();
	}

	// at least 560 per 1000 texts compared, about 3/4 of the lowest
	// share measured with 2000000 iterations (756 in fuzz_backrefs, up
	// to 928 in fuzz_raw_syntax)
	fn finish(&self, seed: u64) {
		const FLOOR: usize = 560;
		let n = self.compared + self.skipped;
		println!("fuzz {seed:x}: compared {} of {n}", self.compared);
		assert!(
			self.compared * 1000 >= n * FLOOR,
			"fuzz {seed:x}: compared {} of {n}",
			self.compared
		);
	}
}

// one pattern against several texts per flag set, counts compiled
// patterns and matches so a broken generator shows
fn fuzz(seed: u64, gen_pattern: impl Fn(&mut Rng) -> Vec<u8>) {
	let mut rng = Rng::new(seed);
	let mut agree = Agree::default();
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
		agree.filter(&p, f, &mut texts);
		let refs: Vec<&[u8]> = texts.iter().map(|t| &t[..]).collect();
		if let Ok(r) = check(&p, f, &refs) {
			compiled += 1;
			texts_run += r.len();
			matched += r.iter().filter(|&&m| m).count();
		}
	}
	agree.finish(seed);
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
		b"\xd9\xa0",
		b"\xc2\xa0",
		b"\xe2\x80\xa8",
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
