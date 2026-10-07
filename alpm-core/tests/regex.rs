// unit tests for alpm_core::regex, glibc itself is compared elsewhere
use alpm_core::regex::{Error, Flags, Regex};

// pacman's -Ss/-Fx flags, and remove.c's
const SEARCH: Flags = Flags {
	icase: true,
	newline: true,
};
const PACSAVE: Flags = Flags {
	icase: false,
	newline: true,
};

fn m(p: &[u8], f: Flags, t: &[u8]) -> bool {
	Regex::new(p, f).unwrap().is_match(t)
}

fn err(p: &[u8]) -> Error {
	Regex::new(p, PACSAVE).unwrap_err()
}

#[test]
fn errors() {
	assert_eq!(err(b"["), Error::BadPattern);
	assert_eq!(err(b"[a"), Error::Bracket);
	assert_eq!(err(b"(a"), Error::Paren);
	assert_eq!(err(b"a{1"), Error::Brace);
	assert_eq!(err(b"a{2,1}"), Error::BadBrace);
	assert_eq!(err(b"[z-a]"), Error::Range);
	assert_eq!(err(b"[[:foo:]]"), Error::Ctype);
	assert_eq!(err(b"[[.ab.]]"), Error::Collate);
	assert_eq!(err(b"\\"), Error::Escape);
	assert_eq!(err(b"\\1"), Error::Subreg);
	assert_eq!(err(b"*a"), Error::Repeat);
	assert_eq!(err(b"a{32768}"), Error::Size);
	assert_eq!(err(b"(a{1000}){1000}{1000}"), Error::Space);
	assert_eq!(Error::Repeat.code(), 13);
	// unmatched ')' is a literal
	assert!(m(b"a)", PACSAVE, b"a)"));
}

#[test]
fn basics() {
	assert!(m(b"", PACSAVE, b""));
	assert!(m(b"b|c", PACSAVE, b"abc"));
	assert!(!m(b"^b", PACSAVE, b"abc"));
	assert!(m(b"^(ab|a)c$", PACSAVE, b"abc"));
	assert!(m(b"^a{2,3}$", PACSAVE, b"aaa"));
	assert!(!m(b"^a{2,3}$", PACSAVE, b"aaaa"));
	assert!(m(b"[[:digit:]]+$", PACSAVE, b"x.pacsave.12"));
	// C strings: the text ends at a nul
	assert!(!m(b"b", PACSAVE, b"a\0b"));
}

#[test]
fn newline_flag() {
	let plain = Flags {
		icase: false,
		newline: false,
	};
	assert!(m(b"^b", PACSAVE, b"a\nb"));
	assert!(!m(b"^b", plain, b"a\nb"));
	assert!(!m(b"a.b", PACSAVE, b"a\nb"));
	assert!(m(b"a.b", plain, b"a\nb"));
	assert!(!m(b"a[^x]b", PACSAVE, b"a\nb"));
	assert!(m(b"a$", PACSAVE, b"a\nb"));
}

#[test]
fn icase_and_utf8() {
	assert!(m(b"PACMAN", SEARCH, b"pacman"));
	assert!(m(b"\xc3\xa9t\xc3\xa9", SEARCH, b"\xc3\x89T\xc3\x89"));
	assert!(m(b"^.$", SEARCH, b"\xe2\x82\xac"));
	assert!(m(b"[[:lower:]]", SEARCH, b"A"));
	// invalid bytes only match themselves
	assert!(!m(b"^.$", SEARCH, b"\xff"));
	assert!(m(b"\xff", SEARCH, b"\xff"));
	assert!(!m(b"\\d", SEARCH, b"d"));
}

#[test]
fn backrefs() {
	assert!(m(b"^(a+)b\\1$", PACSAVE, b"aabaa"));
	assert!(!m(b"^(a+)b\\1$", PACSAVE, b"aaba"));
	assert!(m(b"(\xc3\xa9)\\1", SEARCH, b"\xc3\xa9\xc3\x89"));
}

// linear in the text: a pattern that backtracks exponentially elsewhere
#[test]
fn no_blowup() {
	let text = vec![b'a'; 100_000];
	assert!(!m(b"(a*)*(b|c)", PACSAVE, &text));
	assert!(m(b"(a|aa)*$", PACSAVE, &text));
	let p = [&b"(a?){30}"[..], &[b'a'; 30]].concat();
	assert!(m(&p, PACSAVE, &[b'a'; 30]));
}

// classes and upper case on std's Unicode properties
#[test]
fn std_classes() {
	assert!(m(b"^[[:alpha:]]$", PACSAVE, "\u{3b1}".as_bytes()));
	assert!(!m(b"[[:digit:]]", PACSAVE, "\u{660}".as_bytes()));
	assert!(m(b"^[[:punct:]]$", PACSAVE, "\u{20ac}".as_bytes()));
	assert!(m(b"^\\s$", PACSAVE, "\u{3000}".as_bytes()));
	assert!(m(b"^[[:blank:]]$", PACSAVE, "\u{a0}".as_bytes()));
	assert!(!m(b"[[:blank:]]", PACSAVE, "\u{2028}".as_bytes()));
	assert!(m(b"^[[:cntrl:]]$", PACSAVE, "\u{85}".as_bytes()));
	assert!(m(b"^[[:print:]]$", PACSAVE, "\u{a0}".as_bytes()));
	assert!(!m(b"[[:graph:]]", PACSAVE, "\u{a0}".as_bytes()));
	// upper case only where std gives one char: ß and U+1FB3 stay
	assert!(m("\u{3a3}".as_bytes(), SEARCH, "\u{3c3}".as_bytes()));
	assert!(!m(b"SS", SEARCH, "\u{df}".as_bytes()));
	assert!(!m("\u{1fbc}".as_bytes(), SEARCH, "\u{1fb3}".as_bytes()));
}
