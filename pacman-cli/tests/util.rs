// unit tests for pacman_cli::util
use pacman_cli::util::*;

fn indent(s: &[u8], indent: u16, cols: u16) -> Vec<u8> {
	let mut out = Vec::new();
	indentprint(&mut out, s, indent, cols);
	out
}

#[test]
fn width_cases() {
	assert_eq!(wcwidth('a' as u32), 1);
	assert_eq!(wcwidth(0), 0);
	assert_eq!(wcwidth('\t' as u32), -1);
	assert_eq!(wcwidth(0x301), 0);
	assert_eq!(wcwidth(0x3042), 2);
	// C1 controls, surrogates, past U+10FFFF: -1 like glibc
	assert_eq!(wcwidth(0x85), -1);
	assert_eq!(wcwidth(0xd800), -1);
	assert_eq!(wcwidth(0x11_0000), -1);
	assert_eq!(string_length(b"abc"), 3);
	assert_eq!(string_length("\u{3042}e\u{301}".as_bytes()), 3);
	assert_eq!(string_length(b"\x1b[1;32mab\x1b[0m"), 2);
	// broken sequence stays, ESC itself is not printable
	assert_eq!(string_length(b"\x1b[mab\x1b[0m"), usize::MAX);
	assert_eq!(string_length(b"a\tb"), usize::MAX);
	// invalid tail not counted
	assert_eq!(string_length(b"ab\xffcd"), 2);
	assert_eq!(string_length(b""), 0);
}

#[test]
fn mbstowcs_cases() {
	assert_eq!(mbstowcs("a\u{e9}".as_bytes()), (vec![0x61, 0xe9], true));
	assert_eq!(mbstowcs(b"a\xc3"), (vec![0x61], false));
	// overlong and surrogate rejected, 5 byte form accepted
	assert_eq!(mbstowcs(b"\xc0\xaf"), (vec![], false));
	assert_eq!(mbstowcs(b"\xed\xa0\x80"), (vec![], false));
	assert_eq!(mbstowcs(b"\xf8\x88\x80\x80\x80"), (vec![0x20_0000], true));
}

#[test]
fn indentprint_cases() {
	assert_eq!(indent(b"aaa bbb ccc", 2, 10), b"aaa bbb\n  ccc");
	// space runs collapse
	assert_eq!(indent(b"a   b", 0, 80), b"a b");
	// trailing space kept, it has an empty word after it
	assert_eq!(indent(b"a ", 0, 80), b"a ");
	// not a tty, or indent past cols: as is
	assert_eq!(indent(b"a   b", 0, 0), b"a   b");
	assert_eq!(indent(b"a   b", 5, 4), b"a   b");
	// invalid tail dropped
	assert_eq!(indent(b"ab\xffcd", 0, 80), b"ab");
}

#[test]
fn strreplace_cases() {
	assert_eq!(strreplace(b"%n-%v", b"%n", b"pacman"), b"pacman-%v");
	assert_eq!(strreplace(b"aaa", b"aa", b"b"), b"ba");
	assert_eq!(strreplace(b"abc", b"x", b"y"), b"abc");
	assert_eq!(strreplace(b"abc", b"b", b""), b"ac");
	assert_eq!(strreplace(b"abc", b"", b"y"), b"abc");
}

#[test]
fn display_cases() {
	let c = ColStr::default();
	let mut out = Vec::new();
	string_display(&mut out, Some(b"Name"), b"", 80, &c);
	assert_eq!(out, b"Name None\n");

	out.clear();
	list_display(&mut out, Some(b"T"), &[b"aa", b"bb", b"cc"], 9, &c);
	assert_eq!(out, b"T aa  bb\n  cc\n");

	out.clear();
	let empty: [&[u8]; 0] = [];
	list_display(&mut out, None, &empty, 80, &c);
	assert_eq!(out, b"None\n");

	out.clear();
	list_display_linebreak(&mut out, Some(b"T"), &[b"a", b"b"], 80, &c);
	assert_eq!(out, b"T a\n  b\n");

	let bold = ColStr {
		title: b"<",
		nocolor: b">",
		..ColStr::default()
	};
	out.clear();
	let sig = SigResult {
		status: SigStatus::KeyUnknown,
		validity: SigValidity::Unknown,
		uid: None,
		fingerprint: b"ABCD".to_vec(),
	};
	signature_display(&mut out, Some(b"Sig"), &[sig], 80, &bold);
	assert_eq!(out, b"<Sig> Key unknown, unknown trust from \"ABCD\"\n");

	out.clear();
	signature_display(&mut out, None, &[], 80, &c);
	assert_eq!(out, b"None");
}

#[test]
fn humanize_size_cases() {
	assert_eq!(humanize_size(2048, 0, -1), (2048.0, "B"));
	assert_eq!(humanize_size(2049, 0, -1), (2049.0 / 1024.0, "KiB"));
	assert_eq!(humanize_size(1 << 20, b'M', 2), (1.0, "MiB"));
	assert_eq!(humanize_size(1 << 20, b'x', 2).1, "YiB");
	// would print -0.00
	assert_eq!(humanize_size(-1, b'M', 2), (0.0, "MiB"));
	assert!(humanize_size(-1, b'M', -1).0 < 0.0);
}

#[test]
fn arg_and_console_cases() {
	assert_eq!(
		arg_to_string(&[&b"-S"[..], b"pacman"]),
		Some(b"-S pacman".to_vec())
	);
	let none: [&[u8]; 0] = [];
	assert_eq!(arg_to_string(&none), None);
	let mut out = Vec::new();
	console_cursor_move_up(&mut out, 3);
	console_cursor_move_down(&mut out, 1);
	console_erase_line(&mut out);
	assert_eq!(out, b"\x1b[3F\x1b[1E\x1b[K");
}
