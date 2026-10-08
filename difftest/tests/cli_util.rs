// pacman_cli::util against src/pacman/util.c, both sides in C.UTF-8
use difftest::{
	Rng, c_arg_to_string, c_console_cursor_move_down,
	c_console_cursor_move_up, c_console_erase_line, c_humanize_size,
	c_indentprint, c_list_display, c_list_display_linebreak, c_mbstowcs,
	c_signature_display, c_string_display, c_strreplace, c_wcwidth,
	getcols_both, iters, string_length_in_bounds, widths_agree,
};
use pacman_cli::util::{
	ColStr, SigResult, SigStatus, SigValidity, arg_to_string,
	console_cursor_move_down, console_cursor_move_up, console_erase_line,
	getcols, humanize_size, indentprint, list_display,
	list_display_linebreak, mbstowcs, signature_display, string_display,
	strreplace, wcwidth,
};

// pieces of display text: words, space runs, wide (2), combining (0),
// non printable (-1: tab, past U+10FFFF; unassigned, where unicode-width
// differs: skipped, see Cover), invalid or truncated UTF-8, colour
// sequences whole and broken
const TOKENS: &[&[u8]] = &[
	b"a",
	b"bc",
	b"defgh",
	b" ",
	b" ",
	b"  ",
	"\u{3042}".as_bytes(),
	"\u{1f600}".as_bytes(),
	"e\u{301}".as_bytes(),
	b"\t",
	"\u{378}".as_bytes(),
	b"\xf8\x88\x80\x80\x80",
	b"\xff",
	b"\xc3",
	b"\xed\xa0\x80",
	b"\x1b[1m",
	b"\x1b[0;32m",
	b"\x1b[",
	b"\x1b[1;",
	b"\x1b",
];

// without the non printable and invalid ones, closer to real text
const PLAIN_TOKENS: &[&[u8]] = &[
	b"a",
	b"bc",
	b"defgh",
	b"ijklmnopq",
	b" ",
	b" ",
	"\u{3042}".as_bytes(),
	"e\u{301}".as_bytes(),
	b"\x1b[1m",
];

fn show(s: &[u8]) -> String {
	format!("{:?}", String::from_utf8_lossy(s))
}

fn text(rng: &mut Rng, tokens: &[&[u8]], max: usize) -> Vec<u8> {
	(0..rng.below(max))
		.flat_map(|_| tokens[rng.below(tokens.len())])
		.copied()
		.collect()
}

// any of the token sets, mostly plain
fn any_text(rng: &mut Rng, max: usize) -> Vec<u8> {
	let tokens = if rng.below(3) == 0 {
		TOKENS
	} else {
		PLAIN_TOKENS
	};
	text(rng, tokens, max)
}

// a text the C string_length can take
fn safe_text(rng: &mut Rng, max: usize) -> Vec<u8> {
	loop {
		let t = any_text(rng, max);
		if string_length_in_bounds(&t) {
			return t;
		}
	}
}

fn colors(rng: &mut Rng) -> ColStr<'static> {
	if rng.below(2) == 0 {
		ColStr::default()
	} else {
		ColStr {
			title: b"\x1b[1m",
			nocolor: b"\x1b[0m",
			..ColStr::default()
		}
	}
}

// widths around the text lengths, 0 = not a tty
fn width(rng: &mut Rng) -> u16 {
	match rng.below(8) {
		0 => 0,
		1 => rng.below(65536) as u16,
		_ => rng.below(40) as u16,
	}
}

// display inputs are compared where every character has the same width
// on both sides (see wcwidth_divergence), the others are counted
#[derive(Default)]
struct Cover {
	compared: usize,
	skipped: usize,
}

impl Cover {
	fn agree<T: AsRef<[u8]>>(
		&mut self,
		texts: impl IntoIterator<Item = T>,
	) -> bool {
		let ok = texts.into_iter().all(|t| widths_agree(t.as_ref()));
		if ok {
			self.compared += 1;
		} else {
			self.skipped += 1;
		}
		ok
	}

	// at least 690 per 1000 compared, about 3/4 of the 920 measured with
	// 200000 iterations
	fn finish(&self, what: &str) {
		let n = self.compared + self.skipped;
		println!("{what}: compared {} of {n}", self.compared);
		assert!(
			self.compared * 1000 >= n * 690,
			"{what}: compared {} of {n}",
			self.compared
		);
	}
}

// glibc 2.44 C.UTF-8 wcwidth against the port (unicode-width with the -1
// mapping) over every code point, by (glibc, port) widths. counts are the
// measured ones and may only shrink
struct WidthClass {
	what: &'static str,
	pairs: &'static [(i32, i32)],
	measured: usize,
	example: u32,
}

const fn class(
	what: &'static str,
	pairs: &'static [(i32, i32)],
	measured: usize,
	example: u32,
) -> WidthClass {
	WidthClass {
		what,
		pairs,
		measured,
		example,
	}
}

const WIDTH_DIVERGENCE: &[WidthClass] = &[
	// unassigned and noncharacters: glibc -1, unicode-width a width
	class("unassigned, port 1", &[(-1, 1)], 754_797, 0x378),
	// in the wide default ranges (CJK extension planes, compatibility
	// ideographs)
	class("unassigned, port 2", &[(-1, 2)], 56_166, 0x2_a6e0),
	// default ignorable ranges (U+2065, U+FFF0-FFF8, tags E0000-E0FFF)
	class("unassigned, port 0", &[(-1, 0)], 3_769, 0xe_0000),
	// Prepend and Prepended_Concatenation_Mark, Grapheme_Extend spacing
	// marks (Indic vowel signs and length marks, U+302E-302F,
	// U+16FF0-16FF1, U+FF9E-FF9F), soft hyphen U+00AD, U+A8FA
	class("zero width in port", &[(1, 0), (2, 0)], 84, 0xad),
	// East Asian Width ambiguous, U+3248-324F: wide in glibc
	class("ambiguous, glibc 2", &[(2, 1)], 8, 0x3248),
	// unicode-width rules: U+17A4 2, U+17D8 3, U+2D7F 1
	class("port specials", &[(1, 2), (1, 3), (0, 1)], 3, 0x17d8),
];

#[test]
fn wcwidth_divergence() {
	let mut counts = vec![0usize; WIDTH_DIVERGENCE.len()];
	for c in 0..=0x10_ffff {
		let pair = (c_wcwidth(c), wcwidth(c));
		if pair.0 == pair.1 {
			continue;
		}
		let k = WIDTH_DIVERGENCE
			.iter()
			.position(|d| d.pairs.contains(&pair))
			.unwrap_or_else(|| {
				panic!("U+{c:04X}: new class {pair:?}")
			});
		counts[k] += 1;
	}
	for (d, n) in WIDTH_DIVERGENCE.iter().zip(counts) {
		println!("{}: {n} (measured {})", d.what, d.measured);
		assert!(n <= d.measured, "{}: {n} > {}", d.what, d.measured);
		let pair = (c_wcwidth(d.example), wcwidth(d.example));
		assert!(
			d.pairs.contains(&pair),
			"{}: U+{:04X} {pair:?}",
			d.what,
			d.example
		);
	}
	// past U+10FFFF (the decoder goes up to 0x7fffffff) both say -1
	let mut rng = Rng::new(0x3c3d);
	for c in [0x11_0000, 0x1f_ffff, 0x20_0000, 0x7fff_ffff] {
		assert_eq!(c_wcwidth(c), wcwidth(c), "U+{c:04X}");
	}
	for _ in 0..iters() {
		let c = (rng.next_u64() as u32) & 0x7fff_ffff;
		if c > 0x10_ffff {
			assert_eq!(c_wcwidth(c), wcwidth(c), "U+{c:04X}");
		}
	}
}

// UTF-8 of c in n bytes, overlong if n is more than c needs
fn encode(c: u32, n: usize) -> Vec<u8> {
	if n == 1 {
		return vec![c as u8];
	}
	let lead = [0, 0, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc][n];
	let mut v = vec![lead | (c >> (6 * (n - 1))) as u8];
	for i in (0..n - 1).rev() {
		v.push(0x80 | ((c >> (6 * i)) & 0x3f) as u8);
	}
	v
}

#[test]
fn mbstowcs_decoder() {
	let alphabet =
		b"a \x80\x8f\x90\x9f\xa0\xbf\xc0\xc1\xc2\xdf\xe0\xed\xef\
		\xf0\xf4\xf5\xf7\xf8\xfb\xfc\xfd\xfe\xff";
	let mut rng = Rng::new(0xdec0);
	let check = |s: &[u8]| {
		assert_eq!(c_mbstowcs(s), mbstowcs(s), "{}", show(s));
	};
	for _ in 0..iters() {
		check(&rng.bytes(alphabet, 8));
		// code points of each length, shortest or overlong, surrogates
		let mut s = Vec::new();
		for _ in 0..rng.below(4) {
			let n = 1 + rng.below(6);
			let c = match rng.below(4) {
				0 => 0xd800 + rng.below(0x800) as u32,
				_ => {
					rng.next_u64() as u32
						& ((1u32 << (5 * n + 1)) - 1)
				}
			};
			let c = if n == 1 { c & 0x7f } else { c };
			if c != 0 {
				s.extend(encode(c, n));
			}
		}
		check(&s);
	}
}

#[test]
fn indentprint_wrap() {
	let mut rng = Rng::new(0x1d27);
	let mut cover = Cover::default();
	for _ in 0..iters() {
		let s = any_text(&mut rng, 12);
		let (indent, cols) = (width(&mut rng), width(&mut rng));
		if !cover.agree([&s]) {
			continue;
		}
		let mut out = Vec::new();
		indentprint(&mut out, &s, indent, cols);
		assert_eq!(
			c_indentprint(&s, indent, cols),
			out,
			"{} indent {indent} cols {cols}",
			show(&s)
		);
	}
	cover.finish("indentprint");
}

#[test]
fn strreplace_occurrences() {
	let alphabet = b"aab";
	let mut rng = Rng::new(0x5e9);
	// NULL str gives NULL, NULL replace counts as ""
	assert_eq!(c_strreplace(None, b"a", Some(b"x")), None);
	assert_eq!(
		c_strreplace(Some(b"bab"), b"a", None),
		Some(b"bb".to_vec())
	);
	for _ in 0..iters() {
		let s = rng.bytes(alphabet, 12);
		let mut needle = rng.bytes(alphabet, 4);
		if needle.is_empty() {
			needle.push(b'a');
		}
		let r = rng.bytes(b"xyab", 5);
		assert_eq!(
			c_strreplace(Some(&s), &needle, Some(&r)),
			Some(strreplace(&s, &needle, &r)),
			"{} {} {}",
			show(&s),
			show(&needle),
			show(&r)
		);
	}
}

#[test]
fn string_display_title_indent() {
	let mut rng = Rng::new(0x57d1);
	let mut cover = Cover::default();
	for _ in 0..iters() {
		let title = (rng.below(4) != 0).then(|| safe_text(&mut rng, 4));
		let s = any_text(&mut rng, 10);
		let cols = width(&mut rng);
		let colstr = colors(&mut rng);
		// NULL and "" both print None. drawn before the skip, so the
		// rng stream is the one of the compared inputs
		let c_s =
			(!s.is_empty() || rng.below(2) == 0).then_some(&s[..]);
		if !cover.agree(title.iter().chain([&s])) {
			continue;
		}
		let mut out = Vec::new();
		string_display(&mut out, title.as_deref(), &s, cols, &colstr);
		assert_eq!(
			c_string_display(title.as_deref(), c_s, cols, &colstr),
			out,
			"{:?} {} cols {cols}",
			title.as_deref().map(show),
			show(&s)
		);
	}
	cover.finish("string_display");
}

// string_length is static, its width reaches the output through the
// wrapping of list_display
#[test]
fn list_display_wrap() {
	let mut rng = Rng::new(0x7157);
	let mut cover = Cover::default();
	for _ in 0..iters() {
		let title = (rng.below(4) != 0).then(|| safe_text(&mut rng, 4));
		let list: Vec<Vec<u8>> = (0..rng.below(6))
			.map(|_| safe_text(&mut rng, 4))
			.collect();
		let cols = width(&mut rng);
		let colstr = colors(&mut rng);
		if !cover.agree(title.iter().chain(&list)) {
			continue;
		}
		let mut out = Vec::new();
		list_display(&mut out, title.as_deref(), &list, cols, &colstr);
		assert_eq!(
			c_list_display(title.as_deref(), &list, cols, &colstr),
			out,
			"{:?} {:?} cols {cols}",
			title.as_deref().map(show),
			list.iter().map(|s| show(s)).collect::<Vec<_>>()
		);
	}
	cover.finish("list_display");
}

#[test]
fn list_display_linebreak_items() {
	let mut rng = Rng::new(0x11b7);
	let mut cover = Cover::default();
	for _ in 0..iters() {
		let title = (rng.below(4) != 0).then(|| safe_text(&mut rng, 4));
		let list: Vec<Vec<u8>> = (0..rng.below(4))
			.map(|_| any_text(&mut rng, 8))
			.collect();
		let cols = width(&mut rng);
		let colstr = colors(&mut rng);
		if !cover.agree(title.iter().chain(&list)) {
			continue;
		}
		let mut out = Vec::new();
		list_display_linebreak(
			&mut out,
			title.as_deref(),
			&list,
			cols,
			&colstr,
		);
		assert_eq!(
			c_list_display_linebreak(
				title.as_deref(),
				&list,
				cols,
				&colstr
			),
			out,
			"{:?} {:?} cols {cols}",
			title.as_deref().map(show),
			list.iter().map(|s| show(s)).collect::<Vec<_>>()
		);
	}
	cover.finish("list_display_linebreak");
}

const STATUSES: [SigStatus; 6] = [
	SigStatus::Valid,
	SigStatus::KeyExpired,
	SigStatus::SigExpired,
	SigStatus::KeyUnknown,
	SigStatus::KeyDisabled,
	SigStatus::Invalid,
];
const VALIDITIES: [SigValidity; 4] = [
	SigValidity::Full,
	SigValidity::Marginal,
	SigValidity::Never,
	SigValidity::Unknown,
];

#[test]
fn signature_display_lines() {
	let mut rng = Rng::new(0x5194);
	let mut cover = Cover::default();
	for _ in 0..iters() {
		let title = (rng.below(4) != 0).then(|| safe_text(&mut rng, 4));
		let sigs: Vec<SigResult> = (0..rng.below(4))
			.map(|_| SigResult {
				status: STATUSES[rng.below(STATUSES.len())],
				validity: VALIDITIES
					[rng.below(VALIDITIES.len())],
				uid: (rng.below(2) == 0)
					.then(|| any_text(&mut rng, 4)),
				fingerprint: rng.bytes(b"0123ABCD", 10),
			})
			.collect();
		let cols = width(&mut rng);
		let colstr = colors(&mut rng);
		let uids = sigs.iter().filter_map(|s| s.uid.as_ref());
		if !cover.agree(title.iter().chain(uids)) {
			continue;
		}
		let mut out = Vec::new();
		signature_display(
			&mut out,
			title.as_deref(),
			&sigs,
			cols,
			&colstr,
		);
		assert_eq!(
			c_signature_display(
				title.as_deref(),
				&sigs,
				cols,
				&colstr
			),
			out,
			"{:?} {sigs:?} cols {cols}",
			title.as_deref().map(show)
		);
	}
	cover.finish("signature_display");
}

fn check_humanize(bytes: i64, unit: u8, precision: i32) {
	let (v, label) = humanize_size(bytes, unit, precision);
	let (cv, clabel) = c_humanize_size(bytes, unit, precision);
	assert_eq!(
		(cv.to_bits(), &clabel[..]),
		(v.to_bits(), label.as_bytes()),
		"{bytes} {unit:?} {precision}: {cv} vs {v}"
	);
}

#[test]
fn humanize_size_units() {
	let units = b"\0\0\0BKMGTPEZYkx";
	for b in [0, -1, 1, 2048, 2049, -2048, -2049, i64::MIN, i64::MAX] {
		for &u in units {
			for p in [-1, 0, 2, 308, 309, 1000] {
				check_humanize(b, u, p);
			}
		}
	}
	let mut rng = Rng::new(0x5123);
	for _ in 0..iters() {
		// all magnitudes, many near -0.005 MiB and the 2048 edges
		let bytes = match rng.below(3) {
			0 => rng.next_u64() as i64,
			1 => -(rng.below(12_000) as i64),
			_ => (rng.next_u64() as i64) >> rng.below(64),
		};
		let unit = match rng.below(4) {
			0 => rng.next_u64() as u8,
			_ => units[rng.below(units.len())],
		};
		let precision = rng.below(12) as i32 - 2;
		check_humanize(bytes, unit, precision);
	}
}

#[test]
fn arg_to_string_join() {
	let none: [&[u8]; 0] = [];
	assert_eq!(c_arg_to_string(&none), None);
	assert_eq!(arg_to_string(&none), None);
	let mut rng = Rng::new(0xa765);
	for _ in 0..iters() {
		let args: Vec<Vec<u8>> = (0..rng.below(5))
			.map(|_| rng.bytes(b"ab -", 4))
			.collect();
		assert_eq!(
			c_arg_to_string(&args),
			arg_to_string(&args),
			"{args:?}"
		);
	}
}

#[test]
fn console_sequences() {
	let mut out = Vec::new();
	console_erase_line(&mut out);
	assert_eq!(c_console_erase_line(), out);
	let mut rng = Rng::new(0xc0de);
	let edges = [0, 1, 9, 10, i32::MAX as u32];
	let random = (0..iters() / 100).map(|_| rng.below(1 << 31) as u32);
	for n in edges.into_iter().chain(random) {
		let mut up = Vec::new();
		console_cursor_move_up(&mut up, n);
		assert_eq!(c_console_cursor_move_up(n), up, "{n}");
		let mut down = Vec::new();
		console_cursor_move_down(&mut down, n);
		assert_eq!(c_console_cursor_move_down(n), down, "{n}");
	}
}

// getcols: COLUMNS parsed like strtol (sign, spaces, trailing junk, past
// int and long), unset/empty/negative falls back to the terminal check.
// stdout must not be a terminal (the C asks the tty's width there)
#[test]
fn getcols_columns() {
	use std::io::IsTerminal;
	if std::io::stdout().is_terminal() {
		eprintln!("stdout is a terminal, getcols fallback skipped");
		return;
	}
	let fixed: &[Option<&[u8]>] = &[
		None,
		Some(b""),
		Some(b"80"),
		Some(b"0"),
		Some(b"+5"),
		Some(b"-5"),
		Some(b"  42"),
		Some(b"42 "),
		Some(b"4x"),
		Some(b"-"),
		Some(b" "),
		Some(b"65536"),
		Some(b"65617"),
		Some(b"4294967376"),
		Some(b"99999999999999999999"),
		Some(b"-99999999999999999999"),
		Some(b"\t\n7"),
		Some(b"\xc3\xa9"),
	];
	for &v in fixed {
		let (c, r) = getcols_both(v, getcols);
		assert_eq!(c, r, "COLUMNS={v:?}");
	}
	let mut rng = Rng::new(0xc015);
	for _ in 0..iters() / 20 {
		let v = rng.bytes(b"0123456789+- \tx9", 24);
		let (c, r) = getcols_both(Some(&v), getcols);
		assert_eq!(c, r, "COLUMNS={v:?}");
	}
}
