// pacman_cli::util against src/pacman/util.c, both sides in C.UTF-8
use difftest::{
	Rng, c_arg_to_string, c_console_cursor_move_down,
	c_console_cursor_move_up, c_console_erase_line, c_humanize_size,
	c_indentprint, c_list_display, c_list_display_linebreak, c_mbstowcs,
	c_signature_display, c_string_display, c_strreplace, c_wcwidth, iters,
	string_length_in_bounds,
};
use pacman_cli::util::{
	ColStr, SigResult, SigStatus, SigValidity, arg_to_string,
	console_cursor_move_down, console_cursor_move_up, console_erase_line,
	humanize_size, indentprint, list_display, list_display_linebreak,
	mbstowcs, signature_display, string_display, strreplace, wcwidth,
};

// pieces of display text: words, space runs, wide (2), combining (0),
// non printable (-1: tab, unassigned, past U+10FFFF), invalid or
// truncated UTF-8, colour sequences whole and broken
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

#[test]
fn wcwidth_all_code_points() {
	for c in 0..=0x11_0000 {
		assert_eq!(c_wcwidth(c), wcwidth(c), "U+{c:04X}");
	}
	// the decoder goes up to 0x7fffffff
	let mut rng = Rng::new(0x3c3d);
	for c in [0x1f_ffff, 0x20_0000, 0x7fff_ffff] {
		assert_eq!(c_wcwidth(c), wcwidth(c), "U+{c:04X}");
	}
	for _ in 0..iters() {
		let c = (rng.next_u64() as u32) & 0x7fff_ffff;
		assert_eq!(c_wcwidth(c), wcwidth(c), "U+{c:04X}");
	}
}

// prints WIDTH_RUNS of pacman-cli/src/util.rs from the C wcwidth
#[test]
#[ignore]
fn dump_width_runs() {
	let mut runs = Vec::new();
	let mut prev = i32::MIN;
	for c in 0..=0x11_0000 {
		let w = c_wcwidth(c);
		if w != prev {
			runs.push(c << 2 | (w + 1) as u32);
			prev = w;
		}
	}
	let mut line = String::from("\t");
	println!("const WIDTH_RUNS: &[u32] = &[");
	for r in runs {
		let item = format!("0x{r:x},");
		if line.len() + item.len() + 1 > 72 {
			println!("{line}");
			line = String::from("\t");
		}
		if line.len() > 1 {
			line.push(' ');
		}
		line.push_str(&item);
	}
	println!("{line}\n];");
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
	for _ in 0..iters() {
		let s = any_text(&mut rng, 12);
		let (indent, cols) = (width(&mut rng), width(&mut rng));
		let mut out = Vec::new();
		indentprint(&mut out, &s, indent, cols);
		assert_eq!(
			c_indentprint(&s, indent, cols),
			out,
			"{} indent {indent} cols {cols}",
			show(&s)
		);
	}
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
	for _ in 0..iters() {
		let title = (rng.below(4) != 0).then(|| safe_text(&mut rng, 4));
		let s = any_text(&mut rng, 10);
		let cols = width(&mut rng);
		let colstr = colors(&mut rng);
		let mut out = Vec::new();
		string_display(&mut out, title.as_deref(), &s, cols, &colstr);
		// NULL and "" both print None
		let c_s =
			(!s.is_empty() || rng.below(2) == 0).then_some(&s[..]);
		assert_eq!(
			c_string_display(title.as_deref(), c_s, cols, &colstr),
			out,
			"{:?} {} cols {cols}",
			title.as_deref().map(show),
			show(&s)
		);
	}
}

// string_length is static, its width reaches the output through the
// wrapping of list_display
#[test]
fn list_display_wrap() {
	let mut rng = Rng::new(0x7157);
	for _ in 0..iters() {
		let title = (rng.below(4) != 0).then(|| safe_text(&mut rng, 4));
		let list: Vec<Vec<u8>> = (0..rng.below(6))
			.map(|_| safe_text(&mut rng, 4))
			.collect();
		let cols = width(&mut rng);
		let colstr = colors(&mut rng);
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
}

#[test]
fn list_display_linebreak_items() {
	let mut rng = Rng::new(0x11b7);
	for _ in 0..iters() {
		let title = (rng.below(4) != 0).then(|| safe_text(&mut rng, 4));
		let list: Vec<Vec<u8>> = (0..rng.below(4))
			.map(|_| any_text(&mut rng, 8))
			.collect();
		let cols = width(&mut rng);
		let colstr = colors(&mut rng);
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
