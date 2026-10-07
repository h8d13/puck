// unit tests for pacman_common::ini
use std::path::Path;

use pacman_common::ini::{Ini, parse_ini, parse_ini_reader};

fn events(data: &[u8]) -> Vec<String> {
	let mut out = Vec::new();
	let rc = parse_ini_reader(data, |ev| {
		out.push(match ev {
			Ini::OpenError(e) => format!("open {e}"),
			Ini::Section { line, name } => {
				format!(
					"{line} [{}]",
					String::from_utf8_lossy(name)
				)
			}
			Ini::Directive {
				line,
				section,
				key,
				value,
			} => format!(
				"{line} {:?} {:?} {:?}",
				section.map(String::from_utf8_lossy),
				String::from_utf8_lossy(key),
				value.map(String::from_utf8_lossy)
			),
		});
		0
	});
	assert_eq!(rc, 0);
	out
}

#[test]
fn sections_and_directives() {
	assert_eq!(
		events(b"#c\nk\n[options]\n  a = b = c \nflag\n[]\n"),
		[
			"2 None \"k\" None",
			"3 [options]",
			"4 Some(\"options\") \"a\" Some(\"b = c\")",
			"5 Some(\"options\") \"flag\" None",
			"6 []",
		]
	);
	// 4095 byte chunks, the rest of the line is line 2
	let mut long = vec![b'k'; 4095];
	long.extend(b"=v\n");
	assert_eq!(events(&long)[1], "2 None \"\" Some(\"v\")");
}

#[test]
fn stop_and_open_error() {
	let mut n = 0;
	let rc = parse_ini_reader(&b"a\nb\nc\n"[..], |_| {
		n += 1;
		if n == 2 { 7 } else { 0 }
	});
	assert_eq!((rc, n), (7, 2));
	let rc = parse_ini(Path::new("/nonexistent/x"), |ev| match ev {
		Ini::OpenError(e) => e.raw_os_error().unwrap(),
		_ => 0,
	});
	assert_eq!(rc, 2);
}
