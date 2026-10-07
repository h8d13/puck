// pacman_common::ini::parse_ini against src/common/ini.c
use std::path::Path;

use difftest::{IniCall, Rng, c_parse_ini, iters};
use pacman_common::ini::{Ini, parse_ini};

fn rust_parse_ini(path: &str, stop_at: Option<usize>) -> (i32, Vec<IniCall>) {
	let mut calls = Vec::new();
	let rc = parse_ini(Path::new(path), |ev| {
		let call = match ev {
			Ini::OpenError(e) => IniCall {
				line: 0,
				section: None,
				key: None,
				value: None,
				errno: e.raw_os_error().unwrap(),
			},
			Ini::Section { line, name } => IniCall {
				line: line as i32,
				section: Some(name.to_vec()),
				key: None,
				value: None,
				errno: 0,
			},
			Ini::Directive {
				line,
				section,
				key,
				value,
			} => IniCall {
				line: line as i32,
				section: section.map(<[u8]>::to_vec),
				key: Some(key.to_vec()),
				value: value.map(<[u8]>::to_vec),
				errno: 0,
			},
		};
		let idx = calls.len();
		calls.push(call);
		if stop_at == Some(idx) {
			100 + idx as i32
		} else {
			0
		}
	});
	(rc, calls)
}

fn check(path: &str, stop_at: Option<usize>, what: &str) {
	assert_eq!(
		c_parse_ini(path.as_bytes(), stop_at),
		rust_parse_ini(path, stop_at),
		"stop_at {stop_at:?} {what}"
	);
}

fn tmp(name: &str) -> String {
	format!(
		"{}/difftest-ini-{name}-{}",
		std::env::temp_dir().display(),
		std::process::id()
	)
}

#[test]
fn open_and_read_errors() {
	for stop_at in [None, Some(0)] {
		check(&tmp("does-not-exist/x"), stop_at, "missing");
		check("", stop_at, "empty path");
		// fopen of a directory works, the first read fails (EISDIR)
		let dir = std::env::temp_dir();
		check(&dir.to_string_lossy(), stop_at, "directory");
	}
}

#[test]
fn fixed_files() {
	let path = tmp("fixed");
	let long = |c: u8, n: usize| vec![c; n];
	let cases: Vec<Vec<u8>> = vec![
		b"".to_vec(),
		b"key\n".to_vec(),
		b"[options]\nHoldPkg = pacman glibc\n#Color\n  Color  \n\
		  [core]\nInclude = /etc/pacman.d/mirrorlist\n"
			.to_vec(),
		b"[]\n[\n]\n[[x]]\n[a] \n =v\nk=\n= \na=b=c\n".to_vec(),
		b"a = b # not a comment\n\t#c\nx\0[y]\n[s\0]\n".to_vec(),
		b"\x0b\x0c[v]\r\nk\r=\rv\r\n".to_vec(),
		// chunked at 4095 bytes, the tail counts as its own line
		[long(b'k', 4094), b"=v\n".to_vec()].concat(),
		[b"[".to_vec(), long(b's', 4093), b"]\n".to_vec()].concat(),
		[b"[".to_vec(), long(b's', 4094), b"]\nk\n".to_vec()].concat(),
		[long(b' ', 5000), b"k = v".to_vec()].concat(),
	];
	for data in &cases {
		std::fs::write(&path, data).unwrap();
		for stop_at in [None, Some(0), Some(1), Some(2)] {
			check(&path, stop_at, &format!("{:?}", show(data)));
		}
	}
	std::fs::remove_file(&path).unwrap();
}

fn show(s: &[u8]) -> String {
	let s = String::from_utf8_lossy(s);
	if s.len() > 200 {
		format!("{}...", &s[..200])
	} else {
		s.into()
	}
}

#[test]
fn fuzz() {
	let path = tmp("fuzz");
	let alphabet = b"ab[[]]##===  \t\x0b\r\n\n\n\0";
	let mut rng = Rng::new(0x1a1);
	for i in 0..iters() {
		let mut data = rng.bytes(alphabet, 60);
		// now and then a line crossing the 4095 byte chunk boundary
		if i % 500 == 0 {
			let at = rng.below(data.len() + 1);
			let mut line = rng.bytes(alphabet, 8);
			line.extend(std::iter::repeat_n(
				b'a',
				4080 + rng.below(30),
			));
			line.extend(rng.bytes(alphabet, 8));
			data.splice(at..at, line);
		}
		std::fs::write(&path, &data).unwrap();
		let stop_at = match rng.below(4) {
			0 => Some(rng.below(6)),
			_ => None,
		};
		check(&path, stop_at, &show(&data));
	}
	std::fs::remove_file(&path).unwrap();
}
