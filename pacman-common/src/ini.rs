// port of src/common/ini.c: pacman-style INI parser, callback based
//
// lines are read like the C: safe_fgets with a PATH_MAX buffer, so a line
// longer than 4095 bytes is parsed as several lines, each counted. a nul
// byte ends the line for the parser (the C uses strlen). the C callback's
// file argument is dropped, the caller has it.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use crate::util_common::{safe_fgets, strtrim, until_nul};

// PATH_MAX on linux, the C line buffer
pub const LINE_MAX: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub enum Ini<'a> {
	// fopen failed: C passes line 0 and NULL section, key and value
	OpenError(&'a io::Error),
	// "[name]": C passes NULL key and value
	Section {
		line: usize,
		name: &'a [u8],
	},
	// "key = value", value None without '='. section None before the
	// first section header
	Directive {
		line: usize,
		section: Option<&'a [u8]>,
		key: &'a [u8],
		value: Option<&'a [u8]>,
	},
}

// parse_ini: returns the first non-zero callback result, which stops
// parsing, else 0. a read error ends parsing silently, like the C loop
pub fn parse_ini<F>(file: &Path, cb: F) -> i32
where
	F: FnMut(Ini) -> i32,
{
	match File::open(file) {
		Ok(f) => parse_ini_reader(BufReader::new(f), cb),
		Err(e) => {
			let mut cb = cb;
			cb(Ini::OpenError(&e))
		}
	}
}

// parse_ini past the fopen
pub fn parse_ini_reader<R, F>(mut r: R, mut cb: F) -> i32
where
	R: BufRead,
	F: FnMut(Ini) -> i32,
{
	let mut section: Option<Vec<u8>> = None;
	let mut line = 0;
	while let Ok(Some(chunk)) = safe_fgets(&mut r, LINE_MAX) {
		line += 1;
		let s = strtrim(until_nul(&chunk));
		if s.is_empty() || s[0] == b'#' {
			continue;
		}

		if s[0] == b'[' && s[s.len() - 1] == b']' {
			// "[]" is an empty name, a lone "[" is a directive
			let name = &s[1..s.len() - 1];
			let ret = cb(Ini::Section { line, name });
			section = Some(name.to_vec());
			if ret != 0 {
				return ret;
			}
			continue;
		}

		// strsep at the first '='
		let (key, value) = match s.iter().position(|&c| c == b'=') {
			Some(i) => (&s[..i], Some(strtrim(&s[i + 1..]))),
			None => (s, None),
		};
		let ret = cb(Ini::Directive {
			line,
			section: section.as_deref(),
			key: strtrim(key),
			value,
		});
		if ret != 0 {
			return ret;
		}
	}
	0
}
