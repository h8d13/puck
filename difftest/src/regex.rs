// C side of regex(3): glibc regcomp/regexec/regfree as pacman calls them
// (lib/libalpm/db.c, remove.c, src/pacman/files.c), plus the wide char
// functions behind the port's C.UTF-8 tables.
//
// the results depend on the locale: every call first runs cli_util's
// init, the one place setting LC_ALL=C.UTF-8 (pacman itself runs
// setlocale(LC_ALL, "") and takes the user's locale)
use std::ffi::{c_char, c_int, c_void};

use crate::cli_util::init;
use crate::cstr;

pub const REG_EXTENDED: c_int = 1;
pub const REG_ICASE: c_int = 2;
pub const REG_NEWLINE: c_int = 4;
pub const REG_NOSUB: c_int = 8;

// sizeof(regex_t) on glibc 64-bit is 64 (checked with a C probe), the
// second half is a canary proving regcomp writes no further
const REGEX_T: usize = 64;

#[repr(C, align(8))]
struct RegexBuf([u8; 2 * REGEX_T]);

unsafe extern "C" {
	fn regcomp(
		preg: *mut RegexBuf,
		pattern: *const c_char,
		cflags: c_int,
	) -> c_int;
	fn regexec(
		preg: *const RegexBuf,
		string: *const c_char,
		nmatch: usize,
		pmatch: *mut c_void,
		eflags: c_int,
	) -> c_int;
	fn regfree(preg: *mut RegexBuf);
	fn wctype(name: *const c_char) -> usize;
	// wint_t is a 32-bit unsigned int
	fn iswctype(wc: u32, desc: usize) -> c_int;
	fn towupper(wc: u32) -> u32;
}

// regcomp, then regexec(&reg, text, 0, NULL, 0) == 0 per text, regfree.
// Err: the regcomp error code
pub fn c_regex(
	pattern: &[u8],
	cflags: c_int,
	texts: &[&[u8]],
) -> Result<Vec<bool>, c_int> {
	init();
	let p = cstr(pattern);
	let mut re = RegexBuf([0xa5; 2 * REGEX_T]);
	// SAFETY: re is a writable buffer of at least sizeof(regex_t), p a C
	// string
	let rc = unsafe { regcomp(&mut re, p.as_ptr(), cflags) };
	assert!(re.0[REGEX_T..].iter().all(|&b| b == 0xa5), "regex_t size");
	if rc != 0 {
		// glibc frees everything itself on failure
		return Err(rc);
	}
	let out = texts
		.iter()
		.map(|t| {
			let t = cstr(t);
			// SAFETY: re compiled above, t a C string, no pmatch
			// with nmatch 0
			let r = unsafe {
				regexec(
					&re,
					t.as_ptr(),
					0,
					std::ptr::null_mut(),
					0,
				)
			};
			r == 0
		})
		.collect();
	// SAFETY: re compiled by regcomp, freed once, not used afterwards
	unsafe { regfree(&mut re) };
	Ok(out)
}

// iswctype(wc, wctype(name)) != 0
pub fn c_iswctype(name: &[u8], wc: u32) -> bool {
	init();
	let n = cstr(name);
	// SAFETY: n is a C string, wctype returns 0 for unknown names which
	// iswctype accepts
	unsafe { iswctype(wc, wctype(n.as_ptr())) != 0 }
}

pub fn c_towupper(wc: u32) -> u32 {
	init();
	// SAFETY: plain function of an integer
	unsafe { towupper(wc) }
}
