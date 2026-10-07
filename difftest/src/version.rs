// C side of lib/libalpm/version.c
use std::ffi::{c_char, c_int};

use crate::{cstr, opt_ptr};

unsafe extern "C" {
	fn alpm_pkg_vercmp(a: *const c_char, b: *const c_char) -> c_int;
}

// None maps to NULL
pub fn c_vercmp(a: Option<&[u8]>, b: Option<&[u8]>) -> i32 {
	let (a, b) = (a.map(cstr), b.map(cstr));
	// SAFETY: both pointers are NULL or valid nul-terminated strings
	// that outlive the call, the C does not keep them
	unsafe { alpm_pkg_vercmp(opt_ptr(&a), opt_ptr(&b)) }
}
