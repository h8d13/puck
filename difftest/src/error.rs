// C side of lib/libalpm/error.c
use std::ffi::{CStr, c_char, c_int};

unsafe extern "C" {
	// alpm_errno_t is passed as an int-sized enum
	fn alpm_strerror(err: c_int) -> *const c_char;
}

// static string, never NULL. no setlocale() in the test process, so
// dgettext runs in the C locale and returns the msgid
pub fn c_strerror(err: i32) -> Vec<u8> {
	// SAFETY: alpm_strerror takes any value (switch with default) and
	// returns a static nul-terminated string
	let p = unsafe { alpm_strerror(err) };
	assert!(!p.is_null());
	// SAFETY: p points to a static C string
	unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}
