// C side of lib/libalpm/signing.c and base64.c
use std::ffi::{c_char, c_int};

use crate::{c_free, cstr};

unsafe extern "C" {
	fn alpm_decode_signature(
		b64: *const c_char,
		data: *mut *mut u8,
		data_len: *mut usize,
	) -> c_int;
}

pub struct CDecoded {
	pub rc: i32,
	pub len: usize,
	// None where the C buffer is not initialized, see UPSTREAM.md
	pub data: Option<Vec<u8>>,
}

pub fn c_decode_signature(b64: &[u8]) -> CDecoded {
	let s = cstr(b64);
	let mut data: *mut u8 = std::ptr::null_mut();
	let mut len = 0usize;
	// SAFETY: s is a valid C string, data/len are valid out pointers
	let rc = unsafe {
		alpm_decode_signature(s.as_ptr(), &mut data, &mut len)
	};

	let has_symbol = b64.iter().any(|&c| c != b'\n' && c != b'\r');
	let out = (rc == 0 && has_symbol).then(|| {
		// SAFETY: on success data holds len bytes written by base64_decode,
		// len == 0 still gives a valid malloc(0) pointer on glibc
		unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
	});
	c_free(data.cast());
	CDecoded { rc, len, data: out }
}
