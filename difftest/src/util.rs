// C side of lib/libalpm/util.c, internal symbols from the static archive
use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use std::ptr;

use crate::handle::record_log;
use crate::{CList, alpm_list_add, alpm_list_free, c_free, cstr, take};

// alpm_list_t, alpm_list.h
unsafe extern "C" {
	fn _alpm_strip_newline(s: *mut c_char, len: usize) -> usize;
	fn _alpm_get_fullpath(
		path: *const c_char,
		filename: *const c_char,
		suffix: *const c_char,
	) -> *mut c_char;
	fn _alpm_hash_sdbm(s: *const c_char) -> c_ulong;
	fn _alpm_strtoofft(s: *const c_char) -> i64;
	fn _alpm_parsedate(s: *const c_char) -> i64;
	fn _alpm_splitname(
		target: *const c_char,
		name: *mut *mut c_char,
		version: *mut *mut c_char,
		name_hash: *mut c_ulong,
	) -> c_int;
	fn _alpm_fnmatch(
		pattern: *const c_void,
		string: *const c_void,
	) -> c_int;
	fn _alpm_fnmatch_patterns(
		patterns: *mut CList,
		string: *const c_char,
	) -> c_int;
	fn _alpm_makepath(path: *const c_char) -> c_int;
	fn _alpm_makepath_mode(path: *const c_char, mode: c_uint) -> c_int;
	fn _alpm_copyfile(src: *const c_char, dest: *const c_char) -> c_int;
	fn _alpm_read_file(
		filepath: *const c_char,
		data: *mut *mut u8,
		data_len: *mut usize,
	) -> c_int;
	fn _alpm_files_in_directory(
		handle: *mut c_void,
		path: *const c_char,
		full_count: c_int,
	) -> isize;
	fn umask(mask: c_uint) -> c_uint;
	fn alpm_compute_md5sum(filename: *const c_char) -> *mut c_char;
	fn alpm_compute_sha256sum(filename: *const c_char) -> *mut c_char;
	fn _alpm_test_checksum(
		filepath: *const c_char,
		expected: *const c_char,
		kind: c_int,
	) -> c_int;
}

// alpm_errno_t values returned by _alpm_read_file, alpm.h
pub const ALPM_ERR_MEMORY: c_int = 1;
pub const ALPM_ERR_SYSTEM: c_int = 2;
pub const ALPM_ERR_NOT_A_FILE: c_int = 4;

// returns the trimmed string, the C writes a nul into its buffer
pub fn c_strip_newline(s: &[u8]) -> Vec<u8> {
	let mut buf = cstr(s).into_bytes_with_nul();
	// SAFETY: buf is a writable nul-terminated buffer, len 0 = use strlen
	let n = unsafe { _alpm_strip_newline(buf.as_mut_ptr().cast(), 0) };
	buf.truncate(n);
	buf
}

pub fn c_get_fullpath(path: &[u8], filename: &[u8], suffix: &[u8]) -> Vec<u8> {
	let (p, f, s) = (cstr(path), cstr(filename), cstr(suffix));
	// SAFETY: three valid C strings, result is malloc'd or NULL
	let r = unsafe {
		_alpm_get_fullpath(p.as_ptr(), f.as_ptr(), s.as_ptr())
	};
	take(r).unwrap()
}

pub fn c_hash_sdbm(s: &[u8]) -> c_ulong {
	let s = cstr(s);
	// SAFETY: valid C string
	unsafe { _alpm_hash_sdbm(s.as_ptr()) }
}

pub fn c_strtoofft(s: &[u8]) -> i64 {
	let s = cstr(s);
	// SAFETY: valid C string
	unsafe { _alpm_strtoofft(s.as_ptr()) }
}

pub fn c_parsedate(s: &[u8]) -> i64 {
	let s = cstr(s);
	// SAFETY: valid C string
	unsafe { _alpm_parsedate(s.as_ptr()) }
}

// C precondition: two '-' before the first '/', see UPSTREAM.md
pub fn c_splitname(target: &[u8]) -> Option<(Vec<u8>, Vec<u8>, c_ulong)> {
	let end = target
		.iter()
		.position(|&c| c == b'/')
		.unwrap_or(target.len());
	let hyphens = target[..end].iter().filter(|&&c| c == b'-').count();
	assert!(hyphens >= 2, "unsafe input for C splitname: {target:?}");

	let t = cstr(target);
	let (mut name, mut ver) = (std::ptr::null_mut(), std::ptr::null_mut());
	let mut hash: c_ulong = 0;
	// SAFETY: valid C string with enough '-' to keep the scan in bounds,
	// out pointers start NULL so the C does not free them
	let rc = unsafe {
		_alpm_splitname(t.as_ptr(), &mut name, &mut ver, &mut hash)
	};
	let (name, ver) = (take(name), take(ver));
	if rc != 0 {
		return None;
	}
	Some((name.unwrap(), ver.unwrap(), hash))
}

// 0 on match, FNM_NOMATCH otherwise
pub fn c_fnmatch(pattern: &[u8], string: &[u8]) -> c_int {
	let (p, s) = (cstr(pattern), cstr(string));
	// SAFETY: two valid C strings, read only
	unsafe { _alpm_fnmatch(p.as_ptr().cast(), s.as_ptr().cast()) }
}

// -1 no match, 0 match, 1 inverted match
pub fn c_fnmatch_patterns(patterns: &[Vec<u8>], string: &[u8]) -> c_int {
	let owned: Vec<_> = patterns.iter().map(|p| cstr(p)).collect();
	let mut list = ptr::null_mut();
	for p in &owned {
		// SAFETY: list is NULL or built by alpm_list_add, data stays
		// owned by `owned` and is never written by the C
		list = unsafe {
			alpm_list_add(list, p.as_ptr().cast_mut().cast())
		};
	}
	let s = cstr(string);
	// SAFETY: list holds valid C strings alive for the call
	let r = unsafe { _alpm_fnmatch_patterns(list, s.as_ptr()) };
	// SAFETY: nodes malloc'd by alpm_list_add, data not owned by the list
	unsafe { alpm_list_free(list) };
	r
}

pub fn c_makepath(path: &[u8]) -> c_int {
	let p = cstr(path);
	// SAFETY: valid C string
	unsafe { _alpm_makepath(p.as_ptr()) }
}

pub fn c_makepath_mode(path: &[u8], mode: u32) -> c_int {
	let p = cstr(path);
	// SAFETY: valid C string
	unsafe { _alpm_makepath_mode(p.as_ptr(), mode) }
}

pub fn c_copyfile(src: &[u8], dest: &[u8]) -> c_int {
	let (s, d) = (cstr(src), cstr(dest));
	// SAFETY: two valid C strings
	unsafe { _alpm_copyfile(s.as_ptr(), d.as_ptr()) }
}

// file contents, or the alpm_errno_t
pub fn c_read_file(path: &[u8]) -> Result<Vec<u8>, c_int> {
	let p = cstr(path);
	let (mut data, mut len) = (ptr::null_mut(), 0usize);
	// SAFETY: valid C string, out pointers to locals
	let rc = unsafe { _alpm_read_file(p.as_ptr(), &mut data, &mut len) };
	if rc != 0 {
		// data is NULL or freed (and NULLed) by the C on every error
		return Err(rc);
	}
	// SAFETY: on success data holds len bytes malloc'd by the C
	let v = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
	c_free(data.cast());
	Ok(v)
}

// NULL handle: the C only uses it for _alpm_log, which returns on NULL
pub fn c_files_in_directory(path: &[u8], full_count: bool) -> isize {
	let p = cstr(path);
	// SAFETY: valid C string, NULL handle is checked by _alpm_log
	unsafe {
		_alpm_files_in_directory(
			ptr::null_mut(),
			p.as_ptr(),
			c_int::from(full_count),
		)
	}
}

// process umask, returns the previous one
pub fn c_umask(mask: u32) -> u32 {
	// SAFETY: umask cannot fail
	unsafe { umask(mask) }
}

// hex digest, None where the C returns NULL
pub fn c_compute_md5sum(path: &[u8]) -> Option<Vec<u8>> {
	let p = cstr(path);
	// SAFETY: valid C string, the result is malloc'd or NULL
	take(unsafe { alpm_compute_md5sum(p.as_ptr()) })
}

pub fn c_compute_sha256sum(path: &[u8]) -> Option<Vec<u8>> {
	let p = cstr(path);
	// SAFETY: valid C string, the result is malloc'd or NULL
	take(unsafe { alpm_compute_sha256sum(p.as_ptr()) })
}

// -1 error, 0 match, 1 mismatch. None expected maps to NULL
pub fn c_test_checksum(
	path: &[u8],
	expected: Option<&[u8]>,
	kind: c_int,
) -> c_int {
	let p = cstr(path);
	let e = expected.map(cstr);
	// SAFETY: valid C strings or NULL for expected, read only
	unsafe { _alpm_test_checksum(p.as_ptr(), crate::opt_ptr(&e), kind) }
}

// _alpm_unpack: the extraction runs on a handle over root/dbpath (for
// logging and pm_errno); the C chdir()s into prefix and back, the CHandle
// holds the ALPM lock meanwhile
pub struct CUnpack {
	pub rc: c_int,
	pub errno: c_int,
	// every _alpm_log call: level, formatted message
	pub logs: Vec<(c_int, Vec<u8>)>,
}

unsafe extern "C" {
	fn _alpm_unpack(
		handle: *mut c_void,
		path: *const c_char,
		prefix: *const c_char,
		list: *mut CList,
		breakfirst: c_int,
	) -> c_int;
}

pub fn c_unpack(
	root: &[u8],
	dbpath: &[u8],
	path: &[u8],
	prefix: &[u8],
	list: Option<&[Vec<u8>]>,
	breakfirst: bool,
) -> CUnpack {
	let h = crate::db::CHandle::new(root, dbpath).expect("fixture handle");
	let mut logs: Vec<(c_int, Vec<u8>)> = Vec::new();
	let ctx: *mut Vec<(c_int, Vec<u8>)> = &mut logs;
	// SAFETY: h is live, ctx outlives every call made on h below
	unsafe {
		crate::handle::alpm_option_set_logcb(
			h.raw(),
			Some(record_log),
			ctx.cast(),
		)
	};
	let (path, prefix) = (cstr(path), cstr(prefix));
	let owned: Vec<_> =
		list.unwrap_or_default().iter().map(|s| cstr(s)).collect();
	let mut clist = ptr::null_mut();
	for s in &owned {
		// SAFETY: clist is NULL or built by alpm_list_add, data stays
		// owned by `owned`
		clist = unsafe {
			alpm_list_add(clist, s.as_ptr().cast_mut().cast())
		};
	}
	// SAFETY: valid C strings, clist holds them for the call; the C
	// restores the cwd before returning
	let (rc, errno) = h.call(|| unsafe {
		_alpm_unpack(
			h.raw(),
			path.as_ptr(),
			prefix.as_ptr(),
			clist,
			c_int::from(breakfirst),
		)
	});
	// SAFETY: nodes malloc'd by alpm_list_add, data not owned by the list
	unsafe { alpm_list_free(clist) };
	// SAFETY: h is live, the callback is dropped before logs goes
	unsafe {
		crate::handle::alpm_option_set_logcb(
			h.raw(),
			None,
			ptr::null_mut(),
		)
	};
	CUnpack { rc, errno, logs }
}
