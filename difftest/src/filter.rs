// C side of libarchive's read filters as pacman sets them up
// (_alpm_archive_read_support_filter_all = archive_read_support_filter_all),
// compared with alpm_core::filter: the data is read through the raw format
// (one entry, the filters' output), so the decoded bytes, where a cut or
// corrupt stream fails and libarchive's text are seen directly. the
// formats raw and empty only: their bids read nothing past the filters'
// first block, like tar's
//
// also libarchive's write filters, for streams no Rust encoder writes
// (compress, lzma, lzip, lz4 frames as bsdtar writes them)
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use crate::check::archive_error_string;

// archive.h
const ARCHIVE_OK: c_int = 0;
const ARCHIVE_EOF: c_int = 1;
const AE_IFREG: u32 = 0o100000;

unsafe extern "C" {
	fn archive_read_new() -> *mut c_void;
	fn archive_read_support_filter_all(a: *mut c_void) -> c_int;
	fn archive_read_support_format_raw(a: *mut c_void) -> c_int;
	fn archive_read_support_format_empty(a: *mut c_void) -> c_int;
	fn archive_read_open_memory(
		a: *mut c_void,
		buf: *const c_void,
		size: usize,
	) -> c_int;
	fn archive_read_open_filename(
		a: *mut c_void,
		path: *const c_char,
		block: usize,
	) -> c_int;
	fn archive_read_next_header(
		a: *mut c_void,
		entry: *mut *mut c_void,
	) -> c_int;
	fn archive_read_data_block(
		a: *mut c_void,
		buf: *mut *const c_void,
		len: *mut usize,
		offset: *mut i64,
	) -> c_int;
	fn archive_read_free(a: *mut c_void) -> c_int;
	fn archive_filter_code(a: *mut c_void, n: c_int) -> c_int;
	fn archive_filter_count(a: *mut c_void) -> c_int;

	fn archive_write_new() -> *mut c_void;
	fn archive_write_add_filter_by_name(
		a: *mut c_void,
		name: *const c_char,
	) -> c_int;
	fn archive_write_set_options(
		a: *mut c_void,
		opts: *const c_char,
	) -> c_int;
	fn archive_write_set_format_raw(a: *mut c_void) -> c_int;
	fn archive_write_set_bytes_in_last_block(
		a: *mut c_void,
		n: c_int,
	) -> c_int;
	fn archive_write_open_memory(
		a: *mut c_void,
		buf: *mut c_void,
		size: usize,
		used: *mut usize,
	) -> c_int;
	fn archive_write_header(a: *mut c_void, entry: *mut c_void) -> c_int;
	fn archive_write_data(
		a: *mut c_void,
		buf: *const c_void,
		len: usize,
	) -> isize;
	fn archive_write_close(a: *mut c_void) -> c_int;
	fn archive_write_free(a: *mut c_void) -> c_int;
	fn archive_entry_new() -> *mut c_void;
	fn archive_entry_free(e: *mut c_void);
	fn archive_entry_set_pathname(e: *mut c_void, p: *const c_char);
	fn archive_entry_set_filetype(e: *mut c_void, t: u32);
	fn archive_entry_set_size(e: *mut c_void, s: i64);
}

// what the filters gave: the open's error text, or the bytes up to the
// end or the failing read and its text; the top filter's code
// (ARCHIVE_FILTER_*) and how many filters ran (the client counts one)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CFiltered {
	pub open_error: Option<Vec<u8>>,
	pub data: Vec<u8>,
	pub read_error: Option<Vec<u8>>,
	pub code: c_int,
	pub count: c_int,
}

fn error_text(a: *mut c_void) -> Vec<u8> {
	// SAFETY: a is a live archive; the string is copied before it goes
	let s = unsafe { archive_error_string(a) };
	if s.is_null() {
		return Vec::new();
	}
	// SAFETY: non-null, nul-terminated
	unsafe { CStr::from_ptr(s) }.to_bytes().to_vec()
}

// a: an archive opened (rc its open's result), read to its end and freed
fn read_all(a: *mut c_void, rc: c_int) -> CFiltered {
	let mut out = CFiltered {
		open_error: None,
		data: Vec::new(),
		read_error: None,
		// SAFETY: a is live
		code: unsafe { archive_filter_code(a, 0) },
		// SAFETY: a is live
		count: unsafe { archive_filter_count(a) },
	};
	if rc != ARCHIVE_OK {
		out.open_error = Some(error_text(a));
		// SAFETY: a came from archive_read_new
		unsafe { archive_read_free(a) };
		return out;
	}
	let mut entry = ptr::null_mut();
	// SAFETY: a is open, entry an out pointer
	let r = unsafe { archive_read_next_header(a, &mut entry) };
	if r != ARCHIVE_OK && r != ARCHIVE_EOF {
		out.read_error = Some(error_text(a));
	}
	// the blocks as the format hands them out, so a failing read does
	// not take what came before it in the same call
	let mut more = r == ARCHIVE_OK;
	while more {
		let (mut buf, mut len, mut off) = (ptr::null(), 0usize, 0i64);
		// SAFETY: a is open, the rest out pointers
		let r = unsafe {
			archive_read_data_block(a, &mut buf, &mut len, &mut off)
		};
		if r != ARCHIVE_OK && r != ARCHIVE_EOF {
			out.read_error = Some(error_text(a));
		}
		more = r == ARCHIVE_OK;
		if more && len > 0 {
			// SAFETY: libarchive's block of len bytes, valid
			// until the next read
			let b = unsafe {
				std::slice::from_raw_parts(buf.cast(), len)
			};
			out.data.extend_from_slice(b);
		}
	}
	// SAFETY: a came from archive_read_new
	unsafe { archive_read_free(a) };
	out
}

fn reader() -> *mut c_void {
	// SAFETY: plain constructor and setup calls on the new archive
	unsafe {
		let a = archive_read_new();
		assert!(!a.is_null());
		archive_read_support_filter_all(a);
		archive_read_support_format_raw(a);
		archive_read_support_format_empty(a);
		a
	}
}

// archive_read_open_memory, like be_package's .MTREE
pub fn c_filter_memory(data: &[u8]) -> CFiltered {
	let a = reader();
	// SAFETY: data outlives the archive, which read_all frees
	let rc = unsafe {
		archive_read_open_memory(a, data.as_ptr().cast(), data.len())
	};
	read_all(a, rc)
}

// the file read in blocks of block bytes, like _alpm_open_archive's fd
pub fn c_filter_file(path: &Path, block: usize) -> CFiltered {
	let a = reader();
	let p = CString::new(path.as_os_str().as_bytes()).unwrap();
	// SAFETY: p is a valid C string
	let rc = unsafe { archive_read_open_filename(a, p.as_ptr(), block) };
	read_all(a, rc)
}

// data through libarchive's write filter `name` (archive_write_add_filter
// _by_name) with filter options (archive_write_set_options), unpadded
pub fn c_filter_write(name: &str, options: &str, data: &[u8]) -> Vec<u8> {
	let name = CString::new(name).unwrap();
	let options = CString::new(options).unwrap();
	let mut buf = vec![0u8; data.len() * 2 + (1 << 20)];
	let mut used = 0usize;
	// SAFETY: the archive and entry live through these calls and are
	// freed at the end; buf and used outlive archive_write_close
	unsafe {
		let a = archive_write_new();
		assert!(!a.is_null());
		assert_eq!(
			archive_write_add_filter_by_name(a, name.as_ptr()),
			ARCHIVE_OK,
			"{name:?}"
		);
		if !options.is_empty() {
			assert_eq!(
				archive_write_set_options(a, options.as_ptr()),
				ARCHIVE_OK,
				"{options:?}"
			);
		}
		archive_write_set_format_raw(a);
		archive_write_set_bytes_in_last_block(a, 1);
		let rc = archive_write_open_memory(
			a,
			buf.as_mut_ptr().cast(),
			buf.len(),
			&mut used,
		);
		assert_eq!(rc, ARCHIVE_OK);
		let e = archive_entry_new();
		archive_entry_set_pathname(e, c"data".as_ptr());
		archive_entry_set_filetype(e, AE_IFREG);
		archive_entry_set_size(e, data.len() as i64);
		assert_eq!(archive_write_header(a, e), ARCHIVE_OK);
		archive_entry_free(e);
		if !data.is_empty() {
			let n = archive_write_data(
				a,
				data.as_ptr().cast(),
				data.len(),
			);
			assert_eq!(n, data.len() as isize);
		}
		assert_eq!(archive_write_close(a), ARCHIVE_OK);
		archive_write_free(a);
	}
	buf.truncate(used);
	buf
}
