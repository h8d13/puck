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
use std::ffi::{CStr, CString, OsString, c_char, c_int, c_void};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use alpm_core::filter::{Code, open_file, open_memory};
use std::ptr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::TempRoot;
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

// libarchive's texts the port's filters produce too
const TEXTS: [&[u8]; 12] = [
	b"Invalid compressed data",
	b"Lzma library error",
	b"Lzma decompression failed",
	b"Lzip: ",
	b"truncated input",
	b"lz4 ",
	b"malformed lz4 data",
	b"Malformed lz4 data",
	b"truncated lz4 input",
	b"Invalid sequence",
	b"Child process exited",
	b"Input requires too many filters",
];

// ARCHIVE_FILTER_* of a code
fn c_code(code: Code) -> c_int {
	match code {
		Code::None => 0,
		Code::Gzip => 1,
		Code::Bzip2 => 2,
		Code::Compress => 3,
		Code::Lzma => 5,
		Code::Xz => 6,
		Code::Lzip => 9,
		Code::Lrzip => 10,
		Code::Lzop => 11,
		Code::Grzip => 12,
		Code::Lz4 => 13,
		Code::Zstd => 14,
	}
}

// what one side gave, texts the port lacks cut to their presence
#[derive(Debug, PartialEq, Eq)]
pub struct FilterOutcome {
	pub open_error: Option<Vec<u8>>,
	pub data: Vec<u8>,
	pub read_error: Option<Vec<u8>>,
	pub code: Option<c_int>,
}

// a text the port does not reproduce becomes its mere presence
fn norm(t: Option<Vec<u8>>) -> Option<Vec<u8>> {
	t.map(|t| match TEXTS.iter().any(|k| t.starts_with(k)) {
		true => t,
		false => b"(other)".to_vec(),
	})
}

fn from_c(c: CFiltered) -> FilterOutcome {
	let opened = c.open_error.is_none();
	FilterOutcome {
		open_error: norm(c.open_error),
		data: c.data,
		read_error: norm(c.read_error),
		code: opened.then_some(c.code),
	}
}

fn from_port(r: std::io::Result<alpm_core::filter::Filter>) -> FilterOutcome {
	let mut f = match r {
		Ok(f) => f,
		Err(e) => {
			return FilterOutcome {
				open_error: norm(Some(e
					.to_string()
					.into_bytes())),
				data: Vec::new(),
				read_error: None,
				code: None,
			};
		}
	};
	let code = c_code(f.code());
	let mut data = Vec::new();
	let r = f.read_to_end(&mut data);
	FilterOutcome {
		open_error: None,
		data,
		read_error: norm(r.err().map(|e| e.to_string().into_bytes())),
		code: Some(code),
	}
}

fn short(d: &[u8]) -> String {
	let n = d.len().min(48);
	format!("{} bytes {:02x?}", d.len(), &d[..n])
}

// the slowest compares so far: (the slower side, C, port, case, input
// and output size)
type Slow = (Duration, Duration, Duration, String, usize, usize);
static SLOWEST: Mutex<Vec<Slow>> = Mutex::new(Vec::new());

// the slowest compares of this process, one line each
pub fn filter_slowest() -> Vec<String> {
	SLOWEST.lock()
		.unwrap()
		.iter()
		.map(|(_, c, r, what, n, out)| {
			format!("C {c:?} port {r:?} {what}: {n} bytes -> {out}")
		})
		.collect()
}

// one input through libarchive's filters and the port's, in memory: the
// C's outcome, asserted equal
pub fn filter_compare(what: &str, input: &[u8]) -> FilterOutcome {
	if std::env::var_os("FILTER_TRACE").is_some() {
		eprintln!("{what}");
	}
	let t = Instant::now();
	let c = from_c(c_filter_memory(input));
	let tc = t.elapsed();
	let t = Instant::now();
	let r = from_port(open_memory(input.to_vec()));
	let tr = t.elapsed();
	let mut slow = SLOWEST.lock().unwrap();
	slow.push((tc.max(tr), tc, tr, what.into(), input.len(), c.data.len()));
	slow.sort_by_key(|s| std::cmp::Reverse(s.0));
	slow.truncate(10);
	drop(slow);
	assert!(
		c == r,
		"{what}: {}\nC    {:?} {} data {}\nport {:?} {} data {}",
		short(input),
		c.open_error.as_ref().map(|t| String::from_utf8_lossy(t)),
		String::from_utf8_lossy(c.read_error.as_deref().unwrap_or(b"")),
		c.data.len(),
		r.open_error.as_ref().map(|t| String::from_utf8_lossy(t)),
		String::from_utf8_lossy(r.read_error.as_deref().unwrap_or(b"")),
		r.data.len(),
	);
	c
}

// the same from a file read in 8 KiB blocks, like _alpm_open_archive
pub fn filter_compare_file(what: &str, input: &[u8]) {
	let t = TempRoot::new("filter-file");
	let p = PathBuf::from(OsString::from_vec(t.path("in")));
	fs::write(&p, input).unwrap();
	let c = from_c(c_filter_file(&p, 8192));
	let r = from_port(open_file(fs::File::open(&p).unwrap(), 8192));
	assert!(
		c == r,
		"{what} (file): {}\nC {c:?}\nport {r:?}",
		short(input)
	);
}
