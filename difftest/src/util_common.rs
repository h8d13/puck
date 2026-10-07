// C side of src/common/util-common.c, from libcommon.a
use std::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};

use crate::{CFile as File, cstr, fclose, opt_ptr, take};

unsafe extern "C" {
	fn hex_representation(
		bytes: *const c_uchar,
		size: usize,
	) -> *mut c_char;
	fn mbasename(path: *const c_char) -> *const c_char;
	fn mdirname(path: *const c_char) -> *mut c_char;
	fn llstat(path: *mut c_char, buf: *mut Stat) -> c_int;
	fn safe_fgets(
		s: *mut c_char,
		size: c_int,
		stream: *mut File,
	) -> *mut c_char;
	fn strtrim(str: *mut c_char) -> usize;
	fn wordsplit(str: *const c_char) -> *mut *mut c_char;
	fn wordsplit_free(ws: *mut *mut c_char);

	fn fmemopen(
		buf: *mut c_void,
		size: usize,
		mode: *const c_char,
	) -> *mut File;
	fn fopen(path: *const c_char, mode: *const c_char) -> *mut File;
	fn ftell(f: *mut File) -> c_long;
	fn __errno_location() -> *mut c_int;
}

const EINVAL: c_int = 22;

pub(crate) fn errno() -> c_int {
	// SAFETY: glibc returns the calling thread's errno slot
	unsafe { *__errno_location() }
}

pub(crate) fn set_errno(v: c_int) {
	// SAFETY: as above, writable for this thread
	unsafe { *__errno_location() = v }
}

// struct stat as glibc lays it out on x86_64 (stat64 is the same there)
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Default)]
struct Stat {
	st_dev: u64,
	st_ino: u64,
	st_nlink: u64,
	st_mode: u32,
	st_uid: u32,
	st_gid: u32,
	_pad0: i32,
	st_rdev: u64,
	st_size: i64,
	st_blksize: i64,
	st_blocks: i64,
	st_times: [i64; 6],
	_unused: [i64; 3],
}

// the fields the port is compared on
#[derive(Debug, PartialEq, Eq)]
pub struct CStat {
	pub dev: u64,
	pub ino: u64,
	pub mode: u32,
	pub nlink: u64,
	pub size: i64,
}

pub fn c_hex_representation(bytes: &[u8]) -> Vec<u8> {
	// SAFETY: bytes holds bytes.len() readable bytes, result is malloc'd
	let r = unsafe { hex_representation(bytes.as_ptr(), bytes.len()) };
	take(r).unwrap()
}

pub fn c_mbasename(path: &[u8]) -> Vec<u8> {
	let p = cstr(path);
	// SAFETY: valid C string, result points into it (p still alive)
	let r = unsafe { CStr::from_ptr(mbasename(p.as_ptr())) };
	r.to_bytes().to_vec()
}

// None maps to NULL
pub fn c_mdirname(path: Option<&[u8]>) -> Vec<u8> {
	let p = path.map(cstr);
	// SAFETY: NULL or a valid C string, result is malloc'd
	take(unsafe { mdirname(opt_ptr(&p)) }).unwrap()
}

// Err is errno. the C writes into the path and must put it back
pub fn c_llstat(path: &[u8]) -> Result<CStat, i32> {
	let mut buf = cstr(path).into_bytes_with_nul();
	let before = buf.clone();
	let mut st = Stat::default();
	// SAFETY: buf is a writable nul-terminated buffer, st a valid stat
	let rc = unsafe { llstat(buf.as_mut_ptr().cast(), &mut st) };
	let err = errno();
	assert_eq!(buf, before, "llstat did not restore its path");
	if rc != 0 {
		return Err(err);
	}
	Ok(CStat {
		dev: st.st_dev,
		ino: st.st_ino,
		mode: st.st_mode,
		nlink: st.st_nlink,
		size: st.st_size,
	})
}

// returns the C length and the trimmed string
pub fn c_strtrim(s: &[u8]) -> (usize, Vec<u8>) {
	let mut buf = cstr(s).into_bytes_with_nul();
	// SAFETY: writable nul-terminated buffer, trimmed in place
	let n = unsafe { strtrim(buf.as_mut_ptr().cast()) };
	// SAFETY: still nul-terminated after the in-place trim
	let r = unsafe { CStr::from_ptr(buf.as_ptr().cast()) };
	(n, r.to_bytes().to_vec())
}

pub fn c_strtrim_null() -> usize {
	// SAFETY: strtrim checks for NULL first
	unsafe { strtrim(std::ptr::null_mut()) }
}

// None is the C NULL, errno must then be EINVAL (malloc failures aside)
pub fn c_wordsplit(s: Option<&[u8]>) -> Option<Vec<Vec<u8>>> {
	let p = s.map(cstr);
	set_errno(0);
	// SAFETY: NULL or a valid C string
	let ws = unsafe { wordsplit(opt_ptr(&p)) };
	if ws.is_null() {
		assert_eq!(errno(), EINVAL, "wordsplit({s:?})");
		return None;
	}
	let mut out = Vec::new();
	for i in 0.. {
		// SAFETY: ws is a NULL-terminated array of C strings
		let w = unsafe { *ws.add(i) };
		if w.is_null() {
			break;
		}
		// SAFETY: each entry is a valid nul-terminated string
		out.push(unsafe { CStr::from_ptr(w) }.to_bytes().to_vec());
	}
	// SAFETY: ws came from wordsplit, not used afterwards
	unsafe { wordsplit_free(ws) };
	Some(out)
}

// repeated safe_fgets on f until NULL or max_calls. each chunk is the
// raw bytes fgets stored, nul bytes included: its length comes from the
// stream position, and the C buffer must hold exactly data[pos..] + '\0'
fn fgets_chunks(
	f: *mut File,
	data: &[u8],
	size: i32,
	max_calls: usize,
) -> Vec<Vec<u8>> {
	let mut buf = vec![0xa5u8; size.max(1) as usize];
	let mut chunks = Vec::new();
	for _ in 0..max_calls {
		buf.fill(0xa5);
		// SAFETY: f is an open stream
		let pos = unsafe { ftell(f) } as usize;
		// errno 0: safe_fgets loops on a stale EINTR, see report
		set_errno(0);
		// SAFETY: buf has max(size, 1) writable bytes, f is open
		let r = unsafe { safe_fgets(buf.as_mut_ptr().cast(), size, f) };
		if r.is_null() {
			break;
		}
		assert_eq!(r.cast::<u8>(), buf.as_mut_ptr());
		// SAFETY: f is an open stream
		let n = unsafe { ftell(f) } as usize - pos;
		assert_eq!(buf[n], 0, "chunk not nul-terminated");
		assert_eq!(&buf[..n], &data[pos..pos + n]);
		chunks.push(buf[..n].to_vec());
	}
	chunks
}

// safe_fgets over an in-memory FILE (fmemopen)
pub fn c_fgets_mem(data: &[u8], size: i32, max_calls: usize) -> Vec<Vec<u8>> {
	let mut copy = data.to_vec();
	// fmemopen wants a non-empty buffer, size 0 is still passed
	copy.push(0);
	let mode = cstr(b"r");
	// SAFETY: copy outlives the stream, read-only mode
	let f = unsafe {
		fmemopen(copy.as_mut_ptr().cast(), data.len(), mode.as_ptr())
	};
	assert!(!f.is_null(), "fmemopen failed");
	let chunks = fgets_chunks(f, data, size, max_calls);
	// SAFETY: f open, not used afterwards
	unsafe { fclose(f) };
	chunks
}

// safe_fgets over a real file, path must hold exactly data
pub fn c_fgets_file(
	path: &[u8],
	data: &[u8],
	size: i32,
	max_calls: usize,
) -> Vec<Vec<u8>> {
	let (p, mode) = (cstr(path), cstr(b"r"));
	// SAFETY: two valid C strings
	let f = unsafe { fopen(p.as_ptr(), mode.as_ptr()) };
	assert!(!f.is_null(), "fopen failed");
	let chunks = fgets_chunks(f, data, size, max_calls);
	// SAFETY: f open, not used afterwards
	unsafe { fclose(f) };
	chunks
}
