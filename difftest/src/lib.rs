// safe wrappers over the C reference, so tests compare like with like.
// one module per C source file, shared helpers here.
use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::{Mutex, MutexGuard};

mod backup;
mod be_local;
mod be_local_write;
mod be_package;
mod be_sync;
mod callback;
mod check;
mod cli_util;
mod cli_util2;
mod conf;
mod conflict;
mod database;
mod db;
mod db_search;
mod db_update;
mod deps;
mod deps_graph;
mod deps_resolve;
mod diskspace;
mod dload;
mod error;
mod filelist;
mod files_op;
mod fixtures;
mod getopt;
mod group;
mod handle;
mod handle_opts;
mod hook;
mod ini;
mod package;
mod pkg_show;
mod pkghash;
mod query;
mod regex;
mod remove_commit;
mod sandbox;
mod signing;
mod sync_ro;
mod trans_prep;
mod util;
mod util_common;
mod version;

pub use backup::*;
pub use be_local::*;
pub use be_local_write::*;
pub use be_package::*;
pub use be_sync::*;
pub use callback::*;
pub use check::*;
pub use cli_util::*;
pub use cli_util2::*;
pub use conf::*;
pub use conflict::*;
pub use database::*;
pub use db::*;
pub use db_search::*;
pub use db_update::*;
pub use deps::*;
pub use deps_graph::*;
pub use deps_resolve::*;
pub use diskspace::*;
pub use dload::*;
pub use error::*;
pub use filelist::*;
pub use files_op::*;
pub use fixtures::*;
pub use getopt::*;
pub use group::*;
pub use handle_opts::*;
pub use hook::*;
pub use ini::*;
pub use package::*;
pub use pkg_show::*;
pub use pkghash::*;
pub use query::*;
pub use regex::*;
pub use remove_commit::*;
pub use sandbox::*;
pub use signing::*;
pub use sync_ro::*;
pub use trans_prep::*;
pub use util::*;
pub use util_common::*;
pub use version::*;

// the umask is process wide: C that sets it (dload's _getumask,
// umask(0) in _alpm_makepath_mode and _alpm_local_db_prepare,
// umask(0022) in _alpm_unpack and _alpm_local_db_write) changes the
// modes of files every other thread creates meanwhile, port and fixtures
// alike. a case running such C, or comparing modes of files created next
// to it, holds this lock for both sides. taken before a C handle (the
// ALPM lock), never while holding one
static UMASK: Mutex<()> = Mutex::new(());

pub fn umask_lock() -> MutexGuard<'static, ()> {
	UMASK.lock().unwrap_or_else(|e| e.into_inner())
}

// libc FILE, opaque. one declaration for every module, rustc flags
// clashing extern signatures across modules
#[repr(C)]
pub(crate) struct CFile {
	_private: [u8; 0],
}

// alpm_list_t mirror, shared by every module passing lists to the C
#[repr(C)]
pub(crate) struct CList {
	pub(crate) data: *mut c_void,
	// set when lists are built on the Rust side, read only by the C
	#[allow(dead_code)]
	pub(crate) prev: *mut CList,
	pub(crate) next: *mut CList,
}

unsafe extern "C" {
	fn free(p: *mut c_void);
	pub(crate) fn alpm_list_add(
		list: *mut CList,
		data: *mut c_void,
	) -> *mut CList;
	pub(crate) fn alpm_list_free(list: *mut CList);
	pub(crate) fn fclose(f: *mut CFile) -> std::ffi::c_int;
	pub(crate) fn fflush(f: *mut CFile) -> std::ffi::c_int;
	pub(crate) fn open_memstream(
		buf: *mut *mut c_char,
		size: *mut usize,
	) -> *mut CFile;
	pub(crate) fn strdup(s: *const c_char) -> *mut c_char;
	pub(crate) static mut stdout: *mut CFile;
	pub(crate) static mut stderr: *mut CFile;
	// va_list passed as a pointer: valid on x86_64 and aarch64
	pub(crate) fn vsnprintf(
		s: *mut c_char,
		n: usize,
		fmt: *const c_char,
		ap: *mut c_void,
	) -> std::ffi::c_int;
}

// interior nul panics, the C could not see past it anyway
pub(crate) fn cstr(s: &[u8]) -> CString {
	CString::new(s).unwrap()
}

// None maps to NULL
pub(crate) fn opt_ptr(s: &Option<CString>) -> *const c_char {
	s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr())
}

// copies a malloc'd C string out and frees it
pub(crate) fn take(p: *mut c_char) -> Option<Vec<u8>> {
	if p.is_null() {
		return None;
	}
	// SAFETY: p is a nul-terminated string malloc'd by libalpm
	let v = unsafe { CStr::from_ptr(p) }.to_bytes().to_vec();
	c_free(p.cast());
	Some(v)
}

pub(crate) fn c_free(p: *mut c_void) {
	// SAFETY: callers only pass NULL or pointers malloc'd by libalpm,
	// not used afterwards
	unsafe { free(p) }
}

// fuzz iterations per test, DIFFTEST_ITERS overrides
pub fn iters() -> usize {
	std::env::var("DIFFTEST_ITERS").map_or(200_000, |s| s.parse().unwrap())
}

// xorshift64, deterministic fuzz input without a rand crate
pub struct Rng(u64);

impl Rng {
	pub fn new(seed: u64) -> Self {
		Rng(seed.max(1))
	}

	pub fn next_u64(&mut self) -> u64 {
		let mut x = self.0;
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
		self.0 = x;
		x
	}

	pub fn below(&mut self, n: usize) -> usize {
		(self.next_u64() % n as u64) as usize
	}

	pub fn pick(&mut self, alphabet: &[u8]) -> u8 {
		alphabet[self.below(alphabet.len())]
	}

	// up to max - 1 bytes drawn from alphabet
	pub fn bytes(&mut self, alphabet: &[u8], max: usize) -> Vec<u8> {
		(0..self.below(max)).map(|_| self.pick(alphabet)).collect()
	}
}
