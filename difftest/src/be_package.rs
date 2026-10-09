// C side of lib/libalpm/be_package.c through the exported API: one handle
// on a fixture root, package files loaded with alpm_pkg_load at siglevel
// 0 and read through the package mirror, with the lines each load logs
use std::ffi::{c_int, c_void};
use std::path::Path;
use std::ptr;
use std::sync::MutexGuard;

use alpm_core::internals::package::Package;

use crate::cstr;
use crate::handle::{
	_alpm_pkg_validate_internal, ALPM, CLogs, alpm_errno, alpm_initialize,
	alpm_option_set_logcb, alpm_pkg_changelog_close,
	alpm_pkg_changelog_open, alpm_pkg_changelog_read, alpm_pkg_free,
	alpm_pkg_load, alpm_release, record_log,
};
use crate::package::{CPkg, CPkgBox, read_pkg};

// a live handle; holds the ALPM lock for its lifetime, alpm_initialize
// and alpm_release are not thread safe
pub struct CPkgHandle {
	h: *mut c_void,
	logs: *mut CLogs,
	_guard: MutexGuard<'static, ()>,
}

// a loaded package with what alpm_pkg_changelog_* read from it, None
// when open returned NULL. a read error ends the bytes early
#[derive(Debug)]
pub struct CLoaded {
	pub pkg: Package,
	pub changelog: Option<Vec<u8>>,
}

// alpm_pkg_load's result (Err is pm_errno) and the lines it logged
pub type CLoad = (Result<CLoaded, c_int>, CLogs);

impl CPkgHandle {
	// root and dbpath must exist
	pub fn new(root: &Path, dbpath: &Path) -> Self {
		let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let root = cstr(root.as_os_str().as_encoded_bytes());
		let dbpath = cstr(dbpath.as_os_str().as_encoded_bytes());
		let mut err = 0;
		// SAFETY: valid C strings, err receives the failure code
		let h = unsafe {
			alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			)
		};
		assert!(!h.is_null(), "alpm_initialize failed: {err}");
		let logs = Box::into_raw(Box::new(CLogs::new()));
		// SAFETY: h is live, logs stays valid until after the release
		unsafe {
			alpm_option_set_logcb(h, Some(record_log), logs.cast())
		};
		CPkgHandle {
			h,
			logs,
			_guard: guard,
		}
	}

	// what the C logged since the last call
	fn take_logs(&self) -> CLogs {
		// SAFETY: logs is live until drop, the C is not running
		std::mem::take(unsafe { &mut *self.logs })
	}

	// alpm_pkg_load(handle, path, full, 0, &pkg) with its log lines; the
	// changelog reads after it are not logged
	pub fn load_logged(&self, path: &[u8], full: bool) -> CLoad {
		self.take_logs();
		let r = self.load_pkg(path, full);
		let logs = self.take_logs();
		(r.map(|pkg| self.loaded(pkg)), logs)
	}

	// alpm_pkg_load(handle, path, full, 0, &pkg), Err is pm_errno
	pub fn load(&self, path: &[u8], full: bool) -> Result<CLoaded, c_int> {
		self.load_logged(path, full).0
	}

	fn load_pkg(
		&self,
		path: &[u8],
		full: bool,
	) -> Result<*mut CPkg, c_int> {
		let path = cstr(path);
		let mut pkg: *mut CPkg = ptr::null_mut();
		// SAFETY: live handle, valid string, pkg receives a new
		// package or stays NULL
		let rc = unsafe {
			alpm_pkg_load(
				self.h,
				path.as_ptr(),
				full as c_int,
				0,
				&mut pkg,
			)
		};
		if rc != 0 {
			assert!(pkg.is_null());
			// SAFETY: live handle
			return Err(unsafe { alpm_errno(self.h) });
		}
		Ok(pkg)
	}

	// the package's fields and changelog, the package freed
	fn loaded(&self, pkg: *mut CPkg) -> CLoaded {
		let out = CLoaded {
			pkg: read_pkg(pkg),
			changelog: self.changelog(pkg),
		};
		// SAFETY: pkg came from alpm_pkg_load, not used afterwards
		unsafe { alpm_pkg_free(pkg) };
		self.take_logs();
		out
	}

	fn changelog(&self, pkg: *mut CPkg) -> Option<Vec<u8>> {
		// SAFETY: pkg is a live file package with its ops, the stream
		// is read until 0 and closed before returning
		unsafe {
			let fp = alpm_pkg_changelog_open(pkg);
			if fp.is_null() {
				return None;
			}
			let mut out = Vec::new();
			let mut buf = [0u8; 4096];
			loop {
				let n = alpm_pkg_changelog_read(
					buf.as_mut_ptr().cast(),
					buf.len(),
					pkg,
					fp,
				);
				if n == 0 {
					break;
				}
				out.extend_from_slice(&buf[..n]);
			}
			alpm_pkg_changelog_close(pkg, fp);
			Some(out)
		}
	}

	// _alpm_pkg_validate_internal at level 0, Ok is the validation bits,
	// Err pm_errno
	pub fn validate(
		&self,
		path: &[u8],
		syncpkg: Option<&Package>,
	) -> Result<c_int, c_int> {
		let path = cstr(path);
		let sync = syncpkg.map(CPkgBox::new);
		let sp = sync.as_ref().map_or(ptr::null_mut(), |b| b.0);
		let mut validation = 0;
		// SAFETY: live handle and package, level 0 never touches
		// sigdata
		let rc = unsafe {
			_alpm_pkg_validate_internal(
				self.h,
				path.as_ptr(),
				sp,
				0,
				ptr::null_mut(),
				&mut validation,
			)
		};
		if rc != 0 {
			// SAFETY: live handle
			return Err(unsafe { alpm_errno(self.h) });
		}
		Ok(validation)
	}
}

impl Drop for CPkgHandle {
	fn drop(&mut self) {
		// SAFETY: h is live and not used afterwards
		unsafe { alpm_release(self.h) };
		// SAFETY: from Box::into_raw in new, the handle using it is
		// released; the lock is released after
		drop(unsafe { Box::from_raw(self.logs) });
	}
}

// the texts of libarchive's mtree reader, which the port has too
const MTREE_TEXTS: [&[u8]; 20] = [
	b"Unrecognized archive format\n",
	b"Can't parse line ",
	b"Line too long\n",
	b"/unset shall not contain",
	b"Missing type keyword",
	b"Malformed attribute ",
	b"Unrecognized key ",
	b"Unrecognized file type ",
	b"Symbolic or non-octal mode ",
	b"incorrect digest length",
	b"invalid digest data",
	b"Unknown format `",
	b"Missing number\n",
	b"Too many arguments\n",
	b"Not enough arguments\n",
	b"invalid major number\n",
	b"invalid minor number\n",
	b"too many fields for format\n",
	b"invalid unit number\n",
	b"invalid subunit number\n",
];

// libarchive's own error texts cannot match the port's (its reader,
// strerror, an fd number): cut after the path of an open failure, a read
// failure and an mtree failure (unless the mtree reader's own text), the
// message's newline kept. one message, wherever the head sits in it
// (after testpkg's or pacman's colored "error: ")
pub fn cut_archive_text(msg: &[u8]) -> Vec<u8> {
	let mtree: &[u8] = b"error while reading mtree of package ";
	let heads = [
		&b"could not open file "[..],
		b"error while reading package ",
		mtree,
	];
	let mut out = msg.to_vec();
	for head in heads {
		let Some(body) =
			out.windows(head.len()).position(|w| w == head)
		else {
			continue;
		};
		let start = body + head.len();
		let Some(i) = out[start..].windows(2).position(|w| w == b": ")
		else {
			continue;
		};
		let at = start + i + 2;
		let text = &out[at..];
		if head != mtree
			|| !MTREE_TEXTS.iter().any(|t| text.starts_with(t))
		{
			let nl = out.ends_with(b"\n");
			out.truncate(at);
			out.extend(nl.then_some(b'\n'));
		}
	}
	out
}
