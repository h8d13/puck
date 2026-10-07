// C side of lib/libalpm/be_package.c through the exported API: one handle
// on a fixture root, package files loaded with alpm_pkg_load at siglevel
// 0 and read through the package mirror
use std::ffi::{c_int, c_void};
use std::path::Path;
use std::ptr;
use std::sync::MutexGuard;

use alpm_core::package::Package;

use crate::cstr;
use crate::handle::{
	_alpm_pkg_validate_internal, ALPM, alpm_errno, alpm_initialize,
	alpm_pkg_changelog_close, alpm_pkg_changelog_open,
	alpm_pkg_changelog_read, alpm_pkg_free, alpm_pkg_load, alpm_release,
};
use crate::package::{CPkg, CPkgBox, read_pkg};

// a live handle; holds the ALPM lock for its lifetime, alpm_initialize
// and alpm_release are not thread safe
pub struct CPkgHandle {
	h: *mut c_void,
	_guard: MutexGuard<'static, ()>,
}

// a loaded package with what alpm_pkg_changelog_* read from it, None
// when open returned NULL. a read error ends the bytes early
#[derive(Debug)]
pub struct CLoaded {
	pub pkg: Package,
	pub changelog: Option<Vec<u8>>,
}

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
		CPkgHandle { h, _guard: guard }
	}

	// alpm_pkg_load(handle, path, full, 0, &pkg), Err is pm_errno
	pub fn load(&self, path: &[u8], full: bool) -> Result<CLoaded, c_int> {
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
		let out = CLoaded {
			pkg: read_pkg(pkg),
			changelog: self.changelog(pkg),
		};
		// SAFETY: pkg came from alpm_pkg_load, not used afterwards
		unsafe { alpm_pkg_free(pkg) };
		Ok(out)
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
	}
}
