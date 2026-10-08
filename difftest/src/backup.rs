// C side of lib/libalpm/backup.c, internal symbols from the static archive
use std::ffi::c_char;

use alpm_core::backup::Backup;
use alpm_core::package::Package;

use crate::package::{CPkg, CPkgBox, alpm_pkg_get_backup, list_data};
use crate::{c_free, cstr, opt_ptr, take};

// alpm_backup_t
#[repr(C)]
struct CBackup {
	name: *mut c_char,
	hash: *mut c_char,
}

unsafe extern "C" {
	fn _alpm_backup_dup(backup: *const CBackup) -> *mut CBackup;
	fn _alpm_needbackup(
		file: *const c_char,
		pkg: *mut CPkg,
	) -> *mut CBackup;
}

pub fn c_backup_dup(backup: &Backup) -> Backup {
	let name = cstr(&backup.name);
	let hash = backup.hash.as_deref().map(cstr);
	let b = CBackup {
		name: name.as_ptr().cast_mut(),
		hash: opt_ptr(&hash).cast_mut(),
	};
	// SAFETY: b holds valid C strings (hash maybe NULL), the C only reads
	// them and returns a calloc'd struct with fresh copies
	let d = unsafe { _alpm_backup_dup(&b) };
	assert!(!d.is_null());
	// SAFETY: d is the valid struct just returned
	let (n, h) = unsafe { ((*d).name, (*d).hash) };
	let out = Backup {
		name: take(n).unwrap().into(),
		hash: take(h).map(Box::from),
	};
	c_free(d.cast());
	out
}

// position in pkg.backup of the entry _alpm_needbackup returns
pub fn c_needbackup(file: &[u8], pkg: &Package) -> Option<usize> {
	let b = CPkgBox::new(pkg);
	let f = cstr(file);
	// SAFETY: b.0 is live, f a valid C string; the result points into
	// b.0's backup list, read as a pointer only
	let found = unsafe { _alpm_needbackup(f.as_ptr(), b.0) };
	// SAFETY: b.0 is live, the list stays owned by it
	let list = unsafe { alpm_pkg_get_backup(b.0) };
	list_data(list).iter().position(|&p| p == found.cast())
}

// contract for the C ABI shim: NULL file or package gives NULL
pub fn c_needbackup_null() -> (bool, bool) {
	let b = CPkgBox::new(&Package::default());
	let f = cstr(b"x");
	// SAFETY: NULL arguments return before any dereference
	unsafe {
		(
			_alpm_needbackup(std::ptr::null(), b.0).is_null(),
			_alpm_needbackup(f.as_ptr(), std::ptr::null_mut())
				.is_null(),
		)
	}
}
