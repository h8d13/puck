// C side of lib/libalpm/backup.c, internal symbols from the static archive
use std::ffi::{c_char, c_int};

use alpm_core::backup::Backup;

use crate::{c_free, cstr, opt_ptr, take};

// alpm_backup_t
#[repr(C)]
struct CBackup {
	name: *mut c_char,
	hash: *mut c_char,
}

unsafe extern "C" {
	fn _alpm_split_backup(
		s: *const c_char,
		backup: *mut *mut CBackup,
	) -> c_int;
	fn _alpm_backup_dup(backup: *const CBackup) -> *mut CBackup;
}

// None maps to NULL. returns rc and the name/hash the C stored
pub fn c_split_backup(
	s: Option<&[u8]>,
) -> (i32, Option<Vec<u8>>, Option<Vec<u8>>) {
	let s = s.map(cstr);
	let mut b = CBackup {
		name: std::ptr::null_mut(),
		hash: std::ptr::null_mut(),
	};
	let mut bp: *mut CBackup = &mut b;
	// SAFETY: s is NULL or a valid C string, bp points to a live struct
	// the C fills with malloc'd strings or NULL
	let rc = unsafe { _alpm_split_backup(opt_ptr(&s), &mut bp) };
	(rc, take(b.name), take(b.hash))
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
		name: take(n).unwrap(),
		hash: take(h),
	};
	c_free(d.cast());
	out
}
