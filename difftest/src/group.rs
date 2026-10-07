// C side of lib/libalpm/group.c, internal symbols from the static archive
use std::ffi::{CStr, c_char};

use crate::CList;
use crate::{cstr, opt_ptr};

// alpm_group_t, alpm.h
#[repr(C)]
pub(crate) struct CGroup {
	pub(crate) name: *mut c_char,
	pub(crate) packages: *mut CList,
}

unsafe extern "C" {
	fn _alpm_group_new(name: *const c_char) -> *mut CGroup;
	fn _alpm_group_free(grp: *mut CGroup);
}

// None maps to NULL. the copied name (None for NULL) and whether the
// member list starts empty
pub fn c_group_new(name: Option<&[u8]>) -> (Option<Vec<u8>>, bool) {
	let name = name.map(cstr);
	// SAFETY: name is NULL or a valid C string, result calloc'd
	let g = unsafe { _alpm_group_new(opt_ptr(&name)) };
	assert!(!g.is_null());
	// SAFETY: g is the valid struct just returned, freed after the copy
	unsafe {
		let n = (*g).name;
		let out = (!n.is_null())
			.then(|| CStr::from_ptr(n).to_bytes().to_vec());
		let empty = (*g).packages.is_null();
		_alpm_group_free(g);
		(out, empty)
	}
}
