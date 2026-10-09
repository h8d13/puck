// the alpm.h type layer: the #[repr(C)] structs the consumers read and
// compile-time checks that the enum values alpm-core carries are the
// alpm.h ones. the opaque handle/db/pkg pointers are our own wrappers
// (state.rs); C only ever sees them behind a pointer.

use std::ffi::{c_char, c_int, c_ulong, c_void};

use alpm_core::{DepMod, Errno, PkgReason};

/// alpm_list_t: a doubly linked list, {void *data; prev; next;}. the
/// field order and offsets are alpm.h's; consumers read `->data` and
/// `->next` directly (pyalpm util.c) and walk with alpm_list_next.
#[repr(C)]
pub struct AlpmList {
	pub data: *mut c_void,
	pub prev: *mut AlpmList,
	pub next: *mut AlpmList,
}

/// alpm_depend_t: the basic dependency type, read field by field by
/// consumers and passed to alpm_dep_compute_string. `mod` is a Rust
/// keyword, so the field is `mod_`; the layout is unchanged.
#[repr(C)]
pub struct AlpmDepend {
	pub name: *mut c_char,
	pub version: *mut c_char,
	pub desc: *mut c_char,
	pub name_hash: c_ulong,
	pub mod_: c_int,
}

// alpm_depmod_t: ANY=1 then EQ, GE, LE, GT, LT. alpm-core's DepMod
// carries the same discriminants; pin them so a reorder is caught here.
const _: () = {
	assert!(DepMod::Any as c_int == 1);
	assert!(DepMod::Eq as c_int == 2);
	assert!(DepMod::Ge as c_int == 3);
	assert!(DepMod::Le as c_int == 4);
	assert!(DepMod::Gt as c_int == 5);
	assert!(DepMod::Lt as c_int == 6);
};

// alpm_pkgreason_t: EXPLICIT=0, DEPEND=1, UNKNOWN=2.
const _: () = {
	assert!(PkgReason::Explicit as c_int == 0);
	assert!(PkgReason::Depend as c_int == 1);
	assert!(PkgReason::Unknown as c_int == 2);
};

// alpm_errno_t: 56 values, ALPM_ERR_OK = 0 first. alpm-core's Errno is
// declared #[repr(i32)] in the same order; ALL[i] as i32 == i.
const _: () = {
	assert!(Errno::Ok as c_int == 0);
	assert!(Errno::ALL.len() == 56);
	assert!(Errno::MissingCapabilitySignatures as c_int == 55);
};
