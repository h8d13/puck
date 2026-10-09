//! libalpm.so.16 C ABI shim: a thin `unsafe` cdylib on alpm-core's
//! public (default-feature) API, the `alpm.h` surface C/Python/Go/Rust
//! front ends link. the only crate besides difftest that may use
//! `unsafe`; every block carries a `// SAFETY:` note.
//!
//! this is the read-path subset (PORTING.md "C ABI"): open a handle,
//! read the local and sync dbs and their packages' fields, and vercmp.
//! opaque pointers are our own wrappers (state.rs) so a db or package
//! address stays valid for the handle's life, as alpm.h promises.

// every exported function takes raw pointers the C caller owns; the
// SAFETY notes document the contract. the symbols stay plain (not
// `unsafe extern`) to match the real libalpm's signatures.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod state;
mod stubs;
mod types;

use std::cmp::Ordering;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr::null;
use std::sync::LazyLock;

use alpm_core::{DepMod, Depend, Errno, Handle, LIB_VERSION, vercmp};

use state::{CapiDb, CapiHandle, CapiPkg, to_cstring};
use types::{AlpmDepend, AlpmList};

// the C caller frees alpm_dep_compute_string's result with free(3), so
// it must come from the same allocator; declare malloc rather than pull
// in libc for one symbol
unsafe extern "C" {
	fn malloc(size: usize) -> *mut c_void;
}

// opaque handle types as alpm.h names them; C only sees them by pointer
#[allow(non_camel_case_types)]
pub type alpm_handle_t = CapiHandle;
#[allow(non_camel_case_types)]
pub type alpm_db_t = CapiDb;
#[allow(non_camel_case_types)]
pub type alpm_pkg_t = CapiPkg;

// borrow a C string pointer as bytes, or None for NULL
fn opt_bytes<'a>(p: *const c_char) -> Option<&'a [u8]> {
	if p.is_null() {
		None
	} else {
		// SAFETY: a non-NULL pointer here is a nul-terminated C string
		// the caller keeps alive for the call; we only read it
		Some(unsafe { CStr::from_ptr(p) }.to_bytes())
	}
}

// ---- misc ---------------------------------------------------------------

/// alpm_version: libalpm's LIB_VERSION of the tracked release
#[unsafe(no_mangle)]
pub extern "C" fn alpm_version() -> *const c_char {
	static V: LazyLock<CString> =
		LazyLock::new(|| to_cstring(LIB_VERSION.as_bytes()));
	V.as_ptr()
}

/// alpm_capabilities: puck has the downloader (reqwest) and signature
/// checking (gpg), no gettext (English msgids), so no NLS bit
#[unsafe(no_mangle)]
pub extern "C" fn alpm_capabilities() -> c_int {
	// ALPM_CAPABILITY_DOWNLOADER | ALPM_CAPABILITY_SIGNATURES
	(1 << 1) | (1 << 2)
}

/// alpm_strerror: static message for an alpm_errno_t, the C locale msgid
#[unsafe(no_mangle)]
pub extern "C" fn alpm_strerror(err: c_int) -> *const c_char {
	static MSGS: LazyLock<Vec<CString>> = LazyLock::new(|| {
		Errno::ALL
			.iter()
			.map(|e| to_cstring(e.strerror().as_bytes()))
			.collect()
	});
	let unexpected: &CStr = c"unexpected error";
	match Errno::from_raw(err) {
		Some(e) => MSGS[e as usize].as_ptr(),
		None => unexpected.as_ptr(),
	}
}

// ---- handle -------------------------------------------------------------

/// alpm_errno: the handle's last stored error code
#[unsafe(no_mangle)]
pub extern "C" fn alpm_errno(handle: *mut alpm_handle_t) -> c_int {
	match as_ref(handle) {
		Some(h) => *h.last_err.borrow() as c_int,
		None => Errno::Ok as c_int,
	}
}

/// alpm_initialize: a handle over root/dbpath, or NULL with *err set
#[unsafe(no_mangle)]
pub extern "C" fn alpm_initialize(
	root: *const c_char,
	dbpath: *const c_char,
	err: *mut c_int,
) -> *mut alpm_handle_t {
	let (Some(root), Some(dbpath)) = (opt_bytes(root), opt_bytes(dbpath))
	else {
		set_err_out(err, Errno::WrongArgs);
		return null_handle();
	};
	match Handle::initialize(root, dbpath) {
		Ok(inner) => Box::into_raw(CapiHandle::new(inner)),
		Err(e) => {
			set_err_out(err, e);
			null_handle()
		}
	}
}

/// alpm_release: drop the handle (unregisters its dbs, closes the log)
#[unsafe(no_mangle)]
pub extern "C" fn alpm_release(handle: *mut alpm_handle_t) -> c_int {
	if handle.is_null() {
		return -1;
	}
	// SAFETY: handle came from alpm_initialize's Box::into_raw and is
	// released once; reconstructing the Box drops the CapiHandle
	drop(unsafe { Box::from_raw(handle) });
	0
}

/// alpm_option_get_root (handle-owned, trailing '/')
#[unsafe(no_mangle)]
pub extern "C" fn alpm_option_get_root(
	handle: *mut alpm_handle_t,
) -> *const c_char {
	as_ref(handle).map_or(null(), CapiHandle::root)
}

/// alpm_option_get_dbpath (handle-owned, trailing '/')
#[unsafe(no_mangle)]
pub extern "C" fn alpm_option_get_dbpath(
	handle: *mut alpm_handle_t,
) -> *const c_char {
	as_ref(handle).map_or(null(), CapiHandle::dbpath)
}

/// alpm_option_get_architectures: handle-owned list of strings
#[unsafe(no_mangle)]
pub extern "C" fn alpm_option_get_architectures(
	handle: *mut alpm_handle_t,
) -> *mut AlpmList {
	as_ref(handle).map_or(std::ptr::null_mut(), CapiHandle::architectures)
}

/// alpm_get_localdb: the local db wrapper (stable address)
#[unsafe(no_mangle)]
pub extern "C" fn alpm_get_localdb(
	handle: *mut alpm_handle_t,
) -> *mut alpm_db_t {
	as_ref(handle).map_or(std::ptr::null_mut(), CapiHandle::localdb)
}

/// alpm_get_syncdbs: handle-owned list of the sync db wrappers
#[unsafe(no_mangle)]
pub extern "C" fn alpm_get_syncdbs(
	handle: *mut alpm_handle_t,
) -> *mut AlpmList {
	as_ref(handle).map_or(std::ptr::null_mut(), CapiHandle::syncdbs)
}

/// alpm_register_syncdb: register then a stable db wrapper, NULL on error
#[unsafe(no_mangle)]
pub extern "C" fn alpm_register_syncdb(
	handle: *mut alpm_handle_t,
	treename: *const c_char,
	siglevel: c_int,
) -> *mut alpm_db_t {
	let Some(h) = as_ref(handle) else {
		return std::ptr::null_mut();
	};
	match opt_bytes(treename) {
		Some(name) => h.register_syncdb(name, siglevel),
		None => {
			h.set_err(Errno::WrongArgs);
			std::ptr::null_mut()
		}
	}
}

// ---- db -----------------------------------------------------------------

/// alpm_db_get_name (db-owned)
#[unsafe(no_mangle)]
pub extern "C" fn alpm_db_get_name(db: *const alpm_db_t) -> *const c_char {
	as_db_ref(db).map_or(null(), CapiDb::name)
}

/// alpm_db_get_pkgcache: db-owned list of alpm_pkg_t (not caller-freed)
#[unsafe(no_mangle)]
pub extern "C" fn alpm_db_get_pkgcache(db: *mut alpm_db_t) -> *mut AlpmList {
	as_db_ref(db).map_or(std::ptr::null_mut(), CapiDb::pkgcache)
}

/// alpm_db_get_pkg: one package by name, NULL (pm_errno set) if missing
#[unsafe(no_mangle)]
pub extern "C" fn alpm_db_get_pkg(
	db: *mut alpm_db_t,
	name: *const c_char,
) -> *mut alpm_pkg_t {
	let Some(d) = as_db_ref(db) else {
		return std::ptr::null_mut();
	};
	match opt_bytes(name) {
		Some(name) => d.get_pkg(name),
		None => std::ptr::null_mut(),
	}
}

// ---- package getters ----------------------------------------------------

macro_rules! pkg_str {
	($fn:ident, $field:expr) => {
		#[unsafe(no_mangle)]
		pub extern "C" fn $fn(pkg: *mut alpm_pkg_t) -> *const c_char {
			as_pkg_ref(pkg).map_or(null(), |p| p.cstr($field))
		}
	};
}
pkg_str!(alpm_pkg_get_name, state::F_NAME);
pkg_str!(alpm_pkg_get_version, state::F_VERSION);
pkg_str!(alpm_pkg_get_desc, state::F_DESC);
pkg_str!(alpm_pkg_get_arch, state::F_ARCH);

macro_rules! pkg_list {
	($fn:ident, $id:expr) => {
		#[unsafe(no_mangle)]
		pub extern "C" fn $fn(pkg: *mut alpm_pkg_t) -> *mut AlpmList {
			as_pkg_ref(pkg)
				.map_or(std::ptr::null_mut(), |p| p.list($id))
		}
	};
}
pkg_list!(alpm_pkg_get_licenses, state::L_LICENSES);
pkg_list!(alpm_pkg_get_groups, state::L_GROUPS);
pkg_list!(alpm_pkg_get_depends, state::L_DEPENDS);

/// alpm_pkg_get_isize: off_t (int64 on x86_64)
#[unsafe(no_mangle)]
pub extern "C" fn alpm_pkg_get_isize(pkg: *mut alpm_pkg_t) -> i64 {
	as_pkg_ref(pkg).map_or(0, CapiPkg::isize)
}

/// alpm_pkg_get_builddate: alpm_time_t (int64)
#[unsafe(no_mangle)]
pub extern "C" fn alpm_pkg_get_builddate(pkg: *mut alpm_pkg_t) -> i64 {
	as_pkg_ref(pkg).map_or(0, CapiPkg::builddate)
}

/// alpm_pkg_get_reason: alpm_pkgreason_t (0 explicit, 1 depend, 2 unknown)
#[unsafe(no_mangle)]
pub extern "C" fn alpm_pkg_get_reason(pkg: *mut alpm_pkg_t) -> c_int {
	as_pkg_ref(pkg).map_or(0, CapiPkg::reason)
}

// ---- deps / version -----------------------------------------------------

/// alpm_dep_compute_string: "name[op ver][: desc]", malloc'd, caller frees
#[unsafe(no_mangle)]
pub extern "C" fn alpm_dep_compute_string(
	dep: *const AlpmDepend,
) -> *mut c_char {
	let Some(d) = as_ref(dep as *mut AlpmDepend) else {
		return std::ptr::null_mut();
	};
	let depmod = match d.mod_ {
		1 => DepMod::Any,
		2 => DepMod::Eq,
		3 => DepMod::Ge,
		4 => DepMod::Le,
		5 => DepMod::Gt,
		6 => DepMod::Lt,
		_ => DepMod::Any,
	};
	let rebuilt = Depend {
		name: opt_bytes(d.name).unwrap_or(b"").into(),
		version: opt_bytes(d.version).map(Into::into),
		desc: opt_bytes(d.desc).map(Into::into),
		name_hash: d.name_hash,
		depmod,
	};
	let s = alpm_core::dep_compute_string(&rebuilt);
	c_strdup(&s)
}

/// alpm_pkg_vercmp: the c_null_contract NULL behaviour, then rpmvercmp
#[unsafe(no_mangle)]
pub extern "C" fn alpm_pkg_vercmp(a: *const c_char, b: *const c_char) -> c_int {
	match (opt_bytes(a), opt_bytes(b)) {
		(None, None) => 0,
		(None, Some(_)) => -1,
		(Some(_), None) => 1,
		(Some(a), Some(b)) => match vercmp(a, b) {
			Ordering::Less => -1,
			Ordering::Equal => 0,
			Ordering::Greater => 1,
		},
	}
}

// ---- alpm_list walkers --------------------------------------------------

/// alpm_list_next: the next node, NULL at the end
#[unsafe(no_mangle)]
pub extern "C" fn alpm_list_next(node: *const AlpmList) -> *mut AlpmList {
	match as_ref(node as *mut AlpmList) {
		Some(n) => n.next,
		None => std::ptr::null_mut(),
	}
}

/// alpm_list_count: number of nodes
#[unsafe(no_mangle)]
pub extern "C" fn alpm_list_count(list: *const AlpmList) -> usize {
	let mut n = 0;
	let mut cur = list;
	while let Some(node) = as_ref(cur as *mut AlpmList) {
		n += 1;
		cur = node.next;
	}
	n
}

/// alpm_list_add: append data as a new node, return the list head. the
/// head's prev points at the last node, as the C keeps it.
#[unsafe(no_mangle)]
pub extern "C" fn alpm_list_add(
	list: *mut AlpmList,
	data: *mut c_void,
) -> *mut AlpmList {
	let node = Box::into_raw(Box::new(AlpmList {
		data,
		prev: std::ptr::null_mut(),
		next: std::ptr::null_mut(),
	}));
	if list.is_null() {
		// SAFETY: node was just allocated; a single-element list's prev
		// points at itself (the last node), like the C
		unsafe { (*node).prev = node };
		return node;
	}
	// SAFETY: list is a valid head; walk to the last node via head->prev
	unsafe {
		let last = (*list).prev;
		(*last).next = node;
		(*node).prev = last;
		(*list).prev = node;
	}
	list
}

/// alpm_list_free_inner: run a free callback on each node's data. the
/// nodes stay; the caller frees them with alpm_list_free after.
#[unsafe(no_mangle)]
pub extern "C" fn alpm_list_free_inner(
	list: *mut AlpmList,
	fname: Option<unsafe extern "C" fn(*mut c_void)>,
) {
	let mut cur = list;
	while let Some(node) = as_ref(cur) {
		if let Some(f) = fname {
			// SAFETY: fname is the caller's deallocator for the data
			unsafe { f(node.data) };
		}
		cur = node.next;
	}
}

/// alpm_list_free: free a node chain built by alpm_list_add, not the data.
/// handle/db/pkg owned lists are freed with the handle, never here.
#[unsafe(no_mangle)]
pub extern "C" fn alpm_list_free(list: *mut AlpmList) {
	let mut cur = list;
	while !cur.is_null() {
		// SAFETY: a chain of nodes allocated by alpm_list_add
		// (Box::into_raw); each is freed once as we walk forward
		let node = unsafe { Box::from_raw(cur) };
		cur = node.next;
	}
}

// ---- helpers ------------------------------------------------------------

fn null_handle() -> *mut alpm_handle_t {
	std::ptr::null_mut()
}

fn set_err_out(err: *mut c_int, e: Errno) {
	if !err.is_null() {
		// SAFETY: non-NULL out pointer the caller provided for the code
		unsafe { *err = e as c_int };
	}
}

fn c_strdup(bytes: &[u8]) -> *mut c_char {
	// SAFETY: allocate len+1 with the C allocator so the caller's free(3)
	// matches; copy the bytes and a terminating nul
	unsafe {
		let p = malloc(bytes.len() + 1) as *mut u8;
		if p.is_null() {
			return std::ptr::null_mut();
		}
		std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
		*p.add(bytes.len()) = 0;
		p as *mut c_char
	}
}

fn as_ref<'a, T>(p: *mut T) -> Option<&'a T> {
	if p.is_null() {
		None
	} else {
		// SAFETY: a non-NULL pointer here is one we handed out (a boxed
		// wrapper or a node) still owned by a live handle; we take a
		// shared ref and mutate only through interior RefCells
		Some(unsafe { &*p })
	}
}

fn as_db_ref<'a>(p: *const alpm_db_t) -> Option<&'a alpm_db_t> {
	as_ref(p as *mut alpm_db_t)
}

fn as_pkg_ref<'a>(p: *mut alpm_pkg_t) -> Option<&'a alpm_pkg_t> {
	as_ref(p)
}
