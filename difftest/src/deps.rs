// C side of lib/libalpm/deps.c, dependency strings, provides matching
// and satisfiers in package lists
use std::ffi::{CString, c_char, c_int, c_ulong};
use std::ptr;

use crate::package::{CDepend, CPkg, CPkgBox, read_dep};
use crate::{CList, alpm_list_add, alpm_list_free, cstr, opt_ptr, take};

use alpm_core::deps::Depend;
use alpm_core::package::Package;

// alpm_list_t, alpm_list.h
unsafe extern "C" {
	fn alpm_dep_from_string(s: *const c_char) -> *mut CDepend;
	fn alpm_dep_compute_string(dep: *const CDepend) -> *mut c_char;
	fn alpm_dep_free(dep: *mut CDepend);
	fn _alpm_depcmp_provides(
		dep: *mut CDepend,
		provisions: *mut CList,
	) -> c_int;
	fn _alpm_depcmp_literal(pkg: *mut CPkg, dep: *mut CDepend) -> c_int;
	fn _alpm_depcmp(pkg: *mut CPkg, dep: *mut CDepend) -> c_int;
	pub(crate) fn alpm_find_satisfier(
		pkgs: *mut CList,
		depstring: *const c_char,
	) -> *mut CPkg;
}

// None where the C returns NULL (NULL input or allocation failure)
fn c_dep_from_ptr(s: *const c_char) -> Option<Depend> {
	// SAFETY: s is NULL or a valid C string, result is NULL or a struct
	// calloc'd by libalpm
	let d = unsafe { alpm_dep_from_string(s) };
	if d.is_null() {
		return None;
	}
	// d is non-NULL and fully initialized by alpm_dep_from_string
	let dep = read_dep(d);
	// SAFETY: d came from alpm_dep_from_string, not used afterwards
	unsafe { alpm_dep_free(d) };
	Some(dep)
}

pub fn c_dep_from_string(s: &[u8]) -> Depend {
	let s = cstr(s);
	c_dep_from_ptr(s.as_ptr()).unwrap()
}

pub fn c_dep_from_string_null() -> Option<Depend> {
	c_dep_from_ptr(ptr::null())
}

// owned C strings backing one CDepend, keep alive while the mirror is used
struct Owned {
	name: Option<CString>,
	version: Option<CString>,
	desc: Option<CString>,
}

impl Owned {
	fn new(dep: &Depend) -> Self {
		Owned {
			name: Some(cstr(&dep.name)),
			version: dep.version.as_deref().map(cstr),
			desc: dep.desc.as_deref().map(cstr),
		}
	}

	// the C only reads through these pointers
	fn mirror(&self, name_hash: c_ulong, depmod: c_int) -> CDepend {
		CDepend {
			name: opt_ptr(&self.name).cast_mut(),
			version: opt_ptr(&self.version).cast_mut(),
			desc: opt_ptr(&self.desc).cast_mut(),
			name_hash,
			depmod,
		}
	}
}

// raw fields, so NULL name and out of range mods can be pinned
pub fn c_dep_compute_string_raw(
	name: Option<&[u8]>,
	version: Option<&[u8]>,
	desc: Option<&[u8]>,
	depmod: c_int,
) -> Vec<u8> {
	let o = Owned {
		name: name.map(cstr),
		version: version.map(cstr),
		desc: desc.map(cstr),
	};
	let c = o.mirror(0, depmod);
	// SAFETY: c points at strings owned by o, alive for the call, the C
	// only reads them and returns a malloc'd string or NULL
	take(unsafe { alpm_dep_compute_string(&c) }).unwrap()
}

pub fn c_dep_compute_string(dep: &Depend) -> Vec<u8> {
	c_dep_compute_string_raw(
		Some(&dep.name),
		dep.version.as_deref(),
		dep.desc.as_deref(),
		dep.depmod as c_int,
	)
}

pub fn c_dep_compute_string_null() -> Option<Vec<u8>> {
	// SAFETY: NULL is checked first by the C
	take(unsafe { alpm_dep_compute_string(ptr::null()) })
}

// provisions become a Rust-owned alpm_list_t, the C only walks ->next
pub fn c_depcmp_provides(dep: &Depend, provisions: &[Depend]) -> bool {
	let owned: Vec<Owned> = provisions.iter().map(Owned::new).collect();
	let mut mirrors: Vec<CDepend> = owned
		.iter()
		.zip(provisions)
		.map(|(o, p)| o.mirror(p.name_hash, p.depmod as c_int))
		.collect();
	let mut nodes: Vec<CList> = mirrors
		.iter_mut()
		.map(|m| CList {
			data: ptr::from_mut(m).cast(),
			prev: ptr::null_mut(),
			next: ptr::null_mut(),
		})
		.collect();
	// link after collecting, nodes no longer move
	let base = nodes.as_mut_ptr();
	let n = nodes.len();
	for i in 0..n {
		let next = if i + 1 < n {
			base.wrapping_add(i + 1)
		} else {
			ptr::null_mut()
		};
		// SAFETY: i < n nodes behind base, no reference into nodes is
		// live; head->prev is the tail in alpm_list
		unsafe {
			let node = base.add(i);
			(*node).prev = base.add((i + n - 1) % n);
			(*node).next = next;
		}
	}
	let head = if n == 0 { ptr::null_mut() } else { base };

	let d = Owned::new(dep);
	let mut c = d.mirror(dep.name_hash, dep.depmod as c_int);
	// SAFETY: c and every node/mirror point into d, owned, mirrors and
	// nodes, all alive and unmoved for the call; the C only reads them
	unsafe { _alpm_depcmp_provides(&mut c, head) != 0 }
}

// C precondition of both: a NULL package name is only read when the
// stored hashes match (strcmp)
fn with_pkg_dep(
	pkg: &Package,
	dep: &Depend,
	f: unsafe extern "C" fn(*mut CPkg, *mut CDepend) -> c_int,
) -> bool {
	assert!(
		pkg.name.is_some() || pkg.name_hash != dep.name_hash,
		"strcmp on a NULL name"
	);
	let b = CPkgBox::new(pkg);
	let d = Owned::new(dep);
	let mut c = d.mirror(dep.name_hash, dep.depmod as c_int);
	// SAFETY: b.0 is a live package, c points into d, both alive for
	// the call; the C only reads them
	unsafe { f(b.0, &mut c) != 0 }
}

pub fn c_depcmp_literal(pkg: &Package, dep: &Depend) -> bool {
	with_pkg_dep(pkg, dep, _alpm_depcmp_literal)
}

pub fn c_depcmp(pkg: &Package, dep: &Depend) -> bool {
	with_pkg_dep(pkg, dep, _alpm_depcmp)
}

// position of the package alpm_find_satisfier returns. C precondition:
// names set (strcmp after a hash match)
pub fn c_find_satisfier(pkgs: &[Package], depstring: &[u8]) -> Option<usize> {
	assert!(pkgs.iter().all(|p| p.name.is_some()), "NULL name");
	let boxes: Vec<CPkgBox> = pkgs.iter().map(CPkgBox::new).collect();
	let mut list = ptr::null_mut();
	for b in &boxes {
		// SAFETY: list is NULL or built by alpm_list_add, the packages
		// stay owned by boxes
		list = unsafe { alpm_list_add(list, b.0.cast()) };
	}
	let s = cstr(depstring);
	// SAFETY: list holds live packages for the call, s a valid C string
	let found = unsafe { alpm_find_satisfier(list, s.as_ptr()) };
	// SAFETY: nodes malloc'd by alpm_list_add, data owned by boxes
	unsafe { alpm_list_free(list) };
	boxes.iter().position(|b| b.0 == found)
}
