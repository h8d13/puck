// C side of lib/libalpm/deps.c, dependency strings and provides matching
use std::ffi::{CStr, CString, c_char, c_int, c_ulong};
use std::ptr;

use crate::{CList, cstr, opt_ptr, take};

use alpm_core::deps::{DepMod, Depend};

// alpm_depend_t, alpm.h
#[repr(C)]
struct CDepend {
	name: *mut c_char,
	version: *mut c_char,
	desc: *mut c_char,
	name_hash: c_ulong,
	depmod: c_int,
}

// alpm_list_t, alpm_list.h
unsafe extern "C" {
	fn alpm_dep_from_string(s: *const c_char) -> *mut CDepend;
	fn alpm_dep_compute_string(dep: *const CDepend) -> *mut c_char;
	fn alpm_dep_free(dep: *mut CDepend);
	fn _alpm_depcmp_provides(
		dep: *mut CDepend,
		provisions: *mut CList,
	) -> c_int;
}

fn depmod_from_c(m: c_int) -> DepMod {
	match m {
		1 => DepMod::Any,
		2 => DepMod::Eq,
		3 => DepMod::Ge,
		4 => DepMod::Le,
		5 => DepMod::Gt,
		6 => DepMod::Lt,
		_ => panic!("C returned unknown alpm_depmod_t {m}"),
	}
}

// copies a C string field out, NULL is None
fn field(p: *const c_char) -> Option<Vec<u8>> {
	// SAFETY: p is NULL or a nul-terminated string owned by the struct
	(!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

// None where the C returns NULL (NULL input or allocation failure)
fn c_dep_from_ptr(s: *const c_char) -> Option<Depend> {
	// SAFETY: s is NULL or a valid C string, result is NULL or a struct
	// calloc'd by libalpm
	let d = unsafe { alpm_dep_from_string(s) };
	if d.is_null() {
		return None;
	}
	// SAFETY: d is non-NULL and fully initialized by alpm_dep_from_string
	let c = unsafe { &*d };
	let dep = Depend {
		name: field(c.name).expect("C name is NULL"),
		version: field(c.version),
		desc: field(c.desc),
		name_hash: c.name_hash,
		depmod: depmod_from_c(c.depmod),
	};
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
