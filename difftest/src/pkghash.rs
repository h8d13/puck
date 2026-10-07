// C side of lib/libalpm/pkghash.c, internal symbols from the static archive
//
// a CPkgHash owns a pool of C packages, the hash only points at them like
// a db cache does. packages are named by their index in the pool.
use std::collections::HashMap;
use std::ffi::{c_char, c_uint};
use std::ptr;

use alpm_core::package::Package;

use crate::CList;
use crate::cstr;
use crate::package::{CPkg, CPkgBox, list_data};

// alpm_pkghash_t, pkghash.h
#[repr(C)]
struct CHash {
	hash_table: *mut *mut CList,
	list: *mut CList,
	buckets: c_uint,
	entries: c_uint,
	limit: c_uint,
}

unsafe extern "C" {
	fn _alpm_pkghash_create(size: c_uint) -> *mut CHash;
	fn _alpm_pkghash_add(
		hash: *mut *mut CHash,
		pkg: *mut CPkg,
	) -> *mut CHash;
	fn _alpm_pkghash_add_sorted(
		hash: *mut *mut CHash,
		pkg: *mut CPkg,
	) -> *mut CHash;
	fn _alpm_pkghash_remove(
		hash: *mut CHash,
		pkg: *mut CPkg,
		data: *mut *mut CPkg,
	) -> *mut CHash;
	fn _alpm_pkghash_free(hash: *mut CHash);
	fn _alpm_pkghash_find(
		hash: *mut CHash,
		name: *const c_char,
	) -> *mut CPkg;
}

pub struct CPkgHash {
	hash: *mut CHash,
	pool: Vec<CPkgBox>,
	ids: HashMap<*const CPkg, usize>,
}

impl Drop for CPkgHash {
	fn drop(&mut self) {
		// SAFETY: hash came from _alpm_pkghash_create, frees the nodes
		// only, the pool frees the packages after
		unsafe { _alpm_pkghash_free(self.hash) }
	}
}

impl CPkgHash {
	// None when the C refuses the size. C precondition: size / 0.58
	// fits an unsigned int, past that the double conversion is UB
	pub fn new(size: u32, pool: &[Package]) -> Option<Self> {
		assert!(f64::from(size) / 0.58 + 1.0 < f64::from(u32::MAX));
		// SAFETY: plain allocation, NULL or a valid empty hash
		let hash = unsafe { _alpm_pkghash_create(size) };
		if hash.is_null() {
			return None;
		}
		let pool: Vec<CPkgBox> =
			pool.iter().map(CPkgBox::new).collect();
		let ids = pool
			.iter()
			.enumerate()
			.map(|(i, b)| (b.0.cast_const(), i));
		let ids = ids.collect();
		Some(CPkgHash { hash, pool, ids })
	}

	fn id(&self, p: *const CPkg) -> usize {
		self.ids[&p]
	}

	// false where the C returns NULL (table cannot grow)
	pub fn add(&mut self, id: usize, sorted: bool) -> bool {
		let f = match sorted {
			false => _alpm_pkghash_add,
			true => _alpm_pkghash_add_sorted,
		};
		// SAFETY: self.hash is live, the pool package outlives the
		// hash; on success *hash may be replaced by a rehashed table
		unsafe { !f(&mut self.hash, self.pool[id].0).is_null() }
	}

	// pool index of the removed entry. key is a separate package, only
	// its name and name_hash are read
	pub fn remove(&mut self, key: &Package) -> Option<usize> {
		let key = CPkgBox::new(key);
		let mut out = ptr::null_mut();
		// SAFETY: hash and key live, out receives a pool pointer or NULL
		let h = unsafe {
			_alpm_pkghash_remove(self.hash, key.0, &mut out)
		};
		assert_eq!(h, self.hash);
		(!out.is_null()).then(|| self.id(out))
	}

	pub fn find(&self, name: &[u8]) -> Option<usize> {
		let name = cstr(name);
		// SAFETY: hash live, name a valid C string
		let r = unsafe { _alpm_pkghash_find(self.hash, name.as_ptr()) };
		(!r.is_null()).then(|| self.id(r))
	}

	// pool indices in hash->list order
	pub fn list(&self) -> Vec<usize> {
		// SAFETY: self.hash is live
		let head = unsafe { (*self.hash).list };
		list_data(head)
			.into_iter()
			.map(|p| self.id(p.cast()))
			.collect()
	}

	// entries, buckets, limit
	pub fn counts(&self) -> (usize, usize, usize) {
		// SAFETY: self.hash is live
		let h = unsafe { &*self.hash };
		(h.entries as usize, h.buckets as usize, h.limit as usize)
	}
}
