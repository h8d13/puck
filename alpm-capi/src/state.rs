// the objects behind the opaque alpm_handle_t/alpm_db_t/alpm_pkg_t
// pointers. they give the consumers stable addresses (alpm.h promises a
// package or db pointer stays valid for the handle's life) and own the
// C-visible copies the getters hand out: nul-terminated strings and
// alpm_list_t chains, freed when the handle is released.
//
// interior mutability (RefCell) is the whole trick: a db pointer carries
// a raw *mut CapiHandle, so a db call reaches the handle as a shared
// &CapiHandle and mutates the port Handle and the caches through their
// own RefCells. no &mut is ever taken through a raw pointer, so the db
// and handle borrows never alias.

// the Box<T> inside the Vecs here is deliberate, not redundant: each box
// is a node or wrapper whose address is handed to C and must not move
// when the vec grows
#![allow(clippy::vec_box)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CString, c_char, c_void};
use std::ptr::{null, null_mut};

use alpm_core::{Depend, Errno, Handle, INFRQ_ALL, Package};

use crate::types::{AlpmDepend, AlpmList};

// field ids for the per-package string and list caches
pub const F_NAME: u8 = 1;
pub const F_VERSION: u8 = 2;
pub const F_DESC: u8 = 3;
pub const F_ARCH: u8 = 4;
pub const L_LICENSES: u8 = 1;
pub const L_GROUPS: u8 = 2;
pub const L_DEPENDS: u8 = 3;

// a nul-terminated copy; an interior nul (never in the port's byte
// fields) is cut like a C string would see it
pub fn to_cstring(bytes: &[u8]) -> CString {
	match CString::new(bytes) {
		Ok(c) => c,
		Err(e) => {
			let pos = e.nul_position();
			CString::new(&bytes[..pos]).expect("cut at nul")
		}
	}
}

/// an alpm_list_t chain plus the storage its `data` pointers reference,
/// kept alive together. heap-boxed nodes so a node address is stable
/// once built (consumers hold `->next` across calls).
#[derive(Default)]
pub struct OwnedList {
	// boxed per node: a node address is handed to C (prev/next and the
	// list head), so it must not move when the vec grows
	nodes: Vec<Box<AlpmList>>,
	_strings: Vec<CString>,
	_depends: Vec<Box<AlpmDepend>>,
}

impl OwnedList {
	pub fn head(&self) -> *mut AlpmList {
		self.nodes.first().map_or(null_mut(), |n| {
			&**n as *const AlpmList as *mut AlpmList
		})
	}

	// link data pointers into a doubly linked chain of boxed nodes
	fn link(data: Vec<*mut c_void>) -> Vec<Box<AlpmList>> {
		let mut nodes: Vec<Box<AlpmList>> = data
			.into_iter()
			.map(|d| {
				Box::new(AlpmList {
					data: d,
					prev: null_mut(),
					next: null_mut(),
				})
			})
			.collect();
		let ptrs: Vec<*mut AlpmList> = nodes
			.iter_mut()
			.map(|n| &mut **n as *mut AlpmList)
			.collect();
		for i in 0..nodes.len() {
			nodes[i].prev =
				if i > 0 { ptrs[i - 1] } else { null_mut() };
			nodes[i].next =
				ptrs.get(i + 1).copied().unwrap_or(null_mut());
		}
		nodes
	}

	pub fn strings<S: AsRef<[u8]>>(items: &[S]) -> OwnedList {
		let strings: Vec<CString> =
			items.iter().map(|s| to_cstring(s.as_ref())).collect();
		let data = strings
			.iter()
			.map(|c| c.as_ptr() as *mut c_void)
			.collect();
		OwnedList {
			nodes: Self::link(data),
			_strings: strings,
			_depends: Vec::new(),
		}
	}

	pub fn depends(deps: &[Depend]) -> OwnedList {
		let mut strings = Vec::new();
		let mut boxes: Vec<Box<AlpmDepend>> = Vec::new();
		for d in deps {
			let name = to_cstring(&d.name);
			let version = d.version.as_deref().map(to_cstring);
			let desc = d.desc.as_deref().map(to_cstring);
			let dep = Box::new(AlpmDepend {
				name: name.as_ptr() as *mut c_char,
				version: version
					.as_ref()
					.map_or(null_mut(), |c| {
						c.as_ptr() as *mut c_char
					}),
				desc: desc.as_ref().map_or(null_mut(), |c| {
					c.as_ptr() as *mut c_char
				}),
				name_hash: d.name_hash,
				mod_: d.depmod as i32,
			});
			strings.push(name);
			if let Some(v) = version {
				strings.push(v);
			}
			if let Some(d) = desc {
				strings.push(d);
			}
			boxes.push(dep);
		}
		let data = boxes
			.iter()
			.map(|b| &**b as *const AlpmDepend as *mut c_void)
			.collect();
		OwnedList {
			nodes: Self::link(data),
			_strings: strings,
			_depends: boxes,
		}
	}

	// a chain of already-owned data pointers (db/pkg wrappers)
	pub fn ptrs(data: Vec<*mut c_void>) -> OwnedList {
		OwnedList {
			nodes: Self::link(data),
			..OwnedList::default()
		}
	}
}

/// which db of the handle a CapiDb stands for
#[derive(Clone, Copy)]
pub enum DbRef {
	Local,
	Sync(usize),
}

/// the object behind an alpm_pkg_t: a stable pointer to a Package in the
/// handle's db cache, plus the nul-terminated field copies the getters
/// return (pkg-owned, borrowed by the caller)
pub struct CapiPkg {
	pkg: *const Package,
	strings: RefCell<HashMap<u8, Option<CString>>>,
	lists: RefCell<HashMap<u8, OwnedList>>,
}

impl CapiPkg {
	fn pkg(&self) -> &Package {
		// SAFETY: the Package lives in the handle's db cache slab; its
		// address is captured only after the cache is fully loaded, so
		// on the read path nothing grows the slab and the address stays
		// valid for the handle's life.
		unsafe { &*self.pkg }
	}

	pub fn cstr(&self, id: u8) -> *const c_char {
		let mut m = self.strings.borrow_mut();
		let slot = m.entry(id).or_insert_with(|| {
			let p = self.pkg();
			let bytes = match id {
				F_NAME => p.name.as_deref(),
				F_VERSION => p.version.as_deref(),
				F_DESC => p.desc.as_deref(),
				F_ARCH => p.arch.as_deref(),
				_ => None,
			};
			bytes.map(to_cstring)
		});
		// the CString's buffer is on the heap, so the pointer stays valid
		// after this borrow ends and across map growth
		slot.as_ref().map_or(null(), |c| c.as_ptr())
	}

	pub fn list(&self, id: u8) -> *mut AlpmList {
		let mut m = self.lists.borrow_mut();
		let ol = m.entry(id).or_insert_with(|| {
			let p = self.pkg();
			match id {
				L_LICENSES => OwnedList::strings(&p.licenses),
				L_GROUPS => OwnedList::strings(&p.groups),
				L_DEPENDS => OwnedList::depends(&p.depends),
				_ => OwnedList::default(),
			}
		});
		ol.head()
	}

	pub fn reason(&self) -> i32 {
		self.pkg().reason as i32
	}

	pub fn builddate(&self) -> i64 {
		self.pkg().builddate
	}

	pub fn isize(&self) -> i64 {
		self.pkg().isize
	}
}

/// the object behind an alpm_db_t
pub struct CapiDb {
	pub handle: *mut CapiHandle,
	pub which: DbRef,
	pkgs: RefCell<HashMap<usize, Box<CapiPkg>>>,
	pkgcache: RefCell<Option<OwnedList>>,
}

impl CapiDb {
	fn new(handle: *mut CapiHandle, which: DbRef) -> Box<CapiDb> {
		Box::new(CapiDb {
			handle,
			which,
			pkgs: RefCell::new(HashMap::new()),
			pkgcache: RefCell::new(None),
		})
	}

	fn handle(&self) -> &CapiHandle {
		// SAFETY: set at registration to the owning CapiHandle, which
		// outlives every db it owns (dropped only by alpm_release).
		unsafe { &*self.handle }
	}

	// intern a Package address as a stable CapiPkg wrapper
	pub fn wrap_pkg(&self, p: *const Package) -> *mut CapiPkg {
		let mut m = self.pkgs.borrow_mut();
		let w = m.entry(p as usize).or_insert_with(|| {
			Box::new(CapiPkg {
				pkg: p,
				strings: RefCell::new(HashMap::new()),
				lists: RefCell::new(HashMap::new()),
			})
		});
		&mut **w as *mut CapiPkg
	}

	/// alpm_db_get_pkgcache: load then expose a handle-stable list of
	/// alpm_pkg_t. the list is owned by the db (not freed by the caller),
	/// cached so repeated calls return the same nodes.
	pub fn pkgcache(&self) -> *mut AlpmList {
		if self.pkgcache.borrow().is_none() {
			let addrs = self.load_addrs();
			let data = addrs
				.iter()
				.map(|&p| self.wrap_pkg(p) as *mut c_void)
				.collect();
			*self.pkgcache.borrow_mut() =
				Some(OwnedList::ptrs(data));
		}
		self.pkgcache
			.borrow()
			.as_ref()
			.map_or(null_mut(), OwnedList::head)
	}

	// Package addresses of the loaded cache, in name order
	fn load_addrs(&self) -> Vec<*const Package> {
		let h = self.handle();
		let mut inner = h.inner.borrow_mut();
		let dbs = inner.dbs_mut();
		let (dbext, cb) = (dbs.dbext, dbs.cb);
		let db = match self.which {
			DbRef::Local => dbs.local,
			DbRef::Sync(i) => dbs.sync.get_mut(i),
		};
		match db {
			// load every section so the getters find their fields, as
			// the real libalpm does lazily per getter (INFRQ_*)
			Some(db) => match db.load_all(dbext, cb, INFRQ_ALL) {
				Ok(cache) => cache
					.iter()
					.map(|p| p as *const Package)
					.collect(),
				Err(e) => {
					drop(inner);
					h.set_err(e);
					Vec::new()
				}
			},
			None => Vec::new(),
		}
	}

	/// alpm_db_get_pkg: one package by name, cache-backed. NULL (with
	/// pm_errno set) when missing.
	pub fn get_pkg(&self, name: &[u8]) -> *mut CapiPkg {
		let h = self.handle();
		let addr = {
			let mut inner = h.inner.borrow_mut();
			let dbs = inner.dbs_mut();
			let (dbext, cb) = (dbs.dbext, dbs.cb);
			let db = match self.which {
				DbRef::Local => dbs.local,
				DbRef::Sync(i) => dbs.sync.get_mut(i),
			};
			match db {
				Some(db) => db
					.load_pkg(dbext, cb, name, INFRQ_ALL)
					.map(|p| p as *const Package),
				None => Err(Errno::DbNull),
			}
		};
		match addr {
			Ok(p) => self.wrap_pkg(p),
			Err(e) => {
				h.set_err(e);
				null_mut()
			}
		}
	}

	pub fn name(&self) -> *const c_char {
		self.handle().db_name(self.which)
	}
}

/// the object behind an alpm_handle_t
pub struct CapiHandle {
	pub inner: RefCell<Handle>,
	pub last_err: RefCell<Errno>,
	local: RefCell<Option<Box<CapiDb>>>,
	// boxed: a CapiDb address is the alpm_db_t handed to C, stable for
	// the handle's life even as more sync dbs are registered
	sync: RefCell<Vec<Box<CapiDb>>>,
	sync_list: RefCell<Option<OwnedList>>,
	arch_list: RefCell<Option<OwnedList>>,
	root: RefCell<Option<CString>>,
	dbpath: RefCell<Option<CString>>,
	db_names: RefCell<HashMap<usize, CString>>,
}

impl CapiHandle {
	pub fn new(inner: Handle) -> Box<CapiHandle> {
		Box::new(CapiHandle {
			inner: RefCell::new(inner),
			last_err: RefCell::new(Errno::Ok),
			local: RefCell::new(None),
			sync: RefCell::new(Vec::new()),
			sync_list: RefCell::new(None),
			arch_list: RefCell::new(None),
			root: RefCell::new(None),
			dbpath: RefCell::new(None),
			db_names: RefCell::new(HashMap::new()),
		})
	}

	pub fn set_err(&self, e: Errno) {
		*self.last_err.borrow_mut() = e;
	}

	fn this(&self) -> *mut CapiHandle {
		self as *const CapiHandle as *mut CapiHandle
	}

	/// alpm_get_localdb: a wrapper made once, address stable
	pub fn localdb(&self) -> *mut CapiDb {
		let mut slot = self.local.borrow_mut();
		let db = slot.get_or_insert_with(|| {
			CapiDb::new(self.this(), DbRef::Local)
		});
		&mut **db as *mut CapiDb
	}

	/// alpm_register_syncdb: register in the port Handle, then a stable
	/// wrapper over the new db. NULL (pm_errno set) on failure.
	pub fn register_syncdb(
		&self,
		name: &[u8],
		siglevel: i32,
	) -> *mut CapiDb {
		let idx = {
			let mut inner = self.inner.borrow_mut();
			match inner.register_syncdb(name, siglevel) {
				Ok(_) => inner.syncdbs().len() - 1,
				Err(e) => {
					drop(inner);
					self.set_err(e);
					return null_mut();
				}
			}
		};
		let mut sync = self.sync.borrow_mut();
		sync.push(CapiDb::new(self.this(), DbRef::Sync(idx)));
		&mut **sync.last_mut().expect("just pushed") as *mut CapiDb
	}

	/// alpm_get_syncdbs: a list of the sync db wrappers, owned by the
	/// handle. rebuilt if a db was registered since the last call.
	pub fn syncdbs(&self) -> *mut AlpmList {
		let want = self.inner.borrow().syncdbs().len();
		let have = self.sync.borrow().len();
		// ensure a wrapper exists for every registered db; a new one
		// invalidates the cached list
		if have < want {
			for i in have..want {
				self.sync.borrow_mut().push(CapiDb::new(
					self.this(),
					DbRef::Sync(i),
				));
			}
			*self.sync_list.borrow_mut() = None;
		}
		if self.sync_list.borrow().is_none() {
			let data = self
				.sync
				.borrow_mut()
				.iter_mut()
				.map(|d| &mut **d as *mut CapiDb as *mut c_void)
				.collect();
			*self.sync_list.borrow_mut() =
				Some(OwnedList::ptrs(data));
		}
		self.sync_list
			.borrow()
			.as_ref()
			.map_or(null_mut(), OwnedList::head)
	}

	/// alpm_option_get_architectures
	pub fn architectures(&self) -> *mut AlpmList {
		if self.arch_list.borrow().is_none() {
			let inner = self.inner.borrow();
			let list = OwnedList::strings(inner.architectures());
			drop(inner);
			*self.arch_list.borrow_mut() = Some(list);
		}
		self.arch_list
			.borrow()
			.as_ref()
			.map_or(null_mut(), OwnedList::head)
	}

	pub fn root(&self) -> *const c_char {
		let mut slot = self.root.borrow_mut();
		let c = slot.get_or_insert_with(|| {
			to_cstring(self.inner.borrow().root())
		});
		c.as_ptr()
	}

	pub fn dbpath(&self) -> *const c_char {
		let mut slot = self.dbpath.borrow_mut();
		let c = slot.get_or_insert_with(|| {
			to_cstring(self.inner.borrow().dbpath())
		});
		c.as_ptr()
	}

	// alpm_db_get_name, cached per db (the name is handle-owned)
	fn db_name(&self, which: DbRef) -> *const c_char {
		let key = match which {
			DbRef::Local => usize::MAX,
			DbRef::Sync(i) => i,
		};
		let mut m = self.db_names.borrow_mut();
		let c = m.entry(key).or_insert_with(|| {
			let inner = self.inner.borrow();
			let name = match which {
				DbRef::Local => inner
					.localdb()
					.map_or(&b"local"[..], |d| d.name()),
				DbRef::Sync(i) => inner.syncdbs()[i].name(),
			};
			to_cstring(name)
		});
		c.as_ptr()
	}
}
