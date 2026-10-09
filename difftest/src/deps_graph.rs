// C side of the deps.c resolver and graph.c: alpm_checkdeps,
// _alpm_sortbydeps, alpm_find_dbs_satisfier, _alpm_resolvedeps and
// _alpm_recursedeps on a real C handle over a fixture written by the
// caller. log and question callbacks registered on the handle record
// every call; questions are answered from a scripted list (once it runs
// out the C default stays, like no callback). packages are named by
// PkgId, names are unique within a db.
//
// the callbacks and the id mapping read package structs directly: the
// alpm_pkg_get_* getters reset pm_errno.
use std::collections::VecDeque;
use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use alpm_core::internals::deps::{DepMissing, Depend};
use alpm_core::internals::trans::{TRANS_FLAG_NODEPVERSION, TRANS_FLAG_NOLOCK};

use crate::handle::log_message;
use crate::handle::{
	_alpm_db_get_pkgcache_hash, ALPM, CDb, alpm_db_set_usage, alpm_errno,
	alpm_get_localdb, alpm_initialize, alpm_option_set_assumeinstalled,
	alpm_option_set_ignoregroups, alpm_option_set_ignorepkgs,
	alpm_option_set_logcb, alpm_option_set_questioncb,
	alpm_register_syncdb, alpm_release, alpm_trans_init,
	alpm_trans_release,
};
use crate::package::{
	_alpm_pkg_free, CDepend, CPkg, alpm_pkg_get_depends,
	alpm_pkg_get_files, alpm_pkg_has_scriptlet, field, list_data, read_dep,
	read_pkg, with_strs,
};
use crate::{CList, alpm_list_add, alpm_list_free, cstr, opt_ptr};

// alpm_question_type_t
const QUESTION_INSTALL_IGNOREPKG: c_int = 1;
const QUESTION_SELECT_PROVIDER: c_int = 1 << 5;
// alpm_loglevel_t: only the db backends log at this level
pub const LOG_FUNCTION: c_int = 1 << 3;

// a package by db (None: local) and name
pub type PkgId = (Option<usize>, Vec<u8>);

// one question as the callback saw it
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Asked {
	InstallIgnorepkg(PkgId),
	SelectProvider(Vec<PkgId>, Depend),
}

// what the callbacks saw during one call: questions in order, log lines
// (level, formatted message)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Calls {
	pub asked: Vec<Asked>,
	pub logs: Vec<(c_int, Vec<u8>)>,
}

// handle state of one fixture
#[derive(Clone, Debug, Default)]
pub struct Setup {
	pub ignorepkg: Vec<Vec<u8>>,
	pub ignoregroup: Vec<Vec<u8>>,
	// mod Any or Eq, alpm_option_add_assumeinstalled refuses the others
	pub assumeinstalled: Vec<Depend>,
	pub nodepversion: bool,
	pub local_usage: c_int,
	// one per sync db
	pub usage: Vec<c_int>,
}

// alpm_depmissing_t
#[repr(C)]
struct CDepMissing {
	target: *mut c_char,
	depend: *mut CDepend,
	causingpkg: *mut c_char,
}

// alpm_question_install_ignorepkg_t
#[repr(C)]
struct CQIgnore {
	kind: c_int,
	install: c_int,
	pkg: *mut CPkg,
}

// alpm_question_select_provider_t
#[repr(C)]
struct CQProvider {
	kind: c_int,
	use_index: c_int,
	providers: *mut CList,
	depend: *mut CDepend,
}

unsafe extern "C" {
	fn alpm_checkdeps(
		handle: *mut c_void,
		pkglist: *mut CList,
		rem: *mut CList,
		upgrade: *mut CList,
		reversedeps: c_int,
	) -> *mut CList;
	fn alpm_find_dbs_satisfier(
		handle: *mut c_void,
		dbs: *mut CList,
		depstring: *const c_char,
	) -> *mut CPkg;
	fn _alpm_sortbydeps(
		handle: *mut c_void,
		targets: *mut CList,
		ignore: *mut CList,
		reverse: c_int,
	) -> *mut CList;
	fn _alpm_resolvedeps(
		handle: *mut c_void,
		localpkgs: *mut CList,
		pkg: *mut CPkg,
		preferred: *mut CList,
		packages: *mut *mut CList,
		rem: *mut CList,
		data: *mut *mut CList,
	) -> c_int;
	fn _alpm_recursedeps(
		db: *mut CDb,
		targs: *mut *mut CList,
		include_explicit: c_int,
	) -> c_int;
	fn alpm_depmissing_free(miss: *mut CDepMissing);
	// va_list is passed as a pointer on x86_64 (array type) and
	// aarch64 (indirect composite)
}

// copies a depmissing list out, frees entries and nodes
pub(crate) fn take_misses(list: *mut CList) -> Vec<DepMissing> {
	let out = list_data(list)
		.into_iter()
		.map(|p| {
			let m = p.cast::<CDepMissing>();
			// SAFETY: m is a live alpm_depmissing_t of the list
			let c = unsafe { &*m };
			let miss = DepMissing {
				target: field(c.target).expect("NULL target"),
				depend: read_dep(c.depend),
				causingpkg: field(c.causingpkg),
			};
			// SAFETY: allocated by depmiss_new, not used afterwards
			unsafe { alpm_depmissing_free(m) };
			miss
		})
		.collect();
	// SAFETY: nodes from alpm_list_add, entries freed above
	unsafe { alpm_list_free(list) };
	out
}

// callback context: the handle's dbs (to name packages), the answers
// left, what was seen
struct Recorder {
	local: *mut CDb,
	sync: Vec<*mut CDb>,
	answers: VecDeque<c_int>,
	calls: Calls,
}

impl Recorder {
	fn id(&self, p: *mut CPkg) -> PkgId {
		// SAFETY: p is a live cached package; origin_data is its db
		let db = unsafe { (*p).origin_data }.cast::<CDb>();
		let db = match db == self.local {
			true => None,
			false => Some(self
				.sync
				.iter()
				.position(|&d| d == db)
				.expect("package of an unknown db")),
		};
		let name =
			read_pkg(p).name.expect("cached package without name");
		(db, name.into_vec())
	}
}

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	// SAFETY: fmt and args are the pair this callback got
	let msg = unsafe { log_message(fmt, args) };
	// SAFETY: ctx is the Recorder registered with the callback, no
	// other reference to it is live while the C runs
	let rec = unsafe { &mut *ctx.cast::<Recorder>() };
	rec.calls.logs.push((level, msg));
}

unsafe extern "C" fn question_cb(ctx: *mut c_void, q: *mut c_void) {
	// SAFETY: as in log_cb
	let rec = unsafe { &mut *ctx.cast::<Recorder>() };
	// SAFETY: every alpm_question_t starts with its type
	let kind = unsafe { *q.cast::<c_int>() };
	let answer = rec.answers.pop_front();
	match kind {
		QUESTION_INSTALL_IGNOREPKG => {
			// SAFETY: the type says which union member q is
			let q = unsafe { &mut *q.cast::<CQIgnore>() };
			let asked = Asked::InstallIgnorepkg(rec.id(q.pkg));
			rec.calls.asked.push(asked);
			if let Some(a) = answer {
				q.install = a;
			}
		}
		QUESTION_SELECT_PROVIDER => {
			// SAFETY: as above
			let q = unsafe { &mut *q.cast::<CQProvider>() };
			let providers = list_data(q.providers)
				.into_iter()
				.map(|p| rec.id(p.cast()))
				.collect();
			let asked = Asked::SelectProvider(
				providers,
				read_dep(q.depend),
			);
			rec.calls.asked.push(asked);
			if let Some(a) = answer {
				q.use_index = a;
			}
		}
		_ => panic!("unexpected question {kind}"),
	}
}

pub struct CGraph {
	h: *mut c_void,
	rec: *mut Recorder,
}

// a Rust-built alpm_list_t of borrowed pointers
struct PtrList(*mut CList);

impl PtrList {
	fn new<T>(items: impl IntoIterator<Item = *mut T>) -> Self {
		let mut list = ptr::null_mut();
		for p in items {
			// SAFETY: list is NULL or built by alpm_list_add
			list = unsafe { alpm_list_add(list, p.cast()) };
		}
		PtrList(list)
	}
}

impl Drop for PtrList {
	fn drop(&mut self) {
		// SAFETY: nodes from alpm_list_add, data not owned
		unsafe { alpm_list_free(self.0) };
	}
}

impl CGraph {
	// root and dbpath must exist; sync dbs registered in this order with
	// siglevel 0 and must load. caches are loaded before the callbacks
	// go in, a NOLOCK transaction carries the NODEPVERSION flag
	pub fn new(
		root: &[u8],
		dbpath: &[u8],
		syncdbs: &[&str],
		setup: &Setup,
	) -> Self {
		assert_eq!(syncdbs.len(), setup.usage.len());
		let (root, dbpath) = (cstr(root), cstr(dbpath));
		let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let mut err = 0;
		// SAFETY: valid C strings, err is writable
		let h = unsafe {
			alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			)
		};
		assert!(!h.is_null(), "alpm_initialize: {err}");
		drop(guard);
		let sync: Vec<*mut CDb> = syncdbs
			.iter()
			.map(|n| {
				let n = cstr(n.as_bytes());
				// SAFETY: h is live, n a valid name
				let db = unsafe {
					alpm_register_syncdb(h, n.as_ptr(), 0)
				};
				assert!(!db.is_null());
				db
			})
			.collect();
		// SAFETY: h is live
		let local = unsafe { alpm_get_localdb(h) };
		let usage = std::iter::once((local, setup.local_usage))
			.chain(sync.iter().copied().zip(setup.usage.clone()));
		for (db, u) in usage {
			// SAFETY: db belongs to h
			assert_eq!(unsafe { alpm_db_set_usage(db, u) }, 0);
			// SAFETY: as above; loads the cache now, its log lines
			// go nowhere yet
			let hash = unsafe { _alpm_db_get_pkgcache_hash(db) };
			assert!(!hash.is_null(), "db cache failed to load");
		}
		// every local entry loaded whole (or marked failed after its
		// desc, the port's section order) before the callbacks, like
		// the Rust side: the dups of _alpm_recursedeps then see the
		// same entry state on both sides
		// SAFETY: hash is the live local cache table, its packages
		// belong to h; the getters only load
		unsafe {
			let hash = _alpm_db_get_pkgcache_hash(local);
			for p in list_data((*hash).list) {
				alpm_pkg_get_depends(p.cast());
				alpm_pkg_get_files(p.cast());
				alpm_pkg_has_scriptlet(p.cast());
			}
		}
		let assume = Self::assume(&setup.assumeinstalled);
		let mut flags = TRANS_FLAG_NOLOCK;
		if setup.nodepversion {
			flags |= TRANS_FLAG_NODEPVERSION;
		}
		// SAFETY: h is live, the set calls dup lists and strings
		unsafe {
			with_strs(&setup.ignorepkg, |l| {
				alpm_option_set_ignorepkgs(h, l)
			});
			with_strs(&setup.ignoregroup, |l| {
				alpm_option_set_ignoregroups(h, l)
			});
			let list = PtrList::new(
				assume.1.iter()
					.map(|d| ptr::from_ref(d).cast_mut()),
			);
			assert_eq!(
				alpm_option_set_assumeinstalled(h, list.0),
				0
			);
			assert_eq!(alpm_trans_init(h, flags), 0);
		}
		let rec = Box::into_raw(Box::new(Recorder {
			local,
			sync,
			answers: VecDeque::new(),
			calls: Calls::default(),
		}));
		// SAFETY: h is live, rec stays valid until drop
		unsafe {
			alpm_option_set_logcb(h, Some(log_cb), rec.cast());
			alpm_option_set_questioncb(
				h,
				Some(question_cb),
				rec.cast(),
			);
		}
		CGraph { h, rec }
	}

	// CDepend mirrors over owned strings, the C only reads them. the
	// strings must outlive the mirrors: both come back as one tuple
	#[allow(clippy::type_complexity)]
	fn assume(
		deps: &[Depend],
	) -> (Vec<[Option<std::ffi::CString>; 3]>, Vec<CDepend>) {
		let owned: Vec<_> = deps
			.iter()
			.map(|d| {
				[
					Some(cstr(&d.name)),
					d.version.as_deref().map(cstr),
					d.desc.as_deref().map(cstr),
				]
			})
			.collect();
		let mirrors = deps
			.iter()
			.zip(&owned)
			.map(|(d, o)| CDepend {
				name: opt_ptr(&o[0]).cast_mut(),
				version: opt_ptr(&o[1]).cast_mut(),
				desc: opt_ptr(&o[2]).cast_mut(),
				name_hash: d.name_hash,
				depmod: d.depmod as c_int,
			})
			.collect();
		(owned, mirrors)
	}

	fn rec(&self) -> &Recorder {
		// SAFETY: rec is live until drop; the C only writes it during
		// run(), when no such reference is held
		unsafe { &*self.rec }
	}

	fn db(&self, db: Option<usize>) -> *mut CDb {
		let rec = self.rec();
		db.map_or(rec.local, |i| rec.sync[i])
	}

	// the cache entry named id; the hash list, so pm_errno stays
	fn pkg(&self, id: &PkgId) -> *mut CPkg {
		// SAFETY: the db belongs to h, its cache loaded in new()
		let hash = unsafe { _alpm_db_get_pkgcache_hash(self.db(id.0)) };
		// SAFETY: hash is the live cache table
		let list = unsafe { (*hash).list };
		list_data(list)
			.into_iter()
			.map(|p| p.cast::<CPkg>())
			.find(|&p| {
				read_pkg(p).name.as_deref() == Some(&id.1[..])
			})
			.unwrap_or_else(|| panic!("no package {id:?}"))
	}

	fn list(&self, ids: &[PkgId]) -> PtrList {
		PtrList::new(ids.iter().map(|id| self.pkg(id)))
	}

	fn ids(&self, list: *mut CList) -> Vec<PkgId> {
		let ids = list_data(list)
			.into_iter()
			.map(|p| self.rec().id(p.cast()))
			.collect();
		// SAFETY: nodes from alpm_list_add, data owned by the caches
		unsafe { alpm_list_free(list) };
		ids
	}

	// f with these answers scripted, what the callbacks saw
	fn run<R>(
		&self,
		answers: &[c_int],
		f: impl FnOnce() -> R,
	) -> (R, Calls) {
		let rec = self.rec;
		// SAFETY: rec is live, no reference to it is held across f
		unsafe {
			(*rec).answers = answers.iter().copied().collect();
			(*rec).calls = Calls::default();
		}
		let r = f();
		// SAFETY: as above, the C is done with it
		(r, std::mem::take(unsafe { &mut (*rec).calls }))
	}

	pub fn checkdeps(
		&self,
		pkglist: &[PkgId],
		rem: &[PkgId],
		upgrade: &[PkgId],
		reversedeps: bool,
	) -> (Vec<DepMissing>, Calls) {
		let (l, r, u) = (
			self.list(pkglist),
			self.list(rem),
			self.list(upgrade),
		);
		let rev = c_int::from(reversedeps);
		// SAFETY: h is live, the lists hold its cached packages
		let (out, calls) = self.run(&[], || unsafe {
			alpm_checkdeps(self.h, l.0, r.0, u.0, rev)
		});
		(take_misses(out), calls)
	}

	pub fn sortbydeps(
		&self,
		targets: &[PkgId],
		ignore: &[PkgId],
		reverse: bool,
	) -> (Vec<PkgId>, Calls) {
		let (t, i) = (self.list(targets), self.list(ignore));
		let rev = c_int::from(reverse);
		// SAFETY: as in checkdeps
		let (out, calls) = self.run(&[], || unsafe {
			_alpm_sortbydeps(self.h, t.0, i.0, rev)
		});
		(self.ids(out), calls)
	}

	// Err is pm_errno. empty dbs is the NULL list
	pub fn find_dbs_satisfier(
		&self,
		dbs: &[Option<usize>],
		depstring: &[u8],
		answers: &[c_int],
	) -> (Result<PkgId, c_int>, Calls) {
		let list = PtrList::new(dbs.iter().map(|&d| self.db(d)));
		let s = cstr(depstring);
		// SAFETY: h is live, the list holds its dbs, s a C string
		let (p, calls) = self.run(answers, || unsafe {
			alpm_find_dbs_satisfier(self.h, list.0, s.as_ptr())
		});
		let r = match p.is_null() {
			// SAFETY: h is live
			true => Err(unsafe { alpm_errno(self.h) }),
			false => Ok(self.rec().id(p)),
		};
		(r, calls)
	}

	// (return value, packages after, data entries). the arguments are
	// _alpm_resolvedeps' plus the scripted answers
	#[allow(clippy::too_many_arguments)]
	pub fn resolvedeps(
		&self,
		localpkgs: &[PkgId],
		pkg: &PkgId,
		preferred: &[PkgId],
		packages: &[PkgId],
		rem: &[PkgId],
		answers: &[c_int],
	) -> ((c_int, Vec<PkgId>, Vec<DepMissing>), Calls) {
		let (l, p, r) = (
			self.list(localpkgs),
			self.list(preferred),
			self.list(rem),
		);
		let mut pkgs = self.list(packages);
		let target = self.pkg(pkg);
		let mut data = ptr::null_mut();
		// SAFETY: h is live, lists hold its cached packages, packages
		// and data are lists the C extends in place
		let (ret, calls) = self.run(answers, || unsafe {
			_alpm_resolvedeps(
				self.h,
				l.0,
				target,
				p.0,
				&mut pkgs.0,
				r.0,
				&mut data,
			)
		});
		let after = list_data(pkgs.0)
			.into_iter()
			.map(|p| self.rec().id(p.cast()))
			.collect();
		((ret, after, take_misses(data)), calls)
	}

	// (return value, names of the whole targs list after)
	pub fn recursedeps(
		&self,
		targs: &[PkgId],
		include_explicit: bool,
	) -> ((c_int, Vec<Vec<u8>>), Calls) {
		let mut list = self.list(targs);
		let db = self.db(None);
		let inc = c_int::from(include_explicit);
		// SAFETY: db is the local db of h, list holds its packages and
		// gets dups appended
		let (ret, calls) = self.run(&[], || unsafe {
			_alpm_recursedeps(db, &mut list.0, inc)
		});
		let all = list_data(list.0);
		let names = all
			.iter()
			.map(|&p| {
				read_pkg(p.cast())
					.name
					.expect("no name")
					.into_vec()
			})
			.collect();
		for &p in &all[targs.len()..] {
			// SAFETY: dups made by _alpm_recursedeps, owned here
			unsafe { _alpm_pkg_free(p.cast()) };
		}
		((ret, names), calls)
	}
}

impl Drop for CGraph {
	fn drop(&mut self) {
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h came from alpm_initialize with a transaction from
		// new(); rec from Box::into_raw, unused once h is released
		unsafe {
			assert_eq!(alpm_trans_release(self.h), 0);
			alpm_release(self.h);
			drop(Box::from_raw(self.rec));
		}
	}
}
