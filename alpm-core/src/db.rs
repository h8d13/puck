// port of lib/libalpm/db.c: alpm_db_t, its servers, usage, siglevel, the
// package cache (loaded through be_local/be_sync) and the group cache.
//
// a Db is owned by its Handle. dbpath and dbext are read at registration,
// which is also when the C computes and caches _path; calls that may load
// the package cache take handle->dbext as it is at call time, for the sync
// populate size estimate. pm_errno is not modelled: every call returns
// the alpm_errno_t it would leave as Err, Ok where it leaves ALPM_ERR_OK.
// logging is not modelled past registration. not ported: alpm_db_update
// and db->ops (Backend picks the backend).

use std::cmp::Ordering;
use std::ffi::c_int;
use std::ops::ControlFlow;

use crate::be_local::{DbError, INFRQ_DESC, LocalDb};
use crate::be_sync;
use crate::callbacks::{Callbacks, Event, LogLevel};
use crate::deps::{dep_from_string, depcmp_literal, depcmp_provides};
use crate::error::Errno;
use crate::group::Group;
use crate::package::{Package, PkgFrom};
use crate::pkghash::PkgHash;
use crate::regex::{Flags, Regex};
use crate::signing::Keyring;
use crate::util::until_nul;

// alpm_db_usage_t
pub const DB_USAGE_SYNC: c_int = 1;
pub const DB_USAGE_SEARCH: c_int = 1 << 1;
pub const DB_USAGE_INSTALL: c_int = 1 << 2;
pub const DB_USAGE_UPGRADE: c_int = 1 << 3;
pub const DB_USAGE_ALL: c_int = (1 << 4) - 1;

// alpm_siglevel_t bits read by the db and handle code
pub const SIG_DATABASE: c_int = 1 << 10;
pub const SIG_USE_DEFAULT: c_int = 1 << 30;

// db->ops
#[derive(Clone, Debug)]
enum Backend {
	Local(LocalDb),
	Sync,
}

// DB_STATUS_VALID/INVALID/MISSING. the local db is always Valid: a
// local db failing validation is never registered
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
	Valid,
	// sync db file absent at registration: valid, populate refuses
	Missing,
	Invalid,
}

// why _alpm_db_add_pkgincache/_alpm_db_remove_pkgfromcache returned -1
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheError {
	// no DB_STATUS_PKGCACHE, pm_errno untouched
	NotLoaded,
	// remove: no entry with that name and name_hash, pm_errno untouched
	NotFound,
	// add: the table cannot grow, ALPM_ERR_MEMORY
	Memory,
}

impl CacheError {
	// the pm_errno the C sets, None where it leaves it alone
	pub fn errno(self) -> Option<Errno> {
		match self {
			CacheError::Memory => Some(Errno::Memory),
			_ => None,
		}
	}
}

// alpm_db_t
#[derive(Clone, Debug)]
pub struct Db {
	treename: Vec<u8>,
	// _alpm_db_path
	path: Vec<u8>,
	backend: Backend,
	status: Status,
	// Some is DB_STATUS_PKGCACHE
	pkgcache: Option<PkgHash<Package>>,
	// Some is DB_STATUS_GRPCACHE. members are positions in the pkgcache
	// list: every cache change drops the group cache, so they hold
	grpcache: Option<Vec<Group<usize>>>,
	servers: Vec<Vec<u8>>,
	cache_servers: Vec<Vec<u8>>,
	siglevel: c_int,
	usage: c_int,
}

// sanitize_url: one trailing '/' dropped. callers refuse empty urls
fn sanitize_url(url: &[u8]) -> Vec<u8> {
	url.strip_suffix(b"/").unwrap_or(url).to_vec()
}

// alpm_db_add_server/alpm_db_add_cache_server
fn add_url(list: &mut Vec<Vec<u8>>, url: &[u8]) -> Result<(), Errno> {
	let url = until_nul(url);
	if url.is_empty() {
		return Err(Errno::WrongArgs);
	}
	list.push(sanitize_url(url));
	Ok(())
}

// alpm_db_remove_server/alpm_db_remove_cache_server: first equal entry
// after sanitizing. Ok(false) is the C's 1 (not found)
fn remove_url(list: &mut Vec<Vec<u8>>, url: &[u8]) -> Result<bool, Errno> {
	let url = until_nul(url);
	if url.is_empty() {
		return Err(Errno::WrongArgs);
	}
	let url = sanitize_url(url);
	let Some(i) = list.iter().position(|u| *u == url) else {
		return Ok(false);
	};
	list.remove(i);
	Ok(true)
}

// alpm_db_set_servers/alpm_db_set_cache_servers: the old list is freed
// first and the adds stop at the first bad url, keeping those before it
fn set_urls<U: AsRef<[u8]>>(
	list: &mut Vec<Vec<u8>>,
	urls: &[U],
) -> Result<(), Errno> {
	list.clear();
	urls.iter().try_for_each(|u| add_url(list, u.as_ref()))
}

// LAZY_LOAD of the cache ops on a cached package, in place: local
// packages read the missing sections, a failed read sets INFRQ_ERROR and
// is not retried (the C logs it). sync packages are loaded whole.
// Package has no ops pointer: every local cache entry gets the cache ops,
// where an added package keeps the ops of the one it was dup'ed from
fn lazy_load(backend: &Backend, pkg: &mut Package, inforeq: c_int) {
	if let Backend::Local(local) = backend {
		let _ = local.read(pkg, inforeq);
	}
}

// strstr(hay, needle) != NULL: an empty needle is found everywhere
fn strstr(hay: &[u8], needle: &[u8]) -> bool {
	needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

// one package of _alpm_db_search: the name as regex or as plain text
// (strstr, case sensitive), else the description, else any provide
// name, else any group
fn search_match(reg: &Regex, targ: &[u8], pkg: &Package) -> bool {
	let name = pkg.name.as_deref().map(until_nul);
	if name.is_some_and(|n| reg.is_match(n) || strstr(n, targ)) {
		return true;
	}
	if pkg.desc.as_deref().is_some_and(|d| reg.is_match(d)) {
		return true;
	}
	pkg.provides.iter().any(|p| reg.is_match(&p.name))
		|| pkg.groups.iter().any(|g| reg.is_match(g))
}

// load_grpcache over the cache list: a group takes the package when it
// does not hold it yet, else the search goes on. a package naming a
// group twice ends up in two groups of that name. alpm_pkg_get_groups
// loads each desc into its cache entry
fn build_grpcache(
	backend: &Backend,
	cache: &mut PkgHash<Package>,
) -> Vec<Group<usize>> {
	let mut groups: Vec<Group<usize>> = Vec::new();
	for (i, pkg) in cache.iter_mut().enumerate() {
		lazy_load(backend, pkg, INFRQ_DESC);
		for name in &pkg.groups {
			let name = until_nul(name);
			let open = groups.iter_mut().find(|g| {
				g.name == name && !g.packages.contains(&i)
			});
			match open {
				Some(g) => g.packages.push(i),
				None => {
					let mut g = Group::new(name);
					g.packages.push(i);
					groups.push(g);
				}
			}
		}
	}
	groups
}

impl Db {
	fn new(treename: &[u8], path: Vec<u8>, backend: Backend) -> Db {
		Db {
			treename: until_nul(treename).to_vec(),
			path,
			backend,
			status: Status::Valid,
			pkgcache: None,
			grpcache: None,
			servers: Vec::new(),
			cache_servers: Vec::new(),
			siglevel: 0,
			usage: DB_USAGE_ALL,
		}
	}

	// _alpm_db_register_local without the handle: "local", validated
	// (and created when missing) by be_local. dbpath is handle->dbpath
	pub fn register_local(dbpath: &[u8]) -> Result<Db, DbError> {
		let local = LocalDb::register(dbpath)?;
		let path = local.path().to_vec();
		Ok(Db::new(b"local", path, Backend::Local(local)))
	}

	// _alpm_db_register_sync without the handle: the name checks are
	// alpm_register_syncdb's (Handle::register_syncdb), then
	// sync_db_validate with the handle's keyring, default siglevel and
	// callbacks
	#[allow(clippy::too_many_arguments)]
	pub fn register_sync(
		dbpath: &[u8],
		dbext: &[u8],
		treename: &[u8],
		siglevel: c_int,
		default_siglevel: c_int,
		kr: &mut Keyring,
		cb: &mut dyn Callbacks,
	) -> Db {
		let msg = [b"registering sync database '", treename, b"'\n"];
		cb.log(LogLevel::Debug, &msg.concat());
		let path = be_sync::db_path(dbpath, treename, dbext);
		let mut db = Db::new(treename, path, Backend::Sync);
		db.siglevel = siglevel;
		db.validate(default_siglevel, kr, cb);
		db
	}

	// sync_db_validate: a missing file sends ALPM_EVENT_DATABASE_MISSING
	// and is valid, a failed signature check makes the db invalid
	fn validate(
		&mut self,
		default_siglevel: c_int,
		kr: &mut Keyring,
		cb: &mut dyn Callbacks,
	) {
		let level = self.siglevel(default_siglevel);
		let name = &self.treename;
		self.status = match be_sync::sync_db_validate(
			kr, cb, &self.path, name, level,
		) {
			Ok(true) => Status::Valid,
			Ok(false) => {
				let ev =
					Event::DatabaseMissing { dbname: name };
				cb.event(&ev);
				Status::Missing
			}
			Err(_) => Status::Invalid,
		};
	}

	// alpm_db_get_name
	pub fn name(&self) -> &[u8] {
		&self.treename
	}

	// DB_STATUS_LOCAL
	pub fn is_local(&self) -> bool {
		matches!(self.backend, Backend::Local(_))
	}

	// _alpm_db_path: "<dbpath>local/" or "<dbpath>sync/<name><dbext>"
	// with the dbext of the time of registration (the C caches it then)
	pub fn path(&self) -> &[u8] {
		&self.path
	}

	// alpm_db_get_servers
	pub fn servers(&self) -> &[Vec<u8>] {
		&self.servers
	}

	// alpm_db_get_cache_servers
	pub fn cache_servers(&self) -> &[Vec<u8>] {
		&self.cache_servers
	}

	// alpm_db_add_server: WrongArgs for an empty url, one trailing '/'
	// dropped ("/" is stored as "")
	pub fn add_server(&mut self, url: &[u8]) -> Result<(), Errno> {
		add_url(&mut self.servers, url)
	}

	pub fn add_cache_server(&mut self, url: &[u8]) -> Result<(), Errno> {
		add_url(&mut self.cache_servers, url)
	}

	// alpm_db_remove_server: Ok(true) removed (C 0), Ok(false) not
	// found (C 1)
	pub fn remove_server(&mut self, url: &[u8]) -> Result<bool, Errno> {
		remove_url(&mut self.servers, url)
	}

	pub fn remove_cache_server(
		&mut self,
		url: &[u8],
	) -> Result<bool, Errno> {
		remove_url(&mut self.cache_servers, url)
	}

	// alpm_db_set_servers: on Err the urls before the bad one stay
	pub fn set_servers<U: AsRef<[u8]>>(
		&mut self,
		urls: &[U],
	) -> Result<(), Errno> {
		set_urls(&mut self.servers, urls)
	}

	pub fn set_cache_servers<U: AsRef<[u8]>>(
		&mut self,
		urls: &[U],
	) -> Result<(), Errno> {
		set_urls(&mut self.cache_servers, urls)
	}

	// alpm_db_get_usage
	pub fn usage(&self) -> c_int {
		self.usage
	}

	// alpm_db_set_usage: any int is stored
	pub fn set_usage(&mut self, usage: c_int) {
		self.usage = usage;
	}

	// db->siglevel as registered (0 for the local db)
	pub fn raw_siglevel(&self) -> c_int {
		self.siglevel
	}

	// alpm_db_get_siglevel: ALPM_SIG_USE_DEFAULT anywhere in the level
	// gives the handle's default
	pub fn siglevel(&self, default: c_int) -> c_int {
		match self.siglevel & SIG_USE_DEFAULT {
			0 => self.siglevel,
			_ => default,
		}
	}

	// alpm_db_get_valid: the validate op. an invalid sync db reports
	// DbInvalidSig, whatever made it invalid
	pub fn valid(&self) -> Result<(), Errno> {
		match self.status {
			Status::Invalid => Err(Errno::DbInvalidSig),
			_ => Ok(()),
		}
	}

	// db->ops->populate, dbext is handle->dbext now. sync: a failure
	// to open the file or a bad entry makes the db invalid for good, an
	// archive error does not
	fn populate(
		&mut self,
		dbext: &[u8],
	) -> Result<PkgHash<Package>, Errno> {
		if let Backend::Local(local) = &self.backend {
			return local.populate().map_err(|e| e.errno());
		}
		if self.status == Status::Missing {
			return Err(Errno::DbNotFound);
		}
		let err = match be_sync::populate(&self.path, dbext) {
			Ok(cache) => return Ok(cache),
			Err(e) => e,
		};
		// a failure once the table exists frees it, and with it the
		// group cache (_alpm_db_free_pkgcache)
		if let be_sync::Error::Archive(_)
		| be_sync::Error::Invalid { .. } = err
		{
			self.grpcache = None;
		}
		match err {
			be_sync::Error::Archive(_) | be_sync::Error::Memory => {
			}
			_ => self.status = Status::Invalid,
		}
		Err(match err {
			// existed at registration, open(2) now fails
			be_sync::Error::NotFound => Errno::DbOpen,
			e => e.errno(),
		})
	}

	// _alpm_db_get_pkgcache_hash: loaded on first use
	fn load_pkgcache(&mut self, dbext: &[u8]) -> Result<(), Errno> {
		if self.status == Status::Invalid {
			return Err(Errno::DbInvalid);
		}
		if self.pkgcache.is_none() {
			self.pkgcache = Some(self.populate(dbext)?);
		}
		Ok(())
	}

	// the package cache as loaded so far, None before the first load
	pub fn loaded_pkgcache(&self) -> Option<&PkgHash<Package>> {
		self.pkgcache.as_ref()
	}

	// alpm_db_get_pkgcache: list order is by name, the table as the
	// backend filled it. dbext is handle->dbext, read by a sync load
	pub fn pkgcache(
		&mut self,
		dbext: &[u8],
	) -> Result<&PkgHash<Package>, Errno> {
		self.load_pkgcache(dbext)?;
		Ok(self.pkgcache.as_ref().expect("cache just loaded"))
	}

	// alpm_db_get_pkg: a cache that cannot load is PkgNotFound too
	pub fn get_pkg(
		&mut self,
		dbext: &[u8],
		name: &[u8],
	) -> Result<&Package, Errno> {
		self.find_pkg(dbext, name).map(|(_, p)| &*p)
	}

	// alpm_db_get_pkg, then the alpm_pkg_get_* getters reading the
	// INFRQ_* sections of inforeq: loaded into the cache entry, so
	// later lookups see them
	pub fn load_pkg(
		&mut self,
		dbext: &[u8],
		name: &[u8],
		inforeq: c_int,
	) -> Result<&Package, Errno> {
		let (backend, pkg) = self.find_pkg(dbext, name)?;
		lazy_load(backend, pkg, inforeq);
		Ok(pkg)
	}

	// the cache entry at position i of the list, with the INFRQ_*
	// sections of inforeq loaded in place. None past the end or when
	// the cache does not load
	pub fn load_pkg_at(
		&mut self,
		dbext: &[u8],
		i: usize,
		inforeq: c_int,
	) -> Option<&Package> {
		self.load_pkgcache(dbext).ok()?;
		let pkg = self.pkgcache.as_mut()?.iter_mut().nth(i)?;
		lazy_load(&self.backend, pkg, inforeq);
		Some(pkg)
	}

	// alpm_db_get_pkgcache, then the getters of inforeq on every
	// entry in list order, loaded in place
	pub fn load_all(
		&mut self,
		dbext: &[u8],
		inforeq: c_int,
	) -> Result<&PkgHash<Package>, Errno> {
		self.load_pkgcache(dbext)?;
		let cache = self.pkgcache.as_mut().expect("cache just loaded");
		for pkg in cache.iter_mut() {
			lazy_load(&self.backend, pkg, inforeq);
		}
		Ok(cache)
	}

	// a C loop over the cache list calling a getter per package: each
	// entry gets the sections of inforeq loaded just before f sees it
	// (with its list position), entries after a Break stay untouched.
	// Ok(None) when f never breaks, Err when the cache does not load
	pub fn walk<B>(
		&mut self,
		dbext: &[u8],
		inforeq: c_int,
		mut f: impl FnMut(usize, &Package) -> ControlFlow<B>,
	) -> Result<Option<B>, Errno> {
		self.load_pkgcache(dbext)?;
		let cache = self.pkgcache.as_mut().expect("cache just loaded");
		for (i, pkg) in cache.iter_mut().enumerate() {
			lazy_load(&self.backend, pkg, inforeq);
			if let ControlFlow::Break(b) = f(i, pkg) {
				return Ok(Some(b));
			}
		}
		Ok(None)
	}

	// alpm_find_satisfier over the cache list with the getters' loads:
	// a package matching by name and version is taken as it is, the
	// others get their desc loaded for the provides. the list position
	// of the first satisfier
	pub fn find_satisfier(
		&mut self,
		dbext: &[u8],
		depstring: &[u8],
	) -> Option<usize> {
		let dep = dep_from_string(depstring);
		self.load_pkgcache(dbext).ok()?;
		let cache = self.pkgcache.as_mut()?;
		for (i, pkg) in cache.iter_mut().enumerate() {
			if depcmp_literal(pkg, &dep) {
				return Some(i);
			}
			lazy_load(&self.backend, pkg, INFRQ_DESC);
			if depcmp_provides(&dep, &pkg.provides) {
				return Some(i);
			}
		}
		None
	}

	// the local backend (desc/files/mtree/changelog paths), None for a
	// sync db
	pub fn local(&self) -> Option<&LocalDb> {
		match &self.backend {
			Backend::Local(local) => Some(local),
			Backend::Sync => None,
		}
	}

	// _alpm_db_search: the packages matching every needle (AND), in
	// cache list order. needles are EREs with REG_ICASE|REG_NEWLINE,
	// the first one that does not compile is InvalidRegex. a db without
	// DB_USAGE_SEARCH or no needles give nothing, a cache that does not
	// load an empty list to search (the C returns 0 with the load's
	// pm_errno left set). each package searched gets its desc loaded
	pub fn search<S: AsRef<[u8]>>(
		&mut self,
		dbext: &[u8],
		needles: &[S],
	) -> Result<Vec<&Package>, Errno> {
		if self.usage & DB_USAGE_SEARCH == 0 || needles.is_empty() {
			return Ok(Vec::new());
		}
		let _ = self.load_pkgcache(dbext);
		let mut pkgs: Vec<&mut Package> = match &mut self.pkgcache {
			Some(c) => c.iter_mut().collect(),
			None => Vec::new(),
		};
		let mut list: Vec<usize> = (0..pkgs.len()).collect();
		let flags = Flags {
			icase: true,
			newline: true,
		};
		for needle in needles {
			let targ = until_nul(needle.as_ref());
			let reg = Regex::new(targ, flags)
				.map_err(|_| Errno::InvalidRegex)?;
			list.retain(|&i| {
				let pkg = &mut *pkgs[i];
				lazy_load(&self.backend, pkg, INFRQ_DESC);
				search_match(&reg, targ, pkg)
			});
		}
		let pkgs: Vec<&Package> =
			pkgs.into_iter().map(|p| &*p).collect();
		Ok(list.into_iter().map(|i| pkgs[i]).collect())
	}

	// the cache entry alpm_db_get_pkg returns, with the backend that
	// loads it
	fn find_pkg(
		&mut self,
		dbext: &[u8],
		name: &[u8],
	) -> Result<(&Backend, &mut Package), Errno> {
		let name = until_nul(name);
		if name.is_empty() {
			return Err(Errno::WrongArgs);
		}
		self.load_pkgcache(dbext).map_err(|_| Errno::PkgNotFound)?;
		let cache = self.pkgcache.as_mut().expect("cache just loaded");
		let pkg = cache.find_mut(name).ok_or(Errno::PkgNotFound)?;
		Ok((&self.backend, pkg))
	}

	// _alpm_db_get_groupcache. load_grpcache marks the group cache
	// loaded even when the package cache fails: that call returns the
	// cache's error, later ones an empty list. a later successful load
	// keeps it (_alpm_db_free_pkgcache does nothing without a package
	// cache), a failing sync reload drops it (populate frees its table)
	pub fn groupcache(
		&mut self,
		dbext: &[u8],
	) -> Result<Vec<Group<&Package>>, Errno> {
		if self.status == Status::Invalid {
			return Err(Errno::DbInvalid);
		}
		if self.grpcache.is_none() {
			let loaded = self.load_pkgcache(dbext);
			// a failed load leaves no package cache
			let groups = match &mut self.pkgcache {
				Some(c) => build_grpcache(&self.backend, c),
				None => Vec::new(),
			};
			self.grpcache = Some(groups);
			loaded?;
		}
		Ok(self.resolve_groups())
	}

	fn resolve_groups(&self) -> Vec<Group<&Package>> {
		let pkgs: Vec<&Package> =
			self.pkgcache.iter().flat_map(|c| c.iter()).collect();
		let groups = self.grpcache.as_deref().unwrap_or_default();
		groups.iter()
			.map(|g| Group {
				name: g.name.clone(),
				packages: g
					.packages
					.iter()
					.map(|&i| pkgs[i])
					.collect(),
			})
			.collect()
	}

	// alpm_db_get_group: first group of that name. Ok(None) on a miss
	// (NULL with ALPM_ERR_OK), Err when the group cache failed
	pub fn get_group(
		&mut self,
		dbext: &[u8],
		name: &[u8],
	) -> Result<Option<Group<&Package>>, Errno> {
		let name = until_nul(name);
		if name.is_empty() {
			return Err(Errno::WrongArgs);
		}
		let groups = self.groupcache(dbext)?;
		Ok(groups.into_iter().find(|g| g.name == name))
	}

	// _alpm_db_add_pkgincache: a dup() of pkg, origin set to this db,
	// merged into the list by name (duplicate names are not refused).
	// the group cache is dropped. the C's force_load before the dup is
	// not modelled
	pub fn add_pkg_in_cache(
		&mut self,
		pkg: &Package,
	) -> Result<(), CacheError> {
		let cache =
			self.pkgcache.as_mut().ok_or(CacheError::NotLoaded)?;
		let mut newpkg = pkg.dup();
		newpkg.origin = Some(match self.backend {
			Backend::Local(_) => PkgFrom::LocalDb,
			Backend::Sync => PkgFrom::SyncDb,
		});
		cache.add_sorted(newpkg).map_err(|_| CacheError::Memory)?;
		self.grpcache = None;
		Ok(())
	}

	// _alpm_db_remove_pkgfromcache: the entry with pkg's name and
	// stored name_hash, handed back where the C frees it
	pub fn remove_pkg_from_cache(
		&mut self,
		pkg: &Package,
	) -> Result<Package, CacheError> {
		let cache =
			self.pkgcache.as_mut().ok_or(CacheError::NotLoaded)?;
		let removed = cache.remove(pkg).ok_or(CacheError::NotFound)?;
		self.grpcache = None;
		Ok(removed)
	}

	// _alpm_db_free_pkgcache: the group cache goes with the package
	// cache, and stays when there is none
	pub fn free_pkgcache(&mut self) {
		if self.pkgcache.take().is_some() {
			self.grpcache = None;
		}
	}
}

// _alpm_db_cmp: strcmp on the names
pub fn db_cmp(a: &Db, b: &Db) -> Ordering {
	a.treename.cmp(&b.treename)
}
