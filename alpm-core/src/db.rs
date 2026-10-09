// port of lib/libalpm/db.c: alpm_db_t, its servers, usage, siglevel, the
// package cache (loaded through be_local/be_sync) and the group cache.
//
// a Db is owned by its Handle. dbpath and dbext are read at registration,
// which is also when the C computes and caches _path; calls that may load
// the package cache take handle->dbext as it is at call time, for the sync
// populate size estimate. pm_errno is not modelled: every call returns
// the alpm_errno_t it would leave as Err, Ok where it leaves ALPM_ERR_OK.
// _alpm_log goes to the cb each call takes, handle->logcb in the C
// (Handle::dbs_mut lends it with the dbs); RET_ERR's debug line is not
// logged. alpm_db_update is in be_sync.rs. not ported: db->ops (Backend
// picks the backend).

use std::cmp::Ordering;
use std::ffi::c_int;
use std::ops::ControlFlow;

use crate::be_local::{
	INFRQ_DESC, INFRQ_FILES, INFRQ_SCRIPTLET, LocalDb, LocalDbError,
};
use crate::be_sync;
use crate::callbacks::{Callbacks, Event, LogLevel, logv};
use crate::deps::{dep_from_string, depcmp_literal, depcmp_provides};
use crate::error::Errno;
use crate::group::Group;
use crate::package::{Package, PkgFrom, PkgReason};
use crate::pkghash::PkgHash;
use crate::regex::{Flags, Regex};
use crate::signing::Keyring;
use crate::util::until_nul;

/// alpm_db_usage_t ALPM_DB_USAGE_SYNC: the db takes part in -Sy
pub const DB_USAGE_SYNC: c_int = 1;
/// ALPM_DB_USAGE_SEARCH: the db takes part in -Ss
pub const DB_USAGE_SEARCH: c_int = 1 << 1;
/// ALPM_DB_USAGE_INSTALL: packages may be installed from the db
pub const DB_USAGE_INSTALL: c_int = 1 << 2;
/// ALPM_DB_USAGE_UPGRADE: the db takes part in -Su
pub const DB_USAGE_UPGRADE: c_int = 1 << 3;
/// ALPM_DB_USAGE_ALL
pub const DB_USAGE_ALL: c_int = (1 << 4) - 1;

/// alpm_siglevel_t ALPM_SIG_DATABASE: db signatures are checked
pub const SIG_DATABASE: c_int = 1 << 10;
/// ALPM_SIG_USE_DEFAULT: the handle's default siglevel applies
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

/// why _alpm_db_add_pkgincache/_alpm_db_remove_pkgfromcache returned -1
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheError {
	/// no DB_STATUS_PKGCACHE, pm_errno untouched
	NotLoaded,
	/// remove: no entry with that name and name_hash, pm_errno untouched
	NotFound,
	/// add: the table cannot grow, ALPM_ERR_MEMORY
	Memory,
}

impl CacheError {
	/// the pm_errno the C sets, None where it leaves it alone
	pub fn errno(self) -> Option<Errno> {
		match self {
			CacheError::Memory => Some(Errno::Memory),
			_ => None,
		}
	}
}

/// alpm_db_t
#[derive(Clone, Debug)]
pub struct Db {
	treename: Vec<u8>,
	/// _alpm_db_path
	path: Vec<u8>,
	backend: Backend,
	status: Status,
	/// Some is DB_STATUS_PKGCACHE
	pkgcache: Option<PkgHash<Package>>,
	/// Some is DB_STATUS_GRPCACHE. members are positions in the pkgcache
	/// list: every cache change drops the group cache, so they hold
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

// a server list and the word its log lines name it by
struct Urls<'a> {
	list: &'a mut Vec<Vec<u8>>,
	// "" or "cache "
	kind: &'static [u8],
	treename: &'a [u8],
}

// alpm_db_add_server/alpm_db_add_cache_server
fn add_url(
	u: &mut Urls,
	cb: &mut dyn Callbacks,
	url: &[u8],
) -> Result<(), Errno> {
	let url = until_nul(url);
	if url.is_empty() {
		return Err(Errno::WrongArgs);
	}
	let url = sanitize_url(url);
	let what: [&[u8]; 7] = [
		b"adding new ",
		u.kind,
		b"server URL to database '",
		u.treename,
		b"': ",
		&url,
		b"\n",
	];
	u.list.push(url.clone());
	logv(cb, LogLevel::Debug, &what);
	Ok(())
}

// alpm_db_remove_server/alpm_db_remove_cache_server: first equal entry
// after sanitizing. Ok(false) is the C's 1 (not found)
fn remove_url(
	u: &mut Urls,
	cb: &mut dyn Callbacks,
	url: &[u8],
) -> Result<bool, Errno> {
	let url = until_nul(url);
	if url.is_empty() {
		return Err(Errno::WrongArgs);
	}
	let url = sanitize_url(url);
	let Some(i) = u.list.iter().position(|x| *x == url) else {
		return Ok(false);
	};
	u.list.remove(i);
	let what: [&[u8]; 7] = [
		b"removed ",
		u.kind,
		b"server URL from database '",
		u.treename,
		b"': ",
		&url,
		b"\n",
	];
	logv(cb, LogLevel::Debug, &what);
	Ok(true)
}

// alpm_db_set_servers/alpm_db_set_cache_servers: the old list is freed
// first and the adds stop at the first bad url, keeping those before it
fn set_urls<U: AsRef<[u8]>>(
	u: &mut Urls,
	cb: &mut dyn Callbacks,
	urls: &[U],
) -> Result<(), Errno> {
	u.list.clear();
	urls.iter().try_for_each(|url| add_url(u, cb, url.as_ref()))
}

// LAZY_LOAD of the cache ops on a cached package, in place: local
// packages read the missing sections, a failed read sets INFRQ_ERROR and
// is not retried (local_db_read logs it). sync packages are loaded
// whole. one read per section like one getter per section in the C
// (desc, files, scriptlet), so the loading log lines match. Package has
// no ops pointer: every local cache entry gets the cache ops, where an
// added package keeps the ops of the one it was dup'ed from
fn lazy_load(
	backend: &Backend,
	pkg: &mut Package,
	inforeq: c_int,
	cb: &mut dyn Callbacks,
) {
	let Backend::Local(local) = backend else {
		return;
	};
	for bit in [INFRQ_DESC, INFRQ_FILES, INFRQ_SCRIPTLET] {
		if inforeq & bit != 0 {
			let _ = local.read(pkg, bit, cb);
		}
	}
}

// strstr(hay, needle) != NULL: an empty needle is found everywhere
fn strstr(hay: &[u8], needle: &[u8]) -> bool {
	needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

// one package of _alpm_db_search: the name as regex or as plain text
// (strstr, case sensitive), else the description, else any provide
// name, else any group. the text that matched
fn search_match<'p>(
	reg: &Regex,
	targ: &[u8],
	pkg: &'p Package,
) -> Option<&'p [u8]> {
	let name = pkg.name.as_deref().map(until_nul);
	if let Some(n) = name.filter(|n| reg.is_match(n) || strstr(n, targ)) {
		return Some(n);
	}
	let desc = pkg.desc.as_deref().map(until_nul);
	if let Some(d) = desc.filter(|d| reg.is_match(d)) {
		return Some(d);
	}
	let provide = pkg.provides.iter().map(|p| until_nul(&p.name));
	let group = pkg.groups.iter().map(|g| until_nul(g));
	provide.chain(group).find(|s| reg.is_match(s))
}

// load_grpcache over the cache list: a group takes the package when it
// does not hold it yet, else the search goes on. a package naming a
// group twice ends up in two groups of that name. alpm_pkg_get_groups
// loads each desc into its cache entry
fn build_grpcache(
	backend: &Backend,
	cache: &mut PkgHash<Package>,
	cb: &mut dyn Callbacks,
) -> Vec<Group<usize>> {
	let mut groups: Vec<Group<usize>> = Vec::new();
	for (i, pkg) in cache.iter_mut().enumerate() {
		lazy_load(backend, pkg, INFRQ_DESC, cb);
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

	/// _alpm_db_register_local without the handle: "local", validated
	/// (and created when missing) by be_local. dbpath is handle->dbpath
	pub fn register_local(dbpath: &[u8]) -> Result<Db, LocalDbError> {
		let local = LocalDb::register(dbpath)?;
		let path = local.path().to_vec();
		Ok(Db::new(b"local", path, Backend::Local(local)))
	}

	/// _alpm_db_register_sync without the handle: the name checks are
	/// alpm_register_syncdb's (Handle::register_syncdb), then
	/// sync_db_validate with the handle's keyring, default siglevel and
	/// callbacks
	/// the handle fields it reads come apart (split borrow of the handle)
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
		// _alpm_db_path computing it, the first time validate asks
		let msg = [b"database path for tree ", treename, b" set to "];
		cb.log(
			LogLevel::Debug,
			&[&msg.concat()[..], &path, b"\n"].concat(),
		);
		let mut db = Db::new(treename, path, Backend::Sync);
		db.siglevel = siglevel;
		let _ = db.validate(default_siglevel, kr, cb);
		db
	}

	/// sync_db_validate with the status bits cleared first, as at
	/// registration and after alpm_db_update's download: a missing file
	/// sends ALPM_EVENT_DATABASE_MISSING and is valid, a failed signature
	/// check makes the db invalid (Err)
	pub fn validate(
		&mut self,
		default_siglevel: c_int,
		kr: &mut Keyring,
		cb: &mut dyn Callbacks,
	) -> Result<(), Errno> {
		let level = self.siglevel(default_siglevel);
		let name = &self.treename;
		let res = be_sync::sync_db_validate(
			kr, cb, &self.path, name, level,
		);
		self.status = match res {
			Ok(true) => Status::Valid,
			Ok(false) => {
				let ev =
					Event::DatabaseMissing { dbname: name };
				cb.event(&ev);
				Status::Missing
			}
			Err(_) => Status::Invalid,
		};
		res.map(drop)
	}

	/// alpm_db_get_name
	pub fn name(&self) -> &[u8] {
		&self.treename
	}

	/// DB_STATUS_LOCAL
	pub fn is_local(&self) -> bool {
		matches!(self.backend, Backend::Local(_))
	}

	/// _alpm_db_path: `<dbpath>local/` or `<dbpath>sync/<name><dbext>`
	/// with the dbext of the time of registration (the C caches it then)
	pub fn path(&self) -> &[u8] {
		&self.path
	}

	/// alpm_db_get_servers
	pub fn servers(&self) -> &[Vec<u8>] {
		&self.servers
	}

	/// alpm_db_get_cache_servers
	pub fn cache_servers(&self) -> &[Vec<u8>] {
		&self.cache_servers
	}

	fn urls(&mut self, cache: bool) -> Urls<'_> {
		let (list, kind): (_, &[u8]) = match cache {
			false => (&mut self.servers, b""),
			true => (&mut self.cache_servers, b"cache "),
		};
		Urls {
			list,
			kind,
			treename: &self.treename,
		}
	}

	/// alpm_db_add_server: WrongArgs for an empty url, one trailing '/'
	/// dropped ("/" is stored as "")
	pub fn add_server(
		&mut self,
		cb: &mut dyn Callbacks,
		url: &[u8],
	) -> Result<(), Errno> {
		add_url(&mut self.urls(false), cb, url)
	}

	/// alpm_db_add_cache_server
	pub fn add_cache_server(
		&mut self,
		cb: &mut dyn Callbacks,
		url: &[u8],
	) -> Result<(), Errno> {
		add_url(&mut self.urls(true), cb, url)
	}

	/// alpm_db_remove_server: Ok(true) removed (C 0), Ok(false) not
	/// found (C 1)
	pub fn remove_server(
		&mut self,
		cb: &mut dyn Callbacks,
		url: &[u8],
	) -> Result<bool, Errno> {
		remove_url(&mut self.urls(false), cb, url)
	}

	/// alpm_db_remove_cache_server
	pub fn remove_cache_server(
		&mut self,
		cb: &mut dyn Callbacks,
		url: &[u8],
	) -> Result<bool, Errno> {
		remove_url(&mut self.urls(true), cb, url)
	}

	/// alpm_db_set_servers: on Err the urls before the bad one stay
	pub fn set_servers<U: AsRef<[u8]>>(
		&mut self,
		cb: &mut dyn Callbacks,
		urls: &[U],
	) -> Result<(), Errno> {
		set_urls(&mut self.urls(false), cb, urls)
	}

	/// alpm_db_set_cache_servers
	pub fn set_cache_servers<U: AsRef<[u8]>>(
		&mut self,
		cb: &mut dyn Callbacks,
		urls: &[U],
	) -> Result<(), Errno> {
		set_urls(&mut self.urls(true), cb, urls)
	}

	/// alpm_db_get_usage
	pub fn usage(&self) -> c_int {
		self.usage
	}

	/// alpm_db_set_usage: any int is stored
	pub fn set_usage(&mut self, usage: c_int) {
		self.usage = usage;
	}

	/// db->siglevel as registered (0 for the local db)
	pub fn raw_siglevel(&self) -> c_int {
		self.siglevel
	}

	/// alpm_db_get_siglevel: ALPM_SIG_USE_DEFAULT anywhere in the level
	/// gives the handle's default
	pub fn siglevel(&self, default: c_int) -> c_int {
		match self.siglevel & SIG_USE_DEFAULT {
			0 => self.siglevel,
			_ => default,
		}
	}

	/// alpm_db_get_valid: the validate op. an invalid sync db reports
	/// DbInvalidSig, whatever made it invalid
	pub fn valid(&self) -> Result<(), Errno> {
		match self.status {
			Status::Invalid => Err(Errno::DbInvalidSig),
			_ => Ok(()),
		}
	}

	// DB_STATUS_MISSING: a sync db whose file was absent at registration
	pub(crate) fn is_missing(&self) -> bool {
		self.status == Status::Missing
	}

	// db->ops->populate, dbext is handle->dbext now. sync: a failure
	// to open the file or a bad entry makes the db invalid for good, an
	// archive error does not
	fn populate(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
	) -> Result<PkgHash<Package>, Errno> {
		if let Backend::Local(local) = &self.backend {
			return local.populate(cb).map_err(|e| e.errno());
		}
		if self.status == Status::Missing {
			return Err(Errno::DbNotFound);
		}
		let name = &self.treename;
		let err = match be_sync::populate(&self.path, dbext, name, cb) {
			Ok(cache) => return Ok(cache),
			Err(e) => e,
		};
		// a failure once the table exists frees it, and with it the
		// group cache (_alpm_db_free_pkgcache)
		if let be_sync::SyncDbError::Archive(_)
		| be_sync::SyncDbError::Invalid { .. } = err
		{
			self.log_free_pkgcache(cb);
			self.free_groupcache(cb);
		}
		match err {
			be_sync::SyncDbError::Archive(_)
			| be_sync::SyncDbError::Memory => {}
			_ => self.status = Status::Invalid,
		}
		Err(match err {
			// existed at registration, open(2) now fails
			be_sync::SyncDbError::NotFound => Errno::DbOpen,
			e => e.errno(),
		})
	}

	fn log_repo(&self, cb: &mut dyn Callbacks, what: &[u8]) {
		let parts: [&[u8]; 4] =
			[what, b" for repository '", &self.treename, b"'\n"];
		logv(cb, LogLevel::Debug, &parts);
	}

	// _alpm_db_get_pkgcache_hash: loaded on first use (load_pkgcache)
	fn load_pkgcache(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
	) -> Result<(), Errno> {
		if self.status == Status::Invalid {
			return Err(Errno::DbInvalid);
		}
		if self.pkgcache.is_some() {
			return Ok(());
		}
		self.log_repo(cb, b"loading package cache");
		match self.populate(dbext, cb) {
			Ok(cache) => self.pkgcache = Some(cache),
			Err(e) => {
				self.log_repo(
					cb,
					b"failed to load package cache",
				);
				return Err(e);
			}
		}
		Ok(())
	}

	/// the package cache as loaded so far, None before the first load
	pub fn loaded_pkgcache(&self) -> Option<&PkgHash<Package>> {
		self.pkgcache.as_ref()
	}

	/// alpm_db_get_pkgcache: list order is by name, the table as the
	/// backend filled it. dbext is handle->dbext, read by a sync load
	pub fn pkgcache(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
	) -> Result<&PkgHash<Package>, Errno> {
		self.load_pkgcache(dbext, cb)?;
		Ok(self.pkgcache.as_ref().expect("cache just loaded"))
	}

	/// alpm_db_get_pkg: a cache that cannot load is PkgNotFound too
	pub fn get_pkg(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		name: &[u8],
	) -> Result<&Package, Errno> {
		self.find_pkg(dbext, cb, name).map(|(_, p)| &*p)
	}

	/// alpm_db_get_pkg, then the alpm_pkg_get_* getters reading the
	/// INFRQ_* sections of inforeq: loaded into the cache entry, so
	/// later lookups see them
	pub fn load_pkg(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		name: &[u8],
		inforeq: c_int,
	) -> Result<&Package, Errno> {
		let (backend, pkg) = self.find_pkg(dbext, cb, name)?;
		lazy_load(backend, pkg, inforeq, cb);
		Ok(pkg)
	}

	// _alpm_db_get_pkgfromcache, then _alpm_pkg_dup of the entry
	// (LocalDb::dup_pkg: the force_load into the entry, the copy,
	// whether every section loaded; a sync entry dups as it is)
	pub fn dup_pkg(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		name: &[u8],
	) -> Result<(Package, bool), Errno> {
		let (backend, pkg) = self.find_pkg(dbext, cb, name)?;
		Ok(match backend {
			Backend::Local(local) => local.dup_pkg(pkg, cb),
			Backend::Sync => (pkg.dup(), true),
		})
	}

	/// alpm_db_get_pkg on the local db, then alpm_pkg_set_reason on the
	/// cache entry (its desc rewritten on a change). a sync db is
	/// WrongArgs like a package not from handle->db_local; a missing
	/// package is get_pkg's error
	pub fn set_reason(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		name: &[u8],
		reason: PkgReason,
	) -> Result<(), Errno> {
		let (backend, pkg) = self.find_pkg(dbext, cb, name)?;
		match backend {
			Backend::Local(local) => {
				local.set_reason(pkg, reason, cb)
			}
			Backend::Sync => Err(Errno::WrongArgs),
		}
	}

	/// the cache entry at position i of the list, with the INFRQ_*
	/// sections of inforeq loaded in place. None past the end or when
	/// the cache does not load
	pub fn load_pkg_at(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		i: usize,
		inforeq: c_int,
	) -> Option<&Package> {
		self.load_pkgcache(dbext, cb).ok()?;
		let pkg = self.pkgcache.as_mut()?.at_mut(i)?;
		lazy_load(&self.backend, pkg, inforeq, cb);
		Some(pkg)
	}

	/// alpm_db_get_pkgcache, then the getters of inforeq on every
	/// entry in list order, loaded in place
	pub fn load_all(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		inforeq: c_int,
	) -> Result<&PkgHash<Package>, Errno> {
		self.load_except(dbext, cb, inforeq, &[])
	}

	// load_all over the entries not named in skip: a C loop over
	// alpm_list_diff(cache, targets) calling a getter per package
	pub fn load_except(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		inforeq: c_int,
		skip: &[&[u8]],
	) -> Result<&PkgHash<Package>, Errno> {
		self.load_pkgcache(dbext, cb)?;
		let cache = self.pkgcache.as_mut().expect("cache just loaded");
		for pkg in cache.iter_mut() {
			if !skip.contains(&pkg.name_bytes()) {
				lazy_load(&self.backend, pkg, inforeq, cb);
			}
		}
		Ok(cache)
	}

	/// a C loop over the cache list calling a getter per package: each
	/// entry gets the sections of inforeq loaded just before f sees it
	/// (with its list position), entries after a Break stay untouched.
	/// Ok(None) when f never breaks, Err when the cache does not load
	pub fn walk<B>(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		inforeq: c_int,
		mut f: impl FnMut(usize, &Package) -> ControlFlow<B>,
	) -> Result<Option<B>, Errno> {
		self.load_pkgcache(dbext, cb)?;
		let cache = self.pkgcache.as_mut().expect("cache just loaded");
		for (i, pkg) in cache.iter_mut().enumerate() {
			lazy_load(&self.backend, pkg, inforeq, cb);
			if let ControlFlow::Break(b) = f(i, pkg) {
				return Ok(Some(b));
			}
		}
		Ok(None)
	}

	/// alpm_find_satisfier over the cache list with the getters' loads:
	/// a package matching by name and version is taken as it is, the
	/// others get their desc loaded for the provides. the list position
	/// of the first satisfier
	pub fn find_satisfier(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		depstring: &[u8],
	) -> Option<usize> {
		let dep = dep_from_string(depstring);
		self.load_pkgcache(dbext, cb).ok()?;
		let cache = self.pkgcache.as_mut()?;
		for (i, pkg) in cache.iter_mut().enumerate() {
			if depcmp_literal(pkg, &dep) {
				return Some(i);
			}
			lazy_load(&self.backend, pkg, INFRQ_DESC, cb);
			if depcmp_provides(&dep, &pkg.provides) {
				return Some(i);
			}
		}
		None
	}

	/// the local backend (desc/files/mtree/changelog paths), None for a
	/// sync db
	pub fn local(&self) -> Option<&LocalDb> {
		match &self.backend {
			Backend::Local(local) => Some(local),
			Backend::Sync => None,
		}
	}

	/// _alpm_db_search: the packages matching every needle (AND), in
	/// cache list order. needles are EREs with REG_ICASE|REG_NEWLINE,
	/// the first one that does not compile is InvalidRegex. a db without
	/// DB_USAGE_SEARCH or no needles give nothing, a cache that does not
	/// load an empty list to search (the C returns 0 with the load's
	/// pm_errno left set). each package searched gets its desc loaded
	pub fn search<S: AsRef<[u8]>>(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		needles: &[S],
	) -> Result<Vec<&Package>, Errno> {
		if self.usage & DB_USAGE_SEARCH == 0 {
			return Ok(Vec::new());
		}
		let _ = self.load_pkgcache(dbext, cb);
		if needles.is_empty() {
			return Ok(Vec::new());
		}
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
			let parts: [&[u8]; 3] =
				[b"searching for target '", targ, b"'\n"];
			logv(cb, LogLevel::Debug, &parts);
			let reg = Regex::new(targ, flags)
				.map_err(|_| Errno::InvalidRegex)?;
			list.retain(|&i| {
				let pkg = &mut *pkgs[i];
				lazy_load(&self.backend, pkg, INFRQ_DESC, cb);
				let Some(m) = search_match(&reg, targ, pkg)
				else {
					return false;
				};
				let parts: [&[u8]; 7] = [
					b"search target '",
					targ,
					b"' matched '",
					m,
					b"' on package '",
					pkg.name_bytes(),
					b"'\n",
				];
				logv(cb, LogLevel::Debug, &parts);
				true
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
		cb: &mut dyn Callbacks,
		name: &[u8],
	) -> Result<(&Backend, &mut Package), Errno> {
		let name = until_nul(name);
		if name.is_empty() {
			return Err(Errno::WrongArgs);
		}
		self.load_pkgcache(dbext, cb)
			.map_err(|_| Errno::PkgNotFound)?;
		let cache = self.pkgcache.as_mut().expect("cache just loaded");
		let pkg = cache.find_mut(name).ok_or(Errno::PkgNotFound)?;
		Ok((&self.backend, pkg))
	}

	/// _alpm_db_get_groupcache. load_grpcache marks the group cache
	/// loaded even when the package cache fails: that call returns the
	/// cache's error, later ones an empty list. a later successful load
	/// keeps it (_alpm_db_free_pkgcache does nothing without a package
	/// cache), a failing sync reload drops it (populate frees its table)
	pub fn groupcache(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
	) -> Result<Vec<Group<&Package>>, Errno> {
		if self.status == Status::Invalid {
			return Err(Errno::DbInvalid);
		}
		if self.grpcache.is_none() {
			self.log_repo(cb, b"loading group cache");
			let loaded = self.load_pkgcache(dbext, cb);
			// a failed load leaves no package cache
			let groups = match &mut self.pkgcache {
				Some(c) => build_grpcache(&self.backend, c, cb),
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

	/// alpm_db_get_group: first group of that name. Ok(None) on a miss
	/// (NULL with ALPM_ERR_OK), Err when the group cache failed
	pub fn get_group(
		&mut self,
		dbext: &[u8],
		cb: &mut dyn Callbacks,
		name: &[u8],
	) -> Result<Option<Group<&Package>>, Errno> {
		let name = until_nul(name);
		if name.is_empty() {
			return Err(Errno::WrongArgs);
		}
		let groups = self.groupcache(dbext, cb)?;
		Ok(groups.into_iter().find(|g| g.name == name))
	}

	// "<what> entry '<name>' in|from '<treename>' cache<end>"
	fn log_cache_entry(
		&self,
		cb: &mut dyn Callbacks,
		what: &[u8],
		name: &[u8],
		end: &[u8],
	) {
		let prep: &[u8] = match what {
			b"adding" => b"' in '",
			_ => b"' from '",
		};
		let parts: [&[u8]; 7] = [
			what,
			b" entry '",
			name,
			prep,
			&self.treename,
			b"' cache",
			end,
		];
		logv(cb, LogLevel::Debug, &parts);
	}

	/// _alpm_db_add_pkgincache: a dup() of pkg, origin set to this db,
	/// merged into the list by name (duplicate names are not refused).
	/// the group cache is dropped. the C's force_load before the dup is
	/// not modelled
	pub fn add_pkg_in_cache(
		&mut self,
		cb: &mut dyn Callbacks,
		pkg: &Package,
	) -> Result<(), CacheError> {
		if self.pkgcache.is_none() {
			return Err(CacheError::NotLoaded);
		}
		let mut newpkg = pkg.dup();
		let name =
			until_nul(newpkg.name.as_deref().unwrap_or(b"(null)"));
		self.log_cache_entry(cb, b"adding", name, b"\n");
		newpkg.origin = Some(match self.backend {
			Backend::Local(_) => PkgFrom::LocalDb,
			Backend::Sync => PkgFrom::SyncDb,
		});
		let cache = self.pkgcache.as_mut().expect("checked above");
		cache.add_sorted(newpkg).map_err(|_| CacheError::Memory)?;
		self.free_groupcache(cb);
		Ok(())
	}

	/// _alpm_db_remove_pkgfromcache: the entry with pkg's name and
	/// stored name_hash, handed back where the C frees it
	pub fn remove_pkg_from_cache(
		&mut self,
		cb: &mut dyn Callbacks,
		pkg: &Package,
	) -> Result<Package, CacheError> {
		if self.pkgcache.is_none() {
			return Err(CacheError::NotLoaded);
		}
		let name = until_nul(pkg.name.as_deref().unwrap_or(b"(null)"));
		self.log_cache_entry(cb, b"removing", name, b"\n");
		let cache = self.pkgcache.as_mut().expect("checked above");
		let Some(removed) = cache.remove(pkg) else {
			let end = b": not found\n";
			self.log_cache_entry(cb, b"cannot remove", name, end);
			return Err(CacheError::NotFound);
		};
		self.free_groupcache(cb);
		Ok(removed)
	}

	// free_groupcache: logged only when there is one
	fn free_groupcache(&mut self, cb: &mut dyn Callbacks) {
		if self.grpcache.is_some() {
			self.log_repo(cb, b"freeing group cache");
			self.grpcache = None;
		}
	}

	fn log_free_pkgcache(&self, cb: &mut dyn Callbacks) {
		self.log_repo(cb, b"freeing package cache");
	}

	/// _alpm_db_free_pkgcache: the group cache goes with the package
	/// cache, and stays when there is none
	pub fn free_pkgcache(&mut self, cb: &mut dyn Callbacks) {
		if self.pkgcache.is_none() {
			return;
		}
		self.log_free_pkgcache(cb);
		self.pkgcache = None;
		self.free_groupcache(cb);
	}

	/// _alpm_db_unregister: logged, then _alpm_db_free
	pub fn unregister(mut self, cb: &mut dyn Callbacks) {
		let parts: [&[u8]; 3] =
			[b"unregistering database '", &self.treename, b"'\n"];
		logv(cb, LogLevel::Debug, &parts);
		self.free_pkgcache(cb);
	}
}

/// _alpm_db_cmp: strcmp on the names.
/// only the tests call it, the port's own paths do not
#[cfg_attr(not(feature = "internals"), allow(dead_code))]
pub fn db_cmp(a: &Db, b: &Db) -> Ordering {
	a.treename.cmp(&b.treename)
}
