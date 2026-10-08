// port of lib/libalpm/handle.c with alpm_initialize/alpm_release of
// alpm.c: paths, lists and flags of the handle, the lock, the logfile
// (log.rs), the callbacks, the keyring (signing::Keyring holds gpgdir and
// known_keys), the download state and the registered dbs.
//
// pm_errno is not modelled, calls return the alpm_errno_t as Err (the
// getters' CHECK_HANDLE reset has nothing to reset). RET_ERR's debug
// line (C file and line) is not logged, the option setters' own debug
// lines are. NULL arguments belong to the C ABI layer. alpm_release is
// Drop. not ported: the curl multi handle (reqwest clients are per
// call).
use std::ffi::{OsStr, c_int, c_uint};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use crate::be_local::INFRQ_DESC;
use crate::callbacks::{Callbacks, Fetch, LogLevel};
use crate::db::{Db, SIG_USE_DEFAULT};
use crate::deps::{DepMod, Depend};
use crate::dload::{DownloadState, Downloader, Sandbox, Settings};
use crate::error::Errno;
use crate::log::{Clock, Logger};
use crate::package::{DbCaches, Package};
use crate::sandbox::handle_sandbox;
use crate::signing::Keyring;
use crate::trans::Trans;
use crate::util::{
	CALLER_PREFIX, PATH_MAX, fnmatch_patterns, getuid, hash_sdbm, makepath,
	until_nul,
};

// SYSHOOKDIR of the meson build, appended to root without its '/'
const SYSHOOKDIR: &[u8] = b"/usr/share/libalpm/hooks/";
// getpwnam(3) with the "files" NSS source
const PASSWD: &str = "/etc/passwd";
const ENOENT: i32 = 2;

// what runs a download sandboxed: None where _alpm_use_sandbox fails
pub type SandboxFor = fn(&Handle) -> Option<Box<dyn Sandbox>>;

// alpm_handle_t
pub struct Handle {
	// getuid() at alpm_initialize
	user: u32,
	// sandbox::handle_sandbox, swapped by tests that cannot be root
	sandbox_for: SandboxFor,
	root: Vec<u8>,
	dbpath: Vec<u8>,
	dbext: Vec<u8>,
	architectures: Vec<Vec<u8>>,
	siglevel: c_int,
	localfilesiglevel: c_int,
	remotefilesiglevel: c_int,
	noupgrade: Vec<Vec<u8>>,
	noextract: Vec<Vec<u8>>,
	ignorepkg: Vec<Vec<u8>>,
	ignoregroup: Vec<Vec<u8>>,
	overwrite_files: Vec<Vec<u8>>,
	assumeinstalled: Vec<Depend>,
	cachedirs: Vec<Vec<u8>>,
	hookdirs: Vec<Vec<u8>>,
	lockfile: Vec<u8>,
	// Some is lockfd >= 0
	lock: Option<File>,
	// logfile, logstream, usesyslog
	logger: Logger,
	// gpgdir (empty is NULL), known_keys
	keyring: Keyring,
	sandboxuser: Option<Vec<u8>>,
	disable_sandbox_filesystem: u16,
	disable_sandbox_syscalls: u16,
	checkspace: c_int,
	parallel_downloads: c_uint,
	disable_dl_timeout: u16,
	// server_errors and the dload_interrupted static
	download: DownloadState,
	// logcb, eventcb, questioncb, progresscb, dlcb
	cb: Box<dyn Callbacks>,
	fetch: Option<Box<dyn Fetch>>,
	db_local: Option<Db>,
	// registration order
	dbs_sync: Vec<Db>,
	// handle->trans, None is NULL
	trans: Option<Trans>,
}

// Handle::sync_parts
pub(crate) struct SyncParts<'h> {
	pub(crate) keyring: &'h mut Keyring,
	pub(crate) download: &'h mut DownloadState,
	pub(crate) cb: &'h mut dyn Callbacks,
	pub(crate) fetch: Option<&'h mut dyn Fetch>,
	pub(crate) sandbox: Option<Box<dyn Sandbox>>,
	pub(crate) dbs: &'h mut [Db],
}

// the dbs borrowed with what their calls take from the handle: dbext
// (read by cache loads) and the callbacks db.c logs through
pub struct DbsMut<'h> {
	pub dbext: &'h [u8],
	pub cb: &'h mut dyn Callbacks,
	pub local: Option<&'h mut Db>,
	// registration order
	pub sync: &'h mut [Db],
}

impl fmt::Debug for Handle {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Handle")
			.field("root", &self.root)
			.field("dbpath", &self.dbpath)
			.field("db_local", &self.db_local)
			.field("dbs_sync", &self.dbs_sync)
			.finish_non_exhaustive()
	}
}

// canonicalize_path: '/' appended unless there. the C reads (and may
// write) the byte before an empty path, here "" gives "/"
fn canonicalize_path(path: &[u8]) -> Vec<u8> {
	let mut p = path.to_vec();
	if p.last() != Some(&b'/') {
		p.push(b'/');
	}
	p
}

// _alpm_set_directory_option: with must_exist, stat(2) must see a
// directory (symlinks followed) and realpath(3) resolves it; both fail
// as NotADir. the result ends in '/'
pub fn set_directory_option(
	value: &[u8],
	must_exist: bool,
) -> Result<Vec<u8>, Errno> {
	let path = until_nul(value);
	if !must_exist {
		return Ok(canonicalize_path(path));
	}
	let os = OsStr::from_bytes(path);
	if !fs::metadata(os).is_ok_and(|m| m.is_dir()) {
		return Err(Errno::NotADir);
	}
	let real = fs::canonicalize(os).map_err(|_| Errno::NotADir)?;
	let real = real.as_os_str().as_bytes();
	// realpath into char[PATH_MAX]: ENAMETOOLONG past it
	if real.len() >= PATH_MAX {
		return Err(Errno::NotADir);
	}
	Ok(canonicalize_path(real))
}

// _alpm_option_strlist_rem and alpm_option_remove_architecture: first
// equal entry, true when one was removed (C 1)
fn remove_str(list: &mut Vec<Vec<u8>>, s: &[u8]) -> bool {
	let s = until_nul(s);
	let Some(i) = list.iter().position(|x| x == s) else {
		return false;
	};
	list.remove(i);
	true
}

// two optional C strings: both set and strcmp equal, or both NULL
fn opt_eq(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
	match (a, b) {
		(Some(a), Some(b)) => until_nul(a) == until_nul(b),
		(None, None) => true,
		_ => false,
	}
}

// getpwnam(name) != NULL through the files source: a "name:" line
fn passwd_has(name: &[u8]) -> bool {
	let Ok(passwd) = fs::read(PASSWD) else {
		return false;
	};
	if name.is_empty() {
		return false;
	}
	let mut lines = passwd.split(|&c| c == b'\n');
	lines.any(|l| l.split(|&c| c == b':').next() == Some(name))
}

fn strdup_all<S: AsRef<[u8]>>(list: &[S]) -> Vec<Vec<u8>> {
	list.iter()
		.map(|s| until_nul(s.as_ref()).to_vec())
		.collect()
}

impl Handle {
	// alpm_initialize: root then dbpath must be existing directories,
	// stored resolved with a trailing '/'. dbext starts as ".db", the
	// hookdir is root's SYSHOOKDIR, the lockfile "<dbpath>db.lck". the
	// local db is registered (and created when missing); its failure is
	// the errno be_local reports
	pub fn initialize(root: &[u8], dbpath: &[u8]) -> Result<Handle, Errno> {
		let root = set_directory_option(root, true)?;
		let dbpath = set_directory_option(dbpath, true)?;
		let hookdir = [&root[..], &SYSHOOKDIR[1..]].concat();
		let lockfile = [&dbpath[..], b"db.lck"].concat();
		let local =
			Db::register_local(&dbpath).map_err(|e| e.errno())?;
		Ok(Handle {
			user: getuid(),
			sandbox_for: handle_sandbox,
			root,
			dbpath,
			dbext: b".db".to_vec(),
			architectures: Vec::new(),
			siglevel: 0,
			localfilesiglevel: 0,
			remotefilesiglevel: 0,
			noupgrade: Vec::new(),
			noextract: Vec::new(),
			ignorepkg: Vec::new(),
			ignoregroup: Vec::new(),
			overwrite_files: Vec::new(),
			assumeinstalled: Vec::new(),
			cachedirs: Vec::new(),
			hookdirs: vec![hookdir],
			lockfile,
			lock: None,
			logger: Logger::default(),
			keyring: Keyring::new(b""),
			sandboxuser: None,
			disable_sandbox_filesystem: 0,
			disable_sandbox_syscalls: 0,
			checkspace: 0,
			parallel_downloads: 1,
			disable_dl_timeout: 0,
			download: DownloadState::default(),
			cb: Box::new(()),
			fetch: None,
			db_local: Some(local),
			dbs_sync: Vec::new(),
			trans: None,
		})
	}

	fn debug(&mut self, parts: &[&[u8]]) {
		self.cb.log(LogLevel::Debug, &parts.concat());
	}

	// alpm_option_set_logcb/eventcb/questioncb/progresscb/dlcb at once
	pub fn set_callbacks(&mut self, cb: Box<dyn Callbacks>) {
		self.cb = cb;
	}

	pub fn callbacks(&mut self) -> &mut dyn Callbacks {
		&mut *self.cb
	}

	// f with the callbacks lent out next to the handle, for calls that
	// read the handle while they log, ask or send events. the handle's
	// own logging inside f goes nowhere
	pub fn with_callbacks<R>(
		&mut self,
		f: impl FnOnce(&mut Handle, &mut dyn Callbacks) -> R,
	) -> R {
		let mut cb = std::mem::replace(&mut self.cb, Box::new(()));
		let r = f(self, &mut *cb);
		self.cb = cb;
		r
	}

	// handle->trans
	pub fn trans(&self) -> Option<&Trans> {
		self.trans.as_ref()
	}

	pub fn trans_mut(&mut self) -> Option<&mut Trans> {
		self.trans.as_mut()
	}

	// handle->trans = trans, the old one returned
	pub fn set_trans(&mut self, trans: Option<Trans>) -> Option<Trans> {
		std::mem::replace(&mut self.trans, trans)
	}

	// set_callbacks giving the old set back, for a caller that swaps
	// them for one call
	pub fn replace_callbacks(
		&mut self,
		cb: Box<dyn Callbacks>,
	) -> Box<dyn Callbacks> {
		std::mem::replace(&mut self.cb, cb)
	}

	// what alpm_db_update works on at once, borrowed apart
	pub(crate) fn sync_parts(&mut self) -> SyncParts<'_> {
		let sandbox = (self.sandbox_for)(self);
		SyncParts {
			keyring: &mut self.keyring,
			download: &mut self.download,
			cb: &mut *self.cb,
			fetch: self.fetch.as_deref_mut().map(|f| f as _),
			sandbox,
			dbs: &mut self.dbs_sync,
		}
	}

	// alpm_option_set_fetchcb, None is the built-in downloader
	pub fn set_fetchcb(&mut self, fetch: Option<Box<dyn Fetch>>) {
		self.fetch = fetch;
	}

	// alpm_logaction
	pub fn logaction(
		&mut self,
		prefix: &[u8],
		msg: &[u8],
	) -> Result<(), Errno> {
		self.logger.logaction(prefix, msg)
	}

	// the clock logfile and syslog lines are stamped with
	pub fn set_log_clock(&mut self, clock: Clock) {
		self.logger.set_clock(clock);
	}

	// alpm_option_get_logfile
	pub fn logfile(&self) -> Option<&[u8]> {
		self.logger.logfile()
	}

	// alpm_option_set_logfile: the open stream closes
	pub fn set_logfile(&mut self, logfile: &[u8]) {
		self.logger.set_logfile(logfile);
		let f = self.logger.logfile().unwrap_or_default().to_vec();
		self.debug(&[b"option 'logfile' = ", &f, b"\n"]);
	}

	// alpm_option_get_usesyslog
	pub fn usesyslog(&self) -> c_int {
		self.logger.usesyslog()
	}

	pub fn set_usesyslog(&mut self, usesyslog: c_int) {
		self.logger.set_usesyslog(usesyslog);
	}

	// alpm_option_get_lockfile
	pub fn lockfile(&self) -> &[u8] {
		&self.lockfile
	}

	// _alpm_handle_lock: the lockfile's directory made first, then
	// created exclusively (mode 0000). Ok when this handle holds it
	// already; Err keeps errno for the caller's HANDLE_LOCK message
	pub fn lock(&mut self) -> io::Result<()> {
		if self.lock.is_some() {
			return Ok(());
		}
		let lockfile = &self.lockfile;
		let dir = match lockfile.iter().rposition(|&c| c == b'/') {
			Some(i) => &lockfile[..i],
			None => &lockfile[..],
		};
		makepath(dir)?;
		let f = OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o000)
			.open(OsStr::from_bytes(lockfile))?;
		self.lock = Some(f);
		Ok(())
	}

	// whether this handle holds the lock
	pub fn is_locked(&self) -> bool {
		self.lock.is_some()
	}

	// alpm_unlock: closes and unlinks the lockfile, Ok without the lock.
	// Err is ALPM_ERR_SYSTEM with unlink's errno
	pub fn unlock(&mut self) -> io::Result<()> {
		if self.lock.take().is_none() {
			return Ok(());
		}
		fs::remove_file(OsStr::from_bytes(&self.lockfile))
	}

	// _alpm_handle_unlock: a lockfile gone already is a warning only,
	// false (C -1) when it could not be removed
	pub fn handle_unlock(&mut self) -> bool {
		let Err(e) = self.unlock() else {
			return true;
		};
		let missing = e.raw_os_error() == Some(ENOENT);
		let what: &[u8] = match missing {
			true => b"lock file missing ",
			false => b"could not remove lock file ",
		};
		let lockfile = self.lockfile.clone();
		let msg = [what, &lockfile, b"\n"].concat();
		self.cb.log(LogLevel::Warning, &msg);
		let _ = self.logger.logaction(
			CALLER_PREFIX,
			&[b"warning: ", &msg[..]].concat(),
		);
		missing
	}

	// alpm_option_get_cachedirs
	pub fn cachedirs(&self) -> &[Vec<u8>] {
		&self.cachedirs
	}

	// alpm_option_add_cachedir: canonicalized, not stat'ed until used
	pub fn add_cachedir(&mut self, cachedir: &[u8]) {
		let dir = canonicalize_path(until_nul(cachedir));
		self.debug(&[b"option 'cachedir' = ", &dir, b"\n"]);
		self.cachedirs.push(dir);
	}

	pub fn set_cachedirs<S: AsRef<[u8]>>(&mut self, dirs: &[S]) {
		self.cachedirs.clear();
		for d in dirs {
			self.add_cachedir(d.as_ref());
		}
	}

	// alpm_option_remove_cachedir: canonicalized first, true when removed
	pub fn remove_cachedir(&mut self, cachedir: &[u8]) -> bool {
		let dir = canonicalize_path(until_nul(cachedir));
		remove_str(&mut self.cachedirs, &dir)
	}

	// alpm_option_get_hookdirs
	pub fn hookdirs(&self) -> &[Vec<u8>] {
		&self.hookdirs
	}

	pub fn add_hookdir(&mut self, hookdir: &[u8]) {
		let dir = canonicalize_path(until_nul(hookdir));
		self.debug(&[b"option 'hookdir' = ", &dir, b"\n"]);
		self.hookdirs.push(dir);
	}

	pub fn set_hookdirs<S: AsRef<[u8]>>(&mut self, dirs: &[S]) {
		self.hookdirs.clear();
		for d in dirs {
			self.add_hookdir(d.as_ref());
		}
	}

	pub fn remove_hookdir(&mut self, hookdir: &[u8]) -> bool {
		let dir = canonicalize_path(until_nul(hookdir));
		remove_str(&mut self.hookdirs, &dir)
	}

	// alpm_option_get_gpgdir, None until set
	pub fn gpgdir(&self) -> Option<&[u8]> {
		Some(self.keyring.gpgdir()).filter(|g| !g.is_empty())
	}

	// alpm_option_set_gpgdir: _alpm_set_directory_option without the
	// existence check, the keyring keeps its known keys
	pub fn set_gpgdir(&mut self, gpgdir: &[u8]) {
		let dir = canonicalize_path(until_nul(gpgdir));
		self.keyring.set_gpgdir(&dir);
		self.debug(&[b"option 'gpgdir' = ", &dir, b"\n"]);
	}

	pub fn keyring(&self) -> &Keyring {
		&self.keyring
	}

	pub fn keyring_mut(&mut self) -> &mut Keyring {
		&mut self.keyring
	}

	// alpm_option_get_sandboxuser
	pub fn sandboxuser(&self) -> Option<&[u8]> {
		self.sandboxuser.as_deref()
	}

	// alpm_option_set_sandboxuser: the old user goes first, a name
	// getpwnam does not know leaves none and gives false (C 1)
	pub fn set_sandboxuser(&mut self, user: Option<&[u8]>) -> bool {
		self.sandboxuser = None;
		let user = user.map(until_nul);
		if let Some(u) = user
			&& !passwd_has(u)
		{
			let msg = [b"'sandboxuser' (", u, b") does not exist"];
			self.debug(&msg);
			return false;
		}
		self.sandboxuser = user.map(<[u8]>::to_vec);
		// printf("%s", NULL) is "(null)" in glibc
		let shown = user.unwrap_or(b"(null)").to_vec();
		self.debug(&[b"option 'sandboxuser' = ", &shown, b"\n"]);
		true
	}

	// alpm_option_get_disable_sandbox: 2 both restrictions off, 1 one
	pub fn disable_sandbox(&self) -> c_int {
		let fs = self.disable_sandbox_filesystem != 0;
		let sc = self.disable_sandbox_syscalls != 0;
		c_int::from(fs) + c_int::from(sc)
	}

	pub fn set_disable_sandbox(&mut self, disable: u16) {
		self.disable_sandbox_filesystem = disable;
		self.disable_sandbox_syscalls = disable;
	}

	pub fn disable_sandbox_filesystem(&self) -> u16 {
		self.disable_sandbox_filesystem
	}

	pub fn set_disable_sandbox_filesystem(&mut self, disable: u16) {
		self.disable_sandbox_filesystem = disable;
	}

	pub fn disable_sandbox_syscalls(&self) -> u16 {
		self.disable_sandbox_syscalls
	}

	pub fn set_disable_sandbox_syscalls(&mut self, disable: u16) {
		self.disable_sandbox_syscalls = disable;
	}

	// alpm_option_get_checkspace
	pub fn checkspace(&self) -> c_int {
		self.checkspace
	}

	pub fn set_checkspace(&mut self, checkspace: c_int) {
		self.checkspace = checkspace;
	}

	// alpm_option_get_parallel_downloads
	pub fn parallel_downloads(&self) -> c_uint {
		self.parallel_downloads
	}

	// alpm_option_set_parallel_downloads: 0 is WrongArgs
	pub fn set_parallel_downloads(
		&mut self,
		n: c_uint,
	) -> Result<(), Errno> {
		if n < 1 {
			return Err(Errno::WrongArgs);
		}
		self.parallel_downloads = n;
		Ok(())
	}

	// alpm_option_get_disable_dl_timeout
	pub fn disable_dl_timeout(&self) -> u16 {
		self.disable_dl_timeout
	}

	pub fn set_disable_dl_timeout(&mut self, disable: u16) {
		self.disable_dl_timeout = disable;
	}

	// the options dload reads, as they are now
	pub fn dload_settings(&self) -> Settings {
		Settings {
			parallel_downloads: self.parallel_downloads,
			disable_dl_timeout: self.disable_dl_timeout != 0,
			dbext: self.dbext.clone(),
		}
	}

	pub fn download_state(&self) -> &DownloadState {
		&self.download
	}

	// handle->user
	pub fn user(&self) -> u32 {
		self.user
	}

	// how downloads get their sandbox (sandbox::handle_sandbox), for
	// tests standing in for root
	pub fn set_sandbox_for(&mut self, f: SandboxFor) {
		self.sandbox_for = f;
	}

	// f with a Downloader on the handle's download settings, state,
	// callbacks, fetchcb and sandbox, next to the cachedirs
	pub(crate) fn with_downloader<R>(
		&mut self,
		f: impl FnOnce(&mut Downloader, &mut Vec<Vec<u8>>) -> R,
	) -> R {
		let settings = self.dload_settings();
		let mut sandbox = (self.sandbox_for)(self);
		let mut dl = Downloader {
			settings: &settings,
			state: &mut self.download,
			cb: &mut *self.cb,
			fetch: self.fetch.as_deref_mut().map(|f| f as _),
			sandbox: sandbox.as_deref_mut().map(|s| s as _),
		};
		f(&mut dl, &mut self.cachedirs)
	}

	// alpm_fetch_pkgurl with the remote file siglevel
	pub fn fetch_pkgurl<U: AsRef<[u8]>>(
		&mut self,
		urls: &[U],
	) -> Result<Vec<Vec<u8>>, Errno> {
		let siglevel = self.remote_file_siglevel();
		self.with_downloader(|dl, cachedirs| {
			dl.fetch_pkgurl(cachedirs, siglevel, urls)
		})
	}

	// alpm_option_get_overwrite_files and friends, like noupgrade
	pub fn overwrite_files(&self) -> &[Vec<u8>] {
		&self.overwrite_files
	}

	pub fn add_overwrite_file(&mut self, glob: &[u8]) {
		self.overwrite_files.push(until_nul(glob).to_vec());
	}

	pub fn set_overwrite_files<S: AsRef<[u8]>>(&mut self, globs: &[S]) {
		self.overwrite_files = strdup_all(globs);
	}

	pub fn remove_overwrite_file(&mut self, glob: &[u8]) -> bool {
		remove_str(&mut self.overwrite_files, glob)
	}

	// alpm_option_get_assumeinstalled
	pub fn assumeinstalled(&self) -> &[Depend] {
		&self.assumeinstalled
	}

	// alpm_option_add_assumeinstalled: only "name" and "name=version",
	// name_hash recomputed for hand-built deps
	pub fn add_assumeinstalled(
		&mut self,
		dep: &Depend,
	) -> Result<(), Errno> {
		if !matches!(dep.depmod, DepMod::Eq | DepMod::Any) {
			return Err(Errno::WrongArgs);
		}
		let mut dep = dep.clone();
		dep.name_hash = hash_sdbm(&dep.name);
		self.assumeinstalled.push(dep);
		Ok(())
	}

	// alpm_option_set_assumeinstalled: a refused dep stops the copy,
	// the ones before it stay
	pub fn set_assumeinstalled(
		&mut self,
		deps: &[Depend],
	) -> Result<(), Errno> {
		self.assumeinstalled.clear();
		deps.iter().try_for_each(|d| self.add_assumeinstalled(d))
	}

	// alpm_option_remove_assumeinstalled: first entry with dep's
	// name_hash (as given) and name, and the same version or none on
	// both. true when removed
	pub fn remove_assumeinstalled(&mut self, dep: &Depend) -> bool {
		let same = |d: &Depend| {
			d.name_hash == dep.name_hash
				&& until_nul(&d.name) == until_nul(&dep.name)
				&& opt_eq(&d.version, &dep.version)
		};
		let Some(i) = self.assumeinstalled.iter().position(same) else {
			return false;
		};
		self.assumeinstalled.remove(i);
		true
	}

	// alpm_option_get_root
	pub fn root(&self) -> &[u8] {
		&self.root
	}

	// alpm_option_get_dbpath
	pub fn dbpath(&self) -> &[u8] {
		&self.dbpath
	}

	// alpm_option_get_dbext
	pub fn dbext(&self) -> &[u8] {
		&self.dbext
	}

	// alpm_option_set_dbext: dbs registered later use it, registered
	// ones keep their path
	pub fn set_dbext(&mut self, dbext: &[u8]) {
		self.dbext = until_nul(dbext).to_vec();
		let dbext = self.dbext.clone();
		self.debug(&[b"option 'dbext' = ", &dbext, b"\n"]);
	}

	// alpm_get_localdb: None after unregister_localdb
	pub fn localdb(&self) -> Option<&Db> {
		self.db_local.as_ref()
	}

	pub fn localdb_mut(&mut self) -> Option<&mut Db> {
		self.db_local.as_mut()
	}

	// alpm_get_syncdbs
	pub fn syncdbs(&self) -> &[Db] {
		&self.dbs_sync
	}

	pub fn syncdbs_mut(&mut self) -> &mut [Db] {
		&mut self.dbs_sync
	}

	// the local db and the sync dbs borrowed together, with dbext and
	// the callbacks
	pub fn dbs_mut(&mut self) -> DbsMut<'_> {
		DbsMut {
			dbext: &self.dbext,
			cb: &mut *self.cb,
			local: self.db_local.as_mut(),
			sync: &mut self.dbs_sync,
		}
	}

	// alpm_register_syncdb: an empty name or one with '/' is WrongArgs,
	// "local" and registered names DbNotNull. validated, then appended
	// to the sync dbs
	pub fn register_syncdb(
		&mut self,
		treename: &[u8],
		siglevel: c_int,
	) -> Result<&mut Db, Errno> {
		let treename = until_nul(treename);
		if treename.is_empty() || treename.contains(&b'/') {
			return Err(Errno::WrongArgs);
		}
		if treename == b"local"
			|| self.dbs_sync.iter().any(|d| d.name() == treename)
		{
			return Err(Errno::DbNotNull);
		}
		let db = Db::register_sync(
			&self.dbpath,
			&self.dbext,
			treename,
			siglevel,
			self.siglevel,
			&mut self.keyring,
			&mut *self.cb,
		);
		self.dbs_sync.push(db);
		Ok(self.dbs_sync.last_mut().expect("just pushed"))
	}

	// alpm_unregister_all_syncdbs
	pub fn unregister_all_syncdbs(&mut self) {
		for db in std::mem::take(&mut self.dbs_sync) {
			db.unregister(&mut *self.cb);
		}
	}

	// alpm_db_unregister on the local db. DbNotFound once gone (the C
	// would need a freed pointer)
	pub fn unregister_localdb(&mut self) -> Result<(), Errno> {
		let db = self.db_local.take().ok_or(Errno::DbNotFound)?;
		db.unregister(&mut *self.cb);
		Ok(())
	}

	// alpm_db_unregister on a sync db, found by name like _alpm_db_cmp
	pub fn unregister_syncdb(
		&mut self,
		treename: &[u8],
	) -> Result<(), Errno> {
		let treename = until_nul(treename);
		let i = self.dbs_sync.iter().position(|d| d.name() == treename);
		let i = i.ok_or(Errno::DbNotFound)?;
		self.dbs_sync.remove(i).unregister(&mut *self.cb);
		Ok(())
	}

	// alpm_option_get_architectures
	pub fn architectures(&self) -> &[Vec<u8>] {
		&self.architectures
	}

	// alpm_option_add_architecture
	pub fn add_architecture(&mut self, arch: &[u8]) {
		self.architectures.push(until_nul(arch).to_vec());
	}

	// alpm_option_set_architectures
	pub fn set_architectures<S: AsRef<[u8]>>(&mut self, arches: &[S]) {
		self.architectures = strdup_all(arches);
	}

	// alpm_option_remove_architecture: true when removed
	pub fn remove_architecture(&mut self, arch: &[u8]) -> bool {
		remove_str(&mut self.architectures, arch)
	}

	// alpm_option_get_default_siglevel
	pub fn default_siglevel(&self) -> c_int {
		self.siglevel
	}

	// alpm_option_set_default_siglevel: exactly ALPM_SIG_USE_DEFAULT is
	// WrongArgs. gpgme builds store any other level
	pub fn set_default_siglevel(
		&mut self,
		level: c_int,
	) -> Result<(), Errno> {
		if level == SIG_USE_DEFAULT {
			return Err(Errno::WrongArgs);
		}
		self.siglevel = level;
		Ok(())
	}

	// alpm_option_get_local_file_siglevel: ALPM_SIG_USE_DEFAULT anywhere
	// in the level gives the default
	pub fn local_file_siglevel(&self) -> c_int {
		match self.localfilesiglevel & SIG_USE_DEFAULT {
			0 => self.localfilesiglevel,
			_ => self.siglevel,
		}
	}

	pub fn set_local_file_siglevel(&mut self, level: c_int) {
		self.localfilesiglevel = level;
	}

	// alpm_option_get_remote_file_siglevel
	pub fn remote_file_siglevel(&self) -> c_int {
		match self.remotefilesiglevel & SIG_USE_DEFAULT {
			0 => self.remotefilesiglevel,
			_ => self.siglevel,
		}
	}

	pub fn set_remote_file_siglevel(&mut self, level: c_int) {
		self.remotefilesiglevel = level;
	}

	// alpm_option_get_noupgrades and friends: add appends a copy, set
	// replaces with copies, remove drops the first equal entry (true
	// when removed, C 1)
	pub fn noupgrades(&self) -> &[Vec<u8>] {
		&self.noupgrade
	}

	pub fn add_noupgrade(&mut self, pkg: &[u8]) {
		self.noupgrade.push(until_nul(pkg).to_vec());
	}

	pub fn set_noupgrades<S: AsRef<[u8]>>(&mut self, list: &[S]) {
		self.noupgrade = strdup_all(list);
	}

	pub fn remove_noupgrade(&mut self, pkg: &[u8]) -> bool {
		remove_str(&mut self.noupgrade, pkg)
	}

	// alpm_option_match_noupgrade: _alpm_fnmatch_patterns, None is -1
	pub fn match_noupgrade(&self, path: &[u8]) -> Option<bool> {
		fnmatch_patterns(&self.noupgrade, path)
	}

	pub fn noextracts(&self) -> &[Vec<u8>] {
		&self.noextract
	}

	pub fn add_noextract(&mut self, path: &[u8]) {
		self.noextract.push(until_nul(path).to_vec());
	}

	pub fn set_noextracts<S: AsRef<[u8]>>(&mut self, list: &[S]) {
		self.noextract = strdup_all(list);
	}

	pub fn remove_noextract(&mut self, path: &[u8]) -> bool {
		remove_str(&mut self.noextract, path)
	}

	pub fn match_noextract(&self, path: &[u8]) -> Option<bool> {
		fnmatch_patterns(&self.noextract, path)
	}

	pub fn ignorepkgs(&self) -> &[Vec<u8>] {
		&self.ignorepkg
	}

	pub fn add_ignorepkg(&mut self, pkg: &[u8]) {
		self.ignorepkg.push(until_nul(pkg).to_vec());
	}

	pub fn set_ignorepkgs<S: AsRef<[u8]>>(&mut self, list: &[S]) {
		self.ignorepkg = strdup_all(list);
	}

	pub fn remove_ignorepkg(&mut self, pkg: &[u8]) -> bool {
		remove_str(&mut self.ignorepkg, pkg)
	}

	pub fn ignoregroups(&self) -> &[Vec<u8>] {
		&self.ignoregroup
	}

	pub fn add_ignoregroup(&mut self, grp: &[u8]) {
		self.ignoregroup.push(until_nul(grp).to_vec());
	}

	pub fn set_ignoregroups<S: AsRef<[u8]>>(&mut self, list: &[S]) {
		self.ignoregroup = strdup_all(list);
	}

	pub fn remove_ignoregroup(&mut self, grp: &[u8]) -> bool {
		remove_str(&mut self.ignoregroup, grp)
	}
}

// the caches compute_requiredby/optionalfor walk: alpm_db_get_pkgcache,
// with alpm_pkg_get_depends/optdepends loading each local desc in place.
// a db whose cache does not load (or no local db) gives an empty list
impl DbCaches for Handle {
	fn local_cache(&mut self) -> Vec<&Package> {
		let Some(db) = &mut self.db_local else {
			return Vec::new();
		};
		match db.load_all(&self.dbext, &mut *self.cb, INFRQ_DESC) {
			Ok(cache) => cache.iter().collect(),
			Err(_) => Vec::new(),
		}
	}

	fn sync_caches(&mut self) -> Vec<Vec<&Package>> {
		let (dbext, cb) = (&self.dbext, &mut *self.cb);
		let caches = self.dbs_sync.iter_mut().map(|db| {
			db.pkgcache(dbext, cb)
				.map(|c| c.iter().collect())
				.unwrap_or_default()
		});
		caches.collect()
	}
}

// alpm_release: the lock goes with the handle, then the local and the
// sync dbs are unregistered. the logfile stream and the syslog
// connection close with the Logger
impl Drop for Handle {
	fn drop(&mut self) {
		self.handle_unlock();
		let _ = self.unregister_localdb();
		self.unregister_all_syncdbs();
	}
}
