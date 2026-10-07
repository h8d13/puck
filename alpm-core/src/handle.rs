// port of the part of lib/libalpm/handle.c milestone 1 needs, plus
// alpm_initialize/alpm_release of alpm.c: root, dbpath, dbext,
// architectures, siglevels, the ignore/noupgrade/noextract lists and the
// registered dbs.
//
// pm_errno is not modelled, calls return the alpm_errno_t as Err (the
// getters' CHECK_HANDLE reset has nothing to reset). alpm_release is
// Drop. not ported: callbacks, logging and logfile, the lock, cachedirs,
// hookdirs, gpgdir, sandbox options, downloads (parallel_downloads,
// dl timeout), checkspace, usesyslog, overwrite_files, assumeinstalled,
// transactions. the fields alpm_initialize sets only for those (hookdir,
// lockfile, user, curl, parallel_downloads) are left out with them.

use std::ffi::{OsStr, c_int};
use std::fs;
use std::os::unix::ffi::OsStrExt;

use crate::db::{Db, SIG_USE_DEFAULT};
use crate::error::Errno;
use crate::util::{fnmatch_patterns, until_nul};

// limits.h on linux, the realpath buffer of _alpm_set_directory_option
const PATH_MAX: usize = 4096;

// alpm_handle_t
#[derive(Clone, Debug)]
pub struct Handle {
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
	db_local: Option<Db>,
	// registration order
	dbs_sync: Vec<Db>,
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

fn strdup_all<S: AsRef<[u8]>>(list: &[S]) -> Vec<Vec<u8>> {
	list.iter()
		.map(|s| until_nul(s.as_ref()).to_vec())
		.collect()
}

impl Handle {
	// alpm_initialize: root then dbpath must be existing directories,
	// stored resolved with a trailing '/'. dbext starts as ".db". the
	// local db is registered (and created when missing); its failure is
	// the errno be_local reports
	pub fn initialize(root: &[u8], dbpath: &[u8]) -> Result<Handle, Errno> {
		let root = set_directory_option(root, true)?;
		let dbpath = set_directory_option(dbpath, true)?;
		let local =
			Db::register_local(&dbpath).map_err(|e| e.errno())?;
		Ok(Handle {
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
			db_local: Some(local),
			dbs_sync: Vec::new(),
		})
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

	// alpm_register_syncdb: an empty name or one with '/' is WrongArgs,
	// "local" and registered names DbNotNull. appended to the sync dbs
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
		);
		self.dbs_sync.push(db);
		Ok(self.dbs_sync.last_mut().expect("just pushed"))
	}

	// alpm_unregister_all_syncdbs
	pub fn unregister_all_syncdbs(&mut self) {
		self.dbs_sync.clear();
	}

	// alpm_db_unregister on the local db. DbNotFound once gone (the C
	// would need a freed pointer)
	pub fn unregister_localdb(&mut self) -> Result<(), Errno> {
		self.db_local.take().map(drop).ok_or(Errno::DbNotFound)
	}

	// alpm_db_unregister on a sync db, found by name like _alpm_db_cmp
	pub fn unregister_syncdb(
		&mut self,
		treename: &[u8],
	) -> Result<(), Errno> {
		let treename = until_nul(treename);
		let i = self.dbs_sync.iter().position(|d| d.name() == treename);
		let i = i.ok_or(Errno::DbNotFound)?;
		self.dbs_sync.remove(i);
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
