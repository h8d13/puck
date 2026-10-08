// port of lib/libalpm/trans.c: the transaction model (alpm_trans_t in
// Handle::trans), alpm_trans_init/prepare/interrupt/release and the
// getters, _alpm_runscriptlet with its grep helper.
//
// alpm_trans_commit runs a prepared transaction (STATE_PREPARED,
// add/remove sorted, download sizes and oldpkgs set) through sync.rs
// (load, check, commit) or remove.rs, between the transaction hooks.
// the C's trans->add holds pointers into
// the sync caches and mutates them (reason, removes, oldpkg,
// download_size); here every target is an owned TransPkg copy, so the
// caches stay as loaded; the commit replaces sync targets by their
// loaded package files like the C. pm_errno comes back as Err, the data
// lists of alpm_trans_prepare/commit as PrepareData/CommitData.

use std::collections::hash_map::RandomState;
use std::ffi::c_int;
use std::fs::{self, DirBuilder, File};
use std::hash::{BuildHasher, Hasher};
use std::io::{BufReader, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use pacman_common::util_common::safe_fgets;
use rustix::fs::Access;

use crate::be_local::{INFRQ_ALL, INFRQ_DESC};
use crate::callbacks::{Callbacks, Event, HookWhen, LogLevel, logv};
use crate::conflict::{Conflict, FileConflict};
use crate::db::{DB_USAGE_INSTALL, DB_USAGE_UPGRADE};
use crate::deps::{DbPkgs, DepMissing, DepsEnv, sortbydeps};
use crate::error::Errno;
use crate::handle::Handle;
use crate::hook::{AddTarget, Targets, hook_run};
use crate::package::Package;
use crate::pkghash::PkgHash;
use crate::util::{
	CALLER_PREFIX, PATH_MAX, SCRIPTLET_SHELL, alpm_access, copyfile,
	makepath_mode, run_chroot, strerror, unpack_single, until_nul,
};
use crate::{remove, sync};

fn os(path: &[u8]) -> &Path {
	Path::new(std::ffi::OsStr::from_bytes(until_nul(path)))
}

// grep (static in C): needle in a chunk of the file read like
// safe_fgets(line, 1024), cut at its first nul and first '#'. a needle
// split over two chunks is missed like in the C. a read error ends the
// search (the C's feof loop would spin on it)
fn grep(path: &[u8], needle: &[u8]) -> bool {
	let Ok(f) = File::open(os(path)) else {
		return false;
	};
	let needle = until_nul(needle);
	let mut r = BufReader::new(f);
	while let Ok(Some(chunk)) = safe_fgets(&mut r, 1024) {
		let line = until_nul(&chunk);
		let line = match line.iter().position(|&c| c == b'#') {
			Some(i) => &line[..i],
			None => line,
		};
		if needle.is_empty()
			|| line.windows(needle.len()).any(|w| w == needle)
		{
			return true;
		}
	}
	false
}

// mkdtemp(3): template ending in "XXXXXX", made mode 0700 with the X's
// replaced by letters and digits, retried while the name exists
fn mkdtemp(template: &[u8]) -> Option<Vec<u8>> {
	const CHARS: &[u8] =
		b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	let stem = template.strip_suffix(b"XXXXXX")?;
	// glibc's TMP_MAX attempts
	for _ in 0..238_328 {
		let mut h = RandomState::new().build_hasher();
		h.write(stem);
		let mut v = h.finish();
		let mut path = stem.to_vec();
		for _ in 0..6 {
			path.push(CHARS[(v % CHARS.len() as u64) as usize]);
			v /= CHARS.len() as u64;
		}
		match DirBuilder::new().mode(0o700).create(os(&path)) {
			Ok(()) => return Some(path),
			Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
			Err(_) => return None,
		}
	}
	None
}

// _alpm_access(NULL, path, R_OK) == 0
pub(crate) fn readable(path: &[u8], cb: &mut dyn Callbacks) -> bool {
	alpm_access(cb, None, path, Access::READ_OK).is_ok()
}

// _alpm_runscriptlet: runs `. <copy>; <script> <ver> [<oldver>]` with
// SCRIPTLET_SHELL -c under handle->root (with its trailing '/'), the copy being
// filepath (or its .INSTALL entry when is_archive) placed in a fresh
// root/tmp/alpm_XXXXXX. a missing filepath or a script name that does
// not appear in it runs nothing. true unless something failed (C 0)
pub fn runscriptlet(
	h: &mut Handle,
	filepath: &[u8],
	script: &[u8],
	ver: &[u8],
	oldver: Option<&[u8]>,
	is_archive: bool,
) -> bool {
	// the callbacks borrow the handle mutably
	let root = h.root().to_vec();
	let (root, filepath) = (&root[..], until_nul(filepath));
	let (script, ver) = (until_nul(script), until_nul(ver));
	if !readable(filepath, h.callbacks()) {
		logv(
			h.callbacks(),
			LogLevel::Debug,
			&[b"scriptlet '", filepath, b"' not found\n"],
		);
		return true;
	}
	// only a plain file can be checked before it is copied
	if !is_archive && !grep(filepath, script) {
		return true;
	}

	let tmp = [root, b"tmp/"].concat();
	if !os(&tmp).exists() {
		let _ = makepath_mode(&tmp, 0o1777);
	}
	let Some(tmpdir) = mkdtemp(&[root, b"tmp/alpm_XXXXXX"].concat()) else {
		let msg = b"could not create temp directory\n";
		h.callbacks().log(LogLevel::Error, msg);
		return false;
	};
	let scriptfn = [&tmpdir[..], b"/.INSTALL"].concat();
	let mut ok = if is_archive {
		unpack_single(h.callbacks(), filepath, &tmpdir, b".INSTALL")
			.is_ok()
	} else if let Err(e) = copyfile(filepath, &scriptfn) {
		logv(
			h.callbacks(),
			LogLevel::Error,
			&[
				b"could not copy tempfile to ",
				&scriptfn,
				b" (",
				&strerror(&e),
				b")\n",
			],
		);
		false
	} else {
		true
	};

	if ok && (!is_archive || grep(&scriptfn, script)) {
		// the tmpdir as seen inside the chroot
		let scriptpath = &scriptfn[root.len().saturating_sub(1)..];
		let mut cmdline =
			[b". ", scriptpath, b"; ", script, b" ", ver].concat();
		if let Some(old) = oldver {
			cmdline.extend_from_slice(b" ");
			cmdline.extend_from_slice(until_nul(old));
		}
		// snprintf into char[PATH_MAX]
		cmdline.truncate(PATH_MAX - 1);
		logv(
			h.callbacks(),
			LogLevel::Debug,
			&[b"executing \"", &cmdline, b"\"\n"],
		);
		let argv: [&[u8]; 3] = [SCRIPTLET_SHELL, b"-c", &cmdline];
		ok = run_chroot(h, Some(SCRIPTLET_SHELL), &argv, None);
	}

	if fs::remove_file(os(&scriptfn)).is_err() {
		logv(
			h.callbacks(),
			LogLevel::Warning,
			&[b"could not remove ", &scriptfn, b"\n"],
		);
	}
	if fs::remove_dir(os(&tmpdir)).is_err() {
		logv(
			h.callbacks(),
			LogLevel::Warning,
			&[b"could not remove tmpdir ", &tmpdir, b"\n"],
		);
	}
	ok
}

// alpm_transflag_t
pub const TRANS_FLAG_NODEPS: c_int = 1;
pub const TRANS_FLAG_NOSAVE: c_int = 1 << 2;
pub const TRANS_FLAG_NODEPVERSION: c_int = 1 << 3;
pub const TRANS_FLAG_CASCADE: c_int = 1 << 4;
pub const TRANS_FLAG_RECURSE: c_int = 1 << 5;
pub const TRANS_FLAG_DBONLY: c_int = 1 << 6;
pub const TRANS_FLAG_NOHOOKS: c_int = 1 << 7;
pub const TRANS_FLAG_ALLDEPS: c_int = 1 << 8;
pub const TRANS_FLAG_DOWNLOADONLY: c_int = 1 << 9;
pub const TRANS_FLAG_NOSCRIPTLET: c_int = 1 << 10;
pub const TRANS_FLAG_NOCONFLICTS: c_int = 1 << 11;
pub const TRANS_FLAG_NEEDED: c_int = 1 << 13;
pub const TRANS_FLAG_ALLEXPLICIT: c_int = 1 << 14;
pub const TRANS_FLAG_UNNEEDED: c_int = 1 << 15;
pub const TRANS_FLAG_RECURSEALL: c_int = 1 << 16;
pub const TRANS_FLAG_NOLOCK: c_int = 1 << 17;

// alpm_transstate_t
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransState {
	Idle,
	Initialized,
	Prepared,
	Downloading,
	Committing,
	Committed,
	Interrupted,
}

// a package of trans->add (or unresolvable) with the alpm_pkg_t fields
// only transactions use
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransPkg {
	pub pkg: Package,
	// origin_data.db of a sync package: its position in
	// Handle::syncdbs(). None for file packages
	pub db: Option<usize>,
	// pkg->removes: local packages this one replaces or conflicts
	// with, elected for removal
	pub removes: Vec<Package>,
	// pkg->oldpkg: dup of the installed package of the same name, set
	// by a successful sync prepare
	pub oldpkg: Option<Package>,
}

impl TransPkg {
	pub fn new(pkg: Package, db: Option<usize>) -> Self {
		TransPkg {
			pkg,
			db,
			removes: Vec::new(),
			oldpkg: None,
		}
	}
}

// alpm_trans_t
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trans {
	// alpm_transflag_t bits
	pub flags: c_int,
	pub state: TransState,
	// targets dropped by the sync prepare (skipped unresolvable ones,
	// losers of inner conflicts)
	pub unresolvable: Vec<TransPkg>,
	pub add: Vec<TransPkg>,
	// dups of local packages
	pub remove: Vec<Package>,
	// filled by the commit's file conflict check
	pub skip_remove: Vec<Vec<u8>>,
}

// why alpm_trans_init failed
#[derive(Debug)]
pub enum InitError {
	// ALPM_ERR_TRANS_NOT_NULL
	NotNull,
	// ALPM_ERR_HANDLE_LOCK with the errno of the lock attempt
	Lock(std::io::Error),
}

impl InitError {
	pub fn errno(&self) -> Errno {
		match self {
			InitError::NotNull => Errno::TransNotNull,
			InitError::Lock(_) => Errno::HandleLock,
		}
	}
}

// the data list of a failed alpm_trans_prepare
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PrepareData {
	#[default]
	None,
	// ALPM_ERR_PKG_INVALID_ARCH: "name-version-arch" strings
	InvalidArch(Vec<Vec<u8>>),
	// ALPM_ERR_UNSATISFIED_DEPS
	Missing(Vec<DepMissing>),
	// ALPM_ERR_CONFLICTING_DEPS: the conflict that stopped it
	Conflicts(Vec<Conflict>),
}

// a failed alpm_trans_prepare: pm_errno and *data
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareError {
	pub errno: Errno,
	pub data: PrepareData,
}

impl PrepareError {
	pub(crate) fn new(errno: Errno, data: PrepareData) -> Self {
		PrepareError { errno, data }
	}
}

impl From<Errno> for PrepareError {
	fn from(errno: Errno) -> Self {
		PrepareError::new(errno, PrepareData::None)
	}
}

// the data list of a failed alpm_trans_commit
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CommitData {
	#[default]
	None,
	// the file conflict check (ALPM_ERR_FILE_CONFLICTS)
	FileConflicts(Vec<FileConflict>),
	// filenames of cached packages that failed to load or differ from
	// their db entry. the C keeps them whatever pm_errno ends up as
	Invalid(Vec<Vec<u8>>),
}

// a failed alpm_trans_commit: pm_errno as the C leaves it (Ok where it
// fails without one) and *data
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitError {
	pub errno: Errno,
	pub data: CommitData,
}

impl From<Errno> for CommitError {
	fn from(errno: Errno) -> Self {
		CommitError {
			errno,
			data: CommitData::None,
		}
	}
}

// a string field through printf %s: glibc prints NULL as "(null)"
pub(crate) fn opt_str(s: &Option<Vec<u8>>) -> &[u8] {
	s.as_deref().map_or(b"(null)", until_nul)
}

// the handle's trans in the state the call asserts, else its errno
pub(crate) fn trans_in(
	h: &mut Handle,
	state: TransState,
) -> Result<&mut Trans, Errno> {
	let trans = h.trans_mut().ok_or(Errno::TransNull)?;
	match trans.state == state {
		true => Ok(trans),
		false => Err(Errno::TransNotInitialized),
	}
}

// what the planning steps read of the handle: the local cache with its
// descs (what the C getters lazy-load) and the sync caches the resolver
// may use. a cache that is not loaded is the C's NULL list, empty here
pub(crate) struct View<'a> {
	pub handle: &'a Handle,
	pub local: &'a PkgHash<Package>,
	pub local_usage: c_int,
	pub sync: Vec<DbPkgs<'a>>,
}

// loads what View reads: the local cache with INFRQ_DESC, with sync the
// caches of the dbs used for install or upgrade (a failure marks a sync
// db invalid like the C's lazy load)
pub(crate) fn load_caches(h: &mut Handle, sync: bool) {
	let d = h.dbs_mut();
	let (dbext, cb) = (d.dbext, d.cb);
	if let Some(db) = d.local {
		let _ = db.load_all(dbext, cb, INFRQ_DESC);
	}
	if !sync {
		return;
	}
	for db in d.sync {
		if db.usage() & (DB_USAGE_INSTALL | DB_USAGE_UPGRADE) != 0 {
			let _ = db.pkgcache(dbext, cb);
		}
	}
}

impl<'a> View<'a> {
	pub fn new(h: &'a Handle, empty: &'a PkgHash<Package>) -> Self {
		let local = h.localdb();
		let sync = h.syncdbs().iter().map(|db| DbPkgs {
			usage: db.usage(),
			cache: db.loaded_pkgcache().unwrap_or(empty),
		});
		View {
			handle: h,
			local: local
				.and_then(|db| db.loaded_pkgcache())
				.unwrap_or(empty),
			local_usage: local.map_or(0, |db| db.usage()),
			sync: sync.collect(),
		}
	}

	pub fn env(&self, nodepversion: bool) -> DepsEnv<'_> {
		DepsEnv {
			opts: self.handle.deps_opts(),
			nodepversion,
			local: DbPkgs {
				usage: self.local_usage,
				cache: self.local,
			},
			sync: &self.sync,
		}
	}

	// _alpm_db_get_pkgcache(handle->db_local) as a list
	pub fn local_list(&self) -> Vec<&'a Package> {
		self.local.iter().collect()
	}
}

// f on a View of h with the callbacks lent out
pub(crate) fn with_view<R>(
	h: &mut Handle,
	f: impl FnOnce(&View, &mut dyn Callbacks) -> R,
) -> R {
	let empty = PkgHash::new(0).expect("empty table");
	h.with_callbacks(|h, cb| f(&View::new(h, &empty), cb))
}

// alpm_trans_init: the db lock unless NOLOCK, then an initialized
// transaction with these flags (not checked, like the C)
pub fn trans_init(h: &mut Handle, flags: c_int) -> Result<(), InitError> {
	if h.trans().is_some() {
		return Err(InitError::NotNull);
	}
	if flags & TRANS_FLAG_NOLOCK == 0 {
		h.lock().map_err(InitError::Lock)?;
	}
	h.set_trans(Some(Trans {
		flags,
		state: TransState::Initialized,
		unresolvable: Vec::new(),
		add: Vec::new(),
		remove: Vec::new(),
		skip_remove: Vec::new(),
	}));
	Ok(())
}

// alpm_trans_get_flags
pub fn trans_get_flags(h: &Handle) -> Result<c_int, Errno> {
	h.trans().map(|t| t.flags).ok_or(Errno::TransNull)
}

// alpm_trans_get_add
pub fn trans_get_add(h: &Handle) -> Result<&[TransPkg], Errno> {
	h.trans().map(|t| &t.add[..]).ok_or(Errno::TransNull)
}

// alpm_trans_get_remove
pub fn trans_get_remove(h: &Handle) -> Result<&[Package], Errno> {
	h.trans().map(|t| &t.remove[..]).ok_or(Errno::TransNull)
}

// alpm_trans_interrupt: only a committing (or already interrupted)
// transaction
pub fn trans_interrupt(h: &mut Handle) -> Result<(), Errno> {
	let trans = h.trans_mut().ok_or(Errno::TransNull)?;
	match trans.state {
		TransState::Committing | TransState::Interrupted => {
			trans.state = TransState::Interrupted;
			Ok(())
		}
		_ => Err(Errno::TransType),
	}
}

// alpm_trans_release: the transaction goes, then the lock unless it was
// taken without. a failed unlock is only logged, like the C
pub fn trans_release(h: &mut Handle) -> Result<(), Errno> {
	let trans = h.trans().ok_or(Errno::TransNull)?;
	if trans.state == TransState::Idle {
		return Err(Errno::TransNull);
	}
	let nolock = trans.flags & TRANS_FLAG_NOLOCK != 0;
	h.set_trans(None);
	h.interrupt().set_committing(false);
	if !nolock {
		h.handle_unlock();
	}
	Ok(())
}

// check_arch (static in C): "name-version-arch" of every target whose
// arch is set, not "any" and not one of the handle's architectures. no
// architectures skips the check
fn check_arch(
	h: &Handle,
	cb: &mut dyn Callbacks,
	add: &[TransPkg],
) -> Vec<Vec<u8>> {
	let arches = h.architectures();
	if arches.is_empty() {
		logv(cb, LogLevel::Debug, &[b"skipping architecture checks\n"]);
		return Vec::new();
	}
	let mut invalid = Vec::new();
	for t in add {
		let Some(arch) = t.pkg.arch.as_deref().map(until_nul) else {
			continue;
		};
		if arch == b"any" || arches.iter().any(|a| a == arch) {
			continue;
		}
		let p = &t.pkg;
		let (name, ver) = (opt_str(&p.name), opt_str(&p.version));
		invalid.push([name, b"-", ver, b"-", arch].concat());
	}
	invalid
}

// positions in targets of the packages of sorted (the same packages
// reordered, matched by address like the C pointers)
fn positions(targets: &[&Package], sorted: &[&Package]) -> Vec<usize> {
	let at = |s: &&Package| {
		let i = targets.iter().position(|t| std::ptr::eq(*t, *s));
		i.expect("sortbydeps returns its targets")
	};
	sorted.iter().map(at).collect()
}

// list in the order of positions, each element once
fn reorder<T>(list: &mut Vec<T>, order: &[usize]) {
	let mut old: Vec<Option<T>> = list.drain(..).map(Some).collect();
	let each = order.iter().map(|&i| old[i].take().expect("each once"));
	list.extend(each);
}

// alpm_trans_prepare's sort: targets so that dependencies are installed
// first, removals in reverse
fn sort_targets(view: &View, cb: &mut dyn Callbacks, trans: &mut Trans) {
	logv(cb, LogLevel::Debug, &[b"sorting by dependencies\n"]);
	let nodepversion = trans.flags & TRANS_FLAG_NODEPVERSION != 0;
	let env = view.env(nodepversion);
	let order = {
		let add: Vec<&Package> =
			trans.add.iter().map(|t| &t.pkg).collect();
		let rem: Vec<&Package> = trans.remove.iter().collect();
		positions(&add, &sortbydeps(&env, &add, &rem, false, cb))
	};
	reorder(&mut trans.add, &order);
	let order = {
		let rem: Vec<&Package> = trans.remove.iter().collect();
		positions(&rem, &sortbydeps(&env, &rem, &[], true, cb))
	};
	reorder(&mut trans.remove, &order);
}

// _alpm_pkg_dup force-loads every section of a local package: the
// removals and oldpkgs a prepare collected are dup'ed again from their
// fully loaded cache entries, for the commit. not logged: the C reads
// them when it dups, not here
fn load_full(h: &mut Handle, trans: &mut Trans) {
	let d = h.dbs_mut();
	let (dbext, cb) = (d.dbext, &mut ());
	let Some(db) = d.local else {
		return;
	};
	let olds = trans.add.iter_mut().filter_map(|t| t.oldpkg.as_mut());
	for p in trans.remove.iter_mut().chain(olds) {
		if p.infolevel & INFRQ_ALL == INFRQ_ALL {
			continue;
		}
		if let Ok(full) = db.force_load_pkg(dbext, cb, p.name_bytes()) {
			*p = full.dup();
		}
	}
}

// alpm_trans_prepare: nothing to do leaves the transaction initialized.
// file and sync targets go through _alpm_sync_prepare, a removal only
// through _alpm_remove_prepare; then both lists are sorted unless
// NODEPS. a failure keeps what the steps changed so far, like the C
pub fn trans_prepare(h: &mut Handle) -> Result<(), PrepareError> {
	trans_in(h, TransState::Initialized)?;
	let mut trans = h.set_trans(None).expect("checked above");
	let r = prepare(h, &mut trans);
	h.set_trans(Some(trans));
	r
}

fn prepare(h: &mut Handle, trans: &mut Trans) -> Result<(), PrepareError> {
	if trans.add.is_empty() && trans.remove.is_empty() {
		return Ok(());
	}
	let invalid = h.with_callbacks(|h, cb| check_arch(h, cb, &trans.add));
	if !invalid.is_empty() {
		let data = PrepareData::InvalidArch(invalid);
		return Err(PrepareError::new(Errno::PkgInvalidArch, data));
	}
	if trans.add.is_empty() {
		load_caches(h, false);
		with_view(h, |v, cb| remove::remove_prepare(v, cb, trans))?;
	} else {
		sync::check_dbs(h, &trans.add)?;
		load_caches(h, true);
		with_view(h, |v, cb| sync::sync_prepare(v, cb, trans))?;
	}
	load_full(h, trans);
	if trans.flags & TRANS_FLAG_NODEPS == 0 {
		with_view(h, |v, cb| sort_targets(v, cb, trans));
	}
	trans.state = TransState::Prepared;
	Ok(())
}

// the transaction's targets for hook.rs: trans.add with their oldpkgs,
// trans.remove. the transaction leaves the handle for the run
fn run_hooks(h: &mut Handle, when: HookWhen) -> bool {
	let trans = h.set_trans(None).expect("committing");
	let add: Vec<AddTarget> = trans
		.add
		.iter()
		.map(|t| AddTarget {
			pkg: &t.pkg,
			oldpkg: t.oldpkg.as_ref(),
		})
		.collect();
	let remove: Vec<&Package> = trans.remove.iter().collect();
	let targets = Targets {
		add: &add,
		remove: &remove,
	};
	let ok = hook_run(h, &targets, when);
	h.set_trans(Some(trans));
	ok
}

// the commit's state changes. with release the only ones entering or
// leaving COMMITTING/INTERRUPTED, so the ones the Interrupt follows
fn set_state(h: &mut Handle, state: TransState) {
	h.trans_mut().expect("committing").state = state;
	let committing = state == TransState::Committing;
	h.interrupt().set_committing(committing);
}

// trans->state == STATE_INTERRUPTED as the commit loops read it, an
// interrupt another thread asked (Interrupt::trans_interrupt) set into
// the state first
pub(crate) fn interrupted(h: &mut Handle) -> bool {
	let interrupt = h.interrupt();
	let Some(trans) = h.trans_mut() else {
		return false;
	};
	if interrupt.take_request() {
		trans.state = TransState::Interrupted;
	}
	trans.state == TransState::Interrupted
}

fn logaction(h: &mut Handle, msg: &[u8]) {
	// alpm_logaction's result is not checked
	let _ = h.logaction(CALLER_PREFIX, msg);
}

// alpm_trans_commit: a prepared transaction that holds the lock. with
// targets: loaded (downloads, keyring, validation; DOWNLOADONLY stops
// there) and checked (file conflicts, disk space). then the
// PreTransaction hooks, the removal or the sync commit, and unless
// interrupted the PostTransaction hooks. the state ends Committed after
// a commit that ran, interrupted or not
pub fn trans_commit(h: &mut Handle) -> Result<(), CommitError> {
	let trans = h.trans().ok_or(Errno::TransNull)?;
	if trans.state != TransState::Prepared {
		return Err(Errno::TransNotPrepared.into());
	}
	if trans.flags & TRANS_FLAG_NOLOCK != 0 {
		return Err(Errno::TransNotLocked.into());
	}
	// nothing to do, nothing to complain about
	if trans.add.is_empty() && trans.remove.is_empty() {
		return Ok(());
	}
	let (flags, sync) = (trans.flags, !trans.add.is_empty());

	if sync {
		sync::sync_load(h)?;
		if flags & TRANS_FLAG_DOWNLOADONLY != 0 {
			return Ok(());
		}
		sync::sync_check(h)?;
	}
	let hooks = flags & TRANS_FLAG_NOHOOKS == 0;
	if hooks && !run_hooks(h, HookWhen::PreTransaction) {
		return Err(Errno::TransHookFailed.into());
	}

	set_state(h, TransState::Committing);
	logaction(h, b"transaction started\n");
	h.callbacks().event(&Event::TransactionStart);
	let r = match sync {
		false => {
			remove::remove_packages(h, true);
			Ok(())
		}
		true => sync::sync_commit(h),
	};
	if let Err(e) = r {
		logaction(h, b"transaction failed\n");
		return Err(e.into());
	}

	if interrupted(h) {
		logaction(h, b"transaction interrupted\n");
	} else {
		h.callbacks().event(&Event::TransactionDone);
		logaction(h, b"transaction completed\n");
		if hooks {
			run_hooks(h, HookWhen::PostTransaction);
		}
	}
	set_state(h, TransState::Committed);
	Ok(())
}
