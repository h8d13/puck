// port of src/pacman/sync.c: -Si/-Sii (sync_info), -Sl (sync_list),
// -Sg/-Sgg (sync_group), -Ss (sync_search), -Sy/-Syy (util.c's
// sync_syncdbs, shared with -Fy), -Sc/-Scc (sync_cleancache,
// sync_cleandb_all), the pacman_sync dispatch up to them, util.c's
// check_syncdbs they rely on, and the transaction of -S/-Su up and
// through the commit (sync_trans, sync_prepare_execute, also run by -U)
//
// the C prints to stdout and through pm_printf to stderr, both go into an
// Output. config is the C global, handle config->handle; cols is what
// getcols() gives -Si (COLUMNS or the terminal width, 0 when neither).
// -Si shows a sync package in place while the display loads the local
// and the other sync caches (Handle::dbs_mut, the dbs split around the
// shown one). messages are the untranslated msgids.
//
// what -Sy prints during alpm_db_update comes from the handle's
// callbacks (callback.rs); out is flushed (Output::flush) before, so the
// header goes out first.
//
// the branches that prompt need a Ui: pacman_sync returns Deferred where
// it reaches them, the dispatch runs sync_clean or sync_trans.
// multibar_move_completed_up goes through the flag Term shares with the
// callbacks.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufRead, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::Ordering;

use alpm_core::add::add_pkg;
use alpm_core::be_package::pkg_load_level;
use alpm_core::be_sync::{db_update, get_validation};
use alpm_core::callbacks::Callbacks;
use alpm_core::conflict::FileConflictType;
use alpm_core::db::{DB_USAGE_INSTALL, Db};
use alpm_core::deps::{DepMissing, DepMod, dep_compute_string};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::package::{DbCaches, Package, pkg_find};
use alpm_core::signing::{decode_signature, extract_keyid};
use alpm_core::sync::{dbs_satisfier, find_group_pkgs, sync_sysupgrade};
use alpm_core::trans::{
	CommitData, CommitError, PrepareData, PrepareError, TransPkg,
	trans_commit, trans_get_add, trans_get_remove, trans_prepare,
};
use alpm_core::util::{PATH_MAX, fnmatch, strerror, until_nul};
use alpm_core::version::vercmp;

use crate::conf::{
	Config, LOG_DEBUG, LOG_ERROR, LOG_WARNING, PM_CLEAN_KEEPCUR,
	PM_CLEAN_KEEPINST, cat,
};
use crate::package::{
	FileProbe, PkgEnv, dump_pkg_full, dump_pkg_search, print_installed,
};
use crate::util::{
	DbPkg, Output, SigResult, TransTargets, Ui, check_syncdbs,
	colon_printf, display_targets, multiselect_question, noyes, pm_printf,
	print_packages, rmrf_errno, select_display, trans_init, trans_release,
	yesno,
};

// a pacman_sync branch that prompts, left to the dispatch (it has the Ui)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deferred {
	// -Sc/-Scc: sync_clean
	Clean,
	// sync_trans: -S <targets>, -Su
	Transaction,
}

pub(crate) fn error(out: &mut Output, config: &Config, msg: &[&[u8]]) {
	pm_printf(&mut out.stderr, config, LOG_ERROR, &cat(msg));
}

// alpm_db_get_pkgcache as the C list: empty when the cache cannot load
pub(crate) fn cache_list<'a>(
	db: &'a mut Db,
	dbext: &[u8],
	cb: &mut dyn Callbacks,
) -> Vec<&'a Package> {
	db.pkgcache(dbext, cb)
		.map(|c| c.iter().collect())
		.unwrap_or_default()
}

// what dump_pkg_full asks of libalpm for a package of sync db this:
// the dbs registered before and after it load on demand, this one is
// loaded and lends the package
struct SyncEnv<'a> {
	dbext: &'a [u8],
	cb: &'a mut dyn Callbacks,
	local: Option<&'a mut Db>,
	before: &'a mut [Db],
	this: &'a Db,
	after: &'a mut [Db],
	root: &'a [u8],
	config: &'a Config,
	stderr: Vec<u8>,
}

impl DbCaches for SyncEnv<'_> {
	fn local_cache(&mut self) -> Vec<&Package> {
		match self.local.as_deref_mut() {
			Some(db) => cache_list(db, self.dbext, self.cb),
			None => Vec::new(),
		}
	}

	fn sync_caches(&mut self) -> Vec<Vec<&Package>> {
		let (dbext, cb) = (self.dbext, &mut *self.cb);
		let this = self.this.loaded_pkgcache();
		let mut caches: Vec<Vec<&Package>> = Vec::new();
		for db in self.before.iter_mut() {
			caches.push(cache_list(db, dbext, cb));
		}
		caches.push(this
			.map(|c| c.iter().collect())
			.unwrap_or_default());
		for db in self.after.iter_mut() {
			caches.push(cache_list(db, dbext, cb));
		}
		caches
	}
}

impl PkgEnv for SyncEnv<'_> {
	fn db_name(&mut self, _: &Package) -> Option<Vec<u8>> {
		Some(self.this.name().to_vec())
	}

	// alpm_decode_signature, then alpm_extract_keyid on the packets:
	// the keys before a format error, which it logs. base64 that does
	// not decode is no data, so no keys
	fn sig_keys(&mut self, pkg: &Package, b64: &[u8]) -> Vec<Vec<u8>> {
		let sig = decode_signature(b64).unwrap_or_default();
		let mut keys = Vec::new();
		let cb = &mut *self.cb;
		let _ = extract_keyid(cb, pkg.name_bytes(), &sig, &mut keys);
		keys
	}

	// file packages only, -Si never shows one
	fn check_signature(
		&mut self,
		_: &Package,
	) -> Result<Vec<SigResult>, Errno> {
		Err(Errno::SigMissing)
	}

	fn root(&mut self) -> Vec<u8> {
		self.root.to_vec()
	}

	// local -ii backup states only, never reached for sync packages
	fn probe_file(&mut self, _: &[u8]) -> FileProbe {
		FileProbe::Failed
	}

	// -Qc only
	fn changelog(&mut self, _: &Package) -> Option<Vec<u8>> {
		None
	}

	fn error(&mut self, msg: &[u8]) {
		pm_printf(&mut self.stderr, self.config, LOG_ERROR, msg);
	}

	fn validation(&mut self, pkg: &Package) -> i32 {
		get_validation(pkg)
	}
}

// dump_pkg_full in place of every entry of sync db i's cache list, or
// of the first one called name (a cache that cannot load is empty).
// true when one was shown
fn show_full(
	config: &Config,
	handle: &mut Handle,
	i: usize,
	name: Option<&[u8]>,
	cols: u16,
	out: &mut Output,
) -> bool {
	let root = handle.root().to_vec();
	let dbs = handle.dbs_mut();
	let (before, rest) = dbs.sync.split_at_mut(i);
	let (this, after) = rest.split_first_mut().expect("db i exists");
	let _ = this.pkgcache(dbs.dbext, dbs.cb);
	let this = &*this;
	let all = this.loaded_pkgcache().into_iter().flat_map(|c| c.iter());
	let pkgs: Vec<&Package> = match name {
		None => all.collect(),
		Some(n) => {
			all.filter(|p| p.name_bytes() == n).take(1).collect()
		}
	};
	let mut env = SyncEnv {
		dbext: dbs.dbext,
		cb: dbs.cb,
		local: dbs.local,
		before,
		this,
		after,
		root: &root,
		config,
		stderr: Vec::new(),
	};
	let extra = config.op_s_info > 1;
	let colstr = &config.colstr;
	for pkg in &pkgs {
		let stdout = &mut out.stdout;
		dump_pkg_full(stdout, &mut env, pkg, extra, cols, colstr);
		out.stderr.append(&mut env.stderr);
	}
	!pkgs.is_empty()
}

fn os(path: &[u8]) -> &OsStr {
	OsStr::from_bytes(path)
}

fn debug(out: &mut Output, config: &Config, msg: &[&[u8]]) {
	pm_printf(&mut out.stderr, config, LOG_DEBUG, &cat(msg));
}

// unlink_verbose: the C's unlink return value, -1 when it failed (also
// what -Sc sums up), a missing file is fine with ignore_missing
fn unlink_verbose(
	out: &mut Output,
	config: &Config,
	path: &[u8],
	ignore_missing: bool,
) -> i32 {
	let Err(e) = fs::remove_file(os(path)) else {
		return 0;
	};
	if ignore_missing && e.kind() == ErrorKind::NotFound {
		return 0;
	}
	error(
		out,
		config,
		&[b"could not remove ", path, b": ", &strerror(&e), b"\n"],
	);
	-1
}

// the db name of a sync dir file: "<name>.db", ".db.sig", ".files",
// ".files.sig" with a name before the suffix
fn db_stem(file: &[u8]) -> Option<&[u8]> {
	let suffixes: [&[u8]; 4] =
		[b".db", b".db.sig", b".files", b".files.sig"];
	suffixes.iter()
		.find_map(|s| file.strip_suffix(*s).filter(|n| !n.is_empty()))
}

// one entry of sync_cleandb: directories go (rmrf, not counted), files
// not of a registered db are unlinked
fn cleandb_entry(
	out: &mut Output,
	config: &Config,
	syncdbs: &[Db],
	dbpath: &[u8],
	dname: &[u8],
) -> i32 {
	let mut path = [dbpath, dname].concat();
	if path.len() >= PATH_MAX {
		let msg: [&[u8]; 4] = [
			b"could not remove ",
			dbpath,
			dname,
			b": path exceeds PATH_MAX\n",
		];
		error(out, config, &msg);
		// the C goes on with the cut snprintf result
		path.truncate(PATH_MAX - 1);
	}
	match fs::metadata(os(&path)) {
		// the C then reads the uninitialised st_mode: taken as no
		// directory here (UPSTREAM.md)
		Err(e) => {
			let msg = [b"could not remove ", &path[..], b": "];
			error(
				out,
				config,
				&[&msg.concat(), &strerror(&e), b"\n"],
			);
		}
		Ok(m) if m.is_dir() => {
			let (n, e) = rmrf_errno(&path);
			if n != 0 {
				// errno 0 when rmrf left none: "Success"
				let e = e.unwrap_or_else(|| {
					io::Error::from_raw_os_error(0)
				});
				let msg = [
					b"could not remove ",
					&path[..],
					b": ",
				];
				error(
					out,
					config,
					&[&msg.concat(), &strerror(&e), b"\n"],
				);
			}
			return 0;
		}
		Ok(_) => {}
	}
	match db_stem(dname) {
		Some(name) if syncdbs.iter().any(|db| db.name() == name) => 0,
		_ => unlink_verbose(out, config, &path, false),
	}
}

// sync_cleandb: everything in the sync dir but the files of registered
// dbs, 1 when the dir cannot be read
fn sync_cleandb(
	out: &mut Output,
	config: &Config,
	syncdbs: &[Db],
	dbpath: &[u8],
) -> i32 {
	let Ok(dir) = fs::read_dir(os(dbpath)) else {
		error(out, config, &[b"could not access database directory\n"]);
		return 1;
	};
	let mut ret = 0;
	// readdir ends the loop on an error as on the end
	for ent in dir.map_while(Result::ok) {
		let name = ent.file_name();
		let dname = name.as_bytes();
		ret += cleandb_entry(out, config, syncdbs, dbpath, dname);
	}
	ret
}

// sync_cleandb_all: the sync dir of dbpath after a yes (the default)
fn sync_cleandb_all<R: BufRead>(ui: &mut Ui<R>, h: &Handle) -> i32 {
	let (config, dbpath) = (ui.config, h.dbpath());
	let msg = [b"Database directory: ", dbpath, b"\n"];
	ui.out.stdout.extend(cat(&msg));
	let ask = b"Do you want to remove unused repositories?";
	if !yesno(ui.out, config, ui.term, ask) {
		return 0;
	}
	let msg = b"removing unused sync repositories...\n";
	ui.out.stdout.extend_from_slice(msg);
	let syncdir = [dbpath, b"sync/"].concat();
	sync_cleandb(ui.out, config, h.syncdbs(), &syncdir)
}

// what -Sc never removes: signatures go with their package
const GLOB_SKIPS: [&[u8]; 4] =
	[b"*.sig", b"*.db*", b"*.files*", b"*.src.tar.*"];

// a cache file kept by db: the package of that name there has its
// version (a NULL version equals none)
fn kept_by(
	ui: &mut Ui<'_, impl BufRead>,
	h: &mut Handle,
	db: Option<usize>,
	pkg: &Package,
) -> bool {
	// the lookup may load the cache, its log lines come after ours
	ui.out.flush();
	let dbs = h.dbs_mut();
	let db = match db {
		None => dbs.local,
		Some(i) => dbs.sync.get_mut(i),
	};
	let Some(db) = db else {
		return false;
	};
	let version = pkg.version.as_deref().unwrap_or_default();
	db.get_pkg(dbs.dbext, dbs.cb, pkg.name_bytes())
		.is_ok_and(|p| {
			p.version
				.as_deref()
				.is_some_and(|v| vercmp(version, v).is_eq())
		})
}

// one entry of a cache dir: -cc unlinks it, -c loads it as a package and
// unlinks it with its .sig unless cleanmethod keeps it
fn cleancache_entry<R: BufRead>(
	ui: &mut Ui<R>,
	h: &mut Handle,
	cachedir: &[u8],
	name: &[u8],
	method: u16,
) -> i32 {
	let config = ui.config;
	let level = config.op_s_clean;
	if level <= 1 && GLOB_SKIPS.iter().any(|g| fnmatch(g, name)) {
		return 0;
	}
	let path = [cachedir, name].concat();
	if path.len() >= PATH_MAX {
		let msg: [&[u8]; 4] = [
			b"skipping ",
			cachedir,
			name,
			b": path exceeds PATH_MAX\n",
		];
		error(ui.out, config, &msg);
		return 0;
	}
	if level > 1 {
		return unlink_verbose(ui.out, config, &path, false);
	}
	ui.out.flush();
	// alpm_pkg_load(handle, path, 0, 0): metadata only, siglevel 0
	let loaded = h.with_callbacks(|h, cb| {
		pkg_load_level(h.keyring_mut(), cb, &path, false, 0)
	});
	let Ok(pkg) = loaded else {
		let msg = [
			b"skipping ",
			&path[..],
			b", could not load as package\n",
		];
		debug(ui.out, config, &msg);
		return 0;
	};
	let version = pkg.version.as_deref().unwrap_or_default();
	let found = |ui: &mut Ui<R>, which: &[u8]| {
		let msg = [b"package ", pkg.name_bytes(), b"-", version, which];
		debug(ui.out, config, &msg);
	};
	let mut delete = true;
	if method & PM_CLEAN_KEEPINST != 0 && kept_by(ui, h, None, &pkg) {
		found(ui, b" found in local db\n");
		delete = false;
	}
	if method & PM_CLEAN_KEEPCUR != 0 {
		for i in 0..h.syncdbs().len() {
			if !delete {
				break;
			}
			if kept_by(ui, h, Some(i), &pkg) {
				found(ui, b" found in sync db\n");
				delete = false;
			}
		}
	}
	if !delete {
		return 0;
	}
	let mut ret = unlink_verbose(ui.out, config, &path, false);
	// strcpy of ".sig" into the PATH_MAX buffer, when it fits
	if path.len() <= PATH_MAX - 5 {
		let sig = [&path[..], b".sig"].concat();
		ret += unlink_verbose(ui.out, config, &sig, true);
	}
	ret
}

// sync_cleancache(level): every cache dir after its question (-c yes by
// default, -cc no). a dir that cannot be read counts 1
fn sync_cleancache<R: BufRead>(ui: &mut Ui<R>, h: &mut Handle) -> i32 {
	let config = ui.config;
	let level = config.op_s_clean;
	// the C writes the default back into config, read only here
	let method = match config.cleanmethod {
		0 => PM_CLEAN_KEEPINST,
		m => m,
	};
	let out = &mut ui.out.stdout;
	if level == 1 {
		out.extend_from_slice(b"Packages to keep:\n");
		if method & PM_CLEAN_KEEPINST != 0 {
			let msg = b"  All locally installed packages\n";
			out.extend_from_slice(msg);
		}
		if method & PM_CLEAN_KEEPCUR != 0 {
			let msg = b"  All current sync database packages\n";
			out.extend_from_slice(msg);
		}
	}
	out.push(b'\n');

	let mut ret = 0;
	for cachedir in h.cachedirs().to_vec() {
		let msg = [b"Cache directory: ", &cachedir[..], b"\n"];
		ui.out.stdout.extend(cat(&msg));
		let (yes, doing): (bool, &[u8]) = match level {
			1 => (
				yesno(
					ui.out,
					config,
					ui.term,
					b"Do you want to remove all other \
					  packages from cache?",
				),
				b"removing old packages from cache...\n",
			),
			_ => (
				noyes(
					ui.out,
					config,
					ui.term,
					b"Do you want to remove ALL files \
					  from cache?",
				),
				b"removing all files from cache...\n",
			),
		};
		if !yes {
			ui.out.stdout.push(b'\n');
			continue;
		}
		ui.out.stdout.extend_from_slice(doing);
		let Ok(dir) = fs::read_dir(os(&cachedir)) else {
			let msg = [
				b"could not access cache directory ",
				&cachedir[..],
				b"\n",
			];
			error(ui.out, config, &msg);
			ret += 1;
			continue;
		};
		// readdir ends the loop on an error as on the end
		for ent in dir.map_while(Result::ok) {
			let name = ent.file_name();
			let name = name.as_bytes();
			ret += cleancache_entry(ui, h, &cachedir, name, method);
		}
		ui.out.stdout.push(b'\n');
	}
	ret
}

// pacman_sync's -Sc/-Scc branch: the cache dirs, then the sync dir,
// under the db lock (trans_init without flags). the sum of what the
// steps return, a failed unlink counting -1
pub fn sync_clean<R: BufRead>(ui: &mut Ui<R>, h: &mut Handle) -> i32 {
	let config = ui.config;
	if !trans_init(ui.out, config, h, 0, false) {
		return 1;
	}
	let mut ret = sync_cleancache(ui, h);
	ret += sync_cleandb_all(ui, h);
	ui.out.flush();
	if !trans_release(ui.out, config, h) {
		ret += 1;
	}
	ret
}

// sync_group: with targets each group's members per db ("<group> <pkg>",
// the name only when quiet), an error for a group in no db. without,
// every group name once (level 1) or every "<group> <pkg>" (level 2+),
// 1 when no db has a group
pub fn sync_group<S: AsRef<[u8]>>(
	config: &Config,
	handle: &mut Handle,
	level: u16,
	targets: &[S],
	out: &mut Output,
) -> i32 {
	if targets.is_empty() {
		let mut ret = 1;
		let mut seen: Vec<Vec<u8>> = Vec::new();
		let dbs = handle.dbs_mut();
		for db in dbs.sync {
			let groups = db
				.groupcache(dbs.dbext, dbs.cb)
				.unwrap_or_default();
			for grp in groups {
				ret = 0;
				if level > 1 {
					for p in &grp.packages {
						out.stdout.extend(cat(&[
							&grp.name,
							b" ",
							p.name_bytes(),
							b"\n",
						]));
					}
				} else if !seen.contains(&grp.name) {
					out.stdout.extend(cat(&[
						&grp.name, b"\n",
					]));
					seen.push(grp.name);
				}
			}
		}
		return ret;
	}

	let mut ret = 0;
	for t in targets {
		let grpname = until_nul(t.as_ref());
		let mut found = false;
		let dbs = handle.dbs_mut();
		for db in dbs.sync {
			// an empty name is WrongArgs: no group either
			let Ok(Some(grp)) =
				db.get_group(dbs.dbext, dbs.cb, grpname)
			else {
				continue;
			};
			found = true;
			for p in &grp.packages {
				let line: [&[u8]; 4] = match config.quiet {
					0 => [
						grpname,
						b" ",
						p.name_bytes(),
						b"\n",
					],
					_ => [p.name_bytes(), b"\n", b"", b""],
				};
				out.stdout.extend(cat(&line));
			}
		}
		if !found {
			let msg: [&[u8]; 3] = [
				b"package group '",
				grpname,
				b"' was not found\n",
			];
			error(out, config, &msg);
			ret = 1;
		}
	}
	ret
}

// sync_info: "[repo/]name" targets, the first package of that name in
// each matching db shown. one error per missing repo or package, the
// return value counts them. without targets every package of every db
pub fn sync_info<S: AsRef<[u8]>>(
	config: &Config,
	handle: &mut Handle,
	targets: &[S],
	cols: u16,
	out: &mut Output,
) -> i32 {
	let ndbs = handle.syncdbs().len();
	if targets.is_empty() {
		for i in 0..ndbs {
			show_full(config, handle, i, None, cols, out);
		}
		return 0;
	}

	let mut ret = 0;
	for t in targets {
		let target = until_nul(t.as_ref());
		// the first '/' splits off the repo, later ones stay
		let (repo, pkgstr) = match target
			.iter()
			.position(|&c| c == b'/')
		{
			Some(i) => (Some(&target[..i]), &target[i + 1..]),
			None => (None, target),
		};
		let (mut foundpkg, mut founddb) = (false, false);
		for i in 0..ndbs {
			if repo.is_some_and(|r| r != handle.syncdbs()[i].name())
			{
				continue;
			}
			founddb = true;
			let name = Some(pkgstr);
			foundpkg |=
				show_full(config, handle, i, name, cols, out);
		}
		if !founddb {
			// printf("%s", NULL) is "(null)" in glibc
			let repo = repo.unwrap_or(b"(null)");
			let msg: [&[u8]; 3] =
				[b"repository '", repo, b"' does not exist\n"];
			error(out, config, &msg);
			ret += 1;
		}
		if !foundpkg {
			let msg: [&[u8]; 3] =
				[b"package '", target, b"' was not found\n"];
			error(out, config, &msg);
			ret += 1;
		}
	}
	ret
}

// sync_list: "<repo> <name> <version>[ installed]" per package of the
// named repos (every repo without targets), the name only when quiet.
// unknown repos are reported first and listed as empty, 1 then
pub fn sync_list<S: AsRef<[u8]>>(
	config: &Config,
	handle: &mut Handle,
	targets: &[S],
	out: &mut Output,
) -> i32 {
	let mut ret = 0;
	let ls: Vec<Option<usize>> = if targets.is_empty() {
		(0..handle.syncdbs().len()).map(Some).collect()
	} else {
		let mut ls = Vec::new();
		for t in targets {
			let repo = until_nul(t.as_ref());
			let db = handle
				.syncdbs()
				.iter()
				.position(|d| d.name() == repo);
			if db.is_none() {
				let msg: [&[u8]; 3] = [
					b"repository \"",
					repo,
					b"\" was not found.\n",
				];
				error(out, config, &msg);
				ret = 1;
			}
			// the C adds the NULL db too, its cache is empty
			ls.push(db);
		}
		ls
	};

	let c = &config.colstr;
	for i in ls.into_iter().flatten() {
		let dbs = handle.dbs_mut();
		let (dbext, cb, mut localdb) = (dbs.dbext, dbs.cb, dbs.local);
		let db = &mut dbs.sync[i];
		let name = db.name().to_vec();
		for pkg in cache_list(db, dbext, cb) {
			if config.quiet != 0 {
				out.stdout.extend(cat(&[
					pkg.name_bytes(),
					b"\n",
				]));
				continue;
			}
			let version =
				pkg.version.as_deref().unwrap_or_default();
			out.stdout.extend(cat(&[
				c.repo,
				&name,
				b" ",
				c.title,
				pkg.name_bytes(),
				b" ",
				c.version,
				until_nul(version),
				c.nocolor,
			]));
			let local = localdb.as_mut().and_then(|l| {
				l.get_pkg(dbext, cb, pkg.name_bytes()).ok()
			});
			print_installed(&mut out.stdout, local, pkg, c);
			out.stdout.push(b'\n');
		}
	}
	ret
}

// sync_search: dump_pkg_search with the installed marker on every sync
// db, the whole cache without targets. 0 when any db showed something,
// a bad regex stops at its db
pub fn sync_search<S: AsRef<[u8]>>(
	config: &Config,
	handle: &mut Handle,
	targets: &[S],
	cols: u16,
	out: &mut Output,
) -> i32 {
	let dbs = handle.dbs_mut();
	let (dbext, cb, syncs) = (dbs.dbext, dbs.cb, dbs.sync);
	let lcache = dbs.local.and_then(|l| l.pkgcache(dbext, cb).ok());
	let find = |name: &[u8]| lcache.and_then(|c| c.find(name));
	let mut found = 0;
	for db in syncs.iter_mut() {
		let name = db.name().to_vec();
		let results: Vec<&Package> = if targets.is_empty() {
			cache_list(db, dbext, cb)
		} else {
			match db.search(dbext, cb, targets) {
				Ok(r) => r,
				Err(e) => {
					let why = e.strerror().as_bytes();
					let msg = [
						&b"search failed: "[..],
						why,
						b"\n",
					];
					error(out, config, &msg);
					return 1;
				}
			}
		};
		let shown = dump_pkg_search(
			&mut out.stdout,
			&name,
			&results,
			Some(&find),
			config.quiet != 0,
			cols,
			&config.colstr,
		);
		found += i32::from(shown);
	}
	i32::from(found == 0)
}

// pacman_sync: the read-only operations, Err for the branches that
// prompt (in the order the C reaches them). Ok is the C return value
pub fn pacman_sync<S: AsRef<[u8]>>(
	config: &Config,
	handle: &mut Handle,
	targets: &[S],
	cols: u16,
	out: &mut Output,
) -> Result<i32, Deferred> {
	if config.op_s_clean != 0 {
		return Err(Deferred::Clean);
	}
	if check_syncdbs(&mut out.stderr, config, handle, true, false) != 0 {
		return Ok(1);
	}
	if config.op_s_sync != 0 && !refresh(config, handle, out) {
		return Ok(1);
	}
	if check_syncdbs(&mut out.stderr, config, handle, true, true) != 0 {
		return Ok(1);
	}
	if config.op_s_search != 0 {
		return Ok(sync_search(config, handle, targets, cols, out));
	}
	if config.group != 0 {
		return Ok(sync_group(
			config,
			handle,
			config.group,
			targets,
			out,
		));
	}
	if config.op_s_info != 0 {
		return Ok(sync_info(config, handle, targets, cols, out));
	}
	if config.op_q_list != 0 {
		return Ok(sync_list(config, handle, targets, out));
	}
	if targets.is_empty() && config.op_s_upgrade == 0 {
		if config.op_s_sync != 0 {
			return Ok(0);
		}
		let msg: &[u8] = b"no targets specified (use -h for help)\n";
		error(out, config, &[msg]);
		return Ok(1);
	}
	Err(Deferred::Transaction)
}

// sync_syncdbs(level, every sync db): alpm_db_update, forced from -yy.
// false (C 0) when it failed, after the error line
pub fn sync_syncdbs(
	config: &Config,
	handle: &mut Handle,
	level: u16,
	out: &mut Output,
) -> bool {
	// what is buffered goes out first, the callbacks print now. the C
	// also resets multibar_move_completed_up here, a no-op in one run:
	// the commit setting it comes after (no Term reaches this)
	out.flush();
	let dbs: Vec<usize> = (0..handle.syncdbs().len()).collect();
	let ret = db_update(handle, &dbs, level >= 2);
	if let Err(e) = ret {
		let msg = [
			b"failed to synchronize all databases (",
			e.strerror().as_bytes(),
			b")\n",
		];
		error(out, config, &msg);
	}
	ret.is_ok()
}

// the -Sy/-Fy block of pacman_sync and pacman_files: the header, the
// logfile line, sync_syncdbs
pub(crate) fn refresh(
	config: &Config,
	handle: &mut Handle,
	out: &mut Output,
) -> bool {
	let c = &config.colstr;
	let head: &[u8] = b"Synchronizing package databases...\n";
	out.stdout.extend(cat(&[c.colon, head, c.nocolor]));
	let _ = handle.logaction(b"PACMAN", b"synchronizing package lists\n");
	sync_syncdbs(config, handle, config.op_s_sync, out)
}

// pacman.h
const PACMAN_CALLER_PREFIX: &[u8] = b"PACMAN";

pub(crate) fn warning(out: &mut Output, config: &Config, msg: &[&[u8]]) {
	pm_printf(&mut out.stderr, config, LOG_WARNING, &cat(msg));
}

fn opt(s: &Option<Vec<u8>>) -> &[u8] {
	s.as_deref().map_or(b"(null)", until_nul)
}

// the db a transaction package came from, alpm_pkg_get_db
pub(crate) fn db_pkg<'a>(h: &'a Handle, t: &'a TransPkg) -> DbPkg<'a> {
	DbPkg {
		pkg: &t.pkg,
		db: t.db.and_then(|i| h.syncdbs().get(i)),
	}
}

// the local db cache as loaded, empty when it is not
pub(crate) fn local_list(h: &Handle) -> Vec<&Package> {
	let cache = h.localdb().and_then(Db::loaded_pkgcache);
	cache.map(|c| c.iter().collect()).unwrap_or_default()
}

// get_db: position of the sync db of that name
fn get_db(h: &Handle, dbname: &[u8]) -> Option<usize> {
	h.syncdbs().iter().position(|db| db.name() == dbname)
}

// process_pkg: an explicit target, 1 when alpm_add_pkg refused it
fn process_pkg<R>(ui: &mut Ui<R>, h: &mut Handle, t: TransPkg) -> i32 {
	if let Err(e) = add_pkg(h, t.pkg.clone(), t.db) {
		let msg = [
			b"'",
			opt(&t.pkg.name),
			b"': ",
			e.strerror().as_bytes(),
		];
		error(ui.out, ui.config, &[&msg.concat(), b"\n"]);
		return 1;
	}
	ui.explicit_adds.push(t.pkg);
	0
}

// group_exists
fn group_exists(h: &mut Handle, dbs: &[usize], name: &[u8]) -> bool {
	dbs.iter().any(|&i| {
		let d = h.dbs_mut();
		let db = &mut d.sync[i];
		matches!(db.get_group(d.dbext, d.cb, name), Ok(Some(_)))
	})
}

// process_group: the members of a group as targets, picked by
// multiselect_question unless --print. an empty group that exists is
// fine, after an earlier error only the name is checked
fn process_group<R: BufRead>(
	ui: &mut Ui<R>,
	h: &mut Handle,
	dbs: &[usize],
	group: &[u8],
	error_seen: bool,
) -> i32 {
	let pkgs = find_group_pkgs(h, dbs, group);
	if pkgs.is_empty() {
		if group_exists(h, dbs, group) {
			return 0;
		}
		error(
			ui.out,
			ui.config,
			&[b"target not found: ", group, b"\n"],
		);
		return 1;
	}
	if error_seen {
		return 0;
	}
	if ui.config.print != 0 {
		for t in pkgs {
			if process_pkg(ui, h, t) == 1 {
				return 1;
			}
		}
		return 0;
	}
	let cs = &ui.config.colstr;
	let count = pkgs.len();
	// ngettext without a catalog: the singular msgid for 1
	let what = match count {
		1 => format!("There is {count} member in group "),
		_ => format!("There are {count} members in group "),
	};
	let msg = [what.as_bytes(), cs.groups, group, cs.title, b":\n"];
	colon_printf(&mut ui.out.stdout, cs, &msg.concat());
	let shown: Vec<DbPkg> = pkgs.iter().map(|t| db_pkg(h, t)).collect();
	let pairs: Vec<(Option<&[u8]>, &Package)> =
		shown.iter().map(|p| (p.db.map(Db::name), p.pkg)).collect();
	select_display(&mut ui.out.stdout, cs, &pairs, ui.cols);
	let mut array = vec![false; count];
	if multiselect_question(ui.out, ui.config, ui.term, &mut array) != 0 {
		return 1;
	}
	for (t, chosen) in pkgs.into_iter().zip(array) {
		if chosen && process_pkg(ui, h, t) == 1 {
			return 1;
		}
	}
	0
}

// process_targname: the satisfier of targname in dbs, else a group of
// that name. an ignored package the user declined skips the target
fn process_targname<R: BufRead>(
	ui: &mut Ui<R>,
	h: &mut Handle,
	dbs: &[usize],
	targname: &[u8],
	error_seen: bool,
) -> i32 {
	match dbs_satisfier(h, dbs, targname) {
		Err(Errno::PkgIgnored) => {
			let msg: [&[u8]; 3] =
				[b"skipping target: ", targname, b"\n"];
			warning(ui.out, ui.config, &msg);
			0
		}
		Ok(t) => process_pkg(ui, h, t),
		Err(_) => process_group(ui, h, dbs, targname, error_seen),
	}
}

// process_target: "repo/name" looks only in repo (made usable for
// installs meanwhile), anything else in every sync db. a failed target
// that names a readable file gets the -U hint. access(R_OK) is an open
// for reading here
fn process_target<R: BufRead>(
	ui: &mut Ui<R>,
	h: &mut Handle,
	target: &[u8],
	error_seen: bool,
) -> i32 {
	let target = until_nul(target);
	let slash = target.iter().position(|&c| c == b'/').filter(|&i| i > 0);
	let ret = match slash {
		Some(i) => {
			let (dbname, targname) =
				(&target[..i], &target[i + 1..]);
			match get_db(h, dbname) {
				None => {
					let msg: [&[u8]; 3] = [
						b"database not found: ",
						dbname,
						b"\n",
					];
					error(ui.out, ui.config, &msg);
					1
				}
				Some(db) => {
					let usage = h.syncdbs()[db].usage();
					let d = &mut h.syncdbs_mut()[db];
					d.set_usage(usage | DB_USAGE_INSTALL);
					let r = process_targname(
						ui,
						h,
						&[db],
						targname,
						error_seen,
					);
					h.syncdbs_mut()[db].set_usage(usage);
					r
				}
			}
		}
		None => {
			let dbs: Vec<usize> = (0..h.syncdbs().len()).collect();
			process_targname(ui, h, &dbs, target, error_seen)
		}
	};
	let path = std::ffi::OsStr::from_bytes(target);
	if ret != 0 && File::open(path).is_ok() {
		let msg: [&[u8]; 7] = [
			b"'",
			target,
			b"' is a file, did you mean ",
			b"-U/--upgrade",
			b" instead of ",
			b"-S/--sync",
			b"?\n",
		];
		warning(ui.out, ui.config, &msg);
	}
	ret
}

// sync_trans: a transaction with the targets and -u, then
// sync_prepare_execute
pub fn sync_trans<R: BufRead, S: AsRef<[u8]>>(
	ui: &mut Ui<R>,
	h: &mut Handle,
	targets: &[S],
) -> i32 {
	let config = ui.config;
	if !trans_init(ui.out, config, h, config.flags, true) {
		return 1;
	}
	let mut retval = 0;
	for t in targets {
		if process_target(ui, h, t.as_ref(), retval != 0) == 1 {
			retval = 1;
		}
	}
	if retval != 0 {
		trans_release(ui.out, config, h);
		return retval;
	}
	if config.op_s_upgrade != 0 {
		if config.print == 0 {
			let msg = b"Starting full system upgrade...\n";
			colon_printf(&mut ui.out.stdout, &config.colstr, msg);
			let msg = b"starting full system upgrade\n";
			let _ = h.logaction(PACMAN_CALLER_PREFIX, msg);
		}
		if let Err(e) = sync_sysupgrade(h, config.op_s_upgrade >= 2) {
			let msg = [e.strerror().as_bytes(), b"\n"];
			error(ui.out, config, &msg);
			trans_release(ui.out, config, h);
			return 1;
		}
	}
	sync_prepare_execute(ui, h)
}

// print_broken_dep: a missing dependency of a target, or one an
// installed package loses through an upgrade or a removal
fn print_broken_dep<R>(ui: &mut Ui<R>, add: &[TransPkg], miss: &DepMissing) {
	let dep = dep_compute_string(&miss.depend);
	let target = &miss.target[..];
	let msg = match &miss.causingpkg {
		None => cat(&[
			b"unable to satisfy dependency '",
			&dep,
			b"' required by ",
			target,
			b"\n",
		]),
		Some(c) => {
			let add = add.iter().map(|t| &t.pkg);
			match pkg_find(add, c) {
				Some(p) => cat(&[
					b"installing ",
					c,
					b" (",
					opt(&p.version),
					b") breaks dependency '",
					&dep,
					b"' required by ",
					target,
					b"\n",
				]),
				None => cat(&[
					b"removing ",
					c,
					b" breaks dependency '",
					&dep,
					b"' required by ",
					target,
					b"\n",
				]),
			}
		}
	};
	colon_printf(&mut ui.out.stdout, &ui.config.colstr, &msg);
}

// the failure report of sync_prepare_execute
fn prepare_failed<R>(ui: &mut Ui<R>, h: &Handle, e: &PrepareError) {
	let msg = [
		b"failed to prepare transaction (",
		e.errno.strerror().as_bytes(),
		b")\n",
	];
	error(ui.out, ui.config, &msg);
	let cs = &ui.config.colstr;
	match &e.data {
		PrepareData::InvalidArch(pkgs) => {
			for p in pkgs {
				let msg = cat(&[
					b"package ",
					p,
					b" does not have a valid architecture\n",
				]);
				colon_printf(&mut ui.out.stdout, cs, &msg);
			}
		}
		PrepareData::Missing(misses) => {
			let add = trans_get_add(h).unwrap_or_default();
			for m in misses {
				print_broken_dep(ui, add, m);
			}
		}
		PrepareData::Conflicts(conflicts) => {
			for c in conflicts {
				let (p1, p2) = (&c.package1, &c.package2);
				let mut msg = cat(&[
					opt(&p1.name),
					b"-",
					opt(&p1.version),
					b" and ",
					opt(&p2.name),
					b"-",
					opt(&p2.version),
					b" are in conflict",
				]);
				// the reason only when it adds a version
				if c.reason.depmod != DepMod::Any {
					let reason =
						dep_compute_string(&c.reason);
					msg.extend(cat(&[
						b" (", &reason, b")",
					]));
				}
				msg.push(b'\n');
				colon_printf(&mut ui.out.stdout, cs, &msg);
			}
		}
		PrepareData::None => {}
	}
}

// the failure report of the commit in sync_prepare_execute
fn commit_failed<R>(ui: &mut Ui<R>, e: &CommitError) {
	let msg = [
		b"failed to commit transaction (",
		e.errno.strerror().as_bytes(),
		b")\n",
	];
	error(ui.out, ui.config, &msg);
	let err = &mut ui.out.stderr;
	match (e.errno, &e.data) {
		(Errno::FileConflicts, CommitData::FileConflicts(list)) => {
			for c in list {
				let (file, target) =
					(&c.file[..], &c.target[..]);
				let ctarget = &c.ctarget[..];
				let msg = match c.conflict_type {
					FileConflictType::Target => cat(&[
						file,
						b" exists in both '",
						target,
						b"' and '",
						ctarget,
						b"'\n",
					]),
					FileConflictType::Filesystem
						if !ctarget.is_empty() =>
					{
						cat(&[
							target,
							b": ",
							file,
							b" exists in filesystem \
							  (owned by ",
							ctarget,
							b")\n",
						])
					}
					FileConflictType::Filesystem => cat(&[
						target,
						b": ",
						file,
						b" exists in filesystem\n",
					]),
				};
				err.extend_from_slice(&msg);
			}
		}
		(
			Errno::PkgInvalid
			| Errno::PkgInvalidChecksum
			| Errno::PkgInvalidSig,
			CommitData::Invalid(files),
		) => {
			for f in files {
				let msg =
					[&f[..], b" is invalid or corrupted\n"];
				err.extend_from_slice(&msg.concat());
			}
		}
		_ => {}
	}
	let msg = b"Errors occurred, no packages were upgraded.\n";
	ui.out.stdout.extend_from_slice(msg);
}

// sync_prepare_execute: prepare, then nothing to do, --print, or the
// target list and the proceed question; a yes commits. the transaction
// is released at every end
pub fn sync_prepare_execute<R: BufRead>(ui: &mut Ui<R>, h: &mut Handle) -> i32 {
	let config = ui.config;
	let mut retval = match trans_prepare(h) {
		Err(e) => {
			prepare_failed(ui, h, &e);
			1
		}
		Ok(()) => match proceed(ui, h) {
			Some(r) => r,
			None => commit(ui, h),
		},
	};
	if !trans_release(ui.out, config, h) {
		retval = 1;
	}
	retval
}

// alpm_trans_commit with what came before it printed first
fn commit<R>(ui: &mut Ui<R>, h: &mut Handle) -> i32 {
	ui.out.flush();
	// completed package downloads move to the top of the bars
	ui.term.move_completed_up.store(true, Ordering::Relaxed);
	match trans_commit(h) {
		Ok(()) => 0,
		Err(e) => {
			commit_failed(ui, &e);
			1
		}
	}
}

// the steps after a successful prepare, None for a yes to proceed
fn proceed<R: BufRead>(ui: &mut Ui<R>, h: &Handle) -> Option<i32> {
	let config = ui.config;
	let add = trans_get_add(h).unwrap_or_default();
	if add.is_empty() {
		if config.print == 0 {
			ui.out.stdout.extend_from_slice(
				b" there is nothing to do\n",
			);
		}
		return Some(0);
	}
	let pkgs: Vec<DbPkg> = add.iter().map(|t| db_pkg(h, t)).collect();
	if config.print != 0 {
		let out = &mut ui.out.stdout;
		print_packages(
			out,
			config,
			&pkgs,
			h.cachedirs(),
			ui.format_date,
		);
		return Some(0);
	}
	let remove: Vec<&Package> =
		trans_get_remove(h).unwrap_or_default().iter().collect();
	let explicit_adds: Vec<&Package> = ui.explicit_adds.iter().collect();
	let explicit_removes: Vec<&Package> =
		ui.explicit_removes.iter().collect();
	let targets = TransTargets {
		add: &pkgs,
		remove: &remove,
		explicit_adds: &explicit_adds,
		explicit_removes: &explicit_removes,
	};
	display_targets(ui.out, config, &targets, &local_list(h), ui.cols);
	ui.out.stdout.push(b'\n');
	let msg: &[u8] = match config.op_s_downloadonly {
		0 => b"Proceed with installation?",
		_ => b"Proceed with download?",
	};
	match yesno(ui.out, config, ui.term, msg) {
		true => None,
		false => Some(1),
	}
}
