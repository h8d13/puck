// port of src/pacman/sync.c: -Si/-Sii (sync_info), -Sl (sync_list),
// -Sg/-Sgg (sync_group), -Sy/-Syy (util.c's sync_syncdbs, shared with
// -Fy), the pacman_sync dispatch up to them, util.c's check_syncdbs they
// rely on, and the transaction of -S/-Su up to the commit (sync_trans,
// sync_prepare_execute, also run by -U)
//
// the C prints to stdout and through pm_printf to stderr, both go into an
// Output. config is the C global, handle config->handle; cols is what
// getcols() gives -Si (COLUMNS or the terminal width, 0 when neither).
// packages shown are copies of the cache entries: the displays read the
// local db and every sync db cache, which Handle only lends out one at a
// time. messages are the untranslated msgids.
//
// what -Sy prints comes from the frontend callbacks (callback.c) during
// alpm_db_update. callback.rs is not on this base: SyncCallbacks stands
// in for the parts -Sy reaches and is swapped into the handle for the
// call. it draws no progress bars, the display is --noprogressbar's (or
// a pipe's) whatever the terminal.
//
// not ported, returned as Unported where pacman_sync reaches them: -Sc
// (trans_init takes the db lock, then interactive prompts and unlinks
// in the cache dirs) and -Ss (db search). the transaction is sync_trans,
// which ends in Prepared::Commit where the C calls alpm_trans_commit;
// pacman_sync still returns Unported::Transaction for it until the
// dispatch takes a Ui.

use std::cell::RefCell;
use std::fs::File;
use std::io::BufRead;
use std::os::unix::ffi::OsStrExt;
use std::rc::Rc;

use alpm_core::add::add_pkg;
use alpm_core::be_sync::{db_update, get_validation};
use alpm_core::callbacks::{Callbacks, DownloadEvent, LogLevel};
use alpm_core::db::{DB_USAGE_INSTALL, Db};
use alpm_core::deps::{DepMissing, DepMod, dep_compute_string};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::package::{DbCaches, Package, pkg_find};
use alpm_core::sync::{dbs_satisfier, find_group_pkgs, sync_sysupgrade};
use alpm_core::trans::{
	PrepareData, PrepareError, TransPkg, trans_get_add, trans_get_remove,
	trans_prepare,
};
use alpm_core::util::until_nul;

use crate::conf::{
	Config, LOG_DEBUG, LOG_ERROR, LOG_FUNCTION, LOG_WARNING, cat,
};
use crate::package::{FileProbe, PkgEnv, dump_pkg_full, print_installed};
use crate::util::{
	DbPkg, Output, Prepared, SigResult, TransTargets, Ui, check_syncdbs,
	colon_printf, display_targets, multiselect_question, pm_printf,
	print_packages, select_display, trans_init, trans_release, yesno,
};

// a pacman_sync/pacman_files branch this port does not have yet
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unported {
	// -Sc/-Scc: sync_cleancache, sync_cleandb_all
	Clean,
	// -Ss: sync_search
	Search,
	// sync_trans: -S <targets>, -Su
	Transaction,
}

pub(crate) fn error(out: &mut Output, config: &Config, msg: &[&[u8]]) {
	pm_printf(&mut out.stderr, config, LOG_ERROR, &cat(msg));
}

// alpm_db_get_pkgcache as the C list: empty when the cache cannot load
pub(crate) fn cache_list<'a>(db: &'a mut Db, dbext: &[u8]) -> Vec<&'a Package> {
	db.pkgcache(dbext)
		.map(|c| c.iter().collect())
		.unwrap_or_default()
}

// what dump_pkg_full asks of libalpm for a sync package of db_name
struct SyncEnv<'a> {
	handle: &'a mut Handle,
	dbext: Vec<u8>,
	db_name: Vec<u8>,
	config: &'a Config,
	stderr: Vec<u8>,
}

impl DbCaches for SyncEnv<'_> {
	fn local_cache(&mut self) -> Vec<&Package> {
		match self.handle.localdb_mut() {
			Some(db) => cache_list(db, &self.dbext),
			None => Vec::new(),
		}
	}

	fn sync_caches(&mut self) -> Vec<Vec<&Package>> {
		let dbext = &self.dbext;
		self.handle
			.syncdbs_mut()
			.iter_mut()
			.map(|db| cache_list(db, dbext))
			.collect()
	}
}

impl PkgEnv for SyncEnv<'_> {
	fn db_name(&mut self, _: &Package) -> Option<Vec<u8>> {
		Some(self.db_name.clone())
	}

	// alpm_decode_signature, then alpm_extract_keyid on the packets.
	// extract_keyid is not ported yet (signing.c), so no keys. the C
	// lists none either where the base64 does not decode
	fn sig_keys(&mut self, _: &Package, _: &[u8]) -> Vec<Vec<u8>> {
		Vec::new()
	}

	// file packages only, -Si never shows one
	fn check_signature(
		&mut self,
		_: &Package,
	) -> Result<Vec<SigResult>, Errno> {
		Err(Errno::SigMissing)
	}

	fn root(&mut self) -> Vec<u8> {
		self.handle.root().to_vec()
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
}

// dump_pkg_full of a copy of a cache entry of sync db db
fn show_full(
	config: &Config,
	handle: &mut Handle,
	db: usize,
	mut pkg: Package,
	cols: u16,
	out: &mut Output,
) {
	// what alpm_pkg_get_validation computes on first use
	pkg.validation = get_validation(&pkg);
	let mut env = SyncEnv {
		dbext: handle.dbext().to_vec(),
		db_name: handle.syncdbs()[db].name().to_vec(),
		handle,
		config,
		stderr: Vec::new(),
	};
	let extra = config.op_s_info > 1;
	let colstr = &config.colstr;
	dump_pkg_full(&mut out.stdout, &mut env, &pkg, extra, cols, colstr);
	out.stderr.extend(env.stderr);
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
	let dbext = handle.dbext().to_vec();
	if targets.is_empty() {
		let mut ret = 1;
		let mut seen: Vec<Vec<u8>> = Vec::new();
		for db in handle.syncdbs_mut() {
			let groups = db.groupcache(&dbext).unwrap_or_default();
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
		for db in handle.syncdbs_mut() {
			// an empty name is WrongArgs: no group either
			let Ok(Some(grp)) = db.get_group(&dbext, grpname)
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
	let dbext = handle.dbext().to_vec();
	let ndbs = handle.syncdbs().len();
	if targets.is_empty() {
		for i in 0..ndbs {
			let db = &mut handle.syncdbs_mut()[i];
			let pkgs: Vec<Package> = cache_list(db, &dbext)
				.into_iter()
				.cloned()
				.collect();
			for pkg in pkgs {
				show_full(config, handle, i, pkg, cols, out);
			}
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
			let db = &mut handle.syncdbs_mut()[i];
			if repo.is_some_and(|r| r != db.name()) {
				continue;
			}
			founddb = true;
			let pkg = cache_list(db, &dbext)
				.into_iter()
				.find(|p| p.name_bytes() == pkgstr)
				.cloned();
			if let Some(pkg) = pkg {
				show_full(config, handle, i, pkg, cols, out);
				foundpkg = true;
			}
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

	let dbext = handle.dbext().to_vec();
	let c = &config.colstr;
	for i in ls.into_iter().flatten() {
		let (mut localdb, syncdbs) = handle.dbs_mut();
		let db = &mut syncdbs[i];
		let name = db.name().to_vec();
		for pkg in cache_list(db, &dbext) {
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
				l.get_pkg(&dbext, pkg.name_bytes()).ok()
			});
			print_installed(&mut out.stdout, local, pkg, c);
			out.stdout.push(b'\n');
		}
	}
	ret
}

// pacman_sync: the read-only operations, Err for the branches not ported
// (in the order the C reaches them). Ok is the C return value
pub fn pacman_sync<S: AsRef<[u8]>>(
	config: &Config,
	handle: &mut Handle,
	targets: &[S],
	cols: u16,
	out: &mut Output,
) -> Result<i32, Unported> {
	if config.op_s_clean != 0 {
		return Err(Unported::Clean);
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
		return Err(Unported::Search);
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
	Err(Unported::Transaction)
}

// pm_vfprintf/pm_vasprintf to stderr: logmask filter, the level's prefix
fn log_line(err: &mut Vec<u8>, config: &Config, level: u16, msg: &[u8]) {
	let prefix: &[u8] = match level {
		LOG_ERROR | LOG_WARNING => {
			return pm_printf(err, config, level, msg);
		}
		LOG_DEBUG => b"debug: ",
		LOG_FUNCTION => b"function: ",
		_ => b"",
	};
	if config.logmask & level != 0 {
		err.extend(cat(&[prefix, msg]));
	}
}

// clean_filename: cut at the first ".pkg", else ".db", else ".files"
fn clean_filename(name: &[u8]) -> &[u8] {
	let find = |n: &[u8]| name.windows(n.len()).position(|w| w == n);
	let cut = find(b".pkg")
		.or_else(|| find(b".db"))
		.or_else(|| find(b".files"));
	&name[..cut.unwrap_or(name.len())]
}

// the callback.c handlers alpm_db_update reaches: cb_log, cb_download
// without progress bars. cb_event prints nothing for it (the
// DATABASE_MISSING warning is off under -y); cb_log's buffering between
// DB_RETRIEVE_START and DONE/FAILED only orders stderr against stdout,
// which go to separate buffers here
struct SyncCallbacks {
	config: Config,
	out: Rc<RefCell<Output>>,
}

impl Callbacks for SyncCallbacks {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		if msg.is_empty() {
			return;
		}
		let err = &mut self.out.borrow_mut().stderr;
		log_line(err, &self.config, level as u16, msg);
	}

	fn download(&mut self, filename: &[u8], event: DownloadEvent) {
		// no progress for signature files
		if filename.ends_with(b".sig") {
			return;
		}
		if let DownloadEvent::Init { .. } = event {
			let name = clean_filename(filename);
			let line = cat(&[b" ", name, b" downloading...\n"]);
			self.out.borrow_mut().stdout.extend(line);
		}
	}
}

// sync_syncdbs(level, every sync db): alpm_db_update, forced from -yy.
// false (C 0) when it failed, after the error line
pub fn sync_syncdbs(
	config: &Config,
	handle: &mut Handle,
	level: u16,
	out: &mut Output,
) -> bool {
	let shared = Rc::new(RefCell::new(std::mem::take(out)));
	let cb = SyncCallbacks {
		config: config.clone(),
		out: shared.clone(),
	};
	let old = handle.replace_callbacks(Box::new(cb));
	let dbs: Vec<usize> = (0..handle.syncdbs().len()).collect();
	let ret = db_update(handle, &dbs, level >= 2);
	drop(handle.replace_callbacks(old));
	*out = shared.take();
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
	let dbext = h.dbext().to_vec();
	dbs.iter().any(|&i| {
		let db = &mut h.syncdbs_mut()[i];
		matches!(db.get_group(&dbext, name), Ok(Some(_)))
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
	select_display(&mut ui.out.stdout, cs, &shown, ui.cols);
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
) -> Prepared {
	let config = ui.config;
	if !trans_init(ui.out, config, h, config.flags, true) {
		return Prepared::Done(1);
	}
	let mut retval = 0;
	for t in targets {
		if process_target(ui, h, t.as_ref(), retval != 0) == 1 {
			retval = 1;
		}
	}
	if retval != 0 {
		trans_release(ui.out, config, h);
		return Prepared::Done(retval);
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
			return Prepared::Done(1);
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

// sync_prepare_execute: prepare, then nothing to do, --print, or the
// target list and the proceed question. a yes is Prepared::Commit with
// the transaction still held; every other end releases it
pub fn sync_prepare_execute<R: BufRead>(
	ui: &mut Ui<R>,
	h: &mut Handle,
) -> Prepared {
	let config = ui.config;
	let mut retval = match trans_prepare(h) {
		Err(e) => {
			prepare_failed(ui, h, &e);
			1
		}
		Ok(()) => match proceed(ui, h) {
			Some(r) => r,
			None => return Prepared::Commit,
		},
	};
	if !trans_release(ui.out, config, h) {
		retval = 1;
	}
	Prepared::Done(retval)
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
