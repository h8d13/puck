// port of the read-only part of src/pacman/sync.c: -Si/-Sii (sync_info),
// -Sl (sync_list), -Sg/-Sgg (sync_group), -Sy/-Syy (util.c's
// sync_syncdbs, shared with -Fy), the pacman_sync dispatch up to them,
// and util.c's check_syncdbs they rely on
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
// in the cache dirs), -Ss (db search) and the transaction of
// -S <targets>/-Su.

use std::cell::RefCell;
use std::rc::Rc;

use alpm_core::be_sync::{db_update, get_validation};
use alpm_core::callbacks::{Callbacks, DownloadEvent, LogLevel};
use alpm_core::db::Db;
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::package::{DbCaches, Package};
use alpm_core::util::until_nul;

use crate::conf::{
	Config, LOG_DEBUG, LOG_ERROR, LOG_FUNCTION, LOG_WARNING, cat,
};
use crate::package::{FileProbe, PkgEnv, dump_pkg_full, print_installed};
use crate::util::{Output, SigResult, check_syncdbs, pm_printf};

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
