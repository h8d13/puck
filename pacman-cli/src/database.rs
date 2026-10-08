// port of src/pacman/database.c: -D --asdeps/--asexplicit (install reason
// of local packages) and -Dk/-Dkk (consistency of the local or the sync
// dbs: missing files, dependencies, conflicts, files owned twice)
//
// config->handle is the Handle passed in. output goes into an Output like
// query.rs, pm_printf filtered by the config's logmask; messages are the
// untranslated msgids. the C getters' lazy loads happen up front
// (desc before the dependency and conflict checks, files before the file
// list check); checkdeps and checkconflicts log through the handle's
// callbacks.
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use alpm_core::be_local::{INFRQ_DESC, INFRQ_FILES};
use alpm_core::callbacks::Callbacks;
use alpm_core::conflict::checkconflicts;
use alpm_core::db::Db;
use alpm_core::deps::{
	DbPkgs, DepsEnv, DepsOpts, checkdeps, dep_compute_string,
};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::package::{Package, PkgReason};
use alpm_core::pkghash::PkgHash;
use alpm_core::trans::{TRANS_FLAG_ALLDEPS, TRANS_FLAG_ALLEXPLICIT};
use alpm_core::util::{strerror, until_nul};

use crate::conf::{Config, LOG_ERROR};
use crate::util::{Output, pm_printf, trans_init, trans_release};

fn os(path: &[u8]) -> &Path {
	Path::new(OsStr::from_bytes(path))
}

fn error(o: &mut Output, config: &Config, parts: &[&[u8]]) {
	pm_printf(&mut o.stderr, config, LOG_ERROR, &parts.concat());
}

// access(path, F_OK): stat follows symlinks the same way
fn exists(path: &[u8]) -> bool {
	fs::metadata(os(path)).is_ok()
}

// change_install_reason: 0 when every target got the reason
fn change_install_reason(
	config: &Config,
	handle: &mut Handle,
	targets: &[Vec<u8>],
	o: &mut Output,
) -> i32 {
	if targets.is_empty() {
		let msg: &[u8] = b"no targets specified (use -h for help)\n";
		error(o, config, &[msg]);
		return 1;
	}
	let reason = if config.flags & TRANS_FLAG_ALLDEPS != 0 {
		PkgReason::Depend
	} else if config.flags & TRANS_FLAG_ALLEXPLICIT != 0 {
		PkgReason::Explicit
	} else {
		let msg = b"no install reason specified (use -h for help)\n";
		error(o, config, &[msg]);
		return 1;
	};
	// lock database
	if !trans_init(o, config, handle, 0, false) {
		return 1;
	}
	let mut ret = 0;
	for target in targets {
		let name = until_nul(target);
		let dbs = handle.dbs_mut();
		// a handle always has its local db until unregistered
		let r = match dbs.local {
			Some(db) => {
				db.set_reason(dbs.dbext, dbs.cb, name, reason)
			}
			None => Err(Errno::DbNotFound),
		};
		if let Err(e) = r {
			let msg: [&[u8]; 5] = [
				b"could not set install reason for package ",
				name,
				b" (",
				e.strerror().as_bytes(),
				b")\n",
			];
			error(o, config, &msg);
			ret = 1;
			continue;
		}
		if config.quiet == 0 {
			let what: &[u8] = match reason {
				PkgReason::Depend => b"installed as dependency",
				_ => b"explicitly installed",
			};
			o.stdout.extend_from_slice(
				&[
					name,
					b": install reason has been set to '",
					what,
					b"'\n",
				]
				.concat(),
			);
		}
	}
	// unlock database
	if !trans_release(o, config, handle) {
		return 1;
	}
	ret
}

// check_db_missing_deps: alpm_checkdeps(handle, NULL, NULL, pkglist, 0),
// every depend of pkglist satisfied within pkglist or assumeinstalled.
// local is the loaded local cache, None the C's NULL list
fn check_db_missing_deps(
	config: &Config,
	opts: DepsOpts,
	local: Option<&PkgHash<Package>>,
	pkglist: &[&Package],
	cb: &mut dyn Callbacks,
	o: &mut Output,
) -> i32 {
	let empty = PkgHash::new(0).expect("empty table");
	let env = DepsEnv {
		opts,
		// no transaction: ALPM_TRANS_FLAG_NODEPVERSION unset
		nodepversion: false,
		local: DbPkgs {
			usage: 0,
			cache: local.unwrap_or(&empty),
			name: b"local",
		},
		sync: &[],
	};
	let missing = checkdeps(&env, &[], &[], pkglist, false, cb);
	for miss in &missing {
		let depstring = dep_compute_string(&miss.depend);
		let msg: [&[u8]; 5] = [
			b"missing '",
			&depstring,
			b"' dependency for '",
			&miss.target,
			b"'\n",
		];
		error(o, config, &msg);
	}
	i32::from(!missing.is_empty())
}

// check_db_local_files: every entry of "<dbpath>local" but the version
// file needs a desc and a files, in readdir order
fn check_db_local_files(
	config: &Config,
	handle: &Handle,
	o: &mut Output,
) -> i32 {
	let dbpath = handle.dbpath();
	let path = [dbpath, b"local"].concat();
	let dir = match fs::read_dir(os(&path)) {
		Ok(dir) => dir,
		Err(e) => {
			let msg: [&[u8]; 5] = [
				b"could not open local database directory ",
				&path,
				b": ",
				&strerror(&e),
				b"\n",
			];
			error(o, config, &msg);
			return 1;
		}
	};
	let mut ret = 0;
	// readdir stops at the first error, "." and ".." never come out
	for ent in dir.map_while(Result::ok) {
		let name = ent.file_name();
		let name = name.as_bytes();
		if name == b"ALPM_DB_VERSION" {
			continue;
		}
		let entry = [dbpath, b"local/", name, b"/"].concat();
		if !exists(&[&entry[..], b"desc"].concat()) {
			let msg: [&[u8]; 3] = [
				b"'",
				name,
				b"': description file is missing\n",
			];
			error(o, config, &msg);
			ret = 1;
		}
		if !exists(&[&entry[..], b"files"].concat()) {
			let msg: [&[u8]; 3] =
				[b"'", name, b"': file list is missing\n"];
			error(o, config, &msg);
			ret = 1;
		}
	}
	ret
}

// check_db_local_package_conflicts: alpm_checkconflicts on pkglist
fn check_db_local_package_conflicts(
	config: &Config,
	pkglist: &[&Package],
	cb: &mut dyn Callbacks,
	o: &mut Output,
) -> i32 {
	let conflicts = checkconflicts(pkglist, cb);
	for c in &conflicts {
		let msg: [&[u8]; 5] = [
			b"'",
			c.package1.name_bytes(),
			b"' conflicts with '",
			c.package2.name_bytes(),
			b"'\n",
		];
		error(o, config, &msg);
	}
	i32::from(!conflicts.is_empty())
}

// check_db_local_filelist_conflicts: the files (no directories) of all
// packages sorted by name (glibc's qsort merge sorts: stable like
// sort_by), each name equal to the one before reported with both owners.
// an empty name counts as a file, the C reads the byte before it
fn check_db_local_filelist_conflicts(
	config: &Config,
	pkglist: &[&Package],
	o: &mut Output,
) -> i32 {
	let mut all: Vec<(&[u8], &Package)> = Vec::new();
	for &pkg in pkglist {
		for f in &pkg.files.files {
			let name = f.name();
			if name.last() != Some(&b'/') {
				all.push((name, pkg));
			}
		}
	}
	all.sort_by(|a, b| a.0.cmp(b.0));
	let mut ret = 0;
	for w in all.windows(2) {
		let ((prev, prev_pkg), (name, pkg)) = (w[0], w[1]);
		if prev != name {
			continue;
		}
		let msg: [&[u8]; 7] = [
			b"file owned by '",
			prev_pkg.name_bytes(),
			b"' and '",
			pkg.name_bytes(),
			b"': '",
			name,
			b"'\n",
		];
		error(o, config, &msg);
		ret = 1;
	}
	ret
}

// the local cache with the sections of inforeq loaded, borrowed in
// place. a cache that does not load is the C's NULL list
fn local_cache<'h>(
	local: Option<&'h mut Db>,
	dbext: &[u8],
	cb: &mut dyn Callbacks,
	inforeq: i32,
) -> Option<&'h PkgHash<Package>> {
	local?.load_all(dbext, cb, inforeq).ok()
}

fn list(cache: Option<&PkgHash<Package>>) -> Vec<&Package> {
	cache.map(|c| c.iter().collect()).unwrap_or_default()
}

// check_db_local: the file check first, it stops everything else
fn check_db_local(config: &Config, handle: &mut Handle, o: &mut Output) -> i32 {
	let ret = check_db_local_files(config, handle, o);
	if ret != 0 {
		return ret;
	}
	let dbs = handle.dbs_mut();
	let cache = local_cache(dbs.local, dbs.dbext, dbs.cb, INFRQ_DESC);
	let pkglist = list(cache);
	let (opts, cb) = (dbs.opts, dbs.cb);
	let mut ret =
		check_db_missing_deps(config, opts, cache, &pkglist, cb, o);
	ret += check_db_local_package_conflicts(config, &pkglist, cb, o);
	let dbs = handle.dbs_mut();
	let cache = local_cache(dbs.local, dbs.dbext, dbs.cb, INFRQ_FILES);
	ret + check_db_local_filelist_conflicts(config, &list(cache), o)
}

// check_db_sync: the dependencies of every sync package, all dbs joined
// in registration order
fn check_db_sync(config: &Config, handle: &mut Handle, o: &mut Output) -> i32 {
	let dbs = handle.dbs_mut();
	let mut pkglist: Vec<&Package> = Vec::new();
	for db in dbs.sync {
		if let Ok(cache) = db.pkgcache(dbs.dbext, dbs.cb) {
			pkglist.extend(cache.iter());
		}
	}
	let local = dbs.local.as_deref().and_then(Db::loaded_pkgcache);
	check_db_missing_deps(config, dbs.opts, local, &pkglist, dbs.cb, o)
}

// pacman_database: -Dk (op_q_check 1) or -Dkk, then the reason change
// when --asdeps/--asexplicit is given (its result wins)
pub fn pacman_database(
	config: &Config,
	handle: &mut Handle,
	targets: &[Vec<u8>],
	o: &mut Output,
) -> i32 {
	let mut ret = 0;
	if config.op_q_check != 0 {
		ret = match config.op_q_check {
			1 => check_db_local(config, handle, o),
			_ => check_db_sync(config, handle, o),
		};
		if ret == 0 && config.quiet == 0 {
			let msg = b"No database errors have been found!\n";
			o.stdout.extend_from_slice(msg);
		}
	}
	if config.flags & (TRANS_FLAG_ALLDEPS | TRANS_FLAG_ALLEXPLICIT) != 0 {
		ret = change_install_reason(config, handle, targets, o);
	}
	ret
}
