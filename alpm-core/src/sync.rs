// port of the planning part of lib/libalpm/sync.c: alpm_sync_get_new_version,
// alpm_sync_sysupgrade (check_literal, check_replacers),
// alpm_find_group_pkgs, compute_download_size/alpm_pkg_download_size and
// _alpm_sync_prepare (with the db checks run before its caches load), and
// the handle-level entry of alpm_find_dbs_satisfier the frontend uses;
// then the commit side: _alpm_sync_load (download_files, check_keyring,
// check_validity, load_packages), _alpm_sync_check and _alpm_sync_commit.
//
// targets are TransPkg copies of the cache entries (trans.rs). the
// resolver works on references into those copies and the sync caches;
// its results are matched back by address like the C pointers.

use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::ptr;

use std::ffi::c_int;

use crate::be_local::{INFRQ_DSIZE, INFRQ_FILES};
use crate::be_package::{self, pkg_validate};
use crate::callbacks::{Callbacks, Event, LogLevel, Progress, Question, logv};
use crate::conflict::{
	Conflict, FileCheck, FileConflict, add_conflict, check_conflict,
	innerconflicts,
};
use crate::db::{DB_USAGE_INSTALL, DB_USAGE_UPGRADE, Db};
use crate::deps::{
	DepMissing, Depend, checkdeps, dep_from_string, depcmp, depcmp_literal,
	find_dbs_satisfier, find_dep_satisfier, list_diff, resolvedeps,
};
use crate::diskspace::{System, check_diskspace, check_downloadspace};
use crate::dload::Payload;
use crate::error::Errno;
use crate::handle::Handle;
use crate::package::{
	Package, PkgFrom, PkgReason, pkg_compare_versions, pkg_find,
	pkg_should_ignore,
};
use crate::pkghash::PkgHash;
use crate::signing::{
	SIG_PACKAGE, SIG_PACKAGE_MARGINAL_OK, SIG_PACKAGE_OPTIONAL,
	SIG_PACKAGE_UNKNOWN_OK, decode_signature, extract_keyid, key_import,
	key_in_keychain, process_siglist, sigpath,
};
use crate::trans::{
	CommitData, CommitError, PrepareData, PrepareError, TRANS_FLAG_DBONLY,
	TRANS_FLAG_DOWNLOADONLY, TRANS_FLAG_NEEDED, TRANS_FLAG_NOCONFLICTS,
	TRANS_FLAG_NODEPS, TRANS_FLAG_NODEPVERSION, Trans, TransPkg,
	TransState, View, load_caches, load_local_descs, opt_str, pkg_dup,
	readable, trans_in, with_view,
};
use crate::util::{
	ReadFileError, filecache_find, filecache_setup, get_fullpath,
	read_file, until_nul,
};
use crate::{add, remove};

use LogLevel::{Debug, Error, Warning};

fn name(p: &Package) -> &[u8] {
	opt_str(&p.name)
}

fn ver(p: &Package) -> &[u8] {
	opt_str(&p.version)
}

// alpm_pkg_find over targets
fn find_target<'t>(list: &'t [TransPkg], name: &[u8]) -> Option<&'t TransPkg> {
	let i = position(list, name)?;
	Some(&list[i])
}

fn position(list: &[TransPkg], name: &[u8]) -> Option<usize> {
	let found = pkg_find(list.iter().map(|t| &t.pkg), name)?;
	list.iter().position(|t| ptr::eq(&t.pkg, found))
}

// alpm_sync_get_new_version over the handle's sync dbs: the package of
// pkg's name in the first db holding one, with its db, when newer
pub fn sync_get_new_version(
	h: &mut Handle,
	pkg: &Package,
) -> Option<(usize, Package)> {
	let dbs = h.dbs_mut();
	let (dbext, cb) = (dbs.dbext, dbs.cb);
	let found = dbs.sync.iter_mut().enumerate().find_map(|(i, db)| {
		let spkg = db.get_pkg(dbext, cb, pkg.name_bytes()).ok()?;
		Some((i, spkg.clone()))
	});
	let cb = h.callbacks();
	let Some((i, spkg)) = found else {
		let msg = [
			b"'",
			name(pkg),
			b"' not found in sync db => no upgrade\n",
		];
		logv(cb, Debug, &msg);
		return None;
	};
	if pkg_compare_versions(&spkg, pkg) != Ordering::Greater {
		return None;
	}
	let msg = [
		b"new version of '",
		name(pkg),
		b"' found (",
		ver(pkg),
		b" => ",
		ver(&spkg),
		b")\n",
	];
	logv(cb, Debug, &msg);
	Some((i, spkg))
}

fn ignored(h: &Handle, a: &Package, b: &Package) -> bool {
	pkg_should_ignore(h, a) || pkg_should_ignore(h, b)
}

// check_literal (static in C): spkg of sdb_name replaces lpkg when newer
// (or older with enable_downgrade) and neither is ignored
fn check_literal(
	view: &View,
	cb: &mut dyn Callbacks,
	lpkg: &Package,
	spkg: &Package,
	sdb_name: &[u8],
	enable_downgrade: bool,
) -> bool {
	let h = view.handle;
	let change = [name(lpkg), b": "].concat();
	let versions: [&[u8]; 4] = [ver(lpkg), b" => ", ver(spkg), b")\n"];
	match pkg_compare_versions(spkg, lpkg) {
		Ordering::Greater => {
			let msg = [
				b"new version of '",
				name(lpkg),
				b"' found (",
				ver(lpkg),
				b" => ",
				ver(spkg),
				b")\n",
			];
			logv(cb, Debug, &msg);
			if ignored(h, spkg, lpkg) {
				let head: [&[u8]; 2] = [
					&change,
					b"ignoring package upgrade (",
				];
				logv(
					cb,
					Warning,
					&[&head[..], &versions].concat(),
				);
				return false;
			}
			let msg = [
				b"adding package ",
				name(spkg),
				b"-",
				ver(spkg),
				b" to the transaction targets\n",
			];
			logv(cb, Debug, &msg);
			true
		}
		Ordering::Less if enable_downgrade => {
			if ignored(h, spkg, lpkg) {
				let head: [&[u8]; 2] = [
					&change,
					b"ignoring package downgrade (",
				];
				logv(
					cb,
					Warning,
					&[&head[..], &versions].concat(),
				);
				return false;
			}
			let msg = [
				&change[..],
				b"downgrading from version ",
				ver(lpkg),
				b" to version ",
				ver(spkg),
				b"\n",
			];
			logv(cb, Warning, &msg);
			true
		}
		Ordering::Less => {
			let msg = [
				&change[..],
				b"local (",
				ver(lpkg),
				b") is newer than ",
				sdb_name,
				b" (",
				ver(spkg),
				b")\n",
			];
			logv(cb, Warning, &msg);
			false
		}
		Ordering::Equal => false,
	}
}

// check_replacers (static in C): the packages of sync db sdb whose
// replaces name lpkg literally, after the REPLACE_PKG question. one
// already a target takes lpkg into its removes (when from the same db),
// the others come back as new targets with lpkg's reason
fn check_replacers(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
	lpkg: &Package,
	sdb: usize,
) -> Vec<TransPkg> {
	let db = &view.handle.syncdbs()[sdb];
	let msg = [
		b"searching for replacements for ",
		name(lpkg),
		b" in ",
		db.name(),
		b"\n",
	];
	logv(cb, Debug, &msg);
	let mut replacers = Vec::new();
	for spkg in view.sync[sdb].cache.iter() {
		if !spkg.replaces.iter().any(|r| depcmp_literal(lpkg, r)) {
			continue;
		}
		if ignored(view.handle, spkg, lpkg) {
			let msg = [
				b"ignoring package replacement (",
				name(lpkg),
				b"-",
				ver(lpkg),
				b" => ",
				name(spkg),
				b"-",
				ver(spkg),
				b")\n",
			];
			logv(cb, Warning, &msg);
			continue;
		}
		let mut q = Question::ReplacePkg {
			replace: 0,
			oldpkg: lpkg,
			newpkg: spkg,
			newdb: db,
		};
		cb.question(&mut q);
		if q.answer() == 0 {
			continue;
		}
		if let Some(i) = position(&trans.add, spkg.name_bytes()) {
			let tpkg = &mut trans.add[i];
			// a file target (no db) never matches, like the C's
			// origin_data union
			if tpkg.db != Some(sdb) {
				let msg = [
					b"cannot replace ",
					name(lpkg),
					b" by ",
					name(spkg),
					b"\n",
				];
				logv(cb, Warning, &msg);
				continue;
			}
			let msg = [
				b"appending ",
				name(lpkg),
				b" to the removes list of ",
				name(&tpkg.pkg),
				b"\n",
			];
			logv(cb, Debug, &msg);
			tpkg.removes.push(lpkg.clone());
			if lpkg.reason == PkgReason::Explicit {
				tpkg.pkg.reason = PkgReason::Explicit;
			}
		} else {
			let mut t = TransPkg::new(spkg.clone(), Some(sdb));
			t.pkg.reason = lpkg.reason;
			t.removes.push(lpkg.clone());
			let msg = [
				b"adding package ",
				name(spkg),
				b"-",
				ver(spkg),
				b" to the transaction targets\n",
			];
			logv(cb, Debug, &msg);
			replacers.push(t);
		}
	}
	replacers
}

// alpm_sync_sysupgrade: every local package not already a target is
// checked against the sync dbs used for upgrades in order: the first db
// with replacers for it adds them, else the first db holding its name
// decides through check_literal
pub fn sync_sysupgrade(
	h: &mut Handle,
	enable_downgrade: bool,
) -> Result<(), Errno> {
	trans_in(h, TransState::Initialized)?;
	load_caches(h, true);
	let mut trans = h.set_trans(None).expect("checked above");
	with_view(h, |view, cb| {
		sysupgrade(view, cb, &mut trans, enable_downgrade);
	});
	h.set_trans(Some(trans));
	Ok(())
}

fn sysupgrade(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
	enable_downgrade: bool,
) {
	logv(cb, Debug, &[b"checking for package upgrades\n"]);
	for lpkg in view.local.iter() {
		let n = lpkg.name_bytes();
		if pkg_find(&trans.remove, n).is_some() {
			let msg = [
				name(lpkg),
				b" is marked for removal -- skipping\n",
			];
			logv(cb, Debug, &msg);
			continue;
		}
		if find_target(&trans.add, n).is_some() {
			let msg = [
				name(lpkg),
				b" is already in the target list -- skipping\n",
			];
			logv(cb, Debug, &msg);
			continue;
		}
		for (j, sdb) in view.sync.iter().enumerate() {
			if sdb.usage & DB_USAGE_UPGRADE == 0 {
				continue;
			}
			let replacers =
				check_replacers(view, cb, trans, lpkg, j);
			if !replacers.is_empty() {
				trans.add.extend(replacers);
				break;
			}
			let Some(spkg) = sdb.cache.find(n) else {
				continue;
			};
			let dbname = view.handle.syncdbs()[j].name();
			if check_literal(
				view,
				cb,
				lpkg,
				spkg,
				dbname,
				enable_downgrade,
			) {
				trans.add.push(TransPkg::new(
					spkg.clone(),
					Some(j),
				));
			}
			break;
		}
	}
}

// alpm_find_group_pkgs over the sync dbs at positions dbs: the members
// of group name in db order, each name once. with NEEDED (and a
// transaction) members as new as the installed package are skipped;
// ignored ones only with a yes to INSTALL_IGNOREPKG. a name skipped or
// asked about is not looked at again in later dbs
pub fn find_group_pkgs(
	h: &mut Handle,
	dbs: &[usize],
	group: &[u8],
) -> Vec<TransPkg> {
	let mut members = Vec::new();
	for &i in dbs {
		let d = h.dbs_mut();
		let Some(db) = d.sync.get_mut(i) else {
			continue;
		};
		if let Ok(Some(grp)) = db.get_group(d.dbext, d.cb, group) {
			for p in grp.packages {
				members.push(TransPkg::new(p.clone(), Some(i)));
			}
		}
	}
	let needed =
		h.trans().is_some_and(|t| t.flags & TRANS_FLAG_NEEDED != 0);
	load_caches(h, false);
	with_view(h, |view, cb| {
		let mut ignorelist: Vec<&Package> = Vec::new();
		let mut pkgs: Vec<TransPkg> = Vec::new();
		for t in &members {
			let pkg = &t.pkg;
			if pkg_find(
				ignorelist.iter().copied(),
				pkg.name_bytes(),
			)
			.is_some()
			{
				continue;
			}
			let local = view.local.find(pkg.name_bytes());
			if let Some(local) = local.filter(|l| {
				needed && pkg_compare_versions(pkg, l).is_eq()
			}) {
				let msg = [
					name(local),
					b"-",
					ver(local),
					b" is up to date -- skipping\n",
				];
				logv(cb, Warning, &msg);
				ignorelist.push(pkg);
				continue;
			}
			if pkg_should_ignore(view.handle, pkg) {
				ignorelist.push(pkg);
				let mut q = Question::InstallIgnorepkg {
					install: 0,
					pkg,
				};
				cb.question(&mut q);
				if q.answer() == 0 {
					continue;
				}
			}
			if find_target(&pkgs, pkg.name_bytes()).is_none() {
				pkgs.push(t.clone());
			}
		}
		pkgs
	})
}

// compute_download_size (static in C): what is left to download of a
// sync package (0 when cached, size minus a cached .part), stored with
// INFRQ_DSIZE. other origins download nothing. Ok(true) is a partial
// (C 1); a sync package without filename is PkgInvalidName
pub fn compute_download_size(
	h: &Handle,
	cb: &mut dyn Callbacks,
	newpkg: &mut Package,
) -> Result<bool, Errno> {
	if newpkg.origin != Some(PkgFrom::SyncDb) {
		newpkg.infolevel |= INFRQ_DSIZE;
		newpkg.download_size = 0;
		return Ok(false);
	}
	let fname = newpkg.filename.as_deref().ok_or(Errno::PkgInvalidName)?;
	let fname = until_nul(fname).to_vec();
	let mut partial = false;
	let size = if filecache_find(h.cachedirs(), &fname, cb).is_some() {
		0
	} else {
		let part = [&fname[..], b".part"].concat();
		match filecache_find(h.cachedirs(), &part, cb) {
			Some(path) => {
				partial = true;
				match fs::metadata(OsStr::from_bytes(&path)) {
					Ok(md) => {
						let msg = b"using (package - .part) size\n";
						logv(cb, Debug, &[msg]);
						let left = newpkg
							.size
							.wrapping_sub(
								md.len() as i64
							);
						left.max(0)
					}
					Err(_) => 0,
				}
			}
			None => newpkg.size,
		}
	};
	let msg = format!("setting download size {size} for pkg ");
	logv(cb, Debug, &[msg.as_bytes(), name(newpkg), b"\n"]);
	newpkg.infolevel |= INFRQ_DSIZE;
	newpkg.download_size = size;
	Ok(partial)
}

// alpm_pkg_download_size: computed once (INFRQ_DSIZE), then the stored
// value
pub fn pkg_download_size(h: &mut Handle, newpkg: &mut Package) -> i64 {
	if newpkg.infolevel & INFRQ_DSIZE == 0 {
		h.with_callbacks(|h, cb| {
			let _ = compute_download_size(h, cb, newpkg);
		});
	}
	newpkg.download_size
}

// alpm_find_dbs_satisfier on the sync dbs at positions dbs, caches
// loaded first: the satisfier and its db. an empty dbs is WrongArgs
pub fn dbs_satisfier(
	h: &mut Handle,
	dbs: &[usize],
	depstring: &[u8],
) -> Result<TransPkg, Errno> {
	let nodepversion = h
		.trans()
		.is_some_and(|t| t.flags & TRANS_FLAG_NODEPVERSION != 0);
	load_caches(h, false);
	load_until_literal(h, dbs, &dep_from_string(depstring));
	with_view(h, |view, cb| {
		let env = view.env(nodepversion);
		let list: Vec<_> = dbs
			.iter()
			.filter_map(|&i| view.sync.get(i).copied())
			.collect();
		let pkg = find_dbs_satisfier(&env, &list, depstring, cb)?;
		let db = db_of(view, pkg);
		Ok(TransPkg::new(pkg.clone(), db))
	})
}

// the caches resolvedep reads, in its order: each usable db loads
// until one holds a literal it returns at once. an ignored literal
// keeps loading, an answer the C asks about later may skip it
fn load_until_literal(h: &mut Handle, dbs: &[usize], dep: &Depend) {
	let d = h.dbs_mut();
	for &i in dbs {
		let Some(db) = d.sync.get_mut(i) else {
			continue;
		};
		if db.usage() & (DB_USAGE_INSTALL | DB_USAGE_UPGRADE) == 0 {
			continue;
		}
		let Ok(cache) = db.pkgcache(d.dbext, d.cb) else {
			continue;
		};
		let found = cache.find(&dep.name).filter(|&p| {
			depcmp_literal(p, dep) && !d.opts.should_ignore(p)
		});
		if found.is_some() {
			return;
		}
	}
}

// the sync db whose cache holds pkg (by address)
fn db_of(view: &View, pkg: &Package) -> Option<usize> {
	view.sync
		.iter()
		.position(|db| db.cache.iter().any(|p| ptr::eq(p, pkg)))
}

// _alpm_sync_prepare's db check, before anything loads: an invalid sync
// db fails, a missing one when a target comes from a sync db
pub(crate) fn check_dbs(h: &Handle, add: &[TransPkg]) -> Result<(), Errno> {
	let from_sync =
		add.iter().any(|t| t.pkg.origin == Some(PkgFrom::SyncDb));
	for db in h.syncdbs() {
		if db.valid().is_err() {
			return Err(Errno::DbInvalid);
		}
		if from_sync && db.is_missing() {
			return Err(Errno::DbNotFound);
		}
	}
	Ok(())
}

fn event(cb: &mut dyn Callbacks, e: Event) {
	cb.event(&e);
}

fn conflict_err(c: &Conflict) -> PrepareError {
	let data = PrepareData::Conflicts(vec![c.clone()]);
	PrepareError::new(Errno::ConflictingDeps, data)
}

// _alpm_sync_prepare: after check_dbs, dependencies resolved (targets
// replaced by the resolved list, pulled ones as DEPEND), conflicts
// between targets and with the local db settled, removals collected,
// then the whole transaction checked; download sizes and oldpkgs last.
// the local descs the C getters lazy-load along the way are loaded
// before the step that reads them (the sets its walks cover), the
// removals and oldpkgs are dup'ed with their force_load where the C
// dups them
pub(crate) fn sync_prepare(
	h: &mut Handle,
	trans: &mut Trans,
) -> Result<(), PrepareError> {
	check_dbs(h, &trans.add)?;
	load_caches(h, false);
	let flags = trans.flags;
	if flags & TRANS_FLAG_NODEPS == 0 {
		h.with_callbacks(|_, cb| {
			event(cb, Event::ResolvedepsStart);
			logv(
				cb,
				Debug,
				&[b"resolving target's dependencies\n"],
			);
		});
		// the checkdeps walks of resolvedeps read the local packages
		// neither targets nor leaving (list order, up to a
		// satisfier), its local fallback (resolvedep over db_local)
		// every one of them: all here
		load_local_descs(h, &[]);
		if with_view(h, |v, _| resolve_needs_sync(v, trans)) {
			load_caches(h, true);
		}
		with_view(h, |v, cb| resolve(v, cb, trans))?;
	}
	if flags & TRANS_FLAG_NOCONFLICTS == 0 {
		h.with_callbacks(|_, cb| {
			event(cb, Event::InterconflictsStart);
			logv(cb, Debug, &[b"looking for conflicts\n"]);
			inner_conflicts(cb, trans)
		})?;
		// check_conflict's db pass reads the conflicts of every local
		// package not named by a target (with NODEPS the first read)
		load_local_descs(h, &target_names(trans));
		outer_conflicts(h, trans)?;
		event(h.callbacks(), Event::InterconflictsDone);
	}
	remove_list(h, trans);
	if flags & TRANS_FLAG_NODEPS == 0 {
		logv(h.callbacks(), Debug, &[b"checking dependencies\n"]);
		with_view(h, |v, cb| check_transaction(v, cb, trans))?;
	}
	sizes_and_oldpkgs(h, trans)
}

fn target_names(trans: &Trans) -> Vec<&[u8]> {
	trans.add.iter().map(|t| t.pkg.name_bytes()).collect()
}

// the "Build trans->remove list" loop: each removes entry not yet a
// removal joins as a dup of its cache entry; a dup that loaded short
// only warns (the C tests == -1)
fn remove_list(h: &mut Handle, trans: &mut Trans) {
	for i in 0..trans.add.len() {
		for j in 0..trans.add[i].removes.len() {
			let rpkg = &trans.add[i].removes[j];
			if pkg_find(&trans.remove, rpkg.name_bytes()).is_some()
			{
				continue;
			}
			let n = name(rpkg).to_vec();
			let msg = [b"adding '", &n[..], b"' to remove list\n"];
			logv(h.callbacks(), Debug, &msg);
			let copy = pkg_dup(h, &n).map_or_else(
				|| trans.add[i].removes[j].dup(),
				|(copy, _)| copy,
			);
			trans.remove.push(copy);
		}
	}
}

// the checkdeps of the whole transaction
fn check_transaction(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &Trans,
) -> Result<(), PrepareError> {
	let nodepversion = trans.flags & TRANS_FLAG_NODEPVERSION != 0;
	let env = view.env(nodepversion);
	let rem: Vec<&Package> = trans.remove.iter().collect();
	let add: Vec<&Package> = trans.add.iter().map(|t| &t.pkg).collect();
	let local = view.local_list();
	let deps = checkdeps(&env, &local, &rem, &add, true, cb);
	if deps.is_empty() {
		return Ok(());
	}
	let data = PrepareData::Missing(deps);
	Err(PrepareError::new(Errno::UnsatisfiedDeps, data))
}

// the last loop: each target's download size, then its installed
// namesake dup'ed whole as oldpkg. a dup that loaded short is kept
// and fails the prepare with PKG_INVALID (the C tests != 0)
fn sizes_and_oldpkgs(
	h: &mut Handle,
	trans: &mut Trans,
) -> Result<(), PrepareError> {
	for t in &mut trans.add {
		h.with_callbacks(|h, cb| {
			compute_download_size(h, cb, &mut t.pkg)
		})?;
		let name = t.pkg.name_bytes().to_vec();
		if let Some((copy, loaded)) = pkg_dup(h, &name) {
			t.oldpkg = Some(copy);
			if !loaded {
				return Err(Errno::PkgInvalid.into());
			}
		}
	}
	Ok(())
}

// whether resolve will look in the sync dbs: the C loads their caches
// lazily, in resolvedep, reached only for a target dependency neither
// the local db (without the targets) nor another target satisfies
pub(crate) fn resolve_needs_sync(view: &View, trans: &Trans) -> bool {
	if trans.flags & TRANS_FLAG_NODEPS != 0 {
		return false;
	}
	let nodepversion = trans.flags & TRANS_FLAG_NODEPVERSION != 0;
	let env = view.env(nodepversion);
	let targets: Vec<&Package> = trans.add.iter().map(|t| &t.pkg).collect();
	let mut remove: Vec<&Package> = trans.remove.iter().collect();
	remove.extend(trans.add.iter().flat_map(|t| &t.removes));
	let localpkgs = list_diff(&view.local_list(), &targets);
	targets.iter().any(|&pkg| {
		let deps = checkdeps(
			&env,
			&localpkgs,
			&remove,
			&[pkg],
			false,
			&mut (),
		);
		deps.iter().any(|miss| {
			let dep = &miss.depend;
			find_dep_satisfier(targets.iter().copied(), dep)
				.is_none()
		})
	})
}

// the resolver step of _alpm_sync_prepare: each target resolved against
// the local db without the targets, the unresolvable ones dropped after
// a yes to REMOVE_PKGS, two packages with one filename refused
fn resolve(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
) -> Result<(), PrepareError> {
	let nodepversion = trans.flags & TRANS_FLAG_NODEPVERSION != 0;
	let env = view.env(nodepversion);
	let add = std::mem::take(&mut trans.add);
	let targets: Vec<&Package> = add.iter().map(|t| &t.pkg).collect();
	let mut remove: Vec<&Package> = trans.remove.iter().collect();
	remove.extend(add.iter().flat_map(|t| &t.removes));
	let localpkgs = list_diff(&view.local_list(), &targets);

	let mut resolved: Vec<&Package> = Vec::new();
	let mut unresolvable: Vec<&Package> = Vec::new();
	let mut data: Vec<DepMissing> = Vec::new();
	for &pkg in &targets {
		let r = resolvedeps(
			&env,
			&localpkgs,
			pkg,
			&targets,
			&mut resolved,
			&remove,
			&mut data,
			cb,
		);
		if r.is_err() {
			unresolvable.push(pkg);
		}
	}

	if !unresolvable.is_empty() {
		let mut q = Question::RemovePkgs {
			skip: 0,
			packages: &unresolvable,
		};
		cb.question(&mut q);
		if q.answer() == 0 {
			trans.add = add;
			let data = PrepareData::Missing(data);
			return Err(PrepareError::new(
				Errno::UnsatisfiedDeps,
				data,
			));
		}
	}

	let mut dup = false;
	for (i, p1) in resolved.iter().enumerate() {
		for p2 in &resolved[i + 1..] {
			let (f1, f2) = (&p1.filename, &p2.filename);
			// the C strcmps NULL filenames, never reached by pacman
			let same = matches!((f1, f2), (Some(a), Some(b))
				if until_nul(a) == until_nul(b));
			if !same {
				continue;
			}
			dup = true;
			let msg = [
				b"packages ",
				name(p1),
				b" and ",
				name(p2),
				b" have the same filename: ",
				opt_str(f1),
				b"\n",
			];
			logv(cb, Error, &msg);
		}
	}
	if dup {
		trans.add = add;
		return Err(Errno::TransDupFilename.into());
	}

	// the resolved packages back as targets: a target keeps its
	// removes, a pulled one is a DEPEND copy of its sync cache entry
	let to_target = |p: &Package| -> TransPkg {
		match add.iter().find(|t| ptr::eq(&t.pkg, p)) {
			Some(t) => t.clone(),
			None => TransPkg::new(p.clone(), db_of(view, p)),
		}
	};
	let mut new_add: Vec<TransPkg> =
		resolved.iter().map(|p| to_target(p)).collect();
	for t in &mut new_add {
		if find_target(&add, t.pkg.name_bytes()).is_none() {
			t.pkg.reason = PkgReason::Depend;
		}
	}
	trans.unresolvable =
		unresolvable.iter().map(|p| to_target(p)).collect();
	trans.add = new_add;
	event(cb, Event::ResolvedepsDone);
	Ok(())
}

// step 1 of the conflict check: two conflicting targets, the one the
// other provides goes to unresolvable; neither is fatal
fn inner_conflicts(
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
) -> Result<(), PrepareError> {
	logv(cb, Debug, &[b"check targets vs targets\n"]);
	let deps = {
		let add: Vec<&Package> =
			trans.add.iter().map(|t| &t.pkg).collect();
		innerconflicts(&add, cb)
	};
	for conflict in &deps {
		let n1 = conflict.package1.name_bytes();
		let n2 = conflict.package2.name_bytes();
		let (Some(i1), Some(i2)) =
			(position(&trans.add, n1), position(&trans.add, n2))
		else {
			continue;
		};
		let msg = [
			b"conflicting packages in the sync list: '",
			name(&conflict.package1),
			b"' <-> '",
			name(&conflict.package2),
			b"'\n",
		];
		logv(cb, Debug, &msg);
		let (dep1, dep2) = (dep_from_string(n1), dep_from_string(n2));
		let (s1, s2) = (&trans.add[i1].pkg, &trans.add[i2].pkg);
		let (rsync, sync) = if depcmp(s1, &dep2) {
			(i2, i1)
		} else if depcmp(s2, &dep1) {
			(i1, i2)
		} else {
			let msg = b"unresolvable package conflicts detected\n";
			logv(cb, Error, &[msg]);
			return Err(conflict_err(conflict));
		};
		let (r, s) = (&trans.add[rsync].pkg, &trans.add[sync].pkg);
		let msg = [
			b"removing '",
			name(r),
			b"-",
			ver(r),
			b"' from target list because it conflicts with '",
			name(s),
			b"-",
			ver(s),
			b"'\n",
		];
		logv(cb, Warning, &msg);
		let gone = trans.add.remove(rsync);
		trans.unresolvable.push(gone);
	}
	Ok(())
}

// _alpm_outerconflicts and what _alpm_sync_prepare does with each
// conflict: conflict_new dups the target as it is and the local package
// through its cache entry (a force_load, logged; a short load drops the
// conflict); a conflict with a package not leaving already asks, a no
// fails the prepare, a yes elects the local package for removal
fn outer_conflicts(
	h: &mut Handle,
	trans: &mut Trans,
) -> Result<(), PrepareError> {
	let line = b"check targets vs db and db vs targets\n";
	logv(h.callbacks(), Debug, &[line]);
	let mut deps: Vec<Conflict> = Vec::new();
	for reversed in [false, true] {
		let line: &[u8] = match reversed {
			false => b"check targets vs db\n",
			true => b"check db vs targets\n",
		};
		logv(h.callbacks(), Debug, &[line]);
		// (target, local package, reason) in the C's order
		let found: Vec<(Vec<u8>, Vec<u8>, Depend)> =
			with_view(h, |v, _| {
				let add: Vec<&Package> = trans
					.add
					.iter()
					.map(|t| &t.pkg)
					.collect();
				let dblist = list_diff(&v.local_list(), &add);
				let (l1, l2) = match reversed {
					false => (&add, &dblist),
					true => (&dblist, &add),
				};
				check_conflict(l1, l2, reversed)
					.into_iter()
					.map(|(p1, p2, r)| {
						let (n1, n2) = (
							p1.name_bytes(),
							p2.name_bytes(),
						);
						(
							n1.to_vec(),
							n2.to_vec(),
							r.clone(),
						)
					})
					.collect()
			});
		for (target, local, reason) in found {
			let Some((package2, true)) = pkg_dup(h, &local) else {
				continue;
			};
			let package1 = find_target(&trans.add, &target)
				.expect(
					"package1 of an outer conflict is a target",
				)
				.pkg
				.dup();
			let conflict = Conflict {
				package1,
				package2,
				reason,
			};
			add_conflict(&mut deps, conflict, h.callbacks());
		}
	}
	with_view(h, |view, cb| elect_removals(view, cb, trans, &deps))
}

fn elect_removals(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
	deps: &[Conflict],
) -> Result<(), PrepareError> {
	for conflict in deps {
		let (p1, p2) = (&conflict.package1, &conflict.package2);
		let n2 = p2.name_bytes();
		let leaving = pkg_find(&trans.remove, n2).is_some()
			|| trans.add
				.iter()
				.any(|t| pkg_find(&t.removes, n2).is_some());
		if leaving {
			continue;
		}
		let msg = [
			b"package '",
			name(p1),
			b"-",
			ver(p1),
			b"' conflicts with '",
			name(p2),
			b"-",
			ver(p2),
			b"'\n",
		];
		logv(cb, Debug, &msg);
		let mut q = Question::ConflictPkg {
			remove: 0,
			conflict,
		};
		cb.question(&mut q);
		if q.answer() == 0 {
			let msg = b"unresolvable package conflicts detected\n";
			logv(cb, Error, &[msg]);
			return Err(conflict_err(conflict));
		}
		let i = position(&trans.add, p1.name_bytes())
			.expect("package1 of an outer conflict is a target");
		let local = view
			.local
			.find(n2)
			.expect("package2 of an outer conflict is installed");
		logv(cb, Debug, &[b"electing '", name(p2), b"' for removal\n"]);
		trans.add[i].removes.push(local.clone());
	}
	Ok(())
}

// ---- the commit side: _alpm_sync_load, _alpm_sync_check,
// _alpm_sync_commit ----

// prompt_to_delete (static in C): CORRUPTED_PKG about filepath, a yes
// unlinks it and its .sig
fn prompt_to_delete(
	cb: &mut dyn Callbacks,
	filepath: &[u8],
	reason: Errno,
) -> bool {
	let mut q = Question::CorruptedPkg {
		remove: 0,
		filepath,
		reason,
	};
	cb.question(&mut q);
	let remove = q.answer() != 0;
	if remove {
		let _ = fs::remove_file(OsStr::from_bytes(filepath));
		let sig = sigpath(filepath);
		let _ = fs::remove_file(OsStr::from_bytes(&sig));
	}
	remove
}

// the sync db of a target: sync targets carry their position in
// Handle::syncdbs(), file packages none
fn target_db<'h>(h: &'h Handle, t: &TransPkg) -> Option<&'h Db> {
	match t.pkg.origin {
		Some(PkgFrom::File(_)) => None,
		_ => t.db.and_then(|i| h.syncdbs().get(i)),
	}
}

// find_dl_candidates (static in C): positions in trans.add of the sync
// targets to download, those not cached (or with a download size left)
// and those missing the .sig their db's siglevel wants
fn find_dl_candidates(
	h: &Handle,
	cb: &mut dyn Callbacks,
) -> Result<Vec<usize>, Errno> {
	let add = &h.trans().expect("committing").add;
	let mut files = Vec::new();
	for (i, t) in add.iter().enumerate() {
		let Some(db) = target_db(h, t) else {
			continue;
		};
		if db.servers().is_empty() {
			let e = Errno::ServerNone.strerror().as_bytes();
			logv(cb, Error, &[e, b": ", db.name(), b"\n"]);
			return Err(Errno::ServerNone);
		}
		let fname = t.pkg.filename.as_deref().map(until_nul);
		let fname = fname.ok_or(Errno::PkgInvalidName)?;
		let siglevel = db.siglevel(h.default_siglevel());
		let mut need = t.pkg.download_size != 0
			|| filecache_find(h.cachedirs(), fname, cb).is_none();
		// a cached package without its .sig is fetched again with it
		if !need && siglevel & SIG_PACKAGE != 0 {
			let sig = [fname, b".sig"].concat();
			need = filecache_find(h.cachedirs(), &sig, cb)
				.is_none();
		}
		if need {
			files.push(i);
		}
	}
	Ok(files)
}

// the payload of a target downloaded into tmp: filename from the db's
// cache servers then servers, resumable, its .sig as the siglevel says
fn payload(h: &Handle, t: &TransPkg, tmp: &[u8]) -> Payload {
	let db = target_db(h, t).expect("download candidates are synced");
	let siglevel = db.siglevel(h.default_siglevel());
	let fname = until_nul(t.pkg.filename.as_deref().unwrap_or_default());
	let mut p = Payload::default();
	p.remote_name = fname.to_vec();
	p.filepath = Some(fname.to_vec());
	p.destfile_name = Some(get_fullpath(tmp, fname, b""));
	p.tempfile_name = get_fullpath(tmp, fname, b".part");
	p.max_size = t.pkg.size;
	p.cache_servers = db.cache_servers().to_vec();
	p.servers = db.servers().to_vec();
	p.allow_resume = true;
	p.download_signature = siglevel & SIG_PACKAGE != 0;
	p.signature_optional = siglevel & SIG_PACKAGE_OPTIONAL != 0;
	p
}

// download_files (static in C): the candidates fetched into the first
// usable cachedir, after the download space check. the download sizes
// are reset whatever happened
fn download_files(h: &mut Handle) -> Result<(), Errno> {
	let r = download_candidates(h);
	let trans = h.trans_mut().expect("committing");
	for t in &mut trans.add {
		t.pkg.infolevel &= !INFRQ_DSIZE;
		t.pkg.download_size = 0;
	}
	r
}

fn download_candidates(h: &mut Handle) -> Result<(), Errno> {
	let (cachedir, tmp) = h.with_downloader(|dl, cachedirs| {
		let cachedir = filecache_setup(cachedirs, dl.cb);
		let tmp = dl.download_dir_setup(&cachedir);
		(cachedir, tmp)
	});
	let tmp = tmp?;
	h.trans_mut().expect("committing").state = TransState::Downloading;
	let files = h.with_callbacks(|h, cb| find_dl_candidates(h, cb))?;
	if files.is_empty() {
		return Ok(());
	}

	let add = &h.trans().expect("committing").add;
	let sizes: Vec<i64> =
		files.iter().map(|&i| add[i].pkg.download_size).collect();
	if h.checkspace() != 0 {
		let msg = b"checking available disk space for download\n";
		logv(h.callbacks(), Debug, &[msg]);
		h.with_callbacks(|_, cb| {
			check_downloadspace(&tmp, &sizes, &mut System, cb)
		})
		.map_err(|e| e.errno().unwrap_or(Errno::Ok))?;
	}

	// the C reuses one alpm_event_pkg_retrieve_t for all three events
	let num = files.len();
	let total_size = sizes.iter().fold(0i64, |a, &s| a.wrapping_add(s));
	h.callbacks()
		.event(&Event::PkgRetrieveStart { num, total_size });
	let add = &h.trans().expect("committing").add;
	let mut payloads: Vec<Payload> =
		files.iter().map(|&i| payload(h, &add[i], &tmp)).collect();
	let r = h.with_downloader(|dl, _| {
		dl.download(&mut payloads, &cachedir, &tmp)
	});
	if let Err(e) = r {
		let cb = h.callbacks();
		cb.event(&Event::PkgRetrieveFailed { num, total_size });
		logv(cb, Warning, &[b"failed to retrieve some files\n"]);
		return Err(e);
	}
	h.callbacks()
		.event(&Event::PkgRetrieveDone { num, total_size });
	Ok(())
}

// alpm_pkg_get_sig (package.c) on a sync package: its base64 signature
// decoded, else the .sig next to its cached file
fn pkg_get_sig(
	h: &Handle,
	cb: &mut dyn Callbacks,
	pkg: &Package,
) -> Result<Vec<u8>, Errno> {
	if let Some(b64) = &pkg.base64_sig {
		return decode_signature(b64).map_err(|_| Errno::SigInvalid);
	}
	let fname = pkg.filename.as_deref().unwrap_or_default();
	let path = filecache_find(h.cachedirs(), fname, cb)
		.ok_or(Errno::PkgNotFound)?;
	let sig = sigpath(&path);
	if !readable(&sig, cb) {
		return Err(Errno::SigMissing);
	}
	let data = read_file(&sig).map_err(|e| match e {
		ReadFileError::NotAFile => Errno::NotAFile,
		ReadFileError::Memory => Errno::Memory,
		ReadFileError::System => Errno::System,
	})?;
	let size = data.len().to_string();
	let msg = [b"found detached signature ", &sig[..], b" with size "];
	logv(cb, Debug, &[&msg.concat(), size.as_bytes(), b"\n"]);
	Ok(data)
}

// a key a sync target is signed with and the keychain lacks: the
// packager as uid, the key id
struct MissingKey {
	uid: Option<Box<[u8]>>,
	keyid: Vec<u8>,
}

// the signature keys of the sync targets whose siglevel wants package
// signatures, those the keychain does not know, in first-seen order.
// a signature that cannot be read or parsed is skipped; Err is the last
// pm_errno that set (Ok for none)
fn missing_keys(
	h: &mut Handle,
	cb: &mut dyn Callbacks,
) -> (Vec<MissingKey>, Errno) {
	let numtargs = h.trans().expect("committing").add.len();
	let mut errors: Vec<MissingKey> = Vec::new();
	let mut errno = Errno::Ok;
	for current in 0..numtargs {
		let percent = (current * 100 / numtargs) as c_int;
		cb.progress(
			Progress::KeyringStart,
			b"",
			percent,
			numtargs,
			current,
		);
		let t = &h.trans().expect("committing").add[current];
		let Some(db) = target_db(h, t) else {
			continue;
		};
		if db.siglevel(h.default_siglevel()) & SIG_PACKAGE == 0 {
			continue;
		}
		let (pkgname, packager) =
			(t.pkg.name.clone(), t.pkg.packager.clone());
		let sig = match pkg_get_sig(h, cb, &t.pkg) {
			Ok(sig) => sig,
			Err(e) => {
				errno = e;
				continue;
			}
		};
		let mut keys = Vec::new();
		let pkgname = pkgname.as_deref().unwrap_or_default();
		if extract_keyid(cb, pkgname, &sig, &mut keys).is_err() {
			errno = Errno::SigInvalid;
			continue;
		}
		for key in keys {
			logv(
				cb,
				Debug,
				&[b"found signature key: ", &key, b"\n"],
			);
			if errors.iter().any(|k| k.keyid == key) {
				continue;
			}
			match key_in_keychain(h.keyring_mut(), cb, &key) {
				Some(false) => errors.push(MissingKey {
					uid: packager.clone(),
					keyid: key,
				}),
				Some(true) => {}
				None => errno = Errno::Gpgme,
			}
		}
	}
	cb.progress(Progress::KeyringStart, b"", 100, numtargs, numtargs);
	(errors, errno)
}

// check_keyring (static in C): the missing keys offered for import, any
// import failing fails the load
fn check_keyring(h: &mut Handle) -> Result<(), Errno> {
	h.with_callbacks(|h, cb| {
		cb.event(&Event::KeyringStart);
		let (errors, errno) = missing_keys(h, cb);
		cb.event(&Event::KeyringDone);
		if errors.is_empty() {
			return Ok(());
		}
		cb.event(&Event::KeyDownloadStart);
		let mut fail = false;
		for k in &errors {
			let uid = k.uid.as_deref();
			if !key_import(h.keyring_mut(), cb, uid, &k.keyid) {
				fail = true;
			}
		}
		cb.event(&Event::KeyDownloadDone);
		if fail {
			let msg = b"required key missing from keyring\n";
			logv(cb, Error, &[msg]);
			return Err(errno);
		}
		Ok(())
	})
}

// (int)(((double)current / total) * 100): the progress of a byte count
fn byte_percent(current: u64, total: u64) -> c_int {
	(current as f64 / total as f64 * 100.0) as c_int
}

// a sync target that failed validation, as check_validity reports it
struct Invalid {
	name: Vec<u8>,
	path: Vec<u8>,
	siglevel: c_int,
	error: be_package::Error,
}

// check_validity (static in C): every cached sync target validated
// against its db entry and siglevel (the validation bits kept), then
// the failures reported. pm_errno is the last validation's, which
// resets it: PkgInvalid when that one passed
fn check_validity(
	h: &mut Handle,
	total: usize,
	total_bytes: u64,
) -> Result<(), Errno> {
	h.with_callbacks(|h, cb| {
		cb.event(&Event::IntegrityStart);
		let (errors, errno) = validate_all(h, cb, total, total_bytes)?;
		cb.progress(Progress::IntegrityStart, b"", 100, total, total);
		cb.event(&Event::IntegrityDone);
		if errors.is_empty() {
			return Ok(());
		}
		for v in &errors {
			report_invalid(h, cb, v);
		}
		match errno {
			Errno::Ok => Err(Errno::PkgInvalid),
			e => Err(e),
		}
	})
}

// the validation loop of check_validity
fn validate_all(
	h: &mut Handle,
	cb: &mut dyn Callbacks,
	total: usize,
	total_bytes: u64,
) -> Result<(Vec<Invalid>, Errno), Errno> {
	let mut current_bytes: u64 = 0;
	let (mut errors, mut errno) = (Vec::new(), Errno::Ok);
	for current in 0..total {
		let percent = byte_percent(current_bytes, total_bytes);
		cb.progress(
			Progress::IntegrityStart,
			b"",
			percent,
			total,
			current,
		);
		let t = &h.trans().expect("committing").add[current];
		let Some(db) = target_db(h, t) else {
			continue;
		};
		let siglevel = db.siglevel(h.default_siglevel());
		current_bytes = current_bytes.wrapping_add(t.pkg.size as u64);
		let fname = t.pkg.filename.as_deref().unwrap_or_default();
		let Some(path) = filecache_find(h.cachedirs(), fname, cb)
		else {
			let msg = b": could not find package in cache\n";
			logv(cb, Error, &[name(&t.pkg), msg]);
			return Err(Errno::PkgNotFound);
		};
		let syncpkg = t.pkg.clone();
		let r = pkg_validate(
			h.keyring_mut(),
			cb,
			&path,
			Some(&syncpkg),
			siglevel,
		);
		match r {
			Ok(v) => {
				errno = Errno::Ok;
				let trans = h.trans_mut().expect("committing");
				trans.add[current].pkg.validation =
					v.validation;
			}
			Err(error) => {
				errno = error.errno();
				errors.push(Invalid {
					name: name(&syncpkg).to_vec(),
					path,
					siglevel,
					error,
				});
			}
		}
	}
	Ok((errors, errno))
}

// the message (and for bad files the CORRUPTED_PKG question) of one
// failed validation
fn report_invalid(h: &mut Handle, cb: &mut dyn Callbacks, v: &Invalid) {
	let errno = v.error.errno();
	match &v.error {
		be_package::Error::MissingSig => {
			let msg = b": missing required signature\n";
			logv(cb, Error, &[&v.name, msg]);
		}
		be_package::Error::InvalidSig(siglist) => {
			let level = v.siglevel;
			process_siglist(
				h.keyring_mut(),
				cb,
				&v.name,
				siglist,
				level & SIG_PACKAGE_OPTIONAL != 0,
				level & SIG_PACKAGE_MARGINAL_OK != 0,
				level & SIG_PACKAGE_UNKNOWN_OK != 0,
			);
			prompt_to_delete(cb, &v.path, errno);
		}
		be_package::Error::Checksum => {
			prompt_to_delete(cb, &v.path, errno);
		}
		be_package::Error::NotFound
		| be_package::Error::BadPerms
		| be_package::Error::Open(_) => {
			let msg = [
				b"failed to read file ",
				&v.path[..],
				b": ",
				errno.strerror().as_bytes(),
				b"\n",
			];
			logv(cb, Error, &msg);
		}
		_ => {}
	}
}

// dep_not_equal (static in C)
fn dep_equal(a: &Depend, b: &Depend) -> bool {
	a.name_hash == b.name_hash
		&& until_nul(&a.name) == until_nul(&b.name)
		&& a.depmod == b.depmod
		&& a.version.as_deref().map(until_nul)
			== b.version.as_deref().map(until_nul)
}

// alpm_list_cmp_unsorted: same length, and every element of left
// matches a distinct one of right
fn list_eq_unsorted<T>(
	left: &[T],
	right: &[T],
	eq: impl Fn(&T, &T) -> bool,
) -> bool {
	if left.len() != right.len() {
		return false;
	}
	let mut matched = vec![false; right.len()];
	left.iter().all(|l| {
		let m = (0..right.len())
			.find(|&n| !matched[n] && eq(l, &right[n]));
		m.inspect(|&n| matched[n] = true).is_some()
	})
}

// check_pkg_matches_db (static in C): the loaded file against its sync
// db entry, each mismatch logged. true when they differ
fn pkg_differs(cb: &mut dyn Callbacks, spkg: &Package, file: &Package) -> bool {
	let mut lines: Vec<Vec<u8>> = Vec::new();
	let pair = |what: &str, a: &[u8], b: &[u8]| {
		let what = format!(
			"internal package {what} mismatch, expected: '"
		);
		[what.as_bytes(), a, b"', actual: '", b, b"'\n"].concat()
	};
	let (sname, fname) = (name(spkg), name(file));
	if sname != fname {
		lines.push(pair("name", sname, fname));
	}
	let (sver, fver) = (ver(spkg), ver(file));
	if sver != fver {
		lines.push(pair("version", sver, fver));
	}
	if spkg.isize != file.isize {
		let (a, b) = (spkg.isize.to_string(), file.isize.to_string());
		lines.push(pair("install size", a.as_bytes(), b.as_bytes()));
	}
	let deps =
		|a: &[Depend], b: &[Depend]| list_eq_unsorted(a, b, dep_equal);
	let groups = list_eq_unsorted(&spkg.groups, &file.groups, |a, b| {
		until_nul(a) == until_nul(b)
	});
	let fields: [(&[u8], bool); 5] = [
		(b"depends", deps(&spkg.depends, &file.depends)),
		(b"conflicts", deps(&spkg.conflicts, &file.conflicts)),
		(b"replaces", deps(&spkg.replaces, &file.replaces)),
		(b"provides", deps(&spkg.provides, &file.provides)),
		(b"groups", groups),
	];
	for (what, same) in fields {
		if !same {
			lines.push([
				b"internal package ",
				what,
				b" mismatch\n",
			]
			.concat());
		}
	}
	for l in &lines {
		cb.log(Debug, l);
	}
	!lines.is_empty()
}

// load_packages (static in C): each cached sync target replaced by its
// package file loaded in full (reason, validation and oldpkg carried
// over, now a file package). files that fail to load or differ from the
// db entry go into data and are offered for deletion; pm_errno is the
// last load failure's, PkgInvalid without one
fn load_packages(
	h: &mut Handle,
	data: &mut Vec<Vec<u8>>,
	total: usize,
	total_bytes: u64,
) -> Result<(), Errno> {
	h.with_callbacks(|h, cb| {
		cb.event(&Event::LoadStart);
		let mut delete = Vec::new();
		let errno =
			load_all(h, cb, data, &mut delete, total, total_bytes)?;
		cb.progress(Progress::LoadStart, b"", 100, total, total);
		cb.event(&Event::LoadDone);
		if delete.is_empty() {
			return Ok(());
		}
		for path in &delete {
			prompt_to_delete(cb, path, Errno::PkgInvalid);
		}
		match errno {
			Errno::Ok => Err(Errno::PkgInvalid),
			e => Err(e),
		}
	})
}

// the loading loop of load_packages: Ok is the pm_errno it left
fn load_all(
	h: &mut Handle,
	cb: &mut dyn Callbacks,
	data: &mut Vec<Vec<u8>>,
	delete: &mut Vec<Vec<u8>>,
	total: usize,
	total_bytes: u64,
) -> Result<Errno, Errno> {
	let mut current_bytes: u64 = 0;
	let mut errno = Errno::Ok;
	for current in 0..total {
		let percent = byte_percent(current_bytes, total_bytes);
		cb.progress(Progress::LoadStart, b"", percent, total, current);
		let t = &h.trans().expect("committing").add[current];
		if target_db(h, t).is_none() {
			continue;
		}
		current_bytes = current_bytes.wrapping_add(t.pkg.size as u64);
		let fname = t.pkg.filename.clone().unwrap_or_default();
		let Some(path) = filecache_find(h.cachedirs(), &fname, cb)
		else {
			let msg = b": could not find package in cache\n";
			logv(cb, Error, &[name(&t.pkg), msg]);
			return Err(Errno::PkgNotFound);
		};
		let msg = b"replacing pkgcache entry with package file for target ";
		logv(cb, Debug, &[msg, name(&t.pkg), b"\n"]);
		let file = match be_package::pkg_load_internal(cb, &path, true)
		{
			Ok(file) => Some(file)
				.filter(|f| !pkg_differs(cb, &t.pkg, f)),
			Err(e) => {
				errno = e.errno();
				let msg = b"failed to load pkgfile internal\n";
				logv(cb, Debug, &[msg]);
				None
			}
		};
		let Some(mut file) = file else {
			data.push(until_nul(&fname).to_vec());
			delete.push(path);
			continue;
		};
		let t = &mut h.trans_mut().expect("committing").add[current];
		file.reason = t.pkg.reason;
		file.validation = t.pkg.validation;
		// the sync-only fields go with the db entry
		t.pkg = file;
		t.db = None;
		t.removes = Vec::new();
	}
	Ok(errno)
}

// _alpm_sync_load: the downloads, the keyring, the validation, then
// (unless DOWNLOADONLY) the package files replacing the targets
pub(crate) fn sync_load(h: &mut Handle) -> Result<(), CommitError> {
	download_files(h)?;
	check_keyring(h)?;

	// the total size of all packages, for a more realistic progress bar
	// when small and huge packages mix
	let trans = h.trans().expect("committing");
	let total = trans.add.len();
	let total_bytes = trans
		.add
		.iter()
		.filter(|t| !matches!(t.pkg.origin, Some(PkgFrom::File(_))))
		.fold(0u64, |a, t| a.wrapping_add(t.pkg.size as u64));
	// only a malicious db gets here with 0
	let total_bytes = total_bytes.max(1);
	let flags = trans.flags;

	check_validity(h, total, total_bytes)?;
	if flags & TRANS_FLAG_DOWNLOADONLY != 0 {
		return Ok(());
	}
	let mut data = Vec::new();
	load_packages(h, &mut data, total, total_bytes).map_err(|errno| {
		CommitError {
			errno,
			data: CommitData::Invalid(data),
		}
	})
}

// _alpm_sync_check: file conflicts (DBONLY skips them), then with
// checkspace the disk space
pub(crate) fn sync_check(h: &mut Handle) -> Result<(), CommitError> {
	let flags = h.trans().expect("committing").flags;
	if flags & TRANS_FLAG_DBONLY != 0 {
		return Ok(());
	}
	h.callbacks().event(&Event::FileconflictsStart);
	logv(h.callbacks(), Debug, &[b"looking for file conflicts\n"]);
	let conflicts = find_fileconflicts(h);
	if !conflicts.is_empty() {
		return Err(CommitError {
			errno: Errno::FileConflicts,
			data: CommitData::FileConflicts(conflicts),
		});
	}
	h.callbacks().event(&Event::FileconflictsDone);

	if h.checkspace() == 0 {
		return Ok(());
	}
	h.callbacks().event(&Event::DiskspaceStart);
	logv(h.callbacks(), Debug, &[b"checking available disk space\n"]);
	let trans = h.set_trans(None).expect("committing");
	// check_diskspace takes package lists, the targets are TransPkgs
	let add: Vec<Package> =
		trans.add.iter().map(|t| t.pkg.clone()).collect();
	let r = h.with_callbacks(|h, cb| {
		check_diskspace(h, &add, &trans.remove, &mut System, cb)
	});
	h.set_trans(Some(trans));
	if let Err(e) = r {
		let msg = b"not enough free disk space\n";
		logv(h.callbacks(), Error, &[msg]);
		return Err(e.errno().unwrap_or(Errno::Ok).into());
	}
	h.callbacks().event(&Event::DiskspaceDone);
	Ok(())
}

// _alpm_db_find_fileconflicts on trans.add and trans.remove, the local
// files loaded first (the C getters load them as the check goes), the
// paths changing hands appended to trans.skip_remove
fn find_fileconflicts(h: &mut Handle) -> Vec<FileConflict> {
	let d = h.dbs_mut();
	if let Some(db) = d.local {
		let _ = db.load_all(d.dbext, d.cb, INFRQ_FILES);
	}
	let mut trans = h.set_trans(None).expect("committing");
	let empty = PkgHash::new(0).expect("empty table");
	let out = h.with_callbacks(|h, cb| {
		let local = h.localdb().and_then(|db| db.loaded_pkgcache());
		let check = FileCheck {
			root: h.root(),
			local: local.unwrap_or(&empty),
			overwrite: h.overwrite_files(),
		};
		let add: Vec<&Package> =
			trans.add.iter().map(|t| &t.pkg).collect();
		let rem: Vec<&Package> = trans.remove.iter().collect();
		check.find_fileconflicts(&add, &rem, cb)
	});
	trans.skip_remove.extend(out.skip_remove);
	h.set_trans(Some(trans));
	out.conflicts
}

// _alpm_sync_commit: the conflicting and replaced packages removed, then
// the targets installed. the C's "could not commit removal transaction"
// branch is dead: _alpm_remove_single_package always returns 0
pub(crate) fn sync_commit(h: &mut Handle) -> Result<(), Errno> {
	if !h.trans().expect("committing").remove.is_empty() {
		let msg = b"removing conflicting and to-be-replaced packages\n";
		logv(h.callbacks(), Debug, &[msg]);
		remove::remove_packages(h, false);
	}
	logv(h.callbacks(), Debug, &[b"installing packages\n"]);
	add::upgrade_packages(h).inspect_err(|_| {
		let msg = b"could not commit transaction\n";
		logv(h.callbacks(), Error, &[msg]);
	})
}
