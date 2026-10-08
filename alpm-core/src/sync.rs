// port of the planning part of lib/libalpm/sync.c: alpm_sync_get_new_version,
// alpm_sync_sysupgrade (check_literal, check_replacers),
// alpm_find_group_pkgs, compute_download_size/alpm_pkg_download_size and
// _alpm_sync_prepare (with the db checks run before its caches load), and
// the handle-level entry of alpm_find_dbs_satisfier the frontend uses.
//
// not here: _alpm_sync_load, _alpm_sync_check, _alpm_sync_commit and the
// download/validation steps they run (the commit port).
//
// targets are TransPkg copies of the cache entries (trans.rs). the
// resolver works on references into those copies and the sync caches;
// its results are matched back by address like the C pointers.

use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::ptr;

use crate::callbacks::{Callbacks, Event, LogLevel, Question};
use crate::conflict::{Conflict, innerconflicts, outerconflicts};
use crate::db::DB_USAGE_UPGRADE;
use crate::deps::{
	DepMissing, checkdeps, dep_from_string, depcmp, depcmp_literal,
	find_dbs_satisfier, list_diff, resolvedeps,
};
use crate::error::Errno;
use crate::handle::Handle;
use crate::package::{
	Package, PkgFrom, PkgReason, pkg_compare_versions, pkg_find,
	pkg_should_ignore,
};
use crate::trans::{
	PrepareData, PrepareError, TRANS_FLAG_NEEDED, TRANS_FLAG_NOCONFLICTS,
	TRANS_FLAG_NODEPS, TRANS_FLAG_NODEPVERSION, Trans, TransPkg,
	TransState, View, load_caches, log, opt_str, trans_in, with_view,
};
use crate::util::{filecache_find, until_nul};

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
	let dbext = h.dbext().to_vec();
	let found =
		h.syncdbs_mut().iter_mut().enumerate().find_map(|(i, db)| {
			let spkg = db.get_pkg(&dbext, pkg.name_bytes()).ok()?;
			Some((i, spkg.clone()))
		});
	let cb = h.callbacks();
	let Some((i, spkg)) = found else {
		let msg = [
			b"'",
			name(pkg),
			b"' not found in sync db => no upgrade\n",
		];
		log(cb, Debug, &msg);
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
	log(cb, Debug, &msg);
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
			log(cb, Debug, &msg);
			if ignored(h, spkg, lpkg) {
				let head: [&[u8]; 2] = [
					&change,
					b"ignoring package upgrade (",
				];
				log(
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
			log(cb, Debug, &msg);
			true
		}
		Ordering::Less if enable_downgrade => {
			if ignored(h, spkg, lpkg) {
				let head: [&[u8]; 2] = [
					&change,
					b"ignoring package downgrade (",
				];
				log(
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
			log(cb, Warning, &msg);
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
			log(cb, Warning, &msg);
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
	log(cb, Debug, &msg);
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
			log(cb, Warning, &msg);
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
				log(cb, Warning, &msg);
				continue;
			}
			let msg = [
				b"appending ",
				name(lpkg),
				b" to the removes list of ",
				name(&tpkg.pkg),
				b"\n",
			];
			log(cb, Debug, &msg);
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
			log(cb, Debug, &msg);
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
	log(cb, Debug, &[b"checking for package upgrades\n"]);
	for lpkg in view.local.iter() {
		let n = lpkg.name_bytes();
		if pkg_find(&trans.remove, n).is_some() {
			let msg = [
				name(lpkg),
				b" is marked for removal -- skipping\n",
			];
			log(cb, Debug, &msg);
			continue;
		}
		if find_target(&trans.add, n).is_some() {
			let msg = [
				name(lpkg),
				b" is already in the target list -- skipping\n",
			];
			log(cb, Debug, &msg);
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
	let dbext = h.dbext().to_vec();
	let mut members = Vec::new();
	for &i in dbs {
		let Some(db) = h.syncdbs_mut().get_mut(i) else {
			continue;
		};
		if let Ok(Some(grp)) = db.get_group(&dbext, group) {
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
				log(cb, Warning, &msg);
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

// _alpm_filecache_find with its "found cached pkg" debug line
fn filecache_lookup(
	h: &Handle,
	cb: &mut dyn Callbacks,
	filename: &[u8],
) -> Option<Vec<u8>> {
	let path = filecache_find(h.cachedirs(), filename, cb)?;
	log(cb, Debug, &[b"found cached pkg: ", &path, b"\n"]);
	Some(path)
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
	use crate::be_local::INFRQ_DSIZE;
	if newpkg.origin != Some(PkgFrom::SyncDb) {
		newpkg.infolevel |= INFRQ_DSIZE;
		newpkg.download_size = 0;
		return Ok(false);
	}
	let fname = newpkg.filename.as_deref().ok_or(Errno::PkgInvalidName)?;
	let fname = until_nul(fname).to_vec();
	let mut partial = false;
	let size = if filecache_lookup(h, cb, &fname).is_some() {
		0
	} else {
		let part = [&fname[..], b".part"].concat();
		match filecache_lookup(h, cb, &part) {
			Some(path) => {
				partial = true;
				match fs::metadata(OsStr::from_bytes(&path)) {
					Ok(md) => {
						let msg = b"using (package - .part) size\n";
						log(cb, Debug, &[msg]);
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
	log(cb, Debug, &[msg.as_bytes(), name(newpkg), b"\n"]);
	newpkg.infolevel |= INFRQ_DSIZE;
	newpkg.download_size = size;
	Ok(partial)
}

// alpm_pkg_download_size: computed once (INFRQ_DSIZE), then the stored
// value
pub fn pkg_download_size(h: &mut Handle, newpkg: &mut Package) -> i64 {
	use crate::be_local::INFRQ_DSIZE;
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
	let dbext = h.dbext().to_vec();
	for &i in dbs {
		if let Some(db) = h.syncdbs_mut().get_mut(i) {
			let _ = db.pkgcache(&dbext);
		}
	}
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

// _alpm_sync_prepare after check_dbs: dependencies resolved (targets
// replaced by the resolved list, pulled ones as DEPEND), conflicts
// between targets and with the local db settled, removals collected,
// then the whole transaction checked; download sizes and oldpkgs last
pub(crate) fn sync_prepare(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
) -> Result<(), PrepareError> {
	if trans.flags & TRANS_FLAG_NODEPS == 0 {
		resolve(view, cb, trans)?;
	}
	if trans.flags & TRANS_FLAG_NOCONFLICTS == 0 {
		event(cb, Event::InterconflictsStart);
		log(cb, Debug, &[b"looking for conflicts\n"]);
		inner_conflicts(cb, trans)?;
		outer_conflicts(view, cb, trans)?;
		event(cb, Event::InterconflictsDone);
	}

	for t in &trans.add {
		for rpkg in &t.removes {
			if pkg_find(&trans.remove, rpkg.name_bytes()).is_some()
			{
				continue;
			}
			let msg = [
				b"adding '",
				name(rpkg),
				b"' to remove list\n",
			];
			log(cb, Debug, &msg);
			trans.remove.push(rpkg.dup());
		}
	}

	if trans.flags & TRANS_FLAG_NODEPS == 0 {
		log(cb, Debug, &[b"checking dependencies\n"]);
		let nodepversion = trans.flags & TRANS_FLAG_NODEPVERSION != 0;
		let env = view.env(nodepversion);
		let rem: Vec<&Package> = trans.remove.iter().collect();
		let add: Vec<&Package> =
			trans.add.iter().map(|t| &t.pkg).collect();
		let local = view.local_list();
		let deps = checkdeps(&env, &local, &rem, &add, true, cb);
		if !deps.is_empty() {
			let data = PrepareData::Missing(deps);
			return Err(PrepareError::new(
				Errno::UnsatisfiedDeps,
				data,
			));
		}
	}
	for t in &mut trans.add {
		compute_download_size(view.handle, cb, &mut t.pkg)?;
		if let Some(lpkg) = view.local.find(t.pkg.name_bytes()) {
			t.oldpkg = Some(lpkg.dup());
		}
	}
	Ok(())
}

// the resolver step of _alpm_sync_prepare: each target resolved against
// the local db without the targets, the unresolvable ones dropped after
// a yes to REMOVE_PKGS, two packages with one filename refused
fn resolve(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
) -> Result<(), PrepareError> {
	event(cb, Event::ResolvedepsStart);
	log(cb, Debug, &[b"resolving target's dependencies\n"]);
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
			log(cb, Error, &msg);
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
	log(cb, Debug, &[b"check targets vs targets\n"]);
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
		log(cb, Debug, &msg);
		let (dep1, dep2) = (dep_from_string(n1), dep_from_string(n2));
		let (s1, s2) = (&trans.add[i1].pkg, &trans.add[i2].pkg);
		let (rsync, sync) = if depcmp(s1, &dep2) {
			(i2, i1)
		} else if depcmp(s2, &dep1) {
			(i1, i2)
		} else {
			let msg = b"unresolvable package conflicts detected\n";
			log(cb, Error, &[msg]);
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
		log(cb, Warning, &msg);
		let gone = trans.add.remove(rsync);
		trans.unresolvable.push(gone);
	}
	Ok(())
}

// step 2: a target against an installed package not already leaving,
// settled by CONFLICT_PKG (yes elects the local package for removal)
fn outer_conflicts(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
) -> Result<(), PrepareError> {
	log(cb, Debug, &[b"check targets vs db and db vs targets\n"]);
	let deps = {
		let add: Vec<&Package> =
			trans.add.iter().map(|t| &t.pkg).collect();
		outerconflicts(view.local, &add, cb)
	};
	for conflict in &deps {
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
		log(cb, Debug, &msg);
		let mut q = Question::ConflictPkg {
			remove: 0,
			conflict,
		};
		cb.question(&mut q);
		if q.answer() == 0 {
			let msg = b"unresolvable package conflicts detected\n";
			log(cb, Error, &[msg]);
			return Err(conflict_err(conflict));
		}
		let i = position(&trans.add, p1.name_bytes())
			.expect("package1 of an outer conflict is a target");
		let local = view
			.local
			.find(n2)
			.expect("package2 of an outer conflict is installed");
		log(cb, Debug, &[b"electing '", name(p2), b"' for removal\n"]);
		trans.add[i].removes.push(local.clone());
	}
	Ok(())
}
