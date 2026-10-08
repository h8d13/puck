// port of lib/libalpm/remove.c: alpm_remove_pkg and _alpm_remove_prepare
// (cascade, keep needed, optdepend notices), then the commit side of one
// package (_alpm_remove_single_package and its file removal) and the
// loop over trans->remove (_alpm_remove_packages). trans->remove holds
// dups of local packages; the C dups force-load every section, trans.rs
// reloads them fully after prepare.

use std::ffi::{OsStr, c_int, c_ulong};
use std::fs;
use std::ops::ControlFlow;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use pacman_common::util_common::{mbasename, mdirname};
use rustix::fs::Access;

use crate::backup::needbackup;
use crate::be_local::{INFRQ_FILES, scan_zu};
use crate::callbacks::{
	Callbacks, Event, LogLevel, PackageOp, PackageOperation, Progress, logv,
};
use crate::deps::{
	DepMissing, checkdeps, dep_compute_string, find_satisfier, recursedeps,
};
use crate::error::Errno;
use crate::handle::Handle;
use crate::package::{Package, PkgFrom, has_name, pkg_cmp, pkg_find};
use crate::regex::{Flags, Regex};
use crate::trans::{
	PrepareData, PrepareError, TRANS_FLAG_CASCADE, TRANS_FLAG_DBONLY,
	TRANS_FLAG_NODEPS, TRANS_FLAG_NODEPVERSION, TRANS_FLAG_NOSAVE,
	TRANS_FLAG_NOSCRIPTLET, TRANS_FLAG_RECURSE, TRANS_FLAG_RECURSEALL,
	TRANS_FLAG_UNNEEDED, Trans, TransState, View, interrupted, opt_str,
	runscriptlet, trans_in,
};
use crate::util::{
	CALLER_PREFIX, PATH_MAX, alpm_access, compute_md5sum,
	files_in_directory, fnmatch_patterns, ldconfig, llstat, strerror,
	until_nul,
};

use LogLevel::{Debug, Error, Warning};

// alpm_remove_pkg: a local package joins the removals once, as a dup of
// its fully loaded cache entry. other origins are WrongArgs
pub fn remove_pkg(h: &mut Handle, pkg: &Package) -> Result<(), Errno> {
	if pkg.origin != Some(PkgFrom::LocalDb) {
		return Err(Errno::WrongArgs);
	}
	let trans = trans_in(h, TransState::Initialized)?;
	let name = opt_str(&pkg.name).to_vec();
	if pkg_find(&trans.remove, pkg.name_bytes()).is_some() {
		let msg = [b"skipping duplicate target: ", &name[..], b"\n"];
		logv(h.callbacks(), Debug, &msg);
		return Ok(());
	}
	let msg = [
		b"adding package ",
		&name[..],
		b" to the transaction remove list\n",
	];
	logv(h.callbacks(), Debug, &msg);
	let dbs = h.dbs_mut();
	let (dbext, cb) = (dbs.dbext, dbs.cb);
	let full = dbs
		.local
		.and_then(|db| {
			db.force_load_pkg(dbext, cb, pkg.name_bytes()).ok()
		})
		.map(Package::dup);
	let copy = full.unwrap_or_else(|| pkg.dup());
	let trans = h.trans_mut().expect("checked above");
	trans.remove.push(copy);
	Ok(())
}

fn checkdeps_rev(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &Trans,
) -> Vec<DepMissing> {
	let nodepversion = trans.flags & TRANS_FLAG_NODEPVERSION != 0;
	let env = view.env(nodepversion);
	let rem: Vec<&Package> = trans.remove.iter().collect();
	checkdeps(&env, &view.local_list(), &rem, &[], true, cb)
}

// remove_prepare_cascade (static in C): the local packages whose
// dependencies break join the removals, until nothing breaks
fn cascade(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
	mut lp: Vec<DepMissing>,
) {
	while !lp.is_empty() {
		for miss in &lp {
			let Some(info) = view.local.find(&miss.target) else {
				let msg = [
					b"could not find ",
					&miss.target[..],
					b" in database -- skipping\n",
				];
				logv(cb, Error, &msg);
				continue;
			};
			if pkg_find(&trans.remove, info.name_bytes()).is_some()
			{
				continue;
			}
			let msg = [
				b"pulling ",
				opt_str(&info.name),
				b" in target list\n",
			];
			logv(cb, Debug, &msg);
			trans.remove.push(info.dup());
		}
		lp = checkdeps_rev(view, cb, trans);
	}
}

// remove_prepare_keep_needed (static in C): removals that break a
// dependency leave the target list, until nothing breaks
fn keep_needed(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
	mut lp: Vec<DepMissing>,
) {
	while !lp.is_empty() {
		for miss in &lp {
			let causing =
				miss.causingpkg.as_deref().unwrap_or_default();
			let Some(pkg) = pkg_find(&trans.remove, causing) else {
				continue;
			};
			// alpm_list_remove with _alpm_pkg_cmp: the first of that
			// name
			let i = trans
				.remove
				.iter()
				.position(|p| pkg_cmp(p, pkg).is_eq())
				.expect("found above");
			let gone = trans.remove.remove(i);
			let msg = [
				b"removing ",
				opt_str(&gone.name),
				b" from target list\n",
			];
			logv(cb, Warning, &msg);
		}
		lp = checkdeps_rev(view, cb, trans);
	}
}

// remove_notify_needed_optdepends (static in C): an OPTDEP_REMOVAL event
// per optdepend of a remaining local package a removal satisfies
fn notify_optdepends(view: &View, cb: &mut dyn Callbacks, trans: &Trans) {
	for pkg in view.local.iter() {
		if pkg.optdepends.is_empty()
			|| pkg_find(&trans.remove, pkg.name_bytes()).is_some()
		{
			continue;
		}
		for optdep in &pkg.optdepends {
			let optstring = dep_compute_string(optdep);
			if find_satisfier(&trans.remove, &optstring).is_some() {
				cb.event(&Event::OptdepRemoval { pkg, optdep });
			}
		}
	}
}

// _alpm_remove_prepare: -Rs adds what only the targets need (after the
// cascade with -Rcs), a broken dependency pulls its package in (-Rc),
// drops the removal that breaks it (-Ru) or fails with the missing
// dependencies
pub(crate) fn remove_prepare(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
) -> Result<(), PrepareError> {
	let flags = trans.flags;
	let recurse = flags & TRANS_FLAG_RECURSE != 0;
	let cascading = flags & TRANS_FLAG_CASCADE != 0;
	let nodeps = flags & TRANS_FLAG_NODEPS != 0;
	let explicit = flags & TRANS_FLAG_RECURSEALL != 0;
	if recurse && !cascading {
		logv(cb, Debug, &[b"finding removable dependencies\n"]);
		recursedeps(view.local, &mut trans.remove, explicit, cb);
	}

	if !nodeps {
		cb.event(&Event::CheckdepsStart);
		logv(cb, Debug, &[b"looking for unsatisfied dependencies\n"]);
		let lp = checkdeps_rev(view, cb, trans);
		if !lp.is_empty() {
			if cascading {
				cascade(view, cb, trans, lp);
			} else if flags & TRANS_FLAG_UNNEEDED != 0 {
				keep_needed(view, cb, trans, lp);
			} else {
				let data = PrepareData::Missing(lp);
				let e = Errno::UnsatisfiedDeps;
				return Err(PrepareError::new(e, data));
			}
		}
	}

	if cascading && recurse {
		logv(cb, Debug, &[b"finding removable dependencies\n"]);
		recursedeps(view.local, &mut trans.remove, explicit, cb);
	}

	if !nodeps {
		notify_optdepends(view, cb, trans);
		cb.event(&Event::CheckdepsDone);
	}
	Ok(())
}

// commit side: _alpm_remove_single_package with its static helpers
// (dir_is_mountpoint, can_remove_file, shift_pacsave, unlink_file,
// should_skip_file, remove_package_files). flags and skip_remove
// come from h.trans(); oldpkg is a trans->remove dup (every section
// loaded, as alpm_remove_pkg leaves it), newpkg the upgrading package
// with its files sorted. the local cache is walked with INFRQ_FILES
// loaded in place, like the C getters. the debug lines of
// _alpm_files_in_directory, _alpm_access and
// _alpm_db_remove_pkgfromcache are logged here, the ported helpers do
// not log

// path of a C string
fn os(path: &[u8]) -> &Path {
	Path::new(OsStr::from_bytes(until_nul(path)))
}

// snprintf(buf, PATH_MAX, "%s%s", a, b): cut to PATH_MAX - 1 bytes
fn join_path(a: &[u8], b: &[u8]) -> Vec<u8> {
	let mut p = [until_nul(a), until_nul(b)].concat();
	p.truncate(PATH_MAX - 1);
	p
}

fn logaction(h: &mut Handle, parts: &[&[u8]]) {
	let _ = h.logaction(CALLER_PREFIX, &parts.concat());
}

// dir_is_mountpoint (static in C): directory ends in '/'; its st_dev
// (stat'ed when dev is None) differs from the one of "<directory>..".
// a failed stat is no mountpoint
fn dir_is_mountpoint(
	cb: &mut dyn Callbacks,
	directory: &[u8],
	dev: Option<u64>,
) -> bool {
	let dev = match dev {
		Some(d) => d,
		None => match fs::metadata(os(directory)) {
			Ok(m) => m.dev(),
			Err(e) => {
				let msg = [
					b"failed to stat directory ",
					directory,
					b": ",
					&strerror(&e),
					b"\n",
				];
				logv(cb, Debug, &msg);
				return false;
			}
		},
	};
	let parent = join_path(directory, b"..");
	match fs::metadata(os(&parent)) {
		Ok(m) => dev != m.dev(),
		Err(e) => {
			let msg = [
				b"failed to stat parent of ",
				directory,
				b": ",
				&parent,
				b": ",
				&strerror(&e),
				b"\n",
			];
			logv(cb, Debug, &msg);
			false
		}
	}
}

// can_remove_file (static in C): false only for a file that exists but
// is not writable for another reason than its permissions (EROFS). a
// mountpoint directory counts as removable
fn can_remove_file(h: &mut Handle, name: &[u8]) -> bool {
	let filepath = join_path(h.root(), name);
	let cb = h.callbacks();
	// the C reads name[strlen - 1], empty names never get here
	if name.last() == Some(&b'/') && dir_is_mountpoint(cb, &filepath, None)
	{
		return true;
	}
	let Err(e) = alpm_access(cb, None, &filepath, Access::WRITE_OK) else {
		return true;
	};
	if e == rustix::io::Errno::ACCESS
		|| e == rustix::io::Errno::TXTBSY
		|| alpm_access(cb, None, &filepath, Access::EXISTS).is_err()
	{
		return true;
	}
	let err = strerror(&e.into());
	let msg = [b"cannot remove file '", &filepath[..], b"': ", &err, b"\n"];
	logv(cb, Error, &msg);
	false
}

// shift_pacsave (static in C): file.pacsave.N becomes .N+1 from the
// highest N down, then file.pacsave becomes file.pacsave.1. N is found
// by the C's regex built from the unescaped basename and read at the
// basename's length past the name start (UPSTREAM.md); past the end of
// the name it reads as 0 here
fn shift_pacsave(cb: &mut dyn Callbacks, file: &[u8]) {
	let dirname = mdirname(file);
	let basename = mbasename(file);
	let mut regstr =
		[b"^", basename, b"\\.pacsave\\.([[:digit:]]+)$"].concat();
	regstr.truncate(PATH_MAX - 1);
	let flags = Flags {
		icase: false,
		newline: true,
	};
	let Ok(reg) = Regex::new(&regstr, flags) else {
		return;
	};
	let dir = match fs::read_dir(os(&dirname)) {
		Ok(d) => d,
		Err(e) => {
			let msg = [
				b"could not open directory: ",
				&dirname[..],
				b": ",
				&strerror(&e),
				b"\n",
			];
			logv(cb, Error, &msg);
			return;
		}
	};
	let mut log_max: c_ulong = 0;
	for ent in dir.map_while(Result::ok) {
		let name = ent.file_name();
		let name = name.as_bytes();
		if !reg.is_match(name) {
			continue;
		}
		let at = basename.len() + b".pacsave.".len();
		let num = name.get(at..).unwrap_or_default();
		log_max = log_max.max(scan_zu(num).unwrap_or(0));
	}

	let overflow = |cb: &mut dyn Callbacks| {
		let msg = [
			b"could not backup ",
			file,
			b" due to PATH_MAX overflow\n",
		];
		logv(cb, Error, &msg);
	};
	// log_max at ULONG_MAX wraps to 0 and shifts nothing, like the C
	let mut i = log_max.wrapping_add(1);
	while i > 1 {
		let (prev, cur) = ((i - 1).to_string(), i.to_string());
		let old = [file, b".pacsave.", prev.as_bytes()].concat();
		let new = [file, b".pacsave.", cur.as_bytes()].concat();
		if old.len() >= PATH_MAX || new.len() >= PATH_MAX {
			return overflow(cb);
		}
		let _ = fs::rename(os(&old), os(&new));
		i -= 1;
	}
	let old = [file, b".pacsave"].concat();
	let new = [&old[..], b".1"].concat();
	if old.len() >= PATH_MAX || new.len() >= PATH_MAX {
		return overflow(cb);
	}
	// stat: a dangling .pacsave link stays and is overwritten later
	if fs::metadata(os(&old)).is_ok() {
		let _ = fs::rename(os(&old), os(&new));
	}
}

// what unlink_file did: C 0, 1 and -1
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unlinked {
	// removed, saved as .pacsave, or a directory kept
	Done,
	// missing
	Skipped,
	Failed,
}

// errno of opendir on a non-directory
const ENOTDIR: i32 = 20;

// _alpm_files_in_directory(handle, path, 0): None is the C's -1
fn has_entries(cb: &mut dyn Callbacks, path: &[u8]) -> Option<bool> {
	match files_in_directory(path, false) {
		Ok(n) => Some(n > 0),
		Err(e) => {
			let msg: [&[u8]; 3] = match e.raw_os_error() {
				Some(ENOTDIR) => {
					[b"", path, b" was not a directory\n"]
				}
				_ => [
					b"could not read directory ",
					path,
					b"\n",
				],
			};
			logv(cb, Debug, &msg);
			None
		}
	}
}

// unlink_file (static in C), a directory: removed when empty, not in
// newpkg, no mountpoint and no other local package owns it. file ends
// in '/'
fn unlink_dir(
	h: &mut Handle,
	oldpkg: &Package,
	newpkg: Option<&Package>,
	name: &[u8],
	file: &[u8],
	dev: u64,
) -> Unlinked {
	let keep = |h: &mut Handle, why: &[u8]| {
		let msg = [b"keeping directory ", file, b" (", why, b")\n"];
		logv(h.callbacks(), Debug, &msg);
		Unlinked::Done
	};
	match has_entries(h.callbacks(), file) {
		Some(true) => return keep(h, b"contains files"),
		None => return keep(h, b"could not count files"),
		Some(false) => {}
	}
	if newpkg.is_some_and(|p| p.files.contains(name).is_some()) {
		return keep(h, b"in new package");
	}
	if dir_is_mountpoint(h.callbacks(), file, Some(dev)) {
		return keep(h, b"mountpoint");
	}
	// the dup in trans->remove is not the cache entry: skip by name
	let (oname, ohash) = (oldpkg.name_bytes(), oldpkg.name_hash);
	let dbs = h.dbs_mut();
	let owner = dbs.local.and_then(|db| {
		let found = db.walk(dbs.dbext, dbs.cb, INFRQ_FILES, |_, p| {
			if has_name(p, oname, ohash)
				|| p.files.contains(name).is_none()
			{
				return ControlFlow::Continue(());
			}
			ControlFlow::Break(opt_str(&p.name).to_vec())
		});
		found.ok().flatten()
	});
	if let Some(owner) = owner {
		return keep(h, &[b"owned by ", &owner[..]].concat());
	}
	if let Err(e) = fs::remove_dir(os(file)) {
		let err = strerror(&e);
		let msg = [
			b"directory removal of ",
			file,
			b" failed: ",
			&err,
			b"\n",
		];
		logv(h.callbacks(), Debug, &msg);
		return Unlinked::Failed;
	}
	let msg = [b"removed directory ", file, b" (no remaining owners)\n"];
	logv(h.callbacks(), Debug, &msg);
	Unlinked::Done
}

// unlink_file, the .pacsave of a modified backup file
fn save_file(h: &mut Handle, oldpkg: &Package, file: &[u8]) -> Unlinked {
	shift_pacsave(h.callbacks(), file);
	let newpath = [file, b".pacsave"].concat();
	if let Err(e) = fs::rename(os(file), os(&newpath)) {
		let err = strerror(&e);
		let what: [&[u8]; 6] = [
			b"could not rename ",
			file,
			b" to ",
			&newpath,
			b" (",
			&err,
		];
		let what = what.concat();
		logv(h.callbacks(), Error, &[&what[..], b")\n"]);
		logaction(h, &[b"error: ", &what[..], b")\n"]);
		return Unlinked::Failed;
	}
	let event = Event::PacsaveCreated { oldpkg, file };
	h.callbacks().event(&event);
	logaction(h, &[b"warning: ", file, b" saved as ", &newpath, b"\n"]);
	Unlinked::Done
}

// unlink_file (static in C): one file of oldpkg under the root. a
// backup file whose md5 differs from the recorded one is renamed to
// .pacsave unless nosave
fn unlink_file(
	h: &mut Handle,
	oldpkg: &Package,
	newpkg: Option<&Package>,
	name: &[u8],
	nosave: bool,
) -> Unlinked {
	let root = h.root().to_vec();
	let name = until_nul(name);
	let mut file = [&root[..], name].concat();
	if file.is_empty() || file.len() >= PATH_MAX {
		let msg = [b"path too long to unlink ", &root[..], name, b"\n"];
		logv(h.callbacks(), Debug, &msg);
		return Unlinked::Failed;
	}
	// a trailing '/' would follow a directory replaced by a symlink
	if file.last() == Some(&b'/') {
		file.pop();
	}
	let Ok(buf) = llstat(&file) else {
		let msg = [b"file ", &file[..], b" does not exist\n"];
		logv(h.callbacks(), Debug, &msg);
		return Unlinked::Skipped;
	};

	if buf.is_dir() {
		if file.len() >= PATH_MAX - 1 {
			let msg = [
				b"path too long to unlink ",
				&root[..],
				name,
				b"\n",
			];
			logv(h.callbacks(), Debug, &msg);
			return Unlinked::Failed;
		}
		file.push(b'/');
		return unlink_dir(h, oldpkg, newpkg, name, &file, buf.dev());
	}

	if let Some(backup) = needbackup(name, oldpkg) {
		if nosave {
			let msg = [
				b"transaction is set to NOSAVE, not backing up '",
				&file[..],
				b"'\n",
			];
			logv(h.callbacks(), Debug, &msg);
		} else {
			// an unreadable file counts as unmodified. a NULL
			// hash crashes the C's strcmp (UPSTREAM.md), here
			// the file counts as modified
			let modified =
				compute_md5sum(&file).is_some_and(|sum| {
					backup.hash.as_deref().map(until_nul)
						!= Some(&sum[..])
				});
			if modified {
				return save_file(h, oldpkg, &file);
			}
		}
	}

	logv(h.callbacks(), Debug, &[b"unlinking ", &file[..], b"\n"]);
	if let Err(e) = fs::remove_file(os(&file)) {
		let what: [&[u8]; 4] =
			[b"cannot remove ", &file, b" (", &strerror(&e)];
		let what = what.concat();
		logv(h.callbacks(), Error, &[&what[..], b")\n"]);
		logaction(h, &[b"error: ", &what[..], b")\n"]);
		return Unlinked::Failed;
	}
	Unlinked::Done
}

// should_skip_file (static in C): kept by NoUpgrade (a positive match),
// listed in skip_remove, or a backup file newpkg ships too
fn should_skip_file(
	h: &Handle,
	skip_remove: &[Vec<u8>],
	newpkg: Option<&Package>,
	path: &[u8],
) -> bool {
	fnmatch_patterns(h.noupgrades(), path) == Some(false)
		|| skip_remove.iter().any(|s| until_nul(s) == until_nul(path))
		|| newpkg.is_some_and(|p| {
			needbackup(path, p).is_some()
				&& p.files.contains(path).is_some()
		})
}

// remove_package_files (static in C): every file not skipped must be
// removable (else PkgCantRemove, nothing touched), then the files go in
// reverse list order. progress (REMOVE_START, howmany pkg_count, current
// targ_count) only without newpkg. Ok is the number of files that
// failed
fn remove_package_files(
	h: &mut Handle,
	flags: c_int,
	skip_remove: &[Vec<u8>],
	oldpkg: &Package,
	newpkg: Option<&Package>,
	targ_count: usize,
	pkg_count: usize,
) -> Result<usize, Errno> {
	let nosave = flags & TRANS_FLAG_NOSAVE != 0;
	let files = &oldpkg.files.files;
	let pkgname = oldpkg.name_bytes();
	for file in files {
		if !should_skip_file(h, skip_remove, newpkg, &file.name)
			&& !can_remove_file(h, &file.name)
		{
			let msg = [
				b"not removing package '",
				opt_str(&oldpkg.name),
				b"', can't remove all files\n",
			];
			logv(h.callbacks(), Debug, &msg);
			return Err(Errno::PkgCantRemove);
		}
	}

	let count = files.len().to_string();
	let msg = [b"removing ", count.as_bytes(), b" files\n"];
	logv(h.callbacks(), Debug, &msg);

	let progress = |h: &mut Handle, percent: usize| {
		if newpkg.is_none() {
			h.callbacks().progress(
				Progress::RemoveStart,
				pkgname,
				percent as c_int,
				pkg_count,
				targ_count,
			);
		}
	};
	progress(h, 0);
	let mut err = 0;
	for (i, file) in files.iter().enumerate().rev() {
		// see db_find_fileconflicts for why skip_remove is honoured
		if should_skip_file(h, skip_remove, newpkg, &file.name) {
			let msg = [
				until_nul(&file.name),
				b" is in skip_remove, skipping removal\n",
			];
			logv(h.callbacks(), Debug, &msg);
			continue;
		}
		let r = unlink_file(h, oldpkg, newpkg, &file.name, nosave);
		if r == Unlinked::Failed {
			err += 1;
		}
		progress(h, (files.len() - (i + 1)) * 100 / files.len());
	}
	progress(h, 100);
	Ok(err)
}

// _alpm_remove_single_package: a removal (no newpkg: events, scriptlets,
// progress and the "removed" log line) or the old half of an upgrade.
// files are removed unless DBONLY, then the local db entry and the cache
// entry go. the C returns 0 and drops the files' result, which is the
// Ok/Err here: Err(PkgCantRemove) is the pm_errno the C leaves on the
// upgrade path (the removal path's alpm_pkg_has_scriptlet resets it).
// no transaction is TransNull (the C dereferences NULL)
pub fn remove_single_package(
	h: &mut Handle,
	oldpkg: &Package,
	newpkg: Option<&Package>,
	targ_count: usize,
	pkg_count: usize,
) -> Result<usize, Errno> {
	let trans = h.trans().ok_or(Errno::TransNull)?;
	let (flags, skip_remove) = (trans.flags, trans.skip_remove.clone());
	let pkgname = opt_str(&oldpkg.name);
	let pkgver = opt_str(&oldpkg.version);
	let op = PackageOp {
		operation: PackageOperation::Remove,
		oldpkg: Some(oldpkg),
		newpkg: None,
		local: &[],
		pending: &[],
	};
	let scriptlet = newpkg.is_none()
		&& oldpkg.scriptlet != 0
		&& flags & TRANS_FLAG_NOSCRIPTLET == 0;
	let install = h
		.localdb()
		.and_then(|db| db.local())
		.map(|l| l.pkgpath(oldpkg, b"install"));

	if newpkg.is_some() {
		let msg = [
			b"removing old package first (",
			pkgname,
			b"-",
			pkgver,
			b")\n",
		];
		logv(h.callbacks(), Debug, &msg);
	} else {
		h.callbacks().event(&Event::PackageOperationStart(op));
		let msg = [b"removing package ", pkgname, b"-", pkgver, b"\n"];
		logv(h.callbacks(), Debug, &msg);
		if scriptlet && let Some(path) = &install {
			runscriptlet(
				h,
				path,
				b"pre_remove",
				pkgver,
				None,
				false,
			);
		}
	}

	let files = match flags & TRANS_FLAG_DBONLY {
		0 => remove_package_files(
			h,
			flags,
			&skip_remove,
			oldpkg,
			newpkg,
			targ_count,
			pkg_count,
		),
		_ => Ok(0),
	};

	if newpkg.is_none() {
		let msg = [b"removed ", pkgname, b" (", pkgver, b")\n"];
		logaction(h, &msg);
		if scriptlet && let Some(path) = &install {
			runscriptlet(
				h,
				path,
				b"post_remove",
				pkgver,
				None,
				false,
			);
		}
		h.callbacks().event(&Event::PackageOperationDone(op));
	}

	let msg = [b"removing database entry '", pkgname, b"'\n"];
	logv(h.callbacks(), Debug, &msg);
	remove_db_entry(h, oldpkg);
	files
}

// the local db entry and the cache entry of _alpm_remove_single_package.
// Db::remove_pkg_from_cache logs its own "removing entry" lines
fn remove_db_entry(h: &mut Handle, oldpkg: &Package) {
	let pkgname = opt_str(&oldpkg.name);
	let pkgver = opt_str(&oldpkg.version);
	let dbs = h.dbs_mut();
	let Some(db) = dbs.local else {
		return;
	};
	if let Some(Err(_)) = db.local().map(|l| l.remove(oldpkg)) {
		let msg = [
			b"could not remove database entry ",
			pkgname,
			b"-",
			pkgver,
			b"\n",
		];
		logv(dbs.cb, Error, &msg);
	}
	if db.remove_pkg_from_cache(dbs.cb, oldpkg).is_err() {
		let msg = [
			b"could not remove entry '",
			pkgname,
			b"' from cache\n",
		];
		logv(dbs.cb, Error, &msg);
	}
}

// _alpm_remove_packages: each package of trans.remove through
// remove_single_package, in order, until the transaction is interrupted
// (which also skips ldconfig). the C's failure branch (TRANS_ABORT, no
// ldconfig) is dead: _alpm_remove_single_package always returns 0, the
// files' result is dropped here like there
pub(crate) fn remove_packages(h: &mut Handle, run_ldconfig: bool) {
	let pkg_count = h.trans().map_or(0, |t| t.remove.len());
	for i in 0..pkg_count {
		if interrupted(h) {
			return;
		}
		let Some(trans) = h.trans() else {
			return;
		};
		// remove_single_package reads flags and skip_remove from the
		// transaction, the package goes in as a copy
		let pkg = trans.remove[i].clone();
		let _ = remove_single_package(h, &pkg, None, i + 1, pkg_count);
	}
	if run_ldconfig {
		ldconfig(h);
	}
}
