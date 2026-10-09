// port of lib/libalpm/conflict.c: dependency conflicts between targets and
// against the local db, and file conflicts between targets and against the
// filesystem.
//
// handle state comes in as parameters: the local db as its package cache
// (pkghash order is the C's cache list order), root and the overwrite
// globs through FileCheck. the C getters lazy-load local packages, here
// the caller loads them first (INFRQ_DESC for dependency conflicts,
// INFRQ_FILES for file conflicts, INFRQ_ALL where a conflict copies them).
// both checks log through Callbacks like the C (the file check's debug
// lines as conflict.c has them). allocation failures are not modelled
// (the C returns NULL or drops entries). progress goes through
// Callbacks, handle->progresscb in the C.

use std::borrow::Borrow;
use std::ffi::{OsStr, c_int};
use std::fs;
use std::os::unix::ffi::OsStrExt;

use crate::backup::needbackup;
use crate::be_local::INFRQ_ERROR;
use crate::callbacks::{Callbacks, LogLevel, Progress, logv};
use crate::deps::{Depend, dep_compute_string, depcmp, list_diff};
use crate::package::{Package, PkgFrom, has_name};
use crate::pkghash::PkgHash;
use crate::util::{PATH_MAX, fnmatch_patterns, llstat, until_nul};

use LogLevel::Debug;

/// alpm_conflict_t. the C dups both packages and points reason into the
/// conflicts list of the package that declares it, cloned here
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
	pub package1: Package,
	pub package2: Package,
	pub reason: Depend,
}

/// alpm_fileconflicttype_t, discriminants as in alpm.h
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileConflictType {
	Target = 1,
	Filesystem,
}

/// alpm_fileconflict_t
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileConflict {
	/// name of the package installing file
	pub target: Vec<u8>,
	pub conflict_type: FileConflictType,
	/// root + path, the trailing '/' of a directory dropped when the
	/// filesystem has something else there
	pub file: Vec<u8>,
	/// owner of file, empty when unowned
	pub ctarget: Vec<u8>,
}

fn same_name(a: &Package, b: &Package) -> bool {
	has_name(a, b.name_bytes(), b.name_hash)
}

// conflict_new on packages dup'ed as they are: _alpm_pkg_dup
// force-loads a local package and fails when that fails (INFRQ_ERROR
// from an earlier read), the conflict is then dropped. a local entry
// read in place goes through Db::dup_pkg instead (sync's outer
// conflicts)
fn dup_fails(pkg: &Package) -> bool {
	pkg.origin == Some(PkgFrom::LocalDb) && pkg.infolevel & INFRQ_ERROR != 0
}

// add_conflict after conflict_new: a pair already listed (by both
// names) is dropped, else listed and logged
pub fn add_conflict(
	baddeps: &mut Vec<Conflict>,
	conflict: Conflict,
	log: &mut dyn Callbacks,
) {
	let (pkg1, pkg2) = (&conflict.package1, &conflict.package2);
	let isin = baddeps.iter().any(|c| {
		same_name(&c.package1, pkg1) && same_name(&c.package2, pkg2)
	});
	if isin {
		return;
	}
	let name = |p: &Package| {
		p.name.as_deref().map_or(&b"(null)"[..], until_nul).to_vec()
	};
	let line: [&[u8]; 7] = [
		b"package ",
		&name(pkg1),
		b" conflicts with ",
		&name(pkg2),
		b" (by ",
		&dep_compute_string(&conflict.reason),
		b")\n",
	];
	logv(log, Debug, &line);
	baddeps.push(conflict);
}

// check_conflict's loops: every (pkg1, pkg2, reason) the C hands to
// add_conflict, in order, package1 first (the list2 package with
// reversed, the C's order < 0). the caller makes the conflicts
// (conflict_new's dups) and adds them
pub fn check_conflict<'a>(
	list1: &[&'a Package],
	list2: &[&'a Package],
	reversed: bool,
) -> Vec<(&'a Package, &'a Package, &'a Depend)> {
	let mut found = Vec::new();
	for pkg1 in list1 {
		for conflict in &pkg1.conflicts {
			for pkg2 in list2 {
				if same_name(pkg1, pkg2)
					|| !depcmp(pkg2, conflict)
				{
					continue;
				}
				found.push(match reversed {
					false => (*pkg1, *pkg2, conflict),
					true => (*pkg2, *pkg1, conflict),
				});
			}
		}
	}
	found
}

// _alpm_innerconflicts: conflicts within packages, dup'ed as they are
pub fn innerconflicts(
	packages: &[&Package],
	log: &mut dyn Callbacks,
) -> Vec<Conflict> {
	let mut baddeps = Vec::new();
	logv(log, Debug, &[b"check targets vs targets\n"]);
	for (pkg1, pkg2, reason) in check_conflict(packages, packages, false) {
		if dup_fails(pkg1) || dup_fails(pkg2) {
			continue;
		}
		let conflict = Conflict {
			package1: pkg1.dup(),
			package2: pkg2.dup(),
			reason: reason.clone(),
		};
		add_conflict(&mut baddeps, conflict, log);
	}
	baddeps
}

/// alpm_checkconflicts: the handle is only checked for NULL
pub fn checkconflicts(
	packages: &[&Package],
	log: &mut dyn Callbacks,
) -> Vec<Conflict> {
	innerconflicts(packages, log)
}

// result of _alpm_db_find_fileconflicts
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileConflicts {
	pub conflicts: Vec<FileConflict>,
	/// paths appended to handle->trans->skip_remove, files changing
	/// hands between two targets
	pub skip_remove: Vec<Vec<u8>>,
}

/// the handle state _alpm_db_find_fileconflicts reads
pub struct FileCheck<'a, P> {
	/// handle->root, ends in '/'
	pub root: &'a [u8],
	/// handle->db_local's cache, files loaded
	pub local: &'a PkgHash<P>,
	/// handle->overwrite_files
	pub overwrite: &'a [Vec<u8>],
}

fn os(path: &[u8]) -> &OsStr {
	OsStr::from_bytes(path)
}

// snprintf into a PATH_MAX buffer: cut to PATH_MAX - 1 bytes
fn cat(parts: &[&[u8]]) -> Vec<u8> {
	let mut p = parts.concat();
	p.truncate(PATH_MAX - 1);
	p
}

fn has_file(pkg: &Package, path: &[u8]) -> bool {
	pkg.files.contains(path).is_some()
}

// add_fileconflict: a local owner makes it a filesystem conflict too
fn fileconflict(
	file: Vec<u8>,
	pkg1: &Package,
	pkg2: Option<&Package>,
	cb: &mut dyn Callbacks,
) -> FileConflict {
	let owner = pkg2.map_or(&b"(filesystem)"[..], Package::name_bytes);
	let line: [&[u8]; 7] = [
		b"found file conflict ",
		&file,
		b", packages ",
		pkg1.name_bytes(),
		b" and ",
		owner,
		b"\n",
	];
	logv(cb, Debug, &line);
	let (conflict_type, ctarget) = match pkg2 {
		None => (FileConflictType::Filesystem, &[][..]),
		Some(p) if p.origin == Some(PkgFrom::LocalDb) => {
			(FileConflictType::Filesystem, p.name_bytes())
		}
		Some(p) => (FileConflictType::Target, p.name_bytes()),
	};
	FileConflict {
		target: pkg1.name_bytes().to_vec(),
		conflict_type,
		file,
		ctarget: ctarget.to_vec(),
	}
}

// dir_belongsto_pkgs: every entry under root + dirpath, recursively, is
// in the file list of one of pkgs. lstat decides what is a directory, so
// a symlink to one is checked as a file. readdir order does not matter,
// any unowned entry or lstat failure answers no; readdir order only
// picks which one is logged. a readdir error ends the walk like the end
// of the directory. an unowned subdirectory is logged at each level
fn dir_belongsto_pkgs(
	root: &[u8],
	dirpath: &[u8],
	pkgs: &[&Package],
	cb: &mut dyn Callbacks,
) -> bool {
	let Ok(dir) = fs::read_dir(os(&cat(&[root, dirpath]))) else {
		return false;
	};
	for ent in dir {
		let Ok(ent) = ent else {
			break;
		};
		let name = ent.file_name();
		let name = name.as_bytes();
		let full = cat(&[root, dirpath, name]);
		let Ok(meta) = fs::symlink_metadata(os(&full)) else {
			logv(cb, Debug, &[b"could not stat ", &full, b"\n"]);
			return false;
		};
		let is_dir = meta.is_dir();
		let slash: &[u8] = if is_dir { b"/" } else { b"" };
		let path = cat(&[dirpath, name, slash]);
		let owned = pkgs.iter().any(|p| has_file(p, &path))
			&& (!is_dir
				|| dir_belongsto_pkgs(root, &path, pkgs, cb));
		if !owned {
			let msg = b" found in directory\n";
			logv(cb, Debug, &[b"unowned file ", &path, msg]);
			return false;
		}
	}
	true
}

// check_filesystem's debug lines of a resolved conflict
const REPLACING_FILE: &[u8] =
	b"replacing package file with a directory, not a conflict\n";
const LOCAL_REMOVED: &[u8] = b"local file will be removed, not a conflict\n";
const CHANGED_HANDS: &[u8] =
	b"file changed packages, adding to remove skiplist\n";
const UNOWNED_BACKUP: &[u8] = b"file was unowned but in new backup list\n";
const FORCED: &[u8] = b"conflict with file on filesystem being forced\n";

// the entries after newfiles[j] inside directory filestr: the C moves j
// to the last of them, the walk goes on after it
fn skip_inside(newfiles: &[&[u8]], j: &mut usize, filestr: &[u8]) {
	while newfiles
		.get(*j + 1)
		.is_some_and(|next| next.starts_with(filestr))
	{
		*j += 1;
	}
}

impl<P: Borrow<Package>> FileCheck<'_, P> {
	fn cache(&self) -> impl Iterator<Item = &Package> {
		self.local.iter().map(Borrow::borrow)
	}

	// _alpm_db_get_pkgfromcache on db_local
	fn local_pkg(&self, name: &[u8]) -> Option<&Package> {
		self.local.find(name).map(Borrow::borrow)
	}

	// _alpm_find_file_owner: first local package in cache order
	fn file_owner(&self, path: &[u8]) -> Option<&Package> {
		self.cache().find(|p| has_file(p, path))
	}

	// _alpm_can_overwrite_file: a non-negated glob matches the path as
	// packaged or with root prepended
	fn can_overwrite(&self, path: &[u8], rootedpath: &[u8]) -> bool {
		let ok = |s| fnmatch_patterns(self.overwrite, s) == Some(false);
		ok(path) || ok(rootedpath)
	}

	// CHECK 1: p1 against the targets after it, through the pathcmp
	// intersection. overwrite only skips paths p2 has in the same form
	// (file-file), so dir-file pairs stay conflicts
	fn check_targets(
		&self,
		p1: &Package,
		rest: &[&Package],
		out: &mut FileConflicts,
		cb: &mut dyn Callbacks,
	) {
		let name = p1.name_bytes();
		logv(
			cb,
			Debug,
			&[b"searching for file conflicts: ", name, b"\n"],
		);
		for p2 in rest {
			for filename in p1.files.intersection(&p2.files) {
				let path = cat(&[self.root, filename]);
				if self.can_overwrite(filename, &path)
					&& has_file(p2, filename)
				{
					let line: [&[u8]; 6] = [
						filename,
						b" exists in both '",
						name,
						b"' and '",
						p2.name_bytes(),
						b"'\n",
					];
					logv(cb, Debug, &line);
					let msg = b"file-file conflict being forced\n";
					logv(cb, Debug, &[msg]);
					continue;
				}
				out.conflicts.push(fileconflict(
					path,
					p1,
					Some(p2),
					cb,
				));
			}
		}
	}

	// the directory at relative_path (no trailing '/') is owned only by
	// dbpkg and rem, and every entry below it by those owners
	fn dir_is_replaced(
		&self,
		relative_path: &[u8],
		dbpkg: Option<&Package>,
		rem: &[&Package],
		cb: &mut dyn Callbacks,
	) -> bool {
		let dir = [relative_path, b"/"].concat();
		let owners: Vec<&Package> =
			self.cache().filter(|p| has_file(p, &dir)).collect();
		if owners.is_empty() {
			return false;
		}
		let pkgs: Vec<&Package> =
			dbpkg.into_iter().chain(rem.iter().copied()).collect();
		if !list_diff(&owners, &pkgs).is_empty() {
			return false;
		}
		let msg = b" belong to removed packages\n";
		logv(cb, Debug, &[b"checking if all files in ", &dir, msg]);
		dir_belongsto_pkgs(self.root, &dir, &owners, cb)
	}

	// CHECK 2: files of p1 new to the installed version (all of them
	// when not installed) that exist under root, minus the cases where
	// the transaction takes care of what is there
	fn check_filesystem(
		&self,
		p1: &Package,
		upgrade: &[&Package],
		rem: &[&Package],
		out: &mut FileConflicts,
		cb: &mut dyn Callbacks,
	) {
		let rootlen = self.root.len();
		let name = p1.name_bytes();
		let msg = b"searching for filesystem conflicts: ";
		logv(cb, Debug, &[msg, name, b"\n"]);
		let dbpkg = self.local_pkg(p1.name_bytes());
		let newfiles: Vec<&[u8]> = match dbpkg {
			Some(db) => p1.files.difference(&db.files),
			None => {
				p1.files.files
					.iter()
					.map(|f| f.name())
					.collect()
			}
		};
		let mut j = 0;
		while j < newfiles.len() {
			let filestr = newfiles[j];
			let mut path = cat(&[self.root, filestr]);
			let Ok(lsbuf) = llstat(&path) else {
				j += 1;
				continue;
			};
			let msg = b"checking possible conflict: ";
			logv(cb, Debug, &[msg, &path, b"\n"]);
			let is_dir = lsbuf.is_dir();
			let mut resolved = false;
			// the C reads path[pathlen - 1] with the untruncated length,
			// past the buffer for paths over PATH_MAX; the cut path here
			let pfile_isdir = path.last() == Some(&b'/');
			if pfile_isdir {
				if is_dir {
					let msg = b"file is a directory, not a conflict\n";
					logv(cb, Debug, &[msg]);
					j += 1;
					continue;
				}
				// compared without the '/' from here on, a file in
				// the old version may become a directory
				path.pop();
				let relative_path =
					path.get(rootlen..).unwrap_or_default();
				if dbpkg.is_some_and(|db| {
					has_file(db, relative_path)
				}) {
					logv(cb, Debug, &[REPLACING_FILE]);
					resolved = true;
					skip_inside(&newfiles, &mut j, filestr);
				}
			}
			let relative_path =
				path.get(rootlen..).unwrap_or_default();

			// a removed package owns what is there
			for rempkg in rem {
				if resolved {
					break;
				}
				if has_file(rempkg, relative_path) {
					logv(cb, Debug, &[LOCAL_REMOVED]);
					resolved = true;
					if pfile_isdir {
						skip_inside(
							&newfiles, &mut j,
							filestr,
						);
					}
				}
			}

			// the installed version of another target owns it: the
			// file changes hands, its removal is skipped
			for p2 in upgrade {
				if resolved {
					break;
				}
				if std::ptr::eq(*p2, p1) {
					continue;
				}
				let Some(localp2) =
					self.local_pkg(p2.name_bytes())
				else {
					continue;
				};
				if has_file(localp2, relative_path) {
					out.skip_remove
						.push(relative_path.to_vec());
					logv(cb, Debug, &[CHANGED_HANDS]);
					resolved = true;
					if filestr.last() == Some(&b'/') {
						skip_inside(
							&newfiles, &mut j,
							filestr,
						);
					}
				}
			}

			if !resolved && is_dir {
				resolved = self.dir_is_replaced(
					relative_path,
					dbpkg,
					rem,
					cb,
				);
			}

			// unowned and in the new package's backup list
			if !resolved
				&& needbackup(relative_path, p1).is_some()
				&& self.file_owner(relative_path).is_none()
			{
				logv(cb, Debug, &[UNOWNED_BACKUP]);
				resolved = true;
			}

			if !is_dir && self.can_overwrite(filestr, &path) {
				logv(cb, Debug, &[FORCED]);
				resolved = true;
			}

			if !resolved {
				let owner = self.file_owner(relative_path);
				out.conflicts.push(fileconflict(
					path.clone(),
					p1,
					owner,
					cb,
				));
			}
			j += 1;
		}
	}

	/// _alpm_db_find_fileconflicts: every target against the targets
	/// after it, then against the filesystem. progress before each target
	/// and once at 100 after the last, nothing for no targets
	pub fn find_fileconflicts(
		&self,
		upgrade: &[&Package],
		rem: &[&Package],
		cb: &mut dyn Callbacks,
	) -> FileConflicts {
		let mut out = FileConflicts::default();
		let numtargs = upgrade.len();
		if numtargs == 0 {
			return out;
		}
		for (current, p1) in upgrade.iter().enumerate() {
			// size_t arithmetic, the quotient fits an int
			let percent = (current * 100 / numtargs) as c_int;
			cb.progress(
				Progress::ConflictsStart,
				b"",
				percent,
				numtargs,
				current,
			);
			let rest = &upgrade[current + 1..];
			self.check_targets(p1, rest, &mut out, cb);
			self.check_filesystem(p1, upgrade, rem, &mut out, cb);
		}
		cb.progress(
			Progress::ConflictsStart,
			b"",
			100,
			numtargs,
			numtargs,
		);
		out
	}
}
