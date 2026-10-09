// port of src/pacman/check.c: -Qk (check_pkg_fast, the files list
// against the filesystem) and -Qkk (check_pkg_full, the local mtree
// against the filesystem)
//
// what the C asks libalpm through config->handle (root, dbpath, NoExtract
// matching, the package's mtree, files list and backup entries, which a
// local package lazy-loads at the getter) goes through CheckEnv; files
// are looked at on root + path like the C: llstat_buf (fstatat on the
// path buffer), std calls to read links and contents. the C prints to
// stdout and, through pm_printf, to stderr: both are appended to an
// Output. messages are the untranslated msgids, _n() picks the singular
// for 1 like ngettext without a catalog.
//
// mtree entries come from libarchive's mtree reader (alpm_core::mtree
// through be_local::read_mtree), in file order. an entry libarchive
// warns about ends the C's walk silently (UPSTREAM.md), here it is
// checked; data that cannot be parsed checks no entries in both.

use std::fs::{self, File};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use alpm_core::backup::Backup;
use alpm_core::be_local::{
	LocalDb, MtreeEntry, MtreeError, MtreeType, Sha256Checksum,
};
use alpm_core::filelist;
use alpm_core::handle::Handle;
use alpm_core::package::Package;
use alpm_core::util::{strerror, until_nul};
use pacman_common::util_common::{PATH_MAX, llstat_buf};
use rustix::fs::{FileType, Stat};

use crate::conf::{Config, LOG_ERROR, LOG_WARNING, cat};
use crate::util::{Output, pm_printf};

// the libalpm calls of check.c
pub trait CheckEnv {
	// alpm_option_get_root, ends in '/'
	fn root(&self) -> &[u8];
	// alpm_option_get_dbpath, ends in '/'
	fn dbpath(&self) -> &[u8];
	// alpm_option_match_noextract: None nothing matched (C -1),
	// Some(false) a pattern matched (C 0), Some(true) a negated one
	fn match_noextract(&self, path: &[u8]) -> Option<bool>;
	// alpm_pkg_get_files, split in two so the list is borrowed, not
	// copied: a local package lazy-loads it here, o holds what the
	// check printed before
	fn load_files(&mut self, o: &mut Output, pkg: &Package);
	// the list load_files loaded
	fn files<'a>(&'a self, pkg: &'a Package) -> &'a [filelist::File];
	// alpm_pkg_get_backup has an entry named path, loaded like files
	fn is_backup(
		&mut self,
		o: &mut Output,
		pkg: &Package,
		path: &[u8],
	) -> bool;
	// alpm_pkg_mtree_open + alpm_pkg_mtree_next until the end
	fn mtree(
		&mut self,
		pkg: &Package,
	) -> Result<Vec<MtreeEntry>, MtreeError>;
}

// the env of a handle and its local db, packages loaded before
pub struct HandleEnv<'a> {
	pub handle: &'a Handle,
	pub db: &'a LocalDb,
}

impl CheckEnv for HandleEnv<'_> {
	fn root(&self) -> &[u8] {
		self.handle.root()
	}

	fn dbpath(&self) -> &[u8] {
		self.handle.dbpath()
	}

	fn match_noextract(&self, path: &[u8]) -> Option<bool> {
		self.handle.match_noextract(path)
	}

	fn load_files(&mut self, _: &mut Output, _: &Package) {}

	fn files<'a>(&'a self, pkg: &'a Package) -> &'a [filelist::File] {
		&pkg.files.files
	}

	fn is_backup(
		&mut self,
		_: &mut Output,
		pkg: &Package,
		path: &[u8],
	) -> bool {
		is_backup(&pkg.backup, path)
	}

	fn mtree(
		&mut self,
		pkg: &Package,
	) -> Result<Vec<MtreeEntry>, MtreeError> {
		self.db.mtree(pkg, &mut ())
	}
}

// the strcmp loop over alpm_pkg_get_backup
pub fn is_backup(backup: &[Backup], path: &[u8]) -> bool {
	backup.iter().any(|b| until_nul(&b.name) == path)
}

// _n(singular, plural, n) without a catalog
fn plural(n: usize, one: &str, many: &str) -> String {
	if n == 1 { one } else { many }.to_string()
}

fn os(path: &[u8]) -> &Path {
	Path::new(std::ffi::OsStr::from_bytes(path))
}

fn quiet_line(o: &mut Output, pkgname: &[u8], filepath: &[u8]) {
	o.stdout.extend(cat(&[pkgname, b" ", filepath, b"\n"]));
}

fn warn(o: &mut Output, c: &Config, pkgname: &[u8], fp: &[u8], what: &[u8]) {
	let msg = cat(&[pkgname, b": ", fp, b" (", what, b")\n"]);
	pm_printf(&mut o.stderr, c, LOG_WARNING, &msg);
}

// the "backup file: " note check.c prints instead of a warning
fn backup_note(
	o: &mut Output,
	c: &Config,
	pkgname: &[u8],
	fp: &[u8],
	what: &[u8],
) {
	let cs = &c.colstr;
	o.stdout.extend(cat(&[cs.title, b"backup file", cs.nocolor, b": "]));
	o.stdout.extend(cat(&[pkgname, b": ", fp, b" (", what, b")\n"]));
}

enum Exists {
	Yes(Stat),
	// matched by NoExtract, not counted
	NoExtract,
	Missing,
}

// check_file_exists: llstat, a missing file is reported unless its path
// below the root matches NoExtract. the C matches filepath + rootlen,
// for db files (.INSTALL) an offset into the dbpath string; past its
// end the C reads stale buffer bytes, here nothing matches. filepath
// is llstat_buf's buffer, left as it was
fn file_exists(
	o: &mut Output,
	c: &Config,
	env: &impl CheckEnv,
	pkgname: &[u8],
	filepath: &mut Vec<u8>,
	rootlen: usize,
) -> Exists {
	match llstat_buf(filepath) {
		Ok(st) => Exists::Yes(st),
		Err(e) => {
			if let Some(rel) = filepath.get(rootlen..)
				&& env.match_noextract(rel) == Some(false)
			{
				return Exists::NoExtract;
			}
			if c.quiet != 0 {
				quiet_line(o, pkgname, filepath);
			} else {
				warn(o, c, pkgname, filepath, &strerror(&e));
			}
			Exists::Missing
		}
	}
}

// check_pkg_fast: every files list entry exists, directories (trailing
// '/') are directories. returns the C's 0/1
pub fn check_pkg_fast(
	o: &mut Output,
	c: &Config,
	env: &mut impl CheckEnv,
	pkg: &Package,
) -> i32 {
	// owned: the lazy getters borrow env mutably
	let root = &until_nul(env.root()).to_vec();
	let rootlen = root.len();
	if rootlen + 1 > PATH_MAX {
		let msg = cat(&[b"path too long: ", root, b"\n"]);
		pm_printf(&mut o.stderr, c, LOG_ERROR, &msg);
		return 1;
	}
	let pkgname = until_nul(pkg.name.as_deref().unwrap_or_default());
	env.load_files(o, pkg);
	let env = &*env;
	let files = env.files(pkg);
	let mut errors = 0usize;
	// one path buffer like the C's filepath[PATH_MAX]: root, then each
	// file's name after it
	let mut filepath = root.clone();
	for file in files {
		let path = file.name();
		if rootlen + 1 + path.len() > PATH_MAX {
			let msg = cat(&[b"path too long: ", root, path, b"\n"]);
			pm_printf(&mut o.stderr, c, LOG_WARNING, &msg);
			continue;
		}
		filepath.truncate(rootlen);
		filepath.extend_from_slice(path);
		match file_exists(o, c, env, pkgname, &mut filepath, rootlen) {
			Exists::Yes(st) => {
				// the C reads path[plen - 1], files lists never
				// hold empty names
				let expect_dir = path.last() == Some(&b'/');
				if expect_dir != is_dir(&st) {
					let what = b"File type mismatch";
					warn(o, c, pkgname, &filepath, what);
					errors += 1;
				}
			}
			Exists::Missing => errors += 1,
			Exists::NoExtract => {}
		}
	}
	if c.quiet == 0 {
		let n = files.len();
		let s = plural(n, "total file", "total files");
		o.stdout.extend(cat(&[pkgname, b": "]));
		o.stdout.extend(format!("{n} {s}, ").into_bytes());
		let s = plural(errors, "missing file", "missing files");
		o.stdout.extend(format!("{errors} {s}\n").into_bytes());
	}
	i32::from(errors != 0)
}

fn is_dir(st: &Stat) -> bool {
	FileType::from_raw_mode(st.st_mode) == FileType::Directory
}

// check_file_type: lstat type against the entry type
fn type_matches(kind: MtreeType, st: &Stat) -> bool {
	let t = FileType::from_raw_mode(st.st_mode);
	match kind {
		MtreeType::File => t == FileType::RegularFile,
		MtreeType::Dir => t == FileType::Directory,
		MtreeType::Link => t == FileType::Symlink,
		// not recognized, check_pkg_full skips them before
		MtreeType::Block | MtreeType::Char | MtreeType::Fifo => false,
	}
}

// check_file_permissions: uid, gid and the mode bits, one warning each,
// counted once
fn permissions(
	o: &mut Output,
	c: &Config,
	pkgname: &[u8],
	fp: &[u8],
	st: &Stat,
	e: &MtreeEntry,
) -> usize {
	let q = c.quiet != 0;
	let checks: [(bool, &[u8]); 3] = [
		(i64::from(st.st_uid) != e.uid, b"UID mismatch"),
		(i64::from(st.st_gid) != e.gid, b"GID mismatch"),
		// S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO
		(st.st_mode & 0o7777 != e.mode, b"Permissions mismatch"),
	];
	let mut errors = 0;
	for (bad, what) in checks {
		if bad {
			errors += 1;
			if !q {
				warn(o, c, pkgname, fp, what);
			}
		}
	}
	usize::from(errors != 0)
}

// check_file_link: readlink must return st_size bytes, then the target
// is compared like strcmp
fn link(
	o: &mut Output,
	c: &Config,
	pkgname: &[u8],
	fp: &[u8],
	st: &Stat,
	e: &MtreeEntry,
) -> usize {
	let target = fs::read_link(os(fp))
		.map(|t| t.into_os_string().into_vec())
		.ok()
		.filter(|t| t.len() as u64 == st.st_size as u64);
	let Some(target) = target else {
		let msg =
			cat(&[b"unable to read symlink contents: ", fp, b"\n"]);
		pm_printf(&mut o.stderr, c, LOG_ERROR, &msg);
		return 1;
	};
	let want = until_nul(e.link.as_deref().unwrap_or_default());
	if until_nul(&target) != want {
		if c.quiet == 0 {
			warn(o, c, pkgname, fp, b"Symlink path mismatch");
		}
		return 1;
	}
	0
}

// the shape of check_file_time, check_file_size and the checksum
// mismatch: a backup file gets a note on stdout and no error
fn mismatch(
	o: &mut Output,
	c: &Config,
	pkgname: &[u8],
	fp: &[u8],
	backup: bool,
	what: &[u8],
) -> usize {
	if backup {
		if c.quiet == 0 {
			backup_note(o, c, pkgname, fp, what);
		}
		return 0;
	}
	if c.quiet == 0 {
		warn(o, c, pkgname, fp, what);
	}
	1
}

// alpm_compute_sha256sum: None where the file cannot be opened or read
fn sha256_file(fp: &[u8]) -> Option<Sha256Checksum> {
	let f = File::open(os(fp)).ok()?;
	Sha256Checksum::calculate_from_reader(f).ok()
}

// check_file_sha256sum + check_file_cksum
fn sha256(
	o: &mut Output,
	c: &Config,
	pkgname: &[u8],
	fp: &[u8],
	e: &MtreeEntry,
	backup: bool,
) -> usize {
	let q = c.quiet != 0;
	let Some(calc) = sha256_file(fp) else {
		if !q {
			let what = b"failed to calculate SHA256 checksum";
			warn(o, c, pkgname, fp, what);
		}
		return 1;
	};
	let Some(want) = &e.sha256 else {
		if !q {
			let what = b"SHA256 checksum information not available";
			warn(o, c, pkgname, fp, what);
		}
		return 1;
	};
	if calc.as_ref() != want {
		let what = b"SHA256 checksum mismatch";
		return mismatch(o, c, pkgname, fp, backup, what);
	}
	0
}

// where an mtree entry is looked for: "./" stripped, top-level dot
// files skipped except .INSTALL and .CHANGELOG, which are the db copies.
// None skips the entry (after a warning when the path is too long)
fn entry_filepath(
	o: &mut Output,
	c: &Config,
	env: &impl CheckEnv,
	pkg: &Package,
	path: &[u8],
) -> Option<Vec<u8>> {
	let root = until_nul(env.root());
	if path.first() != Some(&b'.') {
		let fp = cat(&[root, path]);
		if fp.len() >= PATH_MAX {
			let msg = cat(&[b"path too long: ", root, path, b"\n"]);
			pm_printf(&mut o.stderr, c, LOG_WARNING, &msg);
			return None;
		}
		return Some(fp);
	}
	let dbfile: &[u8] = match path {
		b".INSTALL" => b"install",
		b".CHANGELOG" => b"changelog",
		_ => return None,
	};
	// _alpm_local_db_pkgpath spelled out like the C: dbpath is absolute,
	// the root is not prepended
	let name = until_nul(pkg.name.as_deref().unwrap_or_default());
	let version = until_nul(pkg.version.as_deref().unwrap_or_default());
	let dbpath = until_nul(env.dbpath());
	let parts: [&[u8]; 7] =
		[dbpath, b"local/", name, b"-", version, b"/", dbfile];
	let fp = parts.concat();
	if fp.len() >= PATH_MAX {
		let msg = cat(&[b"path too long: ", &fp, b"\n"]);
		pm_printf(&mut o.stderr, c, LOG_WARNING, &msg);
		return None;
	}
	Some(fp)
}

// the entry's path with a leading "./" stripped
fn entry_path(e: &MtreeEntry) -> &[u8] {
	let path = until_nul(&e.path);
	path.strip_prefix(b"./").unwrap_or(path)
}

// the checks after the type: file_errors of one entry
fn entry_errors(
	o: &mut Output,
	c: &Config,
	env: &mut impl CheckEnv,
	pkg: &Package,
	fp: &[u8],
	st: &Stat,
	e: &MtreeEntry,
) -> usize {
	let pkgname = until_nul(pkg.name.as_deref().unwrap_or_default());
	let mut errors = permissions(o, c, pkgname, fp, st, e);
	if e.kind == MtreeType::Link {
		errors += link(o, c, pkgname, fp, st, e);
	}
	// expected to fail when a backup file was modified. the first entry
	// to get here loads the files in the C, after the warnings above
	let backup = env.is_backup(o, pkg, entry_path(e));
	if e.kind != MtreeType::Dir && st.st_mtime != e.mtime {
		let what = b"Modification time mismatch";
		errors += mismatch(o, c, pkgname, fp, backup, what);
	}
	if e.kind == MtreeType::File {
		if st.st_size as u64 != e.size {
			let what = b"Size mismatch";
			errors += mismatch(o, c, pkgname, fp, backup, what);
		}
		errors += sha256(o, c, pkgname, fp, e, backup);
	}
	errors
}

// check_pkg_full: every mtree entry against the filesystem. returns
// the C's 0/1
pub fn check_pkg_full(
	o: &mut Output,
	c: &Config,
	env: &mut impl CheckEnv,
	pkg: &Package,
) -> i32 {
	// owned: the lazy getters borrow env mutably
	let root = &until_nul(env.root()).to_vec();
	let rootlen = root.len();
	if rootlen + 1 > PATH_MAX {
		let msg = cat(&[b"path too long: ", root, b"\n"]);
		pm_printf(&mut o.stderr, c, LOG_ERROR, &msg);
		return 1;
	}
	let pkgname = until_nul(pkg.name.as_deref().unwrap_or_default());
	let entries = match env.mtree(pkg) {
		Ok(entries) => entries,
		Err(MtreeError::Parse(_)) => Vec::new(),
		Err(MtreeError::Missing | MtreeError::Read(_)) => {
			if c.quiet == 0 {
				o.stdout.extend(cat(&[
					pkgname,
					b": no mtree file\n",
				]));
			}
			return 0;
		}
	};
	let (mut errors, mut file_count) = (0usize, 0usize);
	for e in &entries {
		let path = entry_path(e);
		let Some(mut fp) = entry_filepath(o, c, env, pkg, path) else {
			continue;
		};
		file_count += 1;
		let st = match file_exists(o, c, env, pkgname, &mut fp, rootlen)
		{
			Exists::Yes(st) => st,
			Exists::Missing => {
				errors += 1;
				continue;
			}
			Exists::NoExtract => continue,
		};
		let known = [MtreeType::Dir, MtreeType::File, MtreeType::Link];
		if !known.contains(&e.kind) {
			let msg = cat(&[
				b"file type not recognized: ",
				root,
				path,
				b"\n",
			]);
			pm_printf(&mut o.stderr, c, LOG_WARNING, &msg);
			continue;
		}
		if !type_matches(e.kind, &st) {
			if c.quiet != 0 {
				quiet_line(o, pkgname, &fp);
			} else {
				warn(o, c, pkgname, &fp, b"File type mismatch");
			}
			errors += 1;
			continue;
		}
		let file_errors = entry_errors(o, c, env, pkg, &fp, &st, e);
		if c.quiet != 0 && file_errors != 0 {
			quiet_line(o, pkgname, &fp);
		}
		errors += usize::from(file_errors != 0);
	}
	if c.quiet == 0 {
		let s = plural(file_count, "total file", "total files");
		o.stdout.extend(cat(&[pkgname, b": "]));
		o.stdout.extend(format!("{file_count} {s}, ").into_bytes());
		let s = plural(errors, "altered file", "altered files");
		o.stdout.extend(format!("{errors} {s}\n").into_bytes());
	}
	i32::from(errors != 0)
}
