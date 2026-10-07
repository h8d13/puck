// port of lib/libalpm/be_local.c, reading side: validate, populate and
// local_db_read.
//
// the desc and files formats are parsed by the alpm-db crate, not by a
// translation of the C line reader; its typed values are mapped onto the
// pacman Package model (see PORTING.md for where the two disagree).
//
// lazy loading keeps the C infolevel bits: read() loads the requested
// sections once, a failed read marks the package INFRQ_ERROR and later
// reads give up. logging (name/version mismatch, unknown keys,
// _alpm_pkg_check_meta warnings) is not modelled, it never changes the
// result. mtree reading is the last section. not ported: writing,
// removal, prepare and changelog.

use std::ffi::{OsStr, c_int};
use std::fmt::Display;
use std::fs::{self, DirBuilder, File};
use std::io::{self, ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use alpm_common::MetadataFile;
use alpm_db::desc::{DbDescFile, DbDescFileV1};
use alpm_db::files::DbFiles;
use alpm_mtree::Mtree;
use alpm_mtree::mtree::v2::Path as MtreePath;
use alpm_types::{ExtraDataEntry, PackageInstallReason, PackageValidation};

use crate::backup::Backup;
use crate::deps::{Depend, dep_from_string};
use crate::error::Errno;
use crate::filelist::{File as PkgFile, FileList};
use crate::package::{
	PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM,
	PKG_VALIDATION_SIGNATURE, Package, PkgFrom, PkgReason, PkgXData,
};
use crate::pkghash::PkgHash;
use crate::util::{hash_sdbm, splitname};

// ALPM_LOCAL_DB_VERSION
pub const LOCAL_DB_VERSION: u64 = 9;

// alpm_dbinfrq_t
pub const INFRQ_BASE: c_int = 1 << 0;
pub const INFRQ_DESC: c_int = 1 << 1;
pub const INFRQ_FILES: c_int = 1 << 2;
pub const INFRQ_SCRIPTLET: c_int = 1 << 3;
pub const INFRQ_DSIZE: c_int = 1 << 4;
pub const INFRQ_ALL: c_int =
	INFRQ_BASE | INFRQ_DESC | INFRQ_FILES | INFRQ_SCRIPTLET | INFRQ_DSIZE;
pub const INFRQ_ERROR: c_int = 1 << 30;

// failures of validate/populate, named after the pm_errno the C sets
#[derive(Debug)]
pub enum DbError {
	// ALPM_ERR_DB_OPEN: the directory cannot be listed
	Open(io::Error),
	// ALPM_ERR_DB_CREATE: missing directory could not be created, or
	// its version file not written
	Create(io::Error),
	// ALPM_ERR_DB_VERSION
	Version,
	// ALPM_ERR_MEMORY: the package cache cannot grow
	Memory,
}

impl DbError {
	// the pm_errno the C leaves on the handle
	pub fn errno(&self) -> Errno {
		match self {
			DbError::Open(_) => Errno::DbOpen,
			DbError::Create(_) => Errno::DbCreate,
			DbError::Version => Errno::DbVersion,
			DbError::Memory => Errno::Memory,
		}
	}
}

// failures of read(), the C only logs them and sets INFRQ_ERROR
#[derive(Debug)]
pub enum ReadError {
	// INFRQ_ERROR from an earlier read, no retry
	Earlier,
	// desc/files missing, unreadable or not UTF-8
	Io(io::Error),
	Desc(alpm_db::Error),
	Files(alpm_db::files::Error),
}

// the local alpm_db_t once registered: its validated directory
#[derive(Clone, Debug)]
pub struct LocalDb {
	// _alpm_db_path: "<dbpath>local/"
	path: Vec<u8>,
}

fn os(path: &[u8]) -> &Path {
	Path::new(OsStr::from_bytes(path))
}

// fscanf(f, "%zu") on the version file: C-locale whitespace skipped, then
// strtoul base 10: optional sign, '-' negates modulo 2^64, overflow
// saturates. None when no digit follows (t != 1)
fn scan_zu(s: &[u8]) -> Option<u64> {
	let start = s.iter().position(|c| !b" \t\n\x0b\x0c\r".contains(c))?;
	let s = &s[start..];
	let (neg, s) = match s.first() {
		Some(b'-') => (true, &s[1..]),
		Some(b'+') => (false, &s[1..]),
		_ => (false, s),
	};
	let digits = s.iter().take_while(|c| c.is_ascii_digit()).count();
	if digits == 0 {
		return None;
	}
	let n = s[..digits].iter().try_fold(0u64, |n, &c| {
		n.checked_mul(10)?.checked_add(u64::from(c - b'0'))
	});
	Some(match n {
		None => u64::MAX,
		Some(n) if neg => n.wrapping_neg(),
		Some(n) => n,
	})
}

// local_db_add_version
fn add_version(path: &[u8]) -> io::Result<()> {
	let file = [path, b"ALPM_DB_VERSION"].concat();
	fs::write(os(&file), format!("{LOCAL_DB_VERSION}\n"))
}

// the directory listing as the C reads it: readdir stops at the first
// error. "." and ".." never come out of read_dir
fn entries(dir: fs::ReadDir) -> impl Iterator<Item = fs::DirEntry> {
	dir.map_while(Result::ok)
}

impl LocalDb {
	// _alpm_db_register_local + local_db_validate. dbpath is
	// handle->dbpath: absolute and ending in '/'. a missing local/ is
	// created (mode 0755, one level) with a version file, so is the
	// version file of an empty one
	pub fn register(dbpath: &[u8]) -> Result<LocalDb, DbError> {
		let path = [dbpath, b"local/"].concat();
		let dir = match fs::read_dir(os(&path)) {
			Ok(dir) => dir,
			Err(e) if e.kind() == ErrorKind::NotFound => {
				DirBuilder::new()
					.mode(0o755)
					.create(os(&path))
					.map_err(DbError::Create)?;
				add_version(&path).map_err(DbError::Create)?;
				return Ok(LocalDb { path });
			}
			Err(e) => return Err(DbError::Open(e)),
		};
		let verfile = [&path[..], b"ALPM_DB_VERSION"].concat();
		let Ok(mut f) = File::open(os(&verfile)) else {
			// only an empty db gets a fresh version file
			if entries(dir).next().is_some() {
				return Err(DbError::Version);
			}
			add_version(&path).map_err(|_| DbError::Version)?;
			return Ok(LocalDb { path });
		};
		// fopen succeeds on a directory, the read then fails
		let mut buf = Vec::new();
		f.read_to_end(&mut buf).map_err(|_| DbError::Version)?;
		match scan_zu(&buf) {
			Some(LOCAL_DB_VERSION) => Ok(LocalDb { path }),
			_ => Err(DbError::Version),
		}
	}

	// _alpm_db_path
	pub fn path(&self) -> &[u8] {
		&self.path
	}

	// _alpm_local_db_pkgpath: "<path><name>-<version>/<filename>"
	pub fn pkgpath(&self, pkg: &Package, filename: &[u8]) -> Vec<u8> {
		let name = pkg.name.as_deref().unwrap_or_default();
		let version = pkg.version.as_deref().unwrap_or_default();
		[&self.path[..], name, b"-", version, b"/", filename].concat()
	}

	// the C sizes the cache from the directory link count (subdirs + 2),
	// counting entries where the filesystem reports fewer than 2 links
	fn est_count(&self) -> Result<u32, DbError> {
		let meta =
			fs::metadata(os(&self.path)).map_err(DbError::Open)?;
		let mut est = meta.nlink();
		if est < 2 {
			let dir = fs::read_dir(os(&self.path))
				.map_err(DbError::Open)?;
			// plus the "." and ".." readdir gives the C
			est = entries(dir).count() as u64 + 2;
		}
		// size_t handed to an unsigned int parameter
		Ok(est.saturating_sub(2) as u32)
	}

	// local_db_populate: one package per "name-ver-rel" directory, in
	// readdir order. entries splitname rejects and later duplicates of a
	// name are skipped. the C appends then msorts the list by name; names
	// are unique, so add_sorted gives the same list and bucket layout.
	// only name, version, name_hash and origin are set, read() does the
	// rest (the C's INFRQ_BASE read loads nothing)
	pub fn populate(&self) -> Result<PkgHash<Package>, DbError> {
		let dir =
			fs::read_dir(os(&self.path)).map_err(DbError::Open)?;
		let est = self.est_count()?;
		let mut cache = PkgHash::new(est).ok_or(DbError::Memory)?;
		for ent in entries(dir) {
			// is_dir: stat, so a symlink to a directory counts. the
			// d_type shortcut is compiled out of the meson build
			if !fs::metadata(ent.path()).is_ok_and(|m| m.is_dir()) {
				continue;
			}
			let fname = ent.file_name();
			let Some((name, version)) = splitname(fname.as_bytes())
			else {
				continue;
			};
			if cache.find(name).is_some() {
				continue;
			}
			let pkg = Package {
				name_hash: hash_sdbm(name),
				name: Some(name.to_vec()),
				version: Some(version.to_vec()),
				origin: Some(PkgFrom::LocalDb),
				..Package::default()
			};
			cache.add_sorted(pkg).map_err(|_| DbError::Memory)?;
		}
		Ok(cache)
	}

	// local_db_read: loads the sections of inforeq not loaded yet. on
	// error the sections read before stay, the failing one is left
	// untouched (alpm-db parses a file whole) and INFRQ_ERROR is set
	pub fn read(
		&self,
		pkg: &mut Package,
		inforeq: c_int,
	) -> Result<(), ReadError> {
		if pkg.infolevel & inforeq == inforeq {
			return Ok(());
		}
		if pkg.infolevel & INFRQ_ERROR != 0 {
			return Err(ReadError::Earlier);
		}
		let r = self.read_sections(pkg, inforeq);
		if r.is_err() {
			pkg.infolevel |= INFRQ_ERROR;
		}
		r
	}

	fn wants(pkg: &Package, inforeq: c_int, bit: c_int) -> bool {
		inforeq & bit != 0 && pkg.infolevel & bit == 0
	}

	fn read_sections(
		&self,
		pkg: &mut Package,
		inforeq: c_int,
	) -> Result<(), ReadError> {
		if Self::wants(pkg, inforeq, INFRQ_DESC) {
			let path = self.pkgpath(pkg, b"desc");
			let s = fs::read_to_string(os(&path))
				.map_err(ReadError::Io)?;
			let desc = s
				.parse::<DbDescFile>()
				.map_err(ReadError::Desc)?;
			apply_desc(pkg, desc);
			pkg.infolevel |= INFRQ_DESC;
		}
		if Self::wants(pkg, inforeq, INFRQ_FILES) {
			let path = self.pkgpath(pkg, b"files");
			let s = fs::read_to_string(os(&path))
				.map_err(ReadError::Io)?;
			let files = s
				.parse::<DbFiles>()
				.map_err(ReadError::Files)?;
			apply_files(pkg, &files);
			pkg.infolevel |= INFRQ_FILES;
		}
		if Self::wants(pkg, inforeq, INFRQ_SCRIPTLET) {
			// access(F_OK): follows symlinks
			let path = self.pkgpath(pkg, b"install");
			if fs::metadata(os(&path)).is_ok() {
				pkg.scriptlet = 1;
			}
			pkg.infolevel |= INFRQ_SCRIPTLET;
		}
		Ok(())
	}
}

fn text(v: &impl Display) -> Vec<u8> {
	v.to_string().into_bytes()
}

fn texts<T: Display>(v: &[T]) -> Vec<Vec<u8>> {
	v.iter().map(text).collect()
}

// relations go through their alpm-types string form into pacman's
// alpm_dep_from_string, which is what the C does with the line
fn deps<T: Display>(v: &[T]) -> Vec<Depend> {
	v.iter().map(|d| dep_from_string(&text(d))).collect()
}

// the C table: "md5" is not mapped by local_db_read, it warns and sets no
// bit
fn validation_bits(v: &[PackageValidation]) -> c_int {
	v.iter().fold(0, |bits, m| {
		bits | match m {
			PackageValidation::None => PKG_VALIDATION_NONE,
			PackageValidation::Sha256 => PKG_VALIDATION_SHA256SUM,
			PackageValidation::Pgp => PKG_VALIDATION_SIGNATURE,
			PackageValidation::Md5 => 0,
		}
	})
}

fn apply_desc(pkg: &mut Package, desc: DbDescFile) {
	let (d, xdata): (DbDescFileV1, Vec<ExtraDataEntry>) = match desc {
		DbDescFile::V1(d) => (d, Vec::new()),
		DbDescFile::V2(d) => {
			let xdata = d.xdata.clone().into();
			(d.into(), xdata)
		}
	};
	// %NAME% and %VERSION% only feed the C's mismatch log
	pkg.base = Some(text(&d.base));
	// description and url as read, alpm-types normalizes their Display
	pkg.desc = Some(text(&d.description.as_original_str()));
	// %URL% is required, an empty value is alpm-db's None
	let url = d.url.as_ref().map(|u| text(&u.as_original_str()));
	pkg.url = Some(url.unwrap_or_default());
	pkg.arch = Some(text(&d.arch));
	pkg.builddate = d.builddate;
	pkg.installdate = d.installdate;
	pkg.packager = Some(text(&d.packager));
	// _alpm_strtoofft casts the unsigned long long to off_t: values past
	// i64::MAX wrap (gcc's implementation-defined conversion)
	pkg.isize = d.size as i64;
	pkg.groups = texts(&d.groups);
	pkg.reason = match d.reason {
		PackageInstallReason::Explicit => PkgReason::Explicit,
		PackageInstallReason::Depend => PkgReason::Depend,
	};
	pkg.licenses = texts(&d.license);
	pkg.validation = validation_bits(&d.validation);
	pkg.replaces = deps(&d.replaces);
	pkg.depends = deps(&d.depends);
	pkg.optdepends = deps(&d.optdepends);
	pkg.conflicts = deps(&d.conflicts);
	pkg.provides = deps(&d.provides);
	pkg.xdata = xdata
		.iter()
		.map(|x| PkgXData {
			name: x.key().as_bytes().to_vec(),
			value: x.value().as_bytes().to_vec(),
		})
		.collect();
}

// the C sorts the file list after reading (_alpm_filelist_sort), backups
// keep the order alpm-db returns
fn apply_files(pkg: &mut Package, files: &DbFiles) {
	let paths: &[PathBuf] = files.as_ref();
	pkg.files = FileList {
		files: paths
			.iter()
			.map(|p| PkgFile {
				name: p.as_os_str().as_bytes().to_vec(),
				..PkgFile::default()
			})
			.collect(),
	};
	pkg.files.sort();
	pkg.backup = files
		.backups()
		.iter()
		.map(|b| Backup {
			name: b.path.inner().as_os_str().as_bytes().to_vec(),
			hash: Some(text(&b.md5)),
		})
		.collect();
}

// mtree: _cache_mtree_open/_cache_mtree_next
//
// the C opens "<pkgpath>mtree" with libarchive (every filter, mtree
// format) and yields its entries one by one. here alpm-mtree reads the
// file whole (plain or gzip, MetadataFile::from_reader): it sorts the
// entries by path and rejects the whole file where libarchive warns or
// fails on one entry (see PORTING.md for the divergences)

pub use alpm_types::{Md5Checksum, Sha256Checksum};

// archive_entry_filetype of the three types alpm-mtree knows (its
// PathType has no PartialEq)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtreeType {
	Dir,
	File,
	Link,
}

// what check.c reads of an archive_entry
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtreeEntry {
	// archive_entry_pathname: decoded, with its "./" prefix
	pub path: Vec<u8>,
	pub kind: MtreeType,
	// ~AE_IFMT & archive_entry_mode: the permission bits
	pub mode: u32,
	pub uid: u32,
	pub gid: u32,
	// files only, 0 for the others like an unset archive_entry_size
	pub size: u64,
	pub mtime: i64,
	// links only
	pub link: Option<Vec<u8>>,
	pub sha256: Option<Sha256Checksum>,
	pub md5: Option<Md5Checksum>,
}

#[derive(Debug)]
pub enum MtreeError {
	// access(F_OK) fails: "there is no mtree file for this package"
	Missing,
	// open, read or gunzip failed: where the C's archive_read_open fails
	Read(alpm_mtree::Error),
	// alpm-mtree rejects the data (not UTF-8, syntax, missing keywords)
	Parse(alpm_mtree::Error),
}

fn bytes_of(p: &Path) -> Vec<u8> {
	p.as_os_str().as_bytes().to_vec()
}

// alpm-mtree only stores 3-4 octal digits
fn mode_bits(mode: &str) -> u32 {
	u32::from_str_radix(mode, 8).unwrap_or_default()
}

fn mtree_entry(p: MtreePath) -> MtreeEntry {
	match p {
		MtreePath::Directory(d) => MtreeEntry {
			path: bytes_of(&d.path),
			kind: MtreeType::Dir,
			mode: mode_bits(&d.mode),
			uid: d.uid,
			gid: d.gid,
			size: 0,
			mtime: d.time,
			link: None,
			sha256: None,
			md5: None,
		},
		MtreePath::File(f) => MtreeEntry {
			path: bytes_of(&f.path),
			kind: MtreeType::File,
			mode: mode_bits(&f.mode),
			uid: f.uid,
			gid: f.gid,
			size: f.size,
			mtime: f.time,
			link: None,
			sha256: Some(f.sha256_digest),
			md5: f.md5_digest,
		},
		MtreePath::Link(l) => MtreeEntry {
			path: bytes_of(&l.path),
			kind: MtreeType::Link,
			mode: mode_bits(&l.mode),
			uid: l.uid,
			gid: l.gid,
			size: 0,
			mtime: l.time,
			link: Some(bytes_of(&l.link_path)),
			sha256: None,
			md5: None,
		},
	}
}

// the alpm-mtree call: plain or gzip'd mtree data
pub fn parse_mtree(r: impl Read) -> Result<Vec<MtreeEntry>, MtreeError> {
	let paths = match Mtree::from_reader(r) {
		Ok(Mtree::V1(p) | Mtree::V2(p)) => p,
		Err(
			e @ (alpm_mtree::Error::Io { .. }
			| alpm_mtree::Error::InvalidGzip(_)),
		) => return Err(MtreeError::Read(e)),
		Err(e) => return Err(MtreeError::Parse(e)),
	};
	Ok(paths.into_iter().map(mtree_entry).collect())
}

pub fn read_mtree(path: &[u8]) -> Result<Vec<MtreeEntry>, MtreeError> {
	// access(F_OK) follows symlinks
	if fs::metadata(os(path)).is_err() {
		return Err(MtreeError::Missing);
	}
	let file = File::open(os(path)).map_err(|source| {
		MtreeError::Read(alpm_mtree::Error::Io {
			context: "open".into(),
			source,
		})
	})?;
	parse_mtree(file)
}

impl LocalDb {
	// alpm_pkg_mtree_open + alpm_pkg_mtree_next to the end, on
	// _alpm_local_db_pkgpath(db, pkg, "mtree")
	pub fn mtree(
		&self,
		pkg: &Package,
	) -> Result<Vec<MtreeEntry>, MtreeError> {
		read_mtree(&self.pkgpath(pkg, b"mtree"))
	}
}
