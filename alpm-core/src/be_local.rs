// port of lib/libalpm/be_local.c, reading side: validate, populate and
// local_db_read.
//
// the desc and files formats are read by the alpm-db crate's
// libalpm-compatible readers, not by a translation of the C line reader;
// their typed values are mapped onto the pacman Package model (see
// PORTING.md for where the two disagree).
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
use std::io::{self, ErrorKind, Read, Seek};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use alpm_compress::decompression::{CompressionDecoder, DecompressionSettings};
use alpm_db::desc::{Section, parse_libalpm};
use alpm_db::files::DbFiles;
use alpm_mtree::libarchive::{self, Entry};
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
			let desc =
				parse_libalpm(&s).map_err(ReadError::Desc)?;
			apply_desc(pkg, desc);
			pkg.infolevel |= INFRQ_DESC;
		}
		if Self::wants(pkg, inforeq, INFRQ_FILES) {
			let path = self.pkgpath(pkg, b"files");
			let s = fs::read_to_string(os(&path))
				.map_err(ReadError::Io)?;
			let files = DbFiles::from_str_libalpm(&s)
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

// the C's per-key assignments: a repeated value overwrites, a repeated
// list appends, a missing section leaves the field unset
fn apply_desc(pkg: &mut Package, desc: Vec<Section>) {
	for section in desc {
		apply_section(pkg, section);
	}
}

fn apply_section(pkg: &mut Package, section: Section) {
	match section {
		// only feed the C's mismatch log
		Section::Name(_) | Section::Version(_) => {}
		Section::Base(v) => pkg.base = Some(text(&v)),
		// description and url as read, alpm-types normalizes Display
		Section::Desc(v) => pkg.desc = Some(text(&v.as_original_str())),
		// an empty value is alpm-db's None
		Section::Url(v) => {
			pkg.url = Some(v
				.map(|u| text(&u.as_original_str()))
				.unwrap_or_default())
		}
		Section::Arch(v) => pkg.arch = Some(text(&v)),
		Section::BuildDate(v) => pkg.builddate = v,
		Section::InstallDate(v) => pkg.installdate = v,
		Section::Packager(v) => pkg.packager = Some(text(&v)),
		// _alpm_strtoofft casts the unsigned long long to off_t: values
		// past i64::MAX wrap (gcc's implementation-defined conversion)
		Section::Size(v) => pkg.isize = v as i64,
		Section::Groups(v) => pkg.groups.extend(texts(&v)),
		Section::Reason(PackageInstallReason::Explicit) => {
			pkg.reason = PkgReason::Explicit
		}
		Section::Reason(PackageInstallReason::Depend) => {
			pkg.reason = PkgReason::Depend
		}
		Section::License(v) => pkg.licenses.extend(texts(&v)),
		Section::Validation(v) => pkg.validation |= validation_bits(&v),
		Section::Replaces(v) => pkg.replaces.extend(deps(&v)),
		Section::Depends(v) => pkg.depends.extend(deps(&v)),
		Section::OptDepends(v) => pkg.optdepends.extend(deps(&v)),
		Section::Conflicts(v) => pkg.conflicts.extend(deps(&v)),
		Section::Provides(v) => pkg.provides.extend(deps(&v)),
		Section::MakeDepends(v) => pkg.makedepends.extend(deps(&v)),
		Section::CheckDepends(v) => pkg.checkdepends.extend(deps(&v)),
		Section::XData(v) => {
			let v: Vec<ExtraDataEntry> = v.into();
			pkg.xdata.extend(v.iter().map(|x| PkgXData {
				name: x.key().as_bytes().to_vec(),
				value: x.value().as_bytes().to_vec(),
			}))
		}
	}
}

// the C sorts the file list after reading (_alpm_filelist_sort), backups
// keep file order
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
			// None is the "(null)" the C wrote for a NULL hash
			hash: Some(match &b.md5 {
				Some(md5) => text(md5),
				None => b"(null)".to_vec(),
			}),
		})
		.collect();
}

// mtree: _cache_mtree_open/_cache_mtree_next
//
// the C opens "<pkgpath>mtree" with libarchive (every filter, mtree
// format) and yields its entries one by one. here the filter is picked by
// magic bytes (alpm-compress) and alpm-mtree's libarchive reader parses
// the file whole, entries in file order like the C. data that reader
// cannot parse fails whole, like libarchive (it reads the file at the
// first header). an entry libarchive warns about ends the C's walk
// (UPSTREAM.md), here it is kept, without the warned keyword

pub use alpm_mtree::libarchive::EntryType as MtreeType;
pub use alpm_types::{Md5Checksum, Sha256Checksum};

// what check.c reads of an archive_entry
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtreeEntry {
	// archive_entry_pathname: decoded, with its "./" prefix
	pub path: Vec<u8>,
	pub kind: MtreeType,
	// ~AE_IFMT & archive_entry_mode: the permission bits
	pub mode: u32,
	pub uid: i64,
	pub gid: i64,
	pub size: u64,
	// archive_entry_mtime, 0 when unset
	pub mtime: i64,
	pub link: Option<Vec<u8>>,
	pub sha256: Option<Sha256Checksum>,
	pub md5: Option<Md5Checksum>,
	// archive_read_next_header gave ARCHIVE_WARN for it: a keyword was
	// not read, _cache_mtree_next returns -1
	pub warned: bool,
}

#[derive(Debug)]
pub enum MtreeError {
	// access(F_OK) fails: "there is no mtree file for this package"
	Missing,
	// open, read, decompression or format detection failed: where the
	// C's archive_read_open fails
	Read(alpm_mtree::Error),
	// a line libarchive cannot parse: no entries
	Parse(alpm_mtree::Error),
}

fn into_bytes(p: PathBuf) -> Vec<u8> {
	p.into_os_string().into_vec()
}

fn mtree_entry(e: Entry) -> MtreeEntry {
	MtreeEntry {
		path: into_bytes(e.path),
		kind: e.entry_type,
		mode: e.mode,
		uid: e.uid,
		gid: e.gid,
		// the reader clamps a negative size to 0 like libarchive
		size: u64::try_from(e.size).unwrap_or_default(),
		mtime: e.time.map_or(0, |(seconds, _)| seconds),
		link: e.link.map(into_bytes),
		sha256: e.sha256_digest,
		md5: e.md5_digest,
		warned: !e.warnings.is_empty(),
	}
}

// the alpm-mtree call: plain or gzip'd mtree data
pub fn parse_mtree(r: impl Read) -> Result<Vec<MtreeEntry>, MtreeError> {
	match libarchive::from_reader(r) {
		Ok(entries) => {
			Ok(entries.into_iter().map(mtree_entry).collect())
		}
		Err(
			e @ (alpm_mtree::Error::Io { .. }
			| alpm_mtree::Error::InvalidGzip(_)
			| alpm_mtree::Error::NoMtreeData),
		) => Err(MtreeError::Read(e)),
		Err(e) => Err(MtreeError::Parse(e)),
	}
}

fn read_err(context: &str, source: io::Error) -> MtreeError {
	MtreeError::Read(alpm_mtree::Error::Io {
		context: context.into(),
		source,
	})
}

pub fn read_mtree(path: &[u8]) -> Result<Vec<MtreeEntry>, MtreeError> {
	// access(F_OK) follows symlinks
	if fs::metadata(os(path)).is_err() {
		return Err(MtreeError::Missing);
	}
	let mut file = File::open(os(path)).map_err(|e| read_err("open", e))?;
	// the filter libarchive's bidding would pick
	let mut magic = Vec::with_capacity(DecompressionSettings::MAGIC_LEN);
	(&mut file)
		.take(DecompressionSettings::MAGIC_LEN as u64)
		.read_to_end(&mut magic)
		.and_then(|_| file.rewind())
		.map_err(|e| read_err("read", e))?;
	let settings = DecompressionSettings::from_magic(&magic);
	let decoder = CompressionDecoder::new(file, settings)
		.map_err(|e| read_err("decompress", io::Error::other(e)))?;
	parse_mtree(decoder)
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
