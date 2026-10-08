// port of lib/libalpm/be_local.c, reading side: validate, populate and
// local_db_read.
//
// desc and files are read like the C: safe_fgets into a 1024 byte line
// (longer lines come in 1023 byte pieces), the READ_* macros, keys
// matched as C strings. a NULL from fgets at the end of the file leaves
// the line as it was, the C then reads the last value once more as a key.
//
// lazy loading keeps the C infolevel bits: read() loads the requested
// sections once, a failed read marks the package INFRQ_ERROR and later
// reads give up; what a failing section read before the error stays.
// populate and read log through the caller's Callbacks like the C
// through handle->logcb. mtree reading and the writing side are the last
// sections. not ported: changelog.

use std::ffi::{OsStr, c_int};
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, BufReader, ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{
	DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::path::Path;

use pacman_common::util_common::safe_fgets_into;

use crate::backup::split_backup;
use crate::callbacks::{Callbacks, LogLevel, logv};
use crate::deps::{dep_compute_string, dep_from_string};
use crate::error::Errno;
use crate::filelist::{File as PkgFile, FileList};
use crate::mtree;
use crate::package::{
	PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM,
	PKG_VALIDATION_SIGNATURE, Package, PkgFrom, PkgReason, check_meta,
	parse_xdata,
};
use crate::pkghash::PkgHash;
use crate::util::{
	hash_sdbm, makepath, mkdir_mode, parsedate, splitname, strerror,
	strtoofft, until_nul,
};

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
	// desc/files could not be opened, or a desc read failed (ferror)
	Io(io::Error),
	// a %XDATA% line without '=' (_alpm_pkg_parse_xdata NULL)
	XData(Vec<u8>),
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
pub(crate) fn scan_zu(s: &[u8]) -> Option<u64> {
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
	// name are skipped (logged). the C appends then msorts the list by
	// name; names are unique, so add_sorted gives the same list and
	// bucket layout. only name, version, name_hash and origin are set,
	// read() does the rest (the C's INFRQ_BASE read loads nothing but
	// its log line)
	pub fn populate(
		&self,
		cb: &mut dyn Callbacks,
	) -> Result<PkgHash<Package>, DbError> {
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
			let fname = fname.as_bytes();
			let Some((name, version)) = splitname(fname) else {
				let parts: [&[u8]; 3] = [
					b"invalid name for database entry '",
					fname,
					b"'\n",
				];
				logv(cb, LogLevel::Error, &parts);
				continue;
			};
			if cache.find(name).is_some() {
				let parts: [&[u8]; 3] = [
					b"duplicated database entry '",
					name,
					b"'\n",
				];
				logv(cb, LogLevel::Error, &parts);
				continue;
			}
			let mut pkg = Package {
				name_hash: hash_sdbm(name),
				name: Some(name.to_vec()),
				version: Some(version.to_vec()),
				origin: Some(PkgFrom::LocalDb),
				..Package::default()
			};
			// local_db_read(pkg, INFRQ_BASE) never fails
			let _ = self.read(&mut pkg, INFRQ_BASE, cb);
			// metadata errors are only logged for installed packages
			check_meta(name, version, cb);
			let parts: [&[u8]; 3] = [
				b"adding '",
				name,
				b"' to package cache for db 'local'\n",
			];
			logv(cb, LogLevel::Function, &parts);
			cache.add_sorted(pkg).map_err(|_| DbError::Memory)?;
		}
		let count = cache.len().to_string();
		let parts: [&[u8]; 3] = [
			b"added ",
			count.as_bytes(),
			b" packages to package cache for db 'local'\n",
		];
		logv(cb, LogLevel::Debug, &parts);
		Ok(cache)
	}

	// local_db_read: loads the sections of inforeq not loaded yet. on
	// error what was read stays, INFRQ_ERROR is set
	pub fn read(
		&self,
		pkg: &mut Package,
		inforeq: c_int,
		cb: &mut dyn Callbacks,
	) -> Result<(), ReadError> {
		if pkg.infolevel & inforeq == inforeq {
			return Ok(());
		}
		if pkg.infolevel & INFRQ_ERROR != 0 {
			return Err(ReadError::Earlier);
		}
		let level = format!("{inforeq:x}");
		let parts: [&[u8]; 5] = [
			b"loading package data for ",
			pkg.name_bytes(),
			b" : level=0x",
			level.as_bytes(),
			b"\n",
		];
		logv(cb, LogLevel::Function, &parts);
		let r = self.read_sections(pkg, inforeq, cb);
		pkg.shrink_lists();
		if r.is_err() {
			pkg.infolevel |= INFRQ_ERROR;
		}
		r
	}

	// fopen(path, "r") for a section, the failure logged
	fn open_section(
		&self,
		pkg: &Package,
		file: &[u8],
		cb: &mut dyn Callbacks,
	) -> Result<File, ReadError> {
		let path = self.pkgpath(pkg, file);
		File::open(os(&path)).map_err(|e| {
			let err = strerror(&e);
			let parts: [&[u8]; 5] = [
				b"could not open file ",
				&path,
				b": ",
				&err,
				b"\n",
			];
			logv(cb, LogLevel::Error, &parts);
			ReadError::Io(e)
		})
	}

	fn wants(pkg: &Package, inforeq: c_int, bit: c_int) -> bool {
		inforeq & bit != 0 && pkg.infolevel & bit == 0
	}

	fn read_sections(
		&self,
		pkg: &mut Package,
		inforeq: c_int,
		cb: &mut dyn Callbacks,
	) -> Result<(), ReadError> {
		if Self::wants(pkg, inforeq, INFRQ_DESC) {
			let f = self.open_section(pkg, b"desc", cb)?;
			read_desc(pkg, &mut Lines::new(f), cb)?;
			pkg.infolevel |= INFRQ_DESC;
		}
		if Self::wants(pkg, inforeq, INFRQ_FILES) {
			let f = self.open_section(pkg, b"files", cb)?;
			read_files(pkg, &mut Lines::new(f));
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

// sizeof(line) in local_db_read
const LINE_SIZE: usize = 1024;

// the open desc or files: safe_fgets(line, sizeof(line), fp) and the
// stream's end-of-file flag, sticky since glibc 2.28 (fgets at the end
// returns NULL without reading)
struct Lines {
	r: BufReader<File>,
	eof: bool,
	// line as a C string: up to its first nul, the '\n' gone once
	// stripped
	line: Vec<u8>,
	// fgets reads here first: a NULL must leave line as it was
	next: Vec<u8>,
}

impl Lines {
	fn new(f: File) -> Self {
		Lines {
			r: BufReader::new(f),
			eof: false,
			line: Vec::new(),
			next: Vec::new(),
		}
	}

	// Ok(false) is NULL at the end of the file, the line stays as it
	// was; Err is NULL from a read error (ferror)
	fn fgets(&mut self) -> io::Result<bool> {
		if self.eof {
			return Ok(false);
		}
		// two buffers swapped instead of one per line; a NULL at the
		// end leaves what the last fgets put in line, like the C
		if !safe_fgets_into(&mut self.r, LINE_SIZE, &mut self.next)? {
			self.eof = true;
			return Ok(false);
		}
		let l = &mut self.next;
		// fgets stops at '\n' or a full buffer, else it met the end
		self.eof = !l.ends_with(b"\n") && l.len() < LINE_SIZE - 1;
		let n = until_nul(l).len();
		l.truncate(n);
		std::mem::swap(&mut self.line, &mut self.next);
		Ok(true)
	}

	// _alpm_strip_newline(line, 0): the stripped length. the line is cut
	// at its nul already, so only the trailing newlines go
	fn strip(&mut self) -> usize {
		let keep = self.line.iter().rposition(|&c| c != b'\n');
		self.line.truncate(keep.map_or(0, |i| i + 1));
		self.line.len()
	}

	// READ_NEXT: NULL at the end keeps the line
	fn next(&mut self) -> io::Result<&[u8]> {
		self.fgets()?;
		self.strip();
		Ok(&self.line)
	}

	// READ_AND_STORE
	fn store(&mut self) -> io::Result<Option<Vec<u8>>> {
		Ok(Some(self.next()?.to_vec()))
	}

	// READ_AND_STORE_ALL and READ_AND_SPLITDEP: lines up to a blank
	// one or the end of the file
	fn list<T>(
		&mut self,
		out: &mut Vec<T>,
		f: impl Fn(&[u8]) -> T,
	) -> io::Result<()> {
		while self.fgets()? && self.strip() != 0 {
			out.push(f(&self.line));
		}
		Ok(())
	}
}

fn line_vec(s: &[u8]) -> Vec<u8> {
	s.to_vec()
}

// _read_pkgreason
fn read_reason(name: &[u8], line: &[u8], cb: &mut dyn Callbacks) -> PkgReason {
	match line {
		b"0" => PkgReason::Explicit,
		b"1" => PkgReason::Depend,
		_ => {
			let parts: [&[u8]; 5] = [
				b"unknown install reason for package ",
				name,
				b": ",
				line,
				b"\n",
			];
			logv(cb, LogLevel::Error, &parts);
			PkgReason::Unknown
		}
	}
}

// %VALIDATION% values onto their bits, others warned about
fn read_validation(
	pkg: &mut Package,
	lines: &[Vec<u8>],
	cb: &mut dyn Callbacks,
) {
	for v in lines {
		pkg.validation |= match &v[..] {
			b"none" => PKG_VALIDATION_NONE,
			b"sha256" => PKG_VALIDATION_SHA256SUM,
			b"pgp" => PKG_VALIDATION_SIGNATURE,
			_ => {
				let parts: [&[u8]; 5] = [
					b"unknown validation type for package ",
					pkg.name_bytes(),
					b": ",
					v,
					b"\n",
				];
				logv(cb, LogLevel::Warning, &parts);
				0
			}
		};
	}
}

// "local database is inconsistent: <what> mismatch on package <name>"
fn mismatch(what: &[u8], name: &[u8], cb: &mut dyn Callbacks) {
	let parts: [&[u8]; 5] = [
		b"local database is inconsistent: ",
		what,
		b" mismatch on package ",
		name,
		b"\n",
	];
	logv(cb, LogLevel::Error, &parts);
}

// the desc part of local_db_read. a key repeated overwrites a value and
// appends to a list
fn read_desc(
	pkg: &mut Package,
	f: &mut Lines,
	cb: &mut dyn Callbacks,
) -> Result<(), ReadError> {
	let deps = dep_from_string;
	while !f.eof {
		f.fgets().map_err(ReadError::Io)?;
		if f.strip() == 0 {
			continue;
		}
		let key = f.line.clone();
		let name = pkg.name_bytes().to_vec();
		let io = ReadError::Io;
		match &key[..] {
			b"%NAME%" => {
				if f.next().map_err(io)? != &name[..] {
					mismatch(b"name", &name, cb);
				}
			}
			b"%VERSION%" => {
				let v = pkg
					.version
					.as_deref()
					.unwrap_or_default();
				if f.next().map_err(io)? != until_nul(v) {
					mismatch(b"version", &name, cb);
				}
			}
			b"%BASE%" => pkg.base = f.store().map_err(io)?,
			b"%DESC%" => pkg.desc = f.store().map_err(io)?,
			b"%GROUPS%" => {
				f.list(&mut pkg.groups, line_vec).map_err(io)?
			}
			b"%URL%" => pkg.url = f.store().map_err(io)?,
			b"%LICENSE%" => f
				.list(&mut pkg.licenses, line_vec)
				.map_err(io)?,
			b"%ARCH%" => pkg.arch = f.store().map_err(io)?,
			// _alpm_parsedate: 0 for anything but a number
			b"%BUILDDATE%" => {
				let v = parsedate(f.next().map_err(io)?);
				pkg.builddate = v.unwrap_or(0);
			}
			b"%INSTALLDATE%" => {
				let v = parsedate(f.next().map_err(io)?);
				pkg.installdate = v.unwrap_or(0);
			}
			b"%PACKAGER%" => {
				pkg.packager = f.store().map_err(io)?
			}
			b"%REASON%" => {
				let line = f.next().map_err(io)?.to_vec();
				pkg.reason = read_reason(&name, &line, cb);
			}
			b"%VALIDATION%" => {
				let mut v = Vec::new();
				f.list(&mut v, line_vec).map_err(io)?;
				read_validation(pkg, &v, cb);
			}
			// _alpm_strtoofft: -1 for anything but bare digits, the
			// unsigned long long cast to off_t wraps past i64::MAX
			b"%SIZE%" => {
				let v = strtoofft(f.next().map_err(io)?);
				pkg.isize = v.map_or(-1, |v| v as i64);
			}
			b"%REPLACES%" => {
				f.list(&mut pkg.replaces, deps).map_err(io)?
			}
			b"%DEPENDS%" => {
				f.list(&mut pkg.depends, deps).map_err(io)?
			}
			b"%OPTDEPENDS%" => {
				f.list(&mut pkg.optdepends, deps).map_err(io)?
			}
			b"%MAKEDEPENDS%" => f
				.list(&mut pkg.makedepends, deps)
				.map_err(io)?,
			b"%CHECKDEPENDS%" => f
				.list(&mut pkg.checkdepends, deps)
				.map_err(io)?,
			b"%CONFLICTS%" => {
				f.list(&mut pkg.conflicts, deps).map_err(io)?
			}
			b"%PROVIDES%" => {
				f.list(&mut pkg.provides, deps).map_err(io)?
			}
			b"%XDATA%" => {
				let mut lines = Vec::new();
				f.list(&mut lines, line_vec).map_err(io)?;
				// entries before a bad line stay
				for l in lines {
					let x = parse_xdata(&l)
						.ok_or(ReadError::XData(l))?;
					pkg.xdata.push(x);
				}
			}
			_ => {
				let parts: [&[u8]; 4] = [
					&name,
					b": unknown key '",
					&key,
					b"' in local database\n",
				];
				logv(cb, LogLevel::Warning, &parts);
				f.list(&mut Vec::new(), |_| ()).map_err(io)?;
			}
		}
	}
	Ok(())
}

// the files part of local_db_read: any NULL from fgets ends it, lines
// outside the two sections are skipped. a second %FILES% replaces the
// list, %BACKUP% appends. the C sorts the file list
// (_alpm_filelist_sort), backups keep file order
fn read_files(pkg: &mut Package, f: &mut Lines) {
	let more = |f: &mut Lines| f.fgets().unwrap_or(false);
	while more(f) {
		f.strip();
		match &f.line[..] {
			b"%FILES%" => {
				let mut files = Vec::new();
				while more(f) && f.strip() != 0 {
					files.push(PkgFile {
						name: f.line.clone(),
						..PkgFile::default()
					});
				}
				pkg.files = FileList { files };
				pkg.files.sort();
			}
			b"%BACKUP%" => {
				while more(f) && f.strip() != 0 {
					pkg.backup.push(split_backup(&f.line));
				}
			}
			_ => {}
		}
	}
}

// mtree: _cache_mtree_open/_cache_mtree_next
//
// the C opens "<pkgpath>mtree" with libarchive's mtree reader
// (crate::mtree) and yields its entries one by one. an entry libarchive
// warns about ends the C's walk (UPSTREAM.md), here it is kept with its
// warning

pub use crate::mtree::{Entry as MtreeEntry, EntryType as MtreeType};
pub use alpm_types::{Md5Checksum, Sha256Checksum};

#[derive(Debug)]
pub enum MtreeError {
	// access(F_OK) fails: "there is no mtree file for this package"
	Missing,
	// archive_read_open fails
	Read(mtree::Error),
	// the first archive_read_next_header fails: no entries, libarchive's
	// text
	Parse(Vec<u8>),
}

pub fn read_mtree(path: &[u8]) -> Result<Vec<MtreeEntry>, MtreeError> {
	// access(F_OK) follows symlinks
	if fs::metadata(os(path)).is_err() {
		return Err(MtreeError::Missing);
	}
	mtree::read_file(path).map_err(|e| match e {
		mtree::Error::Header(text) => MtreeError::Parse(text),
		e => MtreeError::Read(e),
	})
}

impl LocalDb {
	// alpm_pkg_mtree_open + alpm_pkg_mtree_next to the end, on
	// _alpm_local_db_pkgpath(db, pkg, "mtree"). an open failure is
	// logged like _cache_mtree_open
	pub fn mtree(
		&self,
		pkg: &Package,
		cb: &mut dyn Callbacks,
	) -> Result<Vec<MtreeEntry>, MtreeError> {
		let path = self.pkgpath(pkg, b"mtree");
		let r = read_mtree(&path);
		if let Err(MtreeError::Read(e)) = &r {
			let text = e.text();
			let parts: [&[u8]; 5] = [
				b"error while reading file ",
				&path,
				b": ",
				&text,
				b"\n",
			];
			logv(cb, LogLevel::Error, &parts);
		}
		r
	}
}

// writing side: _alpm_local_db_prepare, _alpm_local_db_write,
// _alpm_local_db_remove and alpm_pkg_set_reason
//
// desc and files are written by a translation of the C writer. fields go
// through %s, so each is cut at its first nul. the
// C sets the umask (0000 for prepare, 0022 for write) around its mkdir and
// fopen; the port gives the same modes by chmod. logging is not modelled

// why _alpm_local_db_prepare returned -1
#[derive(Debug)]
pub enum PrepareError {
	// checkdbdir could not create the db dir or replace a non-directory
	// with one: ALPM_ERR_SYSTEM
	DbDir(io::Error),
	// mkdir of the package dir failed (also when it exists), logged,
	// pm_errno untouched
	Mkdir(io::Error),
}

impl PrepareError {
	// the pm_errno the C sets, None where it leaves it alone
	pub fn errno(&self) -> Option<Errno> {
		match self {
			PrepareError::DbDir(_) => Some(Errno::System),
			PrepareError::Mkdir(_) => None,
		}
	}
}

// why _alpm_local_db_write failed
#[derive(Debug)]
pub enum WriteError {
	// desc or files could not be opened: -1, pm_errno untouched. a desc
	// failure skips the files
	Open(io::Error),
	// writing failed (disk full). the C ignores fprintf/fclose results
	// and returns 0 here
	Write(io::Error),
}

// fopen(path, "w") under umask(0022): a new file gets 0644, an existing
// one keeps its mode and is truncated
fn create_0644(path: &[u8]) -> io::Result<File> {
	let new = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o644)
		.open(os(path));
	match new {
		Ok(f) => {
			f.set_permissions(Permissions::from_mode(0o644))?;
			Ok(f)
		}
		Err(e) if e.kind() == ErrorKind::AlreadyExists => {
			OpenOptions::new()
				.write(true)
				.create(true)
				.truncate(true)
				.mode(0o644)
				.open(os(path))
		}
		Err(e) => Err(e),
	}
}

// fputs of a C string
fn put(out: &mut Vec<u8>, s: &[u8]) {
	out.extend_from_slice(until_nul(s));
}

// "%KEY%\n<value>\n\n" for a set field
fn single(out: &mut Vec<u8>, key: &[u8], value: Option<&[u8]>) {
	if let Some(v) = value {
		put(out, key);
		out.push(b'\n');
		put(out, v);
		out.extend_from_slice(b"\n\n");
	}
}

// a header, one line per value and a blank line, nothing for no values
fn list<T>(
	out: &mut Vec<u8>,
	key: &[u8],
	values: &[T],
	line: impl Fn(&T) -> Vec<u8>,
) {
	if values.is_empty() {
		return;
	}
	put(out, key);
	out.push(b'\n');
	for v in values {
		out.extend_from_slice(&line(v));
		out.push(b'\n');
	}
	out.push(b'\n');
}

// %jd and %u: only written when nonzero
fn number(out: &mut Vec<u8>, key: &[u8], n: i64) {
	if n != 0 {
		single(out, key, Some(n.to_string().as_bytes()));
	}
}

// the desc file, field for field in the C's order
fn desc_text(pkg: &Package) -> Vec<u8> {
	let mut out = Vec::new();
	let name = pkg.name.as_deref().unwrap_or_default();
	let version = pkg.version.as_deref().unwrap_or_default();
	single(&mut out, b"%NAME%", Some(name));
	single(&mut out, b"%VERSION%", Some(version));
	single(&mut out, b"%BASE%", pkg.base.as_deref());
	single(&mut out, b"%DESC%", pkg.desc.as_deref());
	single(&mut out, b"%URL%", pkg.url.as_deref());
	single(&mut out, b"%ARCH%", pkg.arch.as_deref());
	number(&mut out, b"%BUILDDATE%", pkg.builddate);
	number(&mut out, b"%INSTALLDATE%", pkg.installdate);
	single(&mut out, b"%PACKAGER%", pkg.packager.as_deref());
	// only the installed size, csize is irrelevant once installed
	number(&mut out, b"%SIZE%", pkg.isize);
	number(&mut out, b"%REASON%", pkg.reason as i64);
	let text = |s: &Vec<u8>| until_nul(s).to_vec();
	list(&mut out, b"%GROUPS%", &pkg.groups, text);
	list(&mut out, b"%LICENSE%", &pkg.licenses, text);
	if pkg.validation != 0 {
		// the known bits in a fixed order, md5 is never written
		let methods: Vec<&[u8]> = [
			(PKG_VALIDATION_NONE, &b"none"[..]),
			(PKG_VALIDATION_SHA256SUM, b"sha256"),
			(PKG_VALIDATION_SIGNATURE, b"pgp"),
		]
		.into_iter()
		.filter(|(bit, _)| pkg.validation & bit != 0)
		.map(|(_, m)| m)
		.collect();
		out.extend_from_slice(b"%VALIDATION%\n");
		for m in methods {
			out.extend_from_slice(m);
			out.push(b'\n');
		}
		out.push(b'\n');
	}
	// write_deps
	for (key, deps) in [
		(&b"%REPLACES%"[..], &pkg.replaces),
		(b"%DEPENDS%", &pkg.depends),
		(b"%OPTDEPENDS%", &pkg.optdepends),
		(b"%CONFLICTS%", &pkg.conflicts),
		(b"%PROVIDES%", &pkg.provides),
	] {
		list(&mut out, key, deps, dep_compute_string);
	}
	list(&mut out, b"%XDATA%", &pkg.xdata, |x| {
		[until_nul(&x.name), b"=", until_nul(&x.value)].concat()
	});
	out
}

// the files file: %FILES% in list order, %BACKUP% with "<name>\t<hash>".
// a NULL hash prints as glibc's "(null)"
fn files_text(pkg: &Package) -> Vec<u8> {
	let mut out = Vec::new();
	list(&mut out, b"%FILES%", &pkg.files.files, |f| {
		until_nul(&f.name).to_vec()
	});
	list(&mut out, b"%BACKUP%", &pkg.backup, |b| {
		let hash = b.hash.as_deref().unwrap_or(b"(null)");
		[until_nul(&b.name), b"\t", until_nul(hash)].concat()
	});
	out
}

fn write_file(path: &[u8], text: &[u8]) -> Result<(), WriteError> {
	let mut f = create_0644(path).map_err(WriteError::Open)?;
	f.write_all(text).map_err(WriteError::Write)
}

impl LocalDb {
	// checkdbdir: a missing (or unstat-able) db dir is created, a
	// non-directory in its place unlinked and replaced
	fn checkdbdir(&self) -> io::Result<()> {
		match fs::metadata(os(&self.path)) {
			Ok(m) if m.is_dir() => return Ok(()),
			Ok(_) => fs::remove_file(os(&self.path))?,
			Err(_) => {}
		}
		makepath(&self.path)
	}

	// _alpm_local_db_prepare: the package directory, mode 0755 (umask
	// 0000)
	pub fn prepare(&self, pkg: &Package) -> Result<(), PrepareError> {
		self.checkdbdir().map_err(PrepareError::DbDir)?;
		let path = self.pkgpath(pkg, b"");
		mkdir_mode(os(&path), 0o755).map_err(PrepareError::Mkdir)
	}

	// _alpm_local_db_write: desc for INFRQ_DESC, files for INFRQ_FILES.
	// install and mtree are extracted by add.c, nothing to write
	pub fn write(
		&self,
		pkg: &Package,
		inforeq: c_int,
	) -> Result<(), WriteError> {
		if inforeq & INFRQ_DESC != 0 {
			write_file(
				&self.pkgpath(pkg, b"desc"),
				&desc_text(pkg),
			)?;
		}
		if inforeq & INFRQ_FILES != 0 {
			write_file(
				&self.pkgpath(pkg, b"files"),
				&files_text(pkg),
			)?;
		}
		Ok(())
	}

	// _alpm_local_db_remove: unlink every entry of the package dir (they
	// are files), then rmdir it. failures do not stop the others; the
	// first is returned. the C's PATH_MAX check is the kernel's
	// ENAMETOOLONG on the joined name
	pub fn remove(&self, pkg: &Package) -> io::Result<()> {
		let path = self.pkgpath(pkg, b"");
		let dir = fs::read_dir(os(&path))?;
		let mut first = None;
		for ent in entries(dir) {
			// "<pkgpath>/<name>", pkgpath already ends in '/'
			let name = ent.file_name();
			let file = [&path[..], b"/", name.as_bytes()].concat();
			if let Err(e) = fs::remove_file(os(&file)) {
				first.get_or_insert(e);
			}
		}
		if let Err(e) = fs::remove_dir(os(&path)) {
			first.get_or_insert(e);
		}
		first.map_or(Ok(()), Err)
	}

	// alpm_pkg_set_reason on a package of this db (the C checks
	// origin_data.db against handle->db_local, the caller does here).
	// alpm_pkg_get_reason loads the desc first, a failed load compares
	// what the package holds. the desc is rewritten only on a change
	pub fn set_reason(
		&self,
		pkg: &mut Package,
		reason: PkgReason,
		cb: &mut dyn Callbacks,
	) -> Result<(), Errno> {
		if pkg.origin != Some(PkgFrom::LocalDb) {
			return Err(Errno::WrongArgs);
		}
		let n = (reason as u32).to_string();
		let parts: [&[u8]; 5] = [
			b"setting install reason ",
			n.as_bytes(),
			b" for ",
			pkg.name_bytes(),
			b"\n",
		];
		logv(cb, LogLevel::Debug, &parts);
		let _ = self.read(pkg, INFRQ_DESC, cb);
		if pkg.reason == reason {
			return Ok(());
		}
		pkg.reason = reason;
		self.write(pkg, INFRQ_DESC).map_err(|_| Errno::DbWrite)
	}
}
