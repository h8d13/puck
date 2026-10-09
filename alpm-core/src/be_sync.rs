// port of lib/libalpm/be_sync.c, reading side: sync_db_populate,
// sync_db_read, load_pkg_for_entry, _sync_get_validation, and the sync
// branch of db.c's _alpm_db_path.
//
// the tar walk and the entry reader follow the C: _alpm_archive_fgets
// over the entry's data blocks as libarchive cuts them, the READ_*
// macros, keys matched as C strings. libarchive's filters are filter.rs,
// picked by its bidders: the db file name carries no compression suffix.
//
// sync_db_validate without the status bits db.c keeps: the missing file
// and the signature check (signing.rs). alpm_db_update with get_sync_dir:
// downloads through dload.rs, validation through Db::validate. populate
// on a db file that does not exist is NotFound.

use std::collections::HashMap;
use std::ffi::{OsStr, c_int};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{Access, Mode};
use rustix::process::umask;

use crate::callbacks::{Callbacks, Event, LogLevel, logv};
use crate::db::{DB_USAGE_SYNC, Db};
use crate::deps::dep_from_string;
use crate::dload::{
	Downloader, Payload, Settings, remove_temporary_download_dir,
};
use crate::error::Errno;
use crate::filelist::{File as PkgFile, FileList};
use crate::filter::Code;
use crate::handle::{Handle, SyncParts};
use crate::package::{
	PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM,
	PKG_VALIDATION_SIGNATURE, Package, PkgFrom, check_meta, extend_xdata,
};
use crate::pkghash::PkgHash;
use crate::signing::{
	Keyring, SIG_DATABASE, SIG_DATABASE_MARGINAL_OK, SIG_DATABASE_OPTIONAL,
	SIG_DATABASE_UNKNOWN_OK, check_pgp_helper, process_siglist,
};
use crate::tar;
use crate::util::{
	self, ArchiveFgets, DataBlocks, Entry, PATH_MAX, S_IFDIR, S_IFMT,
	alpm_access, get_fullpath, hash_sdbm, makepath, parsedate, splitname,
	strtoofft, until_nul, with_vec,
};

// hard upper limit of a db download
const DB_MAX_SIZE: i64 = 128 * 1024 * 1024;

// why an entry made the db invalid
#[derive(Debug)]
pub enum Reason {
	// _alpm_splitname refused the entry name
	Name,
	// _alpm_pkg_check_meta refused name or version
	Meta,
	// _alpm_validate_filename refused %FILENAME%
	Filename,
	// a data block could not be read, or a line is over 512 KiB
	Read(io::Error),
	// the data ended where a value or a list's blank line was due
	Truncated,
	// a %DATA% line without '=' (_alpm_pkg_parse_xdata NULL)
	XData(Vec<u8>),
	// the cache cannot grow, ALPM_ERR_MEMORY turned into DB_INVALID
	Cache,
}

#[derive(Debug)]
pub enum Error {
	// missing db file: sync_db_validate marks it DB_STATUS_MISSING
	NotFound,
	// _alpm_open_archive failed
	Open(io::Error),
	// _alpm_pkghash_create refused the estimate
	Memory,
	// an entry failed to load, the whole db is dropped
	Invalid { entry: Vec<u8>, reason: Reason },
	// archive_read_next_header failed
	Archive(io::Error),
}

impl Error {
	// pm_errno the C leaves after alpm_db_get_pkgcache
	pub fn errno(&self) -> Errno {
		match self {
			Error::NotFound => Errno::DbNotFound,
			Error::Open(_) => Errno::DbOpen,
			Error::Memory => Errno::Memory,
			Error::Invalid { .. } => Errno::DbInvalid,
			Error::Archive(_) => Errno::Libarchive,
		}
	}
}

// _alpm_db_path for a sync db: dbpath ends with '/' after
// alpm_initialize, nothing is added between dbpath and "sync/"
pub fn db_path(dbpath: &[u8], treename: &[u8], dbext: &[u8]) -> Vec<u8> {
	[
		until_nul(dbpath),
		b"sync/",
		until_nul(treename),
		until_nul(dbext),
	]
	.concat()
}

// sync_db_validate on a db neither valid nor invalid yet: Ok(false) when
// the file at path (its _alpm_db_path) is missing (DB_STATUS_MISSING,
// the C sends ALPM_EVENT_DATABASE_MISSING), Ok(true) when it exists and
// passed. siglevel is alpm_db_get_siglevel; with SIG_DATABASE the
// "<path>.sig" check runs, and again while an offered key import works.
// Err(DbInvalidSig) marks the db invalid
pub fn sync_db_validate(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	path: &[u8],
	treename: &[u8],
	siglevel: c_int,
) -> Result<bool, Errno> {
	let path = until_nul(path);
	// _alpm_access(R_OK) failing with ENOENT, a dangling link exists
	let readable = alpm_access(cb, None, path, Access::READ_OK);
	if readable == Err(rustix::io::Errno::NOENT) {
		return Ok(false);
	}
	if siglevel & SIG_DATABASE == 0 {
		return Ok(true);
	}
	let optional = siglevel & SIG_DATABASE_OPTIONAL != 0;
	let marginal = siglevel & SIG_DATABASE_MARGINAL_OK != 0;
	let unknown = siglevel & SIG_DATABASE_UNKNOWN_OK != 0;
	loop {
		let (ok, siglist) = check_pgp_helper(
			kr,
			cb,
			Some(path),
			None,
			optional,
			marginal,
			unknown,
		);
		if ok.is_ok() {
			return Ok(true);
		}
		let retry = process_siglist(
			kr, cb, treename, &siglist, optional, marginal, unknown,
		);
		if !retry {
			return Err(Errno::DbInvalidSig);
		}
	}
}

// get_sync_dir: "<dbpath>sync/", made when stat(2) fails, a non-directory
// there unlinked first. Err is ALPM_ERR_SYSTEM
fn get_sync_dir(
	dbpath: &[u8],
	cb: &mut dyn Callbacks,
) -> Result<Vec<u8>, Errno> {
	let syncpath = [until_nul(dbpath), b"sync/"].concat();
	let p = Path::new(OsStr::from_bytes(&syncpath));
	match fs::metadata(p) {
		Err(_) => {
			let msg = [
				b"database dir '",
				&syncpath[..],
				b"' does not exist, creating it\n",
			];
			cb.log(LogLevel::Debug, &msg.concat());
			makepath(&syncpath).map_err(|_| Errno::System)?;
		}
		Ok(m) if !m.is_dir() => {
			let msg = [
				b"removing invalid file: ",
				&syncpath[..],
				b"\n",
			];
			cb.log(LogLevel::Warning, &msg.concat());
			fs::remove_file(p).map_err(|_| Errno::System)?;
			makepath(&syncpath).map_err(|_| Errno::System)?;
		}
		Ok(_) => {}
	}
	Ok(syncpath)
}

fn downloader<'a>(
	parts: &'a mut SyncParts<'_>,
	settings: &'a Settings,
) -> Downloader<'a> {
	Downloader {
		settings,
		state: &mut *parts.download,
		cb: &mut *parts.cb,
		fetch: parts.fetch.as_deref_mut().map(|f| f as _),
		sandbox: parts.sandbox.as_deref_mut().map(|s| s as _),
	}
}

// the download payload of a db: "<treename><dbext>" from its servers
// into tmp, its .sig as the siglevel asks
fn db_payload(
	db: &Db,
	dbext: &[u8],
	siglevel: c_int,
	force: bool,
	tmp: &[u8],
) -> Payload {
	let name = [db.name(), until_nul(dbext)].concat();
	let mut p = Payload::default();
	p.servers = db.servers().to_vec();
	p.destfile_name = Some(get_fullpath(tmp, &name, b""));
	p.tempfile_name = get_fullpath(tmp, &name, b".part");
	p.filepath = Some(name.clone());
	p.remote_name = name;
	p.force = force;
	p.unlink_on_fail = true;
	p.download_signature = siglevel & SIG_DATABASE != 0;
	p.signature_optional = siglevel & SIG_DATABASE_OPTIONAL != 0;
	p.max_size = DB_MAX_SIZE;
	p
}

// alpm_db_update once the lock is held: payloads, the download between
// the DB_RETRIEVE events, then every db's cache dropped and its status
// validated anew. a failed validation is Err, the errno of the last one
fn update_locked(
	handle: &mut Handle,
	settings: &Settings,
	dbs: &[usize],
	force: bool,
	syncpath: &[u8],
	tmp: &[u8],
) -> Result<bool, Errno> {
	let dbext = handle.dbext().to_vec();
	let default = handle.default_siglevel();
	let mut parts = handle.sync_parts();
	let mut payloads = Vec::new();
	let mut synced = Vec::new();
	for &i in dbs {
		let db = &parts.dbs[i];
		if db.usage() & DB_USAGE_SYNC == 0 {
			continue;
		}
		if db.servers().is_empty() {
			return Err(Errno::ServerNone);
		}
		// an invalid db is fetched again: a db and signature that do
		// not match may be fixed upstream
		let dbforce = force || db.valid().is_err();
		let level = db.siglevel(default);
		payloads.push(db_payload(db, &dbext, level, dbforce, tmp));
		synced.push(i);
	}
	if payloads.is_empty() {
		return Ok(true);
	}
	parts.cb.event(&Event::DbRetrieveStart);
	let ret = downloader(&mut parts, settings).download(
		&mut payloads,
		syncpath,
		tmp,
	);
	if ret.is_err() {
		parts.cb.event(&Event::DbRetrieveFailed);
		return ret;
	}
	parts.cb.event(&Event::DbRetrieveDone);
	let mut failed = None;
	for i in synced {
		let db = &mut parts.dbs[i];
		db.free_pkgcache(parts.cb);
		let res = db.validate(default, parts.keyring, parts.cb);
		if let Err(e) = res {
			let msg =
				[b"failed to validate db: ", db.name(), b"\n"];
			parts.cb.log(LogLevel::Debug, &msg.concat());
			failed = Some(e);
		}
	}
	failed.map_or(ret, Err)
}

// alpm_db_update: the sync dbs at positions dbs of handle.syncdbs() (used
// for syncing) downloaded into "<dbpath>sync/", with If-Modified-Since
// unless force or the db is invalid. Ok(true) something was downloaded
// (C 0), Ok(false) every db was up to date (C 1), Err the pm_errno of
// the failure (C -1). an empty dbs is the C's NULL list: Err(Errno::Ok),
// the C leaves pm_errno as it was. umask(0022) from the download dir
// setup on, like the C: the dbs get 0644 whatever the process umask
pub fn db_update(
	handle: &mut Handle,
	dbs: &[usize],
	force: bool,
) -> Result<bool, Errno> {
	if dbs.is_empty() {
		return Err(Errno::Ok);
	}
	let dbpath = handle.dbpath().to_vec();
	let syncpath = get_sync_dir(&dbpath, handle.callbacks())?;
	let settings = handle.dload_settings();
	let mut parts = handle.sync_parts();
	let tmp = downloader(&mut parts, &settings)
		.download_dir_setup(&syncpath)?;
	let oldmask = umask(Mode::from_raw_mode(0o022));
	let ret = match handle.lock() {
		Ok(()) => update_locked(
			handle, &settings, dbs, force, &syncpath, &tmp,
		),
		Err(_) => Err(Errno::HandleLock),
	};
	handle.handle_unlock();
	if let Err(e) = ret {
		let msg = [
			b"failed to sync dbs: ",
			e.strerror().as_bytes(),
			b"\n",
		];
		handle.callbacks().log(LogLevel::Debug, &msg.concat());
	}
	// a sandbox download dir left by an early error (the C keeps it)
	if tmp != syncpath {
		remove_temporary_download_dir(&tmp);
	}
	umask(oldmask);
	ret
}

// _sync_get_validation, what alpm_pkg_get_validation computes on first
// use. Package::validation stays 0 in the cache like the C field
pub fn get_validation(pkg: &Package) -> c_int {
	if pkg.validation != 0 {
		return pkg.validation;
	}
	let mut v = 0;
	if pkg.sha256sum.is_some() {
		v |= PKG_VALIDATION_SHA256SUM;
	}
	if pkg.base64_sig.is_some() {
		v |= PKG_VALIDATION_SIGNATURE;
	}
	if v == 0 { PKG_VALIDATION_NONE } else { v }
}

// estimate_package_count's bytes per package for the top filter
// libarchive picked (archive_filter_code(a, 0)); lzip, lz4, zstd and the
// program filters have no case there and take the default
fn bytes_per_package(code: Code) -> u64 {
	match code {
		Code::None => 3015,
		Code::Gzip | Code::Compress => 464,
		Code::Bzip2 => 394,
		Code::Lzma | Code::Xz => 400,
		_ => 500,
	}
}

// _alpm_open_archive plus estimate_package_count
fn open_archive(
	path: &[u8],
	dbext: &[u8],
) -> Result<(tar::Reader, u64), Error> {
	// open(2)'s ENOENT only: a filter's program that cannot run fails
	// with that kind too (filter/program.rs), the C's db open fails then
	let enoent = Some(rustix::io::Errno::NOENT.raw_os_error());
	let archive = util::open_archive(path).map_err(|e| {
		match e.raw_os_error() == enoent {
			true => Error::NotFound,
			false => Error::Open(e),
		}
	})?;
	let size = archive.meta.len();
	let mut est = size / bytes_per_package(archive.code) + 1;
	// files dbs are about four times larger on average
	if dbext == b".files" {
		est /= 4;
	}
	Ok((archive.reader, est))
}

// _alpm_validate_filename, its failure logged
fn validate_filename(
	treename: &[u8],
	name: &[u8],
	filename: &[u8],
	cb: &mut dyn Callbacks,
) -> bool {
	let why: &[u8] = if filename.first() == Some(&b'.')
		|| filename.contains(&b'/')
	{
		b" is illegal\n"
	} else if filename.len() > PATH_MAX {
		b" is too long\n"
	} else {
		return true;
	};
	let parts: [&[u8]; 4] = [
		treename,
		b" database is inconsistent: filename of package ",
		name,
		why,
	];
	logv(cb, LogLevel::Error, &parts);
	false
}

// _alpm_archive_fgets on one entry with the line as the READ_* macros
// see it
struct Lines<'e, 'a> {
	f: ArchiveFgets<'e, 'a>,
	// the last line as a C string. _alpm_strip_newline(line,
	// real_line_size) is 0 exactly when this is empty
	line: Vec<u8>,
}

impl<'e, 'a> Lines<'e, 'a> {
	// over the buffers of the walk's last entry: every entry is small,
	// growing two fresh buffers per entry cost more than the C's one
	// block-sized allocation
	fn new(entry: &'e mut Entry<'a>, bufs: Bufs) -> Self {
		let src = DataBlocks::new(entry);
		Lines {
			f: ArchiveFgets::with_line(src, bufs.0),
			line: bufs.1,
		}
	}

	fn into_bufs(self) -> Bufs {
		(self.f.into_line(), self.line)
	}

	// Ok(true) ARCHIVE_OK, Ok(false) ARCHIVE_EOF, Err a failed block
	// read or a line over MAX_LINE_SIZE
	fn fgets(&mut self) -> io::Result<bool> {
		let Some(l) = self.f.next()? else {
			return Ok(false);
		};
		// one buffer for every line, like the C's b->line
		self.line.clear();
		self.line.extend_from_slice(until_nul(l));
		Ok(true)
	}

	// READ_NEXT, READ_AND_STORE: the end of the data fails too
	fn next(&mut self) -> Result<&[u8], Reason> {
		match self.fgets() {
			Ok(true) => Ok(&self.line),
			Ok(false) => Err(Reason::Truncated),
			Err(e) => Err(Reason::Read(e)),
		}
	}

	fn store(&mut self) -> Result<Option<Box<[u8]>>, Reason> {
		Ok(Some(self.next()?.into()))
	}

	// READ_AND_STORE_ALL, READ_AND_SPLITDEP, the %FILES% loop: lines up
	// to a blank one. READ_AND_SPLITDEP parses the line pointer of the
	// section header, freed once a longer line grows the buffer
	// (UPSTREAM.md): the current line here
	fn list<T>(
		&mut self,
		out: &mut Vec<T>,
		f: impl Fn(&[u8]) -> T,
	) -> Result<(), Reason> {
		loop {
			let line = self.next()?;
			if line.is_empty() {
				return Ok(());
			}
			out.push(f(line));
		}
	}

	// a list section onto a package's list, appended to what an
	// earlier one left
	fn append<T>(
		&mut self,
		out: &mut Box<[T]>,
		f: impl Fn(&[u8]) -> T,
	) -> Result<(), Reason> {
		with_vec(out, |v| self.list(v, f))
	}
}

fn line_vec(s: &[u8]) -> Vec<u8> {
	s.to_vec()
}

fn line_box(s: &[u8]) -> Box<[u8]> {
	s.into()
}

// _alpm_strtoofft: -1 for anything but bare digits, the unsigned long
// long cast to off_t wraps past i64::MAX
fn off_t(s: &[u8]) -> i64 {
	strtoofft(s).map_or(-1, |v| v as i64)
}

// line buffers handed from entry to entry
type Bufs = (Vec<u8>, Vec<u8>);

// the walk state of sync_db_populate. index replaces the lookups in
// db->pkgcache and likely_pkg: both find the one package of that name
struct Walk<'a> {
	bufs: Bufs,
	pkgs: Vec<Package>,
	index: HashMap<Vec<u8>, usize>,
	// db->treename and handle->logcb
	treename: &'a [u8],
	cb: &'a mut dyn Callbacks,
}

fn invalid(entry: &[u8], reason: Reason) -> Error {
	Error::Invalid {
		entry: entry.to_vec(),
		reason,
	}
}

impl Walk<'_> {
	// load_pkg_for_entry: the package named by the entry, created on
	// first sight with name and version from the entry name
	fn pkg_for_entry(&mut self, entryname: &[u8]) -> Result<usize, Reason> {
		let Some((name, version)) = splitname(entryname) else {
			let parts: [&[u8]; 3] = [
				b"invalid name for database entry '",
				entryname,
				b"'\n",
			];
			logv(self.cb, LogLevel::Error, &parts);
			return Err(Reason::Name);
		};
		if let Some(&i) = self.index.get(name) {
			return Ok(i);
		}
		if !check_meta(name, version, self.cb) {
			return Err(Reason::Meta);
		}
		let parts: [&[u8]; 5] = [
			b"adding '",
			name,
			b"' to package cache for db '",
			self.treename,
			b"'\n",
		];
		logv(self.cb, LogLevel::Function, &parts);
		let pkg = Package {
			name_hash: hash_sdbm(name),
			name: Some(name.into()),
			version: Some(version.into()),
			origin: Some(PkgFrom::SyncDb),
			..Package::default()
		};
		self.index.insert(name.to_vec(), self.pkgs.len());
		self.pkgs.push(pkg);
		Ok(self.pkgs.len() - 1)
	}

	// sync_db_read on one non-directory entry
	fn read_entry(&mut self, entry: &mut Entry) -> Result<(), Reason> {
		let entryname = entry.path_bytes().to_vec();
		let parts: [&[u8]; 3] = [
			b"loading package data from archive entry ",
			&entryname,
			b"\n",
		];
		logv(self.cb, LogLevel::Function, &parts);
		let i = self.pkg_for_entry(&entryname).inspect_err(|_| {
			let parts: [&[u8]; 5] = [
				b"entry ",
				&entryname,
				b" could not be loaded into ",
				self.treename,
				b" sync database\n",
			];
			logv(self.cb, LogLevel::Debug, &parts);
		})?;
		// strrchr: the last '/', where splitname cut at the first
		let Some(slash) = entryname.iter().rposition(|&c| c == b'/')
		else {
			// a file outside a directory: no read error, package kept
			let parts: [&[u8]; 3] =
				[b"unknown database file: ", &entryname, b"\n"];
			logv(self.cb, LogLevel::Warning, &parts);
			return Ok(());
		};
		let filename = &entryname[slash + 1..];
		if !matches!(filename, b"desc" | b"depends" | b"files") {
			let parts: [&[u8]; 3] =
				[b"unknown database file: ", filename, b"\n"];
			logv(self.cb, LogLevel::Debug, &parts);
			return Ok(());
		}
		let bufs = std::mem::take(&mut self.bufs);
		let mut lines = Lines::new(entry, bufs);
		let r = self.read_data(i, &mut lines);
		self.bufs = lines.into_bufs();
		// the filename check returns without this line
		if r.as_ref().is_err_and(|r| !matches!(r, Reason::Filename)) {
			let parts: [&[u8]; 3] = [
				b"error parsing database file: ",
				filename,
				b"\n",
			];
			logv(self.cb, LogLevel::Debug, &parts);
		}
		r
	}

	// "<treename> database is inconsistent: <what> mismatch on package"
	fn mismatch(&mut self, what: &[u8], name: &[u8]) {
		let parts: [&[u8]; 6] = [
			self.treename,
			b" database is inconsistent: ",
			what,
			b" mismatch on package ",
			name,
			b"\n",
		];
		logv(self.cb, LogLevel::Error, &parts);
	}

	// the parsing loop of sync_db_read: keys matched as C strings, a
	// repeated key overwrites a value, appends to a list and replaces
	// the file list
	fn read_data(&mut self, i: usize, f: &mut Lines) -> Result<(), Reason> {
		let deps = dep_from_string;
		// read_data only compares against the name, and the key is kept
		// apart from the line the values overwrite: both once per entry,
		// not per line
		let name = self.pkgs[i].name_bytes().to_vec();
		let mut key = Vec::new();
		loop {
			match f.fgets() {
				Ok(true) => {}
				Ok(false) => return Ok(()),
				Err(e) => return Err(Reason::Read(e)),
			}
			key.clear();
			key.extend_from_slice(&f.line);
			if key.is_empty() {
				continue;
			}
			let pkg = &mut self.pkgs[i];
			match &key[..] {
				b"%NAME%" => {
					if f.next()? != &name[..] {
						self.mismatch(b"name", &name);
					}
				}
				b"%VERSION%" => {
					let v = pkg.version.as_deref();
					let v = until_nul(
						v.unwrap_or_default(),
					);
					if f.next()? != v {
						self.mismatch(
							b"version", &name,
						);
					}
				}
				b"%FILENAME%" => {
					pkg.filename = f.store()?;
					let filename = pkg.filename.clone();
					let filename =
						filename.unwrap_or_default();
					let (tree, cb) =
						(self.treename, &mut *self.cb);
					if !validate_filename(
						tree, &name, &filename, cb,
					) {
						return Err(Reason::Filename);
					}
				}
				b"%BASE%" => pkg.base = f.store()?,
				b"%DESC%" => pkg.desc = f.store()?,
				b"%GROUPS%" => {
					f.append(&mut pkg.groups, line_box)?
				}
				b"%URL%" => pkg.url = f.store()?,
				b"%LICENSE%" => {
					f.append(&mut pkg.licenses, line_box)?
				}
				b"%ARCH%" => pkg.arch = f.store()?,
				// _alpm_parsedate: 0 for anything but a number
				b"%BUILDDATE%" => {
					pkg.builddate = parsedate(f.next()?)
						.unwrap_or(0)
				}
				b"%PACKAGER%" => pkg.packager = f.store()?,
				b"%CSIZE%" => pkg.size = off_t(f.next()?),
				b"%ISIZE%" => pkg.isize = off_t(f.next()?),
				// deprecated, skipped
				b"%MD5SUM%" => {
					f.next()?;
				}
				b"%SHA256SUM%" => pkg.sha256sum = f.store()?,
				b"%PGPSIG%" => pkg.base64_sig = f.store()?,
				b"%REPLACES%" => {
					f.append(&mut pkg.replaces, deps)?
				}
				b"%DEPENDS%" => {
					f.append(&mut pkg.depends, deps)?
				}
				b"%OPTDEPENDS%" => {
					f.append(&mut pkg.optdepends, deps)?
				}
				b"%MAKEDEPENDS%" => {
					f.append(&mut pkg.makedepends, deps)?
				}
				b"%CHECKDEPENDS%" => {
					f.append(&mut pkg.checkdepends, deps)?
				}
				b"%CONFLICTS%" => {
					f.append(&mut pkg.conflicts, deps)?
				}
				b"%PROVIDES%" => {
					f.append(&mut pkg.provides, deps)?
				}
				// sorted with _alpm_filelist_sort
				b"%FILES%" => {
					let mut files = Vec::new();
					f.list(&mut files, |l| {
						PkgFile::new(l.to_vec(), 0, 0)
					})?;
					// exact like the C's list, for the
					// cache's life
					files.shrink_to_fit();
					pkg.files = FileList { files };
					pkg.files.sort();
				}
				b"%DATA%" => {
					let mut lines = Vec::new();
					f.list(&mut lines, line_vec)?;
					with_vec(&mut pkg.xdata, |x| {
						extend_xdata(x, lines)
					})
					.map_err(Reason::XData)?;
				}
				_ => {
					let parts: [&[u8]; 4] = [
						&name,
						b": unknown key '",
						&key,
						b"' in sync database\n",
					];
					logv(
						self.cb,
						LogLevel::Warning,
						&parts,
					);
					f.list(&mut Vec::new(), |_| ())?;
				}
			}
		}
	}
}

// sync_db_populate: the package cache of the db file at path (its
// _alpm_db_path), list sorted by name, buckets filled in archive order.
// dbext is handle->dbext at load time: ".files" divides the size
// estimate, whatever the path's own extension.
//
// errors rank like the C: the walk goes on past an entry that fails, and
// any such entry makes the db invalid (the first one is returned), even
// when the archive breaks later; a broken archive with good entries so
// far is an archive error.
//
// logs through cb the C's lines of the walk; the open failures of
// _alpm_open_archive are not logged
pub fn populate(
	path: &[u8],
	dbext: &[u8],
	treename: &[u8],
	cb: &mut dyn Callbacks,
) -> Result<PkgHash<Package>, Error> {
	let path = until_nul(path);
	logv(cb, LogLevel::Debug, &[b"opening archive ", path, b"\n"]);
	let (archive, est) = open_archive(path, until_nul(dbext))?;
	let mut cache = PkgHash::new(est as u32).ok_or(Error::Memory)?;

	let mut walk = Walk {
		bufs: Bufs::default(),
		pkgs: Vec::new(),
		index: HashMap::new(),
		treename,
		cb,
	};
	let mut first_invalid = None;
	let mut broken = None;
	for entry in archive.entries() {
		let mut entry = match entry {
			Ok(e) => e,
			Err(e) => {
				broken = Some(e);
				break;
			}
		};
		if entry.mode() & S_IFMT == S_IFDIR {
			continue;
		}
		if let Err(reason) = walk.read_entry(&mut entry) {
			let entryname = entry.path_bytes().to_vec();
			let parts: [&[u8]; 5] = [
				b"could not parse package description file '",
				&entryname,
				b"' from db '",
				treename,
				b"'\n",
			];
			logv(walk.cb, LogLevel::Error, &parts);
			first_invalid
				.get_or_insert(invalid(&entryname, reason));
		}
	}
	if let Some(e) = first_invalid {
		return Err(e);
	}
	if let Some(e) = broken {
		let why = e.to_string();
		let parts: [&[u8]; 5] = [
			b"could not read db '",
			treename,
			b"' (",
			why.as_bytes(),
			b")\n",
		];
		logv(walk.cb, LogLevel::Error, &parts);
		return Err(Error::Archive(e));
	}
	// _alpm_pkghash_add in archive order then alpm_list_msort by name:
	// names are unique, so add_sorted gives the same buckets and list
	for pkg in walk.pkgs {
		cache.add_sorted(pkg).map_err(|p| {
			let name = p.name.as_deref().unwrap_or_default();
			invalid(name, Reason::Cache)
		})?;
	}
	let count = cache.len().to_string();
	let parts: [&[u8]; 5] = [
		b"added ",
		count.as_bytes(),
		b" packages to package cache for db '",
		treename,
		b"'\n",
	];
	logv(walk.cb, LogLevel::Debug, &parts);
	Ok(cache)
}
