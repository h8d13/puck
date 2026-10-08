// port of lib/libalpm/be_sync.c, reading side: sync_db_populate,
// sync_db_read, load_pkg_for_entry, _sync_get_validation, and the sync
// branch of db.c's _alpm_db_path.
//
// the tar walk and the entry reader follow the C: _alpm_archive_fgets
// over the entry's data blocks as libarchive cuts them, the READ_*
// macros, keys matched as C strings. libarchive is replaced by
// alpm-compress (gzip, bzip2, xz, zstd, none) picked by magic bytes, as
// the db file name carries no compression suffix.
//
// sync_db_validate without the status bits db.c keeps: the missing file
// and the signature check (signing.rs). alpm_db_update with get_sync_dir:
// downloads through dload.rs, validation through Db::validate. populate
// on a db file that does not exist is NotFound.

use std::collections::HashMap;
use std::ffi::{OsStr, c_int};
use std::fs;
use std::io::{self, ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use alpm_compress::decompression::DecompressionSettings;
use rustix::fs::{Access, AtFlags, CWD, accessat};

use crate::callbacks::{Callbacks, Event, LogLevel, logv};
use crate::db::{DB_USAGE_SYNC, Db};
use crate::deps::dep_from_string;
use crate::dload::{
	Downloader, Payload, Settings, remove_temporary_download_dir,
};
use crate::error::Errno;
use crate::filelist::{File as PkgFile, FileList};
use crate::handle::{Handle, SyncParts};
use crate::package::{
	PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM,
	PKG_VALIDATION_SIGNATURE, Package, PkgFrom, check_meta, parse_xdata,
};
use crate::pkghash::PkgHash;
use crate::signing::{
	Keyring, SIG_DATABASE, SIG_DATABASE_MARGINAL_OK, SIG_DATABASE_OPTIONAL,
	SIG_DATABASE_UNKNOWN_OK, check_pgp_helper, process_siglist,
};
use crate::util::{
	self, Entry, Filter, PATH_MAX, get_fullpath, hash_sdbm, makepath,
	parsedate, splitname, strerror, strtoofft, until_nul,
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
	let nofollow = AtFlags::SYMLINK_NOFOLLOW;
	if let Err(e) = accessat(CWD, path, Access::READ_OK, nofollow) {
		let why = strerror(&io::Error::from_raw_os_error(
			e.raw_os_error(),
		));
		let msg = [b"\"", path, b"\" is not readable: ", &why, b"\n"];
		cb.log(LogLevel::Debug, &msg.concat());
		if e == rustix::io::Errno::NOENT {
			return Ok(false);
		}
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
		// sandbox.c plugs in here (_alpm_use_sandbox: root, a sandbox
		// user, a restriction enabled), like for fetch_pkgurl
		sandbox: None,
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
// the C leaves pm_errno as it was. the C's umask(0022) for the call is
// left out (rustix "process"), files get the process umask
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

// estimate_package_count's bytes per package for the filter libarchive
// detects. zstd has no case there and takes the default
fn bytes_per_package(settings: &DecompressionSettings) -> u64 {
	match settings {
		DecompressionSettings::Gzip => 464,
		DecompressionSettings::Bzip2 => 394,
		DecompressionSettings::Xz => 400,
		DecompressionSettings::Zstd => 500,
		DecompressionSettings::None => 3015,
	}
}

// _alpm_open_archive plus estimate_package_count, and the data block
// size of the entries
fn open_archive(
	path: &[u8],
	dbext: &[u8],
) -> Result<(tar::Archive<Filter>, u64, u64), Error> {
	let archive = util::open_archive(path).map_err(|e| match e.kind() {
		ErrorKind::NotFound => Error::NotFound,
		_ => Error::Open(e),
	})?;
	let size = archive.meta.len();
	let mut est = size / bytes_per_package(&archive.settings) + 1;
	// files dbs are about four times larger on average
	if dbext == b".files" {
		est /= 4;
	}
	Ok((archive.reader, est, archive.block))
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

// "512K for a line length seems reasonable"
const MAX_LINE_SIZE: usize = 512 * 1024;
// errno.h
const ERANGE: i32 = 34;

// archive_read_data_block on an entry: its data in pieces ending at the
// multiples of block in the tar stream (util::Archive::block), then
// ARCHIVE_EOF (None). a short read is libarchive's truncated archive
struct Blocks<'e, 'a> {
	entry: &'e mut Entry<'a>,
	// tar stream offset of the next byte, bytes of the entry left
	pos: u64,
	left: u64,
	block: u64,
}

impl Blocks<'_, '_> {
	fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
		if self.left == 0 {
			return Ok(None);
		}
		let n = (self.block - self.pos % self.block).min(self.left);
		let mut data = Vec::with_capacity(n as usize);
		(&mut *self.entry).take(n).read_to_end(&mut data)?;
		if data.len() as u64 != n {
			return Err(ErrorKind::UnexpectedEof.into());
		}
		self.pos += n;
		self.left -= n;
		Ok(Some(data))
	}
}

// struct archive_read_buffer and _alpm_archive_fgets over one entry
struct ArchiveLines<'e, 'a> {
	blocks: Blocks<'e, 'a>,
	// the current data block, block[off..] not consumed yet
	block: Vec<u8>,
	off: usize,
	// b->ret == ARCHIVE_EOF: the last block read was the end
	eof: bool,
	// b->line allocated: sized to the first block, unchecked
	allocated: bool,
	// b->line up to real_line_size: nul bytes included, no '\n'
	line: Vec<u8>,
}

impl<'e, 'a> ArchiveLines<'e, 'a> {
	fn new(entry: &'e mut Entry<'a>, block: u64) -> Self {
		let blocks = Blocks {
			pos: entry.raw_file_position(),
			left: entry.size(),
			entry,
			block,
		};
		ArchiveLines {
			blocks,
			block: Vec::new(),
			off: 0,
			eof: false,
			allocated: false,
			line: Vec::new(),
		}
	}

	// Ok(true) ARCHIVE_OK with a line, Ok(false) ARCHIVE_EOF, Err a
	// failed block read or a line over MAX_LINE_SIZE (-ERANGE). a line
	// ends at the first '\n' of what is left of a block, or at its
	// first nul when it has no '\n'; one without either goes on in the
	// next block. after a final '\n' an empty line comes before the
	// end. the size check skips the block the buffer is first sized
	// for
	fn fgets(&mut self) -> io::Result<bool> {
		self.line.clear();
		loop {
			if self.off == self.block.len() {
				if self.eof {
					return Ok(false);
				}
				match self.blocks.next()? {
					Some(b) => self.block = b,
					None => {
						self.eof = true;
						self.block.clear();
					}
				}
				self.off = 0;
			}
			let rest = &self.block[self.off..];
			let eol = rest
				.iter()
				.position(|&c| c == b'\n')
				.or_else(|| rest.iter().position(|&c| c == 0));
			let needed =
				self.line.len() + eol.unwrap_or(rest.len()) + 1;
			if self.allocated && needed > MAX_LINE_SIZE {
				return Err(io::Error::from_raw_os_error(
					ERANGE,
				));
			}
			self.allocated = true;
			if let Some(i) = eol {
				self.line.extend_from_slice(&rest[..i]);
				self.off += i + 1;
				return Ok(true);
			}
			let len = rest.len();
			self.line.extend_from_slice(rest);
			self.off = self.block.len();
			if len == 0 {
				return Ok(true);
			}
		}
	}

	// the line as a C string. _alpm_strip_newline(line,
	// real_line_size) is 0 exactly when this is empty
	fn cstr(&self) -> &[u8] {
		until_nul(&self.line)
	}

	// READ_NEXT, READ_AND_STORE: the end of the data fails too
	fn next(&mut self) -> Result<&[u8], Reason> {
		match self.fgets() {
			Ok(true) => Ok(self.cstr()),
			Ok(false) => Err(Reason::Truncated),
			Err(e) => Err(Reason::Read(e)),
		}
	}

	fn store(&mut self) -> Result<Option<Vec<u8>>, Reason> {
		Ok(Some(self.next()?.to_vec()))
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
}

fn line_vec(s: &[u8]) -> Vec<u8> {
	s.to_vec()
}

// _alpm_strtoofft: -1 for anything but bare digits, the unsigned long
// long cast to off_t wraps past i64::MAX
fn off_t(s: &[u8]) -> i64 {
	strtoofft(s).map_or(-1, |v| v as i64)
}

// the walk state of sync_db_populate. index replaces the lookups in
// db->pkgcache and likely_pkg: both find the one package of that name
struct Walk<'a> {
	pkgs: Vec<Package>,
	index: HashMap<Vec<u8>, usize>,
	// db->treename and handle->logcb
	treename: &'a [u8],
	cb: &'a mut dyn Callbacks,
	// util::Archive::block
	block: u64,
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
			name: Some(name.to_vec()),
			version: Some(version.to_vec()),
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
		let mut lines = ArchiveLines::new(entry, self.block);
		let r = self.read_data(i, &mut lines);
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
	fn read_data(
		&mut self,
		i: usize,
		f: &mut ArchiveLines,
	) -> Result<(), Reason> {
		let deps = dep_from_string;
		loop {
			match f.fgets() {
				Ok(true) => {}
				Ok(false) => return Ok(()),
				Err(e) => return Err(Reason::Read(e)),
			}
			let key = f.cstr().to_vec();
			if key.is_empty() {
				continue;
			}
			let name = self.pkgs[i].name_bytes().to_vec();
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
					f.list(&mut pkg.groups, line_vec)?
				}
				b"%URL%" => pkg.url = f.store()?,
				b"%LICENSE%" => {
					f.list(&mut pkg.licenses, line_vec)?
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
					f.list(&mut pkg.replaces, deps)?
				}
				b"%DEPENDS%" => {
					f.list(&mut pkg.depends, deps)?
				}
				b"%OPTDEPENDS%" => {
					f.list(&mut pkg.optdepends, deps)?
				}
				b"%MAKEDEPENDS%" => {
					f.list(&mut pkg.makedepends, deps)?
				}
				b"%CHECKDEPENDS%" => {
					f.list(&mut pkg.checkdepends, deps)?
				}
				b"%CONFLICTS%" => {
					f.list(&mut pkg.conflicts, deps)?
				}
				b"%PROVIDES%" => {
					f.list(&mut pkg.provides, deps)?
				}
				// sorted with _alpm_filelist_sort
				b"%FILES%" => {
					let mut files = Vec::new();
					f.list(&mut files, |l| PkgFile {
						name: l.to_vec(),
						..PkgFile::default()
					})?;
					pkg.files = FileList { files };
					pkg.files.sort();
				}
				b"%DATA%" => {
					let mut lines = Vec::new();
					f.list(&mut lines, line_vec)?;
					// entries before a bad line stay
					for l in lines {
						let x = parse_xdata(&l).ok_or(
							Reason::XData(l),
						)?;
						pkg.xdata.push(x);
					}
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
// logs through cb the C's lines of the walk; the archive error line
// carries the port's text where the C has libarchive's, the open
// failures of _alpm_open_archive are not logged
pub fn populate(
	path: &[u8],
	dbext: &[u8],
	treename: &[u8],
	cb: &mut dyn Callbacks,
) -> Result<PkgHash<Package>, Error> {
	let path = until_nul(path);
	logv(cb, LogLevel::Debug, &[b"opening archive ", path, b"\n"]);
	let (mut archive, est, block) = open_archive(path, until_nul(dbext))?;
	let mut cache = PkgHash::new(est as u32).ok_or(Error::Memory)?;

	let mut walk = Walk {
		pkgs: Vec::new(),
		index: HashMap::new(),
		treename,
		cb,
		block,
	};
	let mut first_invalid = None;
	let mut broken = None;
	let entries = archive.entries().map_err(Error::Archive)?;
	for (i, entry) in entries.enumerate() {
		let mut entry = match entry {
			Ok(e) => e,
			// libarchive picks the format while opening: a first header
			// no reader takes is an open failure, like be_package
			Err(e) if i == 0 => return Err(Error::Open(e)),
			Err(e) => {
				broken = Some(e);
				break;
			}
		};
		// libarchive types a regular entry ending in '/' a directory
		let is_dir = entry.header().entry_type().is_dir();
		if is_dir || entry.path_bytes().last() == Some(&b'/') {
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
		let name = pkg.name.clone().unwrap_or_default();
		cache.add_sorted(pkg)
			.map_err(|_| invalid(&name, Reason::Cache))?;
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
