// port of lib/libalpm/be_sync.c, reading side: sync_db_populate,
// sync_db_read, load_pkg_for_entry, _sync_get_validation, and the sync
// branch of db.c's _alpm_db_path.
//
// the tar walk follows the C, the entry contents do not: desc/depends go
// through alpm-repo-db's libalpm-compatible desc reader and files through
// its files reader, in place of _alpm_archive_fgets and the READ_AND_STORE
// macros. the typed values still differ, see PORTING.md. libarchive is
// replaced by alpm-compress (gzip, bzip2, xz, zstd, none) picked by magic
// bytes, as the db file name carries no compression suffix.
//
// sync_db_validate without the status bits db.c keeps: the missing file
// and the signature check (signing.rs). alpm_db_update with get_sync_dir:
// downloads through dload.rs, validation through Db::validate. populate
// on a db file that does not exist is NotFound.

use std::collections::HashMap;
use std::ffi::{OsStr, c_int};
use std::fmt::Display;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Seek};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use alpm_compress::decompression::{CompressionDecoder, DecompressionSettings};
use alpm_compress::tarball::{TarballEntry, TarballReader};
use alpm_repo_db::desc::{Section, parse_libalpm};
use alpm_repo_db::files::RepoFiles;
use rustix::fs::{Access, AtFlags, CWD, accessat};

use crate::callbacks::{Callbacks, Event, LogLevel};
use crate::db::{DB_USAGE_SYNC, Db};
use crate::deps::{Depend, dep_from_string};
use crate::dload::{
	Downloader, Payload, Settings, remove_temporary_download_dir,
};
use crate::error::Errno;
use crate::filelist::{File as PkgFile, FileList};
use crate::handle::{Handle, SyncParts};
use crate::package::{
	PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM,
	PKG_VALIDATION_SIGNATURE, Package, PkgFrom, PkgXData,
};
use crate::pkghash::PkgHash;
use crate::signing::{
	Keyring, SIG_DATABASE, SIG_DATABASE_MARGINAL_OK, SIG_DATABASE_OPTIONAL,
	SIG_DATABASE_UNKNOWN_OK, check_pgp_helper, process_siglist,
};
use crate::util::{
	PATH_MAX, fnmatch, get_fullpath, hash_sdbm, makepath, splitname,
	strerror, until_nul,
};

// limits.h on linux
const NAME_MAX: usize = 255;
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
	// entry data could not be read
	Read(io::Error),
	// alpm-repo-db parses str, the C reads bytes
	Utf8,
	Desc(alpm_repo_db::Error),
	Files(alpm_repo_db::files::Error),
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
		db.free_pkgcache();
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

// _alpm_open_archive plus estimate_package_count
fn open_archive(
	path: &[u8],
	dbext: &[u8],
) -> Result<(TarballReader<'static>, u64), Error> {
	let path = std::path::Path::new(std::ffi::OsStr::from_bytes(path));
	let mut file = File::open(path).map_err(|e| match e.kind() {
		ErrorKind::NotFound => Error::NotFound,
		_ => Error::Open(e),
	})?;
	let size = file.metadata().map_err(Error::Open)?.len();
	let mut magic = Vec::with_capacity(DecompressionSettings::MAGIC_LEN);
	(&mut file)
		.take(DecompressionSettings::MAGIC_LEN as u64)
		.read_to_end(&mut magic)
		.map_err(Error::Open)?;
	file.rewind().map_err(Error::Open)?;
	let settings = DecompressionSettings::from_magic(&magic);
	let per_package = bytes_per_package(&settings);
	let decoder = CompressionDecoder::new(file, settings)
		.map_err(|e| Error::Open(io::Error::other(e)))?;
	let mut est = size / per_package + 1;
	// files dbs are about four times larger on average
	if dbext == b".files" {
		est /= 4;
	}
	Ok((TarballReader::new(decoder), est))
}

// _alpm_pkg_check_meta on what load_pkg_for_entry sets. splitname already
// rules out the version checks ('-' twice, '/'). fnmatch arguments in the
// C's order: the name is the pattern
fn check_meta(name: &[u8], version: &[u8]) -> bool {
	!(name.is_empty()
		|| version.is_empty()
		|| matches!(name[0], b'-' | b'.')
		|| fnmatch(name, b"[![:alnum:]+_.@-]")
		|| name.len() + version.len() + 1 > NAME_MAX)
}

// _alpm_validate_filename
fn validate_filename(filename: &[u8]) -> bool {
	filename.first() != Some(&b'.')
		&& !filename.contains(&b'/')
		&& filename.len() <= PATH_MAX
}

// a package being collected: entry texts are parsed once the walk is done,
// desc and depends of the old split format as one desc
struct Loading {
	pkg: Package,
	// "name-version/", for error reports
	dir: Vec<u8>,
	desc: Option<Vec<u8>>,
	files: Option<Vec<u8>>,
}

// the walk state of sync_db_populate. index replaces the lookups in
// db->pkgcache and likely_pkg: both find the one package of that name
#[derive(Default)]
struct Walk {
	pkgs: Vec<Loading>,
	index: HashMap<Vec<u8>, usize>,
}

fn invalid(entry: &[u8], reason: Reason) -> Error {
	Error::Invalid {
		entry: entry.to_vec(),
		reason,
	}
}

impl Walk {
	// load_pkg_for_entry: the package named by the entry, created on
	// first sight with name and version from the entry name
	fn pkg_for_entry(&mut self, entryname: &[u8]) -> Result<usize, Error> {
		let (name, version) = splitname(entryname)
			.ok_or_else(|| invalid(entryname, Reason::Name))?;
		if let Some(&i) = self.index.get(name) {
			return Ok(i);
		}
		if !check_meta(name, version) {
			return Err(invalid(entryname, Reason::Meta));
		}
		let pkg = Package {
			name_hash: hash_sdbm(name),
			name: Some(name.to_vec()),
			version: Some(version.to_vec()),
			origin: Some(PkgFrom::SyncDb),
			..Package::default()
		};
		self.index.insert(name.to_vec(), self.pkgs.len());
		self.pkgs.push(Loading {
			pkg,
			dir: [name, b"-", version, b"/"].concat(),
			desc: None,
			files: None,
		});
		Ok(self.pkgs.len() - 1)
	}

	// sync_db_read up to the parsing of the entry data
	fn read_entry(
		&mut self,
		entry: &mut TarballEntry,
	) -> Result<(), Error> {
		let entryname = entry.path().as_os_str().as_bytes().to_vec();
		let i = self.pkg_for_entry(&entryname)?;
		// strrchr: the last '/', where splitname cut at the first
		let Some(slash) = entryname.iter().rposition(|&c| c == b'/')
		else {
			// a file outside a directory: warned, package kept
			return Ok(());
		};
		let loading = &mut self.pkgs[i];
		let text = match &entryname[slash + 1..] {
			b"desc" | b"depends" => &mut loading.desc,
			b"files" => &mut loading.files,
			// unknown database file, skipped
			_ => return Ok(()),
		};
		let data = entry.content().map_err(|e| {
			invalid(&entryname, Reason::Read(io_err(e)))
		})?;
		let text = text.get_or_insert_with(Vec::new);
		// the C reads each entry on its own: a blank line ends whatever
		// section the previous entry left open
		if !text.is_empty() {
			if text.last() != Some(&b'\n') {
				text.push(b'\n');
			}
			text.push(b'\n');
		}
		text.extend_from_slice(&data);
		Ok(())
	}
}

fn io_err(e: alpm_compress::Error) -> io::Error {
	match e {
		alpm_compress::Error::IoRead { source, .. } => source,
		e => io::Error::other(e),
	}
}

fn text<T: Display>(v: &T) -> Vec<u8> {
	v.to_string().into_bytes()
}

fn texts<T: Display>(v: &[T]) -> Vec<Vec<u8>> {
	v.iter().map(text).collect()
}

// relations are printed by alpm-types and read back like the C reads its
// lines, through alpm_dep_from_string
fn deps<T: Display>(v: &[T]) -> Vec<Depend> {
	v.iter().map(|d| dep_from_string(&text(d))).collect()
}

// off_t of _alpm_strtoofft: -1 past its range
fn off_t(v: u64) -> i64 {
	i64::try_from(v).unwrap_or(-1)
}

fn utf8(data: &[u8]) -> Result<&str, Reason> {
	std::str::from_utf8(data).map_err(|_| Reason::Utf8)
}

// what sync_db_read stores from a desc, key by key: a repeated value
// overwrites, a repeated list appends, a missing section leaves the field
// unset
fn fill_desc(pkg: &mut Package, data: &[u8]) -> Result<(), Reason> {
	let desc = parse_libalpm(utf8(data)?).map_err(Reason::Desc)?;
	desc.into_iter().try_for_each(|s| fill_section(pkg, s))
}

fn fill_section(pkg: &mut Package, section: Section) -> Result<(), Reason> {
	match section {
		// only compared with the entry name by the C (logged, never
		// stored); %MD5SUM% is skipped
		Section::Name(_) | Section::Version(_) | Section::Md5Sum(_) => {
		}
		Section::Filename(v) => {
			let filename = text(&v);
			if !validate_filename(&filename) {
				return Err(Reason::Filename);
			}
			pkg.filename = Some(filename);
		}
		Section::Base(v) => pkg.base = Some(text(&v)),
		// description and url as read, alpm-types normalizes Display
		Section::Desc(v) => pkg.desc = Some(text(&v.as_original_str())),
		Section::Groups(v) => pkg.groups.extend(texts(&v)),
		// an empty value is alpm-repo-db's None
		Section::Url(v) => {
			pkg.url = Some(v
				.map(|u| text(&u.as_original_str()))
				.unwrap_or_default())
		}
		Section::License(v) => pkg.licenses.extend(texts(&v)),
		Section::Arch(v) => pkg.arch = Some(text(&v)),
		Section::BuildDate(v) => pkg.builddate = v,
		Section::Packager(v) => pkg.packager = Some(text(&v)),
		Section::CSize(v) => pkg.size = off_t(v),
		Section::ISize(v) => pkg.isize = off_t(v),
		Section::Sha256Sum(v) => pkg.sha256sum = Some(text(&v)),
		Section::PgpSig(v) => pkg.base64_sig = Some(text(&v)),
		Section::Replaces(v) => pkg.replaces.extend(deps(&v)),
		Section::Depends(v) => pkg.depends.extend(deps(&v)),
		Section::OptDepends(v) => pkg.optdepends.extend(deps(&v)),
		Section::MakeDepends(v) => pkg.makedepends.extend(deps(&v)),
		Section::CheckDepends(v) => pkg.checkdepends.extend(deps(&v)),
		Section::Conflicts(v) => pkg.conflicts.extend(deps(&v)),
		Section::Provides(v) => pkg.provides.extend(deps(&v)),
		Section::Data(v) => {
			pkg.xdata.extend(v.iter().map(|x| PkgXData {
				name: x.key().as_bytes().to_vec(),
				value: x.value().as_bytes().to_vec(),
			}))
		}
	}
	Ok(())
}

// %FILES%, sorted with _alpm_filelist_sort like the C
fn fill_files(pkg: &mut Package, data: &[u8]) -> Result<(), Reason> {
	let files = RepoFiles::from_str_libalpm(utf8(data)?)
		.map_err(Reason::Files)?;
	let files = files.as_ref().iter().map(|p| PkgFile {
		name: p.as_os_str().as_bytes().to_vec(),
		..PkgFile::default()
	});
	pkg.files = FileList {
		files: files.collect(),
	};
	pkg.files.sort();
	Ok(())
}

fn finish(l: Loading) -> Result<Package, Error> {
	let Loading {
		mut pkg,
		dir,
		desc,
		files,
	} = l;
	let entry = |file: &[u8]| [&dir[..], file].concat();
	if let Some(d) = desc {
		fill_desc(&mut pkg, &d)
			.map_err(|r| invalid(&entry(b"desc"), r))?;
	}
	if let Some(f) = files {
		fill_files(&mut pkg, &f)
			.map_err(|r| invalid(&entry(b"files"), r))?;
	}
	Ok(pkg)
}

// sync_db_populate: the package cache of the db file at path (its
// _alpm_db_path), list sorted by name, buckets filled in archive order.
// dbext is handle->dbext at load time: ".files" divides the size
// estimate, whatever the path's own extension.
//
// errors rank like the C: an entry that fails makes the db invalid even
// when the archive breaks later, a broken archive with good entries so
// far is an archive error
pub fn populate(path: &[u8], dbext: &[u8]) -> Result<PkgHash<Package>, Error> {
	let path = until_nul(path);
	let (mut archive, est) = open_archive(path, until_nul(dbext))?;
	let mut cache = PkgHash::new(est as u32).ok_or(Error::Memory)?;

	let mut walk = Walk::default();
	let mut broken = None;
	let entries =
		archive.entries().map_err(|e| Error::Archive(io_err(e)))?;
	for (i, entry) in entries.enumerate() {
		let mut entry = match entry {
			Ok(e) => e,
			// libarchive picks the format while opening: a first header
			// no reader takes is an open failure, like be_package
			Err(e) if i == 0 => return Err(Error::Open(io_err(e))),
			Err(e) => {
				broken = Some(io_err(e));
				break;
			}
		};
		// libarchive types a regular entry ending in '/' a directory
		let name = entry.path().as_os_str().as_bytes();
		if entry.is_dir() || name.last() == Some(&b'/') {
			continue;
		}
		walk.read_entry(&mut entry)?;
	}

	let pkgs: Vec<Package> = walk
		.pkgs
		.into_iter()
		.map(finish)
		.collect::<Result<_, _>>()?;
	if let Some(e) = broken {
		return Err(Error::Archive(e));
	}
	// _alpm_pkghash_add in archive order then alpm_list_msort by name:
	// names are unique, so add_sorted gives the same buckets and list
	for pkg in pkgs {
		let name = pkg.name.clone().unwrap_or_default();
		cache.add_sorted(pkg)
			.map_err(|_| invalid(&name, Reason::Cache))?;
	}
	Ok(cache)
}
