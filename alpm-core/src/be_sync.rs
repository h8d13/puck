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
// and the signature check (signing.rs). not ported: alpm_db_update
// (dload), get_sync_dir. populate on a db file that does not exist is
// NotFound.

use std::collections::HashMap;
use std::ffi::c_int;
use std::fmt::Display;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Seek};
use std::os::unix::ffi::OsStrExt;

use alpm_compress::decompression::{CompressionDecoder, DecompressionSettings};
use alpm_compress::tarball::{TarballEntry, TarballReader};
use alpm_repo_db::desc::{Section, parse_libalpm};
use alpm_repo_db::files::RepoFiles;
use rustix::fs::{Access, AtFlags, CWD, accessat};

use crate::deps::{Depend, dep_from_string};
use crate::error::Errno;
use crate::filelist::{File as PkgFile, FileList};
use crate::package::{
	PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM,
	PKG_VALIDATION_SIGNATURE, Package, PkgFrom, PkgXData,
};
use crate::pkghash::PkgHash;
use crate::signing::{
	Keyring, SIG_DATABASE, SIG_DATABASE_MARGINAL_OK, SIG_DATABASE_OPTIONAL,
	SIG_DATABASE_UNKNOWN_OK, SigCallbacks, check_pgp_helper,
	process_siglist,
};
use crate::util::{fnmatch, hash_sdbm, splitname, until_nul};

// limits.h on linux
const NAME_MAX: usize = 255;
const PATH_MAX: usize = 4096;

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
	cb: &mut dyn SigCallbacks,
	path: &[u8],
	treename: &[u8],
	siglevel: c_int,
) -> Result<bool, Errno> {
	let path = until_nul(path);
	// _alpm_access(R_OK) failing with ENOENT, a dangling link exists
	let nofollow = AtFlags::SYMLINK_NOFOLLOW;
	let access = accessat(CWD, path, Access::READ_OK, nofollow);
	if access == Err(rustix::io::Errno::NOENT) {
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
