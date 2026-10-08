// port of lib/libalpm/be_package.c: _alpm_pkg_load_internal with
// parse_descfile, alpm_pkg_load (with read_sigfile and the key import),
// _alpm_pkg_validate_internal, and the changelog ops of file packages.
// signatures go through signing.rs, the keyring and callbacks are taken
// as parameters until the handle carries them.
//
// the archive walk follows the C loop. libarchive is replaced by
// alpm-compress (gzip, bzip2, xz, zstd, none, picked by magic bytes like
// libarchive's filter bidding) and its tar reader; .MTREE goes through
// alpm-mtree's libarchive reader. .PKGINFO is read byte for byte like
// parse_descfile, through _alpm_archive_fgets over the entry's data
// blocks.
//
// file packages have no mtree stream: default_pkg_ops.mtree_open returns
// NULL, nothing to port. the load logs the C's lines through Callbacks
// except those carrying libarchive's error texts; the validation logs
// the signature messages only.

use std::ffi::{OsStr, c_int};
use std::fmt::Display;
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use alpm_mtree::libarchive::{self, EntryType};
use alpm_types::Sha256Checksum;
use rustix::fs::{Access, AtFlags, CWD, accessat};

use crate::backup::Backup;
use crate::be_local::{INFRQ_BASE, INFRQ_DESC, INFRQ_FILES, INFRQ_SCRIPTLET};
use crate::callbacks::{Callbacks, LogLevel};
use crate::deps::dep_from_string;
use crate::error::Errno;
use crate::filelist::{File as PkgFile, FileList};
use crate::package::{
	PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM,
	PKG_VALIDATION_SIGNATURE, Package, PkgFrom, parse_xdata,
};
use crate::signing::{
	Keyring, SIG_PACKAGE, SIG_PACKAGE_MARGINAL_OK, SIG_PACKAGE_OPTIONAL,
	SIG_PACKAGE_UNKNOWN_OK, SigResult, check_pgp_helper, extract_keyid,
	key_import, key_in_keychain, sigpath,
};
use crate::util::{
	self, ArchiveFgets, DataBlocks, Entry, fnmatch, hash_sdbm, parsedate,
	strtoofft, until_nul,
};

// limits.h on linux
const NAME_MAX: usize = 255;

// read_sigfile's limit, adopted from repo-add
const MAX_SIGFILE_SIZE: u64 = 16384;

// mode_t file type bits, archive_entry.h AE_IF*
const AE_IFMT: u32 = 0o170000;
const AE_IFREG: u32 = 0o100000;
const AE_IFLNK: u32 = 0o120000;
const AE_IFCHR: u32 = 0o020000;
const AE_IFBLK: u32 = 0o060000;
const AE_IFDIR: u32 = 0o040000;
const AE_IFIFO: u32 = 0o010000;

// why a package file was refused, the C's pkg_invalid label
#[derive(Debug)]
pub enum Reason {
	// parse_descfile's _alpm_archive_fgets failed: a data read error, or
	// a line of MAX_LINE_SIZE bytes or more (ERANGE)
	Read(io::Error),
	// an xdata value without '=', _alpm_pkg_parse_xdata's NULL
	Xdata,
	// "missing package name", "missing package version" or "invalid
	// package version": empty name, empty version or no '-' in it
	Version,
	// _alpm_pkg_check_meta
	Meta,
	// no .PKGINFO in the archive
	Missing,
}

#[derive(Debug)]
pub enum Error {
	// empty path, ALPM_ERR_WRONG_ARGS
	WrongArgs,
	// open failed with ENOENT, ALPM_ERR_PKG_NOT_FOUND
	NotFound,
	// open failed with EACCES, ALPM_ERR_BADPERMS
	BadPerms,
	// any other open/stat/format failure, ALPM_ERR_PKG_OPEN
	Open(io::Error),
	// ALPM_ERR_PKG_INVALID
	Invalid(Reason),
	// archive_read_next_header or data skip failed, ALPM_ERR_LIBARCHIVE
	Archive(io::Error),
	// sha256 of the file differs, ALPM_ERR_PKG_INVALID_CHECKSUM
	Checksum,
	// the level wants a signature and there is none,
	// ALPM_ERR_PKG_MISSING_SIG
	MissingSig,
	// _alpm_check_pgp_helper refused, ALPM_ERR_PKG_INVALID_SIG. the
	// results are what the C passes back in sigdata
	InvalidSig(Vec<SigResult>),
	// alpm_pkg_load: "failed to read signature file", pm_errno untouched
	SigFile,
	// alpm_pkg_load: "required key missing from keyring". pm_errno is
	// what the last failed _alpm_pkg_load_internal of the import loop
	// left, untouched when none failed
	KeyMissing(Option<Errno>),
}

impl Error {
	// pm_errno the C leaves, Ok where it is untouched (alpm_pkg_load's
	// CHECK_HANDLE resets it on entry)
	pub fn errno(&self) -> Errno {
		match self {
			Error::WrongArgs => Errno::WrongArgs,
			Error::NotFound => Errno::PkgNotFound,
			Error::BadPerms => Errno::Badperms,
			Error::Open(_) => Errno::PkgOpen,
			Error::Invalid(_) => Errno::PkgInvalid,
			Error::Archive(_) => Errno::Libarchive,
			Error::Checksum => Errno::PkgInvalidChecksum,
			Error::MissingSig => Errno::PkgMissingSig,
			Error::InvalidSig(_) => Errno::PkgInvalidSig,
			Error::SigFile => Errno::Ok,
			Error::KeyMissing(e) => e.unwrap_or(Errno::Ok),
		}
	}
}

fn os(path: &[u8]) -> &Path {
	Path::new(OsStr::from_bytes(path))
}

// errno mapping of _alpm_pkg_load_internal and _alpm_pkg_validate_internal
fn open_err(e: io::Error) -> Error {
	match e.kind() {
		ErrorKind::NotFound => Error::NotFound,
		ErrorKind::PermissionDenied => Error::BadPerms,
		_ => Error::Open(e),
	}
}

// _alpm_open_archive and the C's errno check after it: the reader,
// st_size and the data block size. a failed open(2) is logged with its
// strerror, a stream the decoder refuses with the decoder's text (the
// C: libarchive's)
fn open_archive(
	cb: &mut dyn Callbacks,
	path: &[u8],
) -> Result<(tar::Archive<util::Filter>, i64, u64), Error> {
	log(cb, LogLevel::Debug, &[b"opening archive ", path, b"\n"]);
	let archive = util::open_archive(path).map_err(|e| {
		let text = util::strerror(&e);
		let msg = [b"could not open file ", path, b": ", &text, b"\n"];
		log(cb, LogLevel::Error, &msg);
		open_err(e)
	})?;
	let block = archive.block_size();
	Ok((archive.reader, archive.meta.len() as i64, block))
}

fn log(cb: &mut dyn Callbacks, level: LogLevel, parts: &[&[u8]]) {
	cb.log(level, &parts.concat());
}

// _alpm_pkg_check_meta on a package with a name and a version (the load
// refuses others before, so its "name or version missing" bail is not
// reached). every failed check logs, fnmatch arguments in the C's order:
// the name is the pattern
fn check_meta(cb: &mut dyn Callbacks, name: &[u8], version: &[u8]) -> bool {
	let mut ok = true;
	let mut fail = |why: &[u8]| {
		let msg = [
			b"invalid metadata for package ",
			name,
			b"-",
			version,
			b" (",
			why,
			b")\n",
		];
		log(cb, LogLevel::Error, &msg);
		ok = false;
	};
	if matches!(name[0], b'-' | b'.') {
		fail(b"package name cannot start with '.' or '-'");
	}
	if fnmatch(name, b"[![:alnum:]+_.@-]") {
		fail(b"package name contains invalid characters");
	}
	let dashes = version.iter().filter(|&&c| c == b'-').count();
	if dashes > 1 {
		fail(b"package version contains invalid characters");
	}
	if version.contains(&b'/') {
		fail(b"package version contains invalid characters");
	}
	if name.len() + version.len() + 1 > NAME_MAX {
		fail(b"package name and version too long");
	}
	ok
}

fn text(v: &impl Display) -> Vec<u8> {
	v.to_string().into_bytes()
}

// one "key = value" line of parse_descfile. the key ends at the line's
// first space, which must start " = "; key and value are read as C
// strings, so a nul cuts them. single keys overwrite, list keys append
fn parse_line(
	cb: &mut dyn Callbacks,
	pkg: &mut Package,
	line: &[u8],
	linenum: c_int,
) -> Result<(), Reason> {
	let name = pkg.name.as_deref().map_or(&b"error"[..], until_nul);
	let num = linenum.to_string().into_bytes();
	let sep = line.iter().position(|&c| c == b' ');
	let Some(i) = sep.filter(|&i| line.get(i..i + 3) == Some(b" = "))
	else {
		let msg = [
			name,
			b": syntax error in description file line ",
			&num,
			b"\n",
		];
		log(cb, LogLevel::Debug, &msg);
		return Ok(());
	};
	let key = until_nul(&line[..i]);
	let v = until_nul(&line[i + 3..]);
	match key {
		b"pkgname" => {
			pkg.name = Some(v.to_vec());
			pkg.name_hash = hash_sdbm(v);
		}
		b"pkgbase" => pkg.base = Some(v.to_vec()),
		b"pkgver" => pkg.version = Some(v.to_vec()),
		// not used atm
		b"basever" => {}
		b"pkgdesc" => pkg.desc = Some(v.to_vec()),
		b"group" => pkg.groups.push(v.to_vec()),
		b"url" => pkg.url = Some(v.to_vec()),
		b"license" => pkg.licenses.push(v.to_vec()),
		// 0 when not a whole number
		b"builddate" => pkg.builddate = parsedate(v).unwrap_or(0),
		b"packager" => pkg.packager = Some(v.to_vec()),
		b"arch" => pkg.arch = Some(v.to_vec()),
		// off_t: -1 when not bare digits, past i64::MAX the unsigned
		// value wraps (gcc's conversion)
		b"size" => pkg.isize = strtoofft(v).map_or(-1, |n| n as i64),
		b"depend" => pkg.depends.push(dep_from_string(v)),
		b"optdepend" => pkg.optdepends.push(dep_from_string(v)),
		b"makedepend" => pkg.makedepends.push(dep_from_string(v)),
		b"checkdepend" => pkg.checkdepends.push(dep_from_string(v)),
		b"conflict" => pkg.conflicts.push(dep_from_string(v)),
		b"replaces" => pkg.replaces.push(dep_from_string(v)),
		b"provides" => pkg.provides.push(dep_from_string(v)),
		b"backup" => pkg.backup.push(Backup {
			name: v.to_vec(),
			hash: None,
		}),
		b"xdata" => {
			pkg.xdata.push(parse_xdata(v).ok_or(Reason::Xdata)?)
		}
		_ => {
			let what =
				[name, b": unknown key '", key, b"'"].concat();
			let msg = [&what[..], b" in package description\n"];
			log(cb, LogLevel::Warning, &msg);
			let msg = [
				&what[..],
				b" in description file line ",
				&num,
				b"\n",
			];
			log(cb, LogLevel::Debug, &msg);
		}
	}
	Ok(())
}

// parse_descfile: the .PKGINFO entry line by line into pkg. empty lines
// (a leading nul reads as one, _alpm_strip_newline) and '#' comments
// are skipped; line numbers count every line. a second .PKGINFO in the
// archive is read into the same package like in the C
fn parse_descfile(
	cb: &mut dyn Callbacks,
	pkg: &mut Package,
	entry: &mut Entry,
	block: u64,
) -> Result<(), Reason> {
	let mut lines = ArchiveFgets::new(DataBlocks::new(entry, block));
	let mut linenum: c_int = 0;
	loop {
		let line = match lines.next() {
			Ok(Some(line)) => line,
			Ok(None) => return Ok(()),
			Err(e) => {
				let msg = b"error parsing package descfile\n";
				cb.log(LogLevel::Debug, msg);
				return Err(Reason::Read(e));
			}
		};
		linenum = linenum.wrapping_add(1);
		if matches!(line.first(), None | Some(0 | b'#')) {
			continue;
		}
		parse_line(cb, pkg, line, linenum)?;
	}
}

// _alpm_pkg_load_internal's checks after parse_descfile, with their
// error lines
fn check_descfile(
	cb: &mut dyn Callbacks,
	pkg: &Package,
	file: &[u8],
) -> Result<(), Reason> {
	let version = pkg.version.as_deref().map(until_nul);
	let what: &[u8] = if pkg.name_bytes().is_empty() {
		b"missing package name in "
	} else if version.is_none_or(<[u8]>::is_empty) {
		b"missing package version in "
	} else if !version.unwrap_or_default().contains(&b'-') {
		b"invalid package version in "
	} else {
		return Ok(());
	};
	log(cb, LogLevel::Error, &[what, file, b"\n"]);
	Err(Reason::Version)
}

// handle_simple_path: .INSTALL marks the scriptlet, every other name
// starting with '.' is skipped
fn simple_path(pkg: &mut Package, path: &[u8]) -> bool {
	if path == b".INSTALL" {
		pkg.scriptlet = 1;
		return true;
	}
	path.first() == Some(&b'.')
}

// add_entry_to_files_list: directories get the trailing '/' other code
// relies on
fn push_file(files: &mut FileList, path: &[u8], mode: u32, size: i64) {
	let mut name = path.to_vec();
	if mode & AE_IFMT == AE_IFDIR && name.last() != Some(&b'/') {
		name.push(b'/');
	}
	files.files.push(PkgFile { name, size, mode });
}

// archive_entry_mode and archive_entry_size of a tar entry the way
// libarchive's tar reader sets them: the type from the type flag over the
// header's permission bits. a hard link has no type bits and size 0
pub(crate) fn tar_mode_size(entry: &Entry) -> io::Result<(u32, i64)> {
	let header = entry.header();
	let perm = header.mode()? & !AE_IFMT;
	let size = entry.size() as i64;
	let name = entry.path_bytes();
	// the header's type flag byte, as libarchive's tar reader sees it
	let (kind, size) = match header.entry_type().as_byte() {
		b'5' => (AE_IFDIR, size),
		b'1' => (0, 0),
		b'2' => (AE_IFLNK, 0),
		b'3' => (AE_IFCHR, 0),
		b'4' => (AE_IFBLK, 0),
		b'6' => (AE_IFIFO, 0),
		// a regular entry named with a trailing '/' is a directory
		_ if name.last() == Some(&b'/') => (AE_IFDIR, 0),
		_ => (AE_IFREG, size),
	};
	Ok((kind | perm, size))
}

// an entry of libarchive's mtree reader: "./" stripped like
// build_filelist_from_mtree does, archive_entry_mode and _size
fn mtree_file(e: &libarchive::Entry) -> (Vec<u8>, u32, i64) {
	let kind = match e.entry_type {
		EntryType::Block => AE_IFBLK,
		EntryType::Char => AE_IFCHR,
		EntryType::Dir => AE_IFDIR,
		EntryType::Fifo => AE_IFIFO,
		EntryType::File => AE_IFREG,
		EntryType::Link => AE_IFLNK,
	};
	let path = e.path.as_os_str().as_bytes();
	let path = path.strip_prefix(b"./").unwrap_or(path);
	(path.to_vec(), kind | e.mode, e.size)
}

// build_filelist_from_mtree: the whole list or nothing, the C keeps the
// archive's list on failure, which includes an entry libarchive warns
// about. a "./.INSTALL" line marks the scriptlet
fn filelist_from_mtree(
	pkg: &mut Package,
	entry: &mut Entry,
) -> Option<FileList> {
	let data = util::content(entry).ok()?;
	let entries = libarchive::from_reader(&data[..]).ok()?;
	if entries.iter().any(|e| !e.warnings.is_empty()) {
		return None;
	}
	let mut files = FileList::default();
	for e in &entries {
		let (path, mode, size) = mtree_file(e);
		if !simple_path(pkg, &path) {
			push_file(&mut files, &path, mode, size);
		}
	}
	Some(files)
}

// _alpm_pkg_load_internal: the package of the archive at pkgfile. full
// reads every entry for the file list, otherwise the walk stops after
// the metadata
pub fn pkg_load_internal(
	cb: &mut dyn Callbacks,
	pkgfile: &[u8],
	full: bool,
) -> Result<Package, Error> {
	let pkgfile = until_nul(pkgfile);
	if pkgfile.is_empty() {
		return Err(Error::WrongArgs);
	}
	let (mut archive, size, block) = open_archive(cb, pkgfile)?;
	let mut entries = archive.entries().map_err(Error::Open)?;
	// libarchive picks the format while opening: a first header no
	// reader takes is _alpm_open_archive's failure, logged with the
	// reader's text
	let first = entries.next().transpose().map_err(|e| {
		let text = e.to_string();
		let msg = [
			b"could not open file ",
			pkgfile,
			b": ",
			text.as_bytes(),
			b"\n",
		];
		log(cb, LogLevel::Error, &msg);
		Error::Open(e)
	})?;
	let msg = [b"starting package load for ", pkgfile, b"\n"];
	log(cb, LogLevel::Debug, &msg);
	let mut pkg = Package {
		filename: Some(pkgfile.to_vec()),
		size,
		..Package::default()
	};
	let (mut config, mut hit_mtree) = (false, false);

	for entry in first.map(Ok).into_iter().chain(entries) {
		let mut entry = entry.map_err(Error::Archive)?;
		let name = entry.path_bytes().to_vec();
		// the .PKGINFO and .MTREE branches continue before the break
		// check below, so the walk always goes one entry further
		if name == b".PKGINFO" {
			let parsed =
				parse_descfile(cb, &mut pkg, &mut entry, block);
			if let Err(why) = parsed {
				let msg = [
					b"could not parse package description file in ",
					pkgfile,
					b"\n",
				];
				log(cb, LogLevel::Error, &msg);
				return Err(Error::Invalid(why));
			}
			check_descfile(cb, &pkg, pkgfile)
				.map_err(Error::Invalid)?;
			config = true;
			continue;
		} else if full && name == b".MTREE" {
			let msg = [b"found mtree for package ", pkgfile];
			let msg = [&msg.concat()[..], b", getting file list\n"];
			log(cb, LogLevel::Debug, &msg);
			let files = filelist_from_mtree(&mut pkg, &mut entry);
			if files.is_some() {
				let msg = [
					b"finished mtree reading for ",
					pkgfile,
				];
				log(
					cb,
					LogLevel::Debug,
					&[&msg.concat(), b"\n"],
				);
			}
			hit_mtree = files.is_some();
			if let Some(files) = files {
				pkg.files = files;
			}
			continue;
		} else if simple_path(&mut pkg, &name) {
			continue;
		} else if full && !hit_mtree {
			let (mode, size) = tar_mode_size(&entry)
				.map_err(Error::Archive)?;
			push_file(&mut pkg.files, &name, mode, size);
		}
		// archive_read_data_skip reads through the data
		io::copy(&mut entry, &mut io::sink())
			.map_err(Error::Archive)?;
		if (!full || hit_mtree) && config {
			break;
		}
	}

	if !config {
		let msg = [b"missing package metadata in ", pkgfile, b"\n"];
		log(cb, LogLevel::Error, &msg);
		return Err(Error::Invalid(Reason::Missing));
	}
	pkg.origin = Some(PkgFrom::File(pkgfile.to_vec()));
	pkg.infolevel = INFRQ_BASE | INFRQ_DESC | INFRQ_SCRIPTLET;
	pkg.validation = PKG_VALIDATION_NONE;
	if full {
		// "checking for conflicts" needs the list sorted
		if !pkg.files.files.is_empty() {
			let msg = [b"sorting package filelist for ", pkgfile];
			log(cb, LogLevel::Debug, &[&msg.concat(), b"\n"]);
		}
		pkg.files.sort();
		pkg.infolevel |= INFRQ_FILES;
	}
	let version = pkg.version.as_deref().unwrap_or_default();
	if !check_meta(cb, pkg.name_bytes(), until_nul(version)) {
		return Err(Error::Invalid(Reason::Meta));
	}
	Ok(pkg)
}

// alpm_compute_sha256sum as lowercase hex, None when unreadable
fn sha256_hex(path: &[u8]) -> Option<Vec<u8>> {
	let file = File::open(os(path)).ok()?;
	let sum = Sha256Checksum::calculate_from_reader(file).ok()?;
	Some(text(&sum))
}

// _alpm_access(NULL, path, R_OK) with its debug line
fn access_read(cb: &mut dyn Callbacks, path: &[u8]) -> io::Result<()> {
	let nofollow = AtFlags::SYMLINK_NOFOLLOW;
	let Err(e) = accessat(CWD, path, Access::READ_OK, nofollow) else {
		return Ok(());
	};
	let e: io::Error = e.into();
	let text = util::strerror(&e);
	let msg = [b"\"", path, b"\" is not readable: ", &text, b"\n"];
	log(cb, LogLevel::Debug, &msg);
	Err(e)
}

// a validation that passed: the validation bits (PKG_VALIDATION_NONE
// when none) and the signature results when the check ran (sigdata)
#[derive(Debug)]
pub struct Validated {
	pub validation: c_int,
	pub siglist: Option<Vec<SigResult>>,
}

// _alpm_pkg_validate_internal: the file must be readable. a syncpkg's
// sha256sum is checked unless the level verifies its base64 signature;
// with SIG_PACKAGE the signature (base64 from syncpkg, else "<file>.sig")
// must pass _alpm_check_pgp_helper, a missing one only when optional
pub fn pkg_validate(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	pkgfile: &[u8],
	syncpkg: Option<&Package>,
	level: c_int,
) -> Result<Validated, Error> {
	let pkgfile = until_nul(pkgfile);
	if pkgfile.is_empty() {
		return Err(Error::WrongArgs);
	}
	access_read(cb, pkgfile).map_err(open_err)?;
	let b64 = syncpkg.and_then(|p| p.base64_sig.as_deref());
	let wants_sig = level & SIG_PACKAGE != 0;
	let has_sig = wants_sig
		&& (b64.is_some()
			|| access_read(cb, &sigpath(pkgfile)).is_ok());
	let mut validation = 0;
	let expected = syncpkg.and_then(|p| p.sha256sum.as_deref());
	if let Some(expected) = expected.filter(|_| !has_sig || b64.is_none()) {
		let expected = until_nul(expected);
		log(cb, LogLevel::Debug, &[b"sha256sum: ", expected, b"\n"]);
		let msg = [b"checking sha256sum for ", pkgfile, b"\n"];
		log(cb, LogLevel::Debug, &msg);
		// _alpm_test_checksum: strcmp with the lowercase hex
		if sha256_hex(pkgfile).as_deref() != Some(until_nul(expected)) {
			return Err(Error::Checksum);
		}
		validation |= PKG_VALIDATION_SHA256SUM;
	}
	let mut siglist = None;
	if wants_sig {
		let data = b64.map_or(&b"<from .sig>"[..], until_nul);
		log(cb, LogLevel::Debug, &[b"sig data: ", data, b"\n"]);
		let optional = level & SIG_PACKAGE_OPTIONAL != 0;
		if !has_sig && !optional {
			return Err(Error::MissingSig);
		}
		let marginal = level & SIG_PACKAGE_MARGINAL_OK != 0;
		let unknown = level & SIG_PACKAGE_UNKNOWN_OK != 0;
		let path = Some(pkgfile);
		let (ok, list) = check_pgp_helper(
			kr, cb, path, b64, optional, marginal, unknown,
		);
		if ok.is_err() {
			return Err(Error::InvalidSig(list));
		}
		if has_sig {
			validation |= PKG_VALIDATION_SIGNATURE;
		}
		siglist = Some(list);
	}
	if validation == 0 {
		validation = PKG_VALIDATION_NONE;
	}
	Ok(Validated {
		validation,
		siglist,
	})
}

// pkg_validate at level 0, no keyring reached: the validation bits
pub fn pkg_validate_internal(
	pkgfile: &[u8],
	syncpkg: Option<&Package>,
) -> Result<c_int, Error> {
	let mut kr = Keyring::new(b"");
	pkg_validate(&mut kr, &mut (), pkgfile, syncpkg, 0)
		.map(|v| v.validation)
}

// read_sigfile: the whole .sig, refused when empty (fread of 0 bytes
// reads no item) or over MAX_SIGFILE_SIZE
fn read_sigfile(sigpath: &[u8]) -> Option<Vec<u8>> {
	let mut file = File::open(os(sigpath)).ok()?;
	let size = file.metadata().ok()?.len();
	if size == 0 || size > MAX_SIGFILE_SIZE {
		return None;
	}
	let mut sig = vec![0; size as usize];
	file.read_exact(&mut sig).ok()?;
	Some(sig)
}

// alpm_pkg_load's key step on a readable .sig: each issuer key id the
// keychain lacks is offered for import. a failed extraction skips it
fn import_missing_keys(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	filename: &[u8],
	sigfile: &[u8],
	full: bool,
) -> Result<(), Error> {
	let Some(sig) = read_sigfile(sigfile) else {
		let msg = [b"failed to read signature file: ", sigfile, b"\n"];
		cb.log(LogLevel::Error, &msg.concat());
		return Err(Error::SigFile);
	};
	let mut keys = Vec::new();
	if extract_keyid(cb, filename, &sig, &mut keys).is_err() {
		return Ok(());
	}
	let (mut fail, mut errno) = (false, None);
	for key in &keys {
		if key_in_keychain(kr, cb, key) != Some(false) {
			continue;
		}
		// the C loads the package here and frees it unused, only its
		// pm_errno stays
		if let Err(e) = pkg_load_internal(cb, filename, full) {
			errno = Some(e.errno());
		}
		if !key_import(kr, cb, None, key) {
			fail = true;
		}
	}
	if fail {
		cb.log(LogLevel::Error, b"required key missing from keyring\n");
		return Err(Error::KeyMissing(errno));
	}
	Ok(())
}

// alpm_pkg_load: with SIG_PACKAGE missing keys offered for import, the
// file validated at level (no sync package), then loaded with the
// validation bits
pub fn pkg_load_level(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	filename: &[u8],
	full: bool,
	level: c_int,
) -> Result<Package, Error> {
	let filename = until_nul(filename);
	// the C tests the .sig whatever the level
	let sigfile = sigpath(filename);
	if access_read(cb, &sigfile).is_ok() && level & SIG_PACKAGE != 0 {
		import_missing_keys(kr, cb, filename, &sigfile, full)?;
	}
	let validated = pkg_validate(kr, cb, filename, None, level)?;
	let mut pkg = pkg_load_internal(cb, filename, full)?;
	pkg.validation = validated.validation;
	Ok(pkg)
}

// alpm_pkg_load at level 0
pub fn pkg_load(filename: &[u8], full: bool) -> Result<Package, Error> {
	let mut kr = Keyring::new(b"");
	pkg_load_level(&mut kr, &mut (), filename, full, 0)
}

// _package_changelog_open/read/close in one: the .CHANGELOG entry of the
// package's file. NotFound when there is none (the C sets errno ENOENT),
// a read error is ALPM_ERR_LIBARCHIVE like _package_changelog_read
pub fn changelog(pkg: &Package) -> Result<Vec<u8>, Error> {
	let Some(PkgFrom::File(path)) = &pkg.origin else {
		return Err(Error::WrongArgs);
	};
	let (mut archive, ..) = open_archive(&mut (), until_nul(path))?;
	let entries = archive.entries().map_err(Error::Open)?;
	// a header error ends the search like the C's while loop
	for mut entry in entries.map_while(Result::ok) {
		if *entry.path_bytes() == *b".CHANGELOG" {
			return util::content(&mut entry)
				.map_err(Error::Archive);
		}
	}
	Err(Error::NotFound)
}
