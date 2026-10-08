// port of lib/libalpm/be_package.c: _alpm_pkg_load_internal with
// parse_descfile, alpm_pkg_load (with read_sigfile and the key import),
// _alpm_pkg_validate_internal, and the changelog ops of file packages.
// signatures go through signing.rs, the keyring and callbacks are taken
// as parameters until the handle carries them.
//
// the archive walk follows the C loop. libarchive is replaced by its read
// filters (filter.rs) and its tar reader (tar.rs); .MTREE goes through
// libarchive's mtree reader (crate::mtree). .PKGINFO is read byte for byte like
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

use alpm_types::Sha256Checksum;
use rustix::fs::Access;

use crate::backup::Backup;
use crate::be_local::{INFRQ_BASE, INFRQ_DESC, INFRQ_FILES, INFRQ_SCRIPTLET};
use crate::callbacks::{Callbacks, LogLevel, logv};
use crate::deps::{Depend, dep_from_string};
use crate::error::Errno;
use crate::filelist::{File as PkgFile, FileList};
use crate::mtree;
use crate::package::{
	PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM,
	PKG_VALIDATION_SIGNATURE, Package, PkgFrom, PkgXData, check_meta,
	parse_xdata,
};
use crate::signing::{
	Keyring, SIG_PACKAGE, SIG_PACKAGE_MARGINAL_OK, SIG_PACKAGE_OPTIONAL,
	SIG_PACKAGE_UNKNOWN_OK, SigResult, check_pgp_helper, extract_keyid,
	key_import, key_in_keychain, sigpath,
};
use crate::tar;
use crate::util::{
	self, ArchiveFgets, DataBlocks, Entry, alpm_access, hash_sdbm,
	parsedate, strtoofft, until_nul, with_vec,
};

// read_sigfile's limit, adopted from repo-add
const MAX_SIGFILE_SIZE: u64 = 16384;

// mode_t file type bits, archive_entry.h AE_IF*
const AE_IFMT: u32 = 0o170000;
const AE_IFDIR: u32 = 0o040000;

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

// _alpm_open_archive and the C's errno check after it: the reader and
// st_size. a failed open(2) is logged with its strerror, a stream the
// decoder refuses with the decoder's text (the C: libarchive's)
fn open_archive(
	cb: &mut dyn Callbacks,
	path: &[u8],
) -> Result<(tar::Reader, i64), Error> {
	logv(cb, LogLevel::Debug, &[b"opening archive ", path, b"\n"]);
	let archive = util::open_archive(path).map_err(|e| {
		let text = util::strerror(&e);
		let msg = [b"could not open file ", path, b": ", &text, b"\n"];
		logv(cb, LogLevel::Error, &msg);
		open_err(e)
	})?;
	Ok((archive.reader, archive.meta.len() as i64))
}

fn text(v: &impl Display) -> Vec<u8> {
	v.to_string().into_bytes()
}

// the list keys of a .PKGINFO while it is read, appended to the
// package's lists once it is done
#[derive(Default)]
struct Lists {
	groups: Vec<Box<[u8]>>,
	licenses: Vec<Box<[u8]>>,
	depends: Vec<Depend>,
	optdepends: Vec<Depend>,
	makedepends: Vec<Depend>,
	checkdepends: Vec<Depend>,
	conflicts: Vec<Depend>,
	replaces: Vec<Depend>,
	provides: Vec<Depend>,
	backup: Vec<Backup>,
	xdata: Vec<PkgXData>,
}

fn append<T>(b: &mut Box<[T]>, v: Vec<T>) {
	with_vec(b, |b| b.extend(v));
}

impl Lists {
	fn put(self, pkg: &mut Package) {
		append(&mut pkg.groups, self.groups);
		append(&mut pkg.licenses, self.licenses);
		append(&mut pkg.depends, self.depends);
		append(&mut pkg.optdepends, self.optdepends);
		append(&mut pkg.makedepends, self.makedepends);
		append(&mut pkg.checkdepends, self.checkdepends);
		append(&mut pkg.conflicts, self.conflicts);
		append(&mut pkg.replaces, self.replaces);
		append(&mut pkg.provides, self.provides);
		append(&mut pkg.backup, self.backup);
		append(&mut pkg.xdata, self.xdata);
	}
}

// one "key = value" line of parse_descfile. the key ends at the line's
// first space, which must start " = "; key and value are read as C
// strings, so a nul cuts them. single keys overwrite, list keys append
fn parse_line(
	cb: &mut dyn Callbacks,
	pkg: &mut Package,
	l: &mut Lists,
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
		logv(cb, LogLevel::Debug, &msg);
		return Ok(());
	};
	let key = until_nul(&line[..i]);
	let v = until_nul(&line[i + 3..]);
	match key {
		b"pkgname" => {
			pkg.name = Some(v.into());
			pkg.name_hash = hash_sdbm(v);
		}
		b"pkgbase" => pkg.base = Some(v.into()),
		b"pkgver" => pkg.version = Some(v.into()),
		// not used atm
		b"basever" => {}
		b"pkgdesc" => pkg.desc = Some(v.into()),
		b"group" => l.groups.push(v.into()),
		b"url" => pkg.url = Some(v.into()),
		b"license" => l.licenses.push(v.into()),
		// 0 when not a whole number
		b"builddate" => pkg.builddate = parsedate(v).unwrap_or(0),
		b"packager" => pkg.packager = Some(v.into()),
		b"arch" => pkg.arch = Some(v.into()),
		// off_t: -1 when not bare digits, past i64::MAX the unsigned
		// value wraps (gcc's conversion)
		b"size" => pkg.isize = strtoofft(v).map_or(-1, |n| n as i64),
		b"depend" => l.depends.push(dep_from_string(v)),
		b"optdepend" => l.optdepends.push(dep_from_string(v)),
		b"makedepend" => l.makedepends.push(dep_from_string(v)),
		b"checkdepend" => l.checkdepends.push(dep_from_string(v)),
		b"conflict" => l.conflicts.push(dep_from_string(v)),
		b"replaces" => l.replaces.push(dep_from_string(v)),
		b"provides" => l.provides.push(dep_from_string(v)),
		b"backup" => l.backup.push(Backup {
			name: v.into(),
			hash: None,
		}),
		b"xdata" => l.xdata.push(parse_xdata(v).ok_or(Reason::Xdata)?),
		_ => {
			let what =
				[name, b": unknown key '", key, b"'"].concat();
			let msg = [&what[..], b" in package description\n"];
			logv(cb, LogLevel::Warning, &msg);
			let msg = [
				&what[..],
				b" in description file line ",
				&num,
				b"\n",
			];
			logv(cb, LogLevel::Debug, &msg);
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
) -> Result<(), Reason> {
	let mut lists = Lists::default();
	let r = read_descfile(cb, pkg, &mut lists, entry);
	// what was read before an error stays, like the C's
	lists.put(pkg);
	r
}

fn read_descfile(
	cb: &mut dyn Callbacks,
	pkg: &mut Package,
	l: &mut Lists,
	entry: &mut Entry,
) -> Result<(), Reason> {
	let mut lines = ArchiveFgets::new(DataBlocks::new(entry));
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
		parse_line(cb, pkg, l, line, linenum)?;
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
	logv(cb, LogLevel::Error, &[what, file, b"\n"]);
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

// an entry of libarchive's mtree reader: "./" stripped like
// build_filelist_from_mtree does, archive_entry_mode and _size
fn mtree_file(e: &mtree::Entry) -> (&[u8], u32, i64) {
	let path = e.path.strip_prefix(b"./").unwrap_or(&e.path);
	(path, e.kind.filetype() | e.mode, e.size as i64)
}

// build_filelist_from_mtree: the whole list or nothing, the C keeps the
// archive's list on failure. entries before one libarchive warns about
// still go through handle_simple_path (a "./.INSTALL" line marks the
// scriptlet)
fn filelist_from_mtree(
	cb: &mut dyn Callbacks,
	pkgfile: &[u8],
	pkg: &mut Package,
	entry: &mut Entry,
) -> Option<FileList> {
	let head = b"error while reading mtree of package ";
	let fail = |cb: &mut dyn Callbacks, text: &[u8]| {
		logv(cb, LogLevel::Debug, &[head, pkgfile, b": ", text, b"\n"]);
	};
	let data = util::content(entry).ok()?;
	let entries = match mtree::read_memory(data) {
		Ok(entries) => entries,
		Err(e) => {
			fail(cb, &e.text());
			return None;
		}
	};
	let mut files = FileList::default();
	for e in &entries {
		if let Some(text) = &e.warning {
			fail(cb, text);
			return None;
		}
		let (path, mode, size) = mtree_file(e);
		if !simple_path(pkg, path) {
			push_file(&mut files, path, mode, size);
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
	let (archive, size) = open_archive(cb, pkgfile)?;
	let msg = [b"starting package load for ", pkgfile, b"\n"];
	logv(cb, LogLevel::Debug, &msg);
	let mut pkg = Package {
		filename: Some(pkgfile.into()),
		size,
		..Package::default()
	};
	let (mut config, mut hit_mtree) = (false, false);

	// a header or data read failing: "error while reading package"
	// with the reader's text (the C: libarchive's)
	let read_err = |cb: &mut dyn Callbacks, e: io::Error| {
		let text = e.to_string();
		let head = b"error while reading package ";
		logv(
			cb,
			LogLevel::Error,
			&[head, pkgfile, b": ", text.as_bytes(), b"\n"],
		);
		Error::Archive(e)
	};
	for entry in archive.entries() {
		let mut entry = entry.map_err(|e| read_err(cb, e))?;
		let name = entry.path_bytes().to_vec();
		// the .PKGINFO and .MTREE branches continue before the break
		// check below, so the walk always goes one entry further
		if name == b".PKGINFO" {
			let parsed = parse_descfile(cb, &mut pkg, &mut entry);
			if let Err(why) = parsed {
				let msg = [
					b"could not parse package description file in ",
					pkgfile,
					b"\n",
				];
				logv(cb, LogLevel::Error, &msg);
				return Err(Error::Invalid(why));
			}
			check_descfile(cb, &pkg, pkgfile)
				.map_err(Error::Invalid)?;
			config = true;
			continue;
		} else if full && name == b".MTREE" {
			let msg = [b"found mtree for package ", pkgfile];
			let msg = [&msg.concat()[..], b", getting file list\n"];
			logv(cb, LogLevel::Debug, &msg);
			let files = filelist_from_mtree(
				cb, pkgfile, &mut pkg, &mut entry,
			);
			if files.is_some() {
				let msg = [
					b"finished mtree reading for ",
					pkgfile,
				];
				logv(
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
			let (mode, size) = (entry.mode(), entry.size());
			push_file(&mut pkg.files, &name, mode, size);
		}
		entry.skip().map_err(|e| read_err(cb, e))?;
		if (!full || hit_mtree) && config {
			break;
		}
	}

	if !config {
		let msg = [b"missing package metadata in ", pkgfile, b"\n"];
		logv(cb, LogLevel::Error, &msg);
		return Err(Error::Invalid(Reason::Missing));
	}
	pkg.origin = Some(PkgFrom::File(pkgfile.into()));
	pkg.infolevel = INFRQ_BASE | INFRQ_DESC | INFRQ_SCRIPTLET;
	pkg.validation = PKG_VALIDATION_NONE;
	if full {
		// "checking for conflicts" needs the list sorted
		if !pkg.files.files.is_empty() {
			let msg = [b"sorting package filelist for ", pkgfile];
			logv(cb, LogLevel::Debug, &[&msg.concat(), b"\n"]);
		}
		pkg.files.sort();
		pkg.infolevel |= INFRQ_FILES;
	}
	let version = pkg.version.as_deref().unwrap_or_default();
	if !check_meta(pkg.name_bytes(), until_nul(version), cb) {
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
	let readable = alpm_access(cb, None, pkgfile, Access::READ_OK);
	readable.map_err(|e| open_err(e.into()))?;
	let b64 = syncpkg.and_then(|p| p.base64_sig.as_deref());
	let wants_sig = level & SIG_PACKAGE != 0;
	let has_sig = wants_sig
		&& (b64.is_some()
			|| alpm_access(
				cb,
				None,
				&sigpath(pkgfile),
				Access::READ_OK,
			)
			.is_ok());
	let mut validation = 0;
	let expected = syncpkg.and_then(|p| p.sha256sum.as_deref());
	if let Some(expected) = expected.filter(|_| !has_sig || b64.is_none()) {
		let expected = until_nul(expected);
		logv(cb, LogLevel::Debug, &[b"sha256sum: ", expected, b"\n"]);
		let msg = [b"checking sha256sum for ", pkgfile, b"\n"];
		logv(cb, LogLevel::Debug, &msg);
		// _alpm_test_checksum: strcmp with the lowercase hex
		if sha256_hex(pkgfile).as_deref() != Some(until_nul(expected)) {
			return Err(Error::Checksum);
		}
		validation |= PKG_VALIDATION_SHA256SUM;
	}
	let mut siglist = None;
	if wants_sig {
		let data = b64.map_or(&b"<from .sig>"[..], until_nul);
		logv(cb, LogLevel::Debug, &[b"sig data: ", data, b"\n"]);
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
	let readable = alpm_access(cb, None, &sigfile, Access::READ_OK);
	if readable.is_ok() && level & SIG_PACKAGE != 0 {
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
pub fn changelog(
	cb: &mut dyn Callbacks,
	pkg: &Package,
) -> Result<Vec<u8>, Error> {
	let Some(PkgFrom::File(path)) = &pkg.origin else {
		return Err(Error::WrongArgs);
	};
	let (archive, _) = open_archive(cb, until_nul(path))?;
	// a header error ends the search like the C's while loop
	for mut entry in archive.entries().map_while(Result::ok) {
		if *entry.path_bytes() == *b".CHANGELOG" {
			return util::content(&mut entry)
				.map_err(Error::Archive);
		}
	}
	Err(Error::NotFound)
}
