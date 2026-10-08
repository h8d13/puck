// port of lib/libalpm/add.c: alpm_add_pkg (the target side of -S/-U)
// and, below, the per-package commit.

use std::cell::Cell;
use std::cmp::Ordering;
use std::ffi::{OsStr, c_int};
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{
	DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, fchown,
	lchown, symlink,
};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use alpm_compress::decompression::DecompressionSettings;
use rustix::fs::{
	AtFlags, CWD, FileType, Mode, OFlags, Timespec, Timestamps, chmodat,
	fchmod, futimens, makedev, mknodat, openat, utimensat,
};

use crate::backup;
use crate::be_local::{INFRQ_DESC, INFRQ_FILES, PrepareError, WriteError};
use crate::be_package::tar_mode_size;
use crate::callbacks::{
	Event, LogLevel, PackageOp, PackageOperation, Progress,
};
use crate::error::Errno;
use crate::handle::Handle;
use crate::package::{
	Package, PkgFrom, PkgReason, pkg_compare_versions, pkg_find,
};
use crate::remove::remove_single_package;
use crate::trans::{
	TRANS_FLAG_ALLDEPS, TRANS_FLAG_ALLEXPLICIT, TRANS_FLAG_DBONLY,
	TRANS_FLAG_DOWNLOADONLY, TRANS_FLAG_NEEDED, TRANS_FLAG_NOSCRIPTLET,
	TransPkg, TransState, load_caches, log, opt_str, runscriptlet,
	trans_in,
};
use crate::util::{
	CALLER_PREFIX, Entry, PATH_MAX, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO,
	S_IFLNK, S_IFMT, check_padding, cleanup_pathname, compute_md5sum,
	enter, llstat, mkdir_mode, open_archive, strerror, until_nul,
};

use LogLevel::{Debug, Error, Warning};

// alpm_add_pkg: a sync (db is its position in Handle::syncdbs()) or
// file package becomes an explicit target. the same sync package again
// is skipped, another of that name is TransDupTarget (a file package is
// never the same: the C compares addresses, pacman loads each file
// once). an installed package of that name only brings warnings, or
// with NEEDED skips an up to date one
pub fn add_pkg(
	h: &mut Handle,
	pkg: Package,
	db: Option<usize>,
) -> Result<(), Errno> {
	if pkg.origin == Some(PkgFrom::LocalDb) {
		return Err(Errno::WrongArgs);
	}
	trans_in(h, TransState::Initialized)?;
	let (name, ver) = (opt_str(&pkg.name).to_vec(), opt_str(&pkg.version));
	let ver = ver.to_vec();
	log(h.callbacks(), Debug, &[b"adding package '", &name, b"'\n"]);

	let trans = h.trans().expect("checked above");
	let add = trans.add.iter().map(|t| &t.pkg);
	if let Some(dup) = pkg_find(add, pkg.name_bytes()) {
		let same = trans.add.iter().any(|t| {
			std::ptr::eq(&t.pkg, dup)
				&& t.db.is_some() && t.db == db
		});
		if !same {
			return Err(Errno::TransDupTarget);
		}
		let msg = [b"skipping duplicate target: ", &name[..], b"\n"];
		log(h.callbacks(), Debug, &msg);
		return Ok(());
	}
	let flags = trans.flags;

	load_caches(h, false);
	let local = h
		.localdb()
		.and_then(|db| db.loaded_pkgcache())
		.and_then(|c| c.find(pkg.name_bytes()))
		.map(|l| (l.clone(), pkg_compare_versions(&pkg, l)));
	if let Some((local, cmp)) = local {
		let (lname, lver) =
			(opt_str(&local.name), opt_str(&local.version));
		let downloadonly = flags & TRANS_FLAG_DOWNLOADONLY != 0;
		let cb = h.callbacks();
		if cmp.is_eq() {
			if flags & TRANS_FLAG_NEEDED != 0 {
				let msg = [
					lname,
					b"-",
					lver,
					b" is up to date -- skipping\n",
				];
				log(cb, Warning, &msg);
				return Ok(());
			}
			if !downloadonly {
				let msg = [
					lname,
					b"-",
					lver,
					b" is up to date -- reinstalling\n",
				];
				log(cb, Warning, &msg);
			}
		} else if cmp.is_lt() && !downloadonly {
			let msg = [
				b"downgrading package ",
				lname,
				b" (",
				lver,
				b" => ",
				&ver[..],
				b")\n",
			];
			log(cb, Warning, &msg);
		}
	}

	let msg = [
		b"adding package ",
		&name[..],
		b"-",
		&ver[..],
		b" to the transaction add list\n",
	];
	log(h.callbacks(), Debug, &msg);
	let trans = h.trans_mut().expect("checked above");
	// the C target is the cache entry itself: one a prepare dropped to
	// unresolvable comes back with its removes and oldpkg
	let dropped = trans.unresolvable.iter().find(|t| {
		t.db.is_some() && t.db == db && t.pkg.name == pkg.name
	});
	let mut t = match dropped {
		Some(t) => t.clone(),
		None => TransPkg::new(pkg, db),
	};
	t.pkg.reason = PkgReason::Explicit;
	trans.add.push(t);
	Ok(())
}

// ---- commit side ----
//
// the per-package commit of add.c: extract_db_file, extract_single_file,
// try_rename, perform_extraction, get_install_time, commit_single_pkg
// and the per-package step of _alpm_upgrade_packages. the driver over
// trans.add (interrupted state, ldconfig) comes with alpm_trans_commit.
// an upgrade removes the old package through remove.rs first.
//
// perform_extraction's archive_write_disk is translated below (Writer)
// for its flags OWNER|PERM|TIME|UNLINK|XATTR|SECURE_SYMLINKS and a fresh
// writer per entry, so a directory's deferred mode and times are fixed
// up right after it. names are absolute (root + entry name); the C
// chdir()s into root for hard link targets, here they are joined to
// root and the process cwd stays. the process umask is taken as 0022
// (pacman's main sets it); modes come out exact either way. not
// restored: xattrs (pax records, not translated yet), pax times and
// ids (the ustar fields are used). libarchive's texts are
// copied, a failed data read shows the port's error text.

// archive_write_disk todo bits
const TODO_MODE_BASE: u32 = 1;
const TODO_MODE_FORCE: u32 = 1 << 1;
const TODO_MODE: u32 = TODO_MODE_BASE | TODO_MODE_FORCE;
const TODO_SGID: u32 = 1 << 2;
const TODO_SGID_CHECK: u32 = 1 << 3;
const TODO_SUID: u32 = 1 << 4;
const TODO_SUID_CHECK: u32 = 1 << 5;
const TODO_OWNER: u32 = 1 << 6;
const TODO_TIMES: u32 = 1 << 7;

const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
// pacman's main: umask(0022)
const UMASK: u32 = 0o022;
// archive_write_disk_posix.c
const MINIMUM_DIR_MODE: u32 = 0o700;
const MAXIMUM_DIR_MODE: u32 = 0o775;
// ARCHIVE_ERRNO_MISC
const ERRNO_MISC: i32 = -1;
const ENOSPC: i32 = 28;
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EEXIST: i32 = 17;

fn os(path: &[u8]) -> &Path {
	Path::new(OsStr::from_bytes(path))
}

fn errno(e: &io::Error) -> i32 {
	e.raw_os_error().unwrap_or(0)
}

// geteuid() from /proc/self/status, like sandbox::System's getuid
fn euid() -> u32 {
	// "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
	let status = fs::read("/proc/self/status").unwrap_or_default();
	status.split(|&c| c == b'\n')
		.find_map(|l| l.strip_prefix(b"Uid:"))
		.and_then(|l| {
			let f = l
				.split(|c| c.is_ascii_whitespace())
				.filter(|f| !f.is_empty())
				.nth(1)?;
			std::str::from_utf8(f).ok()?.parse().ok()
		})
		.unwrap_or(u32::MAX)
}

fn now() -> i64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_or(0, |d| d.as_secs() as i64)
}

// archive_errno and archive_error_string after archive_read_extract2
// returned other than ARCHIVE_OK. fatal: a failed data read (the only
// result it does not cap at ARCHIVE_WARN)
#[derive(Debug)]
struct ExtractError {
	fatal: bool,
	errno: i32,
	msg: Vec<u8>,
}

fn warn(errno: i32, msg: Vec<u8>) -> ExtractError {
	ExtractError {
		fatal: false,
		errno,
		msg,
	}
}

// what create_filesystem_object makes of the entry
#[derive(Clone, Debug)]
enum Object {
	File,
	Dir,
	Symlink(Vec<u8>),
	HardLink(Vec<u8>),
	Node(FileType, u64),
}

// what stays the same over the entries of one package
struct Disk<'a> {
	// the C's cwd during the commit
	root: &'a [u8],
	euid: u32,
	// st_dev/st_ino of the package file (archive_read_extract2's skip
	// file)
	skip: Option<(u64, u64)>,
	// archive length when unfiltered, see util::check_padding
	plain_len: Option<u64>,
}

// a name as the C resolves it: relative ones from the cwd (root)
fn resolve(root: &[u8], name: &[u8]) -> Vec<u8> {
	match name.first() {
		Some(b'/') => name.to_vec(),
		_ => [root, name].concat(),
	}
}

// check_symlinks_fsobj with UNLINK|SECURE_SYMLINKS: each leading
// component is lstat'ed; a missing one ends the walk, a symlink is
// unlinked (the last one too, unless it is a hard link target), a
// directory is entered. path is cleaned, relative ones start at root
fn check_symlinks(
	root: &[u8],
	path: &[u8],
	linkname: bool,
) -> Result<(), ExtractError> {
	if path.is_empty() {
		return Ok(());
	}
	let fail = |e: i32, what: &[u8]| warn(e, [what, path].concat());
	let mut tail = usize::from(path[0] == b'/');
	loop {
		while path.get(tail) == Some(&b'/') {
			tail += 1;
		}
		while tail < path.len() && path[tail] != b'/' {
			tail += 1;
		}
		let last = tail == path.len()
			|| (path[tail] == b'/' && tail + 1 == path.len());
		let head = resolve(root, &path[..tail]);
		match fs::symlink_metadata(os(&head)) {
			Err(e) if e.kind() == ErrorKind::NotFound => break,
			Err(e) => {
				return Err(fail(
					errno(&e),
					b"Could not stat ",
				));
			}
			Ok(st) if st.is_dir() => {
				// la_opendirat(O_RDONLY | O_DIRECTORY)
				if !last && let Err(e) = File::open(os(&head)) {
					let what = b"Could not chdir ";
					return Err(fail(errno(&e), what));
				}
			}
			Ok(st) if st.is_symlink() => {
				// linkat() does not follow a symlink target
				if last && linkname {
					break;
				}
				if let Err(e) = fs::remove_file(os(&head)) {
					return Err(match last {
						true => fail(
							errno(&e),
							b"Could not remove symlink ",
						),
						false => fail(
							0,
							b"Cannot remove intervening symlink ",
						),
					});
				}
				if last {
					break;
				}
			}
			Ok(_) => {}
		}
		if last {
			break;
		}
		tail += 1;
	}
	Ok(())
}

// one entry through archive_write_disk: header, data, finish, close
struct Writer<'d> {
	disk: &'d Disk<'d>,
	// a->name: the cleaned name
	name: Vec<u8>,
	// archive_entry_pathname, the fixups use it uncleaned
	path: Vec<u8>,
	mode: u32,
	obj: Object,
	uid: i64,
	gid: i64,
	mtime: i64,
	filesize: u64,
	todo: u32,
	deferred: u32,
	fd: Option<File>,
	written: u64,
	// the last archive_set_error
	err: Option<(i32, Vec<u8>)>,
}

impl Writer<'_> {
	fn set_err(&mut self, errno: i32, msg: Vec<u8>) {
		self.err = Some((errno, msg));
	}

	fn take_err(&mut self) -> ExtractError {
		let (errno, msg) = self.err.take().unwrap_or_default();
		warn(errno, msg)
	}

	// create_dir: missing parents first, a non-directory in the way
	// unlinked. stat follows symlinks. made 0755 (DEFAULT_DIR_MODE under
	// the umask, within MINIMUM/MAXIMUM_DIR_MODE: no fixup)
	fn create_dir(&mut self, path: &[u8]) -> Result<(), ()> {
		let slash = path.iter().rposition(|&c| c == b'/');
		let base = &path[slash.map_or(0, |i| i + 1)..];
		if matches!(base, b"" | b"." | b"..") {
			return match slash {
				Some(i) => self.create_dir(&path[..i]),
				None => Ok(()),
			};
		}
		let full = resolve(self.disk.root, path);
		let quoted = |what: &str, tail: &str| {
			[what.as_bytes(), path, tail.as_bytes()].concat()
		};
		match fs::metadata(os(&full)) {
			Ok(st) if st.is_dir() => return Ok(()),
			Ok(_) => {
				if let Err(e) = fs::remove_file(os(&full)) {
					let msg = quoted(
						"Can't create directory '",
						"': Conflicting file cannot \
						 be removed",
					);
					self.set_err(errno(&e), msg);
					return Err(());
				}
			}
			Err(e) if !matches!(errno(&e), ENOENT | ENOTDIR) => {
				let msg = quoted("Can't test directory '", "'");
				self.set_err(errno(&e), msg);
				return Err(());
			}
			Err(_) => {
				if let Some(i) = slash {
					self.create_dir(&path[..i])?;
				}
			}
		}
		let r = mkdir_mode(os(&full), 0o777 & !UMASK);
		let Err(e) = r else { return Ok(()) };
		// "a/b/../b/c": the second visit finds it made
		if fs::metadata(os(&full)).is_ok_and(|m| m.is_dir()) {
			return Ok(());
		}
		self.set_err(errno(&e), quoted("Failed to create dir '", "'"));
		Err(())
	}

	// create_filesystem_object: one creation attempt, its errno
	fn create(&mut self) -> Result<(), i32> {
		let name = resolve(self.disk.root, &self.name);
		let io = |r: io::Result<()>| r.map_err(|e| errno(&e));
		match self.obj.clone() {
			Object::HardLink(target) => {
				// cleanup_pathname_fsobj and check_symlinks_fsobj
				// on the target fail as EPERM
				let Some(clean) = cleanup_pathname(&target)
				else {
					let msg = b"Invalid empty pathname"
						.to_vec();
					self.set_err(ERRNO_MISC, msg);
					return Err(EPERM);
				};
				if let Err(e) = check_symlinks(
					self.disk.root,
					&clean,
					true,
				) {
					self.set_err(e.errno, e.msg);
					return Err(EPERM);
				}
				let src = resolve(self.disk.root, &target);
				io(fs::hard_link(os(&src), os(&name)))?;
				// a hard link without data has no metadata of
				// its own
				self.todo = 0;
				self.deferred = 0;
				return Ok(());
			}
			Object::Symlink(target) => {
				return io(symlink(
					OsStr::from_bytes(&target),
					os(&name),
				));
			}
			_ => {}
		}
		let final_mode = self.mode & 0o7777;
		let mut mode = final_mode & 0o777 & !UMASK;
		// writable for setxattr when not root
		if self.disk.euid != 0 {
			mode |= 0o200;
		}
		match self.obj {
			Object::Dir => {
				mode = (mode | MINIMUM_DIR_MODE)
					& MAXIMUM_DIR_MODE;
				io(DirBuilder::new()
					.mode(mode)
					.create(os(&name)))?;
				// times and mode wait for the close
				self.deferred |=
					self.todo & (TODO_TIMES | TODO_MODE);
				self.todo &= !(TODO_TIMES | TODO_MODE);
				return Ok(());
			}
			Object::Node(kind, rdev) => {
				let m = Mode::from_raw_mode(mode);
				mknodat(CWD, os(&name), kind, m, rdev)
					.map_err(|e| e.raw_os_error())?;
			}
			_ => {
				let f = OpenOptions::new()
					.write(true)
					.create_new(true)
					.mode(mode)
					.open(os(&name))
					.map_err(|e| errno(&e))?;
				self.fd = Some(f);
			}
		}
		if mode == final_mode {
			self.todo &= !TODO_MODE;
			// what the C's umask would have left, set exactly
			let _ = fs::set_permissions(
				os(&name),
				Permissions::from_mode(final_mode),
			);
		}
		Ok(())
	}

	// restore_entry
	fn restore(&mut self) -> Result<(), ExtractError> {
		let name = resolve(self.disk.root, &self.name);
		let is_dir = matches!(self.obj, Object::Dir);
		if !is_dir {
			// ARCHIVE_EXTRACT_UNLINK
			match fs::remove_file(os(&name)) {
				Ok(()) => {}
				Err(e) if e.kind() == ErrorKind::NotFound => {}
				Err(_) => {
					if let Err(e) =
						fs::remove_dir(os(&name))
					{
						let m = b"Could not unlink"
							.to_vec();
						return Err(warn(errno(&e), m));
					}
				}
			}
		}
		let mut en = self.create();
		if matches!(en, Err(ENOTDIR | ENOENT)) {
			if let Some(i) =
				self.name.iter().rposition(|&c| c == b'/')
			{
				let parent = self.name[..i].to_vec();
				let _ = self.create_dir(&parent);
			}
			en = self.create();
		}
		if let (Err(ENOENT), Object::HardLink(t)) = (en, &self.obj) {
			let msg = [
				b"Hard-link target '",
				&t[..],
				b"' does not exist",
			]
			.concat();
			return Err(warn(ENOENT, msg));
		}
		let fail = |e: &io::Error, what: &str| {
			warn(errno(e), what.as_bytes().to_vec())
		};
		if en == Err(EISDIR) {
			if let Err(e) = fs::remove_dir(os(&name)) {
				let w = "Can't remove already-existing dir";
				return Err(fail(&e, w));
			}
			en = self.create();
		} else if en == Err(EEXIST) {
			let mut st = match is_dir {
				true => fs::metadata(os(&name)),
				false => fs::symlink_metadata(os(&name)),
			};
			if !is_dir || st.is_err() {
				st = fs::symlink_metadata(os(&name));
			}
			let st = st.map_err(|e| {
				fail(&e, "Can't stat existing object")
			})?;
			if self.disk.skip == Some((st.dev(), st.ino())) {
				let msg = b"Refusing to overwrite archive";
				return Err(warn(0, msg.to_vec()));
			}
			if !st.is_dir() {
				if let Err(e) = fs::remove_file(os(&name)) {
					let w = "Can't unlink already-existing \
						 object";
					return Err(fail(&e, w));
				}
				en = self.create();
			} else if !is_dir {
				if let Err(e) = fs::remove_dir(os(&name)) {
					let w = "Can't replace existing \
						 directory with non-directory";
					return Err(fail(&e, w));
				}
				en = self.create();
			} else {
				// a directory in the way of one: its mode is
				// fixed up at the close
				let differs = self.mode != st.mode();
				if differs && self.todo & TODO_MODE_FORCE != 0 {
					self.deferred |= self.todo & TODO_MODE;
				}
				en = Ok(());
			}
		}
		if let Err(e) = en {
			if self.err.is_none() {
				let msg = [
					b"Can't create '",
					&self.name[..],
					b"'",
				]
				.concat();
				self.set_err(e, msg);
			}
			return Err(self.take_err());
		}
		Ok(())
	}

	// copy_data + _archive_write_disk_data_block: a failed read is
	// fatal, a failed write a warning that ends the copy
	fn copy_data(&mut self, entry: &mut Entry) -> Result<(), ExtractError> {
		// libarchive's tar reader names a short entry, other read
		// errors show the port's text
		let fatal = |e: io::Error| ExtractError {
			fatal: true,
			errno: errno(&e),
			msg: match e.kind() {
				ErrorKind::UnexpectedEof => {
					b"Truncated tar archive \
					detected while reading data"
						.to_vec()
				}
				_ => strerror(&e),
			},
		};
		let Some(mut f) = self.fd.take() else {
			return Ok(());
		};
		let mut buf = vec![0; 64 * 1024];
		let mut r = Ok(());
		while self.written < self.filesize {
			let n = match entry.read(&mut buf) {
				Ok(0) => {
					let e = ErrorKind::UnexpectedEof.into();
					r = Err(fatal(e));
					break;
				}
				Ok(n) => n,
				Err(e) if e.kind()
					== ErrorKind::Interrupted =>
				{
					continue;
				}
				Err(e) => {
					r = Err(fatal(e));
					break;
				}
			};
			if let Err(e) = f.write_all(&buf[..n]) {
				let msg = b"Write failed".to_vec();
				r = Err(warn(errno(&e), msg));
				break;
			}
			self.written += n as u64;
		}
		self.fd = Some(f);
		r?;
		check_padding(entry, self.filesize, self.disk.plain_len)
			.map_err(fatal)
	}

	// lazy_stat: the open file, else lstat of the name
	fn stat(&self) -> io::Result<fs::Metadata> {
		match &self.fd {
			Some(f) => f.metadata(),
			None => {
				let name = resolve(self.disk.root, &self.name);
				fs::symlink_metadata(os(&name))
			}
		}
	}

	// set_ownership: fchown, else lchown. done, the SUID/SGID checks
	// are not needed
	fn set_ownership(&mut self) -> bool {
		let (uid, gid) = (self.uid as u32, self.gid as u32);
		let fd_ok = self.fd.as_ref().is_some_and(|f| {
			fchown(f, Some(uid), Some(gid)).is_ok()
		});
		let name = resolve(self.disk.root, &self.name);
		let r = match fd_ok {
			true => Ok(()),
			false => lchown(os(&name), Some(uid), Some(gid)),
		};
		match r {
			Ok(()) => {
				self.todo &= !(TODO_OWNER
					| TODO_SGID_CHECK
					| TODO_SUID_CHECK);
				true
			}
			Err(e) => {
				let msg = format!(
					"Can't set user={}/group={} for ",
					self.uid, self.gid
				);
				let msg = [msg.as_bytes(), &self.name].concat();
				self.set_err(errno(&e), msg);
				false
			}
		}
	}

	// set_mode: SUID/SGID kept only when the owner is right, then
	// fchmod/chmod; symlinks are skipped (lchmod is not supported on
	// linux), directories wait for the close
	fn set_mode(&mut self) -> bool {
		let mut mode = self.mode & 0o7777;
		let mut ok = true;
		if self.todo & TODO_SGID_CHECK != 0 {
			let st = match self.stat() {
				Ok(st) => st,
				Err(e) => {
					let msg =
						b"Couldn't stat file".to_vec();
					self.set_err(errno(&e), msg);
					return false;
				}
			};
			if i64::from(st.gid()) != self.gid {
				mode &= !S_ISGID;
				let msg = b"Can't restore SGID bit".to_vec();
				self.set_err(ERRNO_MISC, msg);
				ok = false;
			}
			if i64::from(st.uid()) != self.uid
				&& self.todo & TODO_SUID != 0
			{
				mode &= !S_ISUID;
				let msg = b"Can't restore SUID bit".to_vec();
				self.set_err(ERRNO_MISC, msg);
				ok = false;
			}
			self.todo &= !(TODO_SGID_CHECK | TODO_SUID_CHECK);
		} else if self.todo & TODO_SUID_CHECK != 0 {
			if i64::from(self.disk.euid) != self.uid {
				mode &= !S_ISUID;
				let msg = b"Can't make file SUID".to_vec();
				self.set_err(ERRNO_MISC, msg);
				ok = false;
			}
			self.todo &= !TODO_SUID_CHECK;
		}
		let r = match (&self.obj, &self.fd) {
			(Object::Symlink(_) | Object::Dir, _) => return ok,
			(_, Some(f)) => {
				f.set_permissions(Permissions::from_mode(mode))
			}
			(_, None) => {
				let name = resolve(self.disk.root, &self.name);
				let p = Permissions::from_mode(mode);
				fs::set_permissions(os(&name), p)
			}
		};
		if let Err(e) = r {
			let msg = format!("Can't set permissions to 0{mode:o}");
			self.set_err(errno(&e), msg.into_bytes());
			return false;
		}
		ok
	}

	// atime is the writer's start time, mtime the entry's
	fn times(&self) -> Timestamps {
		Timestamps {
			last_access: Timespec {
				tv_sec: now(),
				tv_nsec: 0,
			},
			last_modification: Timespec {
				tv_sec: self.mtime,
				tv_nsec: 0,
			},
		}
	}

	// set_times_from_entry: futimens, else utimensat without following
	fn set_times(&mut self) -> bool {
		let ts = self.times();
		let r = match &self.fd {
			Some(f) => futimens(f, &ts),
			None => {
				let name = resolve(self.disk.root, &self.name);
				let nofollow = AtFlags::SYMLINK_NOFOLLOW;
				utimensat(CWD, os(&name), &ts, nofollow)
			}
		};
		if let Err(e) = r {
			let msg = b"Can't restore time".to_vec();
			self.set_err(e.raw_os_error(), msg);
			return false;
		}
		true
	}

	// _archive_write_disk_finish_entry: size, owner, mode, times
	fn finish(&mut self) -> Result<(), ExtractError> {
		self.err = None;
		if let Some(f) = &self.fd
			&& self.written != self.filesize
			&& let Err(e) = f.set_len(self.filesize)
			&& self.filesize == 0
		{
			let msg = b"File size could not be restored".to_vec();
			self.fd = None;
			return Err(warn(errno(&e), msg));
		}
		let mut ok = true;
		if self.todo & TODO_OWNER != 0 {
			ok &= self.set_ownership();
		}
		if self.todo & TODO_MODE != 0 {
			ok &= self.set_mode();
		}
		if self.todo & TODO_TIMES != 0 {
			ok &= self.set_times();
		}
		self.fd = None;
		match ok {
			true => Ok(()),
			false => Err(self.take_err()),
		}
	}

	// _archive_write_disk_close: the deferred mode and times of a
	// directory, on the uncleaned name without trailing '/'. a name
	// that is no longer a directory is left alone
	fn fixup(&self) {
		if self.deferred & (TODO_MODE | TODO_TIMES) == 0 {
			return;
		}
		let end = self.path.len()
			- self.path
				.iter()
				.rev()
				.take_while(|&&c| c == b'/')
				.count();
		let path = resolve(self.disk.root, &self.path[..end]);
		let flags = OFlags::RDONLY
			| OFlags::NOFOLLOW | OFlags::DIRECTORY
			| OFlags::CLOEXEC;
		let fd = openat(CWD, os(&path), flags, Mode::empty()).ok();
		if fd.is_none()
			&& !fs::symlink_metadata(os(&path))
				.is_ok_and(|m| m.is_dir())
		{
			return;
		}
		let mode = Mode::from_raw_mode(self.mode & 0o7777);
		if self.deferred & TODO_TIMES != 0 {
			let ts = self.times();
			let _ = match &fd {
				Some(fd) => futimens(fd, &ts),
				None => utimensat(
					CWD,
					os(&path),
					&ts,
					AtFlags::SYMLINK_NOFOLLOW,
				),
			};
		}
		if self.deferred & TODO_MODE != 0 {
			let _ = match &fd {
				Some(fd) => fchmod(fd, mode),
				None => chmodat(
					CWD,
					os(&path),
					mode,
					AtFlags::empty(),
				),
			};
		}
	}
}

impl Disk<'_> {
	// archive_read_extract2 of the entry named name (absolute) through a
	// fresh archive_write_disk with pacman's flags. mode and size are
	// libarchive's (tar_mode_size)
	fn extract(
		&self,
		entry: &mut Entry,
		name: &[u8],
		mode: u32,
		size: u64,
	) -> Result<(), ExtractError> {
		let header = entry.header();
		let target = entry.link_name_bytes().unwrap_or_default();
		let dev = |n: io::Result<Option<u32>>| {
			n.ok().flatten().unwrap_or(0)
		};
		let obj = match mode & S_IFMT {
			S_IFDIR => Object::Dir,
			S_IFLNK => Object::Symlink(target.to_vec()),
			// hard links carry no type bits
			0 => Object::HardLink(target.to_vec()),
			S_IFCHR | S_IFBLK => {
				let kind = match mode & S_IFMT {
					S_IFCHR => FileType::CharacterDevice,
					_ => FileType::BlockDevice,
				};
				let rdev = makedev(
					dev(header.device_major()),
					dev(header.device_minor()),
				);
				Object::Node(kind, rdev)
			}
			S_IFIFO => Object::Node(FileType::Fifo, 0),
			_ => Object::File,
		};
		let clean = cleanup_pathname(name).ok_or_else(|| {
			warn(ERRNO_MISC, b"Invalid empty pathname".to_vec())
		})?;
		if let Object::HardLink(t) = &obj
			&& *t == clean
		{
			let msg = [
				&b"Skipping hardlink pointing to itself: "[..],
				&clean,
			]
			.concat();
			return Err(warn(ERRNO_MISC, msg));
		}
		let mut todo = TODO_MODE | TODO_OWNER | TODO_TIMES;
		if mode & S_ISGID != 0 {
			todo |= TODO_SGID | TODO_SGID_CHECK;
		}
		if mode & S_ISUID != 0 {
			todo |= TODO_SUID | TODO_SUID_CHECK;
		}
		let id = |n: io::Result<u64>| n.map_or(0, |n| n as i64);
		let mut w = Writer {
			disk: self,
			name: clean,
			path: name.to_vec(),
			mode,
			obj,
			uid: id(header.uid()),
			gid: id(header.gid()),
			mtime: id(header.mtime()),
			filesize: size,
			todo,
			deferred: 0,
			fd: None,
			written: 0,
			err: None,
		};
		check_symlinks(self.root, &w.name, false)?;
		w.restore()?;
		// a non-file takes no data: the next header skips it
		let mut r = match w.fd.is_some() && size > 0 {
			true => w.copy_data(entry),
			false => Ok(()),
		};
		let finished = w.finish();
		// the first message, the worst result
		if r.is_ok() {
			r = finished;
		}
		w.fixup();
		r
	}
}

// _alpm_log and alpm_logaction with libalpm's prefix
fn logaction(h: &mut Handle, parts: &[&[u8]]) {
	let _ = h.logaction(CALLER_PREFIX, &parts.concat());
}

// perform_extraction: entry extracted to filename. a warning is only
// logged, unless it carries ENOSPC. true on failure (C 1)
fn perform_extraction(
	h: &mut Handle,
	disk: &Disk,
	entry: &mut Entry,
	mode: u32,
	size: u64,
	filename: &[u8],
) -> bool {
	let Err(e) = disk.extract(entry, filename, mode, size) else {
		return false;
	};
	let text = [filename, b" (", &e.msg, b")\n"].concat();
	if !e.fatal && e.errno != ENOSPC {
		let msg = [&b"warning given when extracting "[..], &text];
		log(h.callbacks(), Warning, &msg);
		return false;
	}
	log(h.callbacks(), Error, &[b"could not extract ", &text]);
	logaction(h, &[b"error: could not extract ", &text]);
	true
}

// try_rename: true on failure (C 1)
fn try_rename(h: &mut Handle, src: &[u8], dest: &[u8]) -> bool {
	let Err(e) = fs::rename(os(src), os(dest)) else {
		return false;
	};
	let text = [
		b"could not rename ",
		src,
		b" to ",
		dest,
		b" (",
		&strerror(&e),
		b")\n",
	]
	.concat();
	log(h.callbacks(), Error, &[&text]);
	logaction(h, &[b"error: ", &text]);
	true
}

// extract_db_file: .INSTALL, .CHANGELOG and .MTREE go into the package's
// local db dir as install, changelog and mtree, mode 0644; any other
// name starting with '.' is skipped. true on failure
fn extract_db_file(
	h: &mut Handle,
	disk: &Disk,
	entry: &mut Entry,
	(mode, size): (u32, u64),
	newpkg: &Package,
	entryname: &[u8],
) -> bool {
	let dbfile: &[u8] = match entryname {
		b".INSTALL" => b"install",
		b".CHANGELOG" => b"changelog",
		b".MTREE" => b"mtree",
		_ => {
			// reserved for future use, the data is skipped with
			// the next header
			let msg = [
				b"skipping extraction of '",
				entryname,
				b"'\n",
			];
			log(h.callbacks(), Debug, &msg);
			return false;
		}
	};
	// archive_entry_set_perm keeps the type bits
	let mode = (mode & S_IFMT) | 0o644;
	let dbpath = h.localdb().and_then(|db| db.local()).map(|l| l.path());
	let filename = [
		dbpath.unwrap_or_default(),
		opt_str(&newpkg.name),
		b"-",
		opt_str(&newpkg.version),
		b"/",
		dbfile,
	]
	.concat();
	// snprintf into char[PATH_MAX]
	let filename = &filename[..filename.len().min(PATH_MAX - 1)];
	perform_extraction(h, disk, entry, mode, size, filename)
}

// the ".pacnew" sibling
fn pacnew(filename: &[u8]) -> Vec<u8> {
	[filename, b".pacnew"].concat()
}

// extract_single_file: one entry of the package under handle->root,
// with the C's cases for what is in the way (1-6 in add.c) and the
// backup decision on the md5 of the original (oldpkg's backup entry),
// new and current file. backup hashes of newpkg are updated in place.
// the error count (0 or 1)
fn extract_single_file(
	h: &mut Handle,
	disk: &Disk,
	entry: &mut Entry,
	newpkg: &mut Package,
	oldpkg: Option<&Package>,
) -> usize {
	let entryname = until_nul(&entry.path_bytes()).to_vec();
	let Ok((entrymode, size)) = tar_mode_size(entry) else {
		return 0;
	};
	let size = size as u64;
	if entryname.first() == Some(&b'.') {
		let ms = (entrymode, size);
		return usize::from(extract_db_file(
			h, disk, entry, ms, newpkg, &entryname,
		));
	}
	if newpkg.files.contains(&entryname).is_none() {
		let msg = [
			b"file not found in file list for package ",
			opt_str(&newpkg.name),
			b". skipping extraction of ",
			&entryname,
			b"\n",
		];
		log(h.callbacks(), Warning, &msg);
		return 0;
	}
	let root = h.root().to_vec();
	let mut filename = [&root[..], &entryname].concat();
	let filename_len = filename.len();
	if filename_len >= PATH_MAX {
		let msg = [
			b"unable to extract ",
			&root[..],
			&entryname,
			b": path too long",
		];
		log(h.callbacks(), Error, &msg);
		return 1;
	}
	if h.match_noextract(&entryname) == Some(false) {
		let msg = [
			&entryname[..],
			b" is in NoExtract, skipping extraction of ",
			&filename,
			b"\n",
		];
		log(h.callbacks(), Debug, &msg);
		return 0;
	}

	let backup = newpkg
		.backup
		.iter()
		.position(|b| until_nul(&b.name) == &entryname[..]);
	let (mut notouch, mut needbackup) = (false, false);
	let mut hash_orig: Option<Vec<u8>> = None;
	let lsbuf = llstat(&filename);
	let is_dir = |m: u32| m & S_IFMT == S_IFDIR;
	let mut isnewfile = lsbuf.is_err();
	match lsbuf {
		// cases 1, 2: nothing there, no backup checks
		Err(_) => {}
		// case 6: an existing directory stays
		Ok(st) if st.is_dir() && is_dir(entrymode) => {
			if st.mode() != entrymode {
				let (fs_mode, pkg_mode) = (
					st.mode() & 0o7777,
					entrymode & 0o7777,
				);
				let msg = format!(
					"filesystem: {fs_mode:o}  package: \
					 {pkg_mode:o}\n"
				);
				let text: [&[u8]; 3] = [
					b"directory permissions differ on ",
					&filename,
					b"\n",
				];
				let mut line = text.concat();
				line.extend_from_slice(msg.as_bytes());
				log(h.callbacks(), Warning, &[&line]);
				let act = [
					&b"warning: directory permissions \
					   differ on "[..],
					&filename,
					b", ",
					msg.as_bytes(),
				];
				logaction(h, &act);
			}
			let msg = [
				b"extract: skipping dir extraction of ",
				&filename[..],
				b"\n",
			];
			log(h.callbacks(), Debug, &msg);
			return 0;
		}
		// case 5: no file over a directory
		Ok(st) if st.is_dir() => {
			let msg = [
				b"extract: not overwriting dir with file ",
				&filename[..],
				b"\n",
			];
			log(h.callbacks(), Error, &msg);
			return 1;
		}
		// case 4: a directory over a file
		Ok(_) if is_dir(entrymode) => {
			let msg = [
				b"extract: overwriting file with dir ",
				&filename[..],
				b"\n",
			];
			log(h.callbacks(), Debug, &msg);
		}
		// case 3: a file over a file
		Ok(_) => {
			if h.match_noupgrade(&entryname) == Some(false) {
				notouch = true;
			} else if let Some(old) = oldpkg
				.and_then(|o| backup::needbackup(&entryname, o))
			{
				hash_orig = old.hash.clone();
				needbackup = true;
			} else if backup.is_some() {
				// backup files may be added retroactively
				needbackup = true;
			}
		}
	}

	if notouch || needbackup {
		if filename_len + b".pacnew".len() >= PATH_MAX {
			let msg = [
				b"unable to extract ",
				&filename[..],
				b".pacnew: path too long",
			];
			log(h.callbacks(), Error, &msg);
			return 1;
		}
		filename = pacnew(&filename);
		isnewfile = matches!(
			llstat(&filename),
			Err(e) if e.kind() == ErrorKind::NotFound
		);
	}

	let msg = [b"extracting ", &filename[..], b"\n"];
	log(h.callbacks(), Debug, &msg);
	if perform_extraction(h, disk, entry, entrymode, size, &filename) {
		return 1;
	}
	if let Some(i) = backup {
		newpkg.backup[i].hash = compute_md5sum(&filename);
	}

	let origfile = &filename[..filename_len];
	let mut errors = 0;
	if notouch {
		let event = Event::PacnewCreated {
			from_noupgrade: true,
			oldpkg,
			newpkg,
			file: origfile,
		};
		h.callbacks().event(&event);
		let act = [
			&b"warning: "[..],
			origfile,
			b" installed as ",
			origfile,
			b".pacnew\n",
		];
		logaction(h, &act);
	} else if needbackup {
		let hash_local = compute_md5sum(origfile);
		let hash_pkg = match backup {
			Some(i) => newpkg.backup[i].hash.clone(),
			None => compute_md5sum(&filename),
		};
		let cb = h.callbacks();
		let null = |s: &Option<Vec<u8>>| opt_str(s).to_vec();
		log(cb, Debug, &[b"checking hashes for ", origfile, b"\n"]);
		log(cb, Debug, &[b"current:  ", &null(&hash_local), b"\n"]);
		log(cb, Debug, &[b"new:      ", &null(&hash_pkg), b"\n"]);
		log(cb, Debug, &[b"original: ", &null(&hash_orig), b"\n"]);
		let same = |a: &Option<Vec<u8>>, b: &Option<Vec<u8>>| {
			matches!((a, b), (Some(a), Some(b))
				if until_nul(a) == until_nul(b))
		};
		let install =
			[b"action: installing new file: ", origfile, b"\n"];
		if same(&hash_local, &hash_pkg) {
			// local and new are the same, renamed anyway for the
			// timestamps
			log(cb, Debug, &install);
			errors +=
				usize::from(try_rename(h, &filename, origfile));
		} else if same(&hash_orig, &hash_pkg) {
			// the package did not change it: the local version
			// stays, user changes included
			let msg = b"action: leaving existing file in place\n";
			log(cb, Debug, &[msg]);
			if isnewfile {
				let _ = fs::remove_file(os(&filename));
			}
		} else if same(&hash_orig, &hash_local) {
			// the user did not change it: updated
			log(cb, Debug, &install);
			errors +=
				usize::from(try_rename(h, &filename, origfile));
		} else {
			// all three differ: the new one stays as .pacnew
			let msg = b"action: keeping current file and \
				installing new one with .pacnew ending\n";
			log(cb, Debug, &[msg]);
			let event = Event::PacnewCreated {
				from_noupgrade: false,
				oldpkg,
				newpkg,
				file: origfile,
			};
			cb.event(&event);
			let act = [
				&b"warning: "[..],
				origfile,
				b" installed as ",
				&filename,
				b"\n",
			];
			logaction(h, &act);
		}
	}
	errors
}

// get_install_time: SOURCE_DATE_EPOCH when strtoull(.., 10) reads all of
// it without overflow (leading blanks and a sign taken, a negative value
// wraps like the C's unsigned long long into time_t), else now
pub fn install_time(source_date_epoch: Option<&[u8]>, now: i64) -> i64 {
	let Some(s) = source_date_epoch.map(until_nul) else {
		return now;
	};
	let is_space =
		|c: &u8| matches!(c, b' ' | b'\t' | b'\n' | 0x0b..=b'\r');
	let s = &s[s.iter().take_while(|c| is_space(c)).count()..];
	let (neg, digits) = match s.first() {
		Some(b'-') => (true, &s[1..]),
		Some(b'+') => (false, &s[1..]),
		_ => (false, s),
	};
	if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
		return now;
	}
	let mut v: u64 = 0;
	for &d in digits {
		let next = v
			.checked_mul(10)
			.and_then(|v| v.checked_add(u64::from(d - b'0')));
		// ERANGE
		let Some(next) = next else { return now };
		v = next;
	}
	match neg {
		true => v.wrapping_neg() as i64,
		false => v as i64,
	}
}

// the installed package as the C finds it in the local cache
fn in_local_cache(h: &mut Handle, name: &[u8]) -> bool {
	let dbs = h.dbs_mut();
	dbs.local
		.is_some_and(|db| db.get_pkg(dbs.dbext, dbs.cb, name).is_ok())
}

// checkdbdir's log lines, which LocalDb::prepare does not make
fn log_checkdbdir(h: &mut Handle) {
	let Some(path) = h.localdb().and_then(|d| d.local()).map(|l| l.path())
	else {
		return;
	};
	let path = path.to_vec();
	match fs::metadata(os(&path)) {
		Err(_) => {
			let msg = [
				b"database dir '",
				&path[..],
				b"' does not exist, creating it\n",
			];
			log(h.callbacks(), Debug, &msg);
		}
		Ok(m) if !m.is_dir() => {
			let msg = [
				b"removing invalid database: ",
				&path[..],
				b"\n",
			];
			log(h.callbacks(), Warning, &msg);
		}
		Ok(_) => {}
	}
}

// _alpm_local_db_prepare with its log lines
fn db_prepare(h: &mut Handle, pkg: &Package) -> bool {
	log_checkdbdir(h);
	let Some(local) = h.localdb().and_then(|d| d.local()) else {
		return false;
	};
	match local.prepare(pkg) {
		Ok(()) => true,
		Err(PrepareError::Mkdir(e)) => {
			let path = local.pkgpath(pkg, b"");
			let msg = [
				b"could not create directory ",
				&path[..],
				b": ",
				&strerror(&e),
				b"\n",
			];
			log(h.callbacks(), Error, &msg);
			false
		}
		Err(PrepareError::DbDir(_)) => false,
	}
}

// _alpm_local_db_write(INFRQ_ALL) with its log lines: desc, then files.
// write errors past the open are not checked, like the C's fprintf
fn db_write(h: &mut Handle, pkg: &Package) -> bool {
	for (kind, file, inforeq) in [
		(&b"DESC"[..], &b"desc"[..], INFRQ_DESC),
		(b"FILES", b"files", INFRQ_FILES),
	] {
		let msg = [
			b"writing ",
			opt_str(&pkg.name),
			b"-",
			opt_str(&pkg.version),
			b" ",
			kind,
			b" information back to db\n",
		];
		log(h.callbacks(), Debug, &msg);
		let Some(local) = h.localdb().and_then(|d| d.local()) else {
			return false;
		};
		let path = local.pkgpath(pkg, file);
		match local.write(pkg, inforeq) {
			Ok(()) | Err(WriteError::Write(_)) => {}
			Err(WriteError::Open(e)) => {
				let msg = [
					b"could not open file ",
					&path[..],
					b": ",
					&strerror(&e),
					b"\n",
				];
				log(h.callbacks(), Error, &msg);
				return false;
			}
		}
	}
	true
}

// _alpm_runscriptlet of an install scriptlet, unless NOSCRIPTLET
fn scriptlet(
	h: &mut Handle,
	flags: c_int,
	pkg: &Package,
	oldver: Option<&[u8]>,
	path: &[u8],
	script: &[u8],
	is_archive: bool,
) {
	if pkg.scriptlet == 0 || flags & TRANS_FLAG_NOSCRIPTLET != 0 {
		return;
	}
	let ver = pkg.version.clone().unwrap_or_default();
	runscriptlet(h, path, script, &ver, oldver, is_archive);
}

// the archive position for the progress percentage: the data start of
// the entry in an unfiltered tar (the bytes libarchive consumed), what
// the decoder read of a compressed one by the filter's last block
// (libarchive counts what its client read, equal once the whole stream
// is read)
fn position(entry: &Entry, consumed: &Cell<u64>, plain: bool) -> i64 {
	match plain {
		true => entry.raw_file_position() as i64,
		false => consumed.get() as i64,
	}
}

// commit_single_pkg: t.pkg, a file package (origin File), installed or
// upgraded over t.oldpkg (an upgrade when the local cache still holds a
// package of that name). t is a target of the handle's transaction,
// taken out of trans.add by the driver (the C mutates it in place);
// flags and skip_remove are read from the transaction. pkg_current and
// pkg_count are the progress counters. reason, install date and backup
// hashes are updated in t.pkg. Err is the pm_errno the C leaves (Ok
// where it sets none, also without a transaction)
pub fn commit_single_pkg(
	h: &mut Handle,
	t: &mut TransPkg,
	pkg_current: usize,
	pkg_count: usize,
) -> Result<(), Errno> {
	let flags = h.trans().ok_or(Errno::Ok)?.flags;
	let upgrade =
		in_local_cache(h, t.pkg.name_bytes()) && t.oldpkg.is_some();
	// the C's oldpkg stays NULL unless it is an upgrade
	let oldpkg = t.oldpkg.clone().filter(|_| upgrade);
	let oldpkg = oldpkg.as_ref();
	let (log_msg, progress, operation): (&[u8], _, _) = match oldpkg {
		None => (
			b"adding",
			Progress::AddStart,
			PackageOperation::Install,
		),
		Some(old) => match pkg_compare_versions(&t.pkg, old) {
			Ordering::Less => (
				b"downgrading",
				Progress::DowngradeStart,
				PackageOperation::Downgrade,
			),
			Ordering::Equal => (
				b"reinstalling",
				Progress::ReinstallStart,
				PackageOperation::Reinstall,
			),
			Ordering::Greater => (
				b"upgrading",
				Progress::UpgradeStart,
				PackageOperation::Upgrade,
			),
		},
	};
	if let Some(old) = oldpkg {
		t.pkg.reason = old.reason;
	}
	let op = PackageOp {
		operation,
		oldpkg,
		newpkg: Some(&t.pkg),
	};
	h.callbacks().event(&Event::PackageOperationStart(op));
	let oldver = oldpkg.map(|o| opt_str(&o.version).to_vec());
	let oldver = oldver.as_deref();

	let pkgfile = match &t.pkg.origin {
		Some(PkgFrom::File(f)) => f.clone(),
		_ => Vec::new(),
	};
	let (name, ver) =
		(opt_str(&t.pkg.name).to_vec(), opt_str(&t.pkg.version));
	let ver = ver.to_vec();
	let msg = [log_msg, b" package ", &name[..], b"-", &ver[..], b"\n"];
	log(h.callbacks(), Debug, &msg);
	let pre: &[u8] = match upgrade {
		true => b"pre_upgrade",
		false => b"pre_install",
	};
	scriptlet(h, flags, &t.pkg, oldver, &pkgfile, pre, true);

	// alldeps or allexplicit override any reason set before
	if flags & TRANS_FLAG_ALLDEPS != 0 {
		t.pkg.reason = PkgReason::Depend;
	} else if flags & TRANS_FLAG_ALLEXPLICIT != 0 {
		t.pkg.reason = PkgReason::Explicit;
	}

	// the old package goes first. the C's _alpm_remove_single_package
	// returns 0 whatever the files did, its -1 check here is dead
	if let Some(old) = oldpkg {
		let _ = remove_single_package(h, old, Some(&t.pkg), 0, 0);
	}

	// the db entry dir first, so install and mtree get their modes
	if !db_prepare(h, &t.pkg) {
		let act = [
			b"error: could not create database entry ",
			&name[..],
			b"-",
			&ver[..],
			b"\n",
		];
		logaction(h, &act);
		return Err(Errno::DbWrite);
	}

	let msg = [b"opening archive ", &pkgfile[..], b"\n"];
	log(h.callbacks(), Debug, &msg);
	let open_failed = |h: &mut Handle, e: io::Error| {
		let msg = [
			b"could not open file ",
			&pkgfile[..],
			b": ",
			&strerror(&e),
			b"\n",
		];
		log(h.callbacks(), Error, &msg);
		Errno::PkgOpen
	};
	let mut archive = match open_archive(&pkgfile) {
		Ok(a) => a,
		Err(e) => return Err(open_failed(h, e)),
	};
	let meta = &archive.meta;
	let plain = archive.settings == DecompressionSettings::None;
	let disk_root = h.root().to_vec();
	let disk = Disk {
		root: &disk_root,
		euid: euid(),
		skip: meta.is_file().then(|| (meta.dev(), meta.ino())),
		plain_len: plain.then_some(meta.len()),
	};
	let consumed = archive.consumed;
	let mut entries = match archive.reader.entries() {
		Ok(e) => e,
		Err(e) => return Err(open_failed(h, e)),
	};
	// libarchive reads the first header while opening
	let first = match entries.next() {
		Some(Err(e)) => return Err(open_failed(h, e)),
		first => first,
	};
	// the C chdir()s into root for hard links; checked the same way
	if let Err(e) = enter(&disk_root) {
		let msg = [
			b"could not change directory to ",
			&disk_root[..],
			b" (",
			&strerror(&e),
			b")\n",
		];
		log(h.callbacks(), Error, &msg);
		return Err(Errno::Ok);
	}

	let mut errors = 0;
	// archive_read_next_header other than ARCHIVE_OK ends the loop
	let entries = first.into_iter().chain(entries).map_while(Result::ok);
	if flags & TRANS_FLAG_DBONLY != 0 {
		log(h.callbacks(), Debug, &[b"extracting db files\n"]);
		for mut entry in entries {
			let entryname = until_nul(&entry.path_bytes()).to_vec();
			if entryname.first() != Some(&b'.') {
				continue;
			}
			let Ok((mode, size)) = tar_mode_size(&entry) else {
				continue;
			};
			let ms = (mode, size as u64);
			errors += usize::from(extract_db_file(
				h, &disk, &mut entry, ms, &t.pkg, &entryname,
			));
		}
	} else {
		log(h.callbacks(), Debug, &[b"extracting files\n"]);
		// 0 once, the loop starts past it
		h.callbacks().progress(
			progress,
			&name,
			0,
			pkg_count,
			pkg_current,
		);
		for mut entry in entries {
			// the compressed size, isize lacks the metadata
			let percent = match t.pkg.size {
				0 => 0,
				size => {
					let pos = position(
						&entry, &consumed, plain,
					);
					((pos * 100) / size).min(100) as c_int
				}
			};
			h.callbacks().progress(
				progress,
				&name,
				percent,
				pkg_count,
				pkg_current,
			);
			errors += extract_single_file(
				h, &disk, &mut entry, &mut t.pkg, oldpkg,
			);
		}
	}

	let mut ret = Ok(());
	if errors > 0 {
		ret = Err(Errno::Ok);
		let what: &[u8] = match upgrade {
			true => b"upgrading ",
			false => b"installing ",
		};
		let text = [b"problem occurred while ", what, &name[..], b"\n"];
		log(h.callbacks(), Error, &text);
		logaction(h, &[&b"error: "[..], &text.concat()]);
	}

	let sde = std::env::var_os("SOURCE_DATE_EPOCH");
	let sde = sde.as_ref().map(|s| s.as_bytes());
	t.pkg.installdate = install_time(sde, now());

	log(h.callbacks(), Debug, &[b"updating database\n"]);
	let msg = [b"adding database entry '", &name[..], b"'\n"];
	log(h.callbacks(), Debug, &msg);
	if !db_write(h, &t.pkg) {
		let text = [
			b"could not update database entry ",
			&name[..],
			b"-",
			&ver[..],
			b"\n",
		];
		log(h.callbacks(), Error, &text);
		logaction(h, &[&b"error: "[..], &text.concat()]);
		return Err(Errno::DbWrite);
	}

	if !add_in_local_cache(h, &t.pkg) {
		let msg =
			[b"could not add entry '", &name[..], b"' in cache\n"];
		log(h.callbacks(), Error, &msg);
	}

	h.callbacks()
		.progress(progress, &name, 100, pkg_count, pkg_current);

	let oldv = oldver.unwrap_or_default();
	let act: Vec<u8> = match operation {
		PackageOperation::Install => {
			[b"installed ", &name[..], b" (", &ver[..], b")\n"]
				.concat()
		}
		PackageOperation::Downgrade => [
			b"downgraded ",
			&name[..],
			b" (",
			oldv,
			b" -> ",
			&ver[..],
			b")\n",
		]
		.concat(),
		PackageOperation::Reinstall => {
			[b"reinstalled ", &name[..], b" (", &ver[..], b")\n"]
				.concat()
		}
		PackageOperation::Upgrade => [
			b"upgraded ",
			&name[..],
			b" (",
			oldv,
			b" -> ",
			&ver[..],
			b")\n",
		]
		.concat(),
		PackageOperation::Remove => Vec::new(),
	};
	logaction(h, &[&act]);

	let install = h
		.localdb()
		.and_then(|d| d.local())
		.map(|l| l.pkgpath(&t.pkg, b"install"))
		.unwrap_or_default();
	let post: &[u8] = match upgrade {
		true => b"post_upgrade",
		false => b"post_install",
	};
	scriptlet(h, flags, &t.pkg, oldver, &install, post, false);

	let op = PackageOp {
		operation,
		oldpkg,
		newpkg: Some(&t.pkg),
	};
	h.callbacks().event(&Event::PackageOperationDone(op));
	ret
}

// _alpm_db_add_pkgincache on the local db
fn add_in_local_cache(h: &mut Handle, pkg: &Package) -> bool {
	let dbs = h.dbs_mut();
	dbs.local
		.is_some_and(|db| db.add_pkg_in_cache(dbs.cb, pkg).is_ok())
}

// the per-package step of _alpm_upgrade_packages: any failure of
// commit_single_pkg is ALPM_ERR_TRANS_ABORT. the driver then marks the
// transaction interrupted and skips ldconfig
pub fn upgrade_package(
	h: &mut Handle,
	t: &mut TransPkg,
	pkg_current: usize,
	pkg_count: usize,
) -> Result<(), Errno> {
	commit_single_pkg(h, t, pkg_current, pkg_count)
		.map_err(|_| Errno::TransAbort)
}
