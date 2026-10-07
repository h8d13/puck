// C side of src/pacman/check.c (frontend objects, see build.rs) and of
// be_local.c's mtree reader (_cache_mtree_open/_cache_mtree_next through
// alpm_pkg_mtree_open/next)
//
// a CheckWorld owns a real handle on a fixture the test wrote (root and
// a local db with desc/files/mtree), packages come from its local cache.
// check_pkg_fast/full read config->handle and config->quiet and print
// to the C stdout (summaries, quiet lines, backup notes) and through
// pm_printf to the C stderr: both are swapped for open_memstreams under
// FRONTEND, like cli_util and conf.
use std::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use pacman_cli::conf::ColStr;

use crate::cli_util::{FRONTEND, config, init};
use crate::conf::ColStrC;
use crate::handle::{
	ALPM, CDb, alpm_db_get_pkg, alpm_errno, alpm_get_localdb,
	alpm_initialize, alpm_option_add_noextract, alpm_option_get_dbpath,
	alpm_option_get_root, alpm_release,
};
use crate::package::CPkg;
use crate::{c_free, cstr, fclose, fflush, open_memstream, stderr, stdout};

// archive_entry.h
const AE_IFREG: u32 = 0o100000;
const AE_IFLNK: u32 = 0o120000;
const DIGEST_MD5: c_int = 1;
const DIGEST_SHA256: c_int = 4;

unsafe extern "C" {

	fn check_pkg_fast(pkg: *mut CPkg) -> c_int;
	fn check_pkg_full(pkg: *mut CPkg) -> c_int;

	fn alpm_pkg_mtree_open(pkg: *mut CPkg) -> *mut c_void;
	fn alpm_pkg_mtree_next(
		pkg: *const CPkg,
		archive: *mut c_void,
		entry: *mut *mut c_void,
	) -> c_int;
	fn alpm_pkg_mtree_close(
		pkg: *const CPkg,
		archive: *mut c_void,
	) -> c_int;

	fn archive_error_string(a: *mut c_void) -> *const c_char;
	fn archive_entry_pathname(e: *mut c_void) -> *const c_char;
	fn archive_entry_filetype(e: *mut c_void) -> u32;
	fn archive_entry_perm(e: *mut c_void) -> u32;
	fn archive_entry_mode(e: *mut c_void) -> u32;
	fn archive_entry_uid(e: *mut c_void) -> i64;
	fn archive_entry_gid(e: *mut c_void) -> i64;
	fn archive_entry_size(e: *mut c_void) -> i64;
	fn archive_entry_size_is_set(e: *mut c_void) -> c_int;
	fn archive_entry_mtime(e: *mut c_void) -> i64;
	fn archive_entry_mtime_nsec(e: *mut c_void) -> c_long;
	fn archive_entry_mtime_is_set(e: *mut c_void) -> c_int;
	fn archive_entry_symlink(e: *mut c_void) -> *const c_char;
	fn archive_entry_digest(e: *mut c_void, kind: c_int) -> *const u8;

	fn utimensat(
		dirfd: c_int,
		path: *const c_char,
		times: *const Timespec,
		flags: c_int,
	) -> c_int;
}

// struct timespec, fcntl.h constants
#[repr(C)]
struct Timespec {
	tv_sec: i64,
	tv_nsec: c_long,
}
const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

// fixture helper: atime and mtime of path itself (symlinks too) to t
pub fn set_mtime_nofollow(path: &Path, t: i64) {
	let p = path_c(path);
	let ts = [
		Timespec {
			tv_sec: t,
			tv_nsec: 0,
		},
		Timespec {
			tv_sec: t,
			tv_nsec: 0,
		},
	];
	// SAFETY: p is a valid C string, ts two timespecs
	let r = unsafe {
		utimensat(
			AT_FDCWD,
			p.as_ptr(),
			ts.as_ptr(),
			AT_SYMLINK_NOFOLLOW,
		)
	};
	assert_eq!(r, 0, "utimensat {path:?}");
}

// one archive_entry as libarchive's mtree reader yields it
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CMtreeEntry {
	pub path: Vec<u8>,
	pub filetype: u32,
	pub perm: u32,
	// what check.c compares: ~AE_IFMT & archive_entry_mode
	pub mode_perm: u32,
	pub uid: i64,
	pub gid: i64,
	pub size: Option<i64>,
	pub mtime: Option<(i64, i64)>,
	pub link: Option<Vec<u8>>,
	// NULL from archive_entry_digest is None
	pub sha256: Option<[u8; 32]>,
	pub md5: Option<[u8; 16]>,
}

// the entries up to the first mtree_next that is not 0, that value (1
// end of archive, -1 anything else) and the archive error then
#[derive(Clone, Debug)]
pub struct CMtree {
	pub entries: Vec<CMtreeEntry>,
	pub end: i32,
	pub error: Option<Vec<u8>>,
}

// return value and both streams of one check_pkg_* call
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CCheck {
	pub ret: i32,
	pub stdout: Vec<u8>,
	pub stderr: Vec<u8>,
}

pub struct CheckWorld {
	h: *mut c_void,
	local: *mut CDb,
}

// SAFETY (callers): p NULL or a valid C string
unsafe fn opt_bytes(p: *const c_char) -> Option<Vec<u8>> {
	// SAFETY: see above
	(!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

// SAFETY (callers): p NULL or pointing at n readable bytes
unsafe fn digest<const N: usize>(p: *const u8) -> Option<[u8; N]> {
	// SAFETY: see above
	(!p.is_null()).then(|| unsafe { *p.cast::<[u8; N]>() })
}

// SAFETY (callers): e a live archive_entry
unsafe fn read_entry(e: *mut c_void) -> CMtreeEntry {
	// SAFETY: see above; strings and digests belong to the entry and
	// are copied before the next header replaces it
	unsafe {
		let size_set = archive_entry_size_is_set(e) != 0;
		let mtime_set = archive_entry_mtime_is_set(e) != 0;
		CMtreeEntry {
			path: opt_bytes(archive_entry_pathname(e))
				.unwrap_or_default(),
			filetype: archive_entry_filetype(e),
			perm: archive_entry_perm(e),
			mode_perm: !0o170000 & archive_entry_mode(e),
			uid: archive_entry_uid(e),
			gid: archive_entry_gid(e),
			size: size_set.then(|| archive_entry_size(e)),
			mtime: mtime_set.then(|| {
				(
					archive_entry_mtime(e),
					// c_long
					archive_entry_mtime_nsec(e) as i64,
				)
			}),
			link: opt_bytes(archive_entry_symlink(e)),
			sha256: digest(archive_entry_digest(e, DIGEST_SHA256)),
			md5: digest(archive_entry_digest(e, DIGEST_MD5)),
		}
	}
}

fn path_c(p: &Path) -> std::ffi::CString {
	cstr(p.as_os_str().as_bytes())
}

// runs f with config->colstr, quiet, logmask and handle set and both C
// streams captured: (stdout, stderr)
fn capture2(
	h: *mut c_void,
	quiet: bool,
	logmask: u16,
	colstr: &ColStr,
	f: impl FnOnce(),
) -> (Vec<u8>, Vec<u8>) {
	init();
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	let c = [
		colstr.colon,
		colstr.title,
		colstr.repo,
		colstr.version,
		colstr.groups,
		colstr.meta,
		colstr.warn,
		colstr.err,
		colstr.faint,
		colstr.nocolor,
	]
	.map(cstr);
	let (mut obuf, mut osize) = (ptr::null_mut(), 0usize);
	let (mut ebuf, mut esize) = (ptr::null_mut(), 0usize);
	// SAFETY: FRONTEND serializes every access to config, stdout and
	// stderr. config is valid after init; the colstr strings outlive
	// the call and the old colstr (static literals) is put back before
	// they drop. the memstreams replace the streams only while f runs,
	// their buffers are malloc'd and valid for size bytes after fclose
	unsafe {
		let old = std::mem::replace(
			&mut (*config).colstr,
			ColStrC {
				colon: c[0].as_ptr(),
				title: c[1].as_ptr(),
				repo: c[2].as_ptr(),
				version: c[3].as_ptr(),
				groups: c[4].as_ptr(),
				meta: c[5].as_ptr(),
				warn: c[6].as_ptr(),
				err: c[7].as_ptr(),
				faint: c[8].as_ptr(),
				nocolor: c[9].as_ptr(),
			},
		);
		let old_logmask = (*config).logmask;
		(*config).handle = h;
		(*config).quiet = u16::from(quiet);
		(*config).logmask = logmask;
		let out = open_memstream(&mut obuf, &mut osize);
		let err = open_memstream(&mut ebuf, &mut esize);
		assert!(!out.is_null() && !err.is_null());
		let (real_out, real_err) = (stdout, stderr);
		fflush(real_out);
		fflush(real_err);
		stdout = out;
		stderr = err;
		f();
		fflush(out);
		fflush(err);
		stdout = real_out;
		stderr = real_err;
		fclose(out);
		fclose(err);
		(*config).colstr = old;
		(*config).handle = ptr::null_mut();
		(*config).quiet = 0;
		(*config).logmask = old_logmask;
		let o = std::slice::from_raw_parts(obuf.cast::<u8>(), osize)
			.to_vec();
		let e = std::slice::from_raw_parts(ebuf.cast::<u8>(), esize)
			.to_vec();
		c_free(obuf.cast());
		c_free(ebuf.cast());
		(o, e)
	}
}

impl CheckWorld {
	// alpm_initialize on root and dbpath (existing dirs), noextract
	// patterns added in order
	pub fn open(root: &Path, dbpath: &Path, noextract: &[Vec<u8>]) -> Self {
		let (root, dbpath) = (path_c(root), path_c(dbpath));
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let mut err = 0;
		// SAFETY: valid C strings, err is writable; the handle copies
		// the patterns
		unsafe {
			let h = alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			);
			assert!(!h.is_null(), "alpm_initialize: {err}");
			for p in noextract {
				let p = cstr(p);
				alpm_option_add_noextract(h, p.as_ptr());
			}
			let local = alpm_get_localdb(h);
			assert!(!local.is_null());
			CheckWorld { h, local }
		}
	}

	// the cached local package, loaded by the C getters on demand
	fn pkg(&self, name: &[u8]) -> *mut CPkg {
		let n = cstr(name);
		// SAFETY: the db belongs to the live handle, n is valid
		let p = unsafe { alpm_db_get_pkg(self.local, n.as_ptr()) };
		if p.is_null() {
			// SAFETY: live handle
			let errno = unsafe { alpm_errno(self.h) };
			panic!("no package {name:?}: errno {errno}");
		}
		p
	}

	// alpm_pkg_mtree_open + next until it stops; None where open
	// returns NULL ("no mtree file")
	pub fn mtree(&self, name: &[u8]) -> Option<CMtree> {
		let pkg = self.pkg(name);
		// SAFETY: pkg is a live local package; the archive is read to
		// its end (or error) and closed, entries are copied out while
		// valid
		unsafe {
			let a = alpm_pkg_mtree_open(pkg);
			if a.is_null() {
				return None;
			}
			let mut entries = Vec::new();
			let mut e = ptr::null_mut();
			let end = loop {
				let r = alpm_pkg_mtree_next(pkg, a, &mut e);
				if r != 0 {
					break r;
				}
				entries.push(read_entry(e));
			};
			let error = opt_bytes(archive_error_string(a));
			alpm_pkg_mtree_close(pkg, a);
			Some(CMtree {
				entries,
				end,
				error,
			})
		}
	}

	pub fn fast(
		&self,
		name: &[u8],
		quiet: bool,
		logmask: u16,
		colstr: &ColStr,
	) -> CCheck {
		let pkg = self.pkg(name);
		let mut ret = 0;
		// SAFETY: pkg is live, config->handle is its handle
		let (stdout_, stderr_) =
			capture2(self.h, quiet, logmask, colstr, || unsafe {
				ret = check_pkg_fast(pkg)
			});
		CCheck {
			ret,
			stdout: stdout_,
			stderr: stderr_,
		}
	}

	// C preconditions, checked on the C reader's own entries: every link
	// entry has a target (strcmp on NULL, check.c:145) and every file a
	// sha256 pointer (hex_representation reads it, check.c:226). a
	// missing .INSTALL/.CHANGELOG db copy is matched against NoExtract
	// at filepath + strlen(root): the db path must be at least that long
	// (check.c:34, 351), which "<dbpath>local/" guarantees here
	pub fn full(
		&self,
		name: &[u8],
		quiet: bool,
		logmask: u16,
		colstr: &ColStr,
	) -> CCheck {
		// SAFETY: live handle, both strings owned by it
		let (root, dbpath) = unsafe {
			(
				CStr::from_ptr(alpm_option_get_root(self.h)),
				CStr::from_ptr(alpm_option_get_dbpath(self.h)),
			)
		};
		let (rootlen, dblen) =
			(root.to_bytes().len(), dbpath.to_bytes().len());
		assert!(dblen + 6 >= rootlen, "db file path shorter than root");
		if let Some(m) = self.mtree(name) {
			for e in &m.entries {
				if e.filetype == AE_IFLNK {
					assert!(
						e.link.is_some(),
						"NULL link {e:?}"
					);
				}
				if e.filetype == AE_IFREG {
					assert!(
						e.sha256.is_some(),
						"NULL sha {e:?}"
					);
				}
			}
		}
		let pkg = self.pkg(name);
		let mut ret = 0;
		// SAFETY: pkg is live, config->handle is its handle, the mtree
		// preconditions hold
		let (stdout_, stderr_) =
			capture2(self.h, quiet, logmask, colstr, || unsafe {
				ret = check_pkg_full(pkg)
			});
		CCheck {
			ret,
			stdout: stdout_,
			stderr: stderr_,
		}
	}
}

impl Drop for CheckWorld {
	fn drop(&mut self) {
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h came from alpm_initialize, nothing of it is used
		// afterwards
		unsafe { alpm_release(self.h) };
	}
}
