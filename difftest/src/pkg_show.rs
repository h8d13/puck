// C side of src/pacman/package.c, from the frontend objects (see build.rs)
//
// the displays ask libalpm through config->handle and the package's own
// handle: reverse dependencies walk db caches, sync packages name their
// db, -ii reads files under the root. so each PkgWorld owns a real
// handle on a fresh /tmp fixture (root, empty local db, empty sync dbs
// "core" and "extra"), whose caches are refilled from Rust packages per
// case. displayed packages are mirror-built with that handle and origin
// db. stdout is captured like cli_util, under FRONTEND, with TZ=UTC and
// COLUMNS set for getcols.
use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Once;

use alpm_core::deps::dep_compute_string;
use alpm_core::package::{Package, PkgFrom};
use pacman_cli::package::format_date_at;
use pacman_cli::util::ColStr;

use crate::cli_util::{capture, config};
use crate::deps::alpm_find_satisfier;
use crate::handle::{
	_alpm_db_add_pkgincache, _alpm_db_free_pkgcache, ALPM, CDb,
	alpm_db_get_pkgcache, alpm_errno, alpm_initialize,
	alpm_option_get_root, alpm_register_syncdb, alpm_release,
};
use crate::package::{
	CPkg, CPkgBox, alpm_pkg_compute_optionalfor,
	alpm_pkg_compute_requiredby, take_strs,
};
use crate::{CList, cstr, string_length_in_bounds};

// struct tm of glibc time.h
#[repr(C)]
pub(crate) struct Tm {
	pub(crate) tm_sec: c_int,
	pub(crate) tm_min: c_int,
	pub(crate) tm_hour: c_int,
	pub(crate) tm_mday: c_int,
	pub(crate) tm_mon: c_int,
	pub(crate) tm_year: c_int,
	pub(crate) tm_wday: c_int,
	pub(crate) tm_yday: c_int,
	pub(crate) tm_isdst: c_int,
	pub(crate) tm_gmtoff: c_long,
	pub(crate) tm_zone: *const c_char,
}

unsafe extern "C" {
	fn tzset();
	fn localtime_r(t: *const i64, tm: *mut Tm) -> *mut Tm;
	pub(crate) fn strftime(
		s: *mut c_char,
		max: usize,
		format: *const c_char,
		tm: *const Tm,
	) -> usize;

	pub(crate) fn columns_cache_reset();
	fn dump_pkg_full(pkg: *mut CPkg, extra: c_int);
	fn dump_pkg_backups(pkg: *mut CPkg, cols: u16);
	fn dump_pkg_files(pkg: *mut CPkg, quiet: c_int);
	fn print_installed(db_local: *mut CDb, pkg: *mut CPkg);
	fn print_groups(pkg: *mut CPkg);
	fn dump_pkg_search(
		db: *mut CDb,
		targets: *mut CList,
		show_status: c_int,
	) -> c_int;

}

pub const SYNC_DBS: [&str; 2] = ["core", "extra"];

// TZ for localtime, set once before any date is formatted. callers hold
// FRONTEND (inside capture)
pub(crate) fn utc() {
	static ONCE: Once = Once::new();
	ONCE.call_once(|| {
		// SAFETY: FRONTEND is held, no C code reads the environment
		// concurrently; tzset rereads TZ
		unsafe {
			std::env::set_var("TZ", "UTC");
			tzset();
		}
	});
}

// glibc localtime_r with TZ=UTC, then strftime("%c") into the 50 bytes
// dump_pkg_full uses. None where localtime fails
pub fn c_strftime_c(t: i64) -> Option<Vec<u8>> {
	let mut res = None;
	capture(&ColStr::default(), || {
		utc();
		// SAFETY: tm is written by localtime_r, buf holds max bytes
		unsafe {
			let mut tm: Tm = std::mem::zeroed();
			if localtime_r(&t, &mut tm).is_null() {
				return;
			}
			let mut buf = [0 as c_char; 50];
			let n = strftime(
				buf.as_mut_ptr(),
				50,
				c"%c".as_ptr(),
				&tm,
			);
			let s = std::slice::from_raw_parts(
				buf.as_ptr().cast(),
				n,
			);
			res = Some(s.to_vec());
		}
	});
	res
}

// TZ=UTC for the whole process, the port's localtime included (glibc
// state). before a Rust side formats a date in-process
pub fn tz_utc() {
	c_strftime_c(0);
}

// the port's strftime("%c", localtime(&t)) under TZ=UTC, for Rust sides
// compared against c_strftime_c
pub fn utc_date(t: i64) -> Option<Vec<u8>> {
	format_date_at(t, 0)
}

// dump_pkg_full passes localtime's result to strftime unchecked
fn localtime_ok(t: i64) -> bool {
	t == -1 || c_strftime_c(t).is_some()
}

// what dump_pkg_full printed, and the values it got from libalpm,
// fetched through the same calls on the same package just before
#[derive(Debug)]
pub struct CShown {
	pub out: Vec<u8>,
	// alpm_pkg_compute_requiredby/optionalfor, empty when not asked
	pub required_by: Vec<Vec<u8>>,
	pub optional_for: Vec<Vec<u8>>,
	// optdepend strings alpm_find_satisfier finds in the local cache
	pub installed: Vec<Vec<u8>>,
}

pub struct PkgWorld {
	pub(crate) dir: PathBuf,
	pub(crate) h: *mut c_void,
	pub(crate) local: *mut CDb,
	pub(crate) sync: [*mut CDb; 2],
	root: Vec<u8>,
}

fn path_c(p: &Path) -> CString {
	cstr(p.as_os_str().as_bytes())
}

impl PkgWorld {
	// dir must not exist yet, removed again on drop
	pub fn new(dir: &Path) -> Self {
		fs::create_dir(dir).unwrap();
		fs::create_dir(dir.join("root")).unwrap();
		fs::create_dir_all(dir.join("db/sync")).unwrap();
		for db in SYNC_DBS {
			// an empty file loads as an empty sync db
			fs::write(dir.join(format!("db/sync/{db}.db")), b"")
				.unwrap();
		}
		let root = path_c(&dir.join("root"));
		let dbpath = path_c(&dir.join("db"));
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let mut err = 0;
		// SAFETY: valid C strings, err is writable
		let h = unsafe {
			alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			)
		};
		assert!(!h.is_null(), "alpm_initialize: {err}");
		// SAFETY: h is live; names are valid, siglevel 0 skips all
		// signature checks; root is a string owned by the handle
		unsafe {
			let sync = SYNC_DBS.map(|n| {
				let n = cstr(n.as_bytes());
				let db = alpm_register_syncdb(h, n.as_ptr(), 0);
				assert!(
					!db.is_null(),
					"register: {}",
					alpm_errno(h)
				);
				db
			});
			let local = crate::handle::alpm_get_localdb(h);
			assert!(!local.is_null());
			let root = CStr::from_ptr(alpm_option_get_root(h));
			PkgWorld {
				dir: dir.to_path_buf(),
				h,
				local,
				sync,
				root: root.to_bytes().to_vec(),
			}
		}
	}

	// the handle's root, with its trailing '/'
	pub fn root(&self) -> &[u8] {
		&self.root
	}

	// replaces the db caches: local, then core and extra. names unique
	// per db
	pub fn set_caches(&mut self, local: &[Package], sync: [&[Package]; 2]) {
		let dbs = [self.local, self.sync[0], self.sync[1]];
		let lists = [local, sync[0], sync[1]];
		for (db, pkgs) in dbs.into_iter().zip(lists) {
			// SAFETY: db belongs to the live handle; the reload reads
			// the fixture (no package dirs, empty sync files) and sets
			// DB_STATUS_PKGCACHE, add_pkgincache dups each package
			unsafe {
				_alpm_db_free_pkgcache(db);
				alpm_db_get_pkgcache(db);
				assert_eq!(alpm_errno(self.h), 0);
				for p in pkgs {
					assert!(p.name.is_some());
					let b = self.c_pkg(p, 0);
					assert_eq!(
						_alpm_db_add_pkgincache(
							db, b.0
						),
						0
					);
				}
			}
		}
	}

	// mirror-built package on this handle, origin_data pointing at its
	// db (sync: SYNC_DBS[db])
	pub(crate) fn c_pkg(&self, pkg: &Package, db: usize) -> CPkgBox {
		let b = CPkgBox::new(pkg);
		// SAFETY: b.0 is live and owned here; db origins keep no
		// origin_data of their own, so nothing leaks
		unsafe {
			(*b.0).handle = self.h;
			match pkg.origin {
				Some(PkgFrom::LocalDb) => {
					(*b.0).origin_data = self.local.cast()
				}
				Some(PkgFrom::SyncDb) => {
					(*b.0).origin_data =
						self.sync[db].cast()
				}
				_ => {}
			}
		}
		b
	}

	// runs f with stdout captured, config->handle, config->quiet and
	// COLUMNS (getcols) set
	fn show(
		&self,
		cols: u16,
		quiet: bool,
		colstr: &ColStr,
		f: impl FnOnce(),
	) -> Vec<u8> {
		capture(colstr, || {
			utc();
			// SAFETY: FRONTEND is held by capture: nothing else reads
			// the environment from C or touches config meanwhile
			unsafe {
				std::env::set_var("COLUMNS", cols.to_string());
				columns_cache_reset();
				(*config).handle = self.h;
				(*config).quiet = u16::from(quiet);
				f();
				(*config).handle = ptr::null_mut();
				(*config).quiet = 0;
			}
		})
	}

	// C preconditions: name set (strcmp in _alpm_depcmp); no unset
	// origin with extra (compute_requiredby reads origin_data.db); dates
	// localtime can take; list items string_length can take (see
	// UPSTREAM.md); file packages without base64_sig, filename a readable
	// file without .sig: the C reaches neither gpgme (keyring, gpg
	// processes) nor the early return that leaves its siglist
	// uninitialized. sync -ii: base64_sig invalid or decoding to
	// well-formed signature packets, alpm_extract_keyid is not fuzzed
	// here. local -ii: no backup path is a directory (md5 failure, the
	// C passes NULL to strlen)
	pub fn dump_full(
		&self,
		pkg: &Package,
		db: usize,
		extra: bool,
		cols: u16,
		colstr: &ColStr,
	) -> CShown {
		self.assert_full(pkg, extra);
		let b = self.c_pkg(pkg, db);
		let local = pkg.origin == Some(PkgFrom::LocalDb);
		let (mut required_by, mut optional_for) =
			(Vec::new(), Vec::new());
		if extra || local {
			// SAFETY: b.0 is live with a handle and a db or file origin
			unsafe {
				required_by = take_strs(
					alpm_pkg_compute_requiredby(b.0),
				);
				optional_for = take_strs(
					alpm_pkg_compute_optionalfor(b.0),
				);
			}
		}
		let mut installed = Vec::new();
		if local {
			// SAFETY: the local cache is loaded, the list stays its own
			let cache = unsafe { alpm_db_get_pkgcache(self.local) };
			for d in &pkg.optdepends {
				let s = dep_compute_string(d);
				let c = cstr(&s);
				// SAFETY: cache is a live list, c a valid C string
				if !unsafe {
					alpm_find_satisfier(cache, c.as_ptr())
				}
				.is_null()
				{
					installed.push(s);
				}
			}
		}
		// SAFETY: b.0 is live, preconditions checked above
		let out = self.show(cols, false, colstr, || unsafe {
			dump_pkg_full(b.0, c_int::from(extra))
		});
		CShown {
			out,
			required_by,
			optional_for,
			installed,
		}
	}

	fn assert_full(&self, pkg: &Package, extra: bool) {
		assert!(pkg.name.is_some(), "C strcmp on a NULL name");
		assert!(pkg.origin.is_some() || !extra, "NULL origin db");
		for t in [pkg.builddate, pkg.installdate] {
			assert!(localtime_ok(t), "localtime fails on {t}");
		}
		let deps = [
			&pkg.provides,
			&pkg.depends,
			&pkg.conflicts,
			&pkg.replaces,
		];
		let items = pkg.licenses.iter().chain(&pkg.groups);
		let items = items.map(|s| s.to_vec());
		let deps = deps.into_iter().flatten().map(dep_compute_string);
		let items = items.chain(deps);
		for s in items {
			assert!(
				string_length_in_bounds(&s),
				"string_length {s:?}"
			);
		}
		if let Some(PkgFrom::File(_)) = &pkg.origin {
			assert!(pkg.base64_sig.is_none(), "gpgme reached");
			let f = pkg.filename.as_deref().expect("NULL filename");
			let f = Path::new(std::ffi::OsStr::from_bytes(f));
			assert!(fs::File::open(f).is_ok(), "{f:?} unreadable");
			let mut sig = f.as_os_str().to_owned();
			sig.push(".sig");
			assert!(!Path::new(&sig).exists(), "gpgme reached");
		}
		if pkg.origin == Some(PkgFrom::LocalDb) && extra {
			self.assert_backups(pkg);
		}
	}

	fn assert_backups(&self, pkg: &Package) {
		for b in pkg.backup.iter().filter(|b| b.hash.is_some()) {
			let p = [&self.root[..], &b.name].concat();
			assert!(p.len() < 4096, "PATH_MAX");
			let p = Path::new(std::ffi::OsStr::from_bytes(&p));
			assert!(
				!p.is_dir(),
				"md5 of a directory: C strlen(NULL)"
			);
		}
	}

	// C preconditions as for dump_full with extra on a local package.
	// the titles are only built by dump_pkg_full, so that runs once
	// first, as in pacman where it is the only caller
	pub fn dump_backups(
		&self,
		pkg: &Package,
		cols: u16,
		colstr: &ColStr,
	) -> Vec<u8> {
		self.assert_backups(pkg);
		static TITLES: Once = Once::new();
		TITLES.call_once(|| {
			self.dump_full(&named_pkg(), 0, false, 0, colstr);
		});
		let b = self.c_pkg(pkg, 0);
		// SAFETY: b.0 is live, no backup path is a directory
		self.show(cols, false, colstr, || unsafe {
			dump_pkg_backups(b.0, cols)
		})
	}

	// C precondition: name set unless quiet (printf %s)
	pub fn dump_files(
		&self,
		pkg: &Package,
		quiet: bool,
		colstr: &ColStr,
	) -> Vec<u8> {
		assert!(quiet || pkg.name.is_some(), "printf %s of NULL");
		let b = self.c_pkg(pkg, 0);
		// SAFETY: b.0 is live
		self.show(0, false, colstr, || unsafe {
			dump_pkg_files(b.0, c_int::from(quiet))
		})
	}

	// against the local cache. C precondition: versions set (strcmp)
	pub fn print_installed(
		&self,
		pkg: &Package,
		colstr: &ColStr,
	) -> Vec<u8> {
		assert!(pkg.version.is_some(), "strcmp on a NULL version");
		let b = self.c_pkg(pkg, 0);
		// SAFETY: b.0 and the local db are live
		self.show(0, false, colstr, || unsafe {
			print_installed(self.local, b.0)
		})
	}

	// dump_pkg_search without targets: the whole cache of SYNC_DBS[db].
	// C preconditions: cached names and versions set
	pub fn search(
		&self,
		db: usize,
		show_status: bool,
		quiet: bool,
		cols: u16,
		colstr: &ColStr,
	) -> (i32, Vec<u8>) {
		let mut ret = 0;
		// SAFETY: the db is live, targets NULL lists the cache
		let out = self.show(cols, quiet, colstr, || unsafe {
			ret = dump_pkg_search(
				self.sync[db],
				ptr::null_mut(),
				c_int::from(show_status),
			)
		});
		(ret, out)
	}
}

impl Drop for PkgWorld {
	fn drop(&mut self) {
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h came from alpm_initialize, nothing of it is used
		// afterwards
		unsafe { alpm_release(self.h) };
		fs::remove_dir_all(&self.dir).unwrap();
	}
}

// no origin, no dates: the least dump_pkg_full asks for
fn named_pkg() -> Package {
	Package {
		name: Some(b"x"[..].into()),
		builddate: -1,
		installdate: -1,
		..Package::default()
	}
}

// print_groups reads the package only
pub fn c_print_groups(pkg: &Package, colstr: &ColStr) -> Vec<u8> {
	let b = CPkgBox::new(pkg);
	// SAFETY: b.0 is live
	capture(colstr, || unsafe { print_groups(b.0) })
}
