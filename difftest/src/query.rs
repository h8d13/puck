// C side of src/pacman/query.c and deptest.c (frontend objects, see
// build.rs)
//
// a QueryWorld owns a real handle on a fixture root the test wrote (local
// db, sync db files, package files, installed files). pacman_query and
// pacman_deptest read the global config (op_q_* flags, group, quiet,
// logmask, colstr, handle), print to the C stdout and through pm_printf
// to the C stderr: both are swapped for open_memstreams under FRONTEND,
// like check.rs. getcols() reads COLUMNS (cache reset per run), -Qo's
// search_path reads PATH, dates go through localtime with TZ=UTC: all
// three are set for the run and put back.
use std::ffi::{OsString, c_int, c_void};
use std::ptr;

use pacman_cli::conf::{ColStr, Config};

use crate::cli_util::{FRONTEND, config, init};
use crate::conf::ColStrC;
use crate::handle::{
	ALPM, alpm_db_set_usage, alpm_initialize, alpm_option_add_ignoregroup,
	alpm_option_add_ignorepkg, alpm_option_add_noextract,
	alpm_register_syncdb, alpm_release,
};
use crate::pkg_show::{columns_cache_reset, utc};
use crate::{
	CList, alpm_list_add, alpm_list_free, c_free, cstr, fclose, fflush,
	open_memstream, stderr, stdout,
};

unsafe extern "C" {
	fn pacman_query(targets: *mut CList) -> c_int;
	fn pacman_deptest(targets: *mut CList) -> c_int;
}

// return value and both streams of one run
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CQuery {
	pub ret: i32,
	pub stdout: Vec<u8>,
	pub stderr: Vec<u8>,
}

pub struct QueryWorld {
	h: *mut c_void,
}

// the process environment of one run, put back on drop
struct EnvVars(Vec<(&'static str, Option<OsString>)>);

impl EnvVars {
	// SAFETY (callers): FRONTEND held, no C code reads the environment
	// concurrently
	unsafe fn set(vars: &[(&'static str, &[u8])]) -> Self {
		use std::os::unix::ffi::OsStrExt;
		let old = vars.iter().map(|(k, _)| (*k, std::env::var_os(k)));
		let old = EnvVars(old.collect());
		for (k, v) in vars {
			// SAFETY: see above
			unsafe {
				std::env::set_var(
					k,
					std::ffi::OsStr::from_bytes(v),
				)
			};
		}
		old
	}
}

impl Drop for EnvVars {
	fn drop(&mut self) {
		for (k, v) in &self.0 {
			// SAFETY: dropped while FRONTEND is still held (declared
			// after the guard in run)
			unsafe {
				match v {
					Some(v) => std::env::set_var(k, v),
					None => std::env::remove_var(k),
				}
			}
		}
	}
}

fn colstr_c(c: &[std::ffi::CString; 10]) -> ColStrC {
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
	}
}

fn colstr_strings(c: &ColStr) -> [std::ffi::CString; 10] {
	[
		c.colon, c.title, c.repo, c.version, c.groups, c.meta, c.warn,
		c.err, c.faint, c.nocolor,
	]
	.map(cstr)
}

impl QueryWorld {
	// alpm_initialize on root and dbpath (existing dirs), then what
	// setup_libalpm takes from cfg here: IgnorePkg, IgnoreGroup,
	// NoExtract, and the repos registered in order with siglevel 0 and
	// their usage
	pub fn open(root: &[u8], dbpath: &[u8], cfg: &Config) -> Self {
		let (root, dbpath) = (cstr(root), cstr(dbpath));
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let mut err = 0;
		// SAFETY: valid C strings, err is writable; the handle copies
		// every string
		unsafe {
			let h = alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			);
			assert!(!h.is_null(), "alpm_initialize: {err}");
			for p in &cfg.ignorepkg {
				alpm_option_add_ignorepkg(h, cstr(p).as_ptr());
			}
			for g in &cfg.ignoregrp {
				alpm_option_add_ignoregroup(
					h,
					cstr(g).as_ptr(),
				);
			}
			for p in &cfg.noextract {
				alpm_option_add_noextract(h, cstr(p).as_ptr());
			}
			for r in &cfg.repos {
				let n = cstr(&r.name);
				let db = alpm_register_syncdb(h, n.as_ptr(), 0);
				assert!(!db.is_null(), "register {:?}", r.name);
				alpm_db_set_usage(db, r.usage);
			}
			QueryWorld { h }
		}
	}

	// f(targets list) with config set from cfg and both streams
	// captured
	fn run(
		&self,
		cfg: &Config,
		targets: &[Vec<u8>],
		cols: u16,
		path: &[u8],
		f: unsafe extern "C" fn(*mut CList) -> c_int,
	) -> CQuery {
		init();
		let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
		let strs: Vec<_> = targets.iter().map(|t| cstr(t)).collect();
		let list = strs.iter().fold(ptr::null_mut(), |l, s| {
			// SAFETY: l is NULL or from alpm_list_add, the strings
			// outlive the list; the C only reads them
			unsafe {
				alpm_list_add(l, s.as_ptr().cast_mut().cast())
			}
		});
		let c = colstr_strings(&cfg.colstr);
		let cols = cols.to_string();
		// SAFETY: FRONTEND is held: nothing else reads the environment
		// from C or touches config meanwhile
		let _env = unsafe {
			EnvVars::set(&[
				("COLUMNS", cols.as_bytes()),
				("PATH", path),
			])
		};
		let (mut obuf, mut osize) = (ptr::null_mut(), 0usize);
		let (mut ebuf, mut esize) = (ptr::null_mut(), 0usize);
		// SAFETY: FRONTEND serializes every access to config, stdout and
		// stderr. config is valid after init; the colstr strings outlive
		// the call and the old colstr is put back before they drop. the
		// memstreams replace the streams only while f runs, their
		// buffers are malloc'd and valid for size bytes after fclose
		unsafe {
			utc();
			columns_cache_reset();
			let cf = &mut *config;
			let old =
				std::mem::replace(&mut cf.colstr, colstr_c(&c));
			let old_logmask = cf.logmask;
			cf.handle = self.h;
			cf.quiet = cfg.quiet;
			cf.logmask = cfg.logmask;
			cf.op_q_isfile = cfg.op_q_isfile;
			cf.op_q_info = cfg.op_q_info;
			cf.op_q_list = cfg.op_q_list;
			cf.op_q_unrequired = cfg.op_q_unrequired;
			cf.op_q_deps = cfg.op_q_deps;
			cf.op_q_explicit = cfg.op_q_explicit;
			cf.op_q_owns = cfg.op_q_owns;
			cf.op_q_search = cfg.op_q_search;
			cf.op_q_changelog = cfg.op_q_changelog;
			cf.op_q_upgrade = cfg.op_q_upgrade;
			cf.op_q_check = cfg.op_q_check;
			cf.op_q_locality = cfg.op_q_locality;
			cf.group = cfg.group;
			let out = open_memstream(&mut obuf, &mut osize);
			let err = open_memstream(&mut ebuf, &mut esize);
			assert!(!out.is_null() && !err.is_null());
			let (real_out, real_err) = (stdout, stderr);
			fflush(real_out);
			fflush(real_err);
			stdout = out;
			stderr = err;
			let ret = f(list);
			fflush(out);
			fflush(err);
			stdout = real_out;
			stderr = real_err;
			fclose(out);
			fclose(err);
			cf.colstr = old;
			cf.handle = ptr::null_mut();
			cf.quiet = 0;
			cf.logmask = old_logmask;
			cf.op_q_isfile = 0;
			cf.op_q_info = 0;
			cf.op_q_list = 0;
			cf.op_q_unrequired = 0;
			cf.op_q_deps = 0;
			cf.op_q_explicit = 0;
			cf.op_q_owns = 0;
			cf.op_q_search = 0;
			cf.op_q_changelog = 0;
			cf.op_q_upgrade = 0;
			cf.op_q_check = 0;
			cf.op_q_locality = 0;
			cf.group = 0;
			alpm_list_free(list);
			let o = std::slice::from_raw_parts(
				obuf.cast::<u8>(),
				osize,
			)
			.to_vec();
			let e = std::slice::from_raw_parts(
				ebuf.cast::<u8>(),
				esize,
			)
			.to_vec();
			c_free(obuf.cast());
			c_free(ebuf.cast());
			CQuery {
				ret,
				stdout: o,
				stderr: e,
			}
		}
	}

	// pacman_query(targets) with cfg's -Q flags, quiet, logmask and
	// colours, COLUMNS=cols and PATH=path. C preconditions (callers):
	// PATH's first entry neither empty nor only '/' (search_path reads
	// before the buffer), targets and resolved paths far below PATH_MAX
	// (strcpy into rpath), no .sig next to -Qp files (gpgme), no backup
	// entry naming a directory for -Qii (strlen(NULL)), mtree link
	// entries with a target and files with a sha256 (check.c)
	pub fn query(
		&self,
		cfg: &Config,
		targets: &[Vec<u8>],
		cols: u16,
		path: &[u8],
	) -> CQuery {
		assert!(
			!path.is_empty()
				&& !path.split(|&b| b == b':')
					.next()
					.unwrap()
					.iter()
					.all(|&b| b == b'/'),
			"PATH {path:?}"
		);
		self.run(cfg, targets, cols, path, pacman_query)
	}

	// pacman_deptest(targets)
	pub fn deptest(&self, targets: &[Vec<u8>]) -> CQuery {
		let cfg = Config::new();
		self.run(&cfg, targets, 80, b"/usr/bin", pacman_deptest)
	}
}

impl Drop for QueryWorld {
	fn drop(&mut self) {
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h came from alpm_initialize, nothing of it is used
		// afterwards
		unsafe { alpm_release(self.h) };
	}
}
