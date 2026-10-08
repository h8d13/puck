// C side of the read-only ops of src/pacman/sync.c (frontend objects, see
// build.rs) on fixtures::SyncWorld
//
// pacman_sync reads config (flags, colstr, logmask, handle) and prints to
// the C stdout and, through pm_printf, to stderr. a FrontHandle is a real
// handle on a fixture root with its sync dbs registered (siglevel 0, the
// dbext set first like setup_libalpm). each run holds FRONTEND, puts the
// handle and the flags of a pacman_cli Config into `config`, swaps both
// streams for open_memstreams and puts everything back afterwards. only
// flags that keep pacman_sync away from transactions, downloads and the
// cache dirs are accepted (asserted before the call).
use std::ffi::{CString, c_int, c_void};
use std::ptr;

use pacman_cli::conf::Config;

use crate::cli_util::{FRONTEND, config, init};
use crate::conf::ColStrC;
use crate::fixtures::SyncWorld;
use crate::handle::{
	ALPM, CDb, alpm_db_get_pkgcache, alpm_errno, alpm_initialize,
	alpm_option_set_dbext, alpm_register_syncdb, alpm_release,
};
use crate::pkg_show::{c_strftime_c, columns_cache_reset};
use crate::{
	CList, alpm_list_add, alpm_list_free, c_free, cstr, fclose, fflush,
	open_memstream, stderr, stdout,
};

unsafe extern "C" {
	pub(crate) fn pacman_sync(targets: *mut CList) -> c_int;
}

// a real handle on a fixture, released on drop
pub struct FrontHandle {
	h: *mut c_void,
	dbs: Vec<*mut CDb>,
}

impl FrontHandle {
	// alpm_initialize on root/dbpath (existing dirs), dbext set, then
	// repos registered in order without signature checks
	pub fn open(
		root: &[u8],
		dbpath: &[u8],
		dbext: &[u8],
		repos: &[&str],
	) -> Self {
		let (root, dbpath, ext) =
			(cstr(root), cstr(dbpath), cstr(dbext));
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let mut err = 0;
		// SAFETY: valid C strings, err is writable; the handle copies
		// dbext and the names
		unsafe {
			let h = alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			);
			assert!(!h.is_null(), "alpm_initialize: {err}");
			assert_eq!(alpm_option_set_dbext(h, ext.as_ptr()), 0);
			let dbs = repos
				.iter()
				.map(|r| {
					let n = cstr(r.as_bytes());
					let db = alpm_register_syncdb(
						h,
						n.as_ptr(),
						0,
					);
					assert!(
						!db.is_null(),
						"register {r}: {}",
						alpm_errno(h)
					);
					db
				})
				.collect();
			FrontHandle { h, dbs }
		}
	}

	// the handle and its dbs in registration order, for callers setting
	// more options on them
	pub(crate) fn raw(&self) -> (*mut c_void, &[*mut CDb]) {
		(self.h, &self.dbs)
	}

	// alpm_db_get_pkgcache on every sync db, so a broken db file is
	// already marked invalid when the op starts
	pub fn warm(&self) {
		for &db in &self.dbs {
			// SAFETY: db belongs to the live handle
			unsafe { alpm_db_get_pkgcache(db) };
		}
	}
}

impl Drop for FrontHandle {
	fn drop(&mut self) {
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h came from alpm_initialize, no transaction, nothing
		// of it is used afterwards
		unsafe { alpm_release(self.h) };
	}
}

// what an op returned and printed
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CRun {
	pub ret: i32,
	pub stdout: Vec<u8>,
	pub stderr: Vec<u8>,
}

// the first line where two outputs part, with the lines before it
fn first_diff(what: &str, a: &[u8], b: &[u8]) -> Option<String> {
	if a == b {
		return None;
	}
	let la: Vec<&[u8]> = a.split_inclusive(|&c| c == b'\n').collect();
	let lb: Vec<&[u8]> = b.split_inclusive(|&c| c == b'\n').collect();
	let i = la.iter().zip(&lb).take_while(|(x, y)| x == y).count();
	let show = |l: &[&[u8]]| -> String {
		let from = i.saturating_sub(3);
		let to = (i + 3).min(l.len());
		l[from..to]
			.iter()
			.map(|x| format!("{:?}\n", String::from_utf8_lossy(x)))
			.collect()
	};
	Some(format!(
		"{what} differs at line {i}\nC:\n{}Rust:\n{}",
		show(&la),
		show(&lb)
	))
}

impl CRun {
	// None when equal, else what differs (C self, Rust other)
	pub fn diff(&self, other: &CRun) -> Option<String> {
		let parts = [
			(self.ret != other.ret).then(|| {
				format!("ret C {} Rust {}", self.ret, other.ret)
			}),
			first_diff("stdout", &self.stdout, &other.stdout),
			first_diff("stderr", &self.stderr, &other.stderr),
		];
		let d: Vec<String> = parts.into_iter().flatten().collect();
		(!d.is_empty()).then(|| d.join("\n"))
	}
}

// the config_t fields sync.c, files.c and database.c read, besides handle
// and colstr
#[derive(Clone, Copy)]
struct Flags {
	quiet: u16,
	noprogressbar: u16,
	logmask: u16,
	op_q_list: u16,
	op_s_clean: u16,
	op_s_info: u16,
	op_s_sync: u16,
	op_s_search: u16,
	op_s_upgrade: u16,
	op_f_regex: u16,
	op_f_machinereadable: u16,
	group: u16,
	op_q_check: u16,
	flags: c_int,
}

impl Flags {
	fn of(c: &Config) -> Flags {
		Flags {
			quiet: c.quiet,
			noprogressbar: c.noprogressbar,
			logmask: c.logmask,
			op_q_list: c.op_q_list,
			op_s_clean: c.op_s_clean,
			op_s_info: c.op_s_info,
			op_s_sync: c.op_s_sync,
			op_s_search: c.op_s_search,
			op_s_upgrade: c.op_s_upgrade,
			op_f_regex: c.op_f_regex,
			op_f_machinereadable: c.op_f_machinereadable,
			group: c.group,
			op_q_check: c.op_q_check,
			flags: c.flags,
		}
	}

	// SAFETY (callers): FRONTEND held, config valid
	unsafe fn swap(self) -> Flags {
		// SAFETY: see above
		let c = unsafe { &mut *config };
		let old = Flags {
			quiet: c.quiet,
			noprogressbar: c.noprogressbar,
			logmask: c.logmask,
			op_q_list: c.op_q_list,
			op_s_clean: c.op_s_clean,
			op_s_info: c.op_s_info,
			op_s_sync: c.op_s_sync,
			op_s_search: c.op_s_search,
			op_s_upgrade: c.op_s_upgrade,
			op_f_regex: c.op_f_regex,
			op_f_machinereadable: c.op_f_machinereadable,
			group: c.group,
			op_q_check: c.op_q_check,
			flags: c.flags,
		};
		c.quiet = self.quiet;
		c.noprogressbar = self.noprogressbar;
		c.logmask = self.logmask;
		c.op_q_list = self.op_q_list;
		c.op_s_clean = self.op_s_clean;
		c.op_s_info = self.op_s_info;
		c.op_s_sync = self.op_s_sync;
		c.op_s_search = self.op_s_search;
		c.op_s_upgrade = self.op_s_upgrade;
		c.op_f_regex = self.op_f_regex;
		c.op_f_machinereadable = self.op_f_machinereadable;
		c.group = self.group;
		c.op_q_check = self.op_q_check;
		c.flags = self.flags;
		old
	}
}

// runs op(targets) with config set from cfg, config->handle = fh and
// COLUMNS = cols (getcols), both C streams captured. TZ=UTC for the
// dates of -Si
pub(crate) fn run_op<S: AsRef<[u8]>>(
	fh: &FrontHandle,
	cfg: &Config,
	cols: u16,
	targets: &[S],
	op: unsafe extern "C" fn(*mut CList) -> c_int,
) -> CRun {
	init();
	// sets TZ=UTC once, takes FRONTEND itself
	c_strftime_c(0);
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	let cs = &cfg.colstr;
	let c = [
		cs.colon, cs.title, cs.repo, cs.version, cs.groups, cs.meta,
		cs.warn, cs.err, cs.faint, cs.nocolor,
	]
	.map(cstr);
	let targs: Vec<CString> =
		targets.iter().map(|t| cstr(t.as_ref())).collect();
	let (mut obuf, mut osize) = (ptr::null_mut(), 0usize);
	let (mut ebuf, mut esize) = (ptr::null_mut(), 0usize);
	// SAFETY: FRONTEND serializes every access to config, stdout,
	// stderr and the environment from C. config is valid after init;
	// the colstr strings and targets outlive the call, the old colstr
	// (static literals) and flags are put back before they drop. the
	// target list nodes are freed after, the strings stay ours (sync.c
	// and files.c only read or strdup them). the memstreams replace the
	// streams only while op runs, their buffers are malloc'd and valid
	// for size bytes after fclose
	unsafe {
		std::env::set_var("COLUMNS", cols.to_string());
		columns_cache_reset();
		let mut list: *mut CList = ptr::null_mut();
		for t in &targs {
			list = alpm_list_add(
				list,
				t.as_ptr().cast_mut().cast(),
			);
		}
		let old_colstr = std::mem::replace(
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
		let old_flags = Flags::of(cfg).swap();
		(*config).handle = fh.h;
		let out = open_memstream(&mut obuf, &mut osize);
		let err = open_memstream(&mut ebuf, &mut esize);
		assert!(!out.is_null() && !err.is_null());
		let (real_out, real_err) = (stdout, stderr);
		fflush(real_out);
		fflush(real_err);
		stdout = out;
		stderr = err;
		let ret = op(list);
		fflush(out);
		fflush(err);
		stdout = real_out;
		stderr = real_err;
		fclose(out);
		fclose(err);
		(*config).handle = ptr::null_mut();
		old_flags.swap();
		(*config).colstr = old_colstr;
		alpm_list_free(list);
		let o = std::slice::from_raw_parts(obuf.cast::<u8>(), osize)
			.to_vec();
		let e = std::slice::from_raw_parts(ebuf.cast::<u8>(), esize)
			.to_vec();
		c_free(obuf.cast());
		c_free(ebuf.cast());
		CRun {
			ret,
			stdout: o,
			stderr: e,
		}
	}
}

// pacman_sync reaches only -Ss, -Sg, -Si, -Sl or the "no targets" error
// with these flags: no -Sc (trans_init, cache dirs), -Sy (downloads) or
// sync_trans
pub fn sync_read_only<S>(cfg: &Config, targets: &[S]) -> bool {
	let op = cfg.group != 0
		|| cfg.op_s_info != 0
		|| cfg.op_q_list != 0
		|| cfg.op_s_search != 0;
	cfg.op_s_clean == 0
		&& cfg.op_s_sync == 0
		&& (op || (targets.is_empty() && cfg.op_s_upgrade == 0))
}

// pacman_sync(targets) on fh. C preconditions: sync_read_only, and the
// dump_pkg_full ones of PkgWorld::dump_full for every package -Si shows
// (the generated worlds keep to them: dates localtime takes, no ESC,
// no %PGPSIG%)
pub fn c_pacman_sync<S: AsRef<[u8]>>(
	fh: &FrontHandle,
	cfg: &Config,
	targets: &[S],
	cols: u16,
) -> CRun {
	assert!(sync_read_only(cfg, targets), "op would leave read-only");
	run_op(fh, cfg, cols, targets, pacman_sync)
}

// the C side of a fixtures::SyncWorld
impl SyncWorld {
	// C handle on this world with dbext
	pub fn c_handle(&self, dbext: &[u8]) -> FrontHandle {
		FrontHandle::open(
			&self.fx.root(),
			&self.fx.dbpath(),
			dbext,
			&self.repos,
		)
	}
}
