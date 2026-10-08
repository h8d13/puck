// C handle and db items shared by the db modules (be_local, be_sync,
// pkghash, db): one declaration each, rustc flags clashing extern
// signatures
use std::ffi::{c_char, c_int, c_uint, c_void};
use std::sync::Mutex;

use crate::CList;
use crate::group::CGroup;
use crate::package::CPkg;

// alpm_pkghash_t, pkghash.h
#[repr(C)]
pub(crate) struct CHash {
	pub(crate) hash_table: *mut *mut CList,
	pub(crate) list: *mut CList,
	pub(crate) buckets: c_uint,
	pub(crate) entries: c_uint,
	pub(crate) limit: c_uint,
}

// leading fields of struct _alpm_db_t, db.h, up to pkgcache. only
// pkgcache is read, the others place it
#[repr(C)]
pub(crate) struct CDb {
	_handle: *mut c_void,
	_treename: *mut c_char,
	_path: *mut c_char,
	pub(crate) pkgcache: *mut CHash,
}

unsafe extern "C" {
	pub(crate) fn alpm_initialize(
		root: *const c_char,
		dbpath: *const c_char,
		err: *mut c_int,
	) -> *mut c_void;
	pub(crate) fn alpm_release(handle: *mut c_void) -> c_int;
	pub(crate) fn alpm_errno(handle: *mut c_void) -> c_int;
	pub(crate) fn alpm_get_localdb(handle: *mut c_void) -> *mut CDb;
	pub(crate) fn alpm_db_get_pkgcache(db: *mut CDb) -> *mut CList;
	pub(crate) fn _alpm_db_get_pkgcache_hash(db: *mut CDb) -> *mut CHash;
	pub(crate) fn alpm_register_syncdb(
		handle: *mut c_void,
		treename: *const c_char,
		siglevel: c_int,
	) -> *mut CDb;
	pub(crate) fn alpm_unregister_all_syncdbs(handle: *mut c_void)
	-> c_int;
	pub(crate) fn alpm_get_syncdbs(handle: *mut c_void) -> *mut CList;

	// handle options
	pub(crate) fn alpm_option_get_root(
		handle: *mut c_void,
	) -> *const c_char;
	pub(crate) fn alpm_option_get_dbpath(
		handle: *mut c_void,
	) -> *const c_char;
	pub(crate) fn alpm_option_get_dbext(
		handle: *mut c_void,
	) -> *const c_char;
	pub(crate) fn alpm_option_set_dbext(
		handle: *mut c_void,
		dbext: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_get_default_siglevel(
		handle: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_set_default_siglevel(
		handle: *mut c_void,
		level: c_int,
	) -> c_int;
	pub(crate) fn alpm_option_get_local_file_siglevel(
		handle: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_set_local_file_siglevel(
		handle: *mut c_void,
		level: c_int,
	) -> c_int;
	pub(crate) fn alpm_option_get_remote_file_siglevel(
		handle: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_set_remote_file_siglevel(
		handle: *mut c_void,
		level: c_int,
	) -> c_int;
	pub(crate) fn alpm_option_get_architectures(
		handle: *mut c_void,
	) -> *mut CList;
	pub(crate) fn alpm_option_add_architecture(
		handle: *mut c_void,
		arch: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_set_architectures(
		handle: *mut c_void,
		arches: *mut CList,
	) -> c_int;
	pub(crate) fn alpm_option_remove_architecture(
		handle: *mut c_void,
		arch: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_get_noupgrades(
		handle: *mut c_void,
	) -> *mut CList;
	pub(crate) fn alpm_option_add_noupgrade(
		handle: *mut c_void,
		pkg: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_set_noupgrades(
		handle: *mut c_void,
		list: *mut CList,
	) -> c_int;
	pub(crate) fn alpm_option_remove_noupgrade(
		handle: *mut c_void,
		pkg: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_match_noupgrade(
		handle: *mut c_void,
		path: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_get_noextracts(
		handle: *mut c_void,
	) -> *mut CList;
	pub(crate) fn alpm_option_add_noextract(
		handle: *mut c_void,
		path: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_set_noextracts(
		handle: *mut c_void,
		list: *mut CList,
	) -> c_int;
	pub(crate) fn alpm_option_remove_noextract(
		handle: *mut c_void,
		path: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_match_noextract(
		handle: *mut c_void,
		path: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_get_ignorepkgs(
		handle: *mut c_void,
	) -> *mut CList;
	pub(crate) fn alpm_option_add_ignorepkg(
		handle: *mut c_void,
		pkg: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_set_ignorepkgs(
		handle: *mut c_void,
		list: *mut CList,
	) -> c_int;
	pub(crate) fn alpm_option_remove_ignorepkg(
		handle: *mut c_void,
		pkg: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_get_ignoregroups(
		handle: *mut c_void,
	) -> *mut CList;
	pub(crate) fn alpm_option_add_ignoregroup(
		handle: *mut c_void,
		grp: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_set_ignoregroups(
		handle: *mut c_void,
		list: *mut CList,
	) -> c_int;
	pub(crate) fn alpm_option_remove_ignoregroup(
		handle: *mut c_void,
		grp: *const c_char,
	) -> c_int;

	// db.c
	pub(crate) fn alpm_db_unregister(db: *mut CDb) -> c_int;
	pub(crate) fn alpm_db_get_name(db: *const CDb) -> *const c_char;
	pub(crate) fn alpm_db_get_servers(db: *const CDb) -> *mut CList;
	pub(crate) fn alpm_db_set_servers(
		db: *mut CDb,
		servers: *mut CList,
	) -> c_int;
	pub(crate) fn alpm_db_add_server(
		db: *mut CDb,
		url: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_db_remove_server(
		db: *mut CDb,
		url: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_db_get_cache_servers(db: *const CDb) -> *mut CList;
	pub(crate) fn alpm_db_set_cache_servers(
		db: *mut CDb,
		servers: *mut CList,
	) -> c_int;
	pub(crate) fn alpm_db_add_cache_server(
		db: *mut CDb,
		url: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_db_remove_cache_server(
		db: *mut CDb,
		url: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_db_get_siglevel(db: *mut CDb) -> c_int;
	pub(crate) fn alpm_db_get_valid(db: *mut CDb) -> c_int;
	pub(crate) fn alpm_db_get_pkg(
		db: *mut CDb,
		name: *const c_char,
	) -> *mut CPkg;
	pub(crate) fn alpm_db_get_group(
		db: *mut CDb,
		name: *const c_char,
	) -> *mut CGroup;
	pub(crate) fn alpm_db_get_groupcache(db: *mut CDb) -> *mut CList;
	pub(crate) fn alpm_db_set_usage(db: *mut CDb, usage: c_int) -> c_int;
	pub(crate) fn alpm_db_get_usage(
		db: *mut CDb,
		usage: *mut c_int,
	) -> c_int;
	pub(crate) fn _alpm_db_path(db: *mut CDb) -> *const c_char;
	pub(crate) fn _alpm_db_cmp(
		d1: *const c_void,
		d2: *const c_void,
	) -> c_int;
	pub(crate) fn _alpm_db_add_pkgincache(
		db: *mut CDb,
		pkg: *mut CPkg,
	) -> c_int;
	pub(crate) fn _alpm_db_remove_pkgfromcache(
		db: *mut CDb,
		pkg: *mut CPkg,
	) -> c_int;
	pub(crate) fn _alpm_db_free_pkgcache(db: *mut CDb);
}

// alpm_initialize/alpm_release run curl_global_init/cleanup, which are
// not thread safe: one handle at a time across all modules
pub(crate) static ALPM: Mutex<()> = Mutex::new(());

// be_package.c and the package file entry points
unsafe extern "C" {
	pub(crate) fn alpm_pkg_load(
		handle: *mut c_void,
		filename: *const c_char,
		full: c_int,
		level: c_int,
		pkg: *mut *mut CPkg,
	) -> c_int;
	pub(crate) fn alpm_pkg_free(pkg: *mut CPkg) -> c_int;
	pub(crate) fn alpm_pkg_changelog_open(pkg: *mut CPkg) -> *mut c_void;
	pub(crate) fn alpm_pkg_changelog_read(
		ptr: *mut c_void,
		size: usize,
		pkg: *const CPkg,
		fp: *mut c_void,
	) -> usize;
	pub(crate) fn alpm_pkg_changelog_close(
		pkg: *const CPkg,
		fp: *mut c_void,
	) -> c_int;
	pub(crate) fn _alpm_pkg_validate_internal(
		handle: *mut c_void,
		pkgfile: *const c_char,
		syncpkg: *mut CPkg,
		level: c_int,
		sigdata: *mut *mut c_void,
		validation: *mut c_int,
	) -> c_int;
}

// transactions and the handle options the conflict checks read
// (trans.c, handle.c)
pub(crate) type ProgressFn = unsafe extern "C" fn(
	ctx: *mut c_void,
	progress: c_int,
	pkg: *const c_char,
	percent: c_int,
	howmany: usize,
	current: usize,
);

unsafe extern "C" {
	pub(crate) fn alpm_trans_init(
		handle: *mut c_void,
		flags: c_int,
	) -> c_int;
	pub(crate) fn alpm_trans_release(handle: *mut c_void) -> c_int;
	pub(crate) fn alpm_option_set_overwrite_files(
		handle: *mut c_void,
		globs: *mut CList,
	) -> c_int;
	pub(crate) fn alpm_option_set_progresscb(
		handle: *mut c_void,
		cb: Option<ProgressFn>,
		ctx: *mut c_void,
	) -> c_int;
}

// leading fields of struct _alpm_handle_t, handle.h, up to trans. only
// trans is written (diskspace sets a transaction by hand)
#[repr(C)]
pub(crate) struct CHandleHead {
	_db_local: *mut CDb,
	_dbs_sync: *mut CList,
	_logstream: *mut c_void,
	pub(crate) trans: *mut CTrans,
}

// alpm_trans_t, trans.h
#[repr(C)]
pub(crate) struct CTrans {
	pub(crate) flags: c_int,
	pub(crate) state: c_int,
	pub(crate) unresolvable: *mut CList,
	pub(crate) add: *mut CList,
	pub(crate) remove: *mut CList,
	pub(crate) skip_remove: *mut CList,
}

// alpm_cb_log: va_list as a parameter is a pointer on x86_64 (array
// type) and aarch64 (passed by reference), vsnprintf takes it the same
pub(crate) type CLogCb =
	unsafe extern "C" fn(*mut c_void, c_int, *const c_char, *mut c_void);

unsafe extern "C" {
	pub(crate) fn alpm_option_set_logcb(
		handle: *mut c_void,
		cb: Option<CLogCb>,
		ctx: *mut c_void,
	) -> c_int;
}

// the _alpm_log calls of a handle: alpm_loglevel_t and message
pub type CLogs = Vec<(c_int, Vec<u8>)>;

// the message of one _alpm_log call, for every alpm_cb_log here
//
// # Safety
// fmt and args are the format and va_list the callback got, each call
// uses them once
pub(crate) unsafe fn log_message(
	fmt: *const c_char,
	args: *mut c_void,
) -> Vec<u8> {
	// sync db lines reach 512 KiB (be_sync's unknown key line); one
	// buffer per thread, a fuzz logs millions of lines
	thread_local! {
		static BUF: std::cell::RefCell<Vec<c_char>> =
			std::cell::RefCell::new(vec![0; 1 << 20]);
	}
	BUF.with_borrow_mut(|buf| {
		// SAFETY: the caller's fmt/args pair, used once; buf is
		// writable for its length
		let n = unsafe {
			crate::vsnprintf(buf.as_mut_ptr(), buf.len(), fmt, args)
		};
		assert!(n >= 0 && (n as usize) < buf.len(), "log message cut");
		// SAFETY: vsnprintf nul-terminated buf
		let msg = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
		msg.to_bytes().to_vec()
	})
}

// alpm_cb_log appending to the CLogs at ctx
pub(crate) unsafe extern "C" fn record_log(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	// SAFETY: fmt and args are the pair this callback got
	let msg = unsafe { log_message(fmt, args) };
	// SAFETY: ctx is the CLogs registered with the callback, no other
	// reference to it is live while the C runs
	let logs = unsafe { &mut *ctx.cast::<CLogs>() };
	logs.push((level, msg));
}

// question callback and assumeinstalled (deps_graph)
unsafe extern "C" {
	pub(crate) fn alpm_option_set_questioncb(
		handle: *mut c_void,
		cb: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
		ctx: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_set_assumeinstalled(
		handle: *mut c_void,
		deps: *mut CList,
	) -> c_int;
}

// gpgdir (signing)
unsafe extern "C" {
	pub(crate) fn alpm_option_set_gpgdir(
		handle: *mut c_void,
		gpgdir: *const c_char,
	) -> c_int;
}

// download callbacks and options (dload)
unsafe extern "C" {
	pub(crate) fn alpm_option_set_dlcb(
		handle: *mut c_void,
		cb: Option<
			unsafe extern "C" fn(
				*mut c_void,
				*const c_char,
				c_int,
				*mut c_void,
			),
		>,
		ctx: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_set_fetchcb(
		handle: *mut c_void,
		cb: Option<
			unsafe extern "C" fn(
				*mut c_void,
				*const c_char,
				*const c_char,
				c_int,
			) -> c_int,
		>,
		ctx: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_set_eventcb(
		handle: *mut c_void,
		cb: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
		ctx: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_add_cachedir(
		handle: *mut c_void,
		cachedir: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_get_cachedirs(
		handle: *mut c_void,
	) -> *mut CList;
	pub(crate) fn alpm_option_set_parallel_downloads(
		handle: *mut c_void,
		num_streams: c_uint,
	) -> c_int;
	pub(crate) fn alpm_option_set_disable_dl_timeout(
		handle: *mut c_void,
		disable_dl_timeout: std::ffi::c_ushort,
	) -> c_int;
}

// the rest of handle.c and log.c (handle_opts)
unsafe extern "C" {
	pub(crate) fn alpm_option_get_hookdirs(
		handle: *mut c_void,
	) -> *mut CList;
	pub(crate) fn alpm_option_add_hookdir(
		handle: *mut c_void,
		hookdir: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_set_hookdirs(
		handle: *mut c_void,
		hookdirs: *mut CList,
	) -> c_int;
	pub(crate) fn alpm_option_remove_hookdir(
		handle: *mut c_void,
		hookdir: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_set_cachedirs(
		handle: *mut c_void,
		cachedirs: *mut CList,
	) -> c_int;
	pub(crate) fn alpm_option_remove_cachedir(
		handle: *mut c_void,
		cachedir: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_get_gpgdir(
		handle: *mut c_void,
	) -> *const c_char;
	pub(crate) fn alpm_option_get_logfile(
		handle: *mut c_void,
	) -> *const c_char;
	pub(crate) fn alpm_option_set_logfile(
		handle: *mut c_void,
		logfile: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_get_lockfile(
		handle: *mut c_void,
	) -> *const c_char;
	pub(crate) fn alpm_option_get_sandboxuser(
		handle: *mut c_void,
	) -> *const c_char;
	pub(crate) fn alpm_option_set_sandboxuser(
		handle: *mut c_void,
		sandboxuser: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_get_usesyslog(handle: *mut c_void) -> c_int;
	pub(crate) fn alpm_option_set_usesyslog(
		handle: *mut c_void,
		usesyslog: c_int,
	) -> c_int;
	pub(crate) fn alpm_option_get_checkspace(handle: *mut c_void) -> c_int;
	pub(crate) fn alpm_option_set_checkspace(
		handle: *mut c_void,
		checkspace: c_int,
	) -> c_int;
	pub(crate) fn alpm_option_get_parallel_downloads(
		handle: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_get_disable_dl_timeout(
		handle: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_get_disable_sandbox(
		handle: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_set_disable_sandbox(
		handle: *mut c_void,
		disable: std::ffi::c_ushort,
	) -> c_int;
	pub(crate) fn alpm_option_get_disable_sandbox_filesystem(
		handle: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_set_disable_sandbox_filesystem(
		handle: *mut c_void,
		disable: std::ffi::c_ushort,
	) -> c_int;
	pub(crate) fn alpm_option_get_disable_sandbox_syscalls(
		handle: *mut c_void,
	) -> c_int;
	pub(crate) fn alpm_option_set_disable_sandbox_syscalls(
		handle: *mut c_void,
		disable: std::ffi::c_ushort,
	) -> c_int;
	pub(crate) fn alpm_option_get_overwrite_files(
		handle: *mut c_void,
	) -> *mut CList;
	pub(crate) fn alpm_option_add_overwrite_file(
		handle: *mut c_void,
		glob: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_remove_overwrite_file(
		handle: *mut c_void,
		glob: *const c_char,
	) -> c_int;
	pub(crate) fn alpm_option_get_assumeinstalled(
		handle: *mut c_void,
	) -> *mut CList;
	pub(crate) fn alpm_option_add_assumeinstalled(
		handle: *mut c_void,
		dep: *const c_void,
	) -> c_int;
	pub(crate) fn alpm_option_remove_assumeinstalled(
		handle: *mut c_void,
		dep: *const c_void,
	) -> c_int;
	pub(crate) fn alpm_logaction(
		handle: *mut c_void,
		prefix: *const c_char,
		fmt: *const c_char,
		...
	) -> c_int;
	pub(crate) fn alpm_unlock(handle: *mut c_void) -> c_int;
	pub(crate) fn _alpm_handle_lock(handle: *mut c_void) -> c_int;
	pub(crate) fn _alpm_handle_unlock(handle: *mut c_void) -> c_int;
}
