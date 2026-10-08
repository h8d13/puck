// C side of the transaction prepare phase: alpm_trans_init/release/
// interrupt/get_flags, alpm_add_pkg, alpm_remove_pkg,
// alpm_sync_sysupgrade, alpm_find_group_pkgs and alpm_trans_prepare
// (trans.c, add.c, remove.c, sync.c) on a real handle, and the frontend
// prepare through pacman_sync/pacman_remove/pacman_upgrade (src/pacman
// sync.c, remove.c, upgrade.c). also the fixture worlds both share:
// a local db, three sync dbs, a cache dir and package files over a small
// name set, so dependencies, providers, conflicts and replaces between
// them are common.
//
// log, event and question callbacks registered on the handle record
// every call; questions are answered from a scripted list (once it runs
// out the C default stays, like no callback). caches (and group caches)
// load before the callbacks go in. log lines the port does not make are
// dropped here: ALPM_LOG_FUNCTION (db backends), the debug lines of
// RET_ERR/GOTO_ERR and of db.c's cache loads. packages are named by name (and db index where the
// C pointer says which db).
use std::collections::VecDeque;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs;
use std::path::Path;
use std::ptr;

use alpm_core::deps::{DepMissing, Depend};
use pacman_cli::conf::Config;

use crate::cli_util::config;
use crate::cli_util2::{CIo, run};
use crate::conflict::take_conflicts;
use crate::deps_graph::{LOG_FUNCTION, take_misses};
use crate::fixtures::{
	Comp, LocalEntry, TarEntry, TempRoot, section, tar_dir, tar_file,
	ustar, write_db,
};
use crate::handle::{
	_alpm_db_get_pkgcache_hash, ALPM, CDb, CHandleHead, CTrans,
	alpm_db_get_groupcache, alpm_db_set_usage, alpm_errno,
	alpm_get_localdb, alpm_initialize, alpm_option_add_cachedir,
	alpm_option_set_architectures, alpm_option_set_default_siglevel,
	alpm_option_set_eventcb, alpm_option_set_ignoregroups,
	alpm_option_set_ignorepkgs, alpm_option_set_local_file_siglevel,
	alpm_option_set_logcb, alpm_option_set_questioncb,
	alpm_option_set_remote_file_siglevel, alpm_pkg_free, alpm_pkg_load,
	alpm_register_syncdb, alpm_release, alpm_trans_init,
	alpm_trans_release,
};
use crate::package::{CPkg, field, list_data, with_strs};
use crate::sync_ro::pacman_sync;
use crate::{CList, Rng, alpm_list_add, alpm_list_free, c_free, cstr};
use crate::{deps_graph, vsnprintf};

// ---- fixture worlds ----

pub const TP_SYNC: [&str; 3] = ["core", "extra", "multi"];
const NAMES: [&str; 8] = ["a", "b", "c", "d", "e", "f", "g", "h"];
// provided only
const VIRTUAL: [&str; 3] = ["v1", "v2", "libx"];
const PKG_VERSIONS: [&str; 4] = ["1.0-1", "2.0-1", "1:0.5-1", "1.5-2"];
const DEP_VERSIONS: [&str; 5] = ["1.0", "2.0", "1:0.5", "1.5", "1.0-1"];
const OPS: [&str; 5] = ["=", ">=", "<=", ">", "<"];
pub const TP_GROUPS: [&str; 2] = ["g1", "g2"];
// the handle architectures, when set, are "x86_64"
const ARCHES: [&str; 4] = ["any", "x86_64", "x86_64", "i686"];

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

fn some<T>(rng: &mut Rng, n: usize, f: impl Fn(&mut Rng) -> T) -> Vec<T> {
	(0..rng.below(n)).map(|_| f(rng)).collect()
}

fn any_name(rng: &mut Rng) -> &'static str {
	match rng.below(4) {
		0 => pick(rng, &VIRTUAL),
		_ => pick(rng, &NAMES),
	}
}

fn relation(rng: &mut Rng) -> String {
	let name = any_name(rng);
	match rng.below(3) {
		0 => format!(
			"{name}{}{}",
			pick(rng, &OPS),
			pick(rng, &DEP_VERSIONS)
		),
		_ => name.to_string(),
	}
}

fn provision(rng: &mut Rng) -> String {
	let name = match rng.below(3) {
		0 | 1 => pick(rng, &VIRTUAL),
		_ => pick(rng, &NAMES),
	};
	match rng.below(4) {
		0 | 1 => name.to_string(),
		_ => format!("{name}={}", pick(rng, &DEP_VERSIONS)),
	}
}

fn subset(rng: &mut Rng, items: &[&str], keep: usize) -> Vec<String> {
	let mut v = items.to_vec();
	v.retain(|_| rng.below(keep) == 0);
	v.into_iter().map(String::from).collect()
}

// one package of a world
#[derive(Clone, Debug)]
pub struct TpPkg {
	pub name: &'static str,
	pub version: &'static str,
	pub depends: Vec<String>,
	pub optdepends: Vec<String>,
	pub provides: Vec<String>,
	pub conflicts: Vec<String>,
	pub replaces: Vec<String>,
	pub groups: Vec<String>,
	// %REASON% 1 (local only)
	pub asdep: bool,
	pub arch: &'static str,
	// sync only
	pub filename: String,
	pub csize: u64,
	pub isize: u64,
}

#[derive(Clone, Debug)]
pub struct TpWorld {
	pub local: Vec<TpPkg>,
	pub sync: Vec<Vec<TpPkg>>,
	pub files: Vec<TpPkg>,
}

fn gen_pkg(rng: &mut Rng, name: &'static str, sync: bool) -> TpPkg {
	let version = pick(rng, &PKG_VERSIONS);
	let arch = pick(rng, &ARCHES);
	let mut p = TpPkg {
		name,
		version,
		depends: some(rng, 4, relation),
		optdepends: some(rng, 3, |r| any_name(r).to_string()),
		provides: some(rng, 3, provision),
		conflicts: match rng.below(3) {
			0 => some(rng, 3, relation),
			_ => Vec::new(),
		},
		replaces: match (sync, rng.below(4)) {
			(true, 0) => some(rng, 3, relation),
			_ => Vec::new(),
		},
		groups: subset(rng, &TP_GROUPS, 3),
		asdep: rng.below(2) == 0,
		arch,
		filename: match rng.below(10) {
			0 => "shared-1-1-any.pkg.tar.zst".to_string(),
			_ => format!("{name}-{version}-{arch}.pkg.tar.zst"),
		},
		csize: rng.below(5000) as u64,
		isize: rng.below(90000) as u64,
	};
	// a successor of another package: conflicts with, provides and
	// (in a sync db) replaces it
	if rng.below(5) == 0 {
		let old = pick(rng, &NAMES).to_string();
		p.conflicts.push(old.clone());
		p.provides.push(old.clone());
		if sync {
			p.replaces.push(old);
		}
	}
	p
}

// resolvable: sync depends are names some sync db holds, unversioned,
// and no world package is ignored, so the resolver never fails below a
// target. the C frontend reads every data entry of a CONFLICTING_DEPS
// failure as a conflict, and a failure below a target leaves stale
// depmissing entries in that list (UPSTREAM.md, deps)
pub fn gen_world(rng: &mut Rng, resolvable: bool) -> TpWorld {
	let mut names = NAMES.to_vec();
	names.retain(|_| rng.below(2) == 0);
	let local = names.iter().map(|&n| gen_pkg(rng, n, false)).collect();
	let mut sync: Vec<Vec<TpPkg>> = TP_SYNC
		.iter()
		.map(|_| {
			let mut names = NAMES.to_vec();
			names.retain(|_| rng.below(2) == 0);
			names.into_iter()
				.map(|n| gen_pkg(rng, n, true))
				.collect()
		})
		.collect();
	if resolvable {
		let held: Vec<&'static str> =
			sync.iter().flatten().map(|p| p.name).collect();
		for p in sync.iter_mut().flatten() {
			p.depends = match held.is_empty() {
				true => Vec::new(),
				false => some(rng, 3, |r| {
					pick(r, &held).to_string()
				}),
			};
		}
	}
	let files = (0..rng.below(4))
		.map(|_| {
			let name = pick(rng, &NAMES);
			gen_pkg(rng, name, false)
		})
		.collect();
	TpWorld { local, sync, files }
}

fn relations(p: &TpPkg) -> String {
	[
		section("GROUPS", &p.groups),
		section("DEPENDS", &p.depends),
		section("OPTDEPENDS", &p.optdepends),
		section("CONFLICTS", &p.conflicts),
		section("PROVIDES", &p.provides),
	]
	.concat()
}

fn local_desc(p: &TpPkg) -> String {
	let reason = match p.asdep {
		true => "%REASON%\n1\n\n",
		false => "",
	};
	format!(
		"%NAME%\n{0}\n\n%VERSION%\n{1}\n\n%BASE%\n{0}\n\n\
		%DESC%\nA package\n\n%URL%\nhttps://example.org/\n\n\
		%ARCH%\n{2}\n\n%BUILDDATE%\n1700000000\n\n\
		%INSTALLDATE%\n1700000001\n\n%PACKAGER%\nA B <a@b.org>\n\n\
		%SIZE%\n{3}\n\n{reason}%VALIDATION%\npgp\n\n{4}",
		p.name,
		p.version,
		p.arch,
		p.isize,
		relations(p)
	)
}

fn sync_desc(p: &TpPkg) -> String {
	format!(
		"%FILENAME%\n{0}\n\n%NAME%\n{1}\n\n%BASE%\n{1}\n\n\
		%VERSION%\n{2}\n\n%CSIZE%\n{3}\n\n%ISIZE%\n{4}\n\n\
		%SHA256SUM%\n{5}\n\n%ARCH%\n{6}\n\n%BUILDDATE%\n3\n\n\
		%PACKAGER%\nA B <a@b.org>\n\n{7}{8}",
		p.filename,
		p.name,
		p.version,
		p.csize,
		p.isize,
		"ab".repeat(32),
		p.arch,
		section("REPLACES", &p.replaces),
		relations(p)
	)
}

fn pkginfo(p: &TpPkg) -> String {
	let mut lines = vec![
		format!("pkgname = {}", p.name),
		format!("pkgbase = {}", p.name),
		format!("pkgver = {}", p.version),
		"pkgdesc = A file package".to_string(),
		"url = https://example.org/".to_string(),
		"builddate = 1700000000".to_string(),
		"packager = A B <a@b.org>".to_string(),
		format!("size = {}", p.isize),
		format!("arch = {}", p.arch),
	];
	let lists: [(&str, &Vec<String>); 6] = [
		("group", &p.groups),
		("depend", &p.depends),
		("optdepend", &p.optdepends),
		("conflict", &p.conflicts),
		("provides", &p.provides),
		("replaces", &p.replaces),
	];
	for (key, values) in lists {
		lines.extend(values.iter().map(|v| format!("{key} = {v}")));
	}
	lines.join("\n") + "\n"
}

// <fixture>/cache/: the handle's cache dir
pub fn tp_cachedir(fx: &TempRoot) -> Vec<u8> {
	[&fx.path("cache")[..], b"/"].concat()
}

// the world under fx: local db, sync dbs, the cache dir (some sync
// packages cached whole or as a .part) and the file packages, whose
// paths come back in world order
pub fn write_world(fx: &TempRoot, w: &TpWorld, rng: &mut Rng) -> Vec<Vec<u8>> {
	fx.reset_local();
	let entries: Vec<LocalEntry> =
		w.local.iter()
			.map(|p| LocalEntry {
				dir: format!("{}-{}", p.name, p.version),
				desc: Some(local_desc(p).into_bytes()),
				files: Some(Vec::new()),
				install: false,
			})
			.collect();
	fx.write_local(&entries);
	let cache = fx.dir().join("cache");
	if cache.exists() {
		fs::remove_dir_all(&cache).unwrap();
	}
	fs::create_dir(&cache).unwrap();
	for (name, pkgs) in TP_SYNC.iter().zip(&w.sync) {
		let mut tar: Vec<TarEntry> = Vec::new();
		for p in pkgs {
			let dir = format!("{}-{}/", p.name, p.version);
			tar.push(tar_dir(&dir));
			let desc = sync_desc(p);
			tar.push(tar_file(
				&format!("{dir}desc"),
				desc.as_bytes(),
			));
			let size = rng.below(3000);
			match rng.below(6) {
				0 => fs::write(cache.join(&p.filename), b"x")
					.unwrap(),
				1 => {
					let part =
						format!("{}.part", p.filename);
					fs::write(
						cache.join(part),
						vec![0; size],
					)
					.unwrap();
				}
				_ => {}
			}
		}
		let path = fx.sync_file(name, ".db");
		write_db(&path, Comp::None, &ustar(&tar));
	}
	let dir = fx.dir().join("pkgs");
	if dir.exists() {
		fs::remove_dir_all(&dir).unwrap();
	}
	fs::create_dir(&dir).unwrap();
	w.files.iter()
		.enumerate()
		.map(|(i, p)| {
			let path =
				dir.join(format!("{i}-{}.pkg.tar.gz", p.name));
			let info = pkginfo(p);
			let tar =
				ustar(&[tar_file(".PKGINFO", info.as_bytes())]);
			write_db(&path, Comp::Gzip, &tar);
			path.as_os_str().as_encoded_bytes().to_vec()
		})
		.collect()
}

// every file under dir with its bytes, sorted: a commit would change
// some
pub fn tree_snapshot(dir: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut out = Vec::new();
	let mut todo = vec![dir.to_path_buf()];
	while let Some(d) = todo.pop() {
		for e in fs::read_dir(&d).unwrap() {
			let p = e.unwrap().path();
			let name = p.as_os_str().as_encoded_bytes().to_vec();
			if p.is_dir() && !p.is_symlink() {
				out.push((name, Vec::new()));
				todo.push(p);
			} else {
				out.push((
					name,
					fs::read(&p).unwrap_or_default(),
				));
			}
		}
	}
	out.sort();
	out
}

// ---- what both sides record ----

// one event: the kind, OPTDEP_REMOVAL with its package and optdepend
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TpEvent {
	Kind(c_int),
	OptdepRemoval(Vec<u8>, Depend),
}

// one question with its payload by name
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TpAsk {
	InstallIgnorepkg(Vec<u8>),
	// old, new, new db
	Replace(Vec<u8>, Vec<u8>, Vec<u8>),
	Conflict(Vec<u8>, Vec<u8>, Depend),
	RemovePkgs(Vec<Vec<u8>>),
	SelectProvider(Vec<Vec<u8>>, Depend),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TpCalls {
	pub logs: Vec<(c_int, Vec<u8>)>,
	pub events: Vec<TpEvent>,
	pub asked: Vec<TpAsk>,
}

// a target of trans->add as compared
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpAdd {
	pub name: Vec<u8>,
	pub version: Vec<u8>,
	pub reason: c_int,
	// sync db index, None for a file package
	pub db: Option<usize>,
	pub removes: Vec<Vec<u8>>,
	pub download_size: i64,
	// version of the oldpkg
	pub oldpkg: Option<Vec<u8>>,
}

// handle->trans as compared
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpView {
	pub flags: c_int,
	pub state: c_int,
	pub add: Vec<TpAdd>,
	pub unresolvable: Vec<Vec<u8>>,
	// name, version, reason
	pub remove: Vec<(Vec<u8>, Vec<u8>, c_int)>,
}

// a conflict of the data list: package1 and package2 name-version,
// reason
pub type TpConflict = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Depend);

// the data list of a failed prepare
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TpData {
	#[default]
	None,
	Arch(Vec<Vec<u8>>),
	Missing(Vec<DepMissing>),
	Conflicts(Vec<TpConflict>),
}

// ---- C callbacks ----

// alpm_question_*_t, each starts with type and the answer
#[repr(C)]
struct CQPkg {
	kind: c_int,
	answer: c_int,
	pkg: *mut CPkg,
}

#[repr(C)]
struct CQReplace {
	kind: c_int,
	answer: c_int,
	oldpkg: *mut CPkg,
	newpkg: *mut CPkg,
	newdb: *mut CDb,
}

#[repr(C)]
struct CQList {
	kind: c_int,
	answer: c_int,
	list: *mut CList,
	depend: *mut c_void,
}

// alpm_conflict_t, read through package names
#[repr(C)]
struct CConflict {
	package1: *mut CPkg,
	package2: *mut CPkg,
	reason: *mut c_void,
}

// alpm_event_optdep_removal_t
#[repr(C)]
struct CEvOptdep {
	kind: c_int,
	pkg: *mut CPkg,
	optdep: *mut c_void,
}

const EVENT_OPTDEP_REMOVAL: c_int = 26;
const Q_INSTALL_IGNOREPKG: c_int = 1;
const Q_REPLACE_PKG: c_int = 1 << 1;
const Q_CONFLICT_PKG: c_int = 1 << 2;
const Q_REMOVE_PKGS: c_int = 1 << 4;
const Q_SELECT_PROVIDER: c_int = 1 << 5;
const LOG_DEBUG: c_int = 1 << 2;
// debug lines left out on both sides: RET_ERR/GOTO_ERR (not logged by
// the port) and the db.c cache loads (the C retries a missing sync db on
// every lookup, the port's View reads caches loaded once)
pub const UNPORTED_DEBUG: [&[u8]; 5] = [
	b"returning error ",
	b"got error ",
	b"loading package cache for repository ",
	b"failed to load package cache for repository ",
	b"loading group cache for repository ",
];

fn read_dep(d: *mut c_void) -> Depend {
	deps_graph::read_dep(d.cast())
}

fn pkg_name(p: *const CPkg) -> Vec<u8> {
	crate::package::read_pkg(p)
		.name
		.expect("package without name")
}

struct Rec {
	sync: Vec<*mut CDb>,
	answers: VecDeque<c_int>,
	calls: TpCalls,
	// drops log lines (package file loads)
	mute: bool,
}

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	// SAFETY: ctx is the Rec registered with the callback, no other
	// reference to it is live while the C runs
	let rec = unsafe { &mut *ctx.cast::<Rec>() };
	let mut buf = [0 as c_char; 4096];
	// SAFETY: fmt and args are the format and va_list of this call,
	// used once; buf is writable for its length
	let n = unsafe { vsnprintf(buf.as_mut_ptr(), buf.len(), fmt, args) };
	assert!(n >= 0 && (n as usize) < buf.len(), "log message too long");
	// SAFETY: vsnprintf nul-terminated buf
	let msg = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes().to_vec();
	let errline = level == LOG_DEBUG
		&& UNPORTED_DEBUG.iter().any(|p| msg.starts_with(p));
	if rec.mute || level == LOG_FUNCTION || errline {
		return;
	}
	rec.calls.logs.push((level, msg));
}

unsafe extern "C" fn event_cb(ctx: *mut c_void, e: *mut c_void) {
	// SAFETY: as in log_cb
	let rec = unsafe { &mut *ctx.cast::<Rec>() };
	// SAFETY: every alpm_event_t starts with its type
	let kind = unsafe { *e.cast::<c_int>() };
	let ev = match kind {
		EVENT_OPTDEP_REMOVAL => {
			// SAFETY: the type says which member e is
			let o = unsafe { &*e.cast::<CEvOptdep>() };
			TpEvent::OptdepRemoval(
				pkg_name(o.pkg),
				read_dep(o.optdep),
			)
		}
		k => TpEvent::Kind(k),
	};
	rec.calls.events.push(ev);
}

unsafe extern "C" fn question_cb(ctx: *mut c_void, q: *mut c_void) {
	// SAFETY: as in log_cb
	let rec = unsafe { &mut *ctx.cast::<Rec>() };
	// SAFETY: every alpm_question_t starts with type and answer
	let kind = unsafe { *q.cast::<c_int>() };
	let names = |l: *mut CList| -> Vec<Vec<u8>> {
		list_data(l)
			.into_iter()
			.map(|p| pkg_name(p.cast()))
			.collect()
	};
	let asked = match kind {
		Q_INSTALL_IGNOREPKG => {
			// SAFETY: the type says which member q is
			let q = unsafe { &*q.cast::<CQPkg>() };
			TpAsk::InstallIgnorepkg(pkg_name(q.pkg))
		}
		Q_REPLACE_PKG => {
			// SAFETY: as above
			let q = unsafe { &*q.cast::<CQReplace>() };
			let db = rec.sync.iter().position(|&d| d == q.newdb);
			let db = TP_SYNC[db.expect("replace from a known db")];
			let (old, new) =
				(pkg_name(q.oldpkg), pkg_name(q.newpkg));
			TpAsk::Replace(old, new, db.as_bytes().to_vec())
		}
		Q_CONFLICT_PKG => {
			// SAFETY: as above, list is the alpm_conflict_t here
			let q = unsafe { &*q.cast::<CQList>() };
			// SAFETY: a live conflict of _alpm_sync_prepare
			let c = unsafe { &*q.list.cast::<CConflict>() };
			let (a, b) =
				(pkg_name(c.package1), pkg_name(c.package2));
			TpAsk::Conflict(a, b, read_dep(c.reason))
		}
		Q_REMOVE_PKGS => {
			// SAFETY: as above
			let q = unsafe { &*q.cast::<CQList>() };
			TpAsk::RemovePkgs(names(q.list))
		}
		Q_SELECT_PROVIDER => {
			// SAFETY: as above
			let q = unsafe { &*q.cast::<CQList>() };
			TpAsk::SelectProvider(names(q.list), read_dep(q.depend))
		}
		k => panic!("unexpected question {k}"),
	};
	rec.calls.asked.push(asked);
	if let Some(a) = rec.answers.pop_front() {
		// SAFETY: the answer follows the type in every question
		unsafe { *q.cast::<c_int>().add(1) = a };
	}
}

// handle state of a world
#[derive(Clone, Debug, Default)]
pub struct TpSetup {
	pub ignorepkg: Vec<Vec<u8>>,
	pub ignoregroup: Vec<Vec<u8>>,
	// empty skips the architecture check
	pub arches: Vec<Vec<u8>>,
	// one per sync db
	pub usage: Vec<c_int>,
	pub cachedir: Vec<u8>,
}

unsafe extern "C" {
	fn alpm_add_pkg(handle: *mut c_void, pkg: *mut CPkg) -> c_int;
	pub(crate) fn alpm_remove_pkg(
		handle: *mut c_void,
		pkg: *mut CPkg,
	) -> c_int;
	fn alpm_sync_sysupgrade(
		handle: *mut c_void,
		enable_downgrade: c_int,
	) -> c_int;
	fn alpm_find_group_pkgs(
		dbs: *mut CList,
		name: *const c_char,
	) -> *mut CList;
	fn alpm_trans_prepare(
		handle: *mut c_void,
		data: *mut *mut CList,
	) -> c_int;
	fn alpm_trans_interrupt(handle: *mut c_void) -> c_int;
	fn alpm_trans_get_flags(handle: *mut c_void) -> c_int;
	fn pacman_remove(targets: *mut CList) -> c_int;
	fn pacman_upgrade(targets: *mut CList) -> c_int;
}

// a C handle on a world: sync dbs registered (siglevel 0, every
// signature level 0), usage, ignore lists, architectures and the cache
// dir set, caches loaded, then the recording callbacks
pub struct CTx {
	h: *mut c_void,
	local: *mut CDb,
	rec: *mut Rec,
}

// ret 0 or pm_errno
pub type TpRet = Result<(), c_int>;

// a package by sync db (None: local or file) and name
pub type TpId = (Option<usize>, Vec<u8>);

fn arches_list(arches: &[Vec<u8>]) -> (Vec<CString>, *mut CList) {
	let owned: Vec<CString> = arches.iter().map(|a| cstr(a)).collect();
	let mut list = ptr::null_mut();
	for a in &owned {
		// SAFETY: list is NULL or built by alpm_list_add
		list = unsafe {
			alpm_list_add(list, a.as_ptr().cast_mut().cast())
		};
	}
	(owned, list)
}

impl CTx {
	// root and dbpath must exist, the sync db files load. with
	// callbacks false the handle is the frontend's (no callbacks)
	pub fn new(fx: &TempRoot, setup: &TpSetup, callbacks: bool) -> Self {
		let (root, dbpath) = (cstr(&fx.root()), cstr(&fx.dbpath()));
		let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
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
		drop(guard);
		let cachedir = cstr(&setup.cachedir);
		let (_arches, arches) = arches_list(&setup.arches);
		// SAFETY: h is live; the option setters copy strings and lists
		let sync: Vec<*mut CDb> = unsafe {
			assert_eq!(alpm_option_set_default_siglevel(h, 0), 0);
			assert_eq!(
				alpm_option_set_local_file_siglevel(h, 0),
				0
			);
			assert_eq!(
				alpm_option_set_remote_file_siglevel(h, 0),
				0
			);
			with_strs(&setup.ignorepkg, |l| {
				alpm_option_set_ignorepkgs(h, l)
			});
			with_strs(&setup.ignoregroup, |l| {
				alpm_option_set_ignoregroups(h, l)
			});
			assert_eq!(alpm_option_set_architectures(h, arches), 0);
			alpm_list_free(arches);
			assert_eq!(
				alpm_option_add_cachedir(h, cachedir.as_ptr()),
				0
			);
			TP_SYNC.iter()
				.zip(&setup.usage)
				.map(|(n, &u)| {
					let n = cstr(n.as_bytes());
					let db = alpm_register_syncdb(
						h,
						n.as_ptr(),
						0,
					);
					assert!(!db.is_null());
					assert_eq!(alpm_db_set_usage(db, u), 0);
					db
				})
				.collect()
		};
		// SAFETY: h is live
		let local = unsafe { alpm_get_localdb(h) };
		// SAFETY: h is live
		assert!(!unsafe { _alpm_db_get_pkgcache_hash(local) }.is_null());
		for &db in std::iter::once(&local).chain(&sync) {
			// SAFETY: db belongs to h; loads the caches now, before
			// the callbacks (a missing sync db file loads none)
			unsafe {
				_alpm_db_get_pkgcache_hash(db);
				alpm_db_get_groupcache(db);
			}
		}
		let rec = Box::into_raw(Box::new(Rec {
			sync,
			answers: VecDeque::new(),
			calls: TpCalls::default(),
			mute: false,
		}));
		if callbacks {
			// SAFETY: h is live, rec stays valid until drop
			unsafe {
				alpm_option_set_logcb(
					h,
					Some(log_cb),
					rec.cast(),
				);
				alpm_option_set_eventcb(
					h,
					Some(event_cb),
					rec.cast(),
				);
				alpm_option_set_questioncb(
					h,
					Some(question_cb),
					rec.cast(),
				);
			}
		}
		CTx { h, local, rec }
	}

	fn rec(&self) -> &Rec {
		// SAFETY: rec is live until drop; the C writes it only inside
		// run(), when no such reference is held
		unsafe { &*self.rec }
	}

	fn db(&self, db: Option<usize>) -> *mut CDb {
		db.map_or(self.local, |i| self.rec().sync[i])
	}

	// the cache entry of db named name
	fn pkg(&self, db: Option<usize>, name: &[u8]) -> *mut CPkg {
		// SAFETY: the db belongs to h, its cache loaded in new()
		let hash = unsafe { _alpm_db_get_pkgcache_hash(self.db(db)) };
		// SAFETY: hash is the live cache table
		let list = unsafe { (*hash).list };
		list_data(list)
			.into_iter()
			.map(|p| p.cast::<CPkg>())
			.find(|&p| pkg_name(p) == name)
			.unwrap_or_else(|| panic!("no package {db:?} {name:?}"))
	}

	fn ret(&self, r: c_int) -> TpRet {
		match r {
			0 => Ok(()),
			// SAFETY: h is live
			_ => Err(unsafe { alpm_errno(self.h) }),
		}
	}

	// f with these answers scripted, what the callbacks saw
	fn run<R>(
		&self,
		answers: &[c_int],
		f: impl FnOnce() -> R,
	) -> (R, TpCalls) {
		let rec = self.rec;
		// SAFETY: rec is live, no reference to it is held across f
		unsafe {
			(*rec).answers = answers.iter().copied().collect();
			(*rec).calls = TpCalls::default();
		}
		let r = f();
		// SAFETY: as above, the C is done with it
		(r, std::mem::take(unsafe { &mut (*rec).calls }))
	}

	pub fn init(&self, flags: c_int) -> (TpRet, TpCalls) {
		// SAFETY: h is live
		let (r, c) = self
			.run(&[], || unsafe { alpm_trans_init(self.h, flags) });
		(self.ret(r), c)
	}

	pub fn release(&self) -> (TpRet, TpCalls) {
		// SAFETY: h is live
		let (r, c) =
			self.run(&[], || unsafe { alpm_trans_release(self.h) });
		(self.ret(r), c)
	}

	pub fn interrupt(&self) -> TpRet {
		// SAFETY: h is live
		let r = unsafe { alpm_trans_interrupt(self.h) };
		self.ret(r)
	}

	// alpm_trans_get_flags, Err pm_errno for -1
	pub fn flags(&self) -> Result<c_int, c_int> {
		// SAFETY: h is live
		let r = unsafe { alpm_trans_get_flags(self.h) };
		match r {
			// SAFETY: h is live
			-1 => Err(unsafe { alpm_errno(self.h) }),
			f => Ok(f),
		}
	}

	// alpm_add_pkg of a package of db (None: a local one, WrongArgs)
	pub fn add_db(
		&self,
		db: Option<usize>,
		name: &[u8],
		answers: &[c_int],
	) -> (TpRet, TpCalls) {
		let p = self.pkg(db, name);
		// SAFETY: h is live, p one of its cached packages
		let (r, c) = self
			.run(answers, || unsafe { alpm_add_pkg(self.h, p) });
		(self.ret(r), c)
	}

	// alpm_pkg_load (logs dropped) then alpm_add_pkg; a package the
	// transaction did not take is freed. Err(None) a failed load
	pub fn add_file(
		&self,
		path: &[u8],
	) -> (Result<(), Option<c_int>>, TpCalls) {
		let path = cstr(path);
		let mut pkg: *mut CPkg = ptr::null_mut();
		// SAFETY: h is live, pkg receives a new package or stays NULL;
		// rec is not referenced across the call
		let loaded = unsafe {
			(*self.rec).mute = true;
			let r = alpm_pkg_load(
				self.h,
				path.as_ptr(),
				1,
				0,
				&mut pkg,
			);
			(*self.rec).mute = false;
			r
		};
		if loaded != 0 {
			return (Err(None), TpCalls::default());
		}
		// SAFETY: h is live, pkg a loaded file package of it
		let (r, c) =
			self.run(&[], || unsafe { alpm_add_pkg(self.h, pkg) });
		if r != 0 {
			// SAFETY: not taken by the transaction
			unsafe { alpm_pkg_free(pkg) };
		}
		(self.ret(r).map_err(Some), c)
	}

	// alpm_remove_pkg of a package of db (Some: a sync one, WrongArgs)
	pub fn remove(
		&self,
		db: Option<usize>,
		name: &[u8],
	) -> (TpRet, TpCalls) {
		let p = self.pkg(db, name);
		// SAFETY: h is live, p one of its cached packages
		let (r, c) =
			self.run(&[], || unsafe { alpm_remove_pkg(self.h, p) });
		(self.ret(r), c)
	}

	pub fn sysupgrade(
		&self,
		downgrade: bool,
		answers: &[c_int],
	) -> (TpRet, TpCalls) {
		let d = c_int::from(downgrade);
		// SAFETY: h is live
		let (r, c) = self.run(answers, || unsafe {
			alpm_sync_sysupgrade(self.h, d)
		});
		(self.ret(r), c)
	}

	// alpm_find_group_pkgs over the sync dbs dbs: (db, name) in order
	pub fn group_pkgs(
		&self,
		dbs: &[usize],
		group: &[u8],
		answers: &[c_int],
	) -> (Vec<TpId>, TpCalls) {
		let mut list = ptr::null_mut();
		for &i in dbs {
			// SAFETY: list is NULL or built by alpm_list_add
			list = unsafe {
				alpm_list_add(list, self.db(Some(i)).cast())
			};
		}
		let g = cstr(group);
		// SAFETY: the list holds dbs of h, g a valid C string
		let (out, calls) = self.run(answers, || unsafe {
			alpm_find_group_pkgs(list, g.as_ptr())
		});
		let ids = list_data(out)
			.into_iter()
			.map(|p| self.id(p.cast()))
			.collect();
		// SAFETY: nodes only, packages belong to the caches
		unsafe {
			alpm_list_free(out);
			alpm_list_free(list);
		}
		(ids, calls)
	}

	// the sync db of a cached package by its origin_data
	fn id(&self, p: *mut CPkg) -> TpId {
		// SAFETY: p is live
		let db = unsafe { (*p).origin_data }.cast::<CDb>();
		(self.rec().sync.iter().position(|&d| d == db), pkg_name(p))
	}

	// alpm_trans_prepare: the result, the data list and how many
	// entries before the reported ones are stale depmissing leftovers
	pub fn prepare(
		&self,
		answers: &[c_int],
	) -> ((TpRet, TpData, usize), TpCalls) {
		let mut data: *mut CList = ptr::null_mut();
		// SAFETY: h is live, data receives a list
		let (r, calls) = self.run(answers, || unsafe {
			alpm_trans_prepare(self.h, &mut data)
		});
		let ret = self.ret(r);
		let entries = list_data(data);
		let take_tail = |n: usize| -> *mut CList {
			// a fresh list of the last n entries, the earlier ones
			// freed as depmissing
			let (stale, keep) = entries.split_at(entries.len() - n);
			let mut l = ptr::null_mut();
			for &p in keep {
				// SAFETY: building a new list of the C's entries
				l = unsafe { alpm_list_add(l, p) };
			}
			free_misses(stale);
			l
		};
		let (out, stale) = match ret {
			Err(e) if e == ERR_PKG_INVALID_ARCH => {
				let strs = entries
					.iter()
					.map(|&p| {
						let s = field(p.cast())
							.expect("arch string");
						c_free(p);
						s
					})
					.collect();
				(TpData::Arch(strs), 0)
			}
			Err(e) if e == ERR_UNSATISFIED_DEPS => {
				let l = take_tail(entries.len());
				(TpData::Missing(take_misses(l)), 0)
			}
			Err(e) if e == ERR_CONFLICTING_DEPS => {
				let n = entries.len();
				let l = take_tail(1);
				let c = take_conflicts(l)
					.into_iter()
					.map(|c| {
						let (p1, p2) = (
							c.package1, c.package2,
						);
						(
							p1.name.unwrap_or_default(),
							p1.version.unwrap_or_default(),
							p2.name.unwrap_or_default(),
							p2.version.unwrap_or_default(),
							c.reason,
						)
					})
					.collect();
				(TpData::Conflicts(c), n - 1)
			}
			_ => {
				free_misses(&entries);
				(TpData::None, entries.len())
			}
		};
		// SAFETY: the C's nodes, entries freed or moved above
		unsafe { alpm_list_free(data) };
		((ret, out, stale), calls)
	}

	// handle->trans, None without one
	pub fn view(&self) -> Option<TpView> {
		// SAFETY: h is live, its leading fields mirrored
		let t = unsafe { (*self.h.cast::<CHandleHead>()).trans };
		if t.is_null() {
			return None;
		}
		// SAFETY: a live alpm_trans_t
		let t: &CTrans = unsafe { &*t };
		let add = list_data(t.add)
			.into_iter()
			.map(|p| self.add_view(p.cast()))
			.collect();
		let unresolvable = list_data(t.unresolvable)
			.into_iter()
			.map(|p| pkg_name(p.cast()))
			.collect();
		let remove = list_data(t.remove)
			.into_iter()
			.map(|p| {
				let p = crate::package::read_pkg(p.cast());
				let reason = p.reason as c_int;
				(
					p.name.unwrap(),
					p.version.unwrap_or_default(),
					reason,
				)
			})
			.collect();
		Some(TpView {
			flags: t.flags,
			state: t.state,
			add,
			unresolvable,
			remove,
		})
	}

	fn add_view(&self, p: *mut CPkg) -> TpAdd {
		let pkg = crate::package::read_pkg(p);
		// SAFETY: p is live
		let (removes, oldpkg) = unsafe { ((*p).removes, (*p).oldpkg) };
		let db = match pkg.origin {
			Some(alpm_core::package::PkgFrom::File(_)) => None,
			_ => self.id(p).0,
		};
		TpAdd {
			name: pkg.name.unwrap(),
			version: pkg.version.unwrap_or_default(),
			reason: pkg.reason as c_int,
			db,
			removes: list_data(removes)
				.into_iter()
				.map(|r| pkg_name(r.cast()))
				.collect(),
			download_size: pkg.download_size,
			oldpkg: (!oldpkg.is_null()).then(|| {
				crate::package::read_pkg(oldpkg)
					.version
					.unwrap()
			}),
		}
	}
}

// depmissing entries freed (nodes are the caller's)
fn free_misses(entries: &[*mut c_void]) {
	let mut l = ptr::null_mut();
	for &p in entries {
		// SAFETY: a new list over the entries
		l = unsafe { alpm_list_add(l, p) };
	}
	deps_graph::take_misses(l);
}

const ERR_PKG_INVALID_ARCH: c_int =
	alpm_core::error::Errno::PkgInvalidArch as c_int;
const ERR_UNSATISFIED_DEPS: c_int =
	alpm_core::error::Errno::UnsatisfiedDeps as c_int;
const ERR_CONFLICTING_DEPS: c_int =
	alpm_core::error::Errno::ConflictingDeps as c_int;

impl Drop for CTx {
	fn drop(&mut self) {
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h came from alpm_initialize, a transaction left over
		// goes with it; rec from Box::into_raw, unused once h is gone
		unsafe {
			alpm_release(self.h);
			drop(Box::from_raw(self.rec));
		}
	}
}

// ---- frontend ----

// which pacman_* to run
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontOp {
	Sync,
	Remove,
	Upgrade,
}

// pacman_sync/remove/upgrade(targets) on tx's handle with config from
// cfg (also flags, print, op_s_upgrade, holdpkg), COLUMNS = cols, the
// streams captured and stdin reading input. explicit_adds/removes start
// empty. C precondition: the transaction never reaches the commit (the
// caller's input never says yes there, or --print)
pub fn c_front<S: AsRef<[u8]>>(
	op: FrontOp,
	tx: &CTx,
	cfg: &Config,
	targets: &[S],
	cols: u16,
	input: &[u8],
) -> (c_int, CIo) {
	let targs: Vec<CString> =
		targets.iter().map(|t| cstr(t.as_ref())).collect();
	let holds: Vec<CString> = cfg.holdpkg.iter().map(|h| cstr(h)).collect();
	let mut ret = 0;
	let io = run(cfg, cols, input, || {
		let list = |items: &[CString]| {
			let mut l: *mut CList = ptr::null_mut();
			for s in items {
				// SAFETY: l is NULL or built by alpm_list_add
				l = unsafe {
					alpm_list_add(
						l,
						s.as_ptr().cast_mut().cast(),
					)
				};
			}
			l
		};
		let (tl, hl) = (list(&targs), list(&holds));
		// SAFETY: run holds FRONTEND, config is valid; every field set
		// here is put back before the strings drop, list nodes freed
		unsafe {
			let c = &mut *config;
			let old = (
				c.handle,
				c.flags,
				c.print,
				c.op_s_upgrade,
				c.holdpkg,
			);
			c.handle = tx.h;
			c.flags = cfg.flags;
			c.print = cfg.print;
			c.op_s_upgrade = cfg.op_s_upgrade;
			c.holdpkg = hl;
			c.explicit_adds = ptr::null_mut();
			c.explicit_removes = ptr::null_mut();
			ret = match op {
				FrontOp::Sync => pacman_sync(tl),
				FrontOp::Remove => pacman_remove(tl),
				FrontOp::Upgrade => pacman_upgrade(tl),
			};
			alpm_list_free(c.explicit_adds);
			alpm_list_free(c.explicit_removes);
			c.explicit_adds = ptr::null_mut();
			c.explicit_removes = ptr::null_mut();
			(
				c.handle,
				c.flags,
				c.print,
				c.op_s_upgrade,
				c.holdpkg,
			) = old;
			alpm_list_free(tl);
			alpm_list_free(hl);
		}
	});
	(ret, io)
}
