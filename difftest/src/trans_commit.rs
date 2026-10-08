// C side of alpm_trans_commit (trans.c, with sync.c's _alpm_sync_load/
// check/commit, remove.c's and add.c's drivers) on a real handle over a
// fixture world: a local db with its files in the root, one sync db
// "core" whose packages sit on a file:// mirror (some already in the
// cache dir), and package files for -U. a case is a transaction (sync
// targets, sysupgrade, removals or package files) prepared and then
// committed, with hooks from two hook dirs (they run in a chroot of the
// root: fakechroot, a copy of /bin/sh) and signed packages (a GpgFixture
// keyring, the sync db's siglevel; .sig files on the mirror and in the
// cache, %PGPSIG% in the db); the Rust side runs the same on an
// alpm_core Handle.
//
// recorded on both sides in call order: log lines, events (package
// operations, retrieve sizes, hook events and their output lines in
// detail), questions (scripted answers, then the C default 0), progress
// and download init/completed. log lines the port does not make are
// dropped on both sides (see kept).
// compared afterwards: prepare and commit rc/pm_errno, the commit's
// data list, the logfile, the root, local db and cache trees.
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::ptr;
use std::rc::Rc;

use alpm_core::add::add_pkg;
use alpm_core::be_package::pkg_load_level;
use alpm_core::callbacks::{
	Callbacks, DownloadEvent, Event, LogLevel, Progress, Question,
};
use alpm_core::conflict::FileConflictType;
use alpm_core::handle::Handle;
use alpm_core::remove::remove_pkg;
use alpm_core::sync::sync_sysupgrade;
use alpm_core::trans::{
	CommitData, TransState, trans_commit, trans_init, trans_prepare,
	trans_release,
};
use alpm_core::util::compute_sha256sum;

use crate::add_commit::{AcNode, ac_owner, mask_tmpdir, tree};
use crate::conflict::{CFileConflict, alpm_fileconflict_free};
use crate::fixtures::{
	Comp, LocalEntry, TarEntry, TarNode, TempRoot, section, tar_dir,
	tar_file, ustar, ustar_owned, write_db,
};
use crate::handle::log_message;
use crate::handle::{
	_alpm_db_get_pkgcache_hash, ALPM, CDb, CHandleHead, alpm_db_add_server,
	alpm_db_get_pkg, alpm_errno, alpm_get_localdb, alpm_initialize,
	alpm_option_add_cachedir, alpm_option_set_checkspace,
	alpm_option_set_default_siglevel, alpm_option_set_dlcb,
	alpm_option_set_eventcb, alpm_option_set_gpgdir,
	alpm_option_set_hookdirs, alpm_option_set_local_file_siglevel,
	alpm_option_set_logcb, alpm_option_set_logfile,
	alpm_option_set_progresscb, alpm_option_set_questioncb,
	alpm_option_set_remote_file_siglevel, alpm_pkg_load,
	alpm_register_syncdb, alpm_release, alpm_trans_init,
	alpm_trans_release,
};
use crate::hook::{HookRec, c_hook_rec, hook_rec, strip_stamps};
use crate::package::{CPkg, list_data, read_pkg, with_strs};
use crate::signing::{
	GPGME_PROTOCOL_OPENPGP, GpgFixture, encode_base64, gpgme_check_version,
	gpgme_set_engine_info,
};
use crate::trans_prep::{
	alpm_add_pkg, alpm_remove_pkg, alpm_sync_sysupgrade, alpm_trans_prepare,
};
use crate::util::c_umask;
use crate::{CList, alpm_list_free, c_free, cstr};

unsafe extern "C" {
	fn alpm_trans_commit(
		handle: *mut c_void,
		data: *mut *mut CList,
	) -> c_int;
}

// ---- worlds ----

// a package of the world. files: relative paths, directories with a
// trailing '/', parents listed before children
#[derive(Clone, Debug, Default)]
pub struct TcPkg {
	pub name: String,
	pub version: String,
	pub files: Vec<String>,
	pub depends: Vec<String>,
	pub conflicts: Vec<String>,
	pub replaces: Vec<String>,
	pub provides: Vec<String>,
	pub isize: u64,
	// sync only: on the mirror, already in the cache dir, the db's
	// sha256sum wrong, the file's .PKGINFO version differs from the db
	pub on_mirror: bool,
	pub cached: bool,
	pub bad_sum: bool,
	pub mismatch: bool,
	// %CSIZE% instead of the file's size
	pub csize: Option<u64>,
	// sync only: a detached signature (tc_sign), as %PGPSIG% in the
	// db, as .sig next to the package on the mirror and in the cache
	pub sig: Option<Vec<u8>>,
	pub sig_in_db: bool,
	pub sig_on_mirror: bool,
	pub sig_cached: bool,
	// the cached .sig at mode 0: in the cache, unreadable (MISSING_SIG)
	pub sig_unreadable: bool,
}

// what tc_sign signs a package with
#[derive(Clone, Copy, Debug)]
pub enum TcSigKind {
	// a GpgFixture signer key: "full", "marg", "unk", "stranger", ...
	Key(&'static str),
	// a good signature by "full" of other data
	Other,
	// bytes no OpenPGP parser takes
	Garbage,
}

// the signature checks of a case: the gpgdir (GpgFixture::home) and
// the siglevel core is registered with
#[derive(Clone, Debug)]
pub struct TcSign {
	pub gpgdir: Vec<u8>,
	pub level: c_int,
}

#[derive(Clone, Debug, Default)]
pub struct TcWorld {
	pub local: Vec<TcPkg>,
	pub sync: Vec<TcPkg>,
	// -U package files
	pub files: Vec<TcPkg>,
	// root files owned by no package
	pub stray: Vec<String>,
}

// what the transaction does
#[derive(Clone, Debug)]
pub enum TcOp {
	Sync(Vec<String>),
	Sysupgrade,
	Remove(Vec<String>),
	// positions in TcWorld::files
	Upgrade(Vec<usize>),
}

// a hook file: hook dir 0 or 1, file name, text
#[derive(Clone, Debug)]
pub struct TcHook {
	pub dir: usize,
	pub name: String,
	pub text: String,
}

#[derive(Clone, Debug)]
pub struct TcCase {
	pub world: TcWorld,
	pub op: TcOp,
	pub flags: c_int,
	pub checkspace: bool,
	// question answers in order, 0 once used up
	pub answers: Vec<c_int>,
	// none: the default hook dir (root/usr/share/libalpm/hooks/, absent)
	pub hooks: Vec<TcHook>,
	// none: no gpgdir, core at siglevel 0
	pub sign: Option<TcSign>,
}

// hook dir i of the fixture, with its '/'
fn hookdir(fx: &TempRoot, i: usize) -> Vec<u8> {
	tc_dir(fx, &format!("hooks{i}"))
}

// the hook dirs set on the handle, empty for the default
fn tc_hookdirs(fx: &TempRoot, c: &TcCase) -> Vec<Vec<u8>> {
	match c.hooks.is_empty() {
		true => Vec::new(),
		false => (0..2).map(|i| hookdir(fx, i)).collect(),
	}
}

pub const TC_NOLOCK: c_int = 1 << 17;

fn arch_name(p: &TcPkg) -> String {
	format!("{}-{}-x86_64.pkg.tar.gz", p.name, p.version)
}

fn rels(p: &TcPkg) -> String {
	[
		section("DEPENDS", &p.depends),
		section("CONFLICTS", &p.conflicts),
		section("REPLACES", &p.replaces),
		section("PROVIDES", &p.provides),
	]
	.concat()
}

fn file_data(p: &TcPkg, path: &str) -> Vec<u8> {
	format!("{}-{}:{path}\n", p.name, p.version).into_bytes()
}

fn local_desc(p: &TcPkg) -> String {
	format!(
		"%NAME%\n{0}\n\n%VERSION%\n{1}\n\n%BASE%\n{0}\n\n\
		%DESC%\nlocal {0}\n\n%ARCH%\nx86_64\n\n\
		%BUILDDATE%\n1600000000\n\n%INSTALLDATE%\n1600000001\n\n\
		%PACKAGER%\nA B <a@b.org>\n\n%SIZE%\n{2}\n\n{3}",
		p.name,
		p.version,
		p.isize,
		rels(p)
	)
}

fn pkginfo(p: &TcPkg, version: &str) -> String {
	let mut lines = vec![
		format!("pkgname = {}", p.name),
		format!("pkgbase = {}", p.name),
		format!("pkgver = {version}"),
		format!("pkgdesc = new {}", p.name),
		"url = https://example.org/".to_string(),
		"builddate = 1700000000".to_string(),
		"packager = A B <a@b.org>".to_string(),
		format!("size = {}", p.isize),
		"arch = x86_64".to_string(),
	];
	let keyed = [
		("depend", &p.depends),
		("conflict", &p.conflicts),
		("replaces", &p.replaces),
		("provides", &p.provides),
	];
	for (key, values) in keyed {
		lines.extend(values.iter().map(|v| format!("{key} = {v}")));
	}
	lines.join("\n") + "\n"
}

// the package file of p: .PKGINFO (with mismatch the version bumped),
// then its files, owned by the running user
pub fn tc_package(p: &TcPkg) -> Vec<u8> {
	let version = match p.mismatch {
		true => format!("{}.1", p.version),
		false => p.version.clone(),
	};
	let mut nodes = vec![TarNode {
		name: b".PKGINFO".to_vec(),
		kind: b'0',
		mode: 0o644,
		link: Vec::new(),
		data: pkginfo(p, &version).into_bytes(),
	}];
	for f in &p.files {
		let dir = f.ends_with('/');
		nodes.push(TarNode {
			name: f.as_bytes().to_vec(),
			kind: if dir { b'5' } else { b'0' },
			mode: if dir { 0o755 } else { 0o644 },
			link: Vec::new(),
			data: match dir {
				true => Vec::new(),
				false => file_data(p, f),
			},
		});
	}
	ustar_owned(&nodes, ac_owner())
}

fn gzip(tar: &[u8], path: &Path) -> Vec<u8> {
	write_db(path, Comp::Gzip, tar);
	fs::read(path).unwrap()
}

fn sync_desc(p: &TcPkg, csize: u64, sum: &str) -> String {
	let pgpsig = match (&p.sig, p.sig_in_db) {
		(Some(sig), true) => {
			let b64 =
				String::from_utf8(encode_base64(sig)).unwrap();
			format!("%PGPSIG%\n{b64}\n\n")
		}
		_ => String::new(),
	};
	format!(
		"%FILENAME%\n{2}\n\n%NAME%\n{0}\n\n%BASE%\n{0}\n\n\
		%VERSION%\n{1}\n\n%DESC%\nnew {0}\n\n%CSIZE%\n{3}\n\n\
		%ISIZE%\n{4}\n\n%SHA256SUM%\n{5}\n\n{7}%ARCH%\nx86_64\n\n\
		%BUILDDATE%\n1700000000\n\n%PACKAGER%\nA B <a@b.org>\n\n{6}",
		p.name,
		p.version,
		arch_name(p),
		csize,
		p.isize,
		sum,
		rels(p),
		pgpsig
	)
}

// p's signature made once for both sides (gpg signatures carry a
// time): over its package file as tc_write makes it
pub fn tc_sign(fx: &TempRoot, gpg: &GpgFixture, p: &mut TcPkg, k: TcSigKind) {
	let tmp = fx.dir().join("sign.tmp");
	gzip(&tc_package(p), &tmp);
	p.sig = Some(match k {
		TcSigKind::Key(key) => gpg.sign_file(&[key], &tmp),
		TcSigKind::Other => {
			fs::write(&tmp, b"other data\n").unwrap();
			gpg.sign_file(&["full"], &tmp)
		}
		TcSigKind::Garbage => b"\x89\x02garbage, not OpenPGP".to_vec(),
	});
	fs::remove_file(&tmp).unwrap();
}

// <fx>/cache/, <fx>/mirror/, <fx>/pkgs/
pub fn tc_dir(fx: &TempRoot, name: &str) -> Vec<u8> {
	[&fx.path(name)[..], b"/"].concat()
}

fn fresh_dir(path: &Path) {
	crate::fixtures::force_remove(path);
	fs::create_dir_all(path).unwrap();
}

// the world and hooks under fx, everything rebuilt; with hooks a copy
// of /bin/sh in the root. the -U file paths in order
pub fn tc_write(fx: &TempRoot, c: &TcCase) -> Vec<Vec<u8>> {
	let w = &c.world;
	let root = fx.dir().join("root");
	fresh_dir(&root);
	for i in 0..2 {
		fresh_dir(&fx.dir().join(format!("hooks{i}")));
	}
	for hk in &c.hooks {
		let dir = fx.dir().join(format!("hooks{}", hk.dir));
		fs::write(dir.join(&hk.name), &hk.text).unwrap();
	}
	if !c.hooks.is_empty() {
		fs::create_dir_all(root.join("bin")).unwrap();
		fs::copy("/bin/sh", root.join("bin/sh")).unwrap();
	}
	for p in &w.local {
		for f in &p.files {
			let path = root.join(f);
			match f.ends_with('/') {
				true => fs::create_dir_all(&path).unwrap(),
				false => fs::write(&path, file_data(p, f))
					.unwrap(),
			}
		}
	}
	for f in &w.stray {
		let path = root.join(f);
		fs::create_dir_all(path.parent().unwrap()).unwrap();
		if !path.exists() {
			fs::write(&path, b"stray\n").unwrap();
		}
	}
	fx.reset_local();
	let entries: Vec<LocalEntry> = w
		.local
		.iter()
		.map(|p| LocalEntry {
			dir: format!("{}-{}", p.name, p.version),
			desc: Some(local_desc(p).into_bytes()),
			files: Some(section("FILES", &p.files).into_bytes()),
			install: false,
		})
		.collect();
	fx.write_local(&entries);

	let (cache, mirror) = (fx.dir().join("cache"), fx.dir().join("mirror"));
	fresh_dir(&cache);
	fresh_dir(&mirror);
	let mut tar: Vec<TarEntry> = Vec::new();
	for p in &w.sync {
		let file = mirror.join(arch_name(p));
		let data = gzip(&tc_package(p), &file);
		let path = file.as_os_str().as_bytes();
		let sum = compute_sha256sum(path).unwrap();
		let sum = String::from_utf8(sum).unwrap();
		if !p.on_mirror {
			fs::remove_file(&file).unwrap();
		}
		if p.cached {
			fs::write(cache.join(arch_name(p)), &data).unwrap();
		}
		let sigfile = format!("{}.sig", arch_name(p));
		if let Some(sig) = &p.sig {
			if p.sig_on_mirror {
				fs::write(mirror.join(&sigfile), sig).unwrap();
			}
			if p.sig_cached {
				let path = cache.join(&sigfile);
				fs::write(&path, sig).unwrap();
				if p.sig_unreadable {
					set_mode(&path, 0);
				}
			}
		}
		// a valid digest of something else
		let sum = match p.bad_sum {
			true => sum.chars().rev().collect(),
			false => sum,
		};
		let dir = format!("{}-{}/", p.name, p.version);
		tar.push(tar_dir(&dir));
		let csize = p.csize.unwrap_or(data.len() as u64);
		let desc = sync_desc(p, csize, &sum);
		tar.push(tar_file(&format!("{dir}desc"), desc.as_bytes()));
	}
	write_db(&fx.sync_file("core", ".db"), Comp::None, &ustar(&tar));

	let pkgs = fx.dir().join("pkgs");
	fresh_dir(&pkgs);
	w.files.iter()
		.map(|p| {
			let path = pkgs.join(arch_name(p));
			gzip(&tc_package(p), &path);
			path.as_os_str().as_bytes().to_vec()
		})
		.collect()
}

// ---- what both sides record ----

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcRec {
	Log(c_int, Vec<u8>),
	Event(c_int),
	// start (false) or done, operation, old and new "name version"
	Op(bool, c_int, Option<Vec<u8>>, Option<Vec<u8>>),
	// PKG_RETRIEVE_* kind, num, total_size
	Retrieve(c_int, usize, i64),
	// question kind; the corrupted file and its reason, or the key's
	// uid and fingerprint to import
	Ask(c_int, Option<(Vec<u8>, c_int)>),
	AskKey(Option<Vec<u8>>, Vec<u8>),
	Progress(c_int, Vec<u8>, c_int, usize, usize),
	// filename, init (optional) or completed (result)
	Download(Vec<u8>, Result<bool, c_int>),
	// hook events and scriptlet/hook output lines
	Hook(HookRec),
}

// a file conflict: target, type, file, ctarget
pub type TcConflict = (Vec<u8>, c_int, Vec<u8>, Vec<u8>);

// the commit's data list as compared
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TcData {
	#[default]
	None,
	Conflicts(Vec<TcConflict>),
	Invalid(Vec<Vec<u8>>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct TcResult {
	// 0 or pm_errno
	pub prepare: c_int,
	// None when the prepare failed
	pub commit: Option<(c_int, c_int)>,
	pub data: TcData,
	// alpm_transstate_t after the commit
	pub state: c_int,
	pub recs: Vec<TcRec>,
	pub logfile: Vec<u8>,
	pub root: AcNode,
	pub local: AcNode,
	pub cache: AcNode,
}

const LOG_DEBUG: c_int = 4;
const LOG_FUNCTION: c_int = 8;
const EV_OP_START: c_int = 11;
const EV_OP_DONE: c_int = 12;
const EV_RETRIEVE_START: c_int = 21;
const EV_RETRIEVE_FAILED: c_int = 23;
const Q_CORRUPTED: c_int = 1 << 3;
const Q_IMPORT_KEY: c_int = 1 << 6;

// debug lines the port does not make: RET_ERR's and GOTO_ERR's
const C_ONLY: [&[u8]; 2] = [b"returning error ", b"got error "];

// signing.c's debug lines (gpgme internals, key lookups, signature
// details), not ported yet (PORTING.md follow-ups): their starts
const SIGNING_DEBUG: [&[u8]; 24] = [
	b"checking signature for ",
	b"could not import key, 0 results\n",
	b"exp_timestamp: ",
	b"fingerprint: ",
	b"gpg error: ",
	b"GPGME engine info: ",
	b"GPGME version: ",
	b"importing key\n",
	b"key \"",
	b"key lookup ",
	b"key: ",
	b"looking up key ",
	b"missing optional signature\n",
	b"missing required signature\n",
	b"no signatures returned\n",
	b"signature check failed\n",
	b"signature is ",
	b"signature should never be trusted\n",
	b"signature timestamp is greater than system time.\n",
	b"Signature verification will fail!\n",
	b"sig path ",
	b"status: ",
	b"summary: ",
	b"validity: ",
];

fn signing_debug(m: &[u8]) -> bool {
	let found = |m: &[u8]| {
		m.starts_with(b"key ") && m.ends_with(b" found in cache\n")
	};
	SIGNING_DEBUG.iter().any(|p| m.starts_with(p))
		|| m.starts_with(b"timestamp: ")
		|| m.ends_with(b" signatures returned\n")
		|| found(m)
}

// the records compared: no FUNCTION lines (the lazy loads: the port
// loads every local file list before the file conflict check, the C as
// it goes), no debug lines of C_ONLY, and no debug lines inside a
// download (dload's internals)
pub fn kept(recs: Vec<TcRec>) -> Vec<TcRec> {
	let mut quiet = false;
	let mut out: Vec<TcRec> = Vec::new();
	for r in recs {
		let after_sig_data = matches!(
			out.last(),
			Some(TcRec::Log(LOG_DEBUG, m)) if m.starts_with(b"sig data: ")
		);
		match &r {
			TcRec::Retrieve(EV_RETRIEVE_START, ..) => quiet = true,
			TcRec::Retrieve(..) => quiet = false,
			TcRec::Log(LOG_FUNCTION, _) => continue,
			TcRec::Log(LOG_DEBUG, m)
				if quiet || signing_debug(m)
					|| (after_sig_data
						&& sig_unreadable(m)) || C_ONLY
					.iter()
					.any(|p| m.starts_with(p)) =>
			{
				continue;
			}
			_ => {}
		}
		out.push(r);
	}
	out
}

// _alpm_access's line for a .sig: right after be_package's "sig data:"
// line it is _alpm_gpgme_checksig's (signing.c), the port's checksig
// does not log it. be_package's own check of the same path comes before
fn sig_unreadable(m: &[u8]) -> bool {
	let key: &[u8] = b".sig\" is not readable: ";
	m.windows(key.len()).any(|w| w == key)
}

// the free block counts of diskspace's partition lines: the disk the
// fixtures sit on changes between the two runs
fn mask_free(msg: &[u8]) -> Vec<u8> {
	let keys: [&[u8]; 2] = [b", free ", b" blocks needed, "];
	if !msg.to_ascii_lowercase().starts_with(b"partition ") {
		return msg.to_vec();
	}
	let mut out = msg.to_vec();
	for key in keys {
		let Some(i) = out.windows(key.len()).position(|w| w == key)
		else {
			continue;
		};
		let start = i + key.len();
		let digits =
			out[start..].iter().take_while(|c| c.is_ascii_digit());
		let end = start + digits.count();
		out = [&out[..start], b"<n>", &out[end..]].concat();
	}
	out
}

fn name_ver(p: &alpm_core::package::Package) -> Vec<u8> {
	let n = p.name.as_deref().unwrap_or_default();
	let v = p.version.as_deref().unwrap_or_default();
	[n, b" ", v].concat()
}

// files of dir at mode 0 (sig_unreadable) made readable again, so
// the tree can be read
fn readable_again(dir: &Path) {
	for e in fs::read_dir(dir).unwrap() {
		let path = e.unwrap().path();
		let m = fs::symlink_metadata(&path).unwrap();
		if m.is_file() && m.permissions().mode() & 0o777 == 0 {
			set_mode(&path, 0o644);
		}
	}
}

fn set_mode(path: &Path, mode: u32) {
	fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn snapshot_all(fx: &TempRoot) -> (AcNode, AcNode, AcNode) {
	readable_again(&fx.dir().join("cache"));
	(
		tree(&fx.dir().join("root"), false),
		tree(&fx.local(), true),
		tree(&fx.dir().join("cache"), false),
	)
}

// ---- C ----

struct CRec {
	recs: Vec<TcRec>,
	answers: VecDeque<c_int>,
}

fn c_bytes(p: *const c_char) -> Vec<u8> {
	// SAFETY: a nul-terminated string alive for the callback
	unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
}

fn c_name_ver(p: *mut CPkg) -> Option<Vec<u8>> {
	(!p.is_null()).then(|| name_ver(&read_pkg(p)))
}

unsafe extern "C" fn log_cb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	args: *mut c_void,
) {
	// SAFETY: fmt and args are the pair this callback got
	let msg = unsafe { log_message(fmt, args) };
	// SAFETY: ctx is the boxed CRec
	let rec = unsafe { &mut *ctx.cast::<CRec>() };
	rec.recs.push(TcRec::Log(level, msg));
}

// alpm_event_package_operation_t, alpm_event_pkg_retrieve_t
#[repr(C)]
struct CEvOp {
	kind: c_int,
	operation: c_int,
	oldpkg: *mut CPkg,
	newpkg: *mut CPkg,
}

#[repr(C)]
struct CEvRetrieve {
	kind: c_int,
	num: usize,
	total_size: i64,
}

unsafe extern "C" fn event_cb(ctx: *mut c_void, event: *mut c_void) {
	// SAFETY: every event starts with its type; ctx is the CRec
	let (rec, kind) =
		unsafe { (&mut *ctx.cast::<CRec>(), *event.cast::<c_int>()) };
	// SAFETY: a live event
	if let Some(h) = unsafe { c_hook_rec(event) } {
		rec.recs.push(TcRec::Hook(h));
		return;
	}
	// SAFETY: the casts follow kind
	let r = unsafe {
		match kind {
			EV_OP_START | EV_OP_DONE => {
				let e = &*event.cast::<CEvOp>();
				TcRec::Op(
					kind == EV_OP_DONE,
					e.operation,
					c_name_ver(e.oldpkg),
					c_name_ver(e.newpkg),
				)
			}
			EV_RETRIEVE_START..=EV_RETRIEVE_FAILED => {
				let e = &*event.cast::<CEvRetrieve>();
				TcRec::Retrieve(kind, e.num, e.total_size)
			}
			k => TcRec::Event(k),
		}
	};
	rec.recs.push(r);
}

// alpm_question_corrupted_t; every question has type then answer
#[repr(C)]
struct CQCorrupted {
	kind: c_int,
	remove: c_int,
	filepath: *const c_char,
	reason: c_int,
}

// alpm_question_import_key_t
#[repr(C)]
struct CQImportKey {
	kind: c_int,
	import: c_int,
	uid: *const c_char,
	fingerprint: *const c_char,
}

unsafe extern "C" fn question_cb(ctx: *mut c_void, q: *mut c_void) {
	// SAFETY: ctx is the CRec; q starts with type and answer
	let (rec, kind) =
		unsafe { (&mut *ctx.cast::<CRec>(), *q.cast::<c_int>()) };
	let detail = (kind == Q_CORRUPTED).then(|| {
		// SAFETY: a CORRUPTED_PKG question
		let c = unsafe { &*q.cast::<CQCorrupted>() };
		(c_bytes(c.filepath), c.reason)
	});
	rec.recs.push(TcRec::Ask(kind, detail));
	if kind == Q_IMPORT_KEY {
		// SAFETY: an IMPORT_KEY question, uid may be NULL
		let k = unsafe { &*q.cast::<CQImportKey>() };
		let uid = (!k.uid.is_null()).then(|| c_bytes(k.uid));
		rec.recs.push(TcRec::AskKey(uid, c_bytes(k.fingerprint)));
	}
	let answer = rec.answers.pop_front().unwrap_or(0);
	// SAFETY: the answer int follows the type in every question
	unsafe { *q.cast::<c_int>().add(1) = answer };
}

unsafe extern "C" fn progress_cb(
	ctx: *mut c_void,
	kind: c_int,
	pkg: *const c_char,
	percent: c_int,
	howmany: usize,
	current: usize,
) {
	// SAFETY: ctx is the CRec
	let rec = unsafe { &mut *ctx.cast::<CRec>() };
	let r = TcRec::Progress(kind, c_bytes(pkg), percent, howmany, current);
	rec.recs.push(r);
}

// alpm_download_event_completed_t
#[repr(C)]
struct CCompleted {
	total: i64,
	result: c_int,
}

unsafe extern "C" fn dl_cb(
	ctx: *mut c_void,
	filename: *const c_char,
	event: c_int,
	data: *mut c_void,
) {
	// SAFETY: ctx is the CRec, data the event's struct
	let (rec, r) = unsafe {
		let r = match event {
			0 => Ok(*data.cast::<c_int>() != 0),
			3 => Err((*data.cast::<CCompleted>()).result),
			// progress and retry depend on timing
			_ => return,
		};
		(&mut *ctx.cast::<CRec>(), r)
	};
	rec.recs.push(TcRec::Download(c_bytes(filename), r));
}

// the commit data list read out and freed: filenames or fileconflicts
fn c_data(errno: c_int, data: *mut CList) -> TcData {
	let items = list_data(data);
	let out = if items.is_empty() {
		TcData::None
	} else if errno == alpm_core::error::Errno::FileConflicts as c_int {
		let list = items
			.iter()
			.map(|&p| {
				let c = p.cast::<CFileConflict>();
				// SAFETY: a live alpm_fileconflict_t of the list
				let r = unsafe {
					(
						c_bytes((*c).target),
						(*c).conflict_type,
						c_bytes((*c).file),
						c_bytes((*c).ctarget),
					)
				};
				// SAFETY: freed once, not used after
				unsafe { alpm_fileconflict_free(c) };
				r
			})
			.collect();
		TcData::Conflicts(list)
	} else {
		let list = items
			.iter()
			.map(|&p| {
				let s = c_bytes(p.cast());
				c_free(p);
				s
			})
			.collect();
		TcData::Invalid(list)
	};
	// SAFETY: the nodes, their data freed above
	unsafe { alpm_list_free(data) };
	out
}

// the case on a C handle, the world rebuilt first. the caller holds
// umask_lock
pub fn c_commit(fx: &TempRoot, c: &TcCase) -> TcResult {
	let paths = tc_write(fx, c);
	let hookdirs = tc_hookdirs(fx, c);
	let logfile = fx.dir().join("log");
	let _ = fs::remove_file(&logfile);
	let (root, dbpath) = (cstr(&fx.root()), cstr(&fx.dbpath()));
	let log = cstr(logfile.as_os_str().as_bytes());
	let cache = cstr(&tc_dir(fx, "cache"));
	let server = cstr(&[b"file://", &fx.path("mirror")[..]].concat());
	let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
	let mut err = 0;
	// SAFETY: valid C strings, err is writable
	let h = unsafe {
		alpm_initialize(root.as_ptr(), dbpath.as_ptr(), &mut err)
	};
	assert!(!h.is_null(), "alpm_initialize: {err}");
	let rec: *mut CRec = Box::into_raw(Box::new(CRec {
		recs: Vec::new(),
		answers: c.answers.iter().copied().collect(),
	}));
	// SAFETY: h is live until alpm_release; setters copy their strings;
	// rec stays valid until freed after the release. packages handed
	// to alpm_add_pkg/remove_pkg are cache entries or loaded files the
	// transaction owns from then on
	let (prepare, commit, data, state) = unsafe {
		assert_eq!(alpm_option_set_logfile(h, log.as_ptr()), 0);
		assert_eq!(alpm_option_add_cachedir(h, cache.as_ptr()), 0);
		alpm_option_set_default_siglevel(h, 0);
		alpm_option_set_local_file_siglevel(h, 0);
		alpm_option_set_remote_file_siglevel(h, 0);
		alpm_option_set_checkspace(h, c_int::from(c.checkspace));
		if !hookdirs.is_empty() {
			with_strs(&hookdirs, |l| {
				alpm_option_set_hookdirs(h, l)
			});
		}
		let mut level = 0;
		if let Some(sg) = &c.sign {
			// init_gpgme points gpgme's engine at the first
			// handle's gpgdir only, once per process
			let dir = cstr(&sg.gpgdir);
			gpgme_check_version(ptr::null());
			assert_eq!(alpm_option_set_gpgdir(h, dir.as_ptr()), 0);
			let p = GPGME_PROTOCOL_OPENPGP;
			gpgme_set_engine_info(p, ptr::null(), dir.as_ptr());
			level = sg.level;
		}
		let core = cstr(b"core");
		let db = alpm_register_syncdb(h, core.as_ptr(), level);
		assert!(!db.is_null());
		assert_eq!(alpm_db_add_server(db, server.as_ptr()), 0);
		let local: *mut CDb = alpm_get_localdb(h);
		_alpm_db_get_pkgcache_hash(local);
		_alpm_db_get_pkgcache_hash(db);
		alpm_option_set_logcb(h, Some(log_cb), rec.cast());
		alpm_option_set_eventcb(h, Some(event_cb), rec.cast());
		alpm_option_set_questioncb(h, Some(question_cb), rec.cast());
		alpm_option_set_progresscb(h, Some(progress_cb), rec.cast());
		alpm_option_set_dlcb(h, Some(dl_cb), rec.cast());
		assert_eq!(alpm_trans_init(h, c.flags), 0, "trans_init");
		match &c.op {
			TcOp::Sync(names) => {
				for n in names {
					let n = cstr(n.as_bytes());
					let p = alpm_db_get_pkg(db, n.as_ptr());
					assert!(!p.is_null(), "no sync {n:?}");
					alpm_add_pkg(h, p);
				}
			}
			TcOp::Sysupgrade => {
				alpm_sync_sysupgrade(h, 0);
			}
			TcOp::Remove(names) => {
				for n in names {
					let n = cstr(n.as_bytes());
					let p = alpm_db_get_pkg(
						local,
						n.as_ptr(),
					);
					assert!(!p.is_null(), "no local {n:?}");
					alpm_remove_pkg(h, p);
				}
			}
			TcOp::Upgrade(files) => {
				for &i in files {
					let path = cstr(&paths[i]);
					let mut p: *mut CPkg = ptr::null_mut();
					let r = alpm_pkg_load(
						h,
						path.as_ptr(),
						1,
						0,
						&mut p,
					);
					assert_eq!(r, 0, "alpm_pkg_load");
					alpm_add_pkg(h, p);
				}
			}
		}
		let mut pdata: *mut CList = ptr::null_mut();
		let r = alpm_trans_prepare(h, &mut pdata);
		// the prepare's own data is compared in trans_prep
		let prepare = match r {
			0 => 0,
			_ => alpm_errno(h),
		};
		let mut commit = None;
		let mut data = TcData::None;
		let mut state = 0;
		if r == 0 {
			let mut cdata: *mut CList = ptr::null_mut();
			let old = c_umask(0o022);
			let rc = alpm_trans_commit(h, &mut cdata);
			c_umask(old);
			// pm_errno is only meaningful on failure
			let errno = match rc {
				0 => 0,
				_ => alpm_errno(h),
			};
			commit = Some((rc, errno));
			data = c_data(errno, cdata);
			state = (*(*h.cast::<CHandleHead>()).trans).state;
		}
		let _ = pdata;
		alpm_option_set_logcb(h, None, ptr::null_mut());
		alpm_option_set_eventcb(h, None, ptr::null_mut());
		alpm_option_set_questioncb(h, None, ptr::null_mut());
		alpm_option_set_progresscb(h, None, ptr::null_mut());
		alpm_option_set_dlcb(h, None, ptr::null_mut());
		alpm_trans_release(h);
		alpm_release(h);
		(prepare, commit, data, state)
	};
	drop(guard);
	// SAFETY: built by Box::into_raw above, the C is done with it
	let rec = *unsafe { Box::from_raw(rec) };
	finish(fx, prepare, commit, data, state, rec.recs, &logfile)
}

fn finish(
	fx: &TempRoot,
	prepare: c_int,
	commit: Option<(c_int, c_int)>,
	data: TcData,
	state: c_int,
	recs: Vec<TcRec>,
	logfile: &Path,
) -> TcResult {
	let log = fs::read(logfile).unwrap_or_default();
	let recs = recs
		.into_iter()
		.map(|r| match r {
			TcRec::Log(l, m) => {
				TcRec::Log(l, mask_free(&mask_tmpdir(&m)))
			}
			r => r,
		})
		.collect();
	let (root, local, cache) = snapshot_all(fx);
	TcResult {
		prepare,
		commit,
		data,
		state,
		recs: kept(recs),
		logfile: strip_stamps(&log),
		root,
		local,
		cache,
	}
}

// ---- Rust ----

struct RustRec {
	recs: Rc<RefCell<Vec<TcRec>>>,
	answers: VecDeque<c_int>,
}

impl Callbacks for RustRec {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		let r = TcRec::Log(level as c_int, msg.to_vec());
		self.recs.borrow_mut().push(r);
	}

	fn event(&mut self, event: &Event<'_>) {
		if let Some(h) = hook_rec(event) {
			self.recs.borrow_mut().push(TcRec::Hook(h));
			return;
		}
		let r = match event {
			Event::PackageOperationStart(op)
			| Event::PackageOperationDone(op) => TcRec::Op(
				matches!(event, Event::PackageOperationDone(_)),
				op.operation as c_int,
				op.oldpkg.map(name_ver),
				op.newpkg.map(name_ver),
			),
			Event::PkgRetrieveStart { num, total_size }
			| Event::PkgRetrieveDone { num, total_size }
			| Event::PkgRetrieveFailed { num, total_size } => {
				TcRec::Retrieve(event.kind(), *num, *total_size)
			}
			e => TcRec::Event(e.kind()),
		};
		self.recs.borrow_mut().push(r);
	}

	fn question(&mut self, q: &mut Question<'_>) {
		let detail = match q {
			Question::CorruptedPkg {
				filepath, reason, ..
			} => Some((filepath.to_vec(), *reason as c_int)),
			_ => None,
		};
		self.recs.borrow_mut().push(TcRec::Ask(q.kind(), detail));
		if let Question::ImportKey {
			uid, fingerprint, ..
		} = q
		{
			let r = TcRec::AskKey(
				uid.map(<[u8]>::to_vec),
				fingerprint.to_vec(),
			);
			self.recs.borrow_mut().push(r);
		}
		q.set_answer(self.answers.pop_front().unwrap_or(0));
	}

	fn progress(
		&mut self,
		progress: Progress,
		pkg: &[u8],
		percent: c_int,
		howmany: usize,
		current: usize,
	) {
		let r = TcRec::Progress(
			progress as c_int,
			pkg.to_vec(),
			percent,
			howmany,
			current,
		);
		self.recs.borrow_mut().push(r);
	}

	fn download(&mut self, filename: &[u8], event: DownloadEvent) {
		let r = match event {
			DownloadEvent::Init { optional } => Ok(optional),
			DownloadEvent::Completed { result, .. } => Err(result),
			_ => return,
		};
		let r = TcRec::Download(filename.to_vec(), r);
		self.recs.borrow_mut().push(r);
	}
}

fn rust_data(d: &CommitData) -> TcData {
	match d {
		CommitData::None => TcData::None,
		CommitData::Invalid(v) if v.is_empty() => TcData::None,
		CommitData::Invalid(v) => TcData::Invalid(v.clone()),
		CommitData::FileConflicts(v) => TcData::Conflicts(
			v.iter().map(|c| {
				let t = match c.conflict_type {
					FileConflictType::Target => 1,
					FileConflictType::Filesystem => 2,
				};
				let (f, ct) =
					(c.file.clone(), c.ctarget.clone());
				(c.target.clone(), t, f, ct)
			})
			.collect(),
		),
	}
}

fn state_num(s: TransState) -> c_int {
	match s {
		TransState::Idle => 0,
		TransState::Initialized => 1,
		TransState::Prepared => 2,
		TransState::Downloading => 3,
		TransState::Committing => 4,
		TransState::Committed => 5,
		TransState::Interrupted => 6,
	}
}

// the case on an alpm_core Handle, the world rebuilt first. the caller
// holds umask_lock
pub fn rust_commit(fx: &TempRoot, c: &TcCase) -> TcResult {
	let paths = tc_write(fx, c);
	let hookdirs = tc_hookdirs(fx, c);
	let logfile = fx.dir().join("log");
	let _ = fs::remove_file(&logfile);
	let mut h = Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
	h.set_logfile(logfile.as_os_str().as_bytes());
	h.add_cachedir(&tc_dir(fx, "cache"));
	h.set_checkspace(c_int::from(c.checkspace));
	if !hookdirs.is_empty() {
		h.set_hookdirs(&hookdirs);
	}
	let mut level = 0;
	if let Some(sg) = &c.sign {
		h.set_gpgdir(&sg.gpgdir);
		level = sg.level;
	}
	let server = [b"file://", &fx.path("mirror")[..]].concat();
	{
		let db = h.register_syncdb(b"core", level).unwrap();
		db.set_servers(&mut (), &[server]).unwrap();
	}
	let d = h.dbs_mut();
	let _ = d.local.unwrap().pkgcache(d.dbext, &mut ());
	let _ = d.sync[0].pkgcache(d.dbext, &mut ());
	let recs = Rc::new(RefCell::new(Vec::new()));
	h.set_callbacks(Box::new(RustRec {
		recs: recs.clone(),
		answers: c.answers.iter().copied().collect(),
	}));
	trans_init(&mut h, c.flags).unwrap();
	let get = |h: &mut Handle, sync: bool, n: &str| {
		let d = h.dbs_mut();
		let db = match sync {
			true => &mut d.sync[0],
			false => d.local.unwrap(),
		};
		db.get_pkg(d.dbext, d.cb, n.as_bytes()).unwrap().clone()
	};
	match &c.op {
		TcOp::Sync(names) => {
			for n in names {
				let p = get(&mut h, true, n);
				let _ = add_pkg(&mut h, p, Some(0));
			}
		}
		TcOp::Sysupgrade => {
			let _ = sync_sysupgrade(&mut h, false);
		}
		TcOp::Remove(names) => {
			for n in names {
				let p = get(&mut h, false, n);
				let _ = remove_pkg(&mut h, &p);
			}
		}
		TcOp::Upgrade(files) => {
			for &i in files {
				let p = h.with_callbacks(|h, cb| {
					let kr = h.keyring_mut();
					pkg_load_level(
						kr, cb, &paths[i], true, 0,
					)
				});
				let p = p.unwrap();
				let _ = add_pkg(&mut h, p, None);
			}
		}
	}
	let (prepare, mut commit, mut data, mut state) =
		match trans_prepare(&mut h) {
			Ok(()) => (0, None, TcData::None, 0),
			Err(e) => (e.errno as c_int, None, TcData::None, 0),
		};
	if prepare == 0 {
		let r = trans_commit(&mut h);
		commit = Some(match &r {
			Ok(()) => (0, 0),
			Err(e) => (-1, e.errno as c_int),
		});
		if let Err(e) = &r {
			data = rust_data(&e.data);
		}
		state = state_num(h.trans().unwrap().state);
	}
	h.set_callbacks(Box::new(()));
	trans_release(&mut h).unwrap();
	drop(h);
	let recs = std::mem::take(&mut *recs.borrow_mut());
	finish(fx, prepare, commit, data, state, recs, &logfile)
}
