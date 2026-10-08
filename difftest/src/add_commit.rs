// C side of the per-package commit of add.c: _alpm_upgrade_packages
// (commit_single_pkg and its statics are reached through it) on a real
// handle with a minimal transaction: alpm_trans_init, alpm_pkg_load and
// alpm_add_pkg of one package file, newpkg->oldpkg set to a dup of the
// installed package like _alpm_sync_prepare does. the Rust side runs
// alpm_core::add::upgrade_package on the same setup.
//
// recorded on both sides in call order: log lines, the events add.c and
// remove.c send, progress; the logfile text without stamps comes apart.
// cases are built twice from one AcCase, once per side.
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::ptr;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_core::be_local::INFRQ_ALL;
use alpm_core::callbacks::{Callbacks, Event, LogLevel, Progress};
use alpm_core::handle::Handle;
use alpm_core::package::Package;
use alpm_core::{add, be_package, trans, util};

use crate::cstr;
use crate::fixtures::{
	Comp, LocalEntry, Node, TarNode, TempRoot, snapshot, ustar_entries,
	write_db,
};
use crate::handle::log_message;
use crate::handle::{
	ALPM, CDb, alpm_db_get_pkg, alpm_errno, alpm_get_localdb,
	alpm_initialize, alpm_option_set_eventcb, alpm_option_set_logcb,
	alpm_option_set_logfile, alpm_option_set_noextracts,
	alpm_option_set_noupgrades, alpm_option_set_progresscb, alpm_pkg_load,
	alpm_release, alpm_trans_init, alpm_trans_release,
};
use crate::hook::strip_stamps;
use crate::package::{_alpm_pkg_dup, CPkg, read_pkg, text, with_strs};
use crate::trans_prep::alpm_add_pkg;
use crate::util::c_umask;

// ALPM_TRANS_FLAG_NOLOCK: no lock file under the fixture dbpath
pub const AC_NOLOCK: c_int = 1 << 17;
// set when SOURCE_DATE_EPOCH is valid: %INSTALLDATE% compared as is
pub const AC_SDE_EXACT: &str = "DIFFTEST_SDE_EXACT";
// set: the C runs in the C locale instead of C.UTF-8
pub const AC_C_LOCALE: &str = "DIFFTEST_C_LOCALE";
// every tar entry's mtime (fixtures::header)
pub const AC_MTIME: i64 = 1_700_000_000;
// times from here on are the run's own (now), the archives' lie below
const AC_RUN_TIME: i64 = AC_MTIME + 1_000_000;

unsafe extern "C" {
	fn _alpm_upgrade_packages(handle: *mut c_void) -> c_int;
}

// ---- cases ----

// what sits in the root before the commit
#[derive(Clone, Debug)]
pub enum AcFs {
	File(Vec<u8>, u32, Vec<u8>),
	Dir(Vec<u8>, u32),
	Link(Vec<u8>, Vec<u8>),
}

// the installed package of the same name: version, %FILES%, %BACKUP%
// (name, md5 or None for a "(null)" hash), reason, install scriptlet
#[derive(Clone, Debug)]
pub struct AcOld {
	pub version: String,
	pub files: Vec<String>,
	pub backup: Vec<(String, Option<String>)>,
	pub asdep: bool,
	pub install: bool,
}

#[derive(Clone, Debug)]
pub struct AcCase {
	pub name: String,
	pub version: String,
	// the package's entries after .PKGINFO, in archive order
	pub nodes: Vec<TarNode>,
	// members written by hand after the nodes (pax headers)
	pub tail: Vec<u8>,
	pub backup: Vec<String>,
	pub comp: Comp,
	// entry owner, None: the running user
	pub owner: Option<(u32, u32)>,
	pub root: Vec<AcFs>,
	pub old: Option<AcOld>,
	pub noupgrade: Vec<Vec<u8>>,
	pub noextract: Vec<Vec<u8>>,
	pub flags: c_int,
	// newpkg->oldpkg set even when no old package is installed
	pub stale_oldpkg: bool,
	// the package file cut to this many bytes after loading it
	pub cut: Option<usize>,
	// a ready package file used instead of .PKGINFO, nodes and tail
	pub file: Option<PathBuf>,
}

// uid and gid of the running process, as files get them
pub fn ac_owner() -> (u32, u32) {
	// one probe per call: test threads ask at the same time
	static N: AtomicUsize = AtomicUsize::new(0);
	let n = N.fetch_add(1, Ordering::Relaxed);
	let probe = std::env::temp_dir()
		.join(format!("difftest-owner-{}-{n}", std::process::id()));
	fs::write(&probe, b"").unwrap();
	let p = fs::metadata(&probe).unwrap();
	fs::remove_file(&probe).unwrap();
	(p.uid(), p.gid())
}

fn pkginfo(c: &AcCase) -> String {
	let mut lines = vec![
		format!("pkgname = {}", c.name),
		format!("pkgbase = {}", c.name),
		format!("pkgver = {}", c.version),
		"pkgdesc = A file package".to_string(),
		"url = https://example.org/".to_string(),
		"builddate = 1700000000".to_string(),
		"packager = A B <a@b.org>".to_string(),
		"size = 1234".to_string(),
		"arch = x86_64".to_string(),
	];
	lines.extend(c.backup.iter().map(|b| format!("backup = {b}")));
	lines.join("\n") + "\n"
}

fn old_desc(c: &AcCase, o: &AcOld) -> String {
	let reason = match o.asdep {
		true => "%REASON%\n1\n\n",
		false => "",
	};
	format!(
		"%NAME%\n{0}\n\n%VERSION%\n{1}\n\n%BASE%\n{0}\n\n\
		%DESC%\nOld\n\n%URL%\nhttps://example.org/\n\n\
		%ARCH%\nx86_64\n\n%BUILDDATE%\n1600000000\n\n\
		%INSTALLDATE%\n1600000001\n\n%PACKAGER%\nA B <a@b.org>\n\n\
		%SIZE%\n10\n\n{reason}",
		c.name, o.version
	)
}

fn old_files(o: &AcOld) -> String {
	let mut s = String::new();
	if !o.files.is_empty() {
		s += &format!("%FILES%\n{}\n\n", o.files.join("\n"));
	}
	if !o.backup.is_empty() {
		s += "%BACKUP%\n";
		for (n, h) in &o.backup {
			let h = h.as_deref().unwrap_or("(null)");
			s += &format!("{n}\t{h}\n");
		}
		s += "\n";
	}
	s
}

// the root (cleared, then filled), the local db and the package file
// under fx; the package path
pub fn ac_build(fx: &TempRoot, c: &AcCase) -> Vec<u8> {
	let root = fx.dir().join("root");
	crate::fixtures::force_remove(&root);
	fs::create_dir(&root).unwrap();
	for e in &c.root {
		let path = |p: &[u8]| root.join(std::ffi::OsStr::from_bytes(p));
		match e {
			AcFs::Dir(p, mode) => {
				fs::create_dir_all(path(p)).unwrap();
				let perm = fs::Permissions::from_mode(*mode);
				fs::set_permissions(path(p), perm).unwrap();
			}
			AcFs::File(p, mode, data) => {
				let p = path(p);
				fs::create_dir_all(p.parent().unwrap())
					.unwrap();
				fs::write(&p, data).unwrap();
				let perm = fs::Permissions::from_mode(*mode);
				fs::set_permissions(&p, perm).unwrap();
			}
			AcFs::Link(p, target) => {
				let p = path(p);
				fs::create_dir_all(p.parent().unwrap())
					.unwrap();
				let t = std::ffi::OsStr::from_bytes(target);
				symlink(t, &p).unwrap();
			}
		}
	}
	fx.reset_local();
	if let Some(o) = &c.old {
		fx.write_local(&[LocalEntry {
			dir: format!("{}-{}", c.name, o.version),
			desc: Some(old_desc(c, o).into_bytes()),
			files: Some(old_files(o).into_bytes()),
			install: o.install,
		}]);
	}
	let pkgs = fx.dir().join("pkgs");
	fs::create_dir_all(&pkgs).unwrap();
	if let Some(file) = &c.file {
		let path = pkgs.join(file.file_name().unwrap());
		fs::copy(file, &path).unwrap();
		return path.as_os_str().as_bytes().to_vec();
	}
	let info = TarNode {
		name: b".PKGINFO".to_vec(),
		kind: b'0',
		mode: 0o644,
		link: Vec::new(),
		data: pkginfo(c).into_bytes(),
	};
	let mut nodes = vec![info];
	nodes.extend(c.nodes.iter().cloned());
	let owner = c.owner.unwrap_or_else(ac_owner);
	let mut tar = ustar_entries(&nodes, owner);
	tar.extend_from_slice(&c.tail);
	tar.resize(tar.len() + 1024, 0);
	let path = pkgs.join(format!("{}-{}.pkg.tar", c.name, c.version));
	if path.exists() {
		fs::remove_file(&path).unwrap();
	}
	write_db(&path, c.comp, &tar);
	path.as_os_str().as_bytes().to_vec()
}

// AcCase::cut on the loaded package file
fn cut_pkg(path: &[u8], c: &AcCase) {
	let Some(n) = c.cut else { return };
	let path = Path::new(std::ffi::OsStr::from_bytes(path));
	let data = fs::read(path).unwrap();
	fs::write(path, &data[..n.min(data.len())]).unwrap();
}

// ---- what both sides record ----

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcRec {
	Log(c_int, Vec<u8>),
	// start (false) or done, operation, old and new "name version"
	Op(bool, c_int, Option<Vec<u8>>, Option<Vec<u8>>),
	// from_noupgrade, old and new name, file
	Pacnew(bool, Option<Vec<u8>>, Vec<u8>, Vec<u8>),
	Pacsave(Vec<u8>, Vec<u8>),
	Scriptlet(Vec<u8>),
	// kind, package, percent, howmany, current
	Progress(c_int, Vec<u8>, c_int, usize, usize),
	Event(c_int),
}

// rc and pm_errno, the records, the logfile without stamps, the root
// and local db afterwards
#[derive(Debug, PartialEq, Eq)]
pub struct AcResult {
	pub rc: c_int,
	pub errno: c_int,
	pub recs: Vec<AcRec>,
	pub logfile: Vec<u8>,
	pub root: AcNode,
	pub local: AcNode,
}

// fixtures::Node plus the metadata (AcMeta); desc files with
// %INSTALLDATE% masked (the C's time(NULL))
#[derive(Debug, PartialEq, Eq)]
pub enum AcNode {
	File(u32, u64, Vec<u8>, AcMeta),
	Dir(u32, Option<Vec<(Vec<u8>, AcNode)>>, AcMeta),
	Link(Vec<u8>, AcMeta),
	Special(u32, AcMeta),
	Unreadable(u32),
}

// owner, the times an archive gave to the nanosecond (None: one of the
// run), the xattrs by name
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AcMeta {
	pub owner: (u32, u32),
	pub mtime: Option<(i64, i64)>,
	pub atime: Option<(i64, i64)>,
	pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

fn archive_time(sec: i64, nsec: i64) -> Option<(i64, i64)> {
	(sec < AC_RUN_TIME).then_some((sec, nsec))
}

// the xattrs of path itself (llistxattr, through libc like the port so
// that fakeroot answers for both)
fn xattrs(path: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut names = vec![0u8; 65536];
	let Ok(n) = rustix::fs::llistxattr(path, &mut names[..]) else {
		return Vec::new();
	};
	let mut out: Vec<(Vec<u8>, Vec<u8>)> = names[..n]
		.split(|&c| c == 0)
		.filter(|n| !n.is_empty())
		.map(|name| {
			let mut v = vec![0u8; 65536];
			let len = rustix::fs::lgetxattr(path, name, &mut v[..])
				.unwrap_or(0);
			(name.to_vec(), v[..len].to_vec())
		})
		.collect();
	out.sort();
	out
}

// AcMeta of every path under root, taken before anything is read: a
// read moves the atime (relatime)
fn metas(path: &Path, out: &mut HashMap<PathBuf, AcMeta>) {
	let Ok(m) = fs::symlink_metadata(path) else {
		return;
	};
	out.insert(
		path.to_path_buf(),
		AcMeta {
			owner: (m.uid(), m.gid()),
			mtime: archive_time(m.mtime(), m.mtime_nsec()),
			// a directory's atime is not stable: any open after the
			// time fixup (either side, order varies) resets an atime
			// older than a day under relatime. files are not read
			// before this snapshot
			atime: (!m.is_dir())
				.then(|| {
					archive_time(m.atime(), m.atime_nsec())
				})
				.flatten(),
			xattrs: xattrs(path),
		},
	);
	if !m.is_dir() {
		return;
	}
	let Ok(rd) = fs::read_dir(path) else { return };
	for e in rd.flatten() {
		metas(&e.path(), out);
	}
}

fn mask_installdate(data: &[u8]) -> Vec<u8> {
	let key = b"%INSTALLDATE%\n";
	let Some(i) = data.windows(key.len()).position(|w| w == key) else {
		return data.to_vec();
	};
	let start = i + key.len();
	let end = data[start..]
		.iter()
		.position(|&c| c == b'\n')
		.map_or(data.len(), |n| start + n);
	[&data[..start], b"<now>", &data[end..]].concat()
}

// the scriptlet's mkdtemp name: alpm_ and six random characters
pub(crate) fn mask_tmpdir(msg: &[u8]) -> Vec<u8> {
	let key = b"/tmp/alpm_";
	let mut out = msg.to_vec();
	let mut i = 0;
	while let Some(n) = out[i..].windows(key.len()).position(|w| w == key) {
		let start = i + n + key.len();
		let end = (start + 6).min(out.len());
		out[start..end].fill(b'X');
		i = end;
	}
	out
}

fn ac_node(
	path: &Path,
	node: Node,
	mask: bool,
	metas: &mut HashMap<PathBuf, AcMeta>,
) -> AcNode {
	let meta = metas.remove(path).unwrap_or_default();
	match node {
		Node::File(m, n, data) => {
			let data = match mask && path
				.file_name()
				.is_some_and(|f| f == "desc")
			{
				true => mask_installdate(&data),
				false => data,
			};
			AcNode::File(m, n, data, meta)
		}
		Node::Dir(m, entries) => {
			let entries = entries.map(|es| {
				es.into_iter()
					.map(|(name, n)| {
						let p = path.join(
							std::ffi::OsStr::from_bytes(
								&name,
							),
						);
						let n = ac_node(
							&p, n, mask, metas,
						);
						(name, n)
					})
					.collect()
			});
			AcNode::Dir(m, entries, meta)
		}
		Node::Link(t) => AcNode::Link(t, meta),
		Node::Special(m) => AcNode::Special(m, meta),
		Node::Unreadable(m) => AcNode::Unreadable(m),
	}
}

pub(crate) fn tree(path: &Path, mask: bool) -> AcNode {
	let mut m = HashMap::new();
	metas(path, &mut m);
	ac_node(path, snapshot(path), mask, &mut m)
}

fn finish(
	fx: &TempRoot,
	rc: c_int,
	errno: c_int,
	recs: Vec<AcRec>,
	logfile: &Path,
) -> AcResult {
	let log = fs::read(logfile).unwrap_or_default();
	let _ = fs::remove_file(logfile);
	let recs = recs
		.into_iter()
		.map(|r| match r {
			AcRec::Log(l, m) => AcRec::Log(l, mask_tmpdir(&m)),
			r => r,
		})
		.collect();
	AcResult {
		rc,
		errno,
		recs,
		logfile: strip_stamps(&log),
		root: tree(&fx.dir().join("root"), false),
		// exact under a valid SOURCE_DATE_EPOCH (the sde_ children)
		local: tree(
			&fx.local(),
			std::env::var_os(AC_SDE_EXACT).is_none(),
		),
	}
}

fn name_ver(p: &Package) -> Vec<u8> {
	let n = p.name.as_deref().unwrap_or_default();
	let v = p.version.as_deref().unwrap_or_default();
	[n, b" ", v].concat()
}

// ---- C ----

// alpm_event_package_operation_t, alpm_event_pacnew_created_t,
// alpm_event_pacsave_created_t, alpm_event_scriptlet_info_t
#[repr(C)]
struct CEvOp {
	kind: c_int,
	operation: c_int,
	oldpkg: *mut CPkg,
	newpkg: *mut CPkg,
}

#[repr(C)]
struct CEvPacnew {
	kind: c_int,
	from_noupgrade: c_int,
	oldpkg: *mut CPkg,
	newpkg: *mut CPkg,
	file: *const c_char,
}

#[repr(C)]
struct CEvPacsave {
	kind: c_int,
	oldpkg: *mut CPkg,
	file: *const c_char,
}

#[repr(C)]
struct CEvLine {
	kind: c_int,
	line: *const c_char,
}

const EV_OP_START: c_int = 11;
const EV_OP_DONE: c_int = 12;
const EV_SCRIPTLET: c_int = 17;
const EV_PACNEW: c_int = 32;
const EV_PACSAVE: c_int = 33;

fn c_name(p: *mut CPkg) -> Option<Vec<u8>> {
	(!p.is_null()).then(|| read_pkg(p).name_bytes().to_vec())
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
	// SAFETY: ctx is the boxed record list
	let recs = unsafe { &mut *ctx.cast::<Vec<AcRec>>() };
	recs.push(AcRec::Log(level, msg));
}

unsafe extern "C" fn event_cb(ctx: *mut c_void, event: *mut c_void) {
	// SAFETY: every event starts with its type, which says the struct;
	// ctx is the boxed record list
	let (recs, kind) = unsafe {
		(&mut *ctx.cast::<Vec<AcRec>>(), *event.cast::<c_int>())
	};
	// SAFETY: the casts follow kind
	let rec = unsafe {
		match kind {
			EV_OP_START | EV_OP_DONE => {
				let e = &*event.cast::<CEvOp>();
				AcRec::Op(
					kind == EV_OP_DONE,
					e.operation,
					c_name_ver(e.oldpkg),
					c_name_ver(e.newpkg),
				)
			}
			EV_PACNEW => {
				let e = &*event.cast::<CEvPacnew>();
				AcRec::Pacnew(
					e.from_noupgrade != 0,
					c_name(e.oldpkg),
					c_name(e.newpkg).unwrap(),
					text(e.file),
				)
			}
			EV_PACSAVE => {
				let e = &*event.cast::<CEvPacsave>();
				AcRec::Pacsave(
					c_name(e.oldpkg).unwrap(),
					text(e.file),
				)
			}
			EV_SCRIPTLET => {
				let e = &*event.cast::<CEvLine>();
				AcRec::Scriptlet(text(e.line))
			}
			k => AcRec::Event(k),
		}
	};
	recs.push(rec);
}

unsafe extern "C" fn progress_cb(
	ctx: *mut c_void,
	kind: c_int,
	pkg: *const c_char,
	percent: c_int,
	howmany: usize,
	current: usize,
) {
	// SAFETY: ctx is the boxed record list
	let recs = unsafe { &mut *ctx.cast::<Vec<AcRec>>() };
	let rec = AcRec::Progress(kind, text(pkg), percent, howmany, current);
	recs.push(rec);
}

// _alpm_upgrade_packages on the case, built under fx; logfile is
// written by alpm_logaction. the caller holds umask_lock
pub fn c_upgrade(fx: &TempRoot, c: &AcCase, logfile: &Path) -> AcResult {
	// pacman's setlocale(LC_ALL, ""): libarchive converts pax strings to
	// the locale's charset, the port models UTF-8. AC_C_LOCALE keeps
	// the process in the C locale (a child run of its own)
	if std::env::var_os(AC_C_LOCALE).is_none() {
		crate::cli_util::init();
	}
	let pkgpath = ac_build(fx, c);
	let pkgfile = cstr(&pkgpath);
	let (root, dbpath) = (cstr(&fx.root()), cstr(&fx.dbpath()));
	let log = cstr(logfile.as_os_str().as_bytes());
	let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
	let mut err = 0;
	// SAFETY: valid C strings, err is writable
	let h = unsafe {
		alpm_initialize(root.as_ptr(), dbpath.as_ptr(), &mut err)
	};
	assert!(!h.is_null(), "alpm_initialize: {err}");
	let recs: *mut Vec<AcRec> = Box::into_raw(Box::default());
	// SAFETY: h is live; setters copy strings and lists; recs stays
	// valid until freed below, after alpm_release
	let (rc, errno) = unsafe {
		assert_eq!(alpm_option_set_logfile(h, log.as_ptr()), 0);
		with_strs(&c.noupgrade, |l| alpm_option_set_noupgrades(h, l));
		with_strs(&c.noextract, |l| alpm_option_set_noextracts(h, l));
		assert_eq!(alpm_trans_init(h, c.flags | AC_NOLOCK), 0);
		let mut pkg: *mut CPkg = ptr::null_mut();
		let r = alpm_pkg_load(h, pkgfile.as_ptr(), 1, 0, &mut pkg);
		assert_eq!(r, 0, "alpm_pkg_load: {}", alpm_errno(h));
		cut_pkg(&pkgpath, c);
		assert_eq!(alpm_add_pkg(h, pkg), 0, "alpm_add_pkg");
		let local: *mut CDb = alpm_get_localdb(h);
		let name = cstr(c.name.as_bytes());
		let lpkg = alpm_db_get_pkg(local, name.as_ptr());
		if !lpkg.is_null() {
			assert_eq!(_alpm_pkg_dup(lpkg, &mut (*pkg).oldpkg), 0);
		} else if c.stale_oldpkg {
			assert_eq!(_alpm_pkg_dup(pkg, &mut (*pkg).oldpkg), 0);
		}
		alpm_option_set_logcb(h, Some(log_cb), recs.cast());
		alpm_option_set_eventcb(h, Some(event_cb), recs.cast());
		alpm_option_set_progresscb(h, Some(progress_cb), recs.cast());
		let old = c_umask(0o022);
		let rc = _alpm_upgrade_packages(h);
		c_umask(old);
		let errno = alpm_errno(h);
		alpm_option_set_logcb(h, None, ptr::null_mut());
		alpm_option_set_eventcb(h, None, ptr::null_mut());
		alpm_option_set_progresscb(h, None, ptr::null_mut());
		alpm_trans_release(h);
		alpm_release(h);
		(rc, errno)
	};
	drop(guard);
	// SAFETY: built by Box::into_raw above, the C is done with it
	let recs = *unsafe { Box::from_raw(recs) };
	finish(fx, rc, errno, recs, logfile)
}

// ---- Rust ----

// the Rust side's callbacks, recording like the C ones
#[derive(Default)]
pub struct AcRecorder(Rc<RefCell<Vec<AcRec>>>);

impl Callbacks for AcRecorder {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.0.borrow_mut()
			.push(AcRec::Log(level as c_int, msg.to_vec()));
	}

	fn event(&mut self, event: &Event<'_>) {
		let rec = match event {
			Event::PackageOperationStart(op)
			| Event::PackageOperationDone(op) => AcRec::Op(
				matches!(event, Event::PackageOperationDone(_)),
				op.operation as c_int,
				op.oldpkg.map(name_ver),
				op.newpkg.map(name_ver),
			),
			Event::PacnewCreated {
				from_noupgrade,
				oldpkg,
				newpkg,
				file,
			} => AcRec::Pacnew(
				*from_noupgrade,
				oldpkg.map(|p| p.name_bytes().to_vec()),
				newpkg.name_bytes().to_vec(),
				file.to_vec(),
			),
			Event::PacsaveCreated { oldpkg, file } => {
				AcRec::Pacsave(
					oldpkg.name_bytes().to_vec(),
					file.to_vec(),
				)
			}
			Event::ScriptletInfo { line } => {
				AcRec::Scriptlet(line.to_vec())
			}
			e => AcRec::Event(e.kind()),
		};
		self.0.borrow_mut().push(rec);
	}

	fn progress(
		&mut self,
		progress: Progress,
		pkg: &[u8],
		percent: c_int,
		howmany: usize,
		current: usize,
	) {
		let rec = AcRec::Progress(
			progress as c_int,
			pkg.to_vec(),
			percent,
			howmany,
			current,
		);
		self.0.borrow_mut().push(rec);
	}
}

// alpm_core's add::upgrade_package on the case, then ldconfig on
// success like _alpm_upgrade_packages. the caller holds umask_lock
pub fn rust_upgrade(fx: &TempRoot, c: &AcCase, logfile: &Path) -> AcResult {
	let pkgfile = ac_build(fx, c);
	let mut h = Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
	h.set_logfile(logfile.as_os_str().as_bytes());
	h.set_noupgrades(&c.noupgrade);
	h.set_noextracts(&c.noextract);
	trans::trans_init(&mut h, c.flags | AC_NOLOCK).unwrap();
	let pkg = be_package::pkg_load(&pkgfile, true).unwrap();
	cut_pkg(&pkgfile, c);
	add::add_pkg(&mut h, pkg, None).unwrap();
	let dbs = h.dbs_mut();
	let db = dbs.local.unwrap();
	let old = db.load_pkg(dbs.dbext, dbs.cb, c.name.as_bytes(), INFRQ_ALL);
	let old = old.map(Package::dup);
	// the driver's share: the targets out of trans.add, the
	// transaction stays on the handle for its flags
	let mut add = std::mem::take(&mut h.trans_mut().unwrap().add);
	let t = &mut add[0];
	match old {
		Ok(old) => t.oldpkg = Some(old),
		Err(_) if c.stale_oldpkg => t.oldpkg = Some(t.pkg.dup()),
		Err(_) => {}
	}
	let recs = Rc::new(RefCell::new(Vec::new()));
	h.set_callbacks(Box::new(AcRecorder(recs.clone())));
	let r = add::upgrade_package(&mut h, t, 1, 1);
	if r.is_ok() {
		util::ldconfig(&mut h);
	}
	h.set_callbacks(Box::new(()));
	h.trans_mut().unwrap().add = add;
	trans::trans_release(&mut h).unwrap();
	drop(h);
	let (rc, errno) = match r {
		Ok(()) => (0, 0),
		Err(e) => (-1, e as c_int),
	};
	let recs = std::mem::take(&mut *recs.borrow_mut());
	finish(fx, rc, errno, recs, logfile)
}
