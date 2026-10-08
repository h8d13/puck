// C side of the rest of src/pacman/util.c, from the frontend objects (see
// build.rs): transaction summary, --print-format, optdepend lists,
// select_display, the prompts, colon_printf and rmrf
//
// every call holds FRONTEND, puts the flags util.c reads (op, noconfirm,
// verbosepkglists, op_s_downloadonly, logmask, print_format, colstr) of
// a pacman_cli Config into `config`, sets COLUMNS for getcols and TZ=UTC,
// and swaps stdout and stderr for open_memstreams and stdin for an
// fmemopen of the given input. fileno of those is -1, so the C sees no
// terminal anywhere: Term { stdin_tty: false, stdout_tty: false } on the
// Rust side. how much input was read comes back as ftell.
//
// the libalpm side (db names and servers, cache dirs, local cache, the
// transaction's add/remove lists) runs on a pkg_show PkgWorld: its sync
// db "core" gets a server, the handle two cache dirs (one missing, one
// with package files), and the transaction is set by hand for the call.
use std::ffi::{CString, OsStr, c_char, c_int};
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::Path;
use std::ptr;

use alpm_core::be_local::INFRQ_DSIZE;
use alpm_core::handle::Handle;
use alpm_core::package::{Package, PkgFrom};
use pacman_cli::conf::Config;
use pacman_cli::util::Output;

use crate::cli_util::{FRONTEND, config, init};
use crate::conf::ColStrC;
use crate::handle::{
	CHandleHead, CTrans, alpm_db_add_server, alpm_option_add_cachedir,
	alpm_option_get_cachedirs,
};
use crate::package::{CPkg, CPkgBox, read_strs};
use crate::pkg_show::{PkgWorld, c_strftime_c, columns_cache_reset, utc};
use crate::util_common::{fmemopen, ftell};
use crate::{
	CFile, CList, alpm_list_add, alpm_list_free, c_free, cstr, fclose,
	fflush, open_memstream, stderr, stdout, string_length_in_bounds,
};

unsafe extern "C" {
	pub(crate) static mut stdin: *mut CFile;

	fn display_targets();
	fn print_packages(packages: *const CList);
	fn display_new_optdepends(oldpkg: *mut CPkg, newpkg: *mut CPkg);
	fn display_optdepends(pkg: *mut CPkg);
	fn select_display(pkglist: *const CList);
	fn select_question(count: c_int) -> c_int;
	fn multiselect_question(array: *mut c_char, count: c_int) -> c_int;
	fn yesno(format: *const c_char, ...) -> c_int;
	fn noyes(format: *const c_char, ...) -> c_int;
	fn colon_printf(format: *const c_char, ...) -> c_int;
	fn rmrf(path: *const c_char) -> c_int;
}

// the server of SYNC_DBS[0], SYNC_DBS[1] has none
pub const CORE_SERVER: &[u8] = b"https://mirror.example/core/os/x86_64";

// files in the second cache dir: a regular file, a directory, a link to
// the regular file and a dangling link (pkg_get_location stats them)
pub const CACHED: [&str; 4] = [
	"cached-1-1-x86_64.pkg.tar.zst",
	"dir-1-1-any.pkg.tar.zst",
	"link-1-1-any.pkg.tar.zst",
	"dangling-1-1-any.pkg.tar.zst",
];

// the config flags util.c reads
struct Flags {
	op: u16,
	noconfirm: u16,
	verbosepkglists: u16,
	op_s_downloadonly: u16,
	logmask: u16,
}

impl Flags {
	fn of(cfg: &Config) -> Self {
		Flags {
			op: cfg.op,
			noconfirm: cfg.noconfirm,
			verbosepkglists: cfg.verbosepkglists,
			op_s_downloadonly: cfg.op_s_downloadonly,
			logmask: cfg.logmask,
		}
	}

	// puts these into config, returns what was there
	//
	// SAFETY: caller holds FRONTEND, config is valid (init)
	unsafe fn swap(self) -> Self {
		// SAFETY: see above
		let c = unsafe { &mut *config };
		Flags {
			op: std::mem::replace(&mut c.op, self.op),
			noconfirm: std::mem::replace(
				&mut c.noconfirm,
				self.noconfirm,
			),
			verbosepkglists: std::mem::replace(
				&mut c.verbosepkglists,
				self.verbosepkglists,
			),
			op_s_downloadonly: std::mem::replace(
				&mut c.op_s_downloadonly,
				self.op_s_downloadonly,
			),
			logmask: std::mem::replace(
				&mut c.logmask,
				self.logmask,
			),
		}
	}
}

// what a call printed and how many input bytes it read
#[derive(Debug)]
pub struct CIo {
	pub out: Output,
	pub consumed: usize,
}

fn colstr_c(c: &[CString; 10]) -> ColStrC {
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

// buffer of a memstream, freed
//
// SAFETY: buf is the malloc'd buffer of a closed memstream, size bytes
unsafe fn take_buf(buf: *mut c_char, size: usize) -> Vec<u8> {
	// SAFETY: see above
	let v = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), size) };
	let v = v.to_vec();
	c_free(buf.cast());
	v
}

// runs f with config set from cfg, COLUMNS = cols, the streams captured
// and stdin reading input
pub(crate) fn run(
	cfg: &Config,
	cols: u16,
	input: &[u8],
	f: impl FnOnce(),
) -> CIo {
	init();
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	let cs = &cfg.colstr;
	let c = [
		cs.colon, cs.title, cs.repo, cs.version, cs.groups, cs.meta,
		cs.warn, cs.err, cs.faint, cs.nocolor,
	]
	.map(cstr);
	let format = cfg.print_format.as_deref().map(cstr);
	// fmemopen wants a non-empty buffer, size 0 is still passed
	let mut copy = input.to_vec();
	copy.push(0);
	let (mut obuf, mut osize) = (ptr::null_mut(), 0usize);
	let (mut ebuf, mut esize) = (ptr::null_mut(), 0usize);
	// SAFETY: FRONTEND serializes every access to config, the three
	// streams and the environment from C. config is valid after init;
	// colstr and print_format point into strings that outlive the call
	// and are put back (or NULLed) before they drop. print_packages
	// strdups "%l" into a NULL print_format, freed here. the memstreams
	// and the fmemopen replace the streams only while f runs; the
	// memstream buffers are malloc'd, valid for size bytes after fclose
	unsafe {
		utc();
		std::env::set_var("COLUMNS", cols.to_string());
		columns_cache_reset();
		let old_colstr =
			std::mem::replace(&mut (*config).colstr, colstr_c(&c));
		let old_flags = Flags::of(cfg).swap();
		(*config).print_format = format
			.as_ref()
			.map_or(ptr::null_mut(), |f| f.as_ptr().cast_mut());
		let inp = fmemopen(
			copy.as_mut_ptr().cast(),
			input.len(),
			c"r".as_ptr(),
		);
		let out = open_memstream(&mut obuf, &mut osize);
		let err = open_memstream(&mut ebuf, &mut esize);
		assert!(!inp.is_null() && !out.is_null() && !err.is_null());
		let (real_out, real_err, real_in) = (stdout, stderr, stdin);
		fflush(real_out);
		fflush(real_err);
		(stdout, stderr, stdin) = (out, err, inp);
		f();
		fflush(out);
		fflush(err);
		let consumed = ftell(inp);
		(stdout, stderr, stdin) = (real_out, real_err, real_in);
		fclose(out);
		fclose(err);
		fclose(inp);
		if format.is_none() {
			c_free((*config).print_format.cast());
		}
		(*config).print_format = ptr::null_mut();
		old_flags.swap();
		(*config).colstr = old_colstr;
		CIo {
			out: Output {
				stdout: take_buf(obuf, osize),
				stderr: take_buf(ebuf, esize),
				sink: None,
			},
			consumed: usize::try_from(consumed).unwrap(),
		}
	}
}

// select_question(count) answering from input
pub fn c_select_question(cfg: &Config, count: i32, input: &[u8]) -> (i32, CIo) {
	let mut ret = 0;
	// SAFETY: reads stdin and prints only
	let io = run(cfg, 0, input, || ret = unsafe { select_question(count) });
	(ret, io)
}

// multiselect_question over count entries, and the array it left
pub fn c_multiselect_question(
	cfg: &Config,
	count: usize,
	input: &[u8],
) -> (i32, Vec<bool>, CIo) {
	let mut array = vec![7u8; count];
	let mut ret = 0;
	let n = c_int::try_from(count).unwrap();
	// SAFETY: array holds count chars, written only below count
	let io = run(cfg, 0, input, || {
		ret = unsafe {
			multiselect_question(array.as_mut_ptr().cast(), n)
		}
	});
	let array = array
		.into_iter()
		.map(|c| {
			assert!(c <= 1, "array entry {c}");
			c == 1
		})
		.collect();
	(ret, array, io)
}

// yesno ("%s", msg) or noyes, answering from input
pub fn c_question(
	cfg: &Config,
	preset: bool,
	msg: &[u8],
	input: &[u8],
) -> (i32, CIo) {
	let msg = cstr(msg);
	let mut ret = 0;
	// SAFETY: "%s" with one valid C string
	let io = run(cfg, 0, input, || unsafe {
		ret = match preset {
			true => yesno(c"%s".as_ptr(), msg.as_ptr()),
			false => noyes(c"%s".as_ptr(), msg.as_ptr()),
		}
	});
	(ret, io)
}

pub fn c_colon_printf(cfg: &Config, msg: &[u8]) -> Vec<u8> {
	let msg = cstr(msg);
	// SAFETY: "%s" with one valid C string
	run(cfg, 0, b"", || unsafe {
		colon_printf(c"%s".as_ptr(), msg.as_ptr());
	})
	.out
	.stdout
}

pub fn c_rmrf(path: &[u8]) -> i32 {
	let p = cstr(path);
	// SAFETY: valid C string, the C only touches the file system
	unsafe { rmrf(p.as_ptr()) }
}

// list over the C packages of boxes, nodes freed by the caller
fn pkg_list(boxes: &[CPkgBox]) -> *mut CList {
	boxes.iter().fold(ptr::null_mut(), |l, b| {
		// SAFETY: l is NULL or built here, b outlives the list
		unsafe { alpm_list_add(l, b.0.cast()) }
	})
}

fn assert_text(what: &str, s: &Option<Box<[u8]>>) {
	let s = s
		.as_deref()
		.unwrap_or_else(|| panic!("printf %s of NULL {what}"));
	assert!(string_length_in_bounds(s), "string_length {what} {s:?}");
}

// alpm_pkg_download_size computes the size of a sync package from the
// cache dirs unless INFRQ_DSIZE says it is done: the port takes the field
fn assert_dsize(pkg: &Package) {
	if pkg.origin == Some(PkgFrom::SyncDb) {
		assert!(
			pkg.infolevel & INFRQ_DSIZE != 0,
			"download size unset"
		);
	}
}

pub struct UtilWorld {
	pub w: PkgWorld,
}

impl UtilWorld {
	// dir must not exist yet, removed again on drop
	pub fn new(dir: &Path) -> Self {
		let w = PkgWorld::new(dir);
		let cache = dir.join("cache2");
		fs::create_dir(&cache).unwrap();
		fs::write(cache.join(CACHED[0]), b"pkg").unwrap();
		fs::create_dir(cache.join(CACHED[1])).unwrap();
		symlink(CACHED[0], cache.join(CACHED[2])).unwrap();
		symlink("missing", cache.join(CACHED[3])).unwrap();
		let server = cstr(CORE_SERVER);
		for c in ["cache1", "cache2"] {
			let d = cstr(dir.join(c).as_os_str().as_bytes());
			// SAFETY: the handle is live, strings are copied
			unsafe {
				assert_eq!(
					alpm_option_add_cachedir(
						w.h,
						d.as_ptr()
					),
					0
				);
			}
		}
		// SAFETY: as above
		unsafe {
			assert_eq!(
				alpm_db_add_server(w.sync[0], server.as_ptr()),
				0
			);
		}
		UtilWorld { w }
	}

	// the same world as a Rust handle: dbs, server and cache dirs
	pub fn rust_handle(&self) -> Handle {
		let path = |p: &str| {
			self.w.dir.join(p).as_os_str().as_bytes().to_vec()
		};
		let mut h =
			Handle::initialize(&path("root"), &path("db")).unwrap();
		for (i, name) in crate::pkg_show::SYNC_DBS.iter().enumerate() {
			h.register_syncdb(name.as_bytes(), 0).unwrap();
			if i == 0 {
				let dbs = h.dbs_mut();
				dbs.sync[i]
					.add_server(dbs.cb, CORE_SERVER)
					.unwrap();
			}
		}
		for c in ["cache1", "cache2"] {
			h.add_cachedir(&path(c));
		}
		// SAFETY: the handle is live, the list stays its own
		let dirs = read_strs(unsafe {
			alpm_option_get_cachedirs(self.w.h)
		});
		assert_eq!(dirs, h.cachedirs());
		h
	}

	pub fn set_caches(&mut self, local: &[Package], sync: [&[Package]; 2]) {
		self.w.set_caches(local, sync);
	}

	// f with config->handle set and a transaction of add and remove
	//
	// SAFETY: caller holds FRONTEND (inside run); add/remove are lists
	// of live packages
	unsafe fn with_trans(
		&self,
		add: *mut CList,
		remove: *mut CList,
		f: impl FnOnce(),
	) {
		let mut trans = CTrans {
			flags: 0,
			state: 1,
			unresolvable: ptr::null_mut(),
			add,
			remove,
			skip_remove: ptr::null_mut(),
		};
		let head = self.w.h.cast::<CHandleHead>();
		// SAFETY: see above; trans lives across f and is unset before
		// anything else can see it
		unsafe {
			(*config).handle = self.w.h;
			(*head).trans = &raw mut trans;
			f();
			(*head).trans = ptr::null_mut();
			(*config).handle = ptr::null_mut();
		}
	}

	fn boxes(&self, pkgs: &[(Package, usize)]) -> Vec<CPkgBox> {
		pkgs.iter().map(|(p, db)| self.w.c_pkg(p, *db)).collect()
	}

	// display_targets with add (sync db index each) and remove as the
	// transaction, explicit as config->explicit_adds/removes. C
	// preconditions: names and versions set and string_length safe,
	// install download sizes computed
	pub fn display_targets(
		&self,
		cfg: &Config,
		add: &[(Package, usize)],
		remove: &[Package],
		explicit: (&[Package], &[Package]),
		cols: u16,
	) -> Output {
		let all = add.iter().map(|(p, _)| p).chain(remove);
		for p in all.clone().chain(explicit.0).chain(explicit.1) {
			assert!(p.name.is_some(), "strcmp of a NULL name");
		}
		for p in all {
			assert_text("name", &p.name);
			assert_text("version", &p.version);
			assert_dsize(p);
		}
		let add = self.boxes(add);
		let remove: Vec<CPkgBox> =
			remove.iter().map(CPkgBox::new).collect();
		let ea: Vec<CPkgBox> =
			explicit.0.iter().map(CPkgBox::new).collect();
		let er: Vec<CPkgBox> =
			explicit.1.iter().map(CPkgBox::new).collect();
		let lists = [&add, &remove, &ea, &er].map(|b| pkg_list(b));
		// SAFETY: the lists hold live packages; explicit lists are
		// unset again before they are freed
		let io = run(cfg, cols, b"", || unsafe {
			(*config).explicit_adds = lists[2];
			(*config).explicit_removes = lists[3];
			self.with_trans(lists[0], lists[1], || {
				display_targets()
			});
			(*config).explicit_adds = ptr::null_mut();
			(*config).explicit_removes = ptr::null_mut();
		});
		for l in lists {
			// SAFETY: nodes built above, data owned by the boxes
			unsafe { alpm_list_free(l) };
		}
		io.out
	}

	// print_packages(pkgs) with cfg.print_format. C preconditions: build
	// dates localtime takes; sync and file packages with a filename,
	// others with name and version (printf %s); download sizes computed
	pub fn print_packages(
		&self,
		cfg: &Config,
		pkgs: &[(Package, usize)],
	) -> Output {
		for (p, _) in pkgs {
			assert!(
				p.builddate == -1
					|| c_strftime_c(p.builddate).is_some(),
				"localtime fails on {}",
				p.builddate
			);
			match p.origin {
				Some(PkgFrom::SyncDb | PkgFrom::File(_)) => {
					assert!(
						p.filename.is_some(),
						"NULL filename"
					);
				}
				_ => {
					assert!(
						p.name.is_some(),
						"printf %s of NULL"
					);
					assert!(
						p.version.is_some(),
						"printf %s of NULL"
					);
				}
			}
			assert_dsize(p);
		}
		let boxes = self.boxes(pkgs);
		let list = pkg_list(&boxes);
		// SAFETY: list holds live packages with this handle
		let io = run(cfg, 0, b"", || unsafe {
			(*config).handle = self.w.h;
			print_packages(list);
			(*config).handle = ptr::null_mut();
		});
		// SAFETY: nodes built above
		unsafe { alpm_list_free(list) };
		io.out
	}

	// display_optdepends(pkg) (old None) or display_new_optdepends(old,
	// pkg), pending as the transaction's add list, against the local
	// cache. C precondition: pkg's name set
	pub fn optdepends(
		&self,
		cfg: &Config,
		old: Option<&Package>,
		pkg: &Package,
		pending: &[Package],
		cols: u16,
	) -> Output {
		assert!(pkg.name.is_some(), "printf %s of NULL");
		let pending: Vec<CPkgBox> =
			pending.iter().map(CPkgBox::new).collect();
		let list = pkg_list(&pending);
		let new = CPkgBox::new(pkg);
		let old = old.map(CPkgBox::new);
		// SAFETY: packages and list live across the call
		let io = run(cfg, cols, b"", || unsafe {
			self.with_trans(list, ptr::null_mut(), || match &old {
				Some(o) => display_new_optdepends(o.0, new.0),
				None => display_optdepends(new.0),
			});
		});
		// SAFETY: nodes built above
		unsafe { alpm_list_free(list) };
		io.out
	}

	// select_display(pkgs). C preconditions: not empty, every package
	// from a db, names set and string_length safe
	pub fn select_display(
		&self,
		cfg: &Config,
		pkgs: &[(Package, usize)],
		cols: u16,
	) -> Output {
		assert!(!pkgs.is_empty(), "printf %s of a NULL db name");
		for (p, _) in pkgs {
			let db = matches!(
				p.origin,
				Some(PkgFrom::SyncDb | PkgFrom::LocalDb)
			);
			assert!(db, "strcmp of a NULL db name");
			assert_text("name", &p.name);
		}
		let boxes = self.boxes(pkgs);
		let list = pkg_list(&boxes);
		// SAFETY: list holds live packages
		let io =
			run(cfg, cols, b"", || unsafe { select_display(list) });
		// SAFETY: nodes built above
		unsafe { alpm_list_free(list) };
		io.out
	}
}

// yesno ("%s", msg) on the process's own stdin and stderr: the tty
// probe's C side, flush_term_input on a real terminal
pub fn c_tty_yesno(msg: &[u8]) -> i32 {
	init();
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	let msg = cstr(msg);
	// SAFETY: config is valid after init, FRONTEND holds it; "%s" with
	// one valid C string
	unsafe {
		(*config).noconfirm = 0;
		yesno(c"%s".as_ptr(), msg.as_ptr())
	}
}

// a pty pair: the master end for the test, a slave end opened for the
// child, the window size set to cols
pub struct Pty {
	pub master: File,
	pub slave: File,
}

impl Pty {
	pub fn open(cols: u16) -> Pty {
		use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname};
		let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY;
		let master = openpt(flags).expect("openpt");
		grantpt(&master).unwrap();
		rustix::pty::unlockpt(&master).unwrap();
		let name = ptsname(&master, Vec::new()).unwrap();
		let slave = File::options()
			.read(true)
			.write(true)
			.custom_flags(rustix::fs::OFlags::NOCTTY.bits() as i32)
			.open(OsStr::from_bytes(name.as_bytes()))
			.unwrap();
		let ws = rustix::termios::Winsize {
			ws_row: 24,
			ws_col: cols,
			ws_xpixel: 0,
			ws_ypixel: 0,
		};
		rustix::termios::tcsetwinsize(&slave, ws).unwrap();
		Pty {
			master: File::from(master),
			slave,
		}
	}
}

// the tty-probe binary in mode on pty (stdin and stdout the slave,
// stderr captured). after the first stderr bytes containing wait_for,
// answer goes to the master. the probe is killed after 20 s; its stderr
pub fn run_tty_probe(
	probe: &Path,
	mode: &str,
	pty: &Pty,
	wait_for: &[u8],
	answer: &[u8],
) -> Vec<u8> {
	use std::io::{Read, Write};
	use std::process::{Command, Stdio};
	use std::sync::mpsc;
	use std::time::{Duration, Instant};
	let mut child = Command::new(probe)
		.arg(mode)
		.stdin(pty.slave.try_clone().unwrap())
		.stdout(pty.slave.try_clone().unwrap())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	let mut err = child.stderr.take().unwrap();
	let (tx, rx) = mpsc::channel();
	let reader = std::thread::spawn(move || {
		let mut buf = [0; 256];
		while let Ok(n) = err.read(&mut buf) {
			if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
				break;
			}
		}
	});
	let deadline = Instant::now() + Duration::from_secs(20);
	let mut got = Vec::new();
	let mut answered = wait_for.is_empty();
	loop {
		let left = deadline.saturating_duration_since(Instant::now());
		match rx.recv_timeout(left) {
			Ok(b) => got.extend(b),
			Err(mpsc::RecvTimeoutError::Disconnected) => break,
			Err(mpsc::RecvTimeoutError::Timeout) => {
				let _ = child.kill();
				break;
			}
		}
		if !answered
			&& got.windows(wait_for.len()).any(|w| w == wait_for)
		{
			// the prompt is printed before its tcflush: give it time
			std::thread::sleep(Duration::from_millis(300));
			let mut m = &pty.master;
			m.write_all(answer).unwrap();
			answered = true;
		}
	}
	let _ = child.kill();
	child.wait().unwrap();
	reader.join().unwrap();
	got
}
