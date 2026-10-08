// C side of src/pacman/conf.c, from the frontend objects (see build.rs)
//
// parseconfig works on the global `config` and prints through pm_printf
// to the C `stderr`: each run holds FRONTEND (shared with cli_util), puts
// a fresh config_new in `config`, swaps `stderr` for an open_memstream
// and `stdout` for a FILE whose isatty answer is chosen (Color probes
// it). parseconfig itself ends in setup_libalpm (alpm_initialize on the
// configured root): the wrapper runs its first half instead, which is
// exported, parseconfigfile + setdefaults + the "finished parsing" trace.
use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::ptr;
use std::sync::OnceLock;

use crate::cli_util::{FRONTEND, config, config_new};
use crate::{
	CFile as File, CList, c_free, cstr, fclose, fflush, open_memstream,
	stderr, stdout, strdup,
};

use pacman_cli::conf::{ColStr, Config, ConfigRepo};

// colstr_t of conf.h
#[repr(C)]
pub(crate) struct ColStrC {
	pub(crate) colon: *const c_char,
	pub(crate) title: *const c_char,
	pub(crate) repo: *const c_char,
	pub(crate) version: *const c_char,
	pub(crate) groups: *const c_char,
	pub(crate) meta: *const c_char,
	pub(crate) warn: *const c_char,
	pub(crate) err: *const c_char,
	pub(crate) faint: *const c_char,
	pub(crate) nocolor: *const c_char,
}

// config_repo_t of conf.h
#[repr(C)]
struct ConfigRepoC {
	name: *mut c_char,
	cache_servers: *mut CList,
	servers: *mut CList,
	usage: c_int,
	siglevel: c_int,
	siglevel_mask: c_int,
}

// config_t of conf.h. checked by init_layout through the fields
// config_new sets, and by every difftest comparing all of them
#[repr(C)]
pub(crate) struct ConfigC {
	op: u16,
	pub(crate) quiet: u16,
	verbose: u16,
	version: u16,
	help: u16,
	noconfirm: u16,
	noprogressbar: u16,
	pub(crate) logmask: u16,
	print: u16,
	checkspace: u16,
	usesyslog: u16,
	color: u16,
	disable_dl_timeout: u16,
	disable_sandbox_filesystem: u16,
	disable_sandbox_syscalls: u16,
	print_format: *mut c_char,
	configfile: *mut c_char,
	rootdir: *mut c_char,
	dbpath: *mut c_char,
	logfile: *mut c_char,
	gpgdir: *mut c_char,
	sysroot: *mut c_char,
	sandboxuser: *mut c_char,
	hookdirs: *mut CList,
	cachedirs: *mut CList,
	architectures: *mut CList,

	pub(crate) op_q_isfile: u16,
	pub(crate) op_q_info: u16,
	pub(crate) op_q_list: u16,
	pub(crate) op_q_unrequired: u16,
	pub(crate) op_q_deps: u16,
	pub(crate) op_q_explicit: u16,
	pub(crate) op_q_owns: u16,
	pub(crate) op_q_search: u16,
	pub(crate) op_q_changelog: u16,
	pub(crate) op_q_upgrade: u16,
	pub(crate) op_q_check: u16,
	pub(crate) op_q_locality: u16,

	pub(crate) op_s_clean: u16,
	op_s_downloadonly: u16,
	pub(crate) op_s_info: u16,
	pub(crate) op_s_sync: u16,
	pub(crate) op_s_search: u16,
	pub(crate) op_s_upgrade: u16,

	pub(crate) op_f_regex: u16,
	pub(crate) op_f_machinereadable: u16,

	pub(crate) group: u16,
	noask: u16,
	ask: c_uint,
	flags: c_int,
	siglevel: c_int,
	localfilesiglevel: c_int,
	remotefilesiglevel: c_int,
	siglevel_mask: c_int,
	localfilesiglevel_mask: c_int,
	remotefilesiglevel_mask: c_int,

	chomp: u16,
	verbosepkglists: u16,
	parallel_downloads: c_uint,
	cleanmethod: u16,
	holdpkg: *mut CList,
	ignorepkg: *mut CList,
	ignoregrp: *mut CList,
	assumeinstalled: *mut CList,
	noupgrade: *mut CList,
	noextract: *mut CList,
	overwrite_files: *mut CList,
	xfercommand: *mut c_char,
	xfercommand_argv: *mut *mut c_char,
	xfercommand_argc: usize,

	pub(crate) handle: *mut c_void,

	explicit_adds: *mut CList,
	explicit_removes: *mut CList,

	pub(crate) colstr: ColStrC,

	repos: *mut CList,
}

// glob_t of glibc glob.h, the GNU extension members as opaque pointers
#[repr(C)]
struct GlobT {
	gl_pathc: usize,
	gl_pathv: *mut *mut c_char,
	gl_offs: usize,
	gl_flags: c_int,
	gl_funcs: [*mut c_void; 5],
}

// glibc sys/utsname.h, _UTSNAME_LENGTH 65
#[repr(C)]
struct Utsname {
	fields: [[c_char; 65]; 6],
}

const GLOB_NOCHECK: c_int = 1 << 4;
const O_RDWR: c_int = 2;
const O_NOCTTY: c_int = 0o400;
const ALPM_LOG_DEBUG: c_int = 1 << 2;

unsafe extern "C" {
	fn config_free(c: *mut ConfigC) -> c_int;
	fn enable_colors(colors: c_int);
	fn parseconfigfile(file: *const c_char) -> c_int;
	fn setdefaults(c: *mut ConfigC) -> c_int;
	fn pm_printf(level: c_int, format: *const c_char, ...) -> c_int;

	fn fdopen(fd: c_int, mode: *const c_char) -> *mut File;
	fn posix_openpt(flags: c_int) -> c_int;
	fn uname(buf: *mut Utsname) -> c_int;
	fn glob(
		pattern: *const c_char,
		flags: c_int,
		errfunc: *const c_void,
		pglob: *mut GlobT,
	) -> c_int;
	fn globfree(pglob: *mut GlobT);
	fn malloc_usable_size(p: *mut c_void) -> usize;
}

// what the command line may have set before parseconfig, both sides
#[derive(Clone, Debug, Default)]
pub struct Preset {
	pub sysroot: Option<Vec<u8>>,
	pub rootdir: Option<Vec<u8>>,
	pub dbpath: Option<Vec<u8>>,
	pub gpgdir: Option<Vec<u8>>,
	pub logfile: Option<Vec<u8>>,
	pub sandboxuser: Option<Vec<u8>>,
	// --color, enable_colors called on it when set
	pub color: u16,
	pub logmask: u16,
	// what isatty(fileno(stdout)) answers
	pub tty: bool,
}

impl Preset {
	// the same state on the Rust side
	pub fn config(&self) -> Config {
		let mut c = Config::new();
		c.sysroot.clone_from(&self.sysroot);
		c.rootdir.clone_from(&self.rootdir);
		c.dbpath.clone_from(&self.dbpath);
		c.gpgdir.clone_from(&self.gpgdir);
		c.logfile.clone_from(&self.logfile);
		c.sandboxuser.clone_from(&self.sandboxuser);
		c.logmask = self.logmask;
		if self.color != 0 {
			c.color = self.color;
			c.enable_colors(self.color);
		}
		c
	}
}

// C parseconfig minus setup_libalpm: return value, resulting config,
// everything printed to stderr (PACMAN_DEBUG timestamps removed)
pub struct CParse {
	pub ret: i32,
	pub config: Config,
	pub stderr: Vec<u8>,
}

// a FILE on a pty master: isatty is true, nothing is written to it
fn tty_file() -> *mut File {
	static TTY: OnceLock<usize> = OnceLock::new();
	*TTY.get_or_init(|| {
		// SAFETY: plain libc calls, the fd and FILE live for the whole
		// process
		unsafe {
			let fd = posix_openpt(O_RDWR | O_NOCTTY);
			assert!(fd >= 0, "posix_openpt failed");
			let f = fdopen(fd, c"w".as_ptr());
			assert!(!f.is_null());
			f as usize
		}
	}) as *mut File
}

// SAFETY (callers): p NULL or a valid C string
unsafe fn opt_bytes(p: *const c_char) -> Option<Vec<u8>> {
	// SAFETY: see above
	(!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

// SAFETY (callers): l an alpm_list_t of C strings
unsafe fn list_bytes(mut l: *const CList) -> Vec<Vec<u8>> {
	let mut out = Vec::new();
	while !l.is_null() {
		// SAFETY: see above, data never NULL in conf.c lists
		unsafe {
			out.push(CStr::from_ptr((*l).data.cast())
				.to_bytes()
				.to_vec());
			l = (*l).next;
		}
	}
	out
}

// SAFETY (callers): s points at one of enable_colors' literal sets
unsafe fn colstr(s: &ColStrC) -> ColStr<'static> {
	// SAFETY: see above
	let colon = unsafe { CStr::from_ptr(s.colon) }.to_bytes();
	let set = [ColStr::PLAIN, ColStr::COLOR]
		.into_iter()
		.find(|c| c.colon == colon)
		.expect("unknown colstr");
	// SAFETY: see above
	let err = unsafe { CStr::from_ptr(s.err) }.to_bytes();
	assert_eq!(err, set.err, "mixed colstr");
	set
}

// SAFETY (callers): c a config_t built by config_new and conf.c
unsafe fn read_config(c: &ConfigC) -> Config {
	// SAFETY: see above, every pointer is NULL or owned by c
	unsafe {
		let mut repos = Vec::new();
		let mut l = c.repos.cast_const();
		while !l.is_null() {
			let r = &*(*l).data.cast::<ConfigRepoC>();
			repos.push(ConfigRepo {
				name: opt_bytes(r.name).unwrap(),
				cache_servers: list_bytes(r.cache_servers),
				servers: list_bytes(r.servers),
				usage: r.usage,
				siglevel: r.siglevel,
				siglevel_mask: r.siglevel_mask,
			});
			l = (*l).next;
		}
		let argv = (!c.xfercommand_argv.is_null()).then(|| {
			let mut v = Vec::new();
			let mut p = c.xfercommand_argv;
			while !(*p).is_null() {
				v.push(CStr::from_ptr(*p).to_bytes().to_vec());
				p = p.add(1);
			}
			v
		});
		assert!(c.handle.is_null() && c.explicit_adds.is_null());
		assert!(c.explicit_removes.is_null());
		Config {
			op: c.op,
			quiet: c.quiet,
			verbose: c.verbose,
			version: c.version,
			help: c.help,
			noconfirm: c.noconfirm,
			noprogressbar: c.noprogressbar,
			logmask: c.logmask,
			print: c.print,
			checkspace: c.checkspace,
			usesyslog: c.usesyslog,
			color: c.color,
			disable_dl_timeout: c.disable_dl_timeout,
			disable_sandbox_filesystem: c
				.disable_sandbox_filesystem,
			disable_sandbox_syscalls: c.disable_sandbox_syscalls,
			print_format: opt_bytes(c.print_format),
			configfile: opt_bytes(c.configfile),
			rootdir: opt_bytes(c.rootdir),
			dbpath: opt_bytes(c.dbpath),
			logfile: opt_bytes(c.logfile),
			gpgdir: opt_bytes(c.gpgdir),
			sysroot: opt_bytes(c.sysroot),
			sandboxuser: opt_bytes(c.sandboxuser),
			hookdirs: list_bytes(c.hookdirs),
			cachedirs: list_bytes(c.cachedirs),
			architectures: list_bytes(c.architectures),
			op_q_isfile: c.op_q_isfile,
			op_q_info: c.op_q_info,
			op_q_list: c.op_q_list,
			op_q_unrequired: c.op_q_unrequired,
			op_q_deps: c.op_q_deps,
			op_q_explicit: c.op_q_explicit,
			op_q_owns: c.op_q_owns,
			op_q_search: c.op_q_search,
			op_q_changelog: c.op_q_changelog,
			op_q_upgrade: c.op_q_upgrade,
			op_q_check: c.op_q_check,
			op_q_locality: c.op_q_locality,
			op_s_clean: c.op_s_clean,
			op_s_downloadonly: c.op_s_downloadonly,
			op_s_info: c.op_s_info,
			op_s_sync: c.op_s_sync,
			op_s_search: c.op_s_search,
			op_s_upgrade: c.op_s_upgrade,
			op_f_regex: c.op_f_regex,
			op_f_machinereadable: c.op_f_machinereadable,
			group: c.group,
			noask: c.noask,
			ask: c.ask,
			flags: c.flags,
			siglevel: c.siglevel,
			localfilesiglevel: c.localfilesiglevel,
			remotefilesiglevel: c.remotefilesiglevel,
			siglevel_mask: c.siglevel_mask,
			localfilesiglevel_mask: c.localfilesiglevel_mask,
			remotefilesiglevel_mask: c.remotefilesiglevel_mask,
			chomp: c.chomp,
			verbosepkglists: c.verbosepkglists,
			parallel_downloads: c.parallel_downloads,
			cleanmethod: c.cleanmethod,
			holdpkg: list_bytes(c.holdpkg),
			ignorepkg: list_bytes(c.ignorepkg),
			ignoregrp: list_bytes(c.ignoregrp),
			assumeinstalled: list_bytes(c.assumeinstalled),
			noupgrade: list_bytes(c.noupgrade),
			noextract: list_bytes(c.noextract),
			overwrite_files: list_bytes(c.overwrite_files),
			xfercommand: opt_bytes(c.xfercommand),
			xfercommand_argv: argv,
			xfercommand_argc: c.xfercommand_argc,
			colstr: colstr(&c.colstr),
			repos,
		}
	}
}

// config_new as read through the mirror: guards its layout, the fields
// set there sit at the start, middle and end of config_t, and the
// allocation fits size_of::<ConfigC>()
pub fn c_config_new() -> Config {
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	// SAFETY: config_new returns a calloc'd config_t or NULL. the
	// global config only needs to point at it for config_free, which
	// frees `config->repos`; FRONTEND serializes the global
	unsafe {
		let c = config_new();
		assert!(!c.is_null());
		// calloc(1, sizeof(config_t)): glibc rounds up by less than 16
		let usable = malloc_usable_size(c.cast());
		let size = size_of::<ConfigC>();
		assert!(usable >= size && usable - size < 16, "config_t size");
		let out = read_config(&*c);
		let old = config;
		config = c;
		config_free(c);
		config = old;
		out
	}
}

// drops the "[HH:MM:SS] " PACMAN_DEBUG puts before debug-enabled lines
fn strip_timestamps(out: &[u8]) -> Vec<u8> {
	let mut res = Vec::with_capacity(out.len());
	for line in out.split_inclusive(|&c| c == b'\n') {
		let stamp = line.len() >= 11
			&& line[0] == b'[' && line[9] == b']'
			&& line[10] == b' ' && line[1..9]
			.iter()
			.enumerate()
			.all(|(i, &c)| {
				if i % 3 == 2 {
					c == b':'
				} else {
					c.is_ascii_digit()
				}
			});
		res.extend_from_slice(if stamp { &line[11..] } else { line });
	}
	res
}

// SAFETY (callers): FRONTEND held, s valid or NULL
unsafe fn set_str(slot: &mut *mut c_char, s: &Option<Vec<u8>>) {
	if let Some(s) = s {
		let s = cstr(s);
		// SAFETY: s is a valid C string, the copy is owned by config
		*slot = unsafe { strdup(s.as_ptr()) };
	}
}

pub fn c_parseconfig(file: &[u8], preset: &Preset) -> CParse {
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	let f = cstr(file);
	let (mut buf, mut size) = (ptr::null_mut(), 0usize);
	// SAFETY: FRONTEND serializes the globals config, stdout, stderr.
	// the fresh config is only reachable through `config` while the C
	// runs and is freed by config_free before the old one is put back.
	// the memstream replaces stderr only during the calls, its buffer
	// is malloc'd and valid for size bytes after fclose
	unsafe {
		let c = config_new();
		assert!(!c.is_null());
		let old = config;
		config = c;
		set_str(&mut (*c).sysroot, &preset.sysroot);
		set_str(&mut (*c).rootdir, &preset.rootdir);
		set_str(&mut (*c).dbpath, &preset.dbpath);
		set_str(&mut (*c).gpgdir, &preset.gpgdir);
		set_str(&mut (*c).logfile, &preset.logfile);
		set_str(&mut (*c).sandboxuser, &preset.sandboxuser);
		(*c).logmask = preset.logmask;
		if preset.color != 0 {
			(*c).color = preset.color;
			enable_colors(preset.color.into());
		}

		let mem = open_memstream(&mut buf, &mut size);
		assert!(!mem.is_null());
		let (real_out, real_err) = (stdout, stderr);
		fflush(real_out);
		fflush(real_err);
		stderr = mem;
		// a memstream has no fd: isatty(-1) is false
		stdout = if preset.tty { tty_file() } else { mem };

		let mut ret = parseconfigfile(f.as_ptr());
		if ret == 0 {
			ret = setdefaults(c);
			if ret == 0 {
				pm_printf(
					ALPM_LOG_DEBUG,
					c"config: finished parsing %s\n"
						.as_ptr(),
					f.as_ptr(),
				);
			}
		}

		fflush(mem);
		stdout = real_out;
		stderr = real_err;
		fclose(mem);
		let out = std::slice::from_raw_parts(buf.cast::<u8>(), size);
		let out = strip_timestamps(out);
		c_free(buf.cast());

		let parsed = read_config(&*c);
		config_free(c);
		config = old;
		CParse {
			ret,
			config: parsed,
			stderr: out,
		}
	}
}

// uname(2) machine, what Architecture = auto becomes
pub fn c_uname_machine() -> Vec<u8> {
	let mut u = Utsname {
		fields: [[0; 65]; 6],
	};
	// SAFETY: u is a utsname sized buffer, filled nul terminated
	unsafe {
		assert_eq!(uname(&mut u), 0);
		CStr::from_ptr(u.fields[4].as_ptr()).to_bytes().to_vec()
	}
}

// glob(pattern, GLOB_NOCHECK, NULL): the result paths, or Err(ret)
pub fn c_glob(pattern: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
	// parseconfig globs under FRONTEND too: keep every C call in this
	// binary serialized
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	let p = cstr(pattern);
	let mut g = GlobT {
		gl_pathc: 0,
		gl_pathv: ptr::null_mut(),
		gl_offs: 0,
		gl_flags: 0,
		gl_funcs: [ptr::null_mut(); 5],
	};
	// SAFETY: g is a glob_t, p a valid C string. on success gl_pathv
	// holds gl_pathc C strings until globfree
	unsafe {
		let ret = glob(p.as_ptr(), GLOB_NOCHECK, ptr::null(), &mut g);
		if ret != 0 {
			globfree(&mut g);
			return Err(ret);
		}
		let out = (0..g.gl_pathc)
			.map(|i| {
				CStr::from_ptr(*g.gl_pathv.add(i))
					.to_bytes()
					.to_vec()
			})
			.collect();
		globfree(&mut g);
		Ok(out)
	}
}
