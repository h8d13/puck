// port of src/pacman/conf.c: the config model and config file parsing
//
// the C config_t is the global `config`, here an owned `Config` passed by
// &mut. parseconfig stops after setdefaults and keeps the resolved repos
// in `Config::repos`; setup_libalpm (the C's last step of parseconfig)
// is separate and returns the Handle instead of setting config->handle,
// registering the repos and dropping the list like the C, and the
// XferCommand fetchcb (XferCommand below). explicit_adds/removes
// (alpm_pkg_t lists) are not modelled.
//
// pm_printf goes through `Host::log` with the config as it is at that
// moment (logmask, colstr), `format_msg` renders it like pm_vfprintf
// minus the PACMAN_DEBUG timestamp. isatty(stdout) and uname are `Host`
// probes too. alpm_capabilities() is taken as signatures built in.
// messages are the untranslated msgids. paths default to the arch build
// (configure-time CONFFILE, DBPATH, ... in the C).

use std::ffi::{OsStr, OsString, c_int};
use std::fs;
use std::io::{self, IsTerminal};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use alpm_core::callbacks::{Callbacks, Fetch};
use alpm_core::deps::dep_from_string;
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::sandbox::{ExecError, IgnoreSignals, SandboxExec};
use alpm_core::util::{fnmatch, strerror, until_nul};
use pacman_common::ini::{Ini, parse_ini};
use pacman_common::util_common::{PATH_MAX, wordsplit};

use crate::pacman::PM_OP_FILES;
use crate::util::{Output, arg_to_string, pm_printf, strreplace};

// meson config.h of the reference build
pub const CONFFILE: &[u8] = b"/etc/pacman.conf";
pub const ROOTDIR: &[u8] = b"/";
pub const DBPATH: &[u8] = b"/var/lib/pacman/";
pub const LOGFILE: &[u8] = b"/var/log/pacman.log";
pub const GPGDIR: &[u8] = b"/etc/pacman.d/gnupg/";
pub const CACHEDIR: &[u8] = b"/var/cache/pacman/pkg/";
pub const HOOKDIR: &[u8] = b"/etc/pacman.d/hooks/";

// alpm_capabilities() & ALPM_CAPABILITY_SIGNATURES
pub const HAVE_SIGNATURES: bool = true;
const MAX_RECURSION: i32 = 10;

// alpm_loglevel_t
pub const LOG_ERROR: u16 = 1;
pub const LOG_WARNING: u16 = 1 << 1;
pub const LOG_DEBUG: u16 = 1 << 2;
pub const LOG_FUNCTION: u16 = 1 << 3;

// alpm_siglevel_t
pub const SIG_PACKAGE: i32 = 1;
pub const SIG_PACKAGE_OPTIONAL: i32 = 1 << 1;
pub const SIG_PACKAGE_MARGINAL_OK: i32 = 1 << 2;
pub const SIG_PACKAGE_UNKNOWN_OK: i32 = 1 << 3;
pub const SIG_DATABASE: i32 = 1 << 10;
pub const SIG_DATABASE_OPTIONAL: i32 = 1 << 11;
pub const SIG_DATABASE_MARGINAL_OK: i32 = 1 << 12;
pub const SIG_DATABASE_UNKNOWN_OK: i32 = 1 << 13;
pub const SIG_USE_DEFAULT: i32 = 1 << 30;

// alpm_db_usage_t
pub const DB_USAGE_SYNC: i32 = 1;
pub const DB_USAGE_SEARCH: i32 = 1 << 1;
pub const DB_USAGE_INSTALL: i32 = 1 << 2;
pub const DB_USAGE_UPGRADE: i32 = 1 << 3;
pub const DB_USAGE_ALL: i32 = (1 << 4) - 1;

// conf.h enums
pub const PM_OP_MAIN: u16 = 1;
pub const PM_CLEAN_KEEPINST: u16 = 1;
pub const PM_CLEAN_KEEPCUR: u16 = 1 << 1;
pub const PM_COLOR_UNSET: u16 = 0;
pub const PM_COLOR_OFF: u16 = 1;
pub const PM_COLOR_ON: u16 = 2;

// colstr_t: the C keeps pointers to string literals, `Config` holds
// 'static ones. the display helpers of util.rs take any lifetime
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColStr<'a> {
	pub colon: &'a [u8],
	pub title: &'a [u8],
	pub repo: &'a [u8],
	pub version: &'a [u8],
	pub groups: &'a [u8],
	pub meta: &'a [u8],
	pub warn: &'a [u8],
	pub err: &'a [u8],
	pub faint: &'a [u8],
	pub nocolor: &'a [u8],
}

impl ColStr<'static> {
	// enable_colors(PM_COLOR_ON)
	pub const COLOR: Self = ColStr {
		colon: b"\x1b[1;34m::\x1b[0;1m ",
		title: b"\x1b[0;1m",
		repo: b"\x1b[1;35m",
		version: b"\x1b[1;32m",
		groups: b"\x1b[1;34m",
		meta: b"\x1b[1;36m",
		warn: b"\x1b[1;33m",
		err: b"\x1b[1;31m",
		faint: b"\x1b[38;5;243m",
		nocolor: b"\x1b[0m",
	};
	// enable_colors(other), config_new
	pub const PLAIN: Self = ColStr {
		colon: b":: ",
		title: b"",
		repo: b"",
		version: b"",
		groups: b"",
		meta: b"",
		warn: b"",
		err: b"",
		faint: b"",
		nocolor: b"",
	};
}

impl Default for ColStr<'_> {
	fn default() -> Self {
		ColStr::PLAIN
	}
}

// config_repo_t
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigRepo {
	pub name: Vec<u8>,
	pub cache_servers: Vec<Vec<u8>>,
	pub servers: Vec<Vec<u8>>,
	pub usage: i32,
	pub siglevel: i32,
	pub siglevel_mask: i32,
}

// config_t, field for field minus handle and explicit_adds/removes.
// NULL strings are None, NULL lists empty
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
	pub op: u16,
	pub quiet: u16,
	pub verbose: u16,
	pub version: u16,
	pub help: u16,
	pub noconfirm: u16,
	pub noprogressbar: u16,
	pub logmask: u16,
	pub print: u16,
	pub checkspace: u16,
	pub usesyslog: u16,
	pub color: u16,
	pub disable_dl_timeout: u16,
	pub disable_sandbox_filesystem: u16,
	pub disable_sandbox_syscalls: u16,
	pub print_format: Option<Vec<u8>>,
	pub configfile: Option<Vec<u8>>,
	pub rootdir: Option<Vec<u8>>,
	pub dbpath: Option<Vec<u8>>,
	pub logfile: Option<Vec<u8>>,
	pub gpgdir: Option<Vec<u8>>,
	pub sysroot: Option<Vec<u8>>,
	pub sandboxuser: Option<Vec<u8>>,
	// setuseragent's HTTP_USER_AGENT: the downloader's User-Agent, in
	// the XferCommand's environment (the C puts it in the process's)
	pub user_agent: Vec<u8>,
	pub hookdirs: Vec<Vec<u8>>,
	pub cachedirs: Vec<Vec<u8>>,
	pub architectures: Vec<Vec<u8>>,

	pub op_q_isfile: u16,
	pub op_q_info: u16,
	pub op_q_list: u16,
	pub op_q_unrequired: u16,
	pub op_q_deps: u16,
	pub op_q_explicit: u16,
	pub op_q_owns: u16,
	pub op_q_search: u16,
	pub op_q_changelog: u16,
	pub op_q_upgrade: u16,
	pub op_q_check: u16,
	pub op_q_locality: u16,

	pub op_s_clean: u16,
	pub op_s_downloadonly: u16,
	pub op_s_info: u16,
	pub op_s_sync: u16,
	pub op_s_search: u16,
	pub op_s_upgrade: u16,

	pub op_f_regex: u16,
	pub op_f_machinereadable: u16,

	pub group: u16,
	pub noask: u16,
	pub ask: u32,
	pub flags: i32,
	pub siglevel: i32,
	pub localfilesiglevel: i32,
	pub remotefilesiglevel: i32,
	pub siglevel_mask: i32,
	pub localfilesiglevel_mask: i32,
	pub remotefilesiglevel_mask: i32,

	pub chomp: u16,
	pub verbosepkglists: u16,
	pub parallel_downloads: u32,
	pub cleanmethod: u16,
	pub holdpkg: Vec<Vec<u8>>,
	pub ignorepkg: Vec<Vec<u8>>,
	pub ignoregrp: Vec<Vec<u8>>,
	pub assumeinstalled: Vec<Vec<u8>>,
	pub noupgrade: Vec<Vec<u8>>,
	pub noextract: Vec<Vec<u8>>,
	pub overwrite_files: Vec<Vec<u8>>,
	pub xfercommand: Option<Vec<u8>>,
	pub xfercommand_argv: Option<Vec<Vec<u8>>>,
	pub xfercommand_argc: usize,

	pub colstr: ColStr<'static>,

	pub repos: Vec<ConfigRepo>,
}

// what pm_printf reports while parsing, one variant per C format string.
// file is the path as handed to parse_ini, err an errno
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
	ReadFailed {
		file: Vec<u8>,
		err: i32,
	},
	NoSection {
		file: Vec<u8>,
		line: usize,
	},
	NeedsValue {
		file: Vec<u8>,
		line: usize,
		key: Vec<u8>,
	},
	MaxRecursion,
	InvalidValue {
		file: Vec<u8>,
		line: usize,
		option: &'static str,
		value: Vec<u8>,
	},
	NotPositive {
		file: Vec<u8>,
		line: usize,
		value: Vec<u8>,
	},
	TooLarge {
		file: Vec<u8>,
		line: usize,
		value: Vec<u8>,
	},
	NoSignatureSupport {
		file: Vec<u8>,
		line: usize,
	},
	UsageNotRecognized {
		file: Vec<u8>,
		line: usize,
		value: Vec<u8>,
	},
	ResolvePath {
		path: Vec<u8>,
		option: &'static str,
		err: i32,
	},
	MirrorNoArch {
		mirror: Vec<u8>,
	},
	// warning
	UnknownDirective {
		file: Vec<u8>,
		line: usize,
		key: Vec<u8>,
		section: Vec<u8>,
	},
	// setup_libalpm and register_repo
	InitFailed {
		root: Vec<u8>,
		dbpath: Vec<u8>,
		err: Errno,
	},
	// fprintf(stderr) after a DB_VERSION failure, no prefix or logmask
	DbUpgradeHint,
	RegisterFailed {
		name: Vec<u8>,
		err: Errno,
	},
	ServerFailed {
		cache: bool,
		db: Vec<u8>,
		url: Vec<u8>,
		err: Errno,
	},
	DownloadUser {
		user: Vec<u8>,
	},
	AssumeInstalled,
	// debug traces, kept as their formatted text
	Debug(Vec<u8>),
}

pub(crate) fn cat(parts: &[&[u8]]) -> Vec<u8> {
	parts.concat()
}

impl Msg {
	pub fn level(&self) -> u16 {
		match self {
			Msg::UnknownDirective { .. } => LOG_WARNING,
			Msg::Debug(_) => LOG_DEBUG,
			_ => LOG_ERROR,
		}
	}

	// the formatted message, without the level prefix
	pub fn text(&self) -> Vec<u8> {
		let at = |file: &[u8], line: usize| {
			let line = line.to_string();
			cat(&[
				b"config file ",
				file,
				b", line ",
				line.as_bytes(),
				b": ",
			])
		};
		match self {
			Msg::ReadFailed { file, err } => cat(&[
				b"config file ",
				file,
				b" could not be read: ",
				&strerror(&io::Error::from_raw_os_error(*err)),
				b"\n",
			]),
			Msg::NoSection { file, line } => cat(&[
				&at(file, *line),
				b"All directives must belong to a section.\n",
			]),
			Msg::NeedsValue { file, line, key } => cat(&[
				&at(file, *line),
				b"directive '",
				key,
				b"' needs a value\n",
			]),
			Msg::MaxRecursion => format!(
				"config parsing exceeded max recursion \
				depth of {MAX_RECURSION}.\n"
			)
			.into_bytes(),
			Msg::InvalidValue {
				file,
				line,
				option,
				value,
			} => cat(&[
				&at(file, *line),
				b"invalid value for '",
				option.as_bytes(),
				b"' : '",
				value,
				b"'\n",
			]),
			Msg::NotPositive { file, line, value } => cat(&[
				&at(file, *line),
				b"value for 'ParallelDownloads' has to be ",
				b"positive : '",
				value,
				b"'\n",
			]),
			Msg::TooLarge { file, line, value } => cat(&[
				&at(file, *line),
				b"value for 'ParallelDownloads' is too large : '",
				value,
				b"'\n",
			]),
			Msg::NoSignatureSupport { file, line } => cat(&[
				&at(file, *line),
				b"'SigLevel' option invalid, no signature support\n",
			]),
			Msg::UsageNotRecognized { file, line, value } => cat(&[
				&at(file, *line),
				b"'Usage' option '",
				value,
				b"' not recognized\n",
			]),
			Msg::ResolvePath { path, option, err } => cat(&[
				b"'failed to resolve path '",
				path,
				b"' passed to '",
				option.as_bytes(),
				b"': ",
				&strerror(&io::Error::from_raw_os_error(*err)),
				b"\n",
			]),
			Msg::MirrorNoArch { mirror } => cat(&[
				b"mirror '",
				mirror,
				b"' contains the '$arch' variable, but no ",
				b"'Architecture' is defined.\n",
			]),
			Msg::UnknownDirective {
				file,
				line,
				key,
				section,
			} => cat(&[
				&at(file, *line),
				b"directive '",
				key,
				b"' in section '",
				section,
				b"' not recognized.\n",
			]),
			Msg::InitFailed { root, dbpath, err } => cat(&[
				b"failed to initialize alpm library:\n(root: ",
				root,
				b", dbpath: ",
				dbpath,
				b")\n",
				err.strerror().as_bytes(),
				b"\n",
			]),
			Msg::DbUpgradeHint => b"try running pacman-db-upgrade\n".to_vec(),
			Msg::RegisterFailed { name, err } => cat(&[
				b"could not register '",
				name,
				b"' database (",
				err.strerror().as_bytes(),
				b")\n",
			]),
			Msg::ServerFailed {
				cache,
				db,
				url,
				err,
			} => cat(&[
				b"could not add ",
				if *cache { b"cache server" } else { b"server" },
				b" URL to database '",
				db,
				b"': ",
				url,
				b" (",
				err.strerror().as_bytes(),
				b")\n",
			]),
			Msg::DownloadUser { user } => cat(&[
				b"problem setting DownloadUser '",
				user,
				b"' (user does not exist)\n",
			]),
			// no newline in the C either
			Msg::AssumeInstalled => {
				b"Failed to pass assume-installed entry to libalpm"
					.to_vec()
			}
			Msg::Debug(s) => s.clone(),
		}
	}
}

// pm_vfprintf to a buffer: None when logmask filters the level
pub fn format_msg(config: &Config, msg: &Msg) -> Option<Vec<u8>> {
	if *msg == Msg::DbUpgradeHint {
		return Some(msg.text());
	}
	let level = msg.level();
	if config.logmask & level == 0 {
		return None;
	}
	let c = &config.colstr;
	let prefix = match level {
		LOG_ERROR => cat(&[c.err, b"error: ", c.nocolor]),
		LOG_WARNING => cat(&[c.warn, b"warning: ", c.nocolor]),
		_ => b"debug: ".to_vec(),
	};
	Some(cat(&[&prefix, &msg.text()]))
}

// what conf.c asks of its environment
pub trait Host {
	// pm_printf: config is the state at the time of the call
	fn log(&mut self, config: &Config, msg: &Msg);

	// where the fetchcb's messages go after setup (Output::sink)
	fn sink(&self) -> Option<fn(&mut Output)> {
		None
	}

	// isatty(fileno(stdout)), for Color
	fn stdout_is_tty(&mut self) -> bool {
		io::stdout().is_terminal()
	}

	// uname(2) machine, for Architecture = auto. the kernel's compiled
	// machine name, which unlike uname ignores personality(2)
	fn machine(&mut self) -> Vec<u8> {
		match fs::read("/proc/sys/kernel/arch") {
			Ok(mut m) => {
				if m.last() == Some(&b'\n') {
					m.pop();
				}
				m
			}
			Err(_) => std::env::consts::ARCH.as_bytes().to_vec(),
		}
	}
}

// failure of parseconfigfile/setdefaults/parseconfig: the C return value
// (1 parse error, -1 setdefaults) and the last error reported
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfError {
	pub ret: i32,
	pub msg: Msg,
}

impl Default for Config {
	fn default() -> Self {
		Config::new()
	}
}

impl Config {
	// config_new
	pub fn new() -> Self {
		let sig = if HAVE_SIGNATURES {
			(SIG_PACKAGE | SIG_DATABASE, SIG_USE_DEFAULT)
		} else {
			(0, 0)
		};
		Config {
			op: PM_OP_MAIN,
			quiet: 0,
			verbose: 0,
			version: 0,
			help: 0,
			noconfirm: 0,
			noprogressbar: 0,
			logmask: LOG_ERROR | LOG_WARNING,
			print: 0,
			checkspace: 0,
			usesyslog: 0,
			color: PM_COLOR_UNSET,
			disable_dl_timeout: 0,
			disable_sandbox_filesystem: 0,
			disable_sandbox_syscalls: 0,
			print_format: None,
			configfile: Some(CONFFILE.to_vec()),
			rootdir: None,
			dbpath: None,
			logfile: None,
			gpgdir: None,
			sysroot: None,
			sandboxuser: None,
			user_agent: Vec::new(),
			hookdirs: Vec::new(),
			cachedirs: Vec::new(),
			architectures: Vec::new(),
			op_q_isfile: 0,
			op_q_info: 0,
			op_q_list: 0,
			op_q_unrequired: 0,
			op_q_deps: 0,
			op_q_explicit: 0,
			op_q_owns: 0,
			op_q_search: 0,
			op_q_changelog: 0,
			op_q_upgrade: 0,
			op_q_check: 0,
			op_q_locality: 0,
			op_s_clean: 0,
			op_s_downloadonly: 0,
			op_s_info: 0,
			op_s_sync: 0,
			op_s_search: 0,
			op_s_upgrade: 0,
			op_f_regex: 0,
			op_f_machinereadable: 0,
			group: 0,
			noask: 0,
			ask: 0,
			flags: 0,
			siglevel: sig.0,
			localfilesiglevel: sig.1,
			remotefilesiglevel: sig.1,
			siglevel_mask: 0,
			localfilesiglevel_mask: 0,
			remotefilesiglevel_mask: 0,
			chomp: 0,
			verbosepkglists: 0,
			parallel_downloads: 1,
			cleanmethod: 0,
			holdpkg: Vec::new(),
			ignorepkg: Vec::new(),
			ignoregrp: Vec::new(),
			assumeinstalled: Vec::new(),
			noupgrade: Vec::new(),
			noextract: Vec::new(),
			overwrite_files: Vec::new(),
			xfercommand: None,
			xfercommand_argv: None,
			xfercommand_argc: 0,
			colstr: ColStr::PLAIN,
			repos: Vec::new(),
		}
	}

	// enable_colors
	pub fn enable_colors(&mut self, colors: u16) {
		self.colstr = if colors == PM_COLOR_ON {
			ColStr::COLOR
		} else {
			ColStr::PLAIN
		};
	}

	// config_add_architecture
	pub fn add_architecture<H: Host>(&mut self, arch: &[u8], host: &mut H) {
		let arch = if arch == b"auto" {
			host.machine()
		} else {
			arch.to_vec()
		};
		let msg = Msg::Debug(cat(&[b"config: arch: ", &arch, b"\n"]));
		host.log(self, &msg);
		self.architectures.push(arch);
	}

	// parseconfigfile: file is looked up under sysroot
	pub fn parseconfigfile<H: Host>(
		&mut self,
		file: &[u8],
		host: &mut H,
	) -> Result<(), ConfError> {
		let realfile = prepend_dir(self.sysroot.as_deref(), file);
		let mut p = Parser {
			config: self,
			host,
			section: Section::default(),
			err: None,
		};
		p.parse_file(&realfile);
		match p.err {
			Some(msg) => Err(ConfError { ret: 1, msg }),
			None => Ok(()),
		}
	}

	// setdefaults
	pub fn setdefaults<H: Host>(
		&mut self,
		host: &mut H,
	) -> Result<(), ConfError> {
		if let Some(root) = &self.rootdir {
			// one trailing slash off. the C indexes rootdir[-1] on an
			// empty rootdir, left untouched here
			let root = root.strip_suffix(b"/").unwrap_or(root);
			// snprintf into PATH_MAX
			let under = |path: &[u8]| {
				let mut p = cat(&[root, b"/", &path[1..]]);
				p.truncate(PATH_MAX - 1);
				p
			};
			if self.dbpath.is_none() {
				self.dbpath = Some(under(DBPATH));
			}
			if self.logfile.is_none() {
				self.logfile = Some(under(LOGFILE));
			}
		} else {
			self.rootdir = Some(ROOTDIR.to_vec());
			self.dbpath.get_or_insert_with(|| DBPATH.to_vec());
		}

		self.logfile.get_or_insert_with(|| LOGFILE.to_vec());
		self.gpgdir.get_or_insert_with(|| GPGDIR.to_vec());
		if self.cachedirs.is_empty() {
			self.cachedirs.push(CACHEDIR.to_vec());
		}
		if self.hookdirs.is_empty() {
			self.hookdirs.push(HOOKDIR.to_vec());
		}
		if self.cleanmethod == 0 {
			self.cleanmethod = PM_CLEAN_KEEPINST;
		}

		self.localfilesiglevel = merge_siglevel(
			self.siglevel,
			self.localfilesiglevel,
			self.localfilesiglevel_mask,
		);
		self.remotefilesiglevel = merge_siglevel(
			self.siglevel,
			self.remotefilesiglevel,
			self.remotefilesiglevel_mask,
		);

		for i in 0..self.repos.len() {
			let r = &mut self.repos[i];
			if r.usage == 0 {
				r.usage = DB_USAGE_ALL;
			}
			r.siglevel = merge_siglevel(
				self.siglevel,
				r.siglevel,
				r.siglevel_mask,
			);
			// lists replaced in place up to the failing entry, like
			// the C
			let replaced = self
				.replace_server_list_vars(i, true)
				.and_then(|()| {
					self.replace_server_list_vars(i, false)
				});
			if let Err(msg) = replaced {
				host.log(self, &msg);
				return Err(ConfError { ret: -1, msg });
			}
		}

		self.prepend_sysroot();
		Ok(())
	}

	// parseconfig up to setup_libalpm, see the header
	pub fn parseconfig<H: Host>(
		&mut self,
		file: &[u8],
		host: &mut H,
	) -> Result<(), ConfError> {
		self.parseconfigfile(file, host)?;
		self.setdefaults(host)?;
		let msg = Msg::Debug(cat(&[
			b"config: finished parsing ",
			file,
			b"\n",
		]));
		host.log(self, &msg);
		Ok(())
	}

	// setup_libalpm: the handle for this config with cb as its
	// callbacks, the repos registered (and dropped from the config). Err
	// is the C return value. the C fails on logfile, gpgdir and hookdirs
	// only for NULL or out of memory, the default siglevel only for
	// exactly SIG_USE_DEFAULT (unchecked), parallel downloads only for 0
	// (setdefaults never leaves it there): not reported here either
	pub fn setup_libalpm<H: Host>(
		&mut self,
		host: &mut H,
		cb: Box<dyn Callbacks>,
	) -> Result<Handle, ConfError> {
		let debug = |s: &[u8]| Msg::Debug(s.to_vec());
		host.log(self, &debug(b"setup_libalpm called\n"));
		let root = self.rootdir.clone().unwrap_or_default();
		let dbpath = self.dbpath.clone().unwrap_or_default();
		let mut handle = match Handle::initialize(&root, &dbpath) {
			Ok(h) => h,
			Err(err) => {
				let msg = Msg::InitFailed { root, dbpath, err };
				host.log(self, &msg);
				if err == Errno::DbVersion {
					host.log(self, &Msg::DbUpgradeHint);
				}
				return Err(ConfError { ret: -1, msg });
			}
		};
		handle.set_callbacks(cb);
		if self.op == PM_OP_FILES {
			handle.set_dbext(b".files");
		}
		handle.set_logfile(self.logfile.as_deref().unwrap_or_default());
		handle.set_gpgdir(self.gpgdir.as_deref().unwrap_or_default());
		for dir in &self.hookdirs {
			handle.add_hookdir(dir);
		}
		handle.set_cachedirs(&self.cachedirs);
		handle.set_overwrite_files(&self.overwrite_files);
		let _ = handle.set_default_siglevel(self.siglevel);
		handle.set_local_file_siglevel(self.localfilesiglevel);
		handle.set_remote_file_siglevel(self.remotefilesiglevel);
		// a repo that does not register is reported and skipped
		for repo in &self.repos {
			register_repo(self, &mut handle, host, repo);
		}
		// alpm_capabilities has the downloader: no "no XferCommand" note
		handle.set_fetchcb(self.xfercommand_fetch(host.sink()));
		handle.set_architectures(&self.architectures);
		handle.set_checkspace(i32::from(self.checkspace));
		handle.set_usesyslog(i32::from(self.usesyslog));
		if !handle.set_sandboxuser(self.sandboxuser.as_deref()) {
			let user = self.sandboxuser.clone().unwrap_or_default();
			let msg = Msg::DownloadUser { user };
			host.log(self, &msg);
			return Err(ConfError { ret: 1, msg });
		}
		handle.set_disable_sandbox_filesystem(
			self.disable_sandbox_filesystem,
		);
		handle.set_disable_sandbox_syscalls(
			self.disable_sandbox_syscalls,
		);
		handle.set_ignorepkgs(&self.ignorepkg);
		handle.set_ignoregroups(&self.ignoregrp);
		handle.set_noupgrades(&self.noupgrade);
		handle.set_noextracts(&self.noextract);
		handle.set_disable_dl_timeout(self.disable_dl_timeout);
		let _ = handle.set_parallel_downloads(self.parallel_downloads);
		if !self.user_agent.is_empty() {
			handle.set_user_agent(Some(&self.user_agent));
		}
		for entry in &self.assumeinstalled {
			let dep = dep_from_string(entry);
			// printf("%s", NULL) is "(null)" in glibc
			let ver = dep.version.as_deref().unwrap_or(b"(null)");
			let line = cat(&[
				b"parsed assume installed: ",
				&dep.name,
				b" ",
				ver,
				b"\n",
			]);
			host.log(self, &Msg::Debug(line));
			if handle.add_assumeinstalled(&dep).is_err() {
				let msg = Msg::AssumeInstalled;
				host.log(self, &msg);
				return Err(ConfError { ret: -1, msg });
			}
		}
		self.repos.clear();
		Ok(handle)
	}

	// replace_server_list_vars over repo i's cache servers or servers,
	// stops at the first entry that fails
	fn replace_server_list_vars(&mut self, i: usize, cache: bool) -> Step {
		let arch = self.architectures.first().cloned();
		let r = &mut self.repos[i];
		let list = if cache {
			&mut r.cache_servers
		} else {
			&mut r.servers
		};
		for url in list.iter_mut() {
			*url = replace_server_vars(
				arch.as_deref(),
				&r.name,
				url,
			)?;
		}
		Ok(())
	}

	fn prepend_sysroot(&mut self) {
		let Some(sysroot) = self.sysroot.clone() else {
			return;
		};
		let root = Some(sysroot.as_slice());
		let paths = [
			&mut self.rootdir,
			&mut self.dbpath,
			&mut self.logfile,
			&mut self.gpgdir,
		];
		for p in paths.into_iter().flatten() {
			*p = prepend_dir(root, p);
		}
		for p in self.cachedirs.iter_mut().chain(&mut self.hookdirs) {
			*p = prepend_dir(root, p);
		}
		// servers only, cache servers keep their file:// urls
		for r in &mut self.repos {
			for url in &mut r.servers {
				if let Some(dir) = url.strip_prefix(b"file://")
				{
					let dir = prepend_dir(root, dir);
					*url = cat(&[b"file://", &dir]);
				}
			}
		}
	}
}

// register_repo: the sync db with its usage and servers, false (C 1)
// at the first failure, reported
fn register_repo<H: Host>(
	config: &Config,
	handle: &mut Handle,
	host: &mut H,
	repo: &ConfigRepo,
) -> bool {
	if let Err(err) = handle.register_syncdb(&repo.name, repo.siglevel) {
		let name = repo.name.clone();
		host.log(config, &Msg::RegisterFailed { name, err });
		return false;
	}
	let dbs = handle.dbs_mut();
	let db = dbs.sync.last_mut().expect("just registered");
	let usage = format!("setting usage of {} for ", repo.usage);
	let line = cat(&[usage.as_bytes(), &repo.name, b" repository\n"]);
	host.log(config, &Msg::Debug(line));
	db.set_usage(repo.usage);
	let lists = [(true, &repo.cache_servers), (false, &repo.servers)];
	for (cache, urls) in lists {
		for url in urls {
			let added = match cache {
				true => db.add_cache_server(dbs.cb, url),
				false => db.add_server(dbs.cb, url),
			};
			if let Err(err) = added {
				let msg = Msg::ServerFailed {
					cache,
					db: db.name().to_vec(),
					url: url.clone(),
					err,
				};
				host.log(config, &msg);
				return false;
			}
		}
	}
	true
}

// replace_server_vars: $arch first (first Architecture), then $repo
fn replace_server_vars(
	arch: Option<&[u8]>,
	repo: &[u8],
	s: &[u8],
) -> Result<Vec<u8>, Msg> {
	match arch {
		None if find(s, b"$arch") => {
			Err(Msg::MirrorNoArch { mirror: s.to_vec() })
		}
		None => Ok(strreplace(s, b"$repo", repo)),
		Some(arch) => {
			let s = strreplace(s, b"$arch", arch);
			Ok(strreplace(&s, b"$repo", repo))
		}
	}
}

fn find(s: &[u8], needle: &[u8]) -> bool {
	s.windows(needle.len()).any(|w| w == needle)
}

// the (level, mask) pair a SigLevel option of [options] sets
fn siglevel_slot<'a>(
	c: &'a mut Config,
	key: &[u8],
) -> (&'a mut i32, &'a mut i32) {
	match key {
		b"SigLevel" => (&mut c.siglevel, &mut c.siglevel_mask),
		b"LocalFileSigLevel" => (
			&mut c.localfilesiglevel,
			&mut c.localfilesiglevel_mask,
		),
		_ => (
			&mut c.remotefilesiglevel,
			&mut c.remotefilesiglevel_mask,
		),
	}
}

// process_siglevel words past the Package/Database prefix: (package
// bits, database bits, set or unset) per SLSET/SLUNSET step
fn sig_steps(value: &[u8]) -> Option<&'static [(i32, i32, bool)]> {
	const PKG_TRUST: i32 = SIG_PACKAGE_MARGINAL_OK | SIG_PACKAGE_UNKNOWN_OK;
	const DB_TRUST: i32 =
		SIG_DATABASE_MARGINAL_OK | SIG_DATABASE_UNKNOWN_OK;
	Some(match value {
		b"Never" => &[(SIG_PACKAGE, SIG_DATABASE, false)],
		b"Optional" => &[(
			SIG_PACKAGE | SIG_PACKAGE_OPTIONAL,
			SIG_DATABASE | SIG_DATABASE_OPTIONAL,
			true,
		)],
		b"Required" => &[
			(SIG_PACKAGE, SIG_DATABASE, true),
			(SIG_PACKAGE_OPTIONAL, SIG_DATABASE_OPTIONAL, false),
		],
		b"TrustedOnly" => &[(PKG_TRUST, DB_TRUST, false)],
		b"TrustAll" => &[(PKG_TRUST, DB_TRUST, true)],
		_ => return None,
	})
}

// merge_siglevel
pub fn merge_siglevel(base: i32, over: i32, mask: i32) -> i32 {
	if mask != 0 {
		(over & mask) | (base & !mask)
	} else {
		over
	}
}

// prepend_dir: dir NULL keeps path, else one '/' between dir and path
// with path's leading slashes dropped
pub fn prepend_dir(dir: Option<&[u8]>, path: &[u8]) -> Vec<u8> {
	let Some(dir) = dir else {
		return path.to_vec();
	};
	let sep: &[u8] = if dir.last() == Some(&b'/') { b"" } else { b"/" };
	let start = path.iter().take_while(|&&c| c == b'/').count();
	cat(&[dir, sep, &path[start..]])
}

// escape_chars: a backslash before every byte of `escape`
fn escape_chars(pattern: &[u8], escape: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(pattern.len());
	for &c in pattern {
		if escape.contains(&c) {
			out.push(b'\\');
		}
		out.push(c);
	}
	out
}

// strtok_r(value, " "): words between runs of spaces, tabs stay
fn split_words(value: &[u8]) -> impl Iterator<Item = &[u8]> {
	value.split(|&c| c == b' ').filter(|w| !w.is_empty())
}

// parse_number: strtol base 10 over the whole string, LONG_MIN/LONG_MAX
// with ERANGE rejected
fn parse_number(value: &[u8]) -> Option<i64> {
	let ws = |c: &u8| {
		matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
	};
	let s = &value[value.iter().take_while(|c| ws(c)).count()..];
	let (neg, digits) = match s.first() {
		Some(b'-') => (true, &s[1..]),
		Some(b'+') => (false, &s[1..]),
		_ => (false, s),
	};
	if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
		return None;
	}
	digits.iter().try_fold(0i64, |n, &c| {
		let n = n.checked_mul(10)?;
		let c = i64::from(c - b'0');
		if neg {
			n.checked_sub(c)
		} else {
			n.checked_add(c)
		}
	})
}

// section_t
#[derive(Default)]
struct Section {
	// the C keeps the name pointer, only ever tested for NULL
	named: bool,
	// index into Config::repos, None in [options]
	repo: Option<usize>,
	depth: i32,
}

struct Parser<'a, H> {
	config: &'a mut Config,
	host: &'a mut H,
	section: Section,
	// the error that stopped parse_ini
	err: Option<Msg>,
}

type Step = Result<(), Msg>;

impl<H: Host> Parser<'_, H> {
	fn log(&mut self, msg: Msg) -> Msg {
		self.host.log(self.config, &msg);
		msg
	}

	fn debug(&mut self, parts: &[&[u8]]) {
		self.log(Msg::Debug(cat(parts)));
	}

	// parse_ini with _parse_directive, err set when the callback failed
	fn parse_file(&mut self, file: &[u8]) {
		let path = Path::new(OsStr::from_bytes(file));
		parse_ini(path, |ini| match self.directive(file, ini) {
			Ok(()) => 0,
			Err(msg) => {
				self.err = Some(msg);
				1
			}
		});
	}

	// _parse_directive
	fn directive(&mut self, file: &[u8], ini: Ini) -> Step {
		let (line, key, value) = match ini {
			Ini::OpenError(e) => {
				let err = e.raw_os_error().unwrap_or(0);
				let file = file.to_vec();
				return Err(
					self.log(Msg::ReadFailed { file, err })
				);
			}
			Ini::Section { name, .. } => {
				self.new_section(name);
				return Ok(());
			}
			Ini::Directive {
				line, key, value, ..
			} => (line, key, value),
		};

		if key == b"Include" {
			return self.process_include(value, file, line);
		}

		if !self.section.named {
			let file = file.to_vec();
			return Err(self.log(Msg::NoSection { file, line }));
		}

		match self.section.repo {
			None => self.parse_options(key, value, file, line),
			Some(i) => self.parse_repo(i, key, value, file, line),
		}
	}

	fn new_section(&mut self, name: &[u8]) {
		self.section.named = true;
		self.debug(&[b"config: new section '", name, b"'\n"]);
		if name == b"options" {
			self.section.repo = None;
		} else {
			self.config.repos.push(ConfigRepo {
				name: name.to_vec(),
				siglevel: SIG_USE_DEFAULT,
				..ConfigRepo::default()
			});
			self.section.repo = Some(self.config.repos.len() - 1);
		}
	}

	// process_include: every glob match parsed in order, the first
	// failure stops. a section opened in an included file stays open in
	// the including one (section_t is shared)
	fn process_include(
		&mut self,
		value: Option<&[u8]>,
		file: &[u8],
		line: usize,
	) -> Step {
		let Some(value) = value else {
			let (file, key) = (file.to_vec(), b"Include".to_vec());
			return Err(self.log(Msg::NeedsValue {
				file,
				line,
				key,
			}));
		};
		if self.section.depth >= MAX_RECURSION {
			return Err(self.log(Msg::MaxRecursion));
		}

		self.section.depth += 1;
		// globdir: sysroot escaped, glob errors cannot happen here
		let pattern = match &self.config.sysroot {
			Some(root) => {
				let root = escape_chars(root, b"\\*?[");
				prepend_dir(Some(&root), value)
			}
			None => value.to_vec(),
		};
		for path in glob(&pattern) {
			let l = line.to_string();
			self.debug(&[
				b"config file ",
				file,
				b", line ",
				l.as_bytes(),
				b": including ",
				&path,
				b"\n",
			]);
			self.parse_file(&path);
			if self.err.is_some() {
				break;
			}
		}
		self.section.depth -= 1;
		match self.err.take() {
			Some(msg) => Err(msg),
			None => Ok(()),
		}
	}

	// setrepeatingoption: words of value, each traced
	fn words(&mut self, value: &[u8], option: &str) -> Vec<Vec<u8>> {
		let mut out = Vec::new();
		for w in split_words(value) {
			let o = option.as_bytes();
			self.debug(&[b"config: ", o, b": ", w, b"\n"]);
			out.push(w.to_vec());
		}
		out
	}

	fn unknown(
		&mut self,
		key: &[u8],
		section: &[u8],
		file: &[u8],
		line: usize,
	) {
		self.log(Msg::UnknownDirective {
			file: file.to_vec(),
			line,
			key: key.to_vec(),
			section: section.to_vec(),
		});
	}

	// _parse_options, options without a value
	fn parse_flag(&mut self, key: &[u8], file: &[u8], line: usize) {
		let trace: &[u8] = match key {
			b"UseSyslog" => b"usesyslog",
			b"ILoveCandy" => b"chomp",
			b"VerbosePkgLists" => b"verbosepkglists",
			_ => b"",
		};
		let c = &mut *self.config;
		match key {
			b"UseSyslog" => c.usesyslog = 1,
			b"ILoveCandy" => c.chomp = 1,
			b"VerbosePkgLists" => c.verbosepkglists = 1,
			b"CheckSpace" => c.checkspace = 1,
			b"Color" => {
				if c.color == PM_COLOR_UNSET {
					c.color = if self.host.stdout_is_tty() {
						PM_COLOR_ON
					} else {
						PM_COLOR_OFF
					};
					c.enable_colors(c.color);
				}
			}
			b"NoProgressBar" => c.noprogressbar = 1,
			b"DisableDownloadTimeout" => c.disable_dl_timeout = 1,
			b"DisableSandbox" => {
				c.disable_sandbox_filesystem = 1;
				c.disable_sandbox_syscalls = 1;
			}
			b"DisableSandboxFilesystem" => {
				c.disable_sandbox_filesystem = 1
			}
			b"DisableSandboxSyscalls" => {
				c.disable_sandbox_syscalls = 1
			}
			_ => self.unknown(key, b"options", file, line),
		}
		if !trace.is_empty() {
			self.debug(&[b"config: ", trace, b"\n"]);
		}
	}

	// _parse_options
	fn parse_options(
		&mut self,
		key: &[u8],
		value: Option<&[u8]>,
		file: &[u8],
		line: usize,
	) -> Step {
		let Some(value) = value else {
			self.parse_flag(key, file, line);
			return Ok(());
		};
		let name = std::str::from_utf8(key).unwrap_or("");
		match key {
			b"NoUpgrade" | b"NoExtract" | b"IgnorePkg"
			| b"IgnoreGroup" | b"HoldPkg" | b"CacheDir"
			| b"HookDir" => {
				let words = self.words(value, name);
				let c = &mut *self.config;
				let list = match key {
					b"NoUpgrade" => &mut c.noupgrade,
					b"NoExtract" => &mut c.noextract,
					b"IgnorePkg" => &mut c.ignorepkg,
					b"IgnoreGroup" => &mut c.ignoregrp,
					b"HoldPkg" => &mut c.holdpkg,
					b"CacheDir" => &mut c.cachedirs,
					_ => &mut c.hookdirs,
				};
				list.extend(words);
			}
			b"Architecture" => {
				for arch in self.words(value, name) {
					self.config.add_architecture(
						&arch, self.host,
					);
				}
			}
			b"DBPath" | b"RootDir" | b"GPGDir" => {
				self.set_path(key, value)?
			}
			b"LogFile" => {
				if self.config.logfile.is_none() {
					self.config.logfile =
						Some(value.to_vec());
					self.debug(&[
						b"config: logfile: ",
						value,
						b"\n",
					]);
				}
			}
			b"DownloadUser" => {
				if self.config.sandboxuser.is_none() {
					self.config.sandboxuser =
						Some(value.to_vec());
					let v = value;
					self.debug(&[
						b"config: sandboxuser: ",
						v,
						b"\n",
					]);
				}
			}
			b"XferCommand" => {
				self.set_xfercommand(value, file, line)?
			}
			b"CleanMethod" => {
				let words = self.words(value, name);
				self.process_cleanmethods(&words, file, line)?
			}
			b"SigLevel"
			| b"LocalFileSigLevel"
			| b"RemoteFileSigLevel" => {
				let words = self.words(value, name);
				let (l, m) = siglevel_slot(self.config, key);
				let (l, m) = (*l, *m);
				let (l, m) = self.process_siglevel(
					&words, l, m, file, line,
				)?;
				let (level, mask) =
					siglevel_slot(self.config, key);
				(*level, *mask) = (l, m);
			}
			b"ParallelDownloads" => {
				let n = self.parallel_downloads(
					value, file, line,
				)?;
				self.config.parallel_downloads = n;
			}
			_ => self.unknown(key, b"options", file, line),
		}
		Ok(())
	}

	// DBPath, RootDir, GPGDir: realpath'd, a value already set (command
	// line) wins
	fn set_path(&mut self, key: &[u8], value: &[u8]) -> Step {
		let (option, label): (&'static str, &[u8]) = match key {
			b"DBPath" => ("DBPath", b"dbpath"),
			b"RootDir" => ("RootDir", b"rootdir"),
			_ => ("GPGDir", b"gpgdir"),
		};
		let slot = match key {
			b"DBPath" => &self.config.dbpath,
			b"RootDir" => &self.config.rootdir,
			_ => &self.config.gpgdir,
		};
		if slot.is_some() {
			return Ok(());
		}
		// std canonicalize is realpath(3)
		let path = match fs::canonicalize(OsStr::from_bytes(value)) {
			Ok(p) => p.into_os_string().into_vec(),
			Err(e) => {
				return Err(self.log(Msg::ResolvePath {
					path: value.to_vec(),
					option,
					err: e.raw_os_error().unwrap_or(0),
				}));
			}
		};
		let c = &mut *self.config;
		let slot = match key {
			b"DBPath" => &mut c.dbpath,
			b"RootDir" => &mut c.rootdir,
			_ => &mut c.gpgdir,
		};
		*slot = Some(path.clone());
		self.debug(&[b"config: ", label, b": ", &path, b"\n"]);
		Ok(())
	}

	// XferCommand: a wordsplit failure drops the argv, keeps command and argc
	// but keeps the previous command string and argc
	fn set_xfercommand(
		&mut self,
		value: &[u8],
		file: &[u8],
		line: usize,
	) -> Step {
		let c = &mut *self.config;
		c.xfercommand_argv = wordsplit(value);
		let Some(argv) = &c.xfercommand_argv else {
			return Err(self.log(Msg::InvalidValue {
				file: file.to_vec(),
				line,
				option: "XferCommand",
				value: value.to_vec(),
			}));
		};
		c.xfercommand_argc = argv.len();
		c.xfercommand = Some(value.to_vec());
		self.debug(&[b"config: xfercommand: ", value, b"\n"]);
		Ok(())
	}

	// process_cleanmethods: words before a bad one are kept
	fn process_cleanmethods(
		&mut self,
		words: &[Vec<u8>],
		file: &[u8],
		line: usize,
	) -> Step {
		for m in words {
			self.config.cleanmethod |= match m.as_slice() {
				b"KeepInstalled" => PM_CLEAN_KEEPINST,
				b"KeepCurrent" => PM_CLEAN_KEEPCUR,
				_ => {
					return Err(self.log(
						Msg::InvalidValue {
							file: file.to_vec(),
							line,
							option: "CleanMethod",
							value: m.clone(),
						},
					));
				}
			};
		}
		Ok(())
	}

	fn parallel_downloads(
		&mut self,
		value: &[u8],
		file: &[u8],
		line: usize,
	) -> Result<u32, Msg> {
		let (file, v) = (file.to_vec(), value.to_vec());
		let msg = match parse_number(value) {
			None => Msg::InvalidValue {
				file,
				line,
				option: "ParallelDownloads",
				value: v,
			},
			Some(n) if n < 1 => Msg::NotPositive {
				file,
				line,
				value: v,
			},
			Some(n) => match u32::try_from(n) {
				Ok(n) if n <= i32::MAX as u32 => return Ok(n),
				_ => Msg::TooLarge {
					file,
					line,
					value: v,
				},
			},
		};
		Err(self.log(msg))
	}

	// process_siglevel: every word is checked, any error leaves the
	// stored level untouched
	fn process_siglevel(
		&mut self,
		words: &[Vec<u8>],
		mut level: i32,
		mut mask: i32,
		file: &[u8],
		line: usize,
	) -> Result<(i32, i32), Msg> {
		let mut err = None;
		// SLSET, SLUNSET
		let set =
			|level: &mut i32, mask: &mut i32, sl: i32, on: bool| {
				if on {
					*level |= sl;
				} else {
					*level &= !sl;
				}
				*mask |= sl;
			};
		for original in words {
			let (value, package, database) = if let Some(v) =
				original.strip_prefix(b"Package")
			{
				(v, true, false)
			} else if let Some(v) =
				original.strip_prefix(b"Database")
			{
				(v, false, true)
			} else {
				(original.as_slice(), true, true)
			};
			let steps = sig_steps(value).unwrap_or_else(|| {
				err = Some(self.log(Msg::InvalidValue {
					file: file.to_vec(),
					line,
					option: "SigLevel",
					value: original.clone(),
				}));
				&[]
			});
			// the C sets package bits fully before database bits
			if package {
				for &(p, _, on) in steps {
					set(&mut level, &mut mask, p, on);
				}
			}
			if database {
				for &(_, db, on) in steps {
					set(&mut level, &mut mask, db, on);
				}
			}
			level &= !SIG_USE_DEFAULT;
		}

		if !HAVE_SIGNATURES && level & (SIG_PACKAGE | SIG_DATABASE) != 0
		{
			let file = file.to_vec();
			err = Some(self
				.log(Msg::NoSignatureSupport { file, line }));
		}
		match err {
			Some(msg) => Err(msg),
			None => Ok((level, mask)),
		}
	}

	// _parse_repo
	fn parse_repo(
		&mut self,
		i: usize,
		key: &[u8],
		value: Option<&[u8]>,
		file: &[u8],
		line: usize,
	) -> Step {
		let known = matches!(
			key,
			b"CacheServer" | b"Server" | b"SigLevel" | b"Usage"
		);
		if !known {
			let name = self.config.repos[i].name.clone();
			self.unknown(key, &name, file, line);
			return Ok(());
		}
		let Some(value) = value else {
			let (file, key) = (file.to_vec(), key.to_vec());
			return Err(self.log(Msg::NeedsValue {
				file,
				line,
				key,
			}));
		};
		match key {
			b"CacheServer" => self.config.repos[i]
				.cache_servers
				.push(value.to_vec()),
			b"Server" => self.config.repos[i]
				.servers
				.push(value.to_vec()),
			b"SigLevel" => {
				let words = self.words(value, "SigLevel");
				if !words.is_empty() {
					let r = &self.config.repos[i];
					let (l, m) =
						(r.siglevel, r.siglevel_mask);
					let (l, m) = self.process_siglevel(
						&words, l, m, file, line,
					)?;
					let r = &mut self.config.repos[i];
					(r.siglevel, r.siglevel_mask) = (l, m);
				}
			}
			_ => {
				let words = self.words(value, "Usage");
				self.process_usage(i, &words, file, line)?;
			}
		}
		Ok(())
	}

	// process_usage: the known words are kept even when one fails
	fn process_usage(
		&mut self,
		i: usize,
		words: &[Vec<u8>],
		file: &[u8],
		line: usize,
	) -> Step {
		let mut err = None;
		for w in words {
			let bit =
				match w.as_slice() {
					b"Sync" => DB_USAGE_SYNC,
					b"Search" => DB_USAGE_SEARCH,
					b"Install" => DB_USAGE_INSTALL,
					b"Upgrade" => DB_USAGE_UPGRADE,
					b"All" => DB_USAGE_ALL,
					_ => {
						err = Some(self.log(Msg::UsageNotRecognized {
						file: file.to_vec(),
						line,
						value: w.clone(),
					}));
						0
					}
				};
			self.config.repos[i].usage |= bit;
		}
		match err {
			Some(msg) => Err(msg),
			None => Ok(()),
		}
	}
}

// glob(3) as conf.c calls it: GLOB_NOCHECK, no errfunc, glibc semantics.
// backslash escapes, '*' '?' '[' per path component through fnmatch,
// leading '.' only matched explicitly (FNM_PERIOD), "." and ".." listed,
// unreadable directories skipped, a trailing '/' keeps directories only
// and marks them. results sorted bytewise: glibc sorts with strcoll, so
// this is the C/C.UTF-8 locale order. no match returns the pattern as is
pub fn glob(pattern: &[u8]) -> Vec<Vec<u8>> {
	glob_flags(
		pattern,
		Flags {
			nocheck: true,
			mark: false,
			onlydir: false,
			sort: true,
		},
	)
}

#[derive(Clone, Copy)]
struct Flags {
	nocheck: bool,
	mark: bool,
	onlydir: bool,
	sort: bool,
}

// __glob_pattern_type bits
const PAT_SPECIAL: u8 = 1;
const PAT_BACKSLASH: u8 = 2;
const PAT_BRACKET: u8 = 4;

fn pattern_type(p: &[u8]) -> u8 {
	let mut ret = 0;
	let mut i = 0;
	while i < p.len() {
		match p[i] {
			b'?' | b'*' => return PAT_SPECIAL,
			b'\\' => {
				if i + 1 < p.len() {
					i += 1;
				}
				ret |= PAT_BACKSLASH;
			}
			b'[' => ret |= PAT_BRACKET,
			b']' if ret & PAT_BRACKET != 0 => return PAT_SPECIAL,
			_ => {}
		}
		i += 1;
	}
	ret
}

// drops a final backslash that is not itself escaped
fn strip_trailing_backslash(d: &[u8]) -> &[u8] {
	let n = d.iter().rev().take_while(|&&c| c == b'\\').count();
	if n % 2 == 1 { &d[..d.len() - 1] } else { d }
}

fn unescape(d: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(d.len());
	let mut it = d.iter();
	while let Some(&c) = it.next() {
		match c {
			// a lone final backslash is dropped
			b'\\' => out.extend(it.next()),
			_ => out.push(c),
		}
	}
	out
}

fn os(p: &[u8]) -> &Path {
	Path::new(OsStr::from_bytes(p))
}

fn is_dir(p: &[u8]) -> bool {
	fs::metadata(os(p)).is_ok_and(|m| m.is_dir())
}

// "/" + name stays "/name"
fn prefix(dir: &[u8], name: &[u8]) -> Vec<u8> {
	let dir: &[u8] = if dir == b"/" { b"" } else { dir };
	cat(&[dir, b"/", name])
}

fn glob_flags(pattern: &[u8], f: Flags) -> Vec<Vec<u8>> {
	let slash = pattern.iter().rposition(|&c| c == b'/');
	let (dirname, filename, has_dir): (&[u8], &[u8], bool) = match slash {
		None => (b".", pattern, false),
		Some(0) => (b"/", &pattern[1..], true),
		Some(1) if pattern[0] == b'\\' => (b"/", &pattern[2..], true),
		Some(i) => (&pattern[..i], &pattern[i + 1..], true),
	};

	// "pattern/": expand pattern, listed entries directories only, all
	// directories marked
	if slash.is_some_and(|i| i > 1) && filename.is_empty() {
		let d = strip_trailing_backslash(dirname);
		let nocheck = f.nocheck && d.len() == dirname.len();
		let out = glob_flags(
			d,
			Flags {
				nocheck,
				mark: true,
				onlydir: true,
				sort: f.sort,
			},
		);
		if out.is_empty() && f.nocheck {
			return vec![pattern.to_vec()];
		}
		return out;
	}

	let meta = pattern_type(dirname);
	let mut out = Vec::new();
	if meta & (PAT_SPECIAL | PAT_BRACKET) != 0 {
		let dirname = strip_trailing_backslash(dirname);
		let dirs = glob_flags(
			dirname,
			Flags {
				nocheck: false,
				mark: false,
				onlydir: true,
				sort: false,
			},
		);
		for d in &dirs {
			let names = glob_in_dir(filename, d, f.onlydir, false);
			out.extend(names.iter().map(|n| prefix(d, n)));
		}
		if out.is_empty() {
			return if f.nocheck {
				vec![pattern.to_vec()]
			} else {
				out
			};
		}
	} else {
		let modified = meta & PAT_BACKSLASH != 0;
		let dir = if modified {
			unescape(dirname)
		} else {
			dirname.to_vec()
		};
		let names = glob_in_dir(
			filename,
			&dir,
			f.onlydir,
			f.nocheck && !modified,
		);
		if names.is_empty() {
			return if f.nocheck && modified {
				vec![pattern.to_vec()]
			} else {
				names
			};
		}
		if has_dir {
			out.extend(names.iter().map(|n| prefix(&dir, n)));
		} else {
			out = names;
		}
	}

	if f.mark {
		for p in &mut out {
			if is_dir(p) {
				p.push(b'/');
			}
		}
	}
	if f.sort {
		out.sort();
	}
	out
}

// fnmatch(pattern, name, FNM_PERIOD): a leading '.' needs a literal one
fn fnmatch_period(pattern: &[u8], name: &[u8]) -> bool {
	if name.first() == Some(&b'.')
		&& !(pattern.starts_with(b".") || pattern.starts_with(b"\\."))
	{
		return false;
	}
	fnmatch(pattern, name)
}

// glob_in_dir: names (not paths) in dir matching pattern
fn glob_in_dir(
	pattern: &[u8],
	dir: &[u8],
	onlydir: bool,
	nocheck: bool,
) -> Vec<Vec<u8>> {
	let meta = pattern_type(pattern);
	if meta == 0 {
		// no test needed with nocheck, else it has to exist
		let full = cat(&[dir, b"/", pattern]);
		if nocheck || fs::symlink_metadata(os(&full)).is_ok() {
			return vec![pattern.to_vec()];
		}
		return Vec::new();
	}

	let mut names = Vec::new();
	if let Ok(rd) = fs::read_dir(os(dir)) {
		// readdir gives "." and "..", read_dir does not
		let dots = [&b"."[..], b".."].map(|n| (n.to_vec(), true));
		let entries = rd.map_while(Result::ok).map(|e| {
			let name = e.file_name().into_vec();
			let dir_like = !onlydir
				|| match e.file_type() {
					Ok(t) if t.is_dir() => true,
					Ok(t) if !t.is_symlink() => false,
					_ => is_dir(&prefix(dir, &name)),
				};
			(name, dir_like)
		});
		for (name, dir_like) in dots.into_iter().chain(entries) {
			if dir_like && fnmatch_period(pattern, &name) {
				names.push(name);
			}
		}
	}
	if names.is_empty() && nocheck {
		names.push(pattern.to_vec());
	}
	names
}

// ---- XferCommand ----
//
// download_with_xfercommand, the fetchcb setup_libalpm registers when
// XferCommand is set: %u and %o (whole arguments only) replaced by the
// url and "<localpath><file>.part", the command run in localpath (the
// process cwd changed and put back like the C), a %o download renamed
// to its name after exit status 0. 0 downloaded, -1 failed (never 1);
// failures wait 2 s for the user to cancel. systemvp runs argv itself,
// or with a sandbox user through the sandbox helper's exec mode
// (alpm_sandbox_setup_child in the C child). SIGINT/SIGQUIT are ignored
// meanwhile (sandbox::IgnoreSignals, read by sighandler.rs).
// messages go out through pm_printf with the config as it was given
pub struct XferCommand {
	config: Config,
	out: Output,
	pub exec: SandboxExec,
	pub sleep: fn(Duration),
}

impl XferCommand {
	// the fetchcb of config, printing to an Output flushed to sink
	pub fn new(config: &Config, sink: Option<fn(&mut Output)>) -> Self {
		let mut exec = SandboxExec::default();
		if let Some(env) = user_agent_env(config) {
			exec.env.push(env);
		}
		XferCommand {
			config: config.clone(),
			out: Output {
				sink,
				..Output::default()
			},
			exec,
			sleep: std::thread::sleep,
		}
	}

	// pm_printf to stderr, unbuffered like the C's
	fn print(&mut self, level: u16, msg: &[u8]) {
		pm_printf(&mut self.out.stderr, &self.config, level, msg);
		self.out.flush();
	}

	// systemvp: the wait status, -1 when the command could not be
	// started. a failed sandbox setup is the C child's error and
	// _Exit(-1)
	fn systemvp(&mut self, argv: &[Vec<u8>]) -> i32 {
		let Some(file) = argv.first() else {
			return -1;
		};
		// SIGINT/SIGQUIT ignored until the command is reaped
		let _quiet = IgnoreSignals::new();
		let r = match self.config.sandboxuser.clone() {
			Some(user) => self.exec.run(&user, argv),
			None => Command::new(OsStr::from_bytes(file))
				.args(argv[1..]
					.iter()
					.map(|a| OsStr::from_bytes(a)))
				.envs(user_agent_env(&self.config))
				.status()
				.map_err(ExecError::Spawn),
		};
		match r {
			Ok(status) => status.into_raw(),
			Err(ExecError::Spawn(_)) => -1,
			Err(ExecError::Setup) => {
				let user = self.config.sandboxuser.clone();
				let msg = cat(&[
					b"switching to sandbox user '",
					&user.unwrap_or_default(),
					b"' failed!\n",
				]);
				self.print(LOG_ERROR, &msg);
				0xff << 8
			}
		}
	}

	// download_with_xfercommand up to its cleanup's sleep
	fn download(
		&mut self,
		url: &[u8],
		localpath: &[u8],
		force: bool,
	) -> c_int {
		let Some(template) = self.config.xfercommand_argv.clone()
		else {
			return -1;
		};
		let (url, localpath) = (until_nul(url), until_nul(localpath));
		let Some(slash) = url.iter().rposition(|&c| c == b'/') else {
			return -1;
		};
		let filename = &url[slash + 1..];
		let destfile = cat(&[localpath, filename]);
		let tempfile = cat(&[localpath, filename, b".part"]);
		if force {
			for f in [&tempfile, &destfile] {
				if fs::metadata(OsStr::from_bytes(f)).is_ok() {
					let _ = fs::remove_file(
						OsStr::from_bytes(f),
					);
				}
			}
		}
		let mut usepart = false;
		let argv: Vec<Vec<u8>> = template
			.iter()
			.map(|a| match &a[..] {
				b"%o" => {
					usepart = true;
					tempfile.clone()
				}
				b"%u" => url.to_vec(),
				_ => a.clone(),
			})
			.collect();
		// open(".", O_RDONLY) to come back to
		let cwd = fs::File::open(".");
		if cwd.is_err() {
			let msg = b"could not get current working directory\n";
			self.print(LOG_ERROR, msg);
		}
		let ret = self.run_in(
			&argv, localpath, usepart, &tempfile, &destfile,
		);
		if let Ok(cwd) = cwd
			&& let Err(e) = rustix::process::fchdir(&cwd)
		{
			let e = strerror(&e.into());
			let msg = cat(&[
				b"could not restore working directory (",
				&e,
				b")\n",
			]);
			self.print(LOG_ERROR, &msg);
		}
		ret
	}

	// chdir(localpath), the command, the .part rename
	fn run_in(
		&mut self,
		argv: &[Vec<u8>],
		localpath: &[u8],
		usepart: bool,
		tempfile: &[u8],
		destfile: &[u8],
	) -> c_int {
		if std::env::set_current_dir(OsStr::from_bytes(localpath))
			.is_err()
		{
			let msg = cat(&[
				b"could not chdir to download directory ",
				localpath,
				b"\n",
			]);
			self.print(LOG_WARNING, &msg);
			return -1;
		}
		if self.config.logmask & LOG_DEBUG != 0
			&& let Some(cmd) = arg_to_string(argv)
		{
			let msg = cat(&[b"running command: ", &cmd, b"\n"]);
			self.print(LOG_DEBUG, &msg);
		}
		let retval = self.systemvp(argv);
		if retval == -1 {
			let msg = b"running XferCommand: fork failed!\n";
			self.print(LOG_WARNING, msg);
			return -1;
		}
		if retval != 0 {
			let msg = format!(
				"XferCommand command returned non-zero status code \
				({retval})\n"
			);
			self.print(LOG_DEBUG, msg.as_bytes());
			return -1;
		}
		if usepart
			&& let Err(e) = fs::rename(
				OsStr::from_bytes(tempfile),
				OsStr::from_bytes(destfile),
			) {
			let msg = cat(&[
				b"could not rename ",
				tempfile,
				b" to ",
				destfile,
				b" (",
				&strerror(&e),
				b")\n",
			]);
			self.print(LOG_ERROR, &msg);
			return -1;
		}
		0
	}
}

// the HTTP_USER_AGENT the command inherits from the C's environment
fn user_agent_env(config: &Config) -> Option<(OsString, OsString)> {
	if config.user_agent.is_empty() {
		return None;
	}
	let agent = OsString::from_vec(config.user_agent.clone());
	Some((OsString::from("HTTP_USER_AGENT"), agent))
}

impl Fetch for XferCommand {
	fn fetch(
		&mut self,
		url: &[u8],
		localpath: &[u8],
		force: bool,
	) -> c_int {
		// the early returns before its cleanup do not wait
		let early = self.config.xfercommand_argv.is_none()
			|| !until_nul(url).contains(&b'/');
		let ret = self.download(url, localpath, force);
		if ret == -1 && !early {
			// hack to let an user the time to cancel a download
			(self.sleep)(Duration::from_secs(2));
		}
		ret
	}
}

impl Config {
	// the fetchcb for this config: XferCommand when set (the C tests
	// the string; a failed wordsplit leaves no argv, every fetch fails)
	pub fn xfercommand_fetch(
		&self,
		sink: Option<fn(&mut Output)>,
	) -> Option<Box<dyn Fetch>> {
		self.xfercommand.as_ref()?;
		Some(Box::new(XferCommand::new(self, sink)))
	}
}
