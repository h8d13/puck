// port of src/pacman/pacman.c: command line parsing, usage, version and
// main
//
// the C fills the global `config` and the static pm_targets list and
// exits through cleanup() on --help, --version and conflicting options.
// here parseargs fills a `Config`, returns the targets, and Err carries
// the exit status instead (0 after --help/--version). stdout and stderr
// of parsing are buffered in `Io`, pm_printf goes through it with the
// config as it is at that moment (colstr, logmask). messages are the
// untranslated msgids. `main_args` is main() from parseargs up to
// parseconfig, `run` the whole of main on a util::Term: setup_libalpm,
// the operation, cleanup, the exit status.
//
// operations and the callbacks write into Outputs flushed to one sink
// (the binary's std streams) where the C flushes. the prompts of the
// operations and of the callbacks read stdin through separate readers
// over the one fd, each unbuffered past its line (std_stdin) so neither
// over-reads the other's input.
// signals: the binary installs sighandler's soft interrupt handler, run
// gives it the handle after setup_libalpm and removes it in cleanup,
// before the handle is released like the C.
use std::ffi::OsStr;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use alpm_core::Handle;
use alpm_core::strerror;
use alpm_core::{LIB_VERSION, PACKAGE_VERSION};
use pacman_common::util_common::{PATH_MAX, mbasename, until_nul};

use crate::callback::Frontend;
use crate::conf::{
	ConfError, Config, Host, LOG_DEBUG, LOG_ERROR, LOG_FUNCTION,
	LOG_WARNING, Msg, PM_COLOR_OFF, PM_COLOR_ON, PM_OP_MAIN, format_msg,
};
use crate::database::pacman_database;
use crate::deptest::pacman_deptest;
use crate::files::pacman_files;
use crate::getopt::{Getopt, HasArg, LongOpt};
use crate::package::format_date;
use crate::query::{QueryEnv, pacman_query};
use crate::remove::pacman_remove;
use crate::sighandler::{remove_soft_interrupt_handler, set_handle};
use crate::sync::{Deferred, pacman_sync, sync_clean, sync_trans};
use crate::upgrade::pacman_upgrade;
use crate::util::{
	Output, Term, Ui, arg_to_string, console_cursor_hide,
	console_cursor_show, debug_stamp, flush_term_input, getcols,
	list_display, needs_root, now_secs, pm_printf,
};

// conf.h operations, PM_OP_MAIN in conf
pub const PM_OP_REMOVE: u16 = 2;
pub const PM_OP_UPGRADE: u16 = 3;
pub const PM_OP_QUERY: u16 = 4;
pub const PM_OP_SYNC: u16 = 5;
pub const PM_OP_DEPTEST: u16 = 6;
pub const PM_OP_DATABASE: u16 = 7;
pub const PM_OP_FILES: u16 = 8;

pub const PKG_LOCALITY_NATIVE: u16 = 1;
pub const PKG_LOCALITY_FOREIGN: u16 = 1 << 1;

// alpm.h alpm_transflag_t, as stored in config->flags
use alpm_core::{
	TRANS_FLAG_ALLDEPS, TRANS_FLAG_ALLEXPLICIT, TRANS_FLAG_CASCADE,
	TRANS_FLAG_DBONLY, TRANS_FLAG_DOWNLOADONLY, TRANS_FLAG_NEEDED,
	TRANS_FLAG_NOCONFLICTS, TRANS_FLAG_NODEPS, TRANS_FLAG_NODEPVERSION,
	TRANS_FLAG_NOHOOKS, TRANS_FLAG_NOLOCK, TRANS_FLAG_NOSAVE,
	TRANS_FLAG_NOSCRIPTLET, TRANS_FLAG_RECURSE, TRANS_FLAG_RECURSEALL,
	TRANS_FLAG_UNNEEDED,
};

// conf.h long option codes, getopt returns them for the long names
pub const OP_LONG_FLAG_MIN: i32 = 1000;
pub const OP_NOCONFIRM: i32 = 1001;
pub const OP_CONFIRM: i32 = 1002;
pub const OP_CONFIG: i32 = 1003;
pub const OP_IGNORE: i32 = 1004;
pub const OP_DEBUG: i32 = 1005;
pub const OP_NOPROGRESSBAR: i32 = 1006;
pub const OP_NOSCRIPTLET: i32 = 1007;
pub const OP_ASK: i32 = 1008;
pub const OP_CACHEDIR: i32 = 1009;
pub const OP_HOOKDIR: i32 = 1010;
pub const OP_ASDEPS: i32 = 1011;
pub const OP_LOGFILE: i32 = 1012;
pub const OP_IGNOREGROUP: i32 = 1013;
pub const OP_NEEDED: i32 = 1014;
pub const OP_ASEXPLICIT: i32 = 1015;
pub const OP_ARCH: i32 = 1016;
pub const OP_PRINTFORMAT: i32 = 1017;
pub const OP_GPGDIR: i32 = 1018;
pub const OP_DBONLY: i32 = 1019;
pub const OP_FORCE: i32 = 1020;
pub const OP_OVERWRITE_FILES: i32 = 1021;
pub const OP_COLOR: i32 = 1022;
pub const OP_DBPATH: i32 = 1023;
pub const OP_CASCADE: i32 = 1024;
pub const OP_CHANGELOG: i32 = 1025;
pub const OP_CLEAN: i32 = 1026;
pub const OP_NODEPS: i32 = 1027;
pub const OP_DEPS: i32 = 1028;
pub const OP_EXPLICIT: i32 = 1029;
pub const OP_GROUPS: i32 = 1030;
pub const OP_HELP: i32 = 1031;
pub const OP_INFO: i32 = 1032;
pub const OP_CHECK: i32 = 1033;
pub const OP_LIST: i32 = 1034;
pub const OP_FOREIGN: i32 = 1035;
pub const OP_NATIVE: i32 = 1036;
pub const OP_NOSAVE: i32 = 1037;
pub const OP_OWNS: i32 = 1038;
pub const OP_FILE: i32 = 1039;
pub const OP_PRINT: i32 = 1040;
pub const OP_QUIET: i32 = 1041;
pub const OP_ROOT: i32 = 1042;
pub const OP_SYSROOT: i32 = 1043;
pub const OP_RECURSIVE: i32 = 1044;
pub const OP_SEARCH: i32 = 1045;
pub const OP_REGEX: i32 = 1046;
pub const OP_MACHINEREADABLE: i32 = 1047;
pub const OP_UNREQUIRED: i32 = 1048;
pub const OP_UPGRADES: i32 = 1049;
pub const OP_SYSUPGRADE: i32 = 1050;
pub const OP_UNNEEDED: i32 = 1051;
pub const OP_VERBOSE: i32 = 1052;
pub const OP_DOWNLOADONLY: i32 = 1053;
pub const OP_REFRESH: i32 = 1054;
pub const OP_ASSUMEINSTALLED: i32 = 1055;
pub const OP_DISABLEDLTIMEOUT: i32 = 1056;
pub const OP_DISABLESANDBOX: i32 = 1057;
pub const OP_DISABLESANDBOXFILESYSTEM: i32 = 1058;
pub const OP_DISABLESANDBOXSYSCALLS: i32 = 1059;

pub const OPTSTRING: &[u8] = b"DFQRSTUVb:cdefghiklmnopqr:stuvwxy";

const fn opt(name: &'static [u8], has_arg: HasArg, val: i32) -> LongOpt {
	LongOpt { name, has_arg, val }
}

const NO: HasArg = HasArg::No;
const REQ: HasArg = HasArg::Required;

// parseargs opts[], in table order: abbreviations and the ambiguity
// lists depend on it
pub const LONGOPTS: &[LongOpt] = &[
	opt(b"database", NO, b'D' as i32),
	opt(b"files", NO, b'F' as i32),
	opt(b"query", NO, b'Q' as i32),
	opt(b"remove", NO, b'R' as i32),
	opt(b"sync", NO, b'S' as i32),
	opt(b"deptest", NO, b'T' as i32),
	opt(b"upgrade", NO, b'U' as i32),
	opt(b"version", NO, b'V' as i32),
	opt(b"help", NO, b'h' as i32),
	opt(b"dbpath", REQ, OP_DBPATH),
	opt(b"cascade", NO, OP_CASCADE),
	opt(b"changelog", NO, OP_CHANGELOG),
	opt(b"clean", NO, OP_CLEAN),
	opt(b"nodeps", NO, OP_NODEPS),
	opt(b"deps", NO, OP_DEPS),
	opt(b"explicit", NO, OP_EXPLICIT),
	opt(b"groups", NO, OP_GROUPS),
	opt(b"info", NO, OP_INFO),
	opt(b"check", NO, OP_CHECK),
	opt(b"list", NO, OP_LIST),
	opt(b"foreign", NO, OP_FOREIGN),
	opt(b"native", NO, OP_NATIVE),
	opt(b"nosave", NO, OP_NOSAVE),
	opt(b"owns", NO, OP_OWNS),
	opt(b"file", NO, OP_FILE),
	opt(b"print", NO, OP_PRINT),
	opt(b"quiet", NO, OP_QUIET),
	opt(b"root", REQ, OP_ROOT),
	opt(b"sysroot", REQ, OP_SYSROOT),
	opt(b"recursive", NO, OP_RECURSIVE),
	opt(b"search", NO, OP_SEARCH),
	opt(b"regex", NO, OP_REGEX),
	opt(b"machinereadable", NO, OP_MACHINEREADABLE),
	opt(b"unrequired", NO, OP_UNREQUIRED),
	opt(b"upgrades", NO, OP_UPGRADES),
	opt(b"sysupgrade", NO, OP_SYSUPGRADE),
	opt(b"unneeded", NO, OP_UNNEEDED),
	opt(b"verbose", NO, OP_VERBOSE),
	opt(b"downloadonly", NO, OP_DOWNLOADONLY),
	opt(b"refresh", NO, OP_REFRESH),
	opt(b"noconfirm", NO, OP_NOCONFIRM),
	opt(b"confirm", NO, OP_CONFIRM),
	opt(b"config", REQ, OP_CONFIG),
	opt(b"ignore", REQ, OP_IGNORE),
	opt(b"assume-installed", REQ, OP_ASSUMEINSTALLED),
	opt(b"debug", HasArg::Optional, OP_DEBUG),
	opt(b"force", NO, OP_FORCE),
	opt(b"overwrite", REQ, OP_OVERWRITE_FILES),
	opt(b"noprogressbar", NO, OP_NOPROGRESSBAR),
	opt(b"noscriptlet", NO, OP_NOSCRIPTLET),
	opt(b"ask", REQ, OP_ASK),
	opt(b"cachedir", REQ, OP_CACHEDIR),
	opt(b"hookdir", REQ, OP_HOOKDIR),
	opt(b"asdeps", NO, OP_ASDEPS),
	opt(b"logfile", REQ, OP_LOGFILE),
	opt(b"ignoregroup", REQ, OP_IGNOREGROUP),
	opt(b"needed", NO, OP_NEEDED),
	opt(b"asexplicit", NO, OP_ASEXPLICIT),
	opt(b"arch", REQ, OP_ARCH),
	opt(b"print-format", REQ, OP_PRINTFORMAT),
	opt(b"gpgdir", REQ, OP_GPGDIR),
	opt(b"dbonly", NO, OP_DBONLY),
	opt(b"color", REQ, OP_COLOR),
	opt(b"disable-download-timeout", NO, OP_DISABLEDLTIMEOUT),
	opt(b"disable-sandbox", NO, OP_DISABLESANDBOX),
	opt(
		b"disable-sandbox-filesystem",
		NO,
		OP_DISABLESANDBOXFILESYSTEM,
	),
	opt(b"disable-sandbox-syscalls", NO, OP_DISABLESANDBOXSYSCALLS),
];

// the process side of parsing: buffered stdout/stderr and the probes
// the C makes (isatty(stdout), getenv("POSIXLY_CORRECT") in getopt).
// debug_stamps puts the PACMAN_DEBUG stamp before messages while debug
// logging is on
#[derive(Clone, Debug, Default)]
pub struct Io {
	pub out: Vec<u8>,
	pub err: Vec<u8>,
	pub stdout_tty: bool,
	pub posixly_correct: bool,
	pub debug_stamps: bool,
}

// a pm_printf message with the PACMAN_DEBUG stamp when asked for
fn stamped(
	config: &Config,
	msg: &Msg,
	stamps: bool,
	now: i64,
) -> Option<Vec<u8>> {
	let s = format_msg(config, msg)?;
	let debug = config.logmask & LOG_DEBUG != 0;
	if !stamps || !debug || *msg == Msg::DbUpgradeHint {
		return Some(s);
	}
	Some([debug_stamp(now), s].concat())
}

impl Host for Io {
	fn log(&mut self, config: &Config, msg: &Msg) {
		let stamps = self.debug_stamps;
		if let Some(s) = stamped(config, msg, stamps, now_secs()) {
			self.err.extend_from_slice(&s);
		}
	}

	fn stdout_is_tty(&mut self) -> bool {
		self.stdout_tty
	}
}

// pm_printf(level, ...) for ALPM_LOG_ERROR and ALPM_LOG_WARNING
fn pm_printf_io(config: &Config, io: &mut Io, level: u16, parts: &[&[u8]]) {
	if config.logmask & level == 0 {
		return;
	}
	// pm_vfprintf's PACMAN_DEBUG stamp, --debug may come first
	if io.debug_stamps && config.logmask & LOG_DEBUG != 0 {
		io.err.extend_from_slice(&debug_stamp(now_secs()));
	}
	let c = &config.colstr;
	let (color, prefix): (&[u8], &[u8]) = match level {
		LOG_WARNING => (c.warn, b"warning: "),
		_ => (c.err, b"error: "),
	};
	io.err.extend_from_slice(color);
	io.err.extend_from_slice(prefix);
	io.err.extend_from_slice(c.nocolor);
	for p in parts {
		io.err.extend_from_slice(p);
	}
}

fn pm_error(config: &Config, io: &mut Io, parts: &[&[u8]]) {
	pm_printf_io(config, io, LOG_ERROR, parts);
}

// setuseragent's agent[100]: "pacman/<ver> (<sysname> <machine>)
// libalpm/<ver>" cut by snprintf at 99 bytes, true when it was
pub fn user_agent_string(sysname: &[u8], machine: &[u8]) -> (Vec<u8>, bool) {
	let mut agent = format!("pacman/{PACKAGE_VERSION} (").into_bytes();
	agent.extend_from_slice(until_nul(sysname));
	agent.push(b' ');
	agent.extend_from_slice(until_nul(machine));
	agent.extend_from_slice(format!(") libalpm/{LIB_VERSION}").as_bytes());
	let truncated = agent.len() >= 100;
	agent.truncate(99);
	(agent, truncated)
}

// setuseragent: HTTP_USER_AGENT for the downloader and XferCommand,
// the environment's own when set (setenv without overwrite). the C
// warns through pm_printf before config_new made config, which would
// dereference NULL (UPSTREAM.md); here the fresh config's logmask
// decides
pub fn setuseragent(config: &Config, io: &mut Io) -> Vec<u8> {
	if let Some(env) = std::env::var_os("HTTP_USER_AGENT") {
		return env.into_vec();
	}
	let un = rustix::system::uname();
	let (agent, truncated) = user_agent_string(
		un.sysname().to_bytes(),
		un.machine().to_bytes(),
	);
	if truncated {
		let msg: &[u8] = b"HTTP_USER_AGENT truncated\n";
		pm_printf_io(config, io, LOG_WARNING, &[msg]);
	}
	agent
}

fn is_space(c: u8) -> bool {
	matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

// options_cmp: leading spaces skipped, a short option sorts before a
// long one, then strcmp past the dashes
fn options_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
	let skip = |s: &[u8]| s.iter().take_while(|&&c| is_space(c)).count();
	let mut s1 = &a[skip(a)..];
	let mut s2 = &b[skip(b)..];
	if s1.first() == Some(&b'-') && s2.first() == Some(&b'-') {
		s1 = &s1[1..];
		s2 = &s2[1..];
		let l1 = s1.first() == Some(&b'-');
		let l2 = s2.first() == Some(&b'-');
		match (l1, l2) {
			(true, true) => {
				s1 = &s1[1..];
				s2 = &s2[1..];
			}
			(false, true) => return std::cmp::Ordering::Less,
			(true, false) => return std::cmp::Ordering::Greater,
			(false, false) => {}
		}
	}
	s1.cmp(s2)
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
	parts.concat()
}

// usage(op, myname): the operation's synopsis, then its options sorted
// by options_cmp (alpm_list_msort is stable like sort_by)
pub fn usage(out: &mut Vec<u8>, op: u16, myname: &[u8]) {
	let (file, pkg) = (b"file(s)", b"package(s)");
	let line = |out: &mut Vec<u8>, parts: &[&[u8]]| {
		out.extend_from_slice(&cat(parts));
	};
	if op == PM_OP_MAIN {
		line(out, &[b"usage:  ", myname, b" <operation> [...]\n"]);
		out.extend_from_slice(b"operations:\n");
		let ops: [(&[u8], &[u8]); 9] = [
			(b"{-h --help}", b""),
			(b"{-V --version}", b""),
			(b"{-D --database} <options> <", pkg),
			(b"{-F --files}    [options] [", file),
			(b"{-Q --query}    [options] [", pkg),
			(b"{-R --remove}   [options] <", pkg),
			(b"{-S --sync}     [options] [", pkg),
			(b"{-T --deptest}  [options] [", pkg),
			(b"{-U --upgrade}  [options] <", file),
		];
		for (i, (syn, what)) in ops.iter().enumerate() {
			let end: &[u8] = match i {
				0 | 1 => b"\n",
				2 | 5 | 8 => b">\n",
				_ => b"]\n",
			};
			line(out, &[b"    ", myname, b" ", syn, what, end]);
		}
		line(
			out,
			&[
				b"\nuse '",
				myname,
				b" {-h --help}' with an operation for ",
				b"available options\n",
			],
		);
		return;
	}

	// the synopsis after "usage:  <myname> ", the operation's options
	let (synopsis, own): (&[u8], &[&str]) = match op {
		PM_OP_REMOVE => {
			(b"{-R --remove} [options] <package(s)>", USAGE_REMOVE)
		}
		PM_OP_UPGRADE => {
			(b"{-U --upgrade} [options] <file(s)>", &[NEEDED])
		}
		PM_OP_QUERY => {
			(b"{-Q --query} [options] [package(s)]", USAGE_QUERY)
		}
		PM_OP_SYNC => {
			(b"{-S --sync} [options] [package(s)]", USAGE_SYNC)
		}
		PM_OP_DATABASE => (
			b"{-D --database} <options> <package(s)>",
			USAGE_DATABASE,
		),
		PM_OP_DEPTEST => {
			(b"{-T --deptest} [options] [package(s)]", &[])
		}
		PM_OP_FILES => {
			(b"{-F --files} [options] [file(s)]", USAGE_FILES)
		}
		_ => (b"", &[]),
	};
	if !synopsis.is_empty() {
		line(out, &[b"usage:  ", myname, b" ", synopsis, b"\n"]);
		out.extend_from_slice(b"options:\n");
	}
	let mut list = own.to_vec();
	// the C switch falls through from SYNC/UPGRADE into REMOVE
	if matches!(op, PM_OP_SYNC | PM_OP_UPGRADE) {
		list.extend(USAGE_UPGRADE);
	}
	if matches!(op, PM_OP_SYNC | PM_OP_UPGRADE | PM_OP_REMOVE) {
		list.extend(USAGE_TRANS);
	}
	list.extend(USAGE_COMMON);
	list.sort_by(|a, b| options_cmp(a.as_bytes(), b.as_bytes()));
	for s in list {
		out.extend_from_slice(s.as_bytes());
	}
}

// one usage line per option, the C's addlist() strings
const NEEDED: &str =
	"      --needed         do not reinstall up to date packages\n";

// the continuation indent of two-line entries
macro_rules! more {
	($s:literal) => {
		concat!("\n                       ", $s, "\n")
	};
}

const USAGE_REMOVE: &[&str] = &[
	concat!(
		"  -c, --cascade        remove packages and all packages that ",
		"depend on them\n"
	),
	"  -n, --nosave         remove configuration files\n",
	concat!(
		"  -s, --recursive      remove unnecessary dependencies",
		more!("(-ss includes explicitly installed dependencies)")
	),
	"  -u, --unneeded       remove unneeded packages\n",
];

const USAGE_QUERY: &[&str] = &[
	"  -c, --changelog      view the changelog of a package\n",
	concat!(
		"  -d, --deps           list packages installed as dependencies ",
		"[filter]\n"
	),
	"  -e, --explicit       list packages explicitly installed [filter]\n",
	"  -g, --groups         view all members of a package group\n",
	concat!(
		"  -i, --info           view package information (-ii for backup ",
		"files)\n"
	),
	concat!(
		"  -k, --check          check that package files exist (-kk for ",
		"file properties)\n"
	),
	"  -l, --list           list the files owned by the queried package\n",
	concat!(
		"  -m, --foreign        list installed packages not found in sync ",
		"db(s) [filter]\n"
	),
	concat!(
		"  -n, --native         list installed packages only found in ",
		"sync db(s) [filter]\n"
	),
	"  -o, --owns <file>    query the package that owns <file>\n",
	concat!(
		"  -p, --file <package> query a package file instead of the ",
		"database\n"
	),
	"  -q, --quiet          show less information for query and search\n",
	concat!(
		"  -s, --search <regex> search locally-installed packages for ",
		"matching strings\n"
	),
	concat!(
		"  -t, --unrequired     list packages not (optionally) required ",
		"by any",
		more!("package (-tt to ignore optdepends) [filter]")
	),
	"  -u, --upgrades       list outdated packages [filter]\n",
];

const USAGE_SYNC: &[&str] = &[
	concat!(
		"  -c, --clean          remove old packages from cache directory ",
		"(-cc for all)\n"
	),
	concat!(
		"  -g, --groups         view all members of a package group",
		more!("(-gg to view all groups and members)")
	),
	concat!(
		"  -i, --info           view package information (-ii for ",
		"extended information)\n"
	),
	"  -l, --list <repo>    view a list of packages in a repo\n",
	"  -q, --quiet          show less information for query and search\n",
	concat!(
		"  -s, --search <regex> search remote repositories for matching ",
		"strings\n"
	),
	concat!(
		"  -u, --sysupgrade     upgrade installed packages (-uu enables ",
		"downgrades)\n"
	),
	concat!(
		"  -y, --refresh        download fresh package databases from ",
		"the server",
		more!("(-yy to force a refresh even if up to date)")
	),
	NEEDED,
];

const USAGE_DATABASE: &[&str] = &[
	"      --asdeps         mark packages as non-explicitly installed\n",
	"      --asexplicit     mark packages as explicitly installed\n",
	concat!(
		"  -k, --check          test local database for validity (-kk ",
		"for sync databases)\n"
	),
	"  -q, --quiet          suppress output of success messages\n",
];

const USAGE_FILES: &[&str] = &[
	"  -l, --list           list the files owned by the queried package\n",
	"  -q, --quiet          show less information for query and search\n",
	"  -x, --regex          enable searching using regular expressions\n",
	concat!(
		"  -y, --refresh        download fresh package databases from ",
		"the server",
		more!("(-yy to force a refresh even if up to date)")
	),
	concat!(
		"      --machinereadable",
		more!("produce machine-readable output")
	),
];

const USAGE_UPGRADE: &[&str] = &[
	concat!(
		"  -w, --downloadonly   download packages but do not ",
		"install/upgrade anything\n"
	),
	concat!(
		"      --overwrite <glob>",
		more!(
			"overwrite conflicting files (can be used more than once)"
		)
	),
	concat!(
		"      --asdeps         install packages as non-explicitly ",
		"installed\n"
	),
	"      --asexplicit     install packages as explicitly installed\n",
	concat!(
		"      --ignore <pkg>   ignore a package upgrade (can be used ",
		"more than once)\n"
	),
	concat!(
		"      --ignoregroup <grp>",
		more!("ignore a group upgrade (can be used more than once)")
	),
];

const USAGE_TRANS: &[&str] = &[
	concat!(
		"  -d, --nodeps         skip dependency version checks (-dd to ",
		"skip all checks)\n"
	),
	concat!(
		"      --assume-installed <package=version>",
		more!("add a virtual package to satisfy dependencies")
	),
	concat!(
		"      --dbonly         only modify database entries, not ",
		"package files\n"
	),
	concat!(
		"      --noprogressbar  do not show a progress bar when ",
		"downloading files\n"
	),
	concat!(
		"      --noscriptlet    do not execute the install scriptlet if ",
		"one exists\n"
	),
	concat!(
		"  -p, --print          print the targets instead of performing ",
		"the operation\n"
	),
	concat!(
		"      --print-format <string>",
		more!("specify how the targets should be printed")
	),
];

const USAGE_COMMON: &[&str] = &[
	"  -b, --dbpath <path>  set an alternate database location\n",
	"  -r, --root <path>    set an alternate installation root\n",
	"  -v, --verbose        be verbose\n",
	"      --arch <arch>    set an alternate architecture\n",
	concat!(
		"      --sysroot        operate on a mounted guest system ",
		"(root-only)\n"
	),
	"      --cachedir <dir> set an alternate package cache location\n",
	"      --hookdir <dir>  set an alternate hook location\n",
	"      --color <when>   colorize the output\n",
	"      --config <path>  set an alternate configuration file\n",
	"      --debug          display debug messages\n",
	"      --gpgdir <path>  set an alternate home directory for GnuPG\n",
	"      --logfile <path> set an alternate log file\n",
	"      --noconfirm      do not ask for any confirmation\n",
	"      --confirm        always ask for confirmation\n",
	concat!(
		"      --disable-download-timeout",
		more!("use relaxed timeouts for download")
	),
	concat!(
		"      --disable-sandbox",
		more!(
			"disables all sandbox features used for the downloader process"
		)
	),
	concat!(
		"      --disable-sandbox-filesystem",
		more!(
			"disables the filesystem part of the downloader process sandbox"
		)
	),
	concat!(
		"      --disable-sandbox-syscalls",
		more!(
			"disables the syscalls part of the downloader process sandbox"
		)
	),
];

// version(): the C's banner when invoked as pacman (pactest, parity), puck's
// own otherwise. puck is a port of pacman's code, so upstream's copyright
// and licence lines stay in both
pub fn version(out: &mut Vec<u8>, myname: &[u8]) {
	let l1 = if myname == b"pacman" {
		format!("Pacman v{PACKAGE_VERSION} - libalpm v{LIB_VERSION}")
	} else {
		format!(
			"Puck v{} - Pacman v{PACKAGE_VERSION} port \
			(libalpm v{LIB_VERSION})",
			env!("CARGO_PKG_VERSION")
		)
	};
	let text = format!(
		concat!(
			"\n",
			" .--.                  {}\n",
			"/ _.-' .-.  .-.  .-.   Copyright (C) 2006-2025 Pacman ",
			"Development Team\n",
			"\\  '-. '-'  '-'  '-'   Copyright (C) 2002-2006 Judd Vinet\n",
			" '--'\n",
			"                       This program may be freely ",
			"redistributed under\n",
			"                       the terms of the GNU General Public ",
			"License.\n",
			"\n"
		),
		l1
	);
	out.extend_from_slice(text.as_bytes());
}

// what a parsearg_* function made of an option
enum Arg {
	Done,
	// not an option of this operation
	Unknown,
	// rejected value, already reported
	Bad,
}

// strtol(s, &end, 10): (value, end offset, ERANGE). no digits leaves
// end at 0 like endptr == nptr
fn strtol(s: &[u8]) -> (i64, usize, bool) {
	let mut i = s.iter().take_while(|&&c| is_space(c)).count();
	let neg = match s.get(i) {
		Some(b'-') => {
			i += 1;
			true
		}
		Some(b'+') => {
			i += 1;
			false
		}
		_ => false,
	};
	let start = i;
	let (mut v, mut erange) = (0i64, false);
	while let Some(&c) = s.get(i).filter(|c| c.is_ascii_digit()) {
		let d = i64::from(c - b'0');
		let next = v.checked_mul(10).and_then(|v| {
			if neg {
				v.checked_sub(d)
			} else {
				v.checked_add(d)
			}
		});
		match next {
			Some(n) => v = n,
			None => {
				erange = true;
				v = if neg { i64::MIN } else { i64::MAX };
			}
		}
		i += 1;
	}
	if i == start {
		return (0, 0, false);
	}
	(v, i, erange)
}

// strtol accepted the whole string without ERANGE
fn whole_long(s: &[u8]) -> Option<i64> {
	let (v, end, erange) = strtol(s);
	(!erange && end != 0 && end == s.len()).then_some(v)
}

// parsearg_util_addlist: strtok_r on ",", empty fields dropped
fn addlist(list: &mut Vec<Vec<u8>>, arg: &[u8]) {
	let fields = arg.split(|&c| c == b',').filter(|f| !f.is_empty());
	list.extend(fields.map(<[u8]>::to_vec));
}

// parsearg_op: the operation letters, applied unless dryrun
fn parsearg_op(config: &mut Config, opt: i32, dryrun: bool) -> bool {
	let op = match u8::try_from(opt) {
		Ok(b'D') => PM_OP_DATABASE,
		Ok(b'F') => PM_OP_FILES,
		Ok(b'Q') => PM_OP_QUERY,
		Ok(b'R') => PM_OP_REMOVE,
		Ok(b'S') => PM_OP_SYNC,
		Ok(b'T') => PM_OP_DEPTEST,
		Ok(b'U') => PM_OP_UPGRADE,
		Ok(b'V') => {
			if !dryrun {
				config.version = 1;
			}
			return true;
		}
		Ok(b'h') => {
			if !dryrun {
				config.help = 1;
			}
			return true;
		}
		_ => return false,
	};
	if !dryrun {
		// a second operation makes op 0, reported after the pass
		config.op = if config.op != PM_OP_MAIN { 0 } else { op };
	}
	true
}

// resolve_path: realpath(3), std canonicalize is the same call
fn resolve_path(
	config: &Config,
	io: &mut Io,
	path: &[u8],
	option: &'static str,
) -> Option<Vec<u8>> {
	match fs::canonicalize(OsStr::from_bytes(path)) {
		Ok(p) => Some(p.into_os_string().into_vec()),
		Err(e) => {
			let msg = Msg::ResolvePath {
				path: path.to_vec(),
				option,
				err: e.raw_os_error().unwrap_or(0),
			};
			io.log(config, &msg);
			None
		}
	}
}

fn strndup_path(s: &[u8]) -> Vec<u8> {
	s[..s.len().min(PATH_MAX)].to_vec()
}

// --debug[=1|2]: the levels add debug, then function messages
fn debug_level(config: &mut Config, io: &mut Io, arg: Option<&[u8]>) -> Arg {
	let mask = match arg.map(whole_long) {
		None | Some(Some(1)) => LOG_DEBUG,
		Some(Some(2)) => LOG_DEBUG | LOG_FUNCTION,
		Some(_) => {
			let a = arg.unwrap_or_default();
			let msg: [&[u8]; 3] =
				[b"'", a, b"' is not a valid debug level\n"];
			pm_error(config, io, &msg);
			return Arg::Bad;
		}
	};
	config.logmask |= mask;
	// progress bars get wonky with debug on
	config.noprogressbar = 1;
	Arg::Done
}

// parsearg_global
fn parsearg_global(
	config: &mut Config,
	io: &mut Io,
	opt: i32,
	arg: Option<&[u8]>,
) -> Arg {
	let a = arg.unwrap_or_default();
	let short = |c: u8| opt == i32::from(c);
	match opt {
		OP_ARCH => config.add_architecture(a, io),
		OP_ASK => {
			// strtol into a long, then any value up to UINT_MAX
			let ask = whole_long(a)
				.filter(|&v| v <= i64::from(u32::MAX));
			let Some(ask) = ask else {
				pm_error(
					config,
					io,
					&[
						b"'",
						a,
						b"' is not a valid ask level\n",
					],
				);
				return Arg::Bad;
			};
			config.noask = 1;
			config.ask = ask as u32;
		}
		OP_CACHEDIR => {
			let Some(p) = resolve_path(config, io, a, "--cachedir")
			else {
				return Arg::Bad;
			};
			config.cachedirs.push(p);
		}
		OP_COLOR => {
			config.color = match a {
				b"never" => PM_COLOR_OFF,
				b"auto" if io.stdout_tty => PM_COLOR_ON,
				b"auto" => PM_COLOR_OFF,
				b"always" => PM_COLOR_ON,
				_ => {
					pm_error(
						config,
						io,
						&[
							b"invalid argument '",
							a,
							b"' for --color\n",
						],
					);
					return Arg::Bad;
				}
			};
			config.enable_colors(config.color);
		}
		OP_CONFIG => config.configfile = Some(strndup_path(a)),
		OP_DEBUG => return debug_level(config, io, arg),
		OP_GPGDIR => {
			let Some(p) = resolve_path(config, io, a, "--gpgdir")
			else {
				return Arg::Bad;
			};
			config.gpgdir = Some(p);
		}
		OP_HOOKDIR => {
			let Some(p) = resolve_path(config, io, a, "--hookdir")
			else {
				return Arg::Bad;
			};
			config.hookdirs.push(p);
		}
		OP_LOGFILE => config.logfile = Some(strndup_path(a)),
		OP_NOCONFIRM => config.noconfirm = 1,
		OP_CONFIRM => config.noconfirm = 0,
		_ if opt == OP_DBPATH || short(b'b') => {
			let Some(p) = resolve_path(config, io, a, "--dbpath")
			else {
				return Arg::Bad;
			};
			config.dbpath = Some(p);
		}
		_ if opt == OP_ROOT || short(b'r') => {
			let Some(p) = resolve_path(config, io, a, "--root")
			else {
				return Arg::Bad;
			};
			config.rootdir = Some(p);
		}
		OP_SYSROOT => {
			let Some(p) = resolve_path(config, io, a, "--sysroot")
			else {
				return Arg::Bad;
			};
			config.sysroot = Some(p);
		}
		OP_DISABLEDLTIMEOUT => config.disable_dl_timeout = 1,
		OP_DISABLESANDBOX => {
			config.disable_sandbox_filesystem = 1;
			config.disable_sandbox_syscalls = 1;
		}
		OP_DISABLESANDBOXFILESYSTEM => {
			config.disable_sandbox_filesystem = 1;
		}
		OP_DISABLESANDBOXSYSCALLS => {
			config.disable_sandbox_syscalls = 1
		}
		_ if opt == OP_VERBOSE || short(b'v') => config.verbose += 1,
		_ => return Arg::Unknown,
	}
	Arg::Done
}

// the long code or the short letter of an option
fn is(opt: i32, long: i32, short: u8) -> bool {
	opt == long || opt == i32::from(short)
}

fn parsearg_database(config: &mut Config, opt: i32) -> Arg {
	match opt {
		OP_ASDEPS => config.flags |= TRANS_FLAG_ALLDEPS,
		OP_ASEXPLICIT => config.flags |= TRANS_FLAG_ALLEXPLICIT,
		_ if is(opt, OP_CHECK, b'k') => config.op_q_check += 1,
		_ if is(opt, OP_QUIET, b'q') => config.quiet = 1,
		_ => return Arg::Unknown,
	}
	Arg::Done
}

fn parsearg_query(config: &mut Config, opt: i32) -> Arg {
	let c = config;
	match opt {
		_ if is(opt, OP_CHANGELOG, b'c') => c.op_q_changelog = 1,
		_ if is(opt, OP_DEPS, b'd') => c.op_q_deps = 1,
		_ if is(opt, OP_EXPLICIT, b'e') => c.op_q_explicit = 1,
		_ if is(opt, OP_GROUPS, b'g') => c.group += 1,
		_ if is(opt, OP_INFO, b'i') => c.op_q_info += 1,
		_ if is(opt, OP_CHECK, b'k') => c.op_q_check += 1,
		_ if is(opt, OP_LIST, b'l') => c.op_q_list = 1,
		_ if is(opt, OP_FOREIGN, b'm') => {
			c.op_q_locality |= PKG_LOCALITY_FOREIGN;
		}
		_ if is(opt, OP_NATIVE, b'n') => {
			c.op_q_locality |= PKG_LOCALITY_NATIVE;
		}
		_ if is(opt, OP_OWNS, b'o') => c.op_q_owns = 1,
		_ if is(opt, OP_FILE, b'p') => c.op_q_isfile = 1,
		_ if is(opt, OP_QUIET, b'q') => c.quiet = 1,
		_ if is(opt, OP_SEARCH, b's') => c.op_q_search = 1,
		_ if is(opt, OP_UNREQUIRED, b't') => c.op_q_unrequired += 1,
		_ if is(opt, OP_UPGRADES, b'u') => c.op_q_upgrade = 1,
		_ => return Arg::Unknown,
	}
	Arg::Done
}

// options common to -S -R -U (and -F)
fn parsearg_trans(config: &mut Config, opt: i32, arg: &[u8]) -> Arg {
	let c = config;
	match opt {
		_ if is(opt, OP_NODEPS, b'd') => {
			// -dd: the second one skips all dependency checks
			if c.flags & TRANS_FLAG_NODEPVERSION != 0 {
				c.flags |= TRANS_FLAG_NODEPS;
			} else {
				c.flags |= TRANS_FLAG_NODEPVERSION;
			}
		}
		OP_DBONLY => {
			c.flags |= TRANS_FLAG_DBONLY
				| TRANS_FLAG_NOSCRIPTLET
				| TRANS_FLAG_NOHOOKS;
		}
		OP_NOPROGRESSBAR => c.noprogressbar = 1,
		OP_NOSCRIPTLET => c.flags |= TRANS_FLAG_NOSCRIPTLET,
		_ if is(opt, OP_PRINT, b'p') => c.print = 1,
		OP_PRINTFORMAT => {
			c.print = 1;
			c.print_format = Some(arg.to_vec());
		}
		OP_ASSUMEINSTALLED => addlist(&mut c.assumeinstalled, arg),
		_ => return Arg::Unknown,
	}
	Arg::Done
}

fn parsearg_remove(config: &mut Config, opt: i32, arg: &[u8]) -> Arg {
	if let Arg::Done = parsearg_trans(config, opt, arg) {
		return Arg::Done;
	}
	let c = config;
	match opt {
		_ if is(opt, OP_CASCADE, b'c') => c.flags |= TRANS_FLAG_CASCADE,
		_ if is(opt, OP_NOSAVE, b'n') => c.flags |= TRANS_FLAG_NOSAVE,
		_ if is(opt, OP_RECURSIVE, b's') => {
			if c.flags & TRANS_FLAG_RECURSE != 0 {
				c.flags |= TRANS_FLAG_RECURSEALL;
			} else {
				c.flags |= TRANS_FLAG_RECURSE;
			}
		}
		_ if is(opt, OP_UNNEEDED, b'u') => {
			c.flags |= TRANS_FLAG_UNNEEDED;
		}
		_ => return Arg::Unknown,
	}
	Arg::Done
}

// options common to -S -U
fn parsearg_upgrade(config: &mut Config, opt: i32, arg: &[u8]) -> Arg {
	if let Arg::Done = parsearg_trans(config, opt, arg) {
		return Arg::Done;
	}
	let c = config;
	match opt {
		OP_OVERWRITE_FILES => addlist(&mut c.overwrite_files, arg),
		OP_ASDEPS => c.flags |= TRANS_FLAG_ALLDEPS,
		OP_ASEXPLICIT => c.flags |= TRANS_FLAG_ALLEXPLICIT,
		OP_NEEDED => c.flags |= TRANS_FLAG_NEEDED,
		OP_IGNORE => addlist(&mut c.ignorepkg, arg),
		OP_IGNOREGROUP => addlist(&mut c.ignoregrp, arg),
		_ if is(opt, OP_DOWNLOADONLY, b'w') => {
			c.op_s_downloadonly = 1;
			c.flags |= TRANS_FLAG_DOWNLOADONLY
				| TRANS_FLAG_NOCONFLICTS;
		}
		_ => return Arg::Unknown,
	}
	Arg::Done
}

fn parsearg_files(config: &mut Config, opt: i32, arg: &[u8]) -> Arg {
	if let Arg::Done = parsearg_trans(config, opt, arg) {
		return Arg::Done;
	}
	let c = config;
	match opt {
		_ if is(opt, OP_LIST, b'l') => c.op_q_list = 1,
		_ if is(opt, OP_REFRESH, b'y') => c.op_s_sync += 1,
		_ if is(opt, OP_REGEX, b'x') => c.op_f_regex = 1,
		OP_MACHINEREADABLE => c.op_f_machinereadable = 1,
		_ if is(opt, OP_QUIET, b'q') => c.quiet = 1,
		_ => return Arg::Unknown,
	}
	Arg::Done
}

fn parsearg_sync(config: &mut Config, opt: i32, arg: &[u8]) -> Arg {
	if let Arg::Done = parsearg_upgrade(config, opt, arg) {
		return Arg::Done;
	}
	let c = config;
	match opt {
		_ if is(opt, OP_CLEAN, b'c') => c.op_s_clean += 1,
		_ if is(opt, OP_GROUPS, b'g') => c.group += 1,
		_ if is(opt, OP_INFO, b'i') => c.op_s_info += 1,
		_ if is(opt, OP_LIST, b'l') => c.op_q_list = 1,
		_ if is(opt, OP_QUIET, b'q') => c.quiet = 1,
		_ if is(opt, OP_SEARCH, b's') => c.op_s_search = 1,
		_ if is(opt, OP_SYSUPGRADE, b'u') => c.op_s_upgrade += 1,
		_ if is(opt, OP_REFRESH, b'y') => c.op_s_sync += 1,
		_ => return Arg::Unknown,
	}
	Arg::Done
}

// the checkargs_* conflict checks: the first conflict ends parsing
struct Check<'a> {
	config: &'a Config,
	io: &'a mut Io,
}

type Checked = Result<(), i32>;

impl Check<'_> {
	// invalid_opt
	fn invalid(&mut self, used: bool, opt1: &str, opt2: &str) -> Checked {
		if !used {
			return Ok(());
		}
		pm_error(
			self.config,
			self.io,
			&[
				b"invalid option: '",
				opt1.as_bytes(),
				b"' and '",
				opt2.as_bytes(),
				b"' may not be used together\n",
			],
		);
		Err(1)
	}

	fn flag(&self, f: i32) -> bool {
		self.config.flags & f != 0
	}

	fn database(&mut self) -> Checked {
		let deps = self.flag(TRANS_FLAG_ALLDEPS);
		let expl = self.flag(TRANS_FLAG_ALLEXPLICIT);
		self.invalid(deps && expl, "--asdeps", "--asexplicit")?;
		if self.config.op_q_check != 0 {
			self.invalid(deps, "--asdeps", "--check")?;
			self.invalid(expl, "--asexplicit", "--check")?;
		}
		Ok(())
	}

	fn query_display_opts(&mut self, opname: &str) -> Checked {
		let c = self.config;
		self.invalid(c.op_q_changelog != 0, opname, "--changelog")?;
		self.invalid(c.op_q_check != 0, opname, "--check")?;
		self.invalid(c.op_q_info != 0, opname, "--info")?;
		self.invalid(c.op_q_list != 0, opname, "--list")
	}

	fn query_filter_opts(&mut self, opname: &str) -> Checked {
		let c = self.config;
		let native = c.op_q_locality & PKG_LOCALITY_NATIVE != 0;
		let foreign = c.op_q_locality & PKG_LOCALITY_FOREIGN != 0;
		self.invalid(c.op_q_deps != 0, opname, "--deps")?;
		self.invalid(c.op_q_explicit != 0, opname, "--explicit")?;
		// the C names the -u option "--upgrade" here
		self.invalid(c.op_q_upgrade != 0, opname, "--upgrade")?;
		self.invalid(c.op_q_unrequired != 0, opname, "--unrequired")?;
		self.invalid(native, opname, "--native")?;
		self.invalid(foreign, opname, "--foreign")
	}

	fn query(&mut self) -> Checked {
		let c = self.config;
		let group = c.group != 0;
		if c.op_q_isfile != 0 {
			self.invalid(group, "--file", "--groups")?;
			self.invalid(c.op_q_search != 0, "--file", "--search")?;
			self.invalid(c.op_q_owns != 0, "--file", "--owns")?;
		} else if c.op_q_search != 0 {
			self.invalid(group, "--search", "--groups")?;
			self.invalid(c.op_q_owns != 0, "--search", "--owns")?;
			self.query_display_opts("--search")?;
			self.query_filter_opts("--search")?;
		} else if c.op_q_owns != 0 {
			self.invalid(group, "--owns", "--groups")?;
			self.query_display_opts("--owns")?;
			self.query_filter_opts("--owns")?;
		} else if group {
			self.query_display_opts("--groups")?;
		}
		let both = c.op_q_deps != 0 && c.op_q_explicit != 0;
		self.invalid(both, "--deps", "--explicit")?;
		let l = c.op_q_locality;
		let both = l & PKG_LOCALITY_NATIVE != 0
			&& l & PKG_LOCALITY_FOREIGN != 0;
		self.invalid(both, "--native", "--foreign")
	}

	fn trans(&mut self) -> Checked {
		if self.config.print != 0 {
			let dbonly = self.flag(TRANS_FLAG_DBONLY);
			let noscriptlet = self.flag(TRANS_FLAG_NOSCRIPTLET);
			self.invalid(dbonly, "--print", "--dbonly")?;
			self.invalid(noscriptlet, "--print", "--noscriptlet")?;
		}
		Ok(())
	}

	fn remove(&mut self) -> Checked {
		self.trans()?;
		if self.flag(TRANS_FLAG_NOSAVE) {
			let print = self.config.print != 0;
			let dbonly = self.flag(TRANS_FLAG_DBONLY);
			self.invalid(print, "--nosave", "--print")?;
			self.invalid(dbonly, "--nosave", "--dbonly")?;
		}
		Ok(())
	}

	fn upgrade(&mut self) -> Checked {
		self.trans()?;
		let both = self.flag(TRANS_FLAG_ALLDEPS)
			&& self.flag(TRANS_FLAG_ALLEXPLICIT);
		self.invalid(both, "--asdeps", "--asexplicit")
	}

	fn files(&mut self) -> Checked {
		// op_q_search is never set under -F
		let c = self.config;
		if c.op_q_search != 0 {
			self.invalid(c.op_q_list != 0, "--regex", "--list")?;
		}
		Ok(())
	}

	fn sync(&mut self) -> Checked {
		self.upgrade()?;
		let c = self.config;
		let group = c.group != 0;
		let info = c.op_s_info != 0;
		let list = c.op_q_list != 0;
		let refresh = c.op_s_sync != 0;
		let search = c.op_s_search != 0;
		let sysupgrade = c.op_s_upgrade != 0;
		let dlonly = c.op_s_downloadonly != 0;
		if c.op_s_clean != 0 {
			self.invalid(group, "--clean", "--groups")?;
			self.invalid(info, "--clean", "--info")?;
			self.invalid(list, "--clean", "--list")?;
			self.invalid(refresh, "--clean", "--refresh")?;
			self.invalid(search, "--clean", "--search")?;
			self.invalid(sysupgrade, "--clean", "--sysupgrade")?;
			self.invalid(dlonly, "--clean", "--downloadonly")?;
		} else if info {
			self.invalid(group, "--info", "--groups")?;
			self.invalid(list, "--info", "--list")?;
			self.invalid(search, "--info", "--search")?;
			self.invalid(sysupgrade, "--info", "--sysupgrade")?;
			self.invalid(dlonly, "--info", "--downloadonly")?;
		} else if search {
			self.invalid(group, "--search", "--groups")?;
			self.invalid(list, "--search", "--list")?;
			self.invalid(sysupgrade, "--search", "--sysupgrade")?;
			self.invalid(dlonly, "--search", "--downloadonly")?;
		} else if list {
			self.invalid(group, "--list", "--groups")?;
			self.invalid(sysupgrade, "--list", "--sysupgrade")?;
			self.invalid(dlonly, "--list", "--downloadonly")?;
		} else if group {
			self.invalid(sysupgrade, "--groups", "--sysupgrade")?;
			self.invalid(dlonly, "--groups", "--downloadonly")?;
		}
		Ok(())
	}
}

// parseargs: two getopt passes over argv (permuted in place like the
// C), the first picks the operation, the second the options valid for
// it. Ok is pm_targets, Err the exit status
pub fn parseargs(
	config: &mut Config,
	argv: &mut [Vec<u8>],
	io: &mut Io,
) -> Result<Vec<Vec<u8>>, i32> {
	let question = i32::from(b'?');
	let mut g = Getopt::new(io.posixly_correct);
	let mut option_index = 0;
	loop {
		let opt = g.getopt_long(
			argv,
			OPTSTRING,
			LONGOPTS,
			&mut option_index,
			&mut io.err,
		);
		if opt == -1 {
			break;
		}
		if opt == question {
			// getopt printed the error
			return Err(1);
		}
		parsearg_op(config, opt, false);
	}

	if config.op == 0 {
		pm_error(
			config,
			io,
			&[b"only one operation may be used at a time\n"],
		);
		return Err(1);
	}
	if config.help != 0 {
		let myname = argv.first().map_or(&b""[..], |a| mbasename(a));
		usage(&mut io.out, config.op, myname);
		return Err(0);
	}
	if config.version != 0 {
		let myname = argv.first().map_or(&b""[..], |a| mbasename(a));
		version(&mut io.out, myname);
		return Err(0);
	}

	g.optind = 1;
	loop {
		let opt = g.getopt_long(
			argv,
			OPTSTRING,
			LONGOPTS,
			&mut option_index,
			&mut io.err,
		);
		if opt == -1 {
			break;
		}
		if opt == question {
			return Err(1);
		}
		if parsearg_op(config, opt, true) {
			continue;
		}
		let optarg = g.optarg.clone();
		let a = optarg.as_deref().unwrap_or_default();
		let r = match config.op {
			PM_OP_DATABASE => parsearg_database(config, opt),
			PM_OP_QUERY => parsearg_query(config, opt),
			PM_OP_REMOVE => parsearg_remove(config, opt, a),
			PM_OP_SYNC => parsearg_sync(config, opt, a),
			PM_OP_UPGRADE => parsearg_upgrade(config, opt, a),
			PM_OP_FILES => parsearg_files(config, opt, a),
			_ => Arg::Unknown,
		};
		if let Arg::Done = r {
			continue;
		}
		match parsearg_global(config, io, opt, optarg.as_deref()) {
			Arg::Done => continue,
			Arg::Bad => return Err(1),
			Arg::Unknown => {}
		}
		if opt < OP_LONG_FLAG_MIN {
			// opt is one of the optstring letters
			let c = [opt as u8];
			pm_error(
				config,
				io,
				&[b"invalid option '-", &c, b"'\n"],
			);
		} else {
			let name = LONGOPTS[option_index].name;
			pm_error(
				config,
				io,
				&[b"invalid option '--", name, b"'\n"],
			);
		}
		return Err(1);
	}

	let targets = argv[g.optind.min(argv.len())..].to_vec();

	let mut check = Check { config, io };
	match config.op {
		PM_OP_DATABASE => check.database()?,
		PM_OP_SYNC => check.sync()?,
		PM_OP_QUERY => check.query()?,
		PM_OP_REMOVE => check.remove()?,
		PM_OP_UPGRADE => check.upgrade()?,
		PM_OP_FILES => check.files()?,
		// -T has no conflicting options
		_ => {}
	}
	Ok(targets)
}

// main: a "-" target is replaced by the lines of stdin (None when stdin
// is a terminal). getline splits after '\n', the C string of each line
// ends at its first NUL, empty ones are skipped. reopen_tty is the
// freopen(ctermid(NULL), "r", stdin) that follows, Err an errno
pub fn stdin_targets(
	config: &Config,
	targets: &mut Vec<Vec<u8>>,
	stdin: Option<&[u8]>,
	reopen_tty: impl FnOnce() -> Result<(), i32>,
	io: &mut Io,
) -> Result<(), i32> {
	let Some(dash) = targets.iter().position(|t| t == b"-") else {
		return Ok(());
	};
	let Some(stdin) = stdin else {
		pm_error(
			config,
			io,
			&[b"argument '-' specified without input on stdin\n"],
		);
		return Err(1);
	};
	targets.remove(dash);
	let mut found = false;
	for line in stdin.split_inclusive(|&c| c == b'\n') {
		let line = line.strip_suffix(b"\n").unwrap_or(line);
		let line = &line[..line
			.iter()
			.position(|&c| c == 0)
			.unwrap_or(line.len())];
		if line.is_empty() {
			continue;
		}
		targets.push(line.to_vec());
		found = true;
	}
	if let Err(e) = reopen_tty() {
		pm_error(
			config,
			io,
			&[
				b"failed to reopen stdin for reading: (",
				&strerror(&io::Error::from_raw_os_error(e)),
				b")\n",
			],
		);
	}
	if !found {
		pm_error(
			config,
			io,
			&[b"argument '-' specified with empty stdin\n"],
		);
		return Err(1);
	}
	Ok(())
}

// what main() needs from the process besides argv
pub struct Process<'a, F: FnOnce() -> Result<(), i32>> {
	pub uid: u32,
	// stdin contents, None when stdin is a terminal
	pub stdin: Option<&'a [u8]>,
	pub reopen_tty: F,
}

// main() from config_new up to parseconfig: Ok is the parsed config and
// targets, Err the exit status (cleanup(ret) with ret -1 exits 255)
pub fn main_args<F: FnOnce() -> Result<(), i32>>(
	argv: &mut [Vec<u8>],
	process: Process<'_, F>,
	io: &mut Io,
) -> Result<(Config, Vec<Vec<u8>>), i32> {
	let mut config = Config::new();
	config.user_agent = setuseragent(&config, io);
	// no progress bar when the output is redirected
	if !io.stdout_tty {
		config.noprogressbar = 1;
	}
	let mut targets = parseargs(&mut config, argv, io)?;
	if process.uid > 0 && needs_root(&config) {
		pm_error(
			&config,
			io,
			&[b"you cannot perform this operation unless you are \
			root.\n"],
		);
		return Err(1);
	}
	stdin_targets(
		&config,
		&mut targets,
		process.stdin,
		process.reopen_tty,
		io,
	)?;
	let msg = Msg::Debug(
		format!("pacman v{PACKAGE_VERSION} - libalpm v{LIB_VERSION}\n")
			.into_bytes(),
	);
	io.log(&config, &msg);
	let file = config.configfile.clone().unwrap_or_default();
	config.parseconfig(&file, io)
		.map_err(|e: ConfError| e.ret & 0xff)?;
	Ok((config, targets))
}

// the binary's stdin. the callbacks' Term and the operation's Term are
// separate readers over the one stdin fd (a held StdinLock would block
// the other); capacity 1 keeps each from reading past the '\n' it stops
// on, so a first prompt (an alpm conflict/replace question from the
// callbacks) does not swallow the input a second prompt ("Proceed with
// installation?") then reads. the leftover stays in the shared fd, like
// the C reading both prompts line by line from one stdio FILE*
pub type StdIn = io::BufReader<io::Stdin>;

fn std_stdin() -> StdIn {
	io::BufReader::with_capacity(1, io::stdin())
}

// CLOCK_MONOTONIC_COARSE counts from boot, so a fresh bar's zero sync
// time is long past: the offset keeps that
fn monotonic_ms() -> i64 {
	static START: OnceLock<Instant> = OnceLock::new();
	let ms = START.get_or_init(Instant::now).elapsed().as_millis();
	i64::try_from(ms)
		.unwrap_or(i64::MAX)
		.saturating_add(1 << 30)
}

// the binary's process: std's stdin, the terminal probes, getcols and
// the clocks
pub fn std_term() -> Term<StdIn> {
	Term {
		stdin: std_stdin(),
		stdin_tty: io::stdin().is_terminal(),
		stdout_tty: io::stdout().is_terminal(),
		cols: getcols,
		flush_input: flush_term_input,
		now_ms: monotonic_ms,
		now_secs,
		move_completed_up: Arc::default(),
	}
}

// Output::sink of the binary: stdout, then stderr, written through.
// write errors are dropped like the unchecked C stdio calls
pub fn std_sink(o: &mut Output) {
	let mut out = io::stdout();
	let _ = out.write_all(&std::mem::take(&mut o.stdout));
	let _ = out.flush();
	let _ = io::stderr().write_all(&std::mem::take(&mut o.stderr));
}

// pm_printf of conf.c messages into an Output
struct OutHost<'a> {
	out: &'a mut Output,
	now_secs: fn() -> i64,
}

impl Host for OutHost<'_> {
	fn sink(&self) -> Option<fn(&mut Output)> {
		self.out.sink
	}

	fn log(&mut self, config: &Config, msg: &Msg) {
		let now = (self.now_secs)();
		if let Some(s) = stamped(config, msg, true, now) {
			self.out.stderr.extend_from_slice(&s);
			// stderr is unbuffered: before the callbacks' next line
			self.out.flush();
		}
	}
}

// main() up to the operation: Err is cleanup(ret). the parse output
// goes out before anything else is printed
fn setup<R: BufRead + 'static>(
	argv: &mut [Vec<u8>],
	process: Process<'_, impl FnOnce() -> Result<(), i32>>,
	io: &mut Io,
	out: &mut Output,
	new_term: &impl Fn() -> Term<R>,
) -> Result<(Config, Vec<Vec<u8>>, Handle), i32> {
	let parsed = main_args(argv, process, io);
	out.stdout.append(&mut io.out);
	out.stderr.append(&mut io.err);
	out.flush();
	let (mut config, targets) = parsed?;
	let sink = out.sink;
	let frontend = |config: &Config| {
		let mut f = Frontend::new(config.clone(), new_term());
		f.out.sink = sink;
		Box::new(f)
	};
	let cb = frontend(&config);
	let now_secs = cb.term.now_secs;
	let mut host = OutHost { out, now_secs };
	let handle = config.setup_libalpm(&mut host, cb);
	out.flush();
	let mut handle = handle.map_err(|e| e.ret & 0xff)?;
	// noask is meant to be non-interactive
	if config.noask != 0 {
		config.noconfirm = 1;
	}
	if config.print != 0 && config.op_s_clean == 0 {
		config.noconfirm = 1;
		config.flags |= TRANS_FLAG_NOCONFLICTS | TRANS_FLAG_NOLOCK;
		// errors only
		config.logmask &= !LOG_WARNING;
	}
	// the callbacks and the fetchcb read the config as it is from here on
	handle.set_callbacks(frontend(&config));
	handle.set_fetchcb(config.xfercommand_fetch(sink));
	Ok((config, targets, handle))
}

// the -v lines before the operation
fn verbose(
	out: &mut Vec<u8>,
	config: &Config,
	handle: &Handle,
	targets: &[Vec<u8>],
) {
	let join = |dirs: &[Vec<u8>]| -> Vec<u8> {
		dirs.iter().flat_map(|d| [&d[..], b"  "].concat()).collect()
	};
	let null = |s: Option<&[u8]>| s.unwrap_or(b"(null)").to_vec();
	let conf = config.configfile.as_deref();
	let lines: [(&[u8], Vec<u8>); 8] = [
		(b"Root      : ", handle.root().to_vec()),
		(b"Conf File : ", null(conf)),
		(b"DB Path   : ", handle.dbpath().to_vec()),
		(b"Cache Dirs: ", join(handle.cachedirs())),
		(b"Hook Dirs : ", join(handle.hookdirs())),
		(b"Lock File : ", handle.lockfile().to_vec()),
		(b"Log File  : ", null(handle.logfile())),
		(b"GPG Dir   : ", null(handle.gpgdir())),
	];
	for (title, value) in lines {
		out.extend_from_slice(&[title, &value[..], b"\n"].concat());
	}
	let title = b"Targets   :";
	list_display(out, Some(title), targets, 0, &config.colstr);
}

// the operation of config.op on handle: the exit status
fn dispatch<R: BufRead>(
	ui: &mut Ui<R>,
	handle: &mut Handle,
	targets: &[Vec<u8>],
) -> i32 {
	let (config, cols) = (ui.config, ui.cols);
	match config.op {
		PM_OP_DATABASE => {
			pacman_database(config, handle, targets, ui.out)
		}
		PM_OP_REMOVE => pacman_remove(ui, handle, targets),
		PM_OP_UPGRADE => pacman_upgrade(ui, handle, targets),
		PM_OP_QUERY => {
			let path =
				std::env::var_os("PATH").map(|p| p.into_vec());
			let env = QueryEnv { cols, path };
			pacman_query(config, handle, &env, targets, ui.out)
		}
		PM_OP_SYNC => {
			match pacman_sync(config, handle, targets, cols, ui.out)
			{
				Ok(ret) => ret,
				Err(Deferred::Clean) => sync_clean(ui, handle),
				Err(Deferred::Transaction) => {
					sync_trans(ui, handle, targets)
				}
			}
		}
		PM_OP_DEPTEST => pacman_deptest(handle, targets, ui.out),
		PM_OP_FILES => pacman_files(config, handle, targets, ui.out),
		_ => {
			let msg = b"no operation specified (use -h for help)\n";
			pm_printf(&mut ui.out.stderr, config, LOG_ERROR, msg);
			1
		}
	}
}

// main(): the exit status (cleanup(ret) exits with ret & 0xff).
// new_term gives the process to each Frontend, sink is where output
// goes (std_sink for the binary)
pub fn run<R: BufRead + 'static>(
	argv: &mut [Vec<u8>],
	process: Process<'_, impl FnOnce() -> Result<(), i32>>,
	io: &mut Io,
	new_term: impl Fn() -> Term<R>,
	sink: Option<fn(&mut Output)>,
) -> i32 {
	// one multibar_move_completed_up flag for the callbacks and the ops
	let flag = Arc::<AtomicBool>::default();
	let new_term = || Term {
		move_completed_up: flag.clone(),
		..new_term()
	};
	let mut term = new_term();
	let mut out = Output {
		sink,
		..Output::default()
	};
	console_cursor_hide(&mut out.stdout, term.stdout_tty);
	// alpm_release comes after remove_soft_interrupt_handler
	let mut released = None;
	let ret = match setup(argv, process, io, &mut out, &new_term) {
		Err(ret) => ret,
		Ok((config, targets, mut handle)) => {
			set_handle(handle.interrupt());
			if config.verbose > 0 {
				verbose(
					&mut out.stdout,
					&config,
					&handle,
					&targets,
				);
			}
			if needs_root(&config) {
				let cl =
					arg_to_string(argv).unwrap_or_default();
				let msg = [&b"Running '"[..], &cl, b"'\n"]
					.concat();
				let _ = handle.logaction(b"PACMAN", &msg);
			}
			let mut ui = Ui {
				config: &config,
				cols: (term.cols)(),
				term: &mut term,
				out: &mut out,
				format_date: &format_date,
				explicit_adds: Vec::new(),
				explicit_removes: Vec::new(),
			};
			let ret = dispatch(&mut ui, &mut handle, &targets);
			// the op's output before alpm_release logs (cleanup)
			ui.out.flush();
			released = Some(handle);
			ret & 0xff
		}
	};
	console_cursor_show(&mut out.stdout, term.stdout_tty);
	out.flush();
	remove_soft_interrupt_handler();
	drop(released);
	ret
}
