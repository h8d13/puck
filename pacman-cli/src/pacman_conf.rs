// port of src/pacman/pacman-conf.c: query the pacman configuration
//
// the C globals (directives, repo_name, verbose, ...) are one `Query`,
// its config_t the conf.rs `Config`, parsed with parseconfigfile and
// setdefaults like the C (no setup_libalpm). stdout and stderr go into
// `Io` (pm_printf through its Host impl); `run` returns the exit status
// where the C calls exit() or returns from main. sep is always '\n': the
// C has no option to change it. messages are the untranslated msgids.
use crate::conf::{
	CONFFILE, Config, ConfigRepo, DB_USAGE_ALL, DB_USAGE_INSTALL,
	DB_USAGE_SEARCH, DB_USAGE_SYNC, DB_USAGE_UPGRADE, PM_CLEAN_KEEPCUR,
	PM_CLEAN_KEEPINST, SIG_DATABASE, SIG_DATABASE_OPTIONAL,
	SIG_DATABASE_UNKNOWN_OK, SIG_PACKAGE, SIG_PACKAGE_OPTIONAL,
	SIG_PACKAGE_UNKNOWN_OK, SIG_USE_DEFAULT,
};
use crate::getopt::{Getopt, HasArg, LongOpt};
use crate::pacman::Io;

const MYNAME: &str = "pacman-conf";
const MYVER: &str = "1.0.0";
const SEP: u8 = b'\n';

const SHORT_OPTS: &[u8] = b"c:hlR:S:r:Vv";

const fn opt(name: &'static [u8], has_arg: HasArg, val: u8) -> LongOpt {
	LongOpt {
		name,
		has_arg,
		val: val as i32,
	}
}

const LONG_OPTS: &[LongOpt] = &[
	opt(b"config", HasArg::Required, b'c'),
	opt(b"rootdir", HasArg::Required, b'R'),
	opt(b"sysroot", HasArg::Required, b'S'),
	opt(b"repo", HasArg::Required, b'r'),
	opt(b"repo-list", HasArg::No, b'l'),
	opt(b"verbose", HasArg::No, b'v'),
	opt(b"help", HasArg::No, b'h'),
	opt(b"version", HasArg::No, b'V'),
];

const USAGE: &str = "pacman-conf - query pacman's configuration file\n\
	usage:  pacman-conf [options] [<directive>...]\n        \
	pacman-conf (--repo-list|--help|--version)\n\
	options:\n  \
	-c, --config=<path>  set an alternate configuration file\n  \
	-R, --rootdir=<path> set an alternate installation root\n  \
	-S, --sysroot=<path> set an alternate system root\n  \
	-r, --repo=<remote>  query options for a specific repo\n  \
	-v, --verbose        always show directive names\n  \
	-l, --repo-list      list configured repositories\n  \
	-h, --help           display this help information\n  \
	-V, --version        display version information\n";

// the C's file-scope state next to its config
struct Query {
	config: Config,
	repo_name: Option<Vec<u8>>,
	verbose: bool,
	out: Vec<u8>,
}

// usage(ret): stdout for --help, stderr otherwise
fn usage(io: &mut Io, ret: i32) -> i32 {
	let stream = if ret != 0 { &mut io.err } else { &mut io.out };
	stream.extend_from_slice(USAGE.as_bytes());
	ret
}

// parse_opts up to the config parse: Err is the exit status. argv is
// permuted like getopt_long does, Ok is optind
fn parse_opts(
	argv: &mut [Vec<u8>],
	config: &mut Config,
	q: &mut Opts,
	io: &mut Io,
) -> Result<usize, i32> {
	let mut g = Getopt::new(io.posixly_correct);
	let mut longind = 0;
	loop {
		let c = g.getopt_long(
			argv,
			SHORT_OPTS,
			LONG_OPTS,
			&mut longind,
			&mut io.err,
		);
		if c == -1 {
			break;
		}
		let arg = g.optarg.take().unwrap_or_default();
		// strdup failures (out of memory) are not modelled
		match u8::try_from(c).unwrap_or(0) {
			b'c' => q.config_file = arg,
			b'R' => config.rootdir = Some(arg),
			b'S' => config.sysroot = Some(arg),
			b'l' => q.repo_list = true,
			b'r' => q.repo_name = Some(arg),
			b'v' => q.verbose = true,
			b'h' => return Err(usage(io, 0)),
			b'V' => {
				let v = format!("{MYNAME} v{MYVER}\n");
				io.out.extend_from_slice(v.as_bytes());
				return Err(0);
			}
			_ => return Err(usage(io, 1)),
		}
	}
	let parsed = config
		.parseconfigfile(&q.config_file, io)
		.and_then(|()| config.setdefaults(io));
	if parsed.is_err() {
		let msg = [b"error parsing '", &q.config_file[..], b"'\n"];
		io.err.extend_from_slice(&msg.concat());
		return Err(1);
	}
	Ok(g.optind)
}

// the options parse_opts sets besides the config
struct Opts {
	config_file: Vec<u8>,
	repo_name: Option<Vec<u8>>,
	repo_list: bool,
	verbose: bool,
}

impl Query {
	fn line(&mut self, parts: &[&[u8]]) {
		for p in parts {
			self.out.extend_from_slice(p);
		}
		self.out.push(SEP);
	}

	fn list_repos(&mut self) {
		let repos = std::mem::take(&mut self.config.repos);
		for r in &repos {
			let wanted = self.repo_name.as_deref();
			if wanted.is_none_or(|n| n == r.name.as_slice()) {
				self.line(&[&r.name]);
			}
		}
		self.config.repos = repos;
	}

	fn show_bool(&mut self, directive: &str, val: u16) {
		if val != 0 {
			self.line(&[directive.as_bytes()]);
		}
	}

	fn show_str(&mut self, directive: &str, val: Option<&[u8]>) {
		let Some(val) = val else {
			return;
		};
		if self.verbose {
			self.line(&[directive.as_bytes(), b" = ", val]);
		} else {
			self.line(&[val]);
		}
	}

	fn show_int(&mut self, directive: &str, val: u32) {
		let val = val.to_string();
		self.show_str(directive, Some(val.as_bytes()));
	}

	fn show_list_str(&mut self, directive: &str, list: &[Vec<u8>]) {
		for i in list {
			self.show_str(directive, Some(i));
		}
	}

	fn show_word(&mut self, directive: &str, word: &str) {
		self.show_str(directive, Some(word.as_bytes()));
	}

	fn show_cleanmethod(&mut self, directive: &str, method: u16) {
		if method & PM_CLEAN_KEEPINST != 0 {
			self.show_word(directive, "KeepInstalled");
		}
		if method & PM_CLEAN_KEEPCUR != 0 {
			self.show_word(directive, "KeepCurrent");
		}
	}

	// one "<Kind>Optional|Required" + "<Kind>TrustAll|TrustedOnly" pair,
	// or "<Kind>Never"
	fn show_sigkind(
		&mut self,
		directive: &str,
		level: i32,
		bits: (i32, i32, i32),
		kind: &str,
	) {
		let (on, optional, unknown_ok) = bits;
		if level & on == 0 {
			self.show_word(directive, &format!("{kind}Never"));
			return;
		}
		let req = if level & optional != 0 {
			"Optional"
		} else {
			"Required"
		};
		self.show_word(directive, &format!("{kind}{req}"));
		let trust = if level & unknown_ok != 0 {
			"TrustAll"
		} else {
			"TrustedOnly"
		};
		self.show_word(directive, &format!("{kind}{trust}"));
	}

	fn show_siglevel(
		&mut self,
		directive: &str,
		level: i32,
		pkgonly: bool,
	) {
		if level == SIG_USE_DEFAULT {
			return;
		}
		let pkg = (
			SIG_PACKAGE,
			SIG_PACKAGE_OPTIONAL,
			SIG_PACKAGE_UNKNOWN_OK,
		);
		self.show_sigkind(directive, level, pkg, "Package");
		if pkgonly {
			return;
		}
		let db = (
			SIG_DATABASE,
			SIG_DATABASE_OPTIONAL,
			SIG_DATABASE_UNKNOWN_OK,
		);
		self.show_sigkind(directive, level, db, "Database");
	}

	fn show_usage(&mut self, directive: &str, usage: i32) {
		if usage == DB_USAGE_ALL {
			self.show_word(directive, "All");
			return;
		}
		let words = [
			(DB_USAGE_SYNC, "Sync"),
			(DB_USAGE_SEARCH, "Search"),
			(DB_USAGE_INSTALL, "Install"),
			(DB_USAGE_UPGRADE, "Upgrade"),
		];
		for (bit, word) in words {
			if usage & bit != 0 {
				self.show_word(directive, word);
			}
		}
	}

	fn dump_repo(&mut self, repo: &ConfigRepo) {
		self.show_usage("Usage", repo.usage);
		self.show_siglevel("SigLevel", repo.siglevel, false);
		self.show_list_str("CacheServer", &repo.cache_servers);
		self.show_list_str("Server", &repo.servers);
	}

	fn dump_config(&mut self) {
		self.line(&[b"[options]"]);
		// the shows borrow self mutably: read from a moved-out copy
		let c = std::mem::take(&mut self.config);
		self.show_str("RootDir", c.rootdir.as_deref());
		self.show_str("DBPath", c.dbpath.as_deref());
		self.show_list_str("CacheDir", &c.cachedirs);
		self.show_list_str("HookDir", &c.hookdirs);
		self.show_str("GPGDir", c.gpgdir.as_deref());
		self.show_str("LogFile", c.logfile.as_deref());
		self.show_str("DownloadUser", c.sandboxuser.as_deref());

		self.show_list_str("HoldPkg", &c.holdpkg);
		self.show_list_str("IgnorePkg", &c.ignorepkg);
		self.show_list_str("IgnoreGroup", &c.ignoregrp);
		self.show_list_str("NoUpgrade", &c.noupgrade);
		self.show_list_str("NoExtract", &c.noextract);

		self.show_list_str("Architecture", &c.architectures);
		self.show_str("XferCommand", c.xfercommand.as_deref());

		self.show_bool("UseSyslog", c.usesyslog);
		self.show_bool("Color", c.color);
		self.show_bool("CheckSpace", c.checkspace);
		self.show_bool("VerbosePkgLists", c.verbosepkglists);
		self.show_bool("DisableDownloadTimeout", c.disable_dl_timeout);
		self.show_bool("ILoveCandy", c.chomp);
		self.show_bool("NoProgressBar", c.noprogressbar);
		let fs = c.disable_sandbox_filesystem;
		self.show_bool("DisableSandboxFilesystem", fs);
		let sys = c.disable_sandbox_syscalls;
		self.show_bool("DisableSandboxSyscalls", sys);

		self.show_int("ParallelDownloads", c.parallel_downloads);

		self.show_cleanmethod("CleanMethod", c.cleanmethod);

		self.show_siglevel("SigLevel", c.siglevel, false);
		self.show_siglevel(
			"LocalFileSigLevel",
			c.localfilesiglevel,
			true,
		);
		let remote = c.remotefilesiglevel;
		self.show_siglevel("RemoteFileSigLevel", remote, true);

		for repo in &c.repos {
			self.line(&[b"[", &repo.name, b"]"]);
			self.dump_repo(repo);
		}
		self.config = c;
	}

	// one directive of a repo, false when it cannot be shown
	fn repo_directive(
		&mut self,
		repo: &ConfigRepo,
		d: &[u8],
		err: &mut Vec<u8>,
	) -> bool {
		let is = |name: &str| d.eq_ignore_ascii_case(name.as_bytes());
		if is("Server") {
			self.show_list_str("Server", &repo.servers);
		} else if is("CacheServer") {
			self.show_list_str("CacheServer", &repo.cache_servers);
		} else if is("SigLevel") {
			self.show_siglevel("SigLevel", repo.siglevel, false);
		} else if is("Usage") {
			self.show_usage("Usage", repo.usage);
		} else {
			return not_shown(d, err);
		}
		true
	}

	fn list_repo_directives(
		&mut self,
		name: &[u8],
		directives: &[Vec<u8>],
		err: &mut Vec<u8>,
	) -> i32 {
		let repos = std::mem::take(&mut self.config.repos);
		let ret = match repos.iter().find(|r| r.name == name) {
			None => {
				let msg = [
					b"error: repo '",
					name,
					b"' not configured\n",
				];
				err.extend_from_slice(&msg.concat());
				1
			}
			Some(repo) if directives.is_empty() => {
				self.dump_repo(repo);
				0
			}
			Some(repo) => {
				let mut ret = 0;
				for d in directives {
					if !self.repo_directive(repo, d, err) {
						ret = 1;
					}
				}
				ret
			}
		};
		self.config.repos = repos;
		ret
	}

	// one directive of [options], false when it cannot be shown. the
	// C's "DisableSandbox" test appears twice (UPSTREAM.md): the second,
	// meant for DisableSandboxFilesystem, never matches, so that name
	// falls through to unknown
	fn directive(
		&mut self,
		c: &Config,
		d: &[u8],
		err: &mut Vec<u8>,
	) -> bool {
		let is = |name: &str| d.eq_ignore_ascii_case(name.as_bytes());
		if is("RootDir") {
			self.show_str("RootDir", c.rootdir.as_deref());
		} else if is("DBPath") {
			self.show_str("DBPath", c.dbpath.as_deref());
		} else if is("CacheDir") {
			self.show_list_str("CacheDir", &c.cachedirs);
		} else if is("HookDir") {
			self.show_list_str("HookDir", &c.hookdirs);
		} else if is("GPGDir") {
			self.show_str("GPGDir", c.gpgdir.as_deref());
		} else if is("LogFile") {
			self.show_str("LogFile", c.logfile.as_deref());
		} else if is("DownloadUser") {
			self.show_str("DownloadUser", c.sandboxuser.as_deref());
		} else if is("HoldPkg") {
			self.show_list_str("HoldPkg", &c.holdpkg);
		} else if is("IgnorePkg") {
			self.show_list_str("IgnorePkg", &c.ignorepkg);
		} else if is("IgnoreGroup") {
			self.show_list_str("IgnoreGroup", &c.ignoregrp);
		} else if is("NoUpgrade") {
			self.show_list_str("NoUpgrade", &c.noupgrade);
		} else if is("NoExtract") {
			self.show_list_str("NoExtract", &c.noextract);
		} else if is("Architecture") {
			self.show_list_str("Architecture", &c.architectures);
		} else if is("XferCommand") {
			self.show_str("XferCommand", c.xfercommand.as_deref());
		} else if is("UseSyslog") {
			self.show_bool("UseSyslog", c.usesyslog);
		} else if is("Color") {
			self.show_bool("Color", c.color);
		} else if is("CheckSpace") {
			self.show_bool("CheckSpace", c.checkspace);
		} else if is("VerbosePkgLists") {
			self.show_bool("VerbosePkgLists", c.verbosepkglists);
		} else if is("DisableDownloadTimeout") {
			let v = c.disable_dl_timeout;
			self.show_bool("DisableDownloadTimeout", v);
		} else if is("ILoveCandy") {
			self.show_bool("ILoveCandy", c.chomp);
		} else if is("NoProgressBar") {
			self.show_bool("NoProgressBar", c.noprogressbar);
		} else if is("DisableSandbox") {
			let fs = c.disable_sandbox_filesystem;
			self.show_bool("DisableSandboxFilesystem", fs);
			let sys = c.disable_sandbox_syscalls;
			self.show_bool("DisableSandboxSyscalls", sys);
		} else if is("DisableSandboxSyscalls") {
			let sys = c.disable_sandbox_syscalls;
			self.show_bool("DisableSandboxSyscalls", sys);
		} else if is("ParallelDownloads") {
			self.show_int(
				"ParallelDownloads",
				c.parallel_downloads,
			);
		} else if is("CleanMethod") {
			self.show_cleanmethod("CleanMethod", c.cleanmethod);
		} else if is("SigLevel") {
			self.show_siglevel("SigLevel", c.siglevel, false);
		} else if is("LocalFileSigLevel") {
			let l = c.localfilesiglevel;
			self.show_siglevel("LocalFileSigLevel", l, true);
		} else if is("RemoteFileSigLevel") {
			let l = c.remotefilesiglevel;
			self.show_siglevel("RemoteFileSigLevel", l, true);
		} else {
			return not_shown(d, err);
		}
		true
	}

	fn list_directives(
		&mut self,
		directives: &[Vec<u8>],
		err: &mut Vec<u8>,
	) -> i32 {
		if directives.is_empty() {
			self.dump_config();
			return 0;
		}
		let c = std::mem::take(&mut self.config);
		let mut ret = 0;
		for d in directives {
			if !self.directive(&c, d, err) {
				ret = 1;
			}
		}
		self.config = c;
		ret
	}
}

// the warnings for Include and unknown names: always false
fn not_shown(d: &[u8], err: &mut Vec<u8>) -> bool {
	let msg: &[&[u8]] = if d.eq_ignore_ascii_case(b"Include") {
		&[b"warning: 'Include' directives cannot be queried\n"]
	} else {
		&[b"warning: unknown directive '", d, b"'\n"]
	};
	err.extend_from_slice(&msg.concat());
	false
}

// main(): the exit status, output in io
pub fn run(argv: &mut [Vec<u8>], io: &mut Io) -> i32 {
	let mut config = Config::new();
	let mut opts = Opts {
		config_file: CONFFILE.to_vec(),
		repo_name: None,
		repo_list: false,
		verbose: false,
	};
	let optind = match parse_opts(argv, &mut config, &mut opts, io) {
		Ok(i) => i,
		Err(ret) => return ret,
	};
	let directives = argv.get(optind..).unwrap_or_default().to_vec();
	let mut q = Query {
		config,
		repo_name: opts.repo_name,
		// names shown unless exactly one directive is asked for
		verbose: opts.verbose || directives.len() != 1,
		out: Vec::new(),
	};
	let ret = if opts.repo_list {
		if directives.is_empty() {
			q.list_repos();
			0
		} else {
			io.err.extend_from_slice(
				b"error: directives may not be specified \
				with --repo-list\n",
			);
			1
		}
	} else if let Some(name) = q.repo_name.clone() {
		q.list_repo_directives(&name, &directives, &mut io.err)
	} else {
		q.list_directives(&directives, &mut io.err)
	};
	io.out.extend_from_slice(&q.out);
	ret
}
