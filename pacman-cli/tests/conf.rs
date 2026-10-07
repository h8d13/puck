// unit tests of pacman_cli::conf, fixtures in a fresh /tmp directory
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use pacman_cli::conf::{
	ColStr, Config, DB_USAGE_ALL, DB_USAGE_SYNC, Host, LOG_DEBUG,
	LOG_ERROR, LOG_WARNING, Msg, PM_CLEAN_KEEPCUR, PM_CLEAN_KEEPINST,
	PM_COLOR_ON, SIG_DATABASE, SIG_DATABASE_OPTIONAL, SIG_PACKAGE,
	SIG_PACKAGE_MARGINAL_OK, SIG_PACKAGE_UNKNOWN_OK, SIG_USE_DEFAULT,
	format_msg, glob, merge_siglevel, prepend_dir,
};

struct Dir(PathBuf);

impl Dir {
	// tests run in parallel: one directory per call
	fn new(tag: &str) -> Dir {
		static N: AtomicUsize = AtomicUsize::new(0);
		let n = N.fetch_add(1, Ordering::Relaxed);
		let p = std::env::temp_dir().join(format!(
			"pacman-cli-conf-{}-{tag}-{n}",
			std::process::id()
		));
		if p.exists() {
			fs::remove_dir_all(&p).unwrap();
		}
		fs::create_dir_all(&p).unwrap();
		Dir(p)
	}

	fn s(&self) -> String {
		self.0.to_str().unwrap().to_string()
	}

	fn write(&self, rel: &str, content: &str) -> Vec<u8> {
		let p = self.0.join(rel);
		fs::create_dir_all(p.parent().unwrap()).unwrap();
		fs::write(&p, content).unwrap();
		p.as_os_str().as_bytes().to_vec()
	}
}

impl Drop for Dir {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

#[derive(Default)]
struct Log {
	msgs: Vec<Msg>,
	out: Vec<u8>,
	tty: bool,
}

impl Host for Log {
	fn log(&mut self, config: &Config, msg: &Msg) {
		self.msgs.push(msg.clone());
		if let Some(s) = format_msg(config, msg) {
			self.out.extend_from_slice(&s);
		}
	}

	fn stdout_is_tty(&mut self) -> bool {
		self.tty
	}

	fn machine(&mut self) -> Vec<u8> {
		b"m68k".to_vec()
	}
}

fn parse(content: &str) -> (Result<(), i32>, Config, Log) {
	let d = Dir::new("parse");
	let f = d.write("pacman.conf", content);
	let mut c = Config::new();
	let mut log = Log::default();
	let r = c.parseconfig(&f, &mut log).map_err(|e| e.ret);
	(r, c, log)
}

fn b(s: &str) -> Vec<u8> {
	s.as_bytes().to_vec()
}

#[test]
fn defaults() {
	let c = Config::new();
	assert_eq!(c.op, 1);
	assert_eq!(c.logmask, LOG_ERROR | LOG_WARNING);
	assert_eq!(c.configfile.as_deref(), Some(&b"/etc/pacman.conf"[..]));
	assert_eq!(c.siglevel, SIG_PACKAGE | SIG_DATABASE);
	assert_eq!(c.localfilesiglevel, SIG_USE_DEFAULT);
	assert_eq!(c.parallel_downloads, 1);
	assert_eq!(c.colstr, ColStr::PLAIN);

	let (r, c, _) = parse("[options]\n");
	assert_eq!(r, Ok(()));
	assert_eq!(c.rootdir, Some(b("/")));
	assert_eq!(c.dbpath, Some(b("/var/lib/pacman/")));
	assert_eq!(c.cachedirs, [b("/var/cache/pacman/pkg/")]);
	assert_eq!(c.cleanmethod, PM_CLEAN_KEEPINST);
	assert_eq!(c.localfilesiglevel, SIG_USE_DEFAULT);
}

#[test]
fn options() {
	let (r, c, log) = parse(
		"[options]\nILoveCandy\nNoUpgrade = a  b\tc\nNoUpgrade = d\n\
		Architecture = auto x\nCleanMethod = KeepCurrent\n\
		ParallelDownloads = +3\nXferCommand = cmd -o '%o x'\n\
		LogFile = /a\nLogFile = /b\nBogus\n",
	);
	assert_eq!(r, Ok(()));
	assert_eq!(c.chomp, 1);
	assert_eq!(c.noupgrade, [b("a"), b("b\tc"), b("d")]);
	assert_eq!(c.architectures, [b("m68k"), b("x")]);
	assert_eq!(c.cleanmethod, PM_CLEAN_KEEPCUR);
	assert_eq!(c.parallel_downloads, 3);
	assert_eq!(
		c.xfercommand_argv,
		Some(vec![b("cmd"), b("-o"), b("%o x")])
	);
	assert_eq!(c.xfercommand_argc, 3);
	assert_eq!(c.logfile, Some(b("/a")));
	let warn = log.msgs.iter().filter(|m| m.level() == LOG_WARNING);
	assert_eq!(warn.count(), 1);
}

#[test]
fn errors() {
	let (r, _, log) = parse("UseSyslog\n");
	assert_eq!(r, Err(1));
	assert!(matches!(log.msgs[..], [Msg::NoSection { line: 1, .. }]));

	for (v, want) in [
		("0", "has to be positive"),
		("2147483648", "too large"),
		("9223372036854775808", "invalid value"),
		("1 2", "invalid value"),
	] {
		let (r, _, log) =
			parse(&format!("[options]\nParallelDownloads={v}"));
		assert_eq!(r, Err(1));
		assert!(
			String::from_utf8_lossy(&log.out).contains(want),
			"{v}"
		);
	}

	// failing XferCommand keeps the old string, drops argv
	let (r, c, _) = parse("[options]\nXferCommand = a\nXferCommand = 'b\n");
	assert_eq!(r, Err(1));
	assert_eq!(c.xfercommand, Some(b("a")));
	assert_eq!(c.xfercommand_argv, None);
	assert_eq!(c.xfercommand_argc, 1);

	let (r, c, log) = parse("[core]\nUsage = Sync Bogus\n");
	assert_eq!(r, Err(1));
	assert_eq!(c.repos[0].usage, DB_USAGE_SYNC);
	assert!(matches!(
		log.msgs.last(),
		Some(Msg::UsageNotRecognized { .. })
	));
}

#[test]
fn siglevel() {
	let (r, c, _) =
		parse("[options]\nSigLevel = Optional PackageTrustAll\n\
		[core]\nSigLevel = PackageNever DatabaseOptional\n[extra]\n");
	assert_eq!(r, Ok(()));
	let all_ok = SIG_PACKAGE_MARGINAL_OK | SIG_PACKAGE_UNKNOWN_OK;
	assert_eq!(c.siglevel & all_ok, all_ok);
	assert_eq!(c.siglevel & SIG_USE_DEFAULT, 0);
	assert_eq!(c.repos[0].siglevel & SIG_PACKAGE, 0);
	assert_ne!(c.repos[0].siglevel & SIG_DATABASE_OPTIONAL, 0);
	// untouched repo siglevel stays for libalpm to resolve
	assert_eq!(c.repos[1].siglevel, SIG_USE_DEFAULT);
	assert_eq!(c.repos[1].usage, DB_USAGE_ALL);

	// an invalid word leaves the level as it was
	let (r, c, _) = parse("[options]\nSigLevel = Never Bogus\n");
	assert_eq!(r, Err(1));
	assert_eq!(c.siglevel, Config::new().siglevel);

	assert_eq!(merge_siglevel(0b1100, 0b0011, 0), 0b0011);
	assert_eq!(merge_siglevel(0b1100, 0b0011, 0b0110), 0b1010);
}

#[test]
fn servers() {
	let (r, c, _) = parse("[options]\nArchitecture = x86_64 i686\n\
		[core]\nServer = http://m/$repo/os/$arch\nCacheServer = $repo\n");
	assert_eq!(r, Ok(()));
	assert_eq!(c.repos[0].servers, [b("http://m/core/os/x86_64")]);
	assert_eq!(c.repos[0].cache_servers, [b("core")]);

	let (r, c, log) = parse("[core]\nServer = a\nServer = $arch\n");
	assert_eq!(r, Err(-1));
	assert_eq!(c.repos[0].servers, [b("a"), b("$arch")]);
	assert!(matches!(log.msgs.last(), Some(Msg::MirrorNoArch { .. })));
}

#[test]
fn include_and_sysroot() {
	let d = Dir::new("include");
	let s = d.s();
	d.write(
		"pacman.conf",
		"[options]\nInclude = /inc/*.conf\nServer = x\n",
	);
	d.write("inc/b.conf", "HoldPkg = b\n[repo]\n");
	d.write("inc/a.conf", "HoldPkg = a\n");
	d.write("inc/.h.conf", "HoldPkg = h\n");
	let mut c = Config::new();
	c.sysroot = Some(b(&s));
	let mut log = Log::default();
	assert_eq!(c.parseconfig(b"/pacman.conf", &mut log), Ok(()));
	// sorted, no dotfiles, the section of b.conf carries over
	assert_eq!(c.holdpkg, [b("a"), b("b")]);
	assert_eq!(c.repos[0].name, b("repo"));
	assert_eq!(c.repos[0].servers, [b("x")]);
	assert_eq!(c.dbpath, Some(b(&format!("{s}/var/lib/pacman/"))));

	// self include stops at depth 10
	d.write("self.conf", &format!("Include = {s}/self.conf\n"));
	let mut c = Config::new();
	let mut log = Log::default();
	let f = format!("{s}/self.conf");
	let e = c.parseconfigfile(f.as_bytes(), &mut log).unwrap_err();
	assert_eq!((e.ret, e.msg), (1, Msg::MaxRecursion));
}

#[test]
fn colors() {
	let d = Dir::new("colors");
	let f = d.write("pacman.conf", "[options]\nColor\nBogus\n");
	let mut c = Config::new();
	c.logmask |= LOG_DEBUG;
	let mut log = Log {
		tty: true,
		..Log::default()
	};
	assert_eq!(c.parseconfigfile(&f, &mut log), Ok(()));
	assert_eq!(c.color, PM_COLOR_ON);
	assert!(log
		.out
		.starts_with(b"debug: config: new section 'options'\n"));
	assert!(log.out.windows(16).any(|w| w == b"\x1b[1;33mwarning: "));
}

#[test]
fn glob_order() {
	let d = Dir::new("glob");
	let s = d.s();
	for f in ["b", "a", "B", ".x", "d/c", "e/c"] {
		d.write(f, "");
	}
	let g = |p: &str| {
		glob(format!("{s}/{p}").as_bytes())
			.into_iter()
			.map(|p| {
				String::from_utf8(p).unwrap()[s.len()..]
					.to_string()
			})
			.collect::<Vec<_>>()
	};
	assert_eq!(g("*"), ["/B", "/a", "/b", "/d", "/e"]);
	assert_eq!(g(".*"), ["/.", "/..", "/.x"]);
	assert_eq!(g("*/c"), ["/d/c", "/e/c"]);
	assert_eq!(g("*/"), ["/d/", "/e/"]);
	assert_eq!(g("z*"), ["/z*"]);
	assert_eq!(g("\\a"), ["/a"]);
	assert_eq!(prepend_dir(Some(b"/r/"), b"//x"), b("/r/x"));
	assert_eq!(prepend_dir(Some(b""), b"x"), b("/x"));
	assert_eq!(prepend_dir(None, b"/x"), b("/x"));
}
