// pacman_cli::conf against src/pacman/conf.c: random config trees under
// /tmp parsed by both, compared on return value, stderr and the whole
// config_t. glob(3) compared directly on the same trees. setup_libalpm:
// the handle both build from a config (every option getter, the sync
// dbs with siglevel, usage and servers), return value and stderr
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use difftest::c_uname_machine;
use difftest::{
	Preset, Rng, c_config_new, c_glob, c_parseconfig, c_setup, iters,
	rust_setup,
};
use pacman_cli::conf::{
	Config, Host, LOG_DEBUG, LOG_ERROR, LOG_WARNING, Msg, PM_COLOR_OFF,
	PM_COLOR_ON, format_msg, glob,
};

// a fresh directory tree under /tmp, removed on drop
struct Tree {
	root: PathBuf,
}

// malloc(n) of escape_chars for this sysroot, n or n + 1 (trailing '/')
// at 16k+8 leaves no slack for the C's extra nul on glibc x86_64/aarch64
fn escape_size_unsafe(path: &std::path::Path) -> bool {
	let s = path.as_os_str().as_encoded_bytes();
	let n = s.len() + s.iter().filter(|c| b"\\*?[".contains(c)).count();
	n % 16 == 8 || (n + 1) % 16 == 8
}

impl Tree {
	// glob characters in the name exercise the sysroot escaping
	fn new(tag: &str, odd: bool) -> Tree {
		let mut name = if odd {
			format!(
				"pacman-conf-dt-{}-{tag}-[x]*?\\",
				std::process::id()
			)
		} else {
			format!("pacman-conf-dt-{}-{tag}", std::process::id())
		};
		// C precondition (UPSTREAM.md): escape_chars writes its nul one
		// byte past malloc(len + escaped). keep that size (with and
		// without a trailing '/') off 16k+8, where glibc's chunk has no
		// slack, so the stray byte stays inside the allocation
		while odd && escape_size_unsafe(
			&std::env::temp_dir().join(&name),
		) {
			name.push('p');
		}
		let root = std::env::temp_dir().join(name);
		if root.exists() {
			fs::remove_dir_all(&root).unwrap();
		}
		for d in ["inc/d1", "inc/d2", "inc/empty", "inc/w*", "root"] {
			fs::create_dir_all(root.join(d)).unwrap();
		}
		for f in INC_FILES {
			fs::write(root.join("inc").join(f), "").unwrap();
		}
		fs::write(root.join("inc/s*"), "").unwrap();
		fs::write(root.join("inc/b\\c"), "").unwrap();
		fs::write(root.join("inc/w*/k"), "").unwrap();
		symlink("root", root.join("link")).unwrap();
		symlink("d1", root.join("inc/l")).unwrap();
		Tree { root }
	}

	fn path(&self) -> Vec<u8> {
		self.root.as_os_str().as_bytes().to_vec()
	}

	fn write(&self, rel: &str, content: &[u8]) {
		fs::write(self.root.join(rel), content).unwrap();
	}
}

impl Drop for Tree {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.root).unwrap();
	}
}

// files the fuzz rewrites every iteration, under inc/
const INC_FILES: &[&str] = &[
	"a.conf",
	"b.conf",
	"c.conf",
	".h.conf",
	"x",
	"d1/a.conf",
	"d1/b",
	"d2/a.conf",
];

struct TestHost {
	out: Vec<u8>,
	tty: bool,
	machine: Vec<u8>,
}

impl Host for TestHost {
	fn log(&mut self, config: &Config, msg: &Msg) {
		if let Some(s) = format_msg(config, msg) {
			self.out.extend_from_slice(&s);
		}
	}

	fn stdout_is_tty(&mut self) -> bool {
		self.tty
	}

	fn machine(&mut self) -> Vec<u8> {
		self.machine.clone()
	}
}

fn show(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

// parses with both, panics on any difference. returns the C ret
fn compare(tree: &Tree, file: &[u8], preset: &Preset) -> i32 {
	let c = c_parseconfig(file, preset);
	let mut config = preset.config();
	let mut host = TestHost {
		out: Vec::new(),
		tty: preset.tty,
		machine: c_uname_machine(),
	};
	let r = config.parseconfig(file, &mut host);
	let ctx = || {
		let mut s =
			format!("file {:?} preset {preset:?}\n", show(file));
		for f in std::iter::once("pacman.conf")
			.chain(INC_FILES.iter().copied())
		{
			let p = tree.root.join(if f == "pacman.conf" {
				f.to_string()
			} else {
				format!("inc/{f}")
			});
			let content = fs::read(&p).unwrap_or_default();
			s += &format!("--- {f}\n{}", show(&content));
		}
		s
	};
	let ret = r.as_ref().map_or_else(|e| e.ret, |()| 0);
	assert_eq!(
		show(&host.out),
		show(&c.stderr),
		"stderr differs\n{}",
		ctx()
	);
	assert_eq!(ret, c.ret, "ret differs\n{}", ctx());
	assert_eq!(config, c.config, "config differs\n{}", ctx());
	// the returned error is the last one reported
	if let Err(e) = r {
		assert_eq!(e.msg.level(), LOG_ERROR);
		if let Some(m) = format_msg(&config, &e.msg) {
			assert!(
				host.out.ends_with(&m),
				"{e:?} not last\n{}",
				ctx()
			);
		}
	}
	c.ret
}

fn debug_preset() -> Preset {
	Preset {
		logmask: LOG_ERROR | LOG_WARNING | LOG_DEBUG,
		..Preset::default()
	}
}

#[test]
fn config_new_layout() {
	assert_eq!(c_config_new(), Config::new());
}

#[test]
fn fixed() {
	let tree = Tree::new("fixed", false);
	let base = tree.path();
	let main = [&base[..], b"/pacman.conf"].concat();
	let s = show(&base);
	let cases: Vec<String> =
		vec![
		String::new(),
		"[options]\n".into(),
		"UseSyslog\n".into(),
		"Include = /nope\n".into(),
		"[options]\nInclude\n".into(),
		"[options]\nColor\nBogus\nSigLevel = Nope\n".into(),
		"[options]\nArchitecture = auto x86_64\n\
		[core]\nServer = http://a/$repo/$arch\n"
			.into(),
		"[core]\nServer = http://a/$repo/$arch\n".into(),
		"[core]\nCacheServer = $arch\nServer = $repo\n".into(),
		"[core]\nServer = file:///srv/$repo\nCacheServer = file:///c\n"
			.into(),
		"[core]\nServer\n".into(),
		"[core]\nUsage = Sync Bogus Search\n".into(),
		"[core]\nSigLevel = PackageNever Bogus DatabaseTrustAll\n".into(),
		"[core]\nSigLevel =\nUsage =\nUsage = All\n".into(),
		"[options]\nSigLevel = Required DatabaseOptional\n\
		LocalFileSigLevel = Never\nRemoteFileSigLevel = PackageTrustAll\n\
		[x]\nSigLevel = TrustedOnly PackageOptional\n"
			.into(),
		"[options]\nCleanMethod = KeepCurrent Bogus\n".into(),
		"[options]\nCleanMethod = KeepCurrent\n".into(),
		"[options]\nParallelDownloads = 0\n".into(),
		"[options]\nParallelDownloads = 2147483648\n".into(),
		"[options]\nParallelDownloads = 9223372036854775808\n".into(),
		"[options]\nParallelDownloads = +7\n".into(),
		"[options]\nXferCommand = /bin/curl -o %o '%u'\n\
		XferCommand = a 'b\nXferCommand = c\n"
			.into(),
		"[options]\nXferCommand = a \"b\n".into(),
		format!("[options]\nRootDir = {s}/link\nDBPath = {s}/root/../inc\n"),
		format!("[options]\nRootDir = {s}/nope\n"),
		format!("[options]\nGPGDir = {s}/inc/a.conf/x\n"),
		"[options]\nRootDir = /\n".into(),
		"[options]\nLogFile = a\nLogFile = b\nDownloadUser = u\n".into(),
		"[options]\nNoUpgrade = a  b\tc\nHoldPkg = \nIgnorePkg = x\n".into(),
		format!("[options]\nInclude = {s}/inc/*.conf\nUseSyslog\n"),
		format!("Include = {s}/inc/d*/a.conf\n"),
		format!("[options]\nInclude = {s}/inc/d1\n"),
		format!("[options]\nInclude = {s}/inc/.*\n"),
		"[]\nServer = x\n[\nx]\n=\n= v\n".into(),
		"[options]\r\nDisableSandbox\r\n[core]\r\nServer = a\r\n".into(),
	];
	for case in &cases {
		tree.write("pacman.conf", case.as_bytes());
		for logmask in [LOG_ERROR | LOG_WARNING, 7] {
			for tty in [false, true] {
				let preset = Preset {
					logmask,
					tty,
					..Preset::default()
				};
				compare(&tree, &main, &preset);
			}
		}
	}
	// command line paths win over the file, sysroot prefixes
	tree.write(
		"pacman.conf",
		format!("[options]\nRootDir = {s}/root\nDBPath = {s}/root\n\
			CacheDir = /c1 c2\nHookDir = /h\n\
			Include = /inc/a.conf\n[core]\nServer = file:///x\n")
		.as_bytes(),
	);
	tree.write("inc/a.conf", b"LogFile = /l\n");
	let presets = [
		Preset {
			sysroot: Some(base.clone()),
			..debug_preset()
		},
		Preset {
			rootdir: Some(b"/srv/root/".to_vec()),
			gpgdir: Some(b"/g".to_vec()),
			color: PM_COLOR_ON,
			..debug_preset()
		},
		Preset {
			dbpath: Some(b"/d".to_vec()),
			logfile: Some(b"/l".to_vec()),
			sandboxuser: Some(b"u".to_vec()),
			color: PM_COLOR_OFF,
			..debug_preset()
		},
	];
	for preset in &presets {
		let file = if preset.sysroot.is_some() {
			b"/pacman.conf".to_vec()
		} else {
			main.clone()
		};
		compare(&tree, &file, preset);
	}
	// self include: recursion limit
	tree.write(
		"pacman.conf",
		format!("[options]\nInclude = {s}/pacman.conf\n").as_bytes(),
	);
	assert_eq!(compare(&tree, &main, &debug_preset()), 1);
	// a section opened by an include stays open after it
	tree.write(
		"pacman.conf",
		format!("[options]\nInclude = {s}/inc/b.conf\nServer = y\n")
			.as_bytes(),
	);
	tree.write("inc/b.conf", b"[repo]\n");
	assert_eq!(compare(&tree, &main, &debug_preset()), 0);
}

const KEYS: &[&str] = &[
	"UseSyslog",
	"ILoveCandy",
	"VerbosePkgLists",
	"CheckSpace",
	"Color",
	"NoProgressBar",
	"DisableDownloadTimeout",
	"DisableSandbox",
	"DisableSandboxFilesystem",
	"DisableSandboxSyscalls",
	"NoUpgrade",
	"NoExtract",
	"IgnorePkg",
	"IgnoreGroup",
	"HoldPkg",
	"CacheDir",
	"HookDir",
	"Architecture",
	"DBPath",
	"RootDir",
	"GPGDir",
	"LogFile",
	"DownloadUser",
	"XferCommand",
	"CleanMethod",
	"SigLevel",
	"LocalFileSigLevel",
	"RemoteFileSigLevel",
	"ParallelDownloads",
	"Server",
	"CacheServer",
	"Usage",
	"Include",
	"usesyslog",
	"Bogus",
	"",
];

const SIG_WORDS: &[&str] = &[
	"Never",
	"Optional",
	"Required",
	"TrustedOnly",
	"TrustAll",
	"Package",
	"Database",
	"PackageNever",
	"PackageOptional",
	"PackageRequired",
	"PackageTrustedOnly",
	"PackageTrustAll",
	"DatabaseNever",
	"DatabaseOptional",
	"DatabaseRequired",
	"DatabaseTrustedOnly",
	"DatabaseTrustAll",
	"never",
	"DatabasePackageNever",
	"Bogus",
];

const NUMBERS: &[&str] = &[
	"1",
	"0",
	"-1",
	"+5",
	"5x",
	"00012",
	"2147483647",
	"2147483648",
	"4294967297",
	"9223372036854775807",
	"9223372036854775808",
	"-9223372036854775808",
	"-9223372036854775809",
	"x",
	"-",
	"1 2",
];

fn words(rng: &mut Rng, pool: &[&str]) -> String {
	let seps = [" ", "  ", "\t", " \t "];
	let mut s = String::new();
	for i in 0..rng.below(4) {
		if i > 0 {
			s += seps[rng.below(seps.len())];
		}
		s += pool[rng.below(pool.len())];
	}
	s
}

// include targets: base is the tree path, or "" under sysroot. nested
// files only include single files, which bounds the work to a chain
fn include_value(rng: &mut Rng, base: &str, nested: bool) -> String {
	let single = ["a.conf", "b.conf", "c.conf", "d1/a.conf", "x", "nope"];
	let globs = [
		"*.conf",
		"?.conf",
		"[ab].conf",
		"[!a]*",
		"d*/a.conf",
		"*/a.conf",
		"*/*",
		"nope*",
		"d1",
		"empty/*",
		".*",
		"*",
		"\\a.conf",
		"w\\*/*",
	];
	let tail = if nested || rng.below(3) == 0 {
		single[rng.below(single.len())]
	} else {
		globs[rng.below(globs.len())]
	};
	match rng.below(12) {
		0 => String::new(),
		1 => "relative-nope".into(),
		2 => format!("{base}//inc/{tail}"),
		_ => format!("{base}/inc/{tail}"),
	}
}

fn value(
	rng: &mut Rng,
	key: &str,
	tree: &str,
	base: &str,
	nested: bool,
) -> String {
	let pick = |rng: &mut Rng, pool: &[&str]| {
		pool[rng.below(pool.len())].to_string()
	};
	match key {
		"NoUpgrade" | "NoExtract" | "IgnorePkg" | "IgnoreGroup"
		| "HoldPkg" | "CacheDir" | "HookDir" | "LogFile"
		| "DownloadUser" => words(rng, &["a", "b*", "/c/", "$repo", "x=y"]),
		"Architecture" => {
			words(rng, &["auto", "x86_64", "i686", "$repo", "any"])
		}
		"SigLevel" | "LocalFileSigLevel" | "RemoteFileSigLevel" => {
			let pool = if rng.below(4) == 0 {
				SIG_WORDS
			} else {
				&SIG_WORDS[..17]
			};
			words(rng, pool)
		}
		"CleanMethod" => {
			let pool =
				["KeepInstalled", "KeepCurrent", "keepcurrent"];
			let n = if rng.below(4) == 0 { 3 } else { 2 };
			words(rng, &pool[..n])
		}
		"Usage" => {
			let pool = [
				"Sync", "Search", "Install", "Upgrade", "All",
				"None",
			];
			let n = if rng.below(4) == 0 { 6 } else { 5 };
			words(rng, &pool[..n])
		}
		"ParallelDownloads" => {
			let n = if rng.below(2) == 0 {
				NUMBERS.len()
			} else {
				1
			};
			pick(rng, &NUMBERS[..n])
		}
		"XferCommand" => {
			let b = rng.bytes(b"a b\"'\\%ou", 12);
			String::from_utf8(b).unwrap()
		}
		"DBPath" | "RootDir" | "GPGDir" => {
			let tails = [
				"/root",
				"/root/",
				"/link",
				"/nope",
				"/inc/a.conf",
				"/root/../inc",
				"/inc/a.conf/x",
			];
			match rng.below(9) {
				0 => String::new(),
				1 => ".".into(),
				_ => format!("{tree}{}", pick(rng, &tails)),
			}
		}
		"Server" | "CacheServer" => pick(
			rng,
			&[
				"http://h/$repo/os/$arch",
				"file:///srv/$repo",
				"file://rel",
				"file://",
				"$arch$arch",
				"$repo$repo",
				"$ar$repoch",
				"x",
			],
		),
		"Include" => include_value(rng, base, nested),
		_ => {
			let b = rng.bytes(b"a =#$\tZ", 8);
			String::from_utf8(b).unwrap()
		}
	}
}

fn line(rng: &mut Rng, tree: &str, base: &str, nested: bool) -> String {
	let sections = [
		"[options]",
		"[options]",
		"[core]",
		"[extra]",
		"[$repo]",
		"[]",
		"[ options ]",
		"[a=b]",
	];
	match rng.below(20) {
		0 => String::new(),
		1 => "  \t".into(),
		2 => "# Server = x".into(),
		3 => "[".into(),
		4 => "x]".into(),
		5 => "= v".into(),
		6..=8 => sections[rng.below(sections.len())].into(),
		_ => {
			let key = if rng.below(6) == 0 {
				"Include"
			} else {
				KEYS[rng.below(KEYS.len())]
			};
			let (pre, eq) =
				[("", " = "), ("\t", "="), ("  ", " =\t")]
					[rng.below(3)];
			match rng.below(8) {
				0 => format!("{pre}{key}"),
				1 => format!("{pre}{key}{eq}"),
				_ => {
					let v = value(
						rng, key, tree, base, nested,
					);
					format!("{pre}{key}{eq}{v}")
				}
			}
		}
	}
}

fn content(
	rng: &mut Rng,
	n: usize,
	tree: &str,
	base: &str,
	nested: bool,
) -> Vec<u8> {
	// nested files mostly inherit the includer's section
	let mut s = if !nested && rng.below(8) != 0 {
		"[options]\n".to_string()
	} else {
		String::new()
	};
	for i in 0..rng.below(n) {
		if i > 0 {
			s += if rng.below(10) == 0 { "\r\n" } else { "\n" };
		}
		s += &line(rng, tree, base, nested);
	}
	if rng.below(4) != 0 {
		s.push('\n');
	}
	s.into_bytes()
}

fn preset(rng: &mut Rng, tree: &Tree) -> Preset {
	let maybe = |rng: &mut Rng, pool: &[&str]| {
		(rng.below(10) == 0).then(|| pool[rng.below(pool.len())].into())
	};
	Preset {
		sysroot: (rng.below(3) == 0).then(|| tree.path()),
		// never "": setdefaults indexes rootdir[-1]
		rootdir: maybe(rng, &["/", "/srv/root/", "/srv/root", "rel/"]),
		dbpath: maybe(rng, &["/d/", "d"]),
		gpgdir: maybe(rng, &["/g"]),
		logfile: maybe(rng, &["/l"]),
		sandboxuser: maybe(rng, &["alpm"]),
		color: [0, 0, 0, 0, PM_COLOR_OFF, PM_COLOR_ON][rng.below(6)],
		logmask: [7, 7, 7, 3, 1, 0][rng.below(6)],
		tty: rng.below(2) == 0,
		..Preset::default()
	}
}

fn fuzz_parse(seed: u64, odd: bool, n: usize) {
	let tree = Tree::new(&format!("fuzz{seed}"), odd);
	let tree_s = show(&tree.path());
	let mut rng = Rng::new(seed);
	let (mut ok, mut failed) = (0, 0);
	for _ in 0..n {
		let mut p = preset(&mut rng, &tree);
		// unescaped, the odd root would be a pattern over /tmp
		if odd {
			p.sysroot = Some(tree.path());
		}
		let base = if p.sysroot.is_some() { "" } else { &tree_s };
		tree.write(
			"pacman.conf",
			&content(&mut rng, 24, &tree_s, base, false),
		);
		for f in INC_FILES {
			let c = content(&mut rng, 6, &tree_s, base, true);
			tree.write(&format!("inc/{f}"), &c);
		}
		let file = match &p.sysroot {
			Some(_) => b"/pacman.conf".to_vec(),
			None => {
				[tree.path(), b"/pacman.conf".to_vec()].concat()
			}
		};
		if compare(&tree, &file, &p) == 0 {
			ok += 1;
		} else {
			failed += 1;
		}
	}
	// both outcomes need to be common for the fuzz to mean anything
	assert!(ok > n / 20 && failed > n / 20, "ok {ok} failed {failed}");
}

// each iteration writes 9 files and parses twice: half of iters()
#[test]
fn fuzz() {
	fuzz_parse(0x5eed, false, iters() / 2);
}

// sysroot with glob characters, escaped before globbing
#[test]
fn fuzz_odd_root() {
	fuzz_parse(0xb0b, true, iters() / 4);
}

fn glob_compare(pattern: &[u8]) {
	let c = c_glob(pattern).unwrap();
	assert_eq!(
		glob(pattern).iter().map(|p| show(p)).collect::<Vec<_>>(),
		c.iter().map(|p| show(p)).collect::<Vec<_>>(),
		"pattern {:?}",
		show(pattern)
	);
}

#[test]
fn glob_fixed() {
	let tree = Tree::new("globfixed", false);
	let t = show(&tree.path());
	let tails = [
		"inc/*",
		"inc/.*",
		"inc/*/a.conf",
		"inc/*/",
		"inc/a.conf",
		"inc/zz",
		"inc/z*",
		"inc//a.conf",
		"inc//*",
		"inc/\\a.conf",
		"inc/\\*",
		"inc/s\\*",
		"inc/b\\\\c",
		"inc/b\\c",
		"inc/[ab]*",
		"inc/[!a]*",
		"inc/a.conf/*",
		"inc/a.conf/b",
		"inc/*/.*",
		"inc/d?/a.conf",
		"inc/x\\",
		"inc/*\\",
		"inc/[",
		"inc/[a",
		"inc/.",
		"inc/..",
		"inc/./a.conf",
		"inc/*/..",
		"inc/\\z",
		"inc/\\d1/*",
		"inc/w\\*/k",
		"inc/w\\*/*",
		"inc/w*/k",
		"inc/q*/c",
		"inc/*/zz",
		"inc/*/[a].conf",
		"inc/[d]1/a.conf",
		"inc/d1/[!.]*",
		"inc/*/\\a.conf",
		"inc/[.]h*",
		"inc/?h*",
		"inc/\\.h.conf",
		"inc/a.conf/",
		"inc/*/a.conf/",
		"inc/d1/",
		"inc/d1//",
		"inc/[]a]*",
		"inc/[!]]*",
		"inc/[[:alpha:]]*",
		"inc/./*",
		"inc\\/*",
		"inc/d1\\/*",
		"inc/*\\/a.conf",
		"",
	];
	for tail in tails {
		glob_compare(format!("{t}/{tail}").as_bytes());
	}
	glob_compare(b"");
	glob_compare(b"relative-nope*");
}

// patterns start 3 levels below the tree root, "." "..", ".*" can climb
// at most that far: the tree is the only filesystem globbed
#[test]
fn glob_fuzz() {
	let tree = Tree::new("globfuzz", false);
	fs::create_dir_all(tree.root.join("u1/u2/u3")).unwrap();
	symlink("../../../inc", tree.root.join("u1/u2/u3/inc")).unwrap();
	let t = [tree.path(), b"/u1/u2/u3".to_vec()].concat();
	let comps: &[&[u8]] = &[
		b"inc",
		b"d1",
		b"d*",
		b"*",
		b"?",
		b"[ab]*",
		b"[!a]*",
		b"*.conf",
		b".*",
		b".",
		b"..",
		b"a.conf",
		b"\\a.conf",
		b"nope",
		b"[",
		b"]",
		b"\\*",
		b"x",
		b"",
		b"w\\*",
		b"w*",
		b"[.]h*",
		b"k",
		b"\\",
		b"l",
		b"s*",
		b"[]",
		b"[!]a]",
		b"b\\c",
		b"u*",
		b"inc/*",
	];
	let climbs = |c: &[u8]| c == b".." || c == b".*";
	let mut rng = Rng::new(42);
	for _ in 0..iters() / 2 {
		let mut p = t.clone();
		let mut up = 0;
		for _ in 0..1 + rng.below(5) {
			let mut c = comps[rng.below(comps.len())];
			up += usize::from(climbs(c));
			if up > 3 {
				c = b"inc";
			}
			p.push(b'/');
			p.extend_from_slice(c);
		}
		glob_compare(&p);
	}
}

// the system pacman.conf and mirrorlist as corpus, copied, includes
// pointed at the copies. skipped where there is none
#[test]
fn system_config() {
	let (Ok(conf), Ok(mirrors)) = (
		fs::read("/etc/pacman.conf"),
		fs::read("/etc/pacman.d/mirrorlist"),
	) else {
		return;
	};
	let tree = Tree::new("system", false);
	let base = tree.path();
	let conf = show(&conf)
		.replace("/etc/pacman.d/", &format!("{}/", show(&base)));
	tree.write("mirrorlist", &mirrors);
	tree.write("pacman.conf", conf.as_bytes());
	let main = [&base[..], b"/pacman.conf"].concat();
	for tty in [false, true] {
		let preset = Preset {
			tty,
			..debug_preset()
		};
		assert_eq!(compare(&tree, &main, &preset), 0);
	}
}

// one config through parseconfig + setup_libalpm on both sides
fn setup_compare(tree: &Tree, conf: &str, preset: &Preset) -> i32 {
	tree.write("setup.conf", conf.as_bytes());
	let file = [tree.path(), b"/setup.conf".to_vec()].concat();
	let mut c = c_setup(&file, preset);
	// a failing setup leaves the C config->handle half set up, the
	// port returns no handle
	if c.ret != 0 {
		c.handle = None;
	}
	let r = rust_setup(&file, preset);
	assert!(
		c == r,
		"{conf}\n{preset:?}\nC  {:?} {}\n{:?}\nRS {:?} {}\n{:?}",
		c.ret,
		show(&c.stderr),
		c.handle,
		r.ret,
		show(&r.stderr),
		r.handle
	);
	c.ret
}

fn setup_preset(tree: &Tree, logmask: u16) -> Preset {
	let at = |rel: &str| {
		Some([tree.path(), rel.as_bytes().to_vec()].concat())
	};
	Preset {
		rootdir: at("/root"),
		dbpath: at("/root/db"),
		gpgdir: at("/gpg"),
		logfile: at("/log/pacman.log"),
		logmask,
		..Preset::default()
	}
}

fn setup_tree(tag: &str) -> Tree {
	let tree = Tree::new(tag, false);
	fs::create_dir_all(tree.root.join("root/db/sync")).unwrap();
	// a db file that exists: no "does not exist" warning for core
	fs::write(tree.root.join("root/db/sync/core.db"), "").unwrap();
	tree
}

#[test]
fn setup_fixed() {
	let tree = setup_tree("setup-fixed");
	let opts = "[options]\nArchitecture = x86_64 auto\n\
		CacheDir = /c1/ /c2\nHookDir = /h\nCheckSpace\n\
		ParallelDownloads = 3\nDisableDownloadTimeout\n\
		DisableSandboxSyscalls\nIgnorePkg = a b\nIgnoreGroup = g\n\
		NoUpgrade = etc/x\nNoExtract = usr/share/doc/*\n\
		SigLevel = Required DatabaseOptional\n\
		LocalFileSigLevel = Optional\nRemoteFileSigLevel = Never\n";
	let cases: Vec<String> = vec![
		"[options]\n".into(),
		format!("{opts}[core]\nServer = http://a/$repo/os/$arch/\n\
			CacheServer = file:///srv/$repo\nUsage = Sync Search\n\
			SigLevel = PackageNever\n[extra]\nServer = /\n\
			Server = http://b//\nUsage = Install\n"),
		"[options]\n[core]\n[core]\n[local]\n[extra]\n".into(),
		"[options]\nDownloadUser = root\n[core]\n".into(),
		"[options]\nDownloadUser = no-such-user-x\n[core]\n".into(),
		"[options]\nDisableSandbox\n[a]\n[b]\nServer = x\n".into(),
		"[options]\nDBPath = /nonexistent-dir\n".into(),
		"[options]\nRootDir = /nonexistent-root\n".into(),
	];
	for logmask in [LOG_ERROR | LOG_WARNING, LOG_ERROR, 0] {
		for conf in &cases {
			for op in [4, 8] {
				let mut p = setup_preset(&tree, logmask);
				p.op = op;
				if conf.contains("DBPath")
					|| conf.contains("RootDir")
				{
					p.dbpath = None;
					p.rootdir = None;
				}
				setup_compare(&tree, conf, &p);
			}
		}
	}
	for assume in [
		&["foo"][..],
		&["foo=1", "bar"],
		&["foo>1"],
		&["a: d"],
		&["x<2", "y"],
	] {
		let mut p = setup_preset(&tree, LOG_ERROR | LOG_WARNING);
		p.assumeinstalled =
			assume.iter().map(|a| a.as_bytes().to_vec()).collect();
		setup_compare(&tree, "[options]\n[core]\n", &p);
	}
}

#[test]
fn setup_fuzz() {
	let tree = setup_tree("setup-fuzz");
	let mut rng = Rng::new(0x5e7);
	let lines = [
		"Architecture = x86_64",
		"Architecture = auto i686",
		"CacheDir = /c",
		"CacheDir = /d/",
		"HookDir = /h1",
		"CheckSpace",
		"UseDelta",
		"ParallelDownloads = 5",
		"DisableDownloadTimeout",
		"DisableSandbox",
		"DisableSandboxFilesystem",
		"IgnorePkg = p q",
		"IgnoreGroup = g",
		"NoUpgrade = etc/*",
		"NoExtract = !usr/a usr/*",
		"SigLevel = Never",
		"SigLevel = Optional TrustAll",
		"SigLevel = PackageRequired DatabaseTrustedOnly",
		"LocalFileSigLevel = Never",
		"RemoteFileSigLevel = Required",
		"DownloadUser = root",
		"DownloadUser = nobody-not-here",
		"GPGDir = /g",
		"LogFile = /l/log",
	];
	let repo_lines = [
		"Server = http://m/$repo/$arch",
		"Server = file:///r/$repo/",
		"CacheServer = http://cache/",
		"Usage = Sync",
		"Usage = Search Upgrade",
		"Usage = All",
		"SigLevel = Optional",
		"SigLevel = DatabaseNever PackageTrustAll",
		"Server = /",
	];
	let names = ["core", "extra", "local", "core", "x-y", "multilib"];
	for _ in 0..(iters() / 1000).max(50) {
		let mut conf = String::from("[options]\n");
		for _ in 0..rng.below(8) {
			conf.push_str(lines[rng.below(lines.len())]);
			conf.push('\n');
		}
		for _ in 0..rng.below(4) {
			conf.push_str(&format!("[{}]\n", names[rng.below(6)]));
			for _ in 0..rng.below(4) {
				conf.push_str(
					repo_lines[rng.below(repo_lines.len())],
				);
				conf.push('\n');
			}
		}
		let logmask = [3, 3, 1, 0][rng.below(4)];
		let mut p = setup_preset(&tree, logmask);
		p.op = [4, 5, 8][rng.below(3)];
		if rng.below(4) == 0 {
			p.assumeinstalled =
				vec![b"v=1".to_vec(), b"w".to_vec()];
		}
		setup_compare(&tree, &conf, &p);
	}
}
