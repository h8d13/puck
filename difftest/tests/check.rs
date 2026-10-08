// pacman_cli::check (-Qk/-Qkk) and alpm_core::be_local's mtree reading
// against the C: fixture roots and local dbs under /tmp (desc, files,
// gzip'd mtree, install files), installed files randomly intact,
// missing or modified (content, size, mode, mtime, type swapped, link
// retargeted, unreadable, parents missing or blocked), checked by C
// check_pkg_fast/check_pkg_full on a real handle and by the port on the
// same fixture: stdout, stderr and return compared. libarchive's mtree
// reader is compared with alpm_core::mtree on every fixture, on odd
// inputs, cut streams and fuzzed mtree text (entries, where it stops and
// its error text), and on the real local db's mtree files
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_core::be_local::{
	INFRQ_ALL, LocalDb, MtreeEntry, MtreeError, MtreeType, read_mtree,
};
use alpm_core::handle::Handle;
use alpm_core::package::Package;
use alpm_types::Sha256Checksum;
use difftest::{
	CCheck, CMtreeEntry, CheckWorld, Comp, FILTERED, Rng, compress_bytes,
	iters, set_mtime_nofollow,
};
use pacman_cli::check::{HandleEnv, check_pkg_fast, check_pkg_full};
use pacman_cli::conf::{ColStr, Config};
use pacman_cli::util::Output;

// one fixture per iteration (files, two handles, sha256 of every file):
// far slower than string fuzz
fn fixture_iters() -> usize {
	(iters() / 50).max(100)
}

const BASE_TIME: i64 = 1_700_000_000;

// root/ and db/local/ under a fresh /tmp dir (or deep below it), removed
// on drop
struct Fixture {
	dir: PathBuf,
	base: PathBuf,
}

impl Fixture {
	fn new() -> Self {
		Self::nested(0)
	}

	// root and db below `depth` directories of 200 bytes
	fn nested(depth: usize) -> Self {
		static N: AtomicUsize = AtomicUsize::new(0);
		let n = N.fetch_add(1, Ordering::Relaxed);
		let id = std::process::id();
		let dir = std::env::temp_dir()
			.join(format!("difftest-check-{id}-{n}"));
		let mut base = dir.clone();
		for _ in 0..depth {
			base.push("r".repeat(200));
		}
		fs::create_dir_all(base.join("root")).unwrap();
		fs::create_dir_all(base.join("db/local")).unwrap();
		fs::write(base.join("db/local/ALPM_DB_VERSION"), "9\n")
			.unwrap();
		Fixture { dir, base }
	}

	fn root(&self) -> PathBuf {
		self.base.join("root")
	}

	fn dbpath(&self) -> PathBuf {
		self.base.join("db")
	}

	fn pkgdir(&self, name: &str, version: &str) -> PathBuf {
		self.base.join(format!("db/local/{name}-{version}"))
	}
}

// directories the fixture made unreadable or unsearchable are opened up
// again first, top down
fn unlock(dir: &Path) {
	let Ok(m) = fs::symlink_metadata(dir) else {
		return;
	};
	if !m.is_dir() {
		return;
	}
	let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
	if let Ok(rd) = fs::read_dir(dir) {
		for e in rd.flatten() {
			unlock(&e.path());
		}
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		unlock(&self.dir);
		fs::remove_dir_all(&self.dir).unwrap();
	}
}

const DESC: &str = "%NAME%\n{name}\n\n%VERSION%\n{version}\n\n\
	%BASE%\n{name}\n\n%DESC%\nA package\n\n%URL%\nhttps://example.org/\n\n\
	%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n\
	%INSTALLDATE%\n1700000001\n\n%PACKAGER%\nA B <a@b.org>\n\n\
	%SIZE%\n42\n\n%VALIDATION%\npgp\n\n";

fn gzip(data: &[u8]) -> Vec<u8> {
	compress_bytes(Comp::Gzip, data, false)
}

// one local db entry: files text (%FILES%/%BACKUP% body), the mtree file
// bytes (None: no mtree file), db copies of .INSTALL/.CHANGELOG
struct DbPkg {
	name: String,
	version: String,
	files: String,
	mtree: Option<Vec<u8>>,
	install: Option<Vec<u8>>,
	changelog: Option<Vec<u8>>,
}

fn write_pkg(fx: &Fixture, p: &DbPkg) {
	let dir = fx.pkgdir(&p.name, &p.version);
	fs::create_dir(&dir).unwrap();
	let desc = DESC
		.replace("{name}", &p.name)
		.replace("{version}", &p.version);
	fs::write(dir.join("desc"), desc).unwrap();
	fs::write(dir.join("files"), &p.files).unwrap();
	if let Some(m) = &p.mtree {
		fs::write(dir.join("mtree"), m).unwrap();
	}
	if let Some(i) = &p.install {
		fs::write(dir.join("install"), i).unwrap();
	}
	if let Some(c) = &p.changelog {
		fs::write(dir.join("changelog"), c).unwrap();
	}
}

fn bytes(p: &Path) -> Vec<u8> {
	use std::os::unix::ffi::OsStrExt;
	p.as_os_str().as_bytes().to_vec()
}

// the port's view of the fixture: handle, local db, loaded packages
struct RustSide {
	handle: Handle,
	db: LocalDb,
	pkgs: Vec<Package>,
}

impl RustSide {
	fn new(fx: &Fixture, noextract: &[Vec<u8>]) -> Self {
		let mut handle = Handle::initialize(
			&bytes(&fx.root()),
			&bytes(&fx.dbpath()),
		)
		.unwrap();
		handle.set_noextracts(noextract);
		let db = LocalDb::register(handle.dbpath()).unwrap();
		let mut pkgs: Vec<Package> =
			db.populate(&mut ()).unwrap().iter().cloned().collect();
		for p in &mut pkgs {
			db.read(p, INFRQ_ALL, &mut ()).unwrap();
		}
		RustSide { handle, db, pkgs }
	}

	fn pkg(&self, name: &str) -> &Package {
		self.pkgs
			.iter()
			.find(|p| p.name.as_deref() == Some(name.as_bytes()))
			.unwrap()
	}

	fn check(&self, name: &str, full: bool, cfg: &Config) -> CCheck {
		let mut env = HandleEnv {
			handle: &self.handle,
			db: &self.db,
		};
		let mut o = Output::default();
		let pkg = self.pkg(name);
		let ret = if full {
			check_pkg_full(&mut o, cfg, &mut env, pkg)
		} else {
			check_pkg_fast(&mut o, cfg, &mut env, pkg)
		};
		CCheck {
			ret,
			stdout: o.stdout,
			stderr: o.stderr,
		}
	}
}

fn config(quiet: bool, logmask: u16, colstr: ColStr<'static>) -> Config {
	let mut c = Config::new();
	c.quiet = u16::from(quiet);
	c.logmask = logmask;
	c.colstr = colstr;
	c
}

fn show(c: &CCheck) -> String {
	format!(
		"ret {}\n--- stdout\n{}--- stderr\n{}",
		c.ret,
		String::from_utf8_lossy(&c.stdout),
		String::from_utf8_lossy(&c.stderr)
	)
}

// both checks, quiet and not, both colour sets, on every package; the
// C outputs are appended to seen
fn assert_checks(
	fx: &Fixture,
	names: &[&str],
	noextract: &[Vec<u8>],
	what: &dyn Fn() -> String,
	seen: &mut Vec<u8>,
) {
	let cw = CheckWorld::open(&fx.root(), &fx.dbpath(), noextract);
	let rs = RustSide::new(fx, noextract);
	for name in names {
		for full in [false, true] {
			for (quiet, logmask, colstr) in [
				(false, 3, ColStr::PLAIN),
				(true, 3, ColStr::PLAIN),
				(false, 3, ColStr::COLOR),
				(false, 1, ColStr::PLAIN),
			] {
				let cfg = config(quiet, logmask, colstr);
				let c = if full {
					cw.full(
						name.as_bytes(),
						quiet,
						logmask,
						&colstr,
					)
				} else {
					cw.fast(
						name.as_bytes(),
						quiet,
						logmask,
						&colstr,
					)
				};
				let r = rs.check(name, full, &cfg);
				seen.extend(&c.stdout);
				seen.extend(&c.stderr);
				assert!(
					c == r,
					"{name} full={full} quiet={quiet} \
					logmask={logmask}\n== C\n{}\n== rust\n{}\n\
					== fixture\n{}",
					show(&c),
					show(&r),
					what()
				);
			}
		}
	}
}

// a digest as libarchive keeps it: unset reads as zeros
fn digest(d: Option<&[u8]>) -> Option<Vec<u8>> {
	d.filter(|d| d.iter().any(|&b| b != 0)).map(<[u8]>::to_vec)
}

// one C entry against one port entry: what check.c and
// build_filelist_from_mtree read
fn entry_diff(c: &CMtreeEntry, r: &MtreeEntry) -> Vec<&'static str> {
	let mut d = Vec::new();
	if c.path != r.path {
		d.push("path");
	}
	if c.filetype != r.kind.filetype() {
		d.push("type");
	}
	if c.mode_perm != r.mode {
		d.push("mode");
	}
	if c.uid != r.uid || c.gid != r.gid {
		d.push("owner");
	}
	// archive_entry_mtime is 0 when unset
	if c.mtime.map_or(0, |t| t.0) != r.mtime {
		d.push("mtime");
	}
	if c.size != i64::try_from(r.size).ok() {
		d.push("size");
	}
	let sha = r.sha256.as_ref().map(|s| s.inner());
	if digest(c.sha256.as_ref().map(|s| &s[..])) != digest(sha) {
		d.push("sha256");
	}
	let md5 = r.md5.as_ref().map(|s| s.inner());
	if digest(c.md5.as_ref().map(|s| &s[..])) != digest(md5) {
		d.push("md5");
	}
	if c.link != r.link {
		d.push("link");
	}
	d
}

// the C's entries against the port's up to the one the C stops at (the
// first libarchive warns about, pacman's -Qkk ends there: UPSTREAM.md)
fn entries_diff(c: &[CMtreeEntry], r: &[MtreeEntry]) -> Option<String> {
	let warned = r.iter().position(|e| e.warning.is_some());
	let r = &r[..warned.unwrap_or(r.len())];
	if c.len() != r.len() {
		return Some(format!("count C {} rust {}", c.len(), r.len()));
	}
	for (i, (ce, re)) in c.iter().zip(r).enumerate() {
		let d = entry_diff(ce, re);
		if !d.is_empty() {
			return Some(format!(
				"entry {i} {d:?}\nC {ce:?}\nR {re:?}"
			));
		}
	}
	None
}

// one-package fixture around an mtree text, the C and port readers
fn read_both(
	mtree: &[u8],
) -> (
	Option<difftest::CMtree>,
	Result<Vec<MtreeEntry>, MtreeError>,
) {
	let fx = Fixture::new();
	let p = DbPkg {
		name: "foo".into(),
		version: "1-1".into(),
		files: String::new(),
		mtree: Some(mtree.to_vec()),
		install: None,
		changelog: None,
	};
	write_pkg(&fx, &p);
	let cw = CheckWorld::open(&fx.root(), &fx.dbpath(), &[]);
	let c = cw.mtree(b"foo");
	let r = read_mtree(&bytes(&fx.pkgdir("foo", "1-1").join("mtree")));
	(c, r)
}

const SHA_A: &str =
	"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
const MD5_A: &str = "0cc175b9c0f1b6a831c399e269772661";

// what each reader makes of one input
#[derive(Debug, PartialEq)]
enum Read {
	// C: alpm_pkg_mtree_open NULL; port: MtreeError::Missing/Read
	NoMtree,
	// C: entries before mtree_next stopped, with its value; port: the
	// entries before the first warned one (-1) or all (1), none for data
	// it cannot parse (-1)
	Entries(usize, i32),
}

fn c_read(c: &Option<difftest::CMtree>) -> Read {
	match c {
		None => Read::NoMtree,
		Some(m) => Read::Entries(m.entries.len(), m.end),
	}
}

fn r_read(r: &Result<Vec<MtreeEntry>, MtreeError>) -> Read {
	match r {
		Ok(v) => match v.iter().position(|e| e.warning.is_some()) {
			Some(n) => Read::Entries(n, -1),
			None => Read::Entries(v.len(), 1),
		},
		Err(MtreeError::Missing | MtreeError::Read(_)) => Read::NoMtree,
		Err(MtreeError::Parse(_)) => Read::Entries(0, -1),
	}
}

// archive_error_string where the walk stopped: the warning of the entry
// it stopped at, read_mtree's error
fn r_text(r: &Result<Vec<MtreeEntry>, MtreeError>) -> Option<Vec<u8>> {
	match r {
		Ok(v) => v.iter().find_map(|e| e.warning.clone()),
		Err(MtreeError::Parse(t)) => Some(t.clone()),
		Err(_) => None,
	}
}

// both readers stop at the same place, with the same text, after the
// same entries
fn assert_same_read(
	c: &Option<difftest::CMtree>,
	r: &Result<Vec<MtreeEntry>, MtreeError>,
	what: &dyn Fn() -> String,
) {
	assert_eq!(c_read(c), r_read(r), "{}\nC {c:?}\nrust {r:?}", what());
	if let (Some(c), Ok(_) | Err(MtreeError::Parse(_))) = (c, r) {
		let (ct, rt) = (c.error.as_deref().map(lossy), r_text(r));
		let rt = rt.as_deref().map(lossy);
		assert_eq!(ct, rt, "{}", what());
	}
	if let (Some(c), Ok(r)) = (c, r) {
		let diff = entries_diff(&c.entries, r);
		assert!(diff.is_none(), "{diff:?}\n{}", what());
	}
}

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

fn line(path: &str, props: &str) -> String {
	format!("{path} {props}\n")
}

// libarchive's mtree reader against the port's on odd inputs (plain and
// gzip'd): the same entries in the same order, the same stop and text
#[test]
fn mtree_odd_inputs() {
	let set = "#mtree\n/set type=file uid=0 gid=0 mode=644\n";
	let f = |p: &str| {
		line(p, &format!("time=1.0 size=1 sha256digest={SHA_A}"))
	};
	let all = |n| Read::Entries(n, 1);
	let warned = |n| Read::Entries(n, -1);
	let long = |n: usize| format!("{set}./{} type=file\n", "a".repeat(n));
	let cases: Vec<(&str, String, Read)> = vec![
		(
			"baseline",
			format!(
				"{set}{}./b type=dir time=2.0 mode=755\n\
			./c type=link link=a time=3.0 mode=777\n",
				f("./a")
			),
			all(3),
		),
		(
			"md5",
			format!("{set}./a time=1.0 size=1 md5digest={MD5_A} \
			sha256digest={SHA_A}\n"),
			all(1),
		),
		(
			"crlf",
			format!("{set}{}", f("./a")).replace('\n', "\r\n"),
			all(1),
		),
		(
			"dot entry",
			"#mtree\n/set type=dir uid=0 gid=0 mode=755\n\
			. time=1.0\n./a time=1.0\n"
				.into(),
			all(2),
		),
		// file order, not path order
		("unsorted", format!("{set}{}{}", f("./b"), f("./a")), all(2)),
		(
			"a-b before a/",
			format!(
				"{set}{}./a type=dir time=1.0\n{}",
				f("./a-b"),
				f("./a/b")
			),
			all(3),
		),
		// a repeated path is one entry, later keywords win
		(
			"duplicate",
			format!(
				"{set}{}./b time=1.0\n./a time=5.0 size=2 \
			sha256digest={SHA_A}\n./\\141 type=dir\n./\\141\\0z uid=7\n",
				f("./a")
			),
			all(2),
		),
		(
			"duplicate without type",
			"#mtree\n./a type=dir\n./b uid=1\n./a uid=2\n".into(),
			warned(1),
		),
		("dot-dot name", "#mtree\n/set type=dir\nusr\n..\\0/x\nz\n".into(), all(2)),
		("escaped #", format!("{set}{}", f("./h\\#x")), all(1)),
		(
			"escapes",
			format!("{set}{}", f("./a\\\\b\\sc\\040\\x\\400\\0d")),
			all(1),
		),
		("non-UTF-8 name", format!("{set}{}", f("./\\377")), all(1)),
		(
			"size sign",
			format!("{set}./a time=1.0 size=+5 \
			sha256digest={SHA_A}\n"),
			all(1),
		),
		(
			"numbers",
			format!(
				"{set}./a time=-5.3 size=12x uid=-1 gid=99999999999 \
			mode=0100644\n./b time=99999999999999999999.5 mode=7777777\n\
			./c time=-99999999999999999999 uid=0x10 link=\n"
			),
			all(3),
		),
		("empty", String::new(), Read::NoMtree),
		("short", "./a\n".into(), Read::NoMtree),
		("signature only", "#mtree".into(), all(0)),
		// keywords libarchive does not require
		("no sha256", format!("{set}./a time=1.0 size=1\n"), all(1)),
		(
			"no link",
			"#mtree\n/set type=link uid=0 gid=0 mode=777\n\
			./a time=1.0\n"
				.into(),
			all(1),
		),
		(
			"no time",
			format!("{set}./a size=1 sha256digest={SHA_A}\n"),
			all(1),
		),
		(
			"integer time",
			format!("{set}./a time=7 size=1 \
			sha256digest={SHA_A}\n"),
			all(1),
		),
		(
			"no mode",
			format!(
				"#mtree\n/set type=file uid=0 gid=0\n{}",
				f("./a")
			),
			all(1),
		),
		(
			"5-digit mode",
			format!("{set}./a time=1.0 size=1 mode=04755 \
			sha256digest={SHA_A}\n"),
			all(1),
		),
		(
			"1-digit mode",
			format!("{set}./a time=1.0 size=1 mode=0 \
			sha256digest={SHA_A}\n"),
			all(1),
		),
		(
			"special files",
			format!(
				"{set}{}./f type=fifo time=1.0\n./c type=char\n\
				./b type=block\n{}",
				f("./a"),
				f("./z")
			),
			all(5),
		),
		(
			"dir and link sizes",
			format!(
				"{set}./d type=dir size=9\n./l type=link link=a \
				size=7\n"
			),
			all(2),
		),
		(
			"known keywords",
			format!(
				"{set}./b time=1.0 nlink=1 uname=root gname=root \
			flags=none inode=3 cksum=1 tags=x content=y device=5 \
			resdevice=native,1,2 nochange optional ignore \
			sha1digest={}\n",
				"a".repeat(40)
			),
			all(1),
		),
		(
			"device packs",
			format!(
				"{set}./a device=linux,1,2,\n./b device=freebsd,1,-65281\n\
			./c device=bsdos,1,2,3\n./d device=netbsd,4095,1048575\n\
			./e device=hpux,255,0xffffff\n./f device=native,4294967295,0\n\
			./g device=solaris,0x3fff,0x3ffff\n./h device=0x77\n"
			),
			all(8),
		),
		(
			"/unset all",
			format!("{set}/unset all\n./a type=file uid=0 \
			gid=0 mode=644 time=1.0 size=1 sha256digest={SHA_A}\n"),
			all(1),
		),
		(
			"/set time",
			"#mtree\n/set type=dir uid=0 gid=0 mode=755 \
			time=1.0\n./a\n"
				.into(),
			all(1),
		),
		(
			"relative v1 paths",
			"#mtree\n/set type=dir uid=0 gid=0 \
			mode=755\nusr time=1.0\nbin time=1.0\n..\nlib type=file\n\
			./x type=file\n..\n..\nz\nd\\057e\n..\ny\n"
				.into(),
			all(7),
		),
		(
			"whitespace",
			format!("{set}  ./a\ttime=1.0 size=1 \
			sha256digest={SHA_A}  \n\t# comment\n   \n"),
			all(1),
		),
		(
			"continuation",
			format!(
				"{set}./a time=1.0 \\\n size=1 sha256digest={SHA_A}\n\
				./b \\\r\n uid=3\n./c\\\\\n"
			),
			all(3),
		),
		(
			"last line without newline",
			format!("{set}{}./b type=dir", f("./a")),
			all(1),
		),
		(
			"uid past u32",
			format!(
				"#mtree\n/set type=file uid=4294967296 \
			gid=0 mode=644\n{}",
				f("./a")
			),
			all(1),
		),
		// no signature: libarchive guesses from the first lines
		(
			"no signature",
			format!(
				"/set type=file uid=0 gid=0 mode=644\n{}",
				f("./a")
			),
			all(1),
		),
		("no signature, one path", "./a type=file\n".into(), all(1)),
		(
			"no signature, three lines",
			"# c\n./a type=dir\n./b \\\n type=dir\n./c type=dir\n./d foo\n"
				.into(),
			warned(3),
		),
		("no signature, unknown keyword", "./a type=file foo=1\n".into(), Read::NoMtree),
		("no signature, text", "hello world\n".into(), Read::NoMtree),
		("no signature, /set only", "/set type=file\n".into(), Read::NoMtree),
		(
			"no signature, last line",
			"/unset all\n./a type=dir\n./b type=dir".into(),
			all(1),
		),
		// NetBSD's mtree -D: the path last
		(
			"form D",
			"type=dir uid=2 ./a\ntype=file ./a/b\n".into(),
			all(2),
		),
		("form D after signature", "#mtree\ntype=dir ./a\n".into(), all(1)),
		(
			"form D mixed",
			"type=dir ./a\n./b type=dir\n./c type=dir\n".into(),
			Read::NoMtree,
		),
		// libarchive warns: the C stops before that entry
		(
			"uppercase sha256",
			format!(
				"{set}{}./b time=1.0 size=1 sha256digest={}\n{}",
				f("./a"),
				SHA_A.to_uppercase(),
				f("./c")
			),
			warned(1),
		),
		(
			"short digest",
			format!("{set}./a time=1.0 md5digest=abc\n"),
			warned(0),
		),
		("unknown keyword", format!("{set}./a foo=1\n"), warned(0)),
		("no value", format!("{set}./a time=1.0 #x\n"), warned(0)),
		("two warnings", format!("{set}./a x y=1 z\n"), warned(0)),
		("unknown type", format!("{set}./a type=bogus\n"), warned(0)),
		("symbolic mode", format!("{set}./a mode=u+x\n"), warned(0)),
		("empty mode", format!("{set}./a mode=\n"), warned(0)),
		("no type", "#mtree\n./a uid=0\n".into(), warned(0)),
		(
			"device format",
			format!("{set}./a device=foo,1,2\n"),
			warned(0),
		),
		("device major", format!("{set}./a device=linux,256,1\n"), warned(0)),
		("device minor", format!("{set}./a device=sco,1,256\n"), warned(0)),
		("device fields", format!("{set}./a device=svr4,1,2,3\n"), warned(0)),
		("device missing", format!("{set}./a device=isc,1,,2\n"), warned(0)),
		("device few", format!("{set}./a device=4bsd,1\n"), warned(0)),
		("device many", format!("{set}./a device=bsdos,1,2,3,4\n"), warned(0)),
		("device unit", format!("{set}./a device=bsdos,1,4096,1\n"), warned(0)),
		("device native", format!("{set}./a device=native,1,4294967296\n"), warned(0)),
		("device netbsd", format!("{set}./a device=netbsd,1,1048576\n"), warned(0)),
		// libarchive cannot parse the file: no entries
		(
			"raw UTF-8 name",
			format!("{set}./a\u{e9} time=1.0\n"),
			warned(0),
		),
		(
			"control byte",
			format!("{set}./a time=1.0\x7f\n"),
			warned(0),
		),
		("inner CR", format!("{set}./a\r time=1.0\n"), warned(0)),
		(
			"unknown command",
			format!("{set}{}/foo\n", f("./a")),
			warned(0),
		),
		("/set alone", format!("{set}/set\n{}", f("./a")), warned(0)),
		("/unset value", format!("{set}/unset uid=0\n"), warned(0)),
		("line too long", long(65530), warned(0)),
		("line just short", long(65518), all(1)),
		// a nul: the rest of the data is one unended line
		(
			"nul",
			format!("{set}{}./b\0 type=dir\n{}", f("./a"), f("./c")),
			all(1),
		),
		(
			"nul, long rest",
			format!("{set}./a\0\n{}", "./b type=dir\n".repeat(6000)),
			warned(0),
		),
	];
	for (name, text, want) in &cases {
		for gz in [false, true] {
			let data = if gz && !text.is_empty() {
				gzip(text.as_bytes())
			} else {
				text.clone().into_bytes()
			};
			let (c, r) = read_both(&data);
			assert_eq!(&c_read(&c), want, "{name} gz={gz} C {c:?}");
			assert_same_read(&c, &r, &|| format!("{name} gz={gz}"));
		}
	}
	// every filter pacman reads, stacked ones too
	let text = format!("{set}{}", f("./a"));
	for comp in FILTERED {
		let data = compress_bytes(comp, text.as_bytes(), false);
		let (c, r) = read_both(&data);
		assert_eq!(c_read(&c), Read::Entries(1, 1), "{comp:?}");
		assert_same_read(&c, &r, &|| format!("{comp:?}"));
	}
	// a filter whose program is missing fails the open
	for magic in [&b"\x89LZO\x00\r\n\x1a\n"[..], b"LRZI\x00\x06"] {
		let data = [magic, text.as_bytes()].concat();
		let (c, r) = read_both(&data);
		assert_same_read(&c, &r, &|| format!("{magic:?}"));
	}
	// gzip members are read one after the other
	let parts = [format!("{set}{}", f("./a")), f("./b")];
	let data =
		[gzip(parts[0].as_bytes()), gzip(parts[1].as_bytes())].concat();
	let (c, r) = read_both(&data);
	assert_eq!(c_read(&c), Read::Entries(2, 1));
	assert_same_read(&c, &r, &|| "gzip members".into());
}

// a compressed mtree cut short, over several of libarchive's filter
// blocks: inside the first the C's open fails (no mtree), later the
// failed read is the end of the data (libarchive's readline)
#[test]
fn mtree_cuts() {
	let mut text =
		String::from("#mtree\n/set type=file uid=0 gid=0 mode=644\n");
	let mut rng = Rng::new(0x3e7_c07);
	for i in 0..6000 {
		let word: String = (0..rng.below(40))
			.map(|_| (b'a' + rng.below(26) as u8) as char)
			.collect();
		text.push_str(&line(
			&format!("./usr/{word}{i}"),
			&format!(
				"time={i}.0 size={} sha256digest={SHA_A}",
				rng.below(99999)
			),
		));
	}
	let mut seen = std::collections::BTreeSet::new();
	for comp in FILTERED {
		let data = compress_bytes(comp, text.as_bytes(), false);
		let len = data.len();
		let mut cuts: Vec<usize> = vec![1, 2, 10, 100];
		cuts.extend((1..32).map(|i| len * i / 32));
		cuts.extend((0..8).map(|_| rng.below(len)));
		cuts.extend([1, 4, 8, 9, 12, 20, 64].map(|d| len - d));
		for n in cuts {
			let (c, r) = read_both(&data[..n]);
			let what = || format!("{comp:?} cut at {n}/{len}");
			assert_same_read(&c, &r, &what);
			seen.insert(format!("{:?}", c_read(&c)));
		}
	}
	assert!(seen.len() >= 2, "{seen:?}");
}

// a path of the fuzzed mtree text: escapes the C decodes, full ("./",
// "/" inside, ".") or relative names, ".." now and then
fn fuzz_path(rng: &mut Rng, seen: &[String]) -> String {
	if !seen.is_empty() && rng.below(6) == 0 {
		return seen[rng.below(seen.len())].clone();
	}
	let piece = |rng: &mut Rng| -> String {
		match rng.below(16) {
			0 => "\\s".into(),
			1 => "\\#".into(),
			2 => "\\\\".into(),
			3 => format!("\\{:03o}", rng.below(256)),
			4 => pick(
				rng,
				&["\\x", "\\4", "\\0", "\\01", "\\a", "\\057"],
			)
			.into(),
			5 => "#".into(),
			6 => ".".into(),
			_ => (rng.pick(b"abcz019-_+=") as char).to_string(),
		}
	};
	let seg = |rng: &mut Rng| -> String {
		(0..1 + rng.below(3)).map(|_| piece(rng)).collect()
	};
	match rng.below(10) {
		0 => pick(rng, &["..", ".", "./.", "..\\0/", "\\056\\056"])
			.into(),
		1 | 2 => seg(rng),
		_ => {
			let mut p = String::from(".");
			for _ in 0..1 + rng.below(3) {
				p.push('/');
				p += &seg(rng);
			}
			p
		}
	}
}

fn fuzz_number(rng: &mut Rng) -> String {
	match rng.below(24) {
		0 => format!("-{}", rng.below(100)),
		1 => format!("+{}", rng.below(100)),
		2 => "99999999999999999999".into(),
		3 => format!("{}x", rng.below(100)),
		4 => String::new(),
		5 => format!("0x{:x}", rng.below(70000)),
		6 => format!("0{:o}", rng.below(70000)),
		_ => rng.below(70000).to_string(),
	}
}

fn fuzz_hex(rng: &mut Rng, len: usize) -> String {
	let n = match rng.below(40) {
		0 => len - 1,
		1 => len + 1,
		_ => len,
	};
	let alphabet: &[u8] = if rng.below(40) == 0 {
		b"0123456789ABCDEF"
	} else {
		b"0123456789abcdef"
	};
	(0..n).map(|_| rng.pick(alphabet) as char).collect()
}

// a device value: raw, or a format with major, minor and maybe more
fn fuzz_device(rng: &mut Rng) -> String {
	if rng.below(4) == 0 {
		return fuzz_number(rng);
	}
	let format = pick(
		rng,
		&[
			"linux", "native", "freebsd", "netbsd", "bsdos",
			"hpux", "solaris", "osf1", "foo", "", "Linux",
		],
	);
	let mut out = String::from(format);
	for _ in 0..rng.below(5) {
		out.push(',');
		match rng.below(6) {
			0 => {}
			1 => out += "4294967296",
			2 => out += &rng.below(1 << 20).to_string(),
			_ => out += &fuzz_number(rng),
		}
	}
	out
}

// one keyword of a path or /set line, mostly well formed
fn fuzz_keyword(rng: &mut Rng) -> String {
	match rng.below(25) {
		0..=3 => format!(
			"type={}",
			pick(
				rng,
				&[
					"dir", "file", "link", "file", "dir",
					"file", "dir", "link", "block", "char",
					"fifo", "bogus"
				]
			)
		),
		4 | 5 => format!("uid={}", fuzz_number(rng)),
		6 => format!("gid={}", fuzz_number(rng)),
		7 | 8 => match rng.below(8) {
			0 if rng.below(4) == 0 => {
				format!("mode={}", pick(rng, &["u+x", "", "9"]))
			}
			1 => format!(
				"mode=0{:o}",
				0o100000 | rng.below(0o7777)
			),
			_ => format!("mode={:o}", rng.below(0o10000)),
		},
		9 => format!("size={}", fuzz_number(rng)),
		10 | 11 => {
			let ns = match rng.below(4) {
				0 => String::new(),
				1 => format!(".{}", rng.below(1_000_000_000)),
				2 => format!(".{}", fuzz_number(rng)),
				_ => ".0".into(),
			};
			format!("time={}{ns}", fuzz_number(rng))
		}
		12 => format!("link={}", fuzz_path(rng, &[])),
		13 | 14 => format!(
			"{}={}",
			pick(rng, &["sha256digest", "sha256"]),
			fuzz_hex(rng, 64)
		),
		15 => format!(
			"{}={}",
			pick(rng, &["md5digest", "md5"]),
			fuzz_hex(rng, 32)
		),
		16 => format!("sha1digest={}", fuzz_hex(rng, 40)),
		17 => pick(
			rng,
			&[
				"nlink=2",
				"uname=root",
				"gname=wheel",
				"flags=uchg",
				"cksum=7",
				"inode=9",
				"tags=a,b",
				"content=x",
				"sha512=x",
				"rmd160=",
			],
		)
		.into(),
		18 => pick(rng, &["nochange", "optional", "ignore"]).into(),
		19 if rng.below(4) == 0 => {
			pick(rng, &["foo=1", "foo", "=x", "TYPE=dir"]).into()
		}
		20 => format!(
			"{}={}",
			pick(rng, &["device", "resdevice"]),
			fuzz_device(rng)
		),
		_ => format!("time={}.0", rng.below(5)),
	}
}

// words joined by the separators libarchive splits on
fn fuzz_join(rng: &mut Rng, words: &[String]) -> String {
	let mut out = String::new();
	for (i, w) in words.iter().enumerate() {
		if i > 0 {
			out += pick(
				rng,
				&[
					" ", " ", " ", "  ", "\t", " \\\n ",
					" \\\r\n ",
				],
			);
		}
		out += w;
	}
	out
}

// mtree text around the shapes bsdtar writes and the odd ones libarchive
// still reads, warns about or refuses
fn fuzz_mtree(rng: &mut Rng) -> Vec<u8> {
	// without signature libarchive guesses from the first lines
	// (detect_form), form D puts the path last
	let head = match rng.below(12) {
		0 => "",
		1 => "#x\n",
		2 => "#mtree v2.0\n",
		_ => "#mtree\n",
	};
	let mut out = String::from(head);
	let form_d = rng.below(8) == 0;
	if rng.below(3) != 0 {
		out += "/set type=file uid=0 gid=0 mode=644\n";
	}
	let mut seen = Vec::new();
	for _ in 0..rng.below(12) {
		let indent = pick(rng, &["", "", "", " ", "\t"]);
		let words = |rng: &mut Rng| -> Vec<String> {
			(0..rng.below(5)).map(|_| fuzz_keyword(rng)).collect()
		};
		let body = match rng.below(20) {
			0 => "# a comment \\#".into(),
			1 => String::new(),
			2 | 3 => {
				let mut w = vec!["/set".to_string()];
				w.extend(words(rng));
				fuzz_join(rng, &w)
			}
			4 => {
				let mut w = vec!["/unset".to_string()];
				for _ in 0..1 + rng.below(3) {
					w.push(pick(
						rng,
						&[
							"uid", "type", "mode",
							"time", "all",
						],
					)
					.into());
				}
				fuzz_join(rng, &w)
			}
			5 if rng.below(20) == 0 => pick(
				rng,
				&[
					"/foo",
					"/set",
					"/unset uid=0",
					"./a\u{e9}",
					"./a\x01",
					"./a\0b",
				],
			)
			.into(),
			_ => {
				let path = fuzz_path(rng, &seen);
				seen.push(path.clone());
				let mut w = words(rng);
				if form_d {
					w.push(path);
				} else {
					w.insert(0, path);
				}
				fuzz_join(rng, &w)
			}
		};
		out += indent;
		out += &body;
		if rng.below(10) == 0 {
			out += pick(rng, &[" ", "\t", "\r", "\\"]);
		}
		out.push('\n');
	}
	if rng.below(10) == 0 {
		out.pop();
	}
	out.into_bytes()
}

// fuzzed mtree text: the C's entries up to where it stops are the
// port's, with the same reason to stop and text
#[test]
fn fuzz_mtree_reader() {
	let mut rng = Rng::new(0x3a7e);
	let n = (iters() / 20).max(200);
	let (mut entries, mut warned, mut fatal, mut none) = (0, 0, 0, 0);
	for i in 0..n {
		let text = fuzz_mtree(&mut rng);
		let data = if rng.below(4) == 0 && !text.is_empty() {
			gzip(&text)
		} else {
			text.clone()
		};
		let (c, r) = read_both(&data);
		let what = || format!("iteration {i}\n{}", lossy(&text));
		assert_same_read(&c, &r, &what);
		match c_read(&c) {
			Read::Entries(k, 1) => entries += k,
			Read::Entries(0, _) if r.is_err() => fatal += 1,
			Read::Entries(_, _) => warned += 1,
			Read::NoMtree => none += 1,
		}
	}
	println!(
		"fuzz_mtree_reader: {n} texts, {entries} entries, {warned} \
		stopped at a warning, {fatal} refused, {none} not mtree"
	);
	assert!(entries * 2 > n && warned * 10 > n && fatal * 50 > n);
	assert!(none * 50 > n && none * 5 < n);
}

// one packaged path: what the mtree and files list say
#[derive(Clone, Debug)]
struct Node {
	// below the root, no "./", no trailing '/'
	rel: String,
	kind: MtreeType,
	content: Vec<u8>,
	target: String,
	mode: u32,
	uid: u32,
	gid: u32,
	mtime: i64,
	disk: Disk,
}

// what the fixture puts on disk for a node
#[derive(Clone, Copy, Debug, PartialEq)]
enum Disk {
	Intact,
	Missing,
	// replaced by another type
	AsFile,
	AsDir,
	AsLink,
	// same size, one byte changed
	Content,
	// one byte longer
	Grown,
	Mode(u32),
	Mtime(i64),
	Retarget,
}

const SEG: &[u8] = b"abcz019._-+@ #";

fn segment(rng: &mut Rng) -> String {
	loop {
		let mut s: String = (0..1 + rng.below(4))
			.map(|_| rng.pick(SEG) as char)
			.collect();
		if rng.below(12) == 0 {
			s.push('é');
		}
		// "." and ".." are no names on disk
		if s != "." && s != ".." {
			return s;
		}
	}
}

fn pick<T: Copy>(rng: &mut Rng, v: &[T]) -> T {
	v[rng.below(v.len())]
}

const DIR_MODES: &[u32] = &[0o755, 0o755, 0o700, 0o555, 0o2755, 0o1777, 0o644];
const FILE_MODES: &[u32] = &[
	0o644, 0o644, 0o755, 0o600, 0o4755, 0o2755, 0o1644, 0o444, 0o000,
];

fn gen_disk(rng: &mut Rng, kind: MtreeType) -> Disk {
	if rng.below(2) == 0 {
		return Disk::Intact;
	}
	let common = [
		Disk::Missing,
		Disk::AsFile,
		Disk::AsDir,
		Disk::AsLink,
		Disk::Mode(pick(rng, FILE_MODES)),
		Disk::Mtime(BASE_TIME + rng.below(3) as i64),
	];
	let mut v: Vec<Disk> = common
		.into_iter()
		.filter(|d| !same_type(*d, kind))
		.collect();
	match kind {
		MtreeType::File => v.extend([Disk::Content, Disk::Grown]),
		MtreeType::Link => v.push(Disk::Retarget),
		MtreeType::Dir => v.push(Disk::Mode(pick(rng, DIR_MODES))),
		MtreeType::Block | MtreeType::Char | MtreeType::Fifo => {}
	}
	pick(rng, &v)
}

fn same_type(d: Disk, kind: MtreeType) -> bool {
	matches!(
		(d, kind),
		(Disk::AsFile, MtreeType::File)
			| (Disk::AsDir, MtreeType::Dir)
			| (Disk::AsLink, MtreeType::Link)
	)
}

fn gen_node(
	rng: &mut Rng,
	rel: String,
	kind: MtreeType,
	me: (u32, u32),
) -> Node {
	let mode = match kind {
		MtreeType::Dir => pick(rng, DIR_MODES),
		MtreeType::Link => 0o777,
		_ => pick(rng, FILE_MODES),
	};
	let content: Vec<u8> =
		(0..rng.below(24)).map(|_| rng.next_u64() as u8).collect();
	let target = pick(rng, &["a", "../x", "/abs/t", "t t", "é", "#1"])
		.to_string();
	let owner = |rng: &mut Rng, mine: u32| {
		if rng.below(8) == 0 { 0 } else { mine }
	};
	Node {
		rel,
		kind,
		content,
		target,
		mode,
		uid: owner(rng, me.0),
		gid: owner(rng, me.1),
		mtime: BASE_TIME + rng.below(3) as i64,
		disk: gen_disk(rng, kind),
	}
}

// a tree: every parent of a path is a Dir node
fn gen_nodes(rng: &mut Rng, me: (u32, u32)) -> Vec<Node> {
	let mut nodes: Vec<Node> = Vec::new();
	for _ in 0..1 + rng.below(10) {
		let mut prefix = String::new();
		for _ in 0..rng.below(3) {
			let seg = segment(rng);
			let rel = format!("{prefix}{seg}");
			match nodes.iter().find(|n| n.rel == rel) {
				Some(n) if n.kind != MtreeType::Dir => break,
				Some(_) => {}
				None => nodes.push(gen_node(
					rng,
					rel.clone(),
					MtreeType::Dir,
					me,
				)),
			}
			prefix = format!("{rel}/");
		}
		let rel = format!("{prefix}{}", segment(rng));
		if nodes.iter().any(|n| n.rel == rel) {
			continue;
		}
		if !prefix.is_empty()
			&& !nodes.iter().any(|n| {
				n.kind == MtreeType::Dir
					&& format!("{}/", n.rel) == prefix
			}) {
			continue;
		}
		let kind = if rng.below(20) == 0 {
			pick(
				rng,
				&[
					MtreeType::Block,
					MtreeType::Char,
					MtreeType::Fifo,
				],
			)
		} else {
			pick(
				rng,
				&[
					MtreeType::File,
					MtreeType::File,
					MtreeType::Link,
					MtreeType::Dir,
				],
			)
		};
		nodes.push(gen_node(rng, rel, kind, me));
	}
	nodes.sort_by(|a, b| Path::new(&a.rel).cmp(Path::new(&b.rel)));
	nodes
}

// mtree path escaping as bsdtar writes it: octal for bytes outside
// '!'..'~' and for '#' and '\\', sometimes \s for a space
fn escape(rng: &mut Rng, s: &str) -> String {
	let mut out = String::new();
	for &b in s.as_bytes() {
		match b {
			b' ' if rng.below(2) == 0 => out.push_str("\\s"),
			b'#' | b'\\' => write!(out, "\\{b:03o}").unwrap(),
			b'!'..=b'~' => out.push(b as char),
			_ => write!(out, "\\{b:03o}").unwrap(),
		}
	}
	out
}

fn hex(b: &[u8]) -> String {
	b.iter().map(|x| format!("{x:02x}")).collect()
}

// /set defaults the entries may lean on
#[derive(Clone, Copy)]
struct Set {
	kind: MtreeType,
	uid: u32,
	gid: u32,
	mode: u32,
}

fn kind_str(k: MtreeType) -> &'static str {
	match k {
		MtreeType::Block => "block",
		MtreeType::Char => "char",
		MtreeType::Dir => "dir",
		MtreeType::Fifo => "fifo",
		MtreeType::File => "file",
		MtreeType::Link => "link",
	}
}

fn time_str(rng: &mut Rng, t: i64) -> String {
	if rng.below(2) == 0 {
		format!("{t}.0")
	} else {
		format!("{t}.{:09}", rng.below(1_000_000_000))
	}
}

// one entry: properties /set does not cover, the others sometimes
fn mtree_line(rng: &mut Rng, path: &str, n: &Node, set: &Set) -> String {
	let mut props: Vec<String> = Vec::new();
	let mut keep = |rng: &mut Rng, differs: bool, p: String| {
		if differs || rng.below(4) == 0 {
			props.push(p);
		}
	};
	keep(
		rng,
		n.kind != set.kind,
		format!("type={}", kind_str(n.kind)),
	);
	keep(rng, n.uid != set.uid, format!("uid={}", n.uid));
	keep(rng, n.gid != set.gid, format!("gid={}", n.gid));
	// bsdtar writes "%o", 1 to 4 digits
	let mode = match rng.below(3) {
		0 => format!("mode={:o}", n.mode),
		1 => format!("mode={:03o}", n.mode),
		_ => format!("mode={:04o}", n.mode),
	};
	keep(rng, n.mode != set.mode || n.mode < 0o100, mode);
	props.push(format!("time={}", time_str(rng, n.mtime)));
	match n.kind {
		MtreeType::File => {
			props.push(format!("size={}", n.content.len()));
			if rng.below(4) == 0 {
				let m = alpm_types::Md5Checksum::calculate_from(
					&n.content,
				);
				props.push(format!(
					"md5digest={}",
					hex(m.inner())
				));
			}
			let s = Sha256Checksum::calculate_from(&n.content);
			props.push(format!("sha256digest={}", hex(s.inner())));
		}
		MtreeType::Link => {
			let t = escape(rng, &n.target);
			props.push(format!("link={t}"));
		}
		_ => {}
	}
	// keyword order is free
	for i in (1..props.len()).rev() {
		props.swap(i, rng.below(i + 1));
	}
	format!("{path} {}\n", props.join(" "))
}

fn gen_set(rng: &mut Rng, me: (u32, u32)) -> Set {
	Set {
		kind: pick(
			rng,
			&[MtreeType::File, MtreeType::Dir, MtreeType::Link],
		),
		uid: pick(rng, &[0, me.0]),
		gid: pick(rng, &[0, me.1]),
		mode: pick(rng, &[0o644, 0o755, 0o777]),
	}
}

fn set_line(s: &Set) -> String {
	format!(
		"/set type={} uid={} gid={} mode={:o}\n",
		kind_str(s.kind),
		s.uid,
		s.gid,
		s.mode
	)
}

// package metadata entries the check skips, plus .INSTALL/.CHANGELOG
// nodes checked against the db copies
fn meta_nodes(rng: &mut Rng, me: (u32, u32)) -> Vec<Node> {
	let mut v = Vec::new();
	for name in
		[".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL", ".CHANGELOG"]
	{
		if rng.below(2) == 0 {
			let mut n =
				gen_node(rng, name.into(), MtreeType::File, me);
			// the db copies are written by the fixture, never swapped
			if !matches!(
				n.disk,
				Disk::Intact
					| Disk::Missing | Disk::Content | Disk::Grown
					| Disk::Mtime(_) | Disk::Mode(_)
			) {
				n.disk = Disk::Intact;
			}
			v.push(n);
		}
	}
	v
}

fn gen_mtree(rng: &mut Rng, nodes: &[Node], me: (u32, u32)) -> String {
	let mut all: Vec<(String, &Node)> =
		nodes.iter().map(|n| (format!("./{}", n.rel), n)).collect();
	// bsdtar's order (paths sorted), or any: the file order is kept
	all.sort_by(|a, b| Path::new(&a.0).cmp(Path::new(&b.0)));
	if rng.below(3) == 0 {
		for i in (1..all.len()).rev() {
			all.swap(i, rng.below(i + 1));
		}
	}
	let mut out = String::from("#mtree\n");
	let mut set = gen_set(rng, me);
	out.push_str(&set_line(&set));
	for (path, n) in all {
		if rng.below(8) == 0 {
			set = gen_set(rng, me);
			out.push_str(&set_line(&set));
		}
		let p = escape(rng, &path);
		out.push_str(&mtree_line(rng, &p, n, &set));
	}
	out
}

fn files_text(nodes: &[Node], backup: &[&Node]) -> String {
	let mut out = String::new();
	if nodes.is_empty() {
		return out;
	}
	out.push_str("%FILES%\n");
	for n in nodes {
		let slash = if n.kind == MtreeType::Dir { "/" } else { "" };
		writeln!(out, "{}{slash}", n.rel).unwrap();
	}
	out.push('\n');
	if !backup.is_empty() {
		out.push_str("%BACKUP%\n");
		for b in backup {
			writeln!(
				out,
				"{}\td41d8cd98f00b204e9800998ecf8427e",
				b.rel
			)
			.unwrap();
		}
		out.push('\n');
	}
	out
}

// creates n at p as its disk state says; false when nothing is there
fn create(n: &Node, p: &Path) -> bool {
	let kind = match n.disk {
		Disk::Missing => return false,
		Disk::AsFile => MtreeType::File,
		Disk::AsDir => MtreeType::Dir,
		Disk::AsLink => MtreeType::Link,
		_ => n.kind,
	};
	match kind {
		MtreeType::Dir => fs::create_dir(p).unwrap(),
		// a regular file in place of the special file: the check warns
		// about the type before it looks
		MtreeType::Block | MtreeType::Char | MtreeType::Fifo => {
			fs::write(p, b"").unwrap()
		}
		MtreeType::File => {
			let mut c = n.content.clone();
			match n.disk {
				Disk::Content if !c.is_empty() => c[0] ^= 1,
				Disk::Content | Disk::Grown => c.push(b'x'),
				_ => {}
			}
			fs::write(p, c).unwrap();
		}
		MtreeType::Link => {
			let t = if n.disk == Disk::Retarget {
				format!("{}~", n.target)
			} else {
				n.target.clone()
			};
			symlink(t, p).unwrap();
		}
	}
	true
}

// mtime then mode, children before parents (reverse path order): a
// parent without search permission would hide them
fn finish(n: &Node, p: &Path) {
	let mtime = match n.disk {
		Disk::Mtime(t) if t != n.mtime => t,
		Disk::Mtime(_) => n.mtime + 7,
		_ => n.mtime,
	};
	set_mtime_nofollow(p, mtime);
	let is_link = fs::symlink_metadata(p).unwrap().file_type().is_symlink();
	if is_link {
		return;
	}
	let mode = match n.disk {
		Disk::Mode(m) if m != n.mode => m,
		Disk::Mode(_) => n.mode ^ 0o20,
		_ => n.mode,
	};
	fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

fn build_root(root: &Path, nodes: &[Node]) {
	let mut made: Vec<(&Node, PathBuf)> = Vec::new();
	for n in nodes {
		// parents that are not real directories hold nothing
		let parent_ok = match n.rel.rfind('/') {
			None => true,
			Some(i) => made.iter().any(|(m, _)| {
				m.rel == n.rel[..i]
					&& fs::symlink_metadata(
						root.join(&m.rel),
					)
					.is_ok_and(|s| s.is_dir())
			}),
		};
		let p = root.join(&n.rel);
		if parent_ok && create(n, &p) {
			made.push((n, p));
		}
	}
	for (n, p) in made.iter().rev() {
		finish(n, p);
	}
}

// .INSTALL/.CHANGELOG nodes become the db copies in the package dir
fn build_db_copies(dir: &Path, meta: &[Node]) {
	for n in meta {
		let file = match n.rel.as_str() {
			".INSTALL" => "install",
			".CHANGELOG" => "changelog",
			_ => continue,
		};
		let p = dir.join(file);
		if create(n, &p) {
			finish(n, &p);
		}
	}
}

fn noextract(rng: &mut Rng, nodes: &[Node]) -> Vec<Vec<u8>> {
	if rng.below(3) != 0 {
		return Vec::new();
	}
	(0..1 + rng.below(2))
		.map(|_| {
			let n = &nodes[rng.below(nodes.len())];
			let p = match rng.below(5) {
				0 => "*".to_string(),
				1 => format!("!{}", n.rel),
				2 => format!(
					"{}*",
					&n.rel[..n.rel.len().min(1)]
				),
				_ => n.rel.clone(),
			};
			p.into_bytes()
		})
		.collect()
}

fn me(fx: &Fixture) -> (u32, u32) {
	let m = fs::metadata(&fx.dir).unwrap();
	(m.uid(), m.gid())
}

// both readers agree on the fixture's mtree, entry for entry
fn assert_same_mtree(fx: &Fixture, name: &str, version: &str, what: &str) {
	let cw = CheckWorld::open(&fx.root(), &fx.dbpath(), &[]);
	let c = cw.mtree(name.as_bytes()).expect("C: no mtree");
	assert_eq!(c.end, 1, "C stopped: {:?}\n{what}", c.error);
	let path = fx.pkgdir(name, version).join("mtree");
	let r = read_mtree(&bytes(&path)).unwrap_or_else(|e| {
		panic!("rust: {e:?}\n{what}");
	});
	if let Some(d) = entries_diff(&c.entries, &r) {
		panic!("{d}\n{what}");
	}
}

#[test]
fn fuzz_checks() {
	let mut rng = Rng::new(0xc0ffee);
	let n = fixture_iters();
	let mut hits = vec![0usize; COVERAGE.len()];
	for i in 0..n {
		let fx = Fixture::new();
		let me = me(&fx);
		let mut names = Vec::new();
		let mut all_nodes = Vec::new();
		let mut texts = Vec::new();
		for k in 0..1 + rng.below(2) {
			let name = format!("p{k}");
			let version = "1.0-1".to_string();
			let nodes: Vec<Node> = gen_nodes(&mut rng, me)
				.into_iter()
				// packages own disjoint top-level trees
				.filter(|n| {
					let top = |r: &str| {
						r.split('/')
							.next()
							.unwrap()
							.to_string()
					};
					!all_nodes.iter().any(|m: &Node| {
						top(&m.rel) == top(&n.rel)
					})
				})
				.collect();
			if nodes.is_empty() {
				continue;
			}
			let meta = meta_nodes(&mut rng, me);
			let mut entries = nodes.clone();
			entries.extend(meta.iter().cloned());
			let mtree = gen_mtree(&mut rng, &entries, me);
			let backup: Vec<&Node> = nodes
				.iter()
				.filter(|n| {
					n.kind != MtreeType::Dir
						&& rng.below(3) == 0
				})
				.collect();
			let p = DbPkg {
				name: name.clone(),
				version: version.clone(),
				files: files_text(&nodes, &backup),
				mtree: match rng.below(12) {
					0 => None,
					1 => Some(mtree.clone().into_bytes()),
					_ => Some(gzip(mtree.as_bytes())),
				},
				install: None,
				changelog: None,
			};
			write_pkg(&fx, &p);
			build_root(&fx.root(), &nodes);
			build_db_copies(&fx.pkgdir(&name, &version), &meta);
			texts.push(format!("{name}:\n{mtree}{}", p.files));
			if p.mtree.is_some() {
				assert_same_mtree(
					&fx,
					&name,
					&version,
					&texts.join("\n"),
				);
			}
			all_nodes.extend(nodes);
			names.push(name);
		}
		if names.is_empty() {
			continue;
		}
		let ne = noextract(&mut rng, &all_nodes);
		let refs: Vec<&str> =
			names.iter().map(String::as_str).collect();
		let mut seen = Vec::new();
		assert_checks(
			&fx,
			&refs,
			&ne,
			&|| {
				format!(
					"iteration {i}, noextract {ne:?}\n{}",
					texts.join("\n")
				)
			},
			&mut seen,
		);
		let seen = String::from_utf8_lossy(&seen);
		for (k, (msg, count)) in
			COVERAGE.iter().zip(&mut hits).enumerate()
		{
			let _ = k;
			*count += seen.matches(msg).count();
		}
	}
	// every message and both outcomes were compared, not just reached
	for (msg, count) in COVERAGE.iter().zip(&hits) {
		println!("{count:8} {msg}");
		assert!(*count > 0, "never seen: {msg}");
	}
}

const COVERAGE: &[&str] = &[
	"No such file or directory",
	"Permission denied",
	"Not a directory",
	"(File type mismatch)",
	"(UID mismatch)",
	"(GID mismatch)",
	"(Permissions mismatch)",
	"(Modification time mismatch)",
	"(Symlink path mismatch)",
	"(Size mismatch)",
	"(SHA256 checksum mismatch)",
	"(failed to calculate SHA256 checksum)",
	"backup file: ",
	": no mtree file",
	" 0 altered files",
	" 1 altered file\n",
	" 1 total file, ",
	" 0 missing files",
	" 1 missing file\n",
	"\x1b[1;33mwarning:",
	"/install (",
	"/changelog (",
	"file type not recognized: ",
];

fn node(rel: &str, kind: MtreeType, disk: Disk, me: (u32, u32)) -> Node {
	Node {
		rel: rel.into(),
		kind,
		content: b"hello\n".to_vec(),
		target: "t".into(),
		mode: match kind {
			MtreeType::Dir => 0o755,
			MtreeType::Link => 0o777,
			_ => 0o644,
		},
		uid: me.0,
		gid: me.1,
		mtime: BASE_TIME,
		disk,
	}
}

// one package "p" of these nodes (mtree gzip'd) on a fresh fixture
fn one_pkg(
	depth: usize,
	nodes: &[Node],
	backup: &[&str],
	meta: &[Node],
) -> (Fixture, String) {
	let fx = Fixture::nested(depth);
	let mut rng = Rng::new(7);
	let mut entries = nodes.to_vec();
	entries.extend(meta.iter().cloned());
	let mtree = gen_mtree(&mut rng, &entries, me(&fx));
	let backup: Vec<&Node> = nodes
		.iter()
		.filter(|n| backup.contains(&n.rel.as_str()))
		.collect();
	let p = DbPkg {
		name: "p".into(),
		version: "1-1".into(),
		files: files_text(nodes, &backup),
		mtree: Some(gzip(mtree.as_bytes())),
		install: None,
		changelog: None,
	};
	write_pkg(&fx, &p);
	build_root(&fx.root(), nodes);
	build_db_copies(&fx.pkgdir("p", "1-1"), meta);
	(fx, format!("{mtree}{}", p.files))
}

// name, nodes, backup paths, .INSTALL/.CHANGELOG nodes, NoExtract
type Case<'a> = (&'a str, Vec<Node>, Vec<&'a str>, Vec<Node>, Vec<&'a str>);

// cases the fuzz rarely or never builds: errno texts (ELOOP,
// ENAMETOOLONG), paths past PATH_MAX, NoExtract on db copies
#[test]
fn fixed_checks() {
	let me = {
		let fx = Fixture::new();
		me(&fx)
	};
	use MtreeType::{Dir, File, Link};
	let mut cases: Vec<Case> = Vec::new();
	// a symlink to itself in place of a directory: ELOOP below it
	let mut loop_dir = node("a", Dir, Disk::AsLink, me);
	loop_dir.target = "a".into();
	cases.push((
		"symlink loop",
		vec![loop_dir, node("a/b", File, Disk::Intact, me)],
		vec![],
		vec![],
		vec![],
	));
	cases.push((
		"name too long",
		vec![node(&"y".repeat(256), File, Disk::Missing, me)],
		vec![],
		vec![],
		vec![],
	));
	// with a root of about 3300 bytes, a chain of 200-byte directories
	// past PATH_MAX, nothing on disk. files list lines stay below the
	// 1023 bytes the C reads whole
	let mut deep = Vec::new();
	let mut rel = String::new();
	for _ in 0..5 {
		if !rel.is_empty() {
			rel.push('/');
		}
		rel.push_str(&"d".repeat(200));
		deep.push(node(&rel, Dir, Disk::Missing, me));
	}
	cases.push(("past PATH_MAX", deep, vec![], vec![], vec![]));
	// every check passes
	cases.push((
		"intact",
		vec![
			node("etc", Dir, Disk::Intact, me),
			node("etc/x.conf", File, Disk::Intact, me),
			node("l", Link, Disk::Intact, me),
		],
		vec!["etc/x.conf"],
		vec![node(".INSTALL", File, Disk::Intact, me)],
		vec![],
	));
	// modified backup file: notes, not warnings
	cases.push((
		"backup modified",
		vec![
			node("etc", Dir, Disk::Intact, me),
			node("etc/x.conf", File, Disk::Grown, me),
			node(
				"etc/y.conf",
				File,
				Disk::Mtime(BASE_TIME + 1),
				me,
			),
		],
		vec!["etc/x.conf", "etc/y.conf"],
		vec![],
		vec![],
	));
	// NoExtract: matched missing files are skipped, "*" also hides a
	// missing .INSTALL db copy (matched at the root length into the
	// dbpath string)
	cases.push((
		"noextract",
		vec![
			node("a", File, Disk::Missing, me),
			node("b", File, Disk::Missing, me),
		],
		vec![],
		vec![node(".INSTALL", File, Disk::Missing, me)],
		vec!["a", "*"],
	));
	cases.push((
		"noextract negated",
		vec![node("a", File, Disk::Missing, me)],
		vec![],
		vec![],
		vec!["a", "!a"],
	));
	for (name, nodes, backup, meta, ne) in cases {
		let depth = if name == "past PATH_MAX" { 16 } else { 0 };
		let (fx, text) = one_pkg(depth, &nodes, &backup, &meta);
		let ne: Vec<Vec<u8>> =
			ne.iter().map(|s| s.as_bytes().to_vec()).collect();
		let mut seen = Vec::new();
		assert_checks(
			&fx,
			&["p"],
			&ne,
			&|| format!("{name}\n{text}"),
			&mut seen,
		);
		let seen = String::from_utf8_lossy(&seen);
		let want = match name {
			"symlink loop" => "Too many levels of symbolic links",
			"name too long" => "File name too long",
			"past PATH_MAX" => "path too long: ",
			"intact" => "p: 3 total files, 0 missing files",
			"backup modified" => "backup file: p: ",
			"noextract" => "p: 3 total files, 0 altered files",
			_ => "p: 1 total file, 1 missing file",
		};
		assert!(seen.contains(want), "{name}: {want:?} not in\n{seen}");
	}
}

// one package "p" with a given files text and mtree, its root from nodes
fn raw_pkg(nodes: &[Node], files: &str, mtree: &str) -> Fixture {
	let fx = Fixture::new();
	let p = DbPkg {
		name: "p".into(),
		version: "1-1".into(),
		files: files.into(),
		mtree: Some(mtree.as_bytes().to_vec()),
		install: None,
		changelog: None,
	};
	write_pkg(&fx, &p);
	build_root(&fx.root(), nodes);
	fx
}

fn full_both(fx: &Fixture) -> (String, String) {
	let cw = CheckWorld::open(&fx.root(), &fx.dbpath(), &[]);
	let rs = RustSide::new(fx, &[]);
	let cfg = config(false, 3, ColStr::PLAIN);
	let c = cw.full(b"p", false, 3, &ColStr::PLAIN);
	let r = rs.check("p", true, &cfg);
	(show(&c), show(&r))
}

// -Qkk on a backup entry with hash "(null)": still a backup file, its
// change is noted, not warned about
#[test]
fn null_backup_hash() {
	let fx = Fixture::new();
	let me = me(&fx);
	let mut rng = Rng::new(3);
	let nodes = [
		node("etc", MtreeType::Dir, Disk::Intact, me),
		node("etc/x.conf", MtreeType::File, Disk::Grown, me),
	];
	let mtree = gen_mtree(&mut rng, &nodes, me);
	let files =
		"%FILES%\netc/\netc/x.conf\n\n%BACKUP%\netc/x.conf\t(null)\n\n";
	let (c, r) = full_both(&raw_pkg(&nodes, files, &mtree));
	assert!(c.contains("backup file: p: ") && c.contains("ret 0"), "{c}");
	assert_eq!(c, r);
}

// -Qkk where the readers differ: pinned C and port outputs
#[test]
fn check_divergences() {
	let me = {
		let fx = Fixture::new();
		me(&fx)
	};
	let conf = |rel: &str, disk: Disk| node(rel, MtreeType::File, disk, me);

	// read alike: empty mtree file, a fifo entry, file order
	let nodes = [conf("a", Disk::Intact)];
	let files = files_text(&nodes, &[]);
	let (c, r) = full_both(&raw_pkg(&nodes, &files, ""));
	assert!(c.contains("p: no mtree file\n"), "{c}");
	assert_eq!(c, r);

	let sha = hex(Sha256Checksum::calculate_from(b"hello\n").inner());
	let (u, g) = me;
	let mtree =
		format!("#mtree\n/set type=file uid={u} gid={g} mode=644\n\
		./a time={BASE_TIME}.0 size=6 sha256digest={sha}\n\
		./f type=fifo time=1.0\n");
	// a regular file stands where the fifo is listed
	let with_f = [conf("a", Disk::Intact), conf("f", Disk::Intact)];
	let (c, r) = full_both(&raw_pkg(&with_f, &files, &mtree));
	assert!(c.contains("file type not recognized: "), "{c}");
	assert!(c.contains("p: 2 total files, 0 altered files\n"), "{c}");
	assert_eq!(c, r);

	let unsorted = [conf("a", Disk::Missing), conf("b", Disk::Missing)];
	let mtree =
		format!("#mtree\n/set type=file uid={u} gid={g} mode=644\n\
		./b time=1.0 size=6 sha256digest={sha}\n\
		./a time=1.0 size=6 sha256digest={sha}\n");
	let files_ab = files_text(&unsorted, &[]);
	let (c, r) = full_both(&raw_pkg(&unsorted, &files_ab, &mtree));
	assert!(c.find("/b ").unwrap() < c.find("/a ").unwrap(), "{c}");
	assert_eq!(c, r);

	// a file entry without sha256: libarchive leaves a zero digest, the
	// C reports a mismatch, never "information not available" (UPSTREAM.md)
	let mtree =
		format!("#mtree\n/set type=file uid={u} gid={g} mode=644\n\
		./a time={BASE_TIME}.0 size=6\n");
	let (c, r) = full_both(&raw_pkg(&nodes, &files, &mtree));
	assert!(c.contains("(SHA256 checksum mismatch)"), "{c}");
	assert!(
		r.contains("(SHA256 checksum information not available)"),
		"{r}"
	);

	// an entry libarchive warns about (uppercase digest): the C stops
	// there and prints totals as if done (UPSTREAM.md), the port checks
	// it and goes on
	let mtree = format!(
		"#mtree\n/set type=file uid={u} gid={g} mode=644\n\
		./a time={BASE_TIME}.0 size=6 sha256digest={sha}\n\
		./f time={BASE_TIME}.0 size=6 sha256digest={}\n\
		./g time={BASE_TIME}.0 size=6 sha256digest={sha}\n",
		sha.to_uppercase()
	);
	let fg = [
		conf("a", Disk::Intact),
		conf("f", Disk::Intact),
		conf("g", Disk::Intact),
	];
	let files_fg = files_text(&fg, &[]);
	let (c, r) = full_both(&raw_pkg(&fg, &files_fg, &mtree));
	assert!(c.contains("p: 1 total file, 0 altered files\n"), "{c}");
	assert!(r.contains("p: 3 total files, 1 altered file\n"), "{r}");
	assert!(r.contains("/f (SHA256 checksum information not available)"));
}

// the mtree files of the real local db, read-only through a fixture db
// of symlinked package dirs: both readers compared, entries in order.
// skipped without /var/lib/pacman/local
#[test]
fn real_local_mtrees() {
	let real = Path::new("/var/lib/pacman/local");
	let Ok(rd) = fs::read_dir(real) else {
		return;
	};
	let fx = Fixture::new();
	let mut dirs = Vec::new();
	for e in rd.flatten() {
		let p = e.path();
		if p.join("mtree").exists() {
			let name = e.file_name().into_string().unwrap();
			symlink(&p, fx.dbpath().join("local").join(&name))
				.unwrap();
			dirs.push(name);
		}
	}
	let cw = CheckWorld::open(&fx.root(), &fx.dbpath(), &[]);
	let (mut entries, mut stopped) = (0, 0);
	for d in &dirs {
		// name-pkgver-pkgrel
		let name = d.rsplitn(3, '-').nth(2).unwrap();
		let c = cw.mtree(name.as_bytes());
		let path = fx.dbpath().join("local").join(d).join("mtree");
		let r = read_mtree(&bytes(&path));
		assert_same_read(&c, &r, &|| d.clone());
		match c_read(&c) {
			Read::Entries(k, 1) => entries += k,
			_ => stopped += 1,
		}
	}
	println!(
		"{} mtree files, {entries} entries, {stopped} stopped early",
		dirs.len()
	);
}
