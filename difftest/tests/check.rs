// pacman_cli::check (-Qk/-Qkk) and alpm_core::be_local's mtree reading
// against the C: fixture roots and local dbs under /tmp (desc, files,
// gzip'd mtree, install files), installed files randomly intact,
// missing or modified (content, size, mode, mtime, type swapped, link
// retargeted, unreadable, parents missing or blocked), checked by C
// check_pkg_fast/check_pkg_full on a real handle and by the port on the
// same fixture: stdout, stderr and return compared. the C mtree reader's
// entries are compared with alpm-mtree's on every fixture, odd inputs
// pin the divergences, the real local db's mtree files give counts
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_compress::compression::{
	CompressionEncoder, CompressionSettings, GzipCompressionLevel,
};
use alpm_core::be_local::{
	INFRQ_ALL, LocalDb, MtreeEntry, MtreeError, MtreeType, read_mtree,
};
use alpm_core::handle::Handle;
use alpm_core::package::Package;
use alpm_types::Sha256Checksum;
use difftest::{
	CCheck, CMtreeEntry, CheckWorld, Rng, iters, set_mtime_nofollow,
};
use pacman_cli::check::{HandleEnv, Output, check_pkg_fast, check_pkg_full};
use pacman_cli::conf::{ColStr, Config};

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
	let settings = CompressionSettings::Gzip {
		compression_level: GzipCompressionLevel::default(),
	};
	let path = std::env::temp_dir().join(format!(
		"difftest-check-gz-{}-{:?}",
		std::process::id(),
		std::thread::current().id()
	));
	let f = fs::File::create(&path).unwrap();
	let mut enc = CompressionEncoder::new(f, &settings).unwrap();
	enc.write_all(data).unwrap();
	enc.finish().unwrap();
	let out = fs::read(&path).unwrap();
	fs::remove_file(&path).unwrap();
	out
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
			db.populate().unwrap().iter().cloned().collect();
		for p in &mut pkgs {
			db.read(p, INFRQ_ALL).unwrap();
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
		let env = HandleEnv {
			handle: &self.handle,
			db: &self.db,
		};
		let mut o = Output::default();
		let pkg = self.pkg(name);
		let ret = if full {
			check_pkg_full(&mut o, cfg, &env, pkg)
		} else {
			check_pkg_fast(&mut o, cfg, &env, pkg)
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

// mode_t of the three types
fn filetype(k: MtreeType) -> u32 {
	match k {
		MtreeType::Dir => 0o040000,
		MtreeType::File => 0o100000,
		MtreeType::Link => 0o120000,
	}
}

// one C entry against one alpm-mtree entry: what check.c reads
fn entry_diff(c: &CMtreeEntry, r: &MtreeEntry) -> Vec<&'static str> {
	let mut d = Vec::new();
	if c.path != r.path {
		d.push("path");
	}
	if c.filetype != filetype(r.kind) {
		d.push("type");
	}
	if c.mode_perm != r.mode {
		d.push("mode");
	}
	if c.uid != i64::from(r.uid) || c.gid != i64::from(r.gid) {
		d.push("owner");
	}
	if c.mtime.map(|t| t.0) != Some(r.mtime) {
		d.push("mtime");
	}
	if r.kind == MtreeType::File {
		if c.size != i64::try_from(r.size).ok() {
			d.push("size");
		}
		let sha = r.sha256.as_ref().map(|s| s.inner().to_vec());
		if c.sha256.map(|s| s.to_vec()) != sha {
			d.push("sha256");
		}
		let md5 = r.md5.as_ref().map(|s| s.inner().to_vec());
		// unset md5 reads as zeros in libarchive
		let cmd5 = c.md5.filter(|m| m != &[0; 16]).map(|m| m.to_vec());
		if cmd5 != md5 {
			d.push("md5");
		}
	}
	if r.kind == MtreeType::Link && c.link != r.link {
		d.push("link");
	}
	d
}

fn entries_diff(c: &[CMtreeEntry], r: &[MtreeEntry]) -> Option<String> {
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
	// C: entries before mtree_next stopped (with its value); port:
	// entries parsed
	Entries(usize, i32),
	// port only: alpm-mtree rejects the data
	Rejected,
}

fn c_read(c: &Option<difftest::CMtree>) -> Read {
	match c {
		None => Read::NoMtree,
		Some(m) => Read::Entries(m.entries.len(), m.end),
	}
}

fn r_read(r: &Result<Vec<MtreeEntry>, MtreeError>) -> Read {
	match r {
		Ok(v) => Read::Entries(v.len(), 1),
		Err(MtreeError::Missing | MtreeError::Read(_)) => Read::NoMtree,
		Err(MtreeError::Parse(_)) => Read::Rejected,
	}
}

fn line(path: &str, props: &str) -> String {
	format!("{path} {props}\n")
}

// libarchive's mtree reader against alpm-mtree on inputs where they
// differ (plain and gzip'd): C and port result, and whether the entries
// both return agree (in order)
#[test]
fn mtree_divergences() {
	let set = "#mtree\n/set type=file uid=0 gid=0 mode=644\n";
	let f = |p: &str| {
		line(p, &format!("time=1.0 size=1 sha256digest={SHA_A}"))
	};
	let cases: Vec<(&str, String, Read, Read, bool)> = vec![
		// agreeing baseline: file, dir, link, md5, CRLF, no #mtree
		(
			"baseline",
			format!(
				"{set}{}./b type=dir time=2.0 mode=755\n\
			./c type=link link=a time=3.0 mode=777\n",
				f("./a")
			),
			Read::Entries(3, 1),
			Read::Entries(3, 1),
			true,
		),
		(
			"md5",
			format!("{set}./a time=1.0 size=1 md5digest={MD5_A} \
			sha256digest={SHA_A}\n"),
			Read::Entries(1, 1),
			Read::Entries(1, 1),
			true,
		),
		(
			"crlf",
			format!("{set}{}", f("./a")).replace('\n', "\r\n"),
			Read::Entries(1, 1),
			Read::Entries(1, 1),
			true,
		),
		(
			"no signature",
			format!(
				"/set type=file uid=0 gid=0 mode=644\n{}",
				f("./a")
			),
			Read::Entries(1, 1),
			Read::Entries(1, 1),
			true,
		),
		(
			"dot entry",
			"#mtree\n/set type=dir uid=0 gid=0 mode=755\n\
			. time=1.0\n./a time=1.0\n"
				.into(),
			Read::Entries(2, 1),
			Read::Entries(2, 1),
			true,
		),
		// alpm-mtree sorts by path (components): file order is lost
		(
			"unsorted",
			format!("{set}{}{}", f("./b"), f("./a")),
			Read::Entries(2, 1),
			Read::Entries(2, 1),
			false,
		),
		(
			"a-b before a/",
			format!(
				"{set}{}./a type=dir time=1.0\n{}",
				f("./a-b"),
				f("./a/b")
			),
			Read::Entries(3, 1),
			Read::Entries(3, 1),
			false,
		),
		// libarchive merges a repeated path into one entry
		(
			"duplicate",
			format!(
				"{set}{}./a time=5.0 size=2 \
			sha256digest={SHA_A}\n",
				f("./a")
			),
			Read::Entries(1, 1),
			Read::Entries(2, 1),
			false,
		),
		// "\#" kept verbatim by libarchive, decoded to '#' by alpm-mtree
		(
			"escaped #",
			format!("{set}{}", f("./h\\#x")),
			Read::Entries(1, 1),
			Read::Entries(1, 1),
			false,
		),
		// "size=+5": libarchive reads 0, alpm-mtree 5
		(
			"size sign",
			format!("{set}./a time=1.0 size=+5 \
			sha256digest={SHA_A}\n"),
			Read::Entries(1, 1),
			Read::Entries(1, 1),
			false,
		),
		// libarchive warns on uppercase hex digests and stops there
		(
			"uppercase sha256",
			format!(
				"{set}./a time=1.0 size=1 \
			sha256digest={}\n",
				SHA_A.to_uppercase()
			),
			Read::Entries(0, -1),
			Read::Entries(1, 1),
			false,
		),
		// an empty file is no mtree for libarchive (format bid fails)
		(
			"empty",
			String::new(),
			Read::NoMtree,
			Read::Entries(0, 1),
			false,
		),
		// read by libarchive, rejected whole by alpm-mtree
		(
			"no sha256",
			format!("{set}./a time=1.0 size=1\n"),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"no link",
			"#mtree\n/set type=link uid=0 gid=0 mode=777\n\
			./a time=1.0\n"
				.into(),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"no time",
			format!("{set}./a size=1 sha256digest={SHA_A}\n"),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"integer time",
			format!("{set}./a time=7 size=1 \
			sha256digest={SHA_A}\n"),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"negative time",
			format!("{set}./a time=-5.0 size=1 \
			sha256digest={SHA_A}\n"),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"no mode",
			format!(
				"#mtree\n/set type=file uid=0 gid=0\n{}",
				f("./a")
			),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"5-digit mode",
			format!("{set}./a time=1.0 size=1 mode=04755 \
			sha256digest={SHA_A}\n"),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"fifo",
			format!(
				"{set}{}./f type=fifo time=1.0\n{}",
				f("./a"),
				f("./z")
			),
			Read::Entries(3, 1),
			Read::Rejected,
			false,
		),
		(
			"nlink keyword",
			format!("{set}./b time=1.0 size=1 nlink=1 \
			sha256digest={SHA_A}\n"),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"non-UTF-8 name",
			format!("{set}{}", f("./\\377")),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"backslash escape",
			format!("{set}{}", f("./a\\\\b")),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"/unset all",
			format!("{set}/unset all\n./a type=file uid=0 \
			gid=0 mode=644 time=1.0 size=1 sha256digest={SHA_A}\n"),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"/set time",
			"#mtree\n/set type=dir uid=0 gid=0 mode=755 \
			time=1.0\n./a\n"
				.into(),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"relative v1 paths",
			"#mtree\n/set type=dir uid=0 gid=0 \
			mode=755\nusr time=1.0\nbin time=1.0\n..\n"
				.into(),
			Read::Entries(2, 1),
			Read::Rejected,
			false,
		),
		(
			"trailing spaces",
			format!("{set}./a time=1.0 size=1 \
			sha256digest={SHA_A}  \n"),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"1-digit mode",
			format!("{set}./a time=1.0 size=1 mode=0 \
			sha256digest={SHA_A}\n"),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
		(
			"uid past u32",
			format!(
				"#mtree\n/set type=file uid=4294967296 \
			gid=0 mode=644\n{}",
				f("./a")
			),
			Read::Entries(1, 1),
			Read::Rejected,
			false,
		),
	];
	for (name, text, want_c, want_r, same) in &cases {
		for gz in [false, true] {
			let data = if gz && !text.is_empty() {
				gzip(text.as_bytes())
			} else {
				text.clone().into_bytes()
			};
			let (c, r) = read_both(&data);
			assert_eq!(
				&c_read(&c),
				want_c,
				"{name} gz={gz} C {c:?}"
			);
			assert_eq!(
				&r_read(&r),
				want_r,
				"{name} gz={gz} rust {r:?}"
			);
			let diff = match (&c, &r) {
				(Some(c), Ok(r)) => entries_diff(&c.entries, r),
				_ => Some("not both read".into()),
			};
			assert_eq!(
				diff.is_none(),
				*same,
				"{name} gz={gz}: {diff:?}"
			);
		}
	}
	// only gzip and plain are read by alpm-mtree, libarchive takes any
	// filter: an xz'd mtree is read by the C only
	let text = format!("{set}{}", f("./a"));
	let xz = {
		let settings = CompressionSettings::Xz {
			compression_level: Default::default(),
		};
		let path = std::env::temp_dir().join(format!(
			"difftest-check-xz-{}",
			std::process::id()
		));
		let file = fs::File::create(&path).unwrap();
		let mut enc = CompressionEncoder::new(file, &settings).unwrap();
		enc.write_all(text.as_bytes()).unwrap();
		enc.finish().unwrap();
		let out = fs::read(&path).unwrap();
		fs::remove_file(&path).unwrap();
		out
	};
	let (c, r) = read_both(&xz);
	assert_eq!(c_read(&c), Read::Entries(1, 1));
	assert_eq!(r_read(&r), Read::Rejected, "{r:?}");
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
		// "." and ".." are no names on disk, alpm-db refuses a
		// whitespace-only backup path
		if s != "." && s != ".." && !s.trim().is_empty() {
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
		MtreeType::File => pick(rng, FILE_MODES),
		MtreeType::Link => 0o777,
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
		let kind = pick(
			rng,
			&[
				MtreeType::File,
				MtreeType::File,
				MtreeType::Link,
				MtreeType::Dir,
			],
		);
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
		MtreeType::Dir => "dir",
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
	let mode = if rng.below(2) == 0 {
		// alpm-mtree wants 3-4 digits
		format!("mode={:03o}", n.mode)
	} else {
		format!("mode={:04o}", n.mode)
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
		MtreeType::Dir => {}
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
	all.sort_by(|a, b| Path::new(&a.0).cmp(Path::new(&b.0)));
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
		panic!("alpm-mtree: {e:?}\n{what}");
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
];

fn node(rel: &str, kind: MtreeType, disk: Disk, me: (u32, u32)) -> Node {
	Node {
		rel: rel.into(),
		kind,
		content: b"hello\n".to_vec(),
		target: "t".into(),
		mode: match kind {
			MtreeType::Dir => 0o755,
			MtreeType::File => 0o644,
			MtreeType::Link => 0o777,
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

	// empty mtree file: no mtree for libarchive, no entries for alpm
	let nodes = [conf("a", Disk::Intact)];
	let files = files_text(&nodes, &[]);
	let (c, r) = full_both(&raw_pkg(&nodes, &files, ""));
	assert!(c.contains("p: no mtree file\n"), "{c}");
	assert!(r.contains("p: 0 total files, 0 altered files\n"), "{r}");

	// a fifo entry: the C checks the others and warns, alpm-mtree
	// rejects the file
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
	assert!(r.contains("p: 0 total files, 0 altered files\n"), "{r}");

	// a file entry without sha256: libarchive leaves a zero digest, the
	// C reports a mismatch (never "information not available")
	let mtree =
		format!("#mtree\n/set type=file uid={u} gid={g} mode=644\n\
		./a time={BASE_TIME}.0 size=6\n");
	let (c, r) = full_both(&raw_pkg(&nodes, &files, &mtree));
	assert!(c.contains("(SHA256 checksum mismatch)"), "{c}");
	assert!(r.contains("p: 0 total files, 0 altered files\n"), "{r}");

	// unsorted entries: same lines, the port's in path order
	let nodes = [conf("a", Disk::Missing), conf("b", Disk::Missing)];
	let files = files_text(&nodes, &[]);
	let mtree =
		format!("#mtree\n/set type=file uid={u} gid={g} mode=644\n\
		./b time=1.0 size=6 sha256digest={sha}\n\
		./a time=1.0 size=6 sha256digest={sha}\n");
	let (c, r) = full_both(&raw_pkg(&nodes, &files, &mtree));
	assert_ne!(c, r);
	let mut cl: Vec<&str> = c.lines().collect();
	let mut rl: Vec<&str> = r.lines().collect();
	cl.sort_unstable();
	rl.sort_unstable();
	assert_eq!(cl, rl);
}

// the mtree files of the real local db, read-only through a fixture db
// of symlinked package dirs: entries of both readers compared, counts
// printed. skipped without /var/lib/pacman/local
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
	let (mut same, mut order, mut differ, mut rejected) = (0, 0, 0, 0);
	for d in &dirs {
		// name-pkgver-pkgrel
		let mut parts = d.rsplitn(3, '-');
		let (rel, ver) = (parts.next().unwrap(), parts.next().unwrap());
		let name = parts.next().unwrap();
		let c = cw.mtree(name.as_bytes()).expect("C: no mtree");
		let path = fx.dbpath().join("local").join(d).join("mtree");
		let r = match read_mtree(&bytes(&path)) {
			Ok(r) => r,
			Err(e) => {
				rejected += 1;
				println!("rejected {name}-{ver}-{rel}: {e:?}");
				continue;
			}
		};
		if entries_diff(&c.entries, &r).is_none() {
			same += 1;
			continue;
		}
		let mut sorted = c.entries.clone();
		sorted.sort_by(|a, b| {
			use std::os::unix::ffi::OsStrExt;
			let p = |x: &[u8]| {
				Path::new(std::ffi::OsStr::from_bytes(x))
					.to_path_buf()
			};
			p(&a.path).cmp(&p(&b.path))
		});
		match entries_diff(&sorted, &r) {
			None => {
				if order == 0 {
					let i = c
						.entries
						.iter()
						.zip(&r)
						.position(|(a, b)| {
							a.path != b.path
						})
						.unwrap();
					println!(
						"order {name}: C {:?} rust {:?}",
						String::from_utf8_lossy(
							&c.entries[i].path
						),
						String::from_utf8_lossy(
							&r[i].path
						)
					);
				}
				order += 1
			}
			Some(d) => {
				differ += 1;
				println!("differ {name}: {d}");
			}
		}
	}
	println!(
		"{} mtree files: {same} same, {order} same after sorting, \
		{differ} differ, {rejected} rejected by alpm-mtree",
		dirs.len()
	);
	assert_eq!(same + order + differ + rejected, dirs.len());
}
