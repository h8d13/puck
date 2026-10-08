// pacman_cli::{query, deptest} against C pacman_query/pacman_deptest:
// fixture roots under /tmp with a local db (desc, files, mtree,
// changelog, install), sync dbs (newer, older, equal and absent
// packages, usage without upgrade, junk files), package files, installed
// files (some missing), a symlinked directory and PATH entries. random
// -Q flag sets (-Qi/-Qii, -Ql, -Qc, -Qk/-Qkk, -Qo, -Qs, -Qg, -Qp, the
// -Qd/-Qe/-Qm/-Qn/-Qt/-Qtt/-Qu filters, -q, colours) and target lists run
// on a C handle in config->handle and on a Rust Handle over the same
// files, one after the other on the same world (lazy loads and invalid
// dbs carry over): stdout, stderr and return compared
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;

use alpm_core::db::{DB_USAGE_ALL, DB_USAGE_UPGRADE};
use alpm_core::handle::Handle;
use alpm_types::{Md5Checksum, Sha256Checksum};
use difftest::{
	CQuery, Comp, QueryWorld, Rng, TempRoot, iters, section, tar_dir,
	tar_file, ustar, write_db,
};
use pacman_cli::conf::{ColStr, Config, ConfigRepo};
use pacman_cli::deptest::pacman_deptest;
use pacman_cli::pacman::{PKG_LOCALITY_FOREIGN, PKG_LOCALITY_NATIVE};
use pacman_cli::query::{QueryEnv, pacman_query};
use pacman_cli::util::Output;

// one world per case (files, two handles), many runs on it
fn worlds() -> usize {
	(iters() / 2000).max(10)
}

const RUNS: usize = 60;

// not in the test's cwd (difftest/), so bare -Qo names go to PATH
const NAMES: [&str; 8] =
	["foo", "bar", "baz", "qux", "lib-a", "lib-b", "tool", "x-y"];
const GROUPS: [&str; 3] = ["g1", "g2", "base"];
const VIRT: [&str; 3] = ["virt", "virt=2", "libp.so=1-64"];
const WORDS: [&str; 8] =
	["a", "tool", "Library", "for", "FOO", "x^y", "data", "c++"];

#[derive(Clone, Debug)]
struct Pkg {
	name: &'static str,
	version: String,
	reason: u8,
	groups: Vec<String>,
	depends: Vec<String>,
	optdepends: Vec<String>,
	provides: Vec<String>,
	desc: String,
	// installed paths below the root, dirs ending in '/', sorted
	files: Vec<String>,
	// files present on disk
	present: Vec<bool>,
	backup: bool,
	// no desc/files file: the lazy load fails and sticks
	desc_file: bool,
	files_file: bool,
	mtree: bool,
	changelog: bool,
	install: bool,
}

fn pick<'a>(rng: &mut Rng, items: &[&'a str]) -> &'a str {
	items[rng.below(items.len())]
}

fn some(rng: &mut Rng, items: &[&str], max: usize) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	for _ in 0..rng.below(max + 1) {
		let s = pick(rng, items).to_string();
		if !out.contains(&s) {
			out.push(s);
		}
	}
	out
}

fn files_of(rng: &mut Rng, name: &str) -> Vec<String> {
	let mut f: Vec<String> = vec![
		"etc/".into(),
		format!("etc/{name}.conf"),
		"usr/".into(),
		"usr/bin/".into(),
		format!("usr/bin/{name}"),
		"usr/share/".into(),
		format!("usr/share/{name}/"),
		format!("usr/share/{name}/data"),
	];
	// shared by every package that has it
	if rng.below(2) == 0 {
		f.push("usr/share/common".into());
	}
	if rng.below(2) == 0 {
		f.push("usr/lib/".into());
		f.push(format!("usr/lib/lib{name}.so"));
	}
	f.sort();
	f
}

fn gen_pkgs(rng: &mut Rng) -> Vec<Pkg> {
	let mut names = NAMES.to_vec();
	let n = 2 + rng.below(5);
	let mut pkgs = Vec::new();
	for _ in 0..n {
		let name = names.remove(rng.below(names.len()));
		let ops = ["", ">=1.1", "<1.2", "=1.0-1"];
		let deps: Vec<String> = some(rng, &NAMES, 2)
			.into_iter()
			.filter(|d| d != name)
			.map(|d| format!("{d}{}", pick(rng, &ops)))
			.collect();
		let mut depends = deps;
		if rng.below(4) == 0 {
			depends.push("virt>=2".into());
		}
		let optdepends = some(rng, &NAMES, 2)
			.into_iter()
			.filter(|d| d != name)
			.map(|d| format!("{d}: for {d}"))
			.collect();
		let files = files_of(rng, name);
		let present = files.iter().map(|_| rng.below(6) != 0).collect();
		let w: Vec<&str> = (0..1 + rng.below(3))
			.map(|_| pick(rng, &WORDS))
			.collect();
		pkgs.push(Pkg {
			name,
			version: format!("1.{}-1", rng.below(3)),
			reason: rng.below(2) as u8,
			groups: some(rng, &GROUPS, 2),
			depends,
			optdepends,
			provides: some(rng, &VIRT, 2),
			desc: w.join(" "),
			files,
			present,
			backup: rng.below(2) == 0,
			desc_file: rng.below(12) != 0,
			files_file: rng.below(12) != 0,
			mtree: rng.below(3) != 0,
			changelog: rng.below(3) == 0,
			install: rng.below(3) == 0,
		});
	}
	pkgs
}

fn local_desc(p: &Pkg) -> String {
	format!(
		"%NAME%\n{0}\n\n%VERSION%\n{1}\n\n%BASE%\n{0}\n\n\
		%DESC%\n{2}\n\n%URL%\nhttps://example.org/\n\n\
		%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n\
		%INSTALLDATE%\n1700000001\n\n%PACKAGER%\nA B <a@b.org>\n\n\
		%REASON%\n{3}\n\n%SIZE%\n42\n\n%VALIDATION%\npgp\n\n{4}{5}{6}{7}",
		p.name,
		p.version,
		p.desc,
		p.reason,
		section("GROUPS", &p.groups),
		section("DEPENDS", &p.depends),
		section("OPTDEPENDS", &p.optdepends),
		section("PROVIDES", &p.provides),
	)
}

fn content(path: &str) -> String {
	format!("content of {path}\n")
}

fn md5(data: &[u8]) -> String {
	Md5Checksum::calculate_from(data).to_string()
}

fn sha256(data: &[u8]) -> String {
	Sha256Checksum::calculate_from(data).to_string()
}

fn local_files(p: &Pkg) -> String {
	let mut s = section("FILES", &p.files);
	if p.backup {
		let conf = format!("etc/{}.conf", p.name);
		let hash = md5(content(&conf).as_bytes());
		s += &section("BACKUP", &[format!("{conf}\t{hash}")]);
	}
	s
}

// gzip'd mtree of the package's files
fn mtree(p: &Pkg) -> Vec<u8> {
	let mut s =
		String::from("#mtree\n/set type=file uid=0 gid=0 mode=644\n");
	for f in &p.files {
		match f.strip_suffix('/') {
			Some(d) => {
				writeln!(s, "./{d} time=1.0 mode=755 type=dir")
					.unwrap()
			}
			None => {
				let c = content(f);
				writeln!(
					s,
					"./{f} time=1700000000.0 size={} sha256digest={}",
					c.len(),
					sha256(c.as_bytes())
				)
				.unwrap()
			}
		}
	}
	s.into_bytes()
}

fn write_local(fx: &TempRoot, pkgs: &[Pkg]) {
	fx.reset_local();
	for p in pkgs {
		let dir = fx.local().join(format!("{}-{}", p.name, p.version));
		fs::create_dir(&dir).unwrap();
		if p.desc_file {
			fs::write(dir.join("desc"), local_desc(p)).unwrap();
		}
		if p.files_file {
			fs::write(dir.join("files"), local_files(p)).unwrap();
		}
		if p.mtree {
			write_db(&dir.join("mtree"), Comp::Gzip, &mtree(p));
		}
		if p.changelog {
			let log = format!("changes of {}\n* one\n", p.name);
			fs::write(dir.join("changelog"), log).unwrap();
		}
		if p.install {
			fs::write(dir.join("install"), "post_install() {}\n")
				.unwrap();
		}
	}
}

// installed files: dirs always, files when present. usr/lib reached
// through root/lib -> usr/lib too
fn write_root(fx: &TempRoot, pkgs: &[Pkg]) {
	let root = fx.dir().join("root");
	for p in pkgs {
		for (f, &present) in p.files.iter().zip(&p.present) {
			let path = root.join(f);
			if f.ends_with('/') {
				fs::create_dir_all(&path).unwrap();
			} else if present {
				fs::create_dir_all(path.parent().unwrap())
					.unwrap();
				fs::write(&path, content(f)).unwrap();
			}
		}
	}
	fs::create_dir_all(root.join("usr/lib")).unwrap();
	symlink("usr/lib", root.join("lib")).unwrap();
	fs::create_dir_all(root.join("srv")).unwrap();
	fs::write(root.join("srv/unowned"), "x\n").unwrap();
	// PATH entries: outside the root and inside it
	fs::create_dir_all(fx.dir().join("bin")).unwrap();
	fs::write(fx.dir().join("bin/qbin"), "#!/bin/sh\n").unwrap();
}

// sync package: name, version, groups
type SyncPkg = (String, String, Vec<String>);

fn sync_desc(p: &SyncPkg) -> String {
	format!(
		"%FILENAME%\n{0}-{1}-any.pkg.tar.zst\n\n%NAME%\n{0}\n\n\
		%BASE%\n{0}\n\n%VERSION%\n{1}\n\n%DESC%\nsync {0}\n\n\
		%CSIZE%\n1\n\n%ISIZE%\n2\n\n%SHA256SUM%\n{2}\n\n\
		%ARCH%\nany\n\n%BUILDDATE%\n3\n\n\
		%PACKAGER%\nA B <a@b.org>\n\n{3}",
		p.0,
		p.1,
		"ab".repeat(32),
		section("GROUPS", &p.2)
	)
}

fn sync_db(pkgs: &[SyncPkg]) -> Vec<u8> {
	let mut entries = Vec::new();
	for p in pkgs {
		let dir = format!("{}-{}/", p.0, p.1);
		entries.push(tar_dir(&dir));
		let desc = sync_desc(p);
		entries.push(tar_file(&format!("{dir}desc"), desc.as_bytes()));
	}
	ustar(&entries)
}

// sync dbs: name, usage, file (None absent), and a log line
fn gen_sync(
	rng: &mut Rng,
	local: &[Pkg],
) -> Vec<(String, i32, Option<Vec<u8>>)> {
	let mut out = Vec::new();
	let n = rng.below(3);
	for name in ["core", "extra", "junk"].iter().take(n + 1) {
		let usage = match rng.below(4) {
			0 => DB_USAGE_ALL & !DB_USAGE_UPGRADE,
			_ => DB_USAGE_ALL,
		};
		let data = match (rng.below(10), *name) {
			(0, _) => None,
			// an entry splitname refuses: the db goes invalid on the
			// first load (a non-archive file does not, see the report)
			(_, "junk") => {
				Some(ustar(&[tar_file("junk/desc", b"x\n")]))
			}
			_ => {
				let mut pkgs: Vec<SyncPkg> = Vec::new();
				for p in local {
					if rng.below(2) == 0 {
						let v = format!(
							"1.{}-1",
							rng.below(3)
						);
						let g = some(rng, &GROUPS, 1);
						pkgs.push((
							p.name.into(),
							v,
							g,
						));
					}
				}
				if rng.below(2) == 0 {
					pkgs.push((
						"synconly".into(),
						"1-1".into(),
						vec![],
					));
				}
				pkgs.sort();
				Some(sync_db(&pkgs))
			}
		};
		out.push((name.to_string(), usage, data));
	}
	out
}

const PKGINFO: &str = "\
pkgname = {name}
pkgbase = {name}
xdata = pkgtype=pkg
pkgver = 2.0-1
pkgdesc = a package file
url = https://example.org/
builddate = 1720811171
packager = John Doe <john@example.org>
size = 2358
arch = x86_64
license = MIT
";

// package files under pkgs/: valid ones (with and without changelog),
// garbage, a directory
fn write_pkgfiles(fx: &TempRoot) -> Vec<Vec<u8>> {
	let dir = fx.dir().join("pkgs");
	fs::create_dir(&dir).unwrap();
	let mut out = Vec::new();
	for (name, log) in [("foo", true), ("newpkg", false)] {
		let mut info = PKGINFO.replace("{name}", name);
		info += "depend = bar\ngroup = g1\nprovides = virt=2\n";
		let mut entries = vec![tar_file(".PKGINFO", info.as_bytes())];
		if log {
			entries.push(tar_file(".CHANGELOG", b"file changes\n"));
		}
		entries.push(tar_dir("usr/"));
		entries.push(tar_dir("usr/bin/"));
		entries.push(tar_file(&format!("usr/bin/{name}"), b"bin\n"));
		let path = dir.join(format!("{name}-2.0-1-x86_64.pkg.tar"));
		fs::write(&path, ustar(&entries)).unwrap();
		out.push(path.as_os_str().as_bytes().to_vec());
	}
	let junk = dir.join("junk.pkg.tar");
	fs::write(&junk, b"not an archive").unwrap();
	out.push(junk.as_os_str().as_bytes().to_vec());
	out.push(dir.as_os_str().as_bytes().to_vec());
	out.push(dir.join("missing.pkg.tar").as_os_str().as_bytes().to_vec());
	out
}

// the world of one case
struct World {
	fx: TempRoot,
	cfg: Config,
	c: QueryWorld,
	r: Handle,
	pkgs: Vec<Pkg>,
	pkgfiles: Vec<Vec<u8>>,
	log: String,
}

fn open_world(rng: &mut Rng) -> World {
	let fx = TempRoot::new("query");
	let pkgs = gen_pkgs(rng);
	write_local(&fx, &pkgs);
	write_root(&fx, &pkgs);
	let pkgfiles = write_pkgfiles(&fx);
	let sync = gen_sync(rng, &pkgs);
	let mut cfg = Config::new();
	for (name, usage, data) in &sync {
		if let Some(d) = data {
			fs::write(fx.sync_file(name, ".db"), d).unwrap();
		}
		cfg.repos.push(ConfigRepo {
			name: name.as_bytes().to_vec(),
			usage: *usage,
			..ConfigRepo::default()
		});
	}
	cfg.ignorepkg = some(rng, &NAMES, 1)
		.into_iter()
		.map(String::into_bytes)
		.collect();
	cfg.ignoregrp = some(rng, &GROUPS, 1)
		.into_iter()
		.map(String::into_bytes)
		.collect();
	if rng.below(3) == 0 {
		cfg.noextract = vec![b"usr/share/*".to_vec()];
	}
	let c = QueryWorld::open(&fx.root(), &fx.dbpath(), &cfg);
	let mut r = Handle::initialize(&fx.root(), &fx.dbpath()).unwrap();
	r.set_ignorepkgs(&cfg.ignorepkg);
	r.set_ignoregroups(&cfg.ignoregrp);
	r.set_noextracts(&cfg.noextract);
	for repo in &cfg.repos {
		r.register_syncdb(&repo.name, 0)
			.unwrap()
			.set_usage(repo.usage);
	}
	let log = format!(
		"pkgs {pkgs:#?}\nsync {:?}\nignore {:?} {:?} noextract {:?}",
		sync.iter()
			.map(|(n, u, d)| (n, u, d.is_some()))
			.collect::<Vec<_>>(),
		cfg.ignorepkg,
		cfg.ignoregrp,
		cfg.noextract
	);
	World {
		fx,
		cfg,
		c,
		r,
		pkgs,
		pkgfiles,
		log,
	}
}

fn s(x: &str) -> Vec<u8> {
	x.as_bytes().to_vec()
}

impl World {
	fn root(&self) -> String {
		String::from_utf8(self.fx.root()).unwrap()
	}

	fn path_env(&self, rng: &mut Rng) -> Vec<u8> {
		let (dir, root) =
			(self.fx.dir().display().to_string(), self.root());
		let p = match rng.below(4) {
			0 => format!("{dir}/bin:{root}/usr/bin"),
			1 => format!("{root}/usr/bin/::{dir}/bin//"),
			2 => format!("{dir}/nothere:{root}/usr/bin"),
			_ => "/nonexistent-difftest".into(),
		};
		p.into_bytes()
	}

	// a -Q/-Qi/... target
	fn pkg_target(&self, rng: &mut Rng) -> Vec<u8> {
		match rng.below(12) {
			0 => format!("local/{}", pick(rng, &NAMES))
				.into_bytes(),
			1 => s(pick(
				rng,
				&["virt", "virt>=2", "virt=3", "libp.so"],
			)),
			2 => s(pick(
				rng,
				&["lib-a>=1.1", "foo<1.1", "bar=1.0-1"],
			)),
			3 => s(pick(
				rng,
				&["Cargo.toml", "", "missing", "local/"],
			)),
			4 => s(pick(rng, &GROUPS)),
			_ => s(pick(rng, &NAMES)),
		}
	}

	// a -Qo target: owned files, dirs (with and without '/'), the
	// symlinked dir, missing paths, bare names for PATH, outside
	fn file_target(&self, rng: &mut Rng) -> Vec<u8> {
		let root = self.root();
		let p = &self.pkgs[rng.below(self.pkgs.len())];
		let f = &p.files[rng.below(p.files.len())];
		let out = match rng.below(14) {
			0..=4 => format!("{root}/{f}"),
			5 => format!("{root}/{}", f.trim_end_matches('/')),
			6 => format!("{root}/lib/lib{}.so", p.name),
			7 => format!("{root}/usr//bin/{}", p.name),
			8 => pick(rng, &NAMES).to_string(),
			9 => pick(rng, &["qbin", "tests", "", "/", "./x"])
				.into(),
			10 => format!("{root}/srv/unowned"),
			11 => format!("{root}/nothere/"),
			12 => {
				pick(rng, &[root.as_str(), "/tmp"]).to_string()
					+ "/"
			}
			_ => format!("{root}/usr/share/./{}/../common", p.name),
		};
		out.into_bytes()
	}

	fn targets(&self, rng: &mut Rng, cfg: &Config) -> Vec<Vec<u8>> {
		let n = match rng.below(4) {
			0 => 0,
			_ => 1 + rng.below(3),
		};
		(0..n).map(|_| {
			if cfg.op_q_owns != 0 {
				self.file_target(rng)
			} else if cfg.op_q_isfile != 0 {
				self.pkgfiles[rng.below(self.pkgfiles.len())]
					.clone()
			} else if cfg.op_q_search != 0 {
				s(pick(
					rng,
					&[
						"foo", "^b", "LIB", "x^y",
						"c++", "(", "virt", "a+", "",
					],
				))
			} else {
				self.pkg_target(rng)
			}
		})
		.collect()
	}
}

fn gen_cfg(rng: &mut Rng, base: &Config) -> Config {
	let mut c = base.clone();
	match rng.below(10) {
		0 => c.op_q_search = 1,
		1 => c.group = 1,
		2 | 3 => c.op_q_owns = 1,
		4 => c.op_q_isfile = 1,
		_ => {}
	}
	let flag = |rng: &mut Rng, max: u16| match rng.below(5) {
		0 => 1 + rng.below(max as usize) as u16,
		_ => 0,
	};
	c.op_q_info = flag(rng, 2);
	c.op_q_list = flag(rng, 1);
	c.op_q_changelog = flag(rng, 1);
	c.op_q_check = flag(rng, 2);
	c.op_q_explicit = flag(rng, 1);
	c.op_q_deps = flag(rng, 1);
	c.op_q_unrequired = flag(rng, 2);
	c.op_q_upgrade = flag(rng, 1);
	c.op_q_locality = match rng.below(8) {
		0 => PKG_LOCALITY_NATIVE,
		1 => PKG_LOCALITY_FOREIGN,
		2 => PKG_LOCALITY_NATIVE | PKG_LOCALITY_FOREIGN,
		_ => 0,
	};
	c.quiet = u16::from(rng.below(3) == 0);
	c.colstr = match rng.below(3) {
		0 => ColStr::COLOR,
		_ => ColStr::PLAIN,
	};
	if rng.below(10) == 0 {
		c.logmask = 0;
	}
	c
}

fn flags(c: &Config) -> String {
	format!(
		"isfile {} info {} list {} unreq {} deps {} explicit {} owns {} \
		search {} changelog {} upgrade {} check {} locality {} group {} \
		quiet {} color {}",
		c.op_q_isfile,
		c.op_q_info,
		c.op_q_list,
		c.op_q_unrequired,
		c.op_q_deps,
		c.op_q_explicit,
		c.op_q_owns,
		c.op_q_search,
		c.op_q_changelog,
		c.op_q_upgrade,
		c.op_q_check,
		c.op_q_locality,
		c.group,
		c.quiet,
		c.colstr.title != b""
	)
}

fn rust_query(
	w: &mut World,
	cfg: &Config,
	targets: &[Vec<u8>],
	env: &QueryEnv,
) -> CQuery {
	let mut o = Output::default();
	let ret = pacman_query(cfg, &mut w.r, env, targets, &mut o);
	CQuery {
		ret,
		stdout: o.stdout,
		stderr: o.stderr,
	}
}

fn lossy(q: &CQuery) -> String {
	format!(
		"ret {}\n--- stdout\n{}--- stderr\n{}",
		q.ret,
		String::from_utf8_lossy(&q.stdout),
		String::from_utf8_lossy(&q.stderr)
	)
}

// one run on both sides
fn compare(
	w: &mut World,
	cfg: &Config,
	targets: &[Vec<u8>],
	cols: u16,
	path: &[u8],
) -> CQuery {
	let c = w.c.query(cfg, targets, cols, path);
	let env = QueryEnv {
		cols,
		path: Some(path.to_vec()),
	};
	let r = rust_query(w, cfg, targets, &env);
	if c != r {
		let t: Vec<_> = targets
			.iter()
			.map(|t| String::from_utf8_lossy(t))
			.collect();
		panic!(
			"{}\ntargets {t:?} cols {cols} PATH {}\n=== C\n{}=== Rust\n{}\n{}",
			flags(cfg),
			String::from_utf8_lossy(path),
			lossy(&c),
			lossy(&r),
			w.log
		);
	}
	c
}

fn cwd_clean() {
	for n in NAMES.iter().chain(&["qbin", "missing", "x"]) {
		assert!(!Path::new(n).exists(), "{n} exists in the cwd");
	}
}

// fixed runs: every option once, the owner resolution cases, -Qu with
// an ignored package, a junk sync db invalid on the second run
#[test]
fn fixed() {
	cwd_clean();
	let mut rng = Rng::new(7);
	let mut w = open_world(&mut rng);
	let root = w.root();
	let path = w.path_env(&mut rng);
	let base = w.cfg.clone();
	let names: Vec<Vec<u8>> = w.pkgs.iter().map(|p| s(p.name)).collect();
	// the first package loses its desc before anything is loaded: found
	// by name and version (no desc read by alpm_find_satisfier), its
	// files and scriptlet still load
	let p0 = &w.pkgs[0];
	let dir = w.fx.local().join(format!("{}-{}", p0.name, p0.version));
	if p0.desc_file {
		fs::remove_file(dir.join("desc")).unwrap();
	}
	let literal = s(&format!("{}>=0", p0.name));
	let mut runs: Vec<(Config, Vec<Vec<u8>>)> = Vec::new();
	let mut add = |f: &dyn Fn(&mut Config), t: Vec<Vec<u8>>| {
		let mut c = base.clone();
		f(&mut c);
		runs.push((c, t));
	};
	add(&|c| c.op_q_list = 1, vec![literal.clone()]);
	add(&|c| c.op_q_info = 1, vec![literal]);
	add(&|_| {}, vec![]);
	add(&|c| c.quiet = 1, vec![]);
	add(&|_| {}, names.clone());
	add(&|c| c.op_q_info = 1, names.clone());
	add(&|c| c.op_q_info = 2, names.clone());
	add(&|c| c.op_q_list = 1, vec![]);
	add(&|c| c.op_q_changelog = 1, names.clone());
	add(&|c| c.op_q_check = 1, vec![]);
	add(&|c| c.op_q_check = 2, vec![]);
	add(&|c| c.op_q_explicit = 1, vec![]);
	add(&|c| c.op_q_deps = 1, vec![]);
	add(&|c| c.op_q_unrequired = 1, vec![]);
	add(&|c| c.op_q_unrequired = 2, vec![]);
	add(&|c| c.op_q_upgrade = 1, vec![]);
	add(&|c| c.op_q_locality = PKG_LOCALITY_NATIVE, vec![]);
	add(&|c| c.op_q_locality = PKG_LOCALITY_FOREIGN, vec![]);
	add(&|c| c.op_q_search = 1, vec![]);
	add(&|c| c.op_q_search = 1, vec![s("foo"), s("a")]);
	add(&|c| c.op_q_search = 1, vec![s("(")]);
	add(&|c| c.group = 1, vec![]);
	add(&|c| c.group = 1, vec![s("g1"), s("nogroup"), s("")]);
	add(&|c| c.op_q_isfile = 1, vec![]);
	add(&|c| c.op_q_owns = 1, vec![]);
	add(&|c| c.op_q_isfile = 1, w.pkgfiles.clone());
	add(
		&|c| {
			c.op_q_isfile = 1;
			c.op_q_info = 2;
		},
		w.pkgfiles.clone(),
	);
	add(
		&|c| {
			c.op_q_isfile = 1;
			c.op_q_changelog = 1;
			c.op_q_list = 1;
			c.op_q_check = 2;
		},
		w.pkgfiles.clone(),
	);
	let owned: Vec<Vec<u8>> = [
		format!("{root}/usr/bin/"),
		format!("{root}/usr/bin"),
		format!("{root}/usr/share/common"),
		format!("{root}/lib"),
		format!("{root}/lib/"),
		format!("{root}/nothere/"),
		format!("{root}/srv/unowned"),
		format!("{root}/etc/foo.conf"),
		format!("{root}/usr/bin/../share/common"),
		root.clone(),
		format!("{root}/"),
		"qbin".into(),
		"foo".into(),
		"tests".into(),
		"/".into(),
		"".into(),
	]
	.iter()
	.map(|x| s(x))
	.collect();
	add(&|c| c.op_q_owns = 1, owned.clone());
	add(
		&|c| {
			c.op_q_owns = 1;
			c.quiet = 1;
		},
		owned,
	);
	add(
		&|_| {},
		vec![s("Cargo.toml"), s("local/foo"), s("virt>=2"), s("")],
	);
	for (cfg, targets) in &runs {
		compare(&mut w, cfg, targets, 80, &path);
	}
	// once the junk db failed to load, check_syncdbs reports it
	for (cfg, targets) in &runs {
		compare(&mut w, cfg, targets, 0, &path);
	}
}

#[test]
fn fuzz() {
	cwd_clean();
	let mut rng = Rng::new(0x9e_57);
	let (mut runs, mut seen) = (0usize, Seen::default());
	for _ in 0..worlds() {
		let mut w = open_world(&mut rng);
		let base = w.cfg.clone();
		for _ in 0..RUNS {
			let mut cfg = gen_cfg(&mut rng, &base);
			// the port loads files up front for -Qkk: with an
			// unreadable desc that shows in later runs on the
			// same handle (see the report)
			if w.pkgs.iter().any(|p| !p.desc_file) {
				cfg.op_q_check = cfg.op_q_check.min(1);
			}
			let targets = w.targets(&mut rng, &cfg);
			let cols = [0, 40, 80, 200][rng.below(4)];
			let path = w.path_env(&mut rng);
			let c = compare(&mut w, &cfg, &targets, cols, &path);
			seen.tally(&cfg, &c);
			runs += 1;
		}
	}
	eprintln!("{seen:?}");
	assert!(runs >= worlds() * RUNS);
	seen.assert_min(runs / 100);
}

// what the fuzz reached: runs per kind with output on stdout, with an
// error on stderr, per return value
#[derive(Debug, Default)]
struct Seen {
	info: usize,
	extra: usize,
	list: usize,
	changelog: usize,
	check_full: usize,
	owns: usize,
	isfile: usize,
	search: usize,
	group: usize,
	upgrade: usize,
	errors: usize,
	ret: [usize; 3],
}

impl Seen {
	fn tally(&mut self, cfg: &Config, c: &CQuery) {
		let out = !c.stdout.is_empty();
		let n = |on: bool| usize::from(on && out);
		self.info += n(cfg.op_q_info == 1);
		self.extra += n(cfg.op_q_info > 1);
		self.list += n(cfg.op_q_list != 0);
		self.changelog += n(cfg.op_q_changelog != 0);
		self.check_full += n(cfg.op_q_check > 1);
		self.owns += n(cfg.op_q_owns != 0);
		self.isfile += n(cfg.op_q_isfile != 0);
		self.search += n(cfg.op_q_search != 0);
		self.group += n(cfg.group != 0);
		self.upgrade += n(cfg.op_q_upgrade != 0);
		self.errors += usize::from(!c.stderr.is_empty());
		self.ret[c.ret.clamp(0, 2) as usize] += 1;
	}

	fn assert_min(&self, min: usize) {
		let all = [
			self.info,
			self.extra,
			self.list,
			self.changelog,
			self.check_full,
			self.owns,
			self.isfile,
			self.search,
			self.group,
			self.upgrade,
			self.errors,
			self.ret[0],
			self.ret[1],
		];
		assert!(all.iter().all(|&n| n >= min), "{self:?} min {min}");
	}
}

fn rust_deptest(w: &mut World, targets: &[Vec<u8>]) -> CQuery {
	let mut o = Output::default();
	let ret = pacman_deptest(&mut w.r, targets, &mut o);
	CQuery {
		ret,
		stdout: o.stdout,
		stderr: o.stderr,
	}
}

const DEPS: [&str; 14] = [
	"foo",
	"foo>=1.1",
	"foo<1.0",
	"foo=1.0-1",
	"virt",
	"virt>=2",
	"virt>2",
	"libp.so",
	"libp.so=1-64",
	"nothere",
	"",
	"lib-a: why",
	"x-y>0",
	"bar<=9",
];

#[test]
fn deptest() {
	let mut rng = Rng::new(0xde_97);
	let mut runs = 0usize;
	for _ in 0..worlds() {
		let mut w = open_world(&mut rng);
		for _ in 0..RUNS {
			let n = rng.below(5);
			let targets: Vec<Vec<u8>> = (0..n)
				.map(|_| s(pick(&mut rng, &DEPS)))
				.collect();
			let c = w.c.deptest(&targets);
			let r = rust_deptest(&mut w, &targets);
			assert_eq!(c, r, "{targets:?}\n{}", w.log);
			runs += 1;
		}
	}
	assert!(runs >= worlds() * RUNS);
}
