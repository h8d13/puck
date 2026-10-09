// every pacman.conf directive at the binary level: C pacman
// (PACMAN_BUILD) and the Rust binary run the same operation on twin
// copies of one fixture world with the directive set, compared on exit
// status, stdout, stderr (PACMAN_DEBUG stamps within CLOCK_SLACK), the
// world's tree (install dates masked), pacman.log (stamps dropped) and,
// for HTTP mirrors, the requests the scripted server saw and how many
// ran at once. each case also proves itself: the C is run once more
// with the directive taken out (Case::without) and that outcome must
// differ, else the case would show nothing. PORTING.md "Configuration
// matrix" lists which difftest covers which directive.
//
// root-only operations run under fakeroot, transactions that extract
// files under fakechroot fakeroot like pactest (hooks and scriptlets
// chroot into the root), terminal-dependent directives (Color,
// NoProgressBar, ILoveCandy) on a pty through script(1) with both
// streams merged, UseSyslog in a user namespace with a datagram socket
// bound over /dev/log
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use alpm_core::compute_sha256sum;
use difftest::{
	Comp, GpgFixture, Home, LocalEntry, Node, Reply, Req, Server, Stamped,
	TempRoot, c_pacman, closed_port, rust_pacman, section, snapshot,
	stamped, tar_dir, tar_file, ustar, write_db,
};

// ---- the fixture world ----

// a package: files end with '/' for directories, parents listed first
struct Pkg {
	name: &'static str,
	version: &'static str,
	arch: &'static str,
	groups: &'static [&'static str],
	files: &'static [&'static str],
}

const ALPHA1: Pkg = Pkg {
	name: "alpha",
	version: "1.0-1",
	arch: "x86_64",
	groups: &[],
	files: &[
		"etc/",
		"etc/alpha.conf",
		"etc/other.conf",
		"usr/",
		"usr/bin/",
		"usr/bin/alpha",
	],
};
const ALPHA2: Pkg = Pkg {
	version: "2.0-1",
	groups: &["grp"],
	..ALPHA1
};
const BETA: Pkg = Pkg {
	name: "beta",
	version: "1.0-1",
	arch: "x86_64",
	groups: &["grp"],
	files: &[
		"usr/",
		"usr/bin/",
		"usr/bin/beta",
		"usr/share/",
		"usr/share/doc/",
		"usr/share/doc/beta/",
		"usr/share/doc/beta/README",
		"usr/share/doc/beta/keep",
	],
};
const GAMMA: Pkg = Pkg {
	name: "gamma",
	version: "1.0-1",
	arch: "armv7h",
	groups: &[],
	files: &["usr/", "usr/bin/", "usr/bin/gamma"],
};
const DELTA: Pkg = Pkg {
	name: "delta",
	version: "1.0-1",
	arch: "x86_64",
	groups: &[],
	files: &["usr/", "usr/bin/", "usr/bin/delta"],
};
const EPS: Pkg = Pkg {
	name: "eps",
	version: "1.0-1",
	arch: "x86_64",
	groups: &[],
	files: &["usr/", "usr/bin/", "usr/bin/eps"],
};
// never in any db or on any mirror: a leftover in the cache
const ZETA: Pkg = Pkg {
	name: "zeta",
	version: "1.0-1",
	arch: "x86_64",
	groups: &[],
	files: &["usr/", "usr/bin/", "usr/bin/zeta"],
};

fn filename(p: &Pkg) -> String {
	format!("{}-{}-{}.pkg.tar.gz", p.name, p.version, p.arch)
}

fn file_data(p: &Pkg, path: &str) -> Vec<u8> {
	format!("{}-{}:{path}\n", p.name, p.version).into_bytes()
}

fn pkginfo(p: &Pkg) -> String {
	let mut s = format!(
		"pkgname = {0}\npkgbase = {0}\npkgver = {1}\npkgdesc = new {0}\n\
		url = https://example.org/\nbuilddate = 1700000000\n\
		packager = A B <a@b.org>\nsize = 4096\narch = {2}\n",
		p.name, p.version, p.arch
	);
	for g in p.groups {
		s.push_str(&format!("group = {g}\n"));
	}
	s
}

// the package file's tar (.PKGINFO first), gzipped by write_db
fn package_tar(p: &Pkg) -> Vec<u8> {
	let mut entries = vec![tar_file(".PKGINFO", pkginfo(p).as_bytes())];
	for f in p.files {
		entries.push(match f.ends_with('/') {
			true => tar_dir(f),
			false => tar_file(f, &file_data(p, f)),
		});
	}
	ustar(&entries)
}

fn strs(v: &[&str]) -> Vec<String> {
	v.iter().map(|s| s.to_string()).collect()
}

fn sync_desc(p: &Pkg, csize: u64, sum: &str) -> String {
	let one = |s: String| vec![s];
	[
		section("FILENAME", &one(filename(p))),
		section("NAME", &one(p.name.into())),
		section("BASE", &one(p.name.into())),
		section("VERSION", &one(p.version.into())),
		section("DESC", &one(format!("new {}", p.name))),
		section("GROUPS", &strs(p.groups)),
		section("CSIZE", &one(csize.to_string())),
		section("ISIZE", &one("4096".into())),
		section("SHA256SUM", &one(sum.into())),
		section("ARCH", &one(p.arch.into())),
		section("BUILDDATE", &one("1700000000".into())),
		section("PACKAGER", &one("A B <a@b.org>".into())),
	]
	.concat()
}

fn local_desc(p: &Pkg) -> String {
	let one = |s: &str| vec![s.to_string()];
	[
		section("NAME", &one(p.name)),
		section("VERSION", &one(p.version)),
		section("BASE", &one(p.name)),
		section("DESC", &one("installed")),
		section("ARCH", &one(p.arch)),
		section("BUILDDATE", &one("1600000000")),
		section("INSTALLDATE", &one("1600000001")),
		section("PACKAGER", &one("A B <a@b.org>")),
		section("SIZE", &one("4096")),
		section("REASON", &one("0")),
		section("VALIDATION", &one("none")),
	]
	.concat()
}

// the fixture: orig/ holds the pristine world, w/ the copy a run works
// on (restored before every run), mirror/ the repos' files served by
// file:// and the HTTP server, pkgs/ the -U files, gpg the keyrings
struct World {
	fx: TempRoot,
	gpg: GpgFixture,
	srv: Server,
	// the mirror's routes, put back before every run over what a case
	// changed
	routes: Vec<(String, Reply)>,
}

const REPOS: [(&str, &[&Pkg]); 2] =
	[("core", &[&ALPHA2, &BETA, &GAMMA]), ("extra", &[&EPS])];

impl World {
	fn new(tag: &str) -> World {
		let fx = TempRoot::new(tag);
		let gpg = GpgFixture::new(&format!("{tag}-gpg"));
		let dir = fx.dir();
		let orig = dir.join("orig");
		for d in [
			"root/bin",
			"db/local",
			"db/sync",
			"cache",
			"cache2",
			"hooks",
			"hooks2",
			"log",
			"gnupg",
			"inc/nested",
		] {
			fs::create_dir_all(orig.join(d)).unwrap();
		}
		// the installed packages' files, /bin/sh for hooks under
		// fakechroot
		fs::copy("/bin/sh", orig.join("root/bin/sh")).unwrap();
		let root = orig.join("root");
		for p in [&ALPHA1, &DELTA] {
			for f in p.files {
				match f.ends_with('/') {
					true => {
						fs::create_dir_all(root.join(f))
							.unwrap()
					}
					false => fs::write(
						root.join(f),
						file_data(p, f),
					)
					.unwrap(),
				}
			}
		}
		let local = orig.join("db/local");
		fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
		let entries: Vec<LocalEntry> = [&ALPHA1, &DELTA]
			.iter()
			.map(|p| LocalEntry {
				dir: format!("{}-{}", p.name, p.version),
				desc: Some(local_desc(p).into_bytes()),
				files: Some(section("FILES", &strs(p.files))
					.into_bytes()),
				install: false,
			})
			.collect();
		for e in &entries {
			let d = local.join(&e.dir);
			fs::create_dir(&d).unwrap();
			fs::write(d.join("desc"), e.desc.as_ref().unwrap())
				.unwrap();
			fs::write(d.join("files"), e.files.as_ref().unwrap())
				.unwrap();
		}
		// the mirror: <repo>.db and the packages, the same bytes on
		// the HTTP routes /m/<repo>/<file> and /cs/<file>; the dbs
		// also under db/sync (old mtime, see restore) for the
		// read-only operations
		let srv = Server::start();
		let routes = std::cell::RefCell::new(Vec::new());
		let serve = |path: &str, body: &[u8]| {
			let reply = Reply::File {
				body: body.to_vec(),
				ranges: true,
				mtime: Some(1_000_000_000),
			};
			srv.route(path, vec![reply.clone()]);
			routes.borrow_mut().push((path.to_string(), reply));
		};
		for (repo, pkgs) in REPOS {
			let mdir = dir.join("mirror").join(repo);
			fs::create_dir_all(&mdir).unwrap();
			let mut tar = Vec::new();
			for p in pkgs {
				let file = mdir.join(filename(p));
				write_db(&file, Comp::Gzip, &package_tar(p));
				let data = fs::read(&file).unwrap();
				let sum = compute_sha256sum(
					file.as_os_str().as_encoded_bytes(),
				)
				.unwrap();
				let sum = String::from_utf8(sum).unwrap();
				let desc =
					sync_desc(p, data.len() as u64, &sum);
				let d = format!("{}-{}/", p.name, p.version);
				tar.push(tar_dir(&d));
				tar.push(tar_file(
					&format!("{d}desc"),
					desc.as_bytes(),
				));
				serve(
					&format!("/m/{repo}/{}", filename(p)),
					&data,
				);
				serve(&format!("/cs/{}", filename(p)), &data);
			}
			let db = mdir.join(format!("{repo}.db"));
			write_db(&db, Comp::Gzip, &ustar(&tar));
			let data = fs::read(&db).unwrap();
			serve(&format!("/m/{repo}/{repo}.db"), &data);
			fs::write(
				orig.join(format!("db/sync/{repo}.db")),
				&data,
			)
			.unwrap();
		}
		// $arch: mirror/x86_64/<repo> is mirror/<repo>
		std::os::unix::fs::symlink(".", dir.join("mirror/x86_64"))
			.unwrap();
		// the -U files
		let pkgs = dir.join("pkgs");
		fs::create_dir_all(&pkgs).unwrap();
		for p in [&ALPHA2, &BETA, &ZETA] {
			write_db(
				&pkgs.join(filename(p)),
				Comp::Gzip,
				&package_tar(p),
			);
		}
		// core.db signed by the fixture's fully trusted key and by a
		// marginally trusted one, mirror/signed-<key>/core.db(.sig)
		for key in ["full", "marg"] {
			let sdir = dir.join(format!("mirror/signed-{key}"));
			fs::create_dir_all(&sdir).unwrap();
			let db = sdir.join("core.db");
			fs::copy(dir.join("mirror/core/core.db"), &db).unwrap();
			let sig = gpg.sign_file(&[key], &db);
			fs::write(sdir.join("core.db.sig"), &sig).unwrap();
			let data = fs::read(&db).unwrap();
			serve(&format!("/s{key}/core.db"), &data);
			serve(&format!("/s{key}/core.db.sig"), &sig);
		}
		// an unsigned package of pkgs/ next to a signed one
		let signed = dir.join("pkgs").join(filename(&ZETA));
		let sig = gpg.sign_file(&["full"], &signed);
		fs::write(format!("{}.sig", signed.display()), sig).unwrap();
		let routes = routes.into_inner();
		World {
			fx,
			gpg,
			srv,
			routes,
		}
	}

	fn dir(&self) -> &Path {
		self.fx.dir()
	}

	// the working copy, "@/w" in labels
	fn w(&self) -> PathBuf {
		self.dir().join("w")
	}

	fn w_str(&self, rel: &str) -> String {
		format!("{}/{rel}", self.w().display())
	}

	fn at(&self, rel: &str) -> String {
		format!("{}/{rel}", self.dir().display())
	}

	// w/ back to orig/, the sync dbs stamped old so a refresh sees the
	// mirror's copies as newer
	fn restore(&self) {
		let w = self.w();
		if w.exists() {
			difftest::force_remove(&w);
		}
		copy_dir(&self.dir().join("orig"), &w);
		let old = std::time::UNIX_EPOCH + Duration::from_secs(1 << 20);
		for e in fs::read_dir(w.join("db/sync")).unwrap() {
			let f = fs::File::options()
				.write(true)
				.open(e.unwrap().path())
				.unwrap();
			f.set_modified(old).unwrap();
		}
	}

	fn file_mirror(&self, repo: &str) -> String {
		format!("file://{}", self.at(&format!("mirror/{repo}")))
	}

	fn http_mirror(&self, repo: &str) -> String {
		format!("{}/m/{repo}", self.srv.base())
	}

	fn pkg_file(&self, p: &Pkg) -> String {
		self.at(&format!("pkgs/{}", filename(p)))
	}

	// the path options of every command line but the ones in `drop`
	fn paths(&self, drop: &[&str]) -> Vec<String> {
		let all = [
			("--config", "pacman.conf"),
			("--root", "root"),
			("--dbpath", "db"),
			("--cachedir", "cache"),
			("--hookdir", "hooks"),
			("--gpgdir", "gnupg"),
			("--logfile", "log/pacman.log"),
		];
		all.iter()
			.filter(|(o, _)| !drop.contains(o))
			.map(|(o, rel)| format!("{o}={}", self.w_str(rel)))
			.collect()
	}
}

fn copy_dir(from: &Path, to: &Path) {
	fs::create_dir_all(to).unwrap();
	for e in fs::read_dir(from).unwrap() {
		let e = e.unwrap();
		let dest = to.join(e.file_name());
		let ty = e.file_type().unwrap();
		if ty.is_symlink() {
			let t = fs::read_link(e.path()).unwrap();
			std::os::unix::fs::symlink(t, dest).unwrap();
		} else if ty.is_dir() {
			copy_dir(&e.path(), &dest);
		} else {
			fs::copy(e.path(), &dest).unwrap();
			let perm =
				fs::metadata(e.path()).unwrap().permissions();
			fs::set_permissions(&dest, perm).unwrap();
		}
	}
}

// pacman.conf: options, then the repos as (name, lines)
fn conf(options: &str, repos: &[(&str, &str)]) -> String {
	let mut s = format!("[options]\nSigLevel = Never\n{options}");
	for (name, lines) in repos {
		s.push_str(&format!("[{name}]\n{lines}"));
	}
	s
}

// ---- running the binaries ----

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fake {
	No,
	// fakeroot: uid 0 for the root-only operations
	Root,
	// fakechroot fakeroot: transactions whose hooks and scriptlets
	// chroot into the root
	Chroot,
	// unshare -Ur -m with w/dev-log bound over /dev/log: syslog
	Syslog,
}

#[derive(Clone, Copy)]
struct How {
	fake: Fake,
	// script(1): stdout a pty, stderr merged into it
	pty: bool,
	// compare the requests' User-Agent (curl's through XferCommand; the
	// built-in downloader's is the frontend's HTTP_USER_AGENT, which
	// the port does not set yet: PORTING.md handover row)
	agent: bool,
}

const PLAIN: How = How {
	fake: Fake::No,
	pty: false,
	agent: false,
};
const ROOT: How = How {
	fake: Fake::Root,
	..PLAIN
};
const CHROOT: How = How {
	fake: Fake::Chroot,
	..PLAIN
};
const XFER: How = How {
	fake: Fake::No,
	pty: false,
	agent: true,
};
const XFER_ROOT: How = How {
	fake: Fake::Root,
	..XFER
};

// GOTO_ERR's "got error <n> at <func> (<file>: <line>)" debug lines
// carry the C's source position, never logged by the port (PORTING.md)
fn is_goto_err(line: &[u8]) -> bool {
	let key = b"got error ";
	let Some(i) = line.windows(key.len()).position(|w| w == key) else {
		return false;
	};
	let rest = &line[i + key.len()..];
	let n = rest.iter().take_while(|c| c.is_ascii_digit()).count();
	n > 0 && rest[n..].starts_with(b" at ")
}

// curl's progress meter (the XferCommand forms without -s): its rates
// and times vary per run. the header lines, then updates led by '\r'
fn is_curl_meter(line: &[u8]) -> bool {
	let n = line
		.iter()
		.take_while(|&&c| c == b' ' || c == b'\r')
		.count();
	let rest = &line[n..];
	rest.starts_with(b"% Total")
		|| rest.starts_with(b"Dload")
		|| rest.first().is_some_and(u8::is_ascii_digit)
}

fn without_curl_meter(err: &[u8]) -> Vec<u8> {
	let lines = err.split_inclusive(|&c| c == b'\n');
	lines.filter(|l| !is_curl_meter(l))
		.flatten()
		.copied()
		.collect()
}

// text with the C's source positions dropped (GOTO_ERR, RET_ERR), the
// sandbox download dir's mkdtemp suffix fixed, the binary's path as
// "pacman" and the fixture dir as "@"
fn norm(text: &[u8], bin: &Path, fx: &Path) -> Vec<u8> {
	let mut out = Vec::new();
	for line in text.split_inclusive(|&c| c == b'\n') {
		if is_goto_err(line)
			|| line.starts_with(b"debug: returning error ")
		{
			continue;
		}
		let mut l = line.to_vec();
		let pat = b"download-";
		let mut i = 0;
		while i + pat.len() + 6 <= l.len() {
			if &l[i..i + pat.len()] == pat {
				let at = i + pat.len();
				l[at..at + 6].copy_from_slice(b"XXXXXX");
				i = at + 6;
			} else {
				i += 1;
			}
		}
		out.extend(l);
	}
	let s = String::from_utf8_lossy(&out)
		.replace(&bin.display().to_string(), "pacman")
		.replace(&fx.display().to_string(), "@");
	s.into_bytes()
}

// "path kind mode [data]" per entry, install dates of the local db
// masked, pacman.log and the XferCommand environment dump left to their
// own comparisons
fn flatten(path: &str, n: &Node, out: &mut Vec<String>) {
	let line = match n {
		Node::File(mode, _, data) => {
			if path.ends_with("/pacman.log")
				|| path.ends_with("/xfer.env")
			{
				return;
			}
			let mut text =
				String::from_utf8_lossy(data).into_owned();
			if path.ends_with("/desc")
				&& path.contains("/db/local/")
			{
				let mut lines: Vec<&str> =
					text.split('\n').collect();
				if let Some(i) = lines
					.iter()
					.position(|l| *l == "%INSTALLDATE%")
				{
					lines[i + 1] = "0";
				}
				text = lines.join("\n");
			}
			format!("{path} file {mode:o} {text:?}")
		}
		Node::Dir(mode, entries) => {
			for (name, e) in entries.iter().flatten() {
				let name = String::from_utf8_lossy(name);
				flatten(&format!("{path}/{name}"), e, out);
			}
			format!("{path} dir {mode:o}")
		}
		other => format!("{path} {other:?}"),
	};
	out.push(line);
}

// pacman.log without its stamps, the binary as "pacman"
fn log_lines(w: &World, bin: &Path) -> Vec<String> {
	let text = fs::read(w.w().join("log/pacman.log")).unwrap_or_default();
	let text = norm(&text, bin, w.dir());
	let text = String::from_utf8_lossy(&text);
	text.lines()
		.map(|l| match l.split_once("] ") {
			Some((_, rest)) => rest.to_string(),
			None => l.to_string(),
		})
		.collect()
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
	status: i32,
	out: Vec<u8>,
	err: Stamped,
	tree: Vec<String>,
	log: Vec<String>,
	requests: Vec<Req>,
	peak: usize,
	// the XferCommand child's environment (xfer.env), HTTP_USER_AGENT
	// taken out: agent holds it
	env: Vec<String>,
	syslog: Vec<String>,
}

const ENV: &[(&str, &str)] = &[
	("LC_ALL", "C.UTF-8"),
	("TZ", "UTC"),
	("COLUMNS", "80"),
	("PATH", "/usr/bin:/bin"),
];

fn sh_quote(s: &str) -> String {
	format!("'{}'", s.replace('\'', "'\\''"))
}

// the command of a run: the binary under its fake, on a pty through
// script(1)
fn command(bin: &Path, args: &[String], how: How, w: &World) -> Command {
	let mut words: Vec<String> = match how.fake {
		Fake::No => vec![],
		Fake::Root => vec!["fakeroot".into()],
		Fake::Chroot => vec!["fakechroot".into(), "fakeroot".into()],
		Fake::Syslog => {
			let sock = w.w_str("dev-log");
			let line = format!(
				"mount --bind {} /dev/log && exec \"$@\"",
				sh_quote(&sock)
			);
			vec![
				"unshare".into(),
				"-Ur".into(),
				"-m".into(),
				"sh".into(),
				"-c".into(),
				line,
				"sh".into(),
			]
		}
	};
	words.push(bin.display().to_string());
	words.extend(args.iter().cloned());
	let mut cmd = if how.pty {
		let line: Vec<String> =
			words.iter().map(|w| sh_quote(w)).collect();
		let mut c = Command::new("script");
		c.args(["-qefc", &line.join(" "), "/dev/null"]);
		c
	} else {
		let mut c = Command::new(&words[0]);
		if how.fake == Fake::No {
			c.arg0("pacman");
		}
		c.args(&words[1..]);
		c
	};
	cmd.current_dir(w.dir())
		.env_clear()
		.envs(ENV.iter().copied())
		.env("HOME", w.dir())
		.stdin(Stdio::null());
	cmd
}

// a datagram listener at w/dev-log, read after the run
fn syslog_socket(w: &World) -> UnixDatagram {
	let s = UnixDatagram::bind(w.w().join("dev-log")).unwrap();
	s.set_nonblocking(true).unwrap();
	s
}

// the packets: "<pri>Mon dd hh:mm:ss tag: msg" with the stamp cut,
// the port's tag (its program name) as the C's, paths as in norm
fn syslog_packets(s: &UnixDatagram, bin: &Path, fx: &Path) -> Vec<String> {
	let mut out = Vec::new();
	let mut buf = [0u8; 4096];
	while let Ok(n) = s.recv(&mut buf) {
		let p = String::from_utf8_lossy(&norm(&buf[..n], bin, fx))
			.into_owned();
		let masked = match p.find('>') {
			// "Mon dd hh:mm:ss " is 16 bytes after the priority
			Some(i) if p.len() > i + 17 => {
				let rest = &p[i + 17..];
				let rest = rest
					.strip_prefix("puck:")
					.map_or(rest.to_string(), |r| {
						format!("pacman:{r}")
					});
				format!("{}{rest}", &p[..=i])
			}
			_ => p,
		};
		out.push(masked);
	}
	out
}

fn run(bin: &Path, case: &Case, w: &World) -> Outcome {
	w.restore();
	if let Some(prep) = case.prep {
		prep(w);
	}
	w.srv.reset();
	for (path, reply) in &w.routes {
		w.srv.route(path, vec![reply.clone()]);
	}
	for (path, replies) in &case.routes {
		w.srv.route(path, replies.clone());
	}
	let sock = (case.how.fake == Fake::Syslog).then(|| syslog_socket(w));
	let mut cmd = command(bin, &case.args, case.how, w);
	let o = difftest::output_capped(&mut cmd, 120);
	let status = o.status.code().expect("killed by a signal");
	let out = norm(&o.stdout, bin, w.dir());
	let err = norm(&without_curl_meter(&o.stderr), bin, w.dir());
	let mut tree = Vec::new();
	flatten("", &snapshot(&w.w()), &mut tree);
	let mut requests = w.srv.requests();
	if case.unordered {
		requests.sort();
	}
	if !case.how.agent {
		for r in &mut requests {
			r.agent = None;
		}
	}
	let env = fs::read(w.w().join("xfer.env")).unwrap_or_default();
	let env = String::from_utf8_lossy(&norm(&env, bin, w.dir()))
		.lines()
		.filter(|l| !l.starts_with("HTTP_USER_AGENT="))
		// fakeroot's key is random per session
		.filter(|l| !l.starts_with("FAKEROOTKEY="))
		.map(str::to_string)
		.collect();
	Outcome {
		status,
		out,
		err: stamped(&err),
		tree,
		log: log_lines(w, bin),
		requests,
		peak: w.srv.peak(),
		env,
		syslog: sock
			.map(|s| syslog_packets(&s, bin, w.dir()))
			.unwrap_or_default(),
	}
}

// ---- cases ----

struct Case {
	label: String,
	conf: String,
	args: Vec<String>,
	how: How,
	// HTTP replies set before each run (hit counts reset)
	routes: Vec<(String, Vec<Reply>)>,
	// extra setup after the restore
	prep: Option<fn(&World)>,
	// parallel streams: the requests' order is a race, compared sorted
	unordered: bool,
	// the conf with the directive under test taken out: the C's outcome
	// on it has to differ. None for cases of a command line option or a
	// pure error path (their proof is in the C's own texts)
	without: Option<String>,
}

impl Case {
	fn new(label: &str, conf: String, args: Vec<String>) -> Case {
		Case {
			label: label.to_string(),
			conf,
			args,
			how: PLAIN,
			routes: Vec::new(),
			prep: None,
			unordered: false,
			without: None,
		}
	}

	fn unordered(mut self) -> Case {
		self.unordered = true;
		self
	}

	fn how(mut self, how: How) -> Case {
		self.how = how;
		self
	}

	fn without(mut self, conf: String) -> Case {
		self.without = Some(conf);
		self
	}

	fn prep(mut self, f: fn(&World)) -> Case {
		self.prep = Some(f);
		self
	}

	fn route(mut self, path: &str, replies: Vec<Reply>) -> Case {
		self.routes.push((path.to_string(), replies));
		self
	}
}

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

fn show(o: &Outcome) -> String {
	format!(
		"status {}\n-- out\n{}-- err\n{}-- log\n{}\n-- requests {:?} peak {}\n\
		-- env\n{}\n-- syslog\n{}\n",
		o.status,
		lossy(&o.out),
		lossy(&o.err.text),
		o.log.join("\n"),
		o.requests,
		o.peak,
		o.env.join("\n"),
		o.syslog.join("")
	)
}

fn tree_diff(a: &[String], b: &[String]) -> String {
	let only = |x: &[String], y: &[String]| -> Vec<String> {
		x.iter().filter(|l| !y.contains(l)).cloned().collect()
	};
	format!(
		"-- tree C only\n{}\n-- tree Rust only\n{}\n",
		only(a, b).join("\n"),
		only(b, a).join("\n")
	)
}

// both binaries on the case, then the C without the directive. one
// line per case; failures collected
fn compare(w: &World, cases: Vec<Case>) {
	let (c, r) = (c_pacman(), rust_pacman());
	let mut failures = Vec::new();
	for case in &cases {
		fs::write(w.dir().join("orig/pacman.conf"), &case.conf)
			.unwrap();
		let co = run(&c, case, w);
		let ro = run(&r, case, w);
		let equal = co == ro;
		let mut proof = "";
		if let Some(without) = &case.without {
			fs::write(w.dir().join("orig/pacman.conf"), without)
				.unwrap();
			let wo = run(&c, case, w);
			proof = if wo == co { " NOPROOF" } else { " proves" };
			if wo == co {
				failures.push(format!(
					"{}: the C runs the same without the directive\n{}",
					case.label,
					show(&co)
				));
			}
		}
		let mark = if equal { "equal" } else { "DIFF" };
		println!("{mark:5}  {}  [{}]{proof}", case.label, co.status);
		// CM_SHOW=1: the C's outcome of every case
		if std::env::var_os("CM_SHOW").is_some() {
			println!("{}", show(&co));
		}
		if !equal {
			failures.push(format!(
				"{}\n-- C\n{}-- Rust\n{}{}",
				case.label,
				show(&co),
				show(&ro),
				tree_diff(&co.tree, &ro.tree)
			));
		}
	}
	assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

// a case with the directive and its proof conf, the repos on the
// file:// mirror
fn with_without(
	w: &World,
	label: &str,
	with: &str,
	without: &str,
	args: &[&str],
) -> Case {
	let repos = [
		("core", format!("Server = {}\n", w.file_mirror("core"))),
		("extra", format!("Server = {}\n", w.file_mirror("extra"))),
	];
	let repos: Vec<(&str, &str)> =
		repos.iter().map(|(n, s)| (*n, s.as_str())).collect();
	let mut all = strs(args);
	all.extend(w.paths(&[]));
	Case::new(label, conf(with, &repos), all).without(conf(without, &repos))
}

fn seed_cache(w: &World) {
	let cache = w.w().join("cache");
	for p in [&ALPHA1, &ALPHA2, &BETA, &DELTA, &ZETA] {
		write_db(&cache.join(filename(p)), Comp::Gzip, &package_tar(p));
	}
}

// a hook in w/<dir> writing /hook-<dir>.ran in the root on every
// package install
fn hook(w: &World, dir: &str) {
	let text = format!(
		"[Trigger]\nOperation = Install\nType = Package\nTarget = *\n\n\
		[Action]\nDescription = hook in {dir}\nWhen = PostTransaction\n\
		Exec = /bin/sh -c 'echo ran > /hook-{dir}.ran'\n"
	);
	fs::write(w.w().join(dir).join("conf-matrix.hook"), text).unwrap();
}

fn hook_both(w: &World) {
	hook(w, "hooks");
	hook(w, "hooks2");
}

// RootDir, DBPath, LogFile, CacheDir, HookDir, GPGDir and their command
// line options; HoldPkg, IgnorePkg, IgnoreGroup, Architecture,
// NoUpgrade, NoExtract, CleanMethod, CheckSpace, VerbosePkgLists
#[test]
fn directives() {
	let w = World::new("cm-dir");
	let root = w.w_str("root");
	let db = w.w_str("db");
	let mut cases = Vec::new();
	// RootDir from the file: the root -Qk checks the files under
	let c = with_without(
		&w,
		"RootDir: -Qk",
		&format!("RootDir = {root}\n"),
		"",
		&["-Qk"],
	);
	cases.push(Case {
		args: [strs(&["-Qk"]), w.paths(&["--root"])].concat(),
		..c
	});
	// --root wins over the file's RootDir (never resolved)
	let c = with_without(
		&w,
		"RootDir: --root wins",
		"RootDir = /nonexistent/root\n",
		"",
		&["-Qk"],
	);
	cases.push(Case { without: None, ..c });
	// DBPath from the file
	let c = with_without(
		&w,
		"DBPath: -Q",
		&format!("DBPath = {db}\n"),
		"",
		&["-Q"],
	);
	cases.push(Case {
		args: [strs(&["-Q"]), w.paths(&["--dbpath"])].concat(),
		..c
	});
	// the first DBPath wins, the second is not even resolved
	let c = with_without(
		&w,
		"DBPath: first wins",
		&format!("DBPath = {db}\nDBPath = /nonexistent/db\n"),
		&format!("DBPath = /nonexistent/db\nDBPath = {db}\n"),
		&["-Q"],
	);
	cases.push(Case {
		args: [strs(&["-Q"]), w.paths(&["--dbpath"])].concat(),
		..c
	});
	// --dbpath wins over the file's
	let c = with_without(
		&w,
		"DBPath: --dbpath wins",
		"DBPath = /nonexistent/db\n",
		"",
		&["-Q"],
	);
	cases.push(Case { without: None, ..c });
	// LogFile from the file: -D logs "Running"
	let log = w.w_str("log/pacman.log");
	let c = with_without(
		&w,
		"LogFile: -D --asdeps",
		&format!("LogFile = {log}\n"),
		"",
		&["-D", "--asdeps", "delta"],
	);
	cases.push(Case {
		args: [
			strs(&["-D", "--asdeps", "delta"]),
			w.paths(&["--logfile"]),
		]
		.concat(),
		how: ROOT,
		..c
	});
	let c = with_without(
		&w,
		"LogFile: first wins",
		&format!(
			"LogFile = {log}\nLogFile = {}\n",
			w.w_str("log/second.log")
		),
		&format!(
			"LogFile = {}\nLogFile = {log}\n",
			w.w_str("log/second.log")
		),
		&["-D", "--asdeps", "delta"],
	);
	cases.push(Case {
		args: [
			strs(&["-D", "--asdeps", "delta"]),
			w.paths(&["--logfile"]),
		]
		.concat(),
		how: ROOT,
		..c
	});
	let c = with_without(
		&w,
		"LogFile: --logfile wins",
		&format!("LogFile = {}\n", w.w_str("log/second.log")),
		"",
		&["-D", "--asdeps", "delta"],
	);
	cases.push(Case {
		how: ROOT,
		without: None,
		..c
	});
	// CacheDir: a second cache dir from the file next to --cachedir;
	// -Scc cleans both
	let cache2 = w.w_str("cache2");
	let c = with_without(
		&w,
		"CacheDir: -Scc cleans the file's dir too",
		&format!("CacheDir = {cache2}\n"),
		"",
		&["-Scc", "--noconfirm"],
	);
	cases.push(Case {
		how: ROOT,
		prep: Some(|w| {
			seed_cache(w);
			let c2 = w.w().join("cache2");
			write_db(
				&c2.join(filename(&ZETA)),
				Comp::Gzip,
				&package_tar(&ZETA),
			);
		}),
		..c
	});
	// CacheDir alone: the file's dir is the download dir; a package
	// found in a later cache dir is not fetched
	let c = with_without(
		&w,
		"CacheDir: -Sw finds the file in the second dir",
		&format!(
			"CacheDir = {}\nCacheDir = {cache2}\n",
			w.w_str("cache")
		),
		&format!("CacheDir = {}\n", w.w_str("cache")),
		&["-Sw", "--noconfirm", "beta"],
	);
	cases.push(Case {
		args: [
			strs(&["-Sw", "--noconfirm", "beta"]),
			w.paths(&["--cachedir"]),
		]
		.concat(),
		how: ROOT,
		prep: Some(|w| {
			let c2 = w.w().join("cache2");
			let src =
				w.dir().join("mirror/core")
					.join(filename(&BETA));
			fs::copy(src, c2.join(filename(&BETA))).unwrap();
		}),
		..c
	});
	// HookDir from the file next to --hookdir: hooks of both run
	let hooks2 = w.w_str("hooks2");
	let c = with_without(
		&w,
		"HookDir: hooks of the file's dir run",
		&format!("HookDir = {hooks2}\n"),
		"",
		&["-U", "--noconfirm", &w.pkg_file(&BETA)],
	);
	cases.push(Case {
		how: CHROOT,
		prep: Some(hook_both),
		..c
	});
	// GPGDir from the file: the keyring verifying a signed core.db
	let pgp = lossy(&w.gpg.home(Home::Pgp));
	let signed =
		format!("Server = file://{}\n", w.at("mirror/signed-full"));
	let signed_conf =
		|opts: &str| format!("[options]\n{opts}[core]\n{signed}");
	cases.push(Case::new(
		"GPGDir: -Sy of a signed db",
		signed_conf(&format!("GPGDir = {pgp}\nSigLevel = Required\n")),
		[strs(&["-Sy"]), w.paths(&["--gpgdir"])].concat(),
	)
	.how(ROOT)
	.without(signed_conf("SigLevel = Required\n")));
	// --gpgdir wins over the file's
	cases.push(Case::new(
		"GPGDir: --gpgdir wins",
		signed_conf(&format!(
			"GPGDir = {}\nSigLevel = Required\n",
			w.w_str("gnupg")
		)),
		[
			strs(&["-Sy"]),
			w.paths(&["--gpgdir"]),
			vec![format!("--gpgdir={pgp}")],
		]
		.concat(),
	)
	.how(ROOT));
	// HoldPkg: the removal asks; with no stdin the answer is no, with
	// --noconfirm the question is printed and takes its default, no
	cases.push(with_without(
		&w,
		"HoldPkg: -R asks",
		"HoldPkg = delta\n",
		"",
		&["-R", "delta"],
	)
	.how(ROOT));
	cases.push(with_without(
		&w,
		"HoldPkg: -R --noconfirm",
		"HoldPkg = delta\n",
		"",
		&["-R", "--noconfirm", "delta"],
	)
	.how(ROOT));
	// IgnorePkg, IgnoreGroup: -Sup leaves the upgrade out, with a
	// warning; --ignore adds to the file's list
	cases.push(with_without(
		&w,
		"IgnorePkg: -Sup",
		"IgnorePkg = alpha\n",
		"",
		&["-Sup"],
	));
	cases.push(with_without(
		&w,
		"IgnorePkg: -Sp asks (print answers yes)",
		"IgnorePkg = alpha\n",
		"",
		&["-Sp", "alpha"],
	));
	cases.push(with_without(
		&w,
		"IgnorePkg: --ignore adds",
		"IgnorePkg = alpha\n",
		"",
		&["-Sp", "--ignore", "beta", "alpha", "beta"],
	));
	cases.push(with_without(
		&w,
		"IgnoreGroup: -Sup",
		"IgnoreGroup = grp\n",
		"",
		&["-Sup"],
	));
	cases.push(with_without(
		&w,
		"IgnoreGroup: --ignoregroup adds",
		"IgnoreGroup = nope\n",
		"",
		&["-Sp", "--ignoregroup", "grp", "alpha"],
	));
	// Architecture: a package of another arch is refused; auto is the
	// machine's; two lines add up; --arch adds
	for (label, value) in [
		(
			"Architecture: x86_64 refuses armv7h",
			"Architecture = x86_64\n",
		),
		("Architecture: auto refuses armv7h", "Architecture = auto\n"),
		(
			"Architecture: two lines allow both",
			"Architecture = x86_64\nArchitecture = armv7h\n",
		),
	] {
		let without = match value.contains("armv7h") {
			true => "Architecture = x86_64\n",
			false => "",
		};
		cases.push(with_without(
			&w,
			label,
			value,
			without,
			&["-Sp", "gamma"],
		));
	}
	cases.push(with_without(
		&w,
		"Architecture: --arch adds",
		"Architecture = x86_64\n",
		"",
		&["-Sp", "--arch", "armv7h", "gamma"],
	)
	.without(conf("Architecture = x86_64\n", &[("core", "Server = x\n")])));
	// $arch and $repo in Server with Architecture = auto
	let arch_mirror = format!("file://{}/$arch/$repo", w.at("mirror"));
	let repos = [("core", format!("Server = {arch_mirror}\n"))];
	let repos: Vec<(&str, &str)> =
		repos.iter().map(|(n, s)| (*n, s.as_str())).collect();
	cases.push(Case::new(
		"Architecture: auto in $arch",
		conf("Architecture = auto\n", &repos),
		[strs(&["-Sy"]), w.paths(&[])].concat(),
	)
	.how(ROOT)
	.without(conf("", &repos)));
	// NoUpgrade: the upgraded file lands as .pacnew; a ! entry takes a
	// file out of an earlier pattern
	let up = w.pkg_file(&ALPHA2);
	cases.push(with_without(
		&w,
		"NoUpgrade: .pacnew",
		"NoUpgrade = etc/alpha.conf\n",
		"",
		&["-U", "--noconfirm", &up],
	)
	.how(CHROOT));
	cases.push(with_without(
		&w,
		"NoUpgrade: ! negation",
		"NoUpgrade = etc/* !etc/alpha.conf\n",
		"NoUpgrade = etc/*\n",
		&["-U", "--noconfirm", &up],
	)
	.how(CHROOT));
	let beta = w.pkg_file(&BETA);
	cases.push(with_without(
		&w,
		"NoExtract: doc left out",
		"NoExtract = usr/share/doc/*\n",
		"",
		&["-U", "--noconfirm", &beta],
	)
	.how(CHROOT));
	cases.push(with_without(
		&w,
		"NoExtract: ! negation",
		"NoExtract = usr/share/doc/* !usr/share/doc/beta/keep\n",
		"NoExtract = usr/share/doc/*\n",
		&["-U", "--noconfirm", &beta],
	)
	.how(CHROOT));
	// CleanMethod: what -Sc keeps
	for (label, value) in [
		("CleanMethod: KeepCurrent", "CleanMethod = KeepCurrent\n"),
		(
			"CleanMethod: KeepInstalled KeepCurrent",
			"CleanMethod = KeepInstalled KeepCurrent\n",
		),
	] {
		cases.push(with_without(
			&w,
			label,
			value,
			"",
			&["-Sc", "--noconfirm"],
		)
		.how(ROOT)
		.prep(seed_cache));
	}
	// CheckSpace: the disk space step shows (no bars off a tty)
	cases.push(with_without(
		&w,
		"CheckSpace: -U",
		"CheckSpace\n",
		"",
		&["-U", "--noconfirm", &beta],
	)
	.how(CHROOT));
	// VerbosePkgLists: the targets table before the prompt (no stdin:
	// the prompt gets no and the transaction is dropped)
	cases.push(with_without(
		&w,
		"VerbosePkgLists: -S",
		"VerbosePkgLists\n",
		"",
		&["-S", "beta"],
	)
	.how(ROOT));
	cases.push(with_without(
		&w,
		"VerbosePkgLists: -R",
		"VerbosePkgLists\n",
		"",
		&["-R", "delta"],
	)
	.how(ROOT));
	compare(&w, cases);
}

// SigLevel in [options] and per repo, LocalFileSigLevel,
// RemoteFileSigLevel: a signed core.db on file:// mirrors and the
// fixture keyring (full and marginal trust), unsigned packages
#[test]
fn signatures() {
	let w = World::new("cm-sig");
	let pgp = lossy(&w.gpg.home(Home::Pgp));
	let mut cases = Vec::new();
	let signed = |key: &str| {
		format!(
			"Server = file://{}\n",
			w.at(&format!("mirror/signed-{key}"))
		)
	};
	let plain = |repo: &str| format!("Server = {}\n", w.file_mirror(repo));
	let sy = |drop: &[&str]| [strs(&["-Sy"]), w.paths(drop)].concat();
	let gpg_args = [
		strs(&["-Sy"]),
		w.paths(&["--gpgdir"]),
		vec![format!("--gpgdir={pgp}")],
	]
	.concat();
	// [options] SigLevel: Never takes an unsigned db, the default does
	// not; Optional takes it (the .sig fetch fails silently); Required
	// with the keyring takes the signed one
	let core = [("core", plain("core"))];
	let core: Vec<(&str, &str)> =
		core.iter().map(|(n, s)| (*n, s.as_str())).collect();
	let opt = |o: &str, repos: &[(&str, &str)]| {
		let mut s = format!("[options]\n{o}");
		for (n, l) in repos {
			s.push_str(&format!("[{n}]\n{l}"));
		}
		s
	};
	cases.push(Case::new(
		"SigLevel: Never on an unsigned db",
		opt("SigLevel = Never\n", &core),
		sy(&[]),
	)
	.how(ROOT)
	.without(opt("", &core)));
	cases.push(Case::new(
		"SigLevel: Optional on an unsigned db",
		opt("SigLevel = Optional\n", &core),
		sy(&[]),
	)
	.how(ROOT)
	.without(opt("", &core)));
	cases.push(Case::new(
		"SigLevel: DatabaseOptional PackageRequired",
		opt("SigLevel = Required DatabaseOptional\n", &core),
		sy(&[]),
	)
	.how(ROOT)
	.without(opt("SigLevel = Required\n", &core)));
	let full = [("core", signed("full"))];
	let full: Vec<(&str, &str)> =
		full.iter().map(|(n, s)| (*n, s.as_str())).collect();
	cases.push(Case::new(
		"SigLevel: Required, signed db, keyring",
		opt("SigLevel = Required\n", &full),
		gpg_args.clone(),
	)
	.how(ROOT)
	.without(
		opt("SigLevel = Required\n", &full)
			.replace("signed-full", "core"),
	));
	// TrustAll takes a marginally trusted signer, TrustedOnly not
	let marg = [("core", signed("marg"))];
	let marg: Vec<(&str, &str)> =
		marg.iter().map(|(n, s)| (*n, s.as_str())).collect();
	cases.push(Case::new(
		"SigLevel: Required TrustAll on marginal trust",
		opt("SigLevel = Required TrustAll\n", &marg),
		gpg_args.clone(),
	)
	.how(ROOT)
	.without(opt("SigLevel = Required\n", &marg)));
	cases.push(Case::new(
		"SigLevel: TrustedOnly on marginal trust",
		opt("SigLevel = Required TrustedOnly\n", &marg),
		gpg_args.clone(),
	)
	.how(ROOT)
	.without(opt("SigLevel = Required TrustAll\n", &marg)));
	// a repo's SigLevel overrides [options]: core unsigned at Never,
	// extra unsigned at the default fails
	let per_repo = |core_level: &str| {
		format!(
			"[options]\n[core]\n{core_level}{}[extra]\n{}",
			plain("core"),
			plain("extra")
		)
	};
	cases.push(Case::new(
		"SigLevel: per repo Never",
		per_repo("SigLevel = Never\n"),
		sy(&[]),
	)
	.how(ROOT)
	.without(per_repo("")));
	cases.push(Case::new(
		"SigLevel: per repo PackageNever keeps the db check",
		per_repo("SigLevel = PackageNever\n"),
		sy(&[]),
	)
	.how(ROOT)
	.without(per_repo("SigLevel = Never\n")));
	// LocalFileSigLevel: -Up of an unsigned file at Required fails, at
	// the default (SigLevel Never) loads; Optional loads the signed and
	// the unsigned
	let zeta = w.pkg_file(&ZETA);
	let beta = w.pkg_file(&BETA);
	let local =
		|level: &str| opt(&format!("SigLevel = Never\n{level}"), &core);
	cases.push(Case::new(
		"LocalFileSigLevel: Required on an unsigned file",
		local("LocalFileSigLevel = Required\n"),
		[strs(&["-Up", &beta]), w.paths(&[])].concat(),
	)
	.without(local("")));
	cases.push(Case::new(
		"LocalFileSigLevel: Required on a signed file, keyring",
		local("LocalFileSigLevel = Required\n"),
		[
			strs(&["-Up", &zeta]),
			w.paths(&["--gpgdir"]),
			vec![format!("--gpgdir={pgp}")],
		]
		.concat(),
	)
	.without(
		local("LocalFileSigLevel = Required\n")
			.replace("Never", "Required"),
	));
	cases.push(Case::new(
		"LocalFileSigLevel: Optional, signed and unsigned",
		local("LocalFileSigLevel = Optional\n"),
		[
			strs(&["-Up", &zeta, &beta]),
			w.paths(&["--gpgdir"]),
			vec![format!("--gpgdir={pgp}")],
		]
		.concat(),
	)
	.without(local("LocalFileSigLevel = Required\n")));
	// RemoteFileSigLevel: -Up of a url (the built-in downloader, no
	// sandbox user) at Required fails after the download
	let url = format!("{}/m/core/{}", w.srv.base(), filename(&BETA));
	cases.push(Case::new(
		"RemoteFileSigLevel: Required on an unsigned url",
		local("RemoteFileSigLevel = Required\n"),
		[strs(&["-Up", &url]), w.paths(&[])].concat(),
	)
	.without(local("")));
	cases.push(Case::new(
		"RemoteFileSigLevel: LocalFileSigLevel does not apply to urls",
		local("LocalFileSigLevel = Required\n"),
		[strs(&["-Up", &url]), w.paths(&[])].concat(),
	)
	.without(local("RemoteFileSigLevel = Required\n")));
	compare(&w, cases);
}

// Color, NoProgressBar, ILoveCandy need a terminal: both streams on a
// pty through script(1); --color=never and --noprogressbar override
#[test]
fn terminal() {
	let w = World::new("cm-tty");
	let pty = How { pty: true, ..PLAIN };
	let pty_root = How { pty: true, ..ROOT };
	let pty_chroot = How {
		pty: true,
		..CHROOT
	};
	let beta = w.pkg_file(&BETA);
	let cases = vec![
		with_without(
			&w,
			"Color: -Ss on a tty",
			"Color\n",
			"",
			&["-Ss", "beta"],
		)
		.how(pty),
		with_without(
			&w,
			"Color: -Qi on a tty",
			"Color\n",
			"",
			&["-Qi", "alpha"],
		)
		.how(pty),
		with_without(
			&w,
			"Color: --color=never wins",
			"Color\n",
			"",
			&["-Ss", "--color=never", "beta"],
		)
		.how(pty),
		// the download line without a bar (the bar's rate and time
		// vary between runs: only the directive's side is compared)
		with_without(
			&w,
			"NoProgressBar: -Sy on a tty",
			"NoProgressBar\n",
			"",
			&["-Sy"],
		)
		.how(pty_root),
		with_without(
			&w,
			"NoProgressBar: -U on a tty",
			"NoProgressBar\n",
			"",
			&["-U", "--noconfirm", &beta],
		)
		.how(pty_chroot),
		with_without(
			&w,
			"NoProgressBar: --noprogressbar",
			"",
			"",
			&["-U", "--noconfirm", "--noprogressbar", &beta],
		)
		.how(pty_chroot),
		// the install bar is drawn per file: deterministic for one
		// package, the pacman chomps through it
		with_without(
			&w,
			"ILoveCandy: -U on a tty",
			"ILoveCandy\n",
			"",
			&["-U", "--noconfirm", &beta],
		)
		.how(pty_chroot),
	];
	// --noprogressbar: its proof is NoProgressBar's case
	let cases: Vec<Case> = cases
		.into_iter()
		.map(|c| match c.label.contains("--noprogressbar") {
			true => Case { without: None, ..c },
			false => c,
		})
		.collect();
	compare(&w, cases);
}

// the download directives on HTTP mirrors: ParallelDownloads,
// DisableDownloadTimeout, DownloadUser with DisableSandbox, Server
// lists, CacheServer, Usage, Include
#[test]
fn downloads() {
	let w = World::new("cm-dl");
	let http = |repo: &str| format!("Server = {}\n", w.http_mirror(repo));
	let core = [("core", http("core"))];
	let core: Vec<(&str, &str)> =
		core.iter().map(|(n, s)| (*n, s.as_str())).collect();
	let both = [("core", http("core")), ("extra", http("extra"))];
	let both: Vec<(&str, &str)> =
		both.iter().map(|(n, s)| (*n, s.as_str())).collect();
	let args = |a: &[&str]| [strs(a), w.paths(&[])].concat();
	let mut cases = Vec::new();
	// ParallelDownloads: three packages stalled 1 s each, how many ran
	// at once at the server
	let stall = |p: &Pkg| {
		let body =
			fs::read(w.dir().join("mirror/core").join(filename(p)))
				.unwrap();
		Reply::Stall {
			body,
			at: 0,
			pause: Duration::from_millis(700),
			finish: true,
		}
	};
	let stalled = |c: Case| {
		c.route(
			&format!("/m/core/{}", filename(&ALPHA2)),
			vec![stall(&ALPHA2)],
		)
		.route(
			&format!("/m/core/{}", filename(&BETA)),
			vec![stall(&BETA)],
		)
		.route(
			&format!("/m/core/{}", filename(&GAMMA)),
			vec![stall(&GAMMA)],
		)
	};
	let sw = args(&["-Sw", "--noconfirm", "alpha", "beta", "gamma"]);
	cases.push(stalled(Case::new(
		"ParallelDownloads: 2 streams",
		conf("ParallelDownloads = 2\n", &core),
		sw.clone(),
	)
	.how(ROOT)
	.unordered()
	.without(conf("", &core))));
	cases.push(stalled(Case::new(
		"ParallelDownloads: last line wins",
		conf("ParallelDownloads = 3\nParallelDownloads = 1\n", &core),
		sw.clone(),
	)
	.how(ROOT)
	.without(conf("ParallelDownloads = 3\n", &core))));
	cases.push(stalled(Case::new(
		"ParallelDownloads: 300 is accepted",
		conf("ParallelDownloads = 300\n", &core),
		sw.clone(),
	)
	.how(ROOT)
	.unordered()
	.without(conf("", &core))));
	// DisableDownloadTimeout: a db that stalls past curl's 10 s low
	// speed time
	let slow = Reply::Stall {
		body: fs::read(w.dir().join("mirror/core/core.db")).unwrap(),
		at: 0,
		pause: Duration::from_millis(11_500),
		finish: true,
	};
	cases.push(Case::new(
		"DisableDownloadTimeout: a stalled db",
		conf("DisableDownloadTimeout\n", &core),
		args(&["-Sy"]),
	)
	.how(ROOT)
	.route("/m/core/core.db", vec![slow.clone()])
	.without(conf("", &core)));
	cases.push(Case::new(
		"DisableDownloadTimeout: --disable-download-timeout",
		conf("", &core),
		args(&["-Sy", "--disable-download-timeout"]),
	)
	.how(ROOT)
	.route("/m/core/core.db", vec![slow]));
	// DownloadUser with the sandbox off (seccomp and landlock), or with
	// the syscall filter alone. landlock alone is not comparable here:
	// the C applies it before no_new_privs, which only real root may,
	// the port after (UPSTREAM.md)
	cases.push(Case::new(
		"DisableSandbox: DownloadUser -Sy --debug",
		conf("DownloadUser = nobody\nDisableSandbox\n", &core),
		args(&["-Sy", "--debug"]),
	)
	.how(ROOT)
	.without(conf(
		"DownloadUser = nobody\nDisableSandboxFilesystem\n",
		&core,
	)));
	cases.push(Case::new(
		"DisableSandboxFilesystem: seccomp stays on",
		conf(
			"DownloadUser = nobody\nDisableSandboxFilesystem\n",
			&core,
		),
		args(&["-Sy", "--debug"]),
	)
	.how(ROOT)
	.without(conf("DownloadUser = nobody\nDisableSandbox\n", &core)));
	cases.push(Case::new(
		"DisableSandbox: --disable-sandbox",
		conf("DownloadUser = nobody\n", &core),
		args(&["-Sy", "--disable-sandbox"]),
	)
	.how(ROOT));
	cases.push(Case::new(
		"DownloadUser: first line wins",
		conf(
			"DownloadUser = nobody\nDownloadUser = no-such-user\nDisableSandbox\n",
			&core,
		),
		args(&["-Sy"]),
	)
	.how(ROOT)
	.without(conf(
		"DownloadUser = no-such-user\nDownloadUser = nobody\nDisableSandbox\n",
		&core,
	)));
	// Server: the next server after a failed one (a closed port, a
	// 404), $repo
	let dead = format!("http://127.0.0.1:{}/m/core", closed_port());
	let two = format!("Server = {dead}\n{}", http("core"));
	let one = format!("Server = {dead}\n");
	cases.push(Case::new(
		"Server: second after a refused connection",
		conf("", &[("core", &two)]),
		args(&["-Sy"]),
	)
	.how(ROOT)
	.without(conf("", &[("core", &one)])));
	let two = format!(
		"Server = {}/none/core\n{}",
		w.srv.base(),
		http("core")
	);
	let one = format!("Server = {}/none/core\n", w.srv.base());
	cases.push(Case::new(
		"Server: second after a 404",
		conf("", &[("core", &two)]),
		args(&["-Sy"]),
	)
	.how(ROOT)
	.without(conf("", &[("core", &one)])));
	let repo = format!("Server = {}/m/$repo\n", w.srv.base());
	cases.push(Case::new(
		"Server: $repo",
		conf("", &[("core", &repo), ("extra", &repo)]),
		args(&["-Sy"]),
	)
	.how(ROOT)
	.without(conf("", &[("core", &repo)])));
	// CacheServer: packages from it first, never the db; a 404 there
	// falls back to Server without dropping it
	let cs = format!("CacheServer = {}/cs\n{}", w.srv.base(), http("core"));
	cases.push(Case::new(
		"CacheServer: -Sw from the cache server",
		conf("", &[("core", &cs)]),
		args(&["-Sw", "--noconfirm", "beta"]),
	)
	.how(ROOT)
	.without(conf("", &core)));
	cases.push(Case::new(
		"CacheServer: -Sy never from it",
		conf("", &[("core", &cs)]),
		args(&["-Sy"]),
	)
	.how(ROOT)
	.without(conf(
		"",
		&[("core", &format!("CacheServer = {}/cs\n", w.srv.base()))],
	)));
	cases.push(Case::new(
		"CacheServer: 404 falls back, server kept",
		conf("", &[("core", &cs)]),
		args(&["-Sw", "--noconfirm", "beta", "gamma"]),
	)
	.how(ROOT)
	.route(
		&format!("/cs/{}", filename(&BETA)),
		vec![Reply::Status(404, b"nope".to_vec())],
	)
	.without(conf("", &core)));
	// Usage: Search finds, Install does not; Sync alone refreshes but
	// is not searched; Install alone is not refreshed
	let usage = |u: &str| format!("Usage = {u}\n{}", http("core"));
	for (label, u, op) in [
		("Usage: Search finds", "Search", &["-Ss", "beta"][..]),
		("Usage: Search does not install", "Search", &["-Sp", "beta"]),
		(
			"Usage: Sync alone is not searched",
			"Sync",
			&["-Ss", "beta"],
		),
		("Usage: Install alone is not refreshed", "Install", &["-Sy"]),
		("Usage: Install upgrades nothing", "Install", &["-Sup"]),
		(
			"Usage: Upgrade installs nothing",
			"Upgrade",
			&["-Sp", "beta"],
		),
		("Usage: Upgrade upgrades", "Upgrade", &["-Sup"]),
		(
			"Usage: two lines add up",
			"Search\nUsage = Install",
			&["-Sp", "beta"],
		),
	] {
		let how = if op[0] == "-Sy" { ROOT } else { PLAIN };
		cases.push(Case::new(
			label,
			conf("", &[("core", &usage(u))]),
			args(op),
		)
		.how(how)
		.without(conf("", &core)));
	}
	// Include: a glob of files, one of them including a nested file;
	// the repos only exist through them
	let inc = w.w_str("inc");
	fs::write(
		w.dir().join("orig/inc/a.conf"),
		format!("[core]\n{}", http("core")),
	)
	.unwrap();
	fs::write(
		w.dir().join("orig/inc/b.conf"),
		format!("Include = {inc}/nested/c.conf\n"),
	)
	.unwrap();
	fs::write(
		w.dir().join("orig/inc/nested/c.conf"),
		format!("[extra]\n{}", http("extra")),
	)
	.unwrap();
	fs::write(w.dir().join("orig/inc/d.txt"), "Server = x\n").unwrap();
	cases.push(Case::new(
		"Include: glob and nested",
		conf(&format!("Include = {inc}/*.conf\n"), &[]),
		args(&["-Sp", "beta", "eps"]),
	)
	.without(conf("", &[])));
	cases.push(Case::new(
		"Include: a repo section opened in the include",
		conf(&format!("Include = {inc}/a.conf\nUsage = Search\n"), &[]),
		args(&["-Sp", "beta"]),
	)
	.without(conf(&format!("Include = {inc}/a.conf\n"), &[])));
	cases.push(Case::new(
		"Include: missing file",
		conf(&format!("Include = {inc}/nope.conf\n"), &both),
		args(&["-Sp", "beta"]),
	));
	cases.push(Case::new(
		"Include: glob matching nothing",
		conf(&format!("Include = {inc}/none-*.conf\n"), &both),
		args(&["-Sp", "beta"]),
	));
	cases.push(Case::new(
		"Include: self include",
		conf(&format!("Include = {}\n", w.w_str("pacman.conf")), &both),
		args(&["-Sp", "beta"]),
	));
	compare(&w, cases);
}

// UseSyslog: the packets at /dev/log, bound over by a datagram socket of
// the test inside a user and mount namespace
#[test]
fn syslog() {
	let w = World::new("cm-syslog");
	let how = How {
		fake: Fake::Syslog,
		..PLAIN
	};
	let cases = vec![
		with_without(&w, "UseSyslog: -Sy", "UseSyslog\n", "", &["-Sy"])
			.how(how),
		with_without(
			&w,
			"UseSyslog: -D --asdeps",
			"UseSyslog\n",
			"",
			&["-D", "--asdeps", "delta"],
		)
		.how(how),
	];
	compare(&w, cases);
}

// the error paths of parsing: rc, stderr, nothing else runs
#[test]
fn errors() {
	let w = World::new("cm-err");
	let core = [("core", format!("Server = {}\n", w.file_mirror("core")))];
	let core: Vec<(&str, &str)> =
		core.iter().map(|(n, s)| (*n, s.as_str())).collect();
	let args = [strs(&["-Sp", "beta"]), w.paths(&[])].concat();
	let case = |label: &str, text: String| {
		Case::new(label, text, args.clone())
	};
	let cases = vec![
		case(
			"unknown directive with a value",
			conf("Bogus = 1\n", &core),
		),
		case("unknown flag", conf("Bogus\n", &core)),
		case("Server in [options]", conf("Server = x\n", &core)),
		case(
			"NoUpgrade in a repo",
			conf(
				"",
				&[("core", "NoUpgrade = etc/x\nServer = x\n")],
			),
		),
		case(
			"Server without a value",
			conf("", &[("core", "Server\n")]),
		),
		case(
			"Usage without a value",
			conf("", &[("core", "Usage\nServer = x\n")]),
		),
		case("IgnorePkg without a value", conf("IgnorePkg\n", &core)),
		case("Include without a value", conf("Include\n", &core)),
		case(
			"directive before any section",
			format!("NoUpgrade = x\n{}", conf("", &core)),
		),
		case(
			"ParallelDownloads 0",
			conf("ParallelDownloads = 0\n", &core),
		),
		case(
			"ParallelDownloads -1",
			conf("ParallelDownloads = -1\n", &core),
		),
		case(
			"ParallelDownloads abc",
			conf("ParallelDownloads = abc\n", &core),
		),
		case(
			"ParallelDownloads 2147483648",
			conf("ParallelDownloads = 2147483648\n", &core),
		),
		case(
			"ParallelDownloads empty",
			conf("ParallelDownloads =\n", &core),
		),
		case("CleanMethod foo", conf("CleanMethod = foo\n", &core)),
		case(
			"CleanMethod KeepCurrent foo",
			conf("CleanMethod = KeepCurrent foo\n", &core),
		),
		case("SigLevel garbage", conf("SigLevel = garbage\n", &core)),
		case(
			"SigLevel PackageGarbage",
			conf("SigLevel = Never PackageGarbage\n", &core),
		),
		case(
			"repo SigLevel garbage",
			conf(
				"",
				&[("core", "SigLevel = garbage\nServer = x\n")],
			),
		),
		case(
			"LocalFileSigLevel garbage",
			conf("LocalFileSigLevel = garbage\n", &core),
		),
		case(
			"Usage garbage",
			conf("", &[("core", "Usage = garbage\nServer = x\n")]),
		),
		case(
			"Usage Sync garbage",
			conf(
				"",
				&[(
					"core",
					"Usage = Sync garbage\nServer = x\n",
				)],
			),
		),
		case(
			"XferCommand unbalanced quote",
			conf("XferCommand = /usr/bin/curl -o \"%o %u\n", &core),
		),
		case(
			"RootDir missing",
			conf("RootDir = /nonexistent/root\n", &core),
		),
		case(
			"$arch without Architecture",
			conf(
				"",
				&[("core", "Server = http://m/$repo/$arch\n")],
			),
		),
		case("no section at all", String::new()),
		case("lowercase directive", conf("noupgrade = x\n", &core)),
		case("[local] repo", conf("", &[("local", "Server = x\n")])),
	];
	// RootDir missing: the path is resolved only without --root
	let cases: Vec<Case> = cases
		.into_iter()
		.map(|c| match c.label.as_str() {
			"RootDir missing" => Case {
				args: [
					strs(&["-Sp", "beta"]),
					w.paths(&["--root"]),
				]
				.concat(),
				..c
			},
			_ => c,
		})
		.collect();
	compare(&w, cases);
}

// --sysroot: every path and file:// server under it, the config too.
// RootDir, DBPath and GPGDir are realpath'd on the host before the
// prefix (resolve_path runs at parse time, prepend_sysroot after), so
// only "/" can be given for them: DBPath and GPGDir keep their defaults
// under the sysroot (var/lib/pacman, etc/pacman.d/gnupg)
#[test]
fn sysroot() {
	let w = World::new("cm-sysroot");
	let text = "[options]\nSigLevel = Never\nRootDir = /\n\
		CacheDir = /cache\nLogFile = /log/pacman.log\n\
		HookDir = /hooks\n[core]\nServer = file:///mirror/core\n";
	let sysroot = w.w_str("");
	let sysroot = sysroot.trim_end_matches('/').to_string();
	let prep: fn(&World) = |w| {
		let w = w.w();
		std::os::unix::fs::symlink("../mirror", w.join("mirror"))
			.unwrap();
		fs::create_dir_all(w.join("var/lib")).unwrap();
		std::os::unix::fs::symlink(
			"../../db",
			w.join("var/lib/pacman"),
		)
		.unwrap();
		fs::create_dir_all(w.join("etc/pacman.d/gnupg")).unwrap();
	};
	let args = |op: &str| {
		vec![
			format!("--sysroot={sysroot}"),
			"--config=/pacman.conf".into(),
			op.into(),
		]
	};
	let cases = vec![
		Case::new("--sysroot: -Sy", text.to_string(), args("-Sy"))
			.how(ROOT)
			.prep(prep),
		Case::new("--sysroot: -Q", text.to_string(), args("-Q"))
			.prep(prep),
		Case::new("--sysroot: -Qk", text.to_string(), args("-Qk"))
			.prep(prep),
	];
	compare(&w, cases);
}

// ---- XferCommand ----

// the script dumping its environment to w/xfer.env before curl
fn env_script(w: &World) -> String {
	let path = w.dir().join("xfer-env.sh");
	let env = w.w_str("xfer.env");
	fs::write(
		&path,
		format!(
			"#!/bin/sh\nenv | sort > '{env}'\nexec curl -sSf -o \"$2\" \"$1\"\n"
		),
	)
	.unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
	path.display().to_string()
}

// XferCommand with curl in every documented shape (pacman.conf(5), the
// shipped pacman.conf, the Arch wiki's wget and aria2c lines as curl
// stands in for them): -Sy, -Sw of a package, -U of a url, on the HTTP
// mirror and file://; the command's cwd (no %o), its environment, PATH
// lookup, failures, partial files and resumes, the directives that
// interact with it
#[test]
fn xfercommand() {
	let w = World::new("cm-xfer");
	let http = |repo: &str| format!("Server = {}\n", w.http_mirror(repo));
	let filem = |repo: &str| format!("Server = {}\n", w.file_mirror(repo));
	let core_http = [("core", http("core"))];
	let core_http: Vec<(&str, &str)> =
		core_http.iter().map(|(n, s)| (*n, s.as_str())).collect();
	let core_file = [("core", filem("core"))];
	let core_file: Vec<(&str, &str)> =
		core_file.iter().map(|(n, s)| (*n, s.as_str())).collect();
	let args = |a: &[&str]| [strs(a), w.paths(&[])].concat();
	let url = format!("{}/m/core/{}", w.srv.base(), filename(&BETA));
	let mut cases = Vec::new();
	// the documented forms, each on -Sy, -Sw and -U <url>
	let forms: [(&str, &str); 6] = [
		// pacman.conf(5) and the wiki
		("curl -L -C -", "/usr/bin/curl -L -C - -f -o %o %u"),
		// the shipped pacman.conf's commented line
		(
			"curl --retry",
			"/usr/bin/curl -fC - --retry 3 --retry-delay 3 -o %o %u",
		),
		// wget --passive-ftp -c -O %o %u: -c is -C -, -O is -o
		("wget shape", "/usr/bin/curl -sS -C - -o %o %u"),
		// aria2c --allow-overwrite=true --continue=true ... --dir=/ --out
		// %o %u: long options, the output as a dir plus a name
		(
			"aria2c shape",
			"/usr/bin/curl --retry=2 --max-time=15 --remote-time --output-dir / -o %o %u",
		),
		// no %o: the file lands in the cwd, the download dir, under the
		// url's basename
		("no %o", "/usr/bin/curl -sSf -O %u"),
		// a relative command through PATH
		("relative command", "curl -sSf -o %o %u"),
	];
	for (label, cmd) in forms {
		let x = format!("XferCommand = {cmd}\n");
		for op in [
			&["-Sy"][..],
			&["-Sw", "--noconfirm", "beta"],
			&["-U", "--noconfirm", &url],
		] {
			cases.push(Case::new(
				&format!("{label}: {}", op.join(" ")),
				conf(&x, &core_http),
				args(op),
			)
			.how(XFER_ROOT)
			.without(conf("", &core_http)));
		}
		cases.push(Case::new(
			&format!("{label}: -Sy file://"),
			conf(&x, &core_file),
			args(&["-Sy"]),
		)
		.how(XFER_ROOT)
		.without(conf("", &core_file)));
	}
	// quotes and spaces: the quoted %o and %u are still the whole
	// argument; the agent with a space reaches the server
	let quoted = "XferCommand = \"/usr/bin/curl\" -sSf --user-agent \"conf matrix agent\" -o '%o' \"%u\"\n";
	cases.push(Case::new(
		"quotes and spaces: -Sy",
		conf(quoted, &core_http),
		args(&["-Sy"]),
	)
	.how(XFER_ROOT)
	.without(conf("", &core_http)));
	// %o inside a word is not replaced
	let inword = "XferCommand = /usr/bin/curl -sSf -o%o %u\n";
	cases.push(Case::new(
		"%o inside a word",
		conf(inword, &core_http),
		args(&["-Sy"]),
	)
	.how(XFER_ROOT)
	.without(conf("", &core_http)));
	// the last XferCommand line wins
	let twice = "XferCommand = /nonexistent/dl %u %o\nXferCommand = /usr/bin/curl -sSf -o %o %u\n";
	cases.push(Case::new(
		"last line wins",
		conf(twice, &core_http),
		args(&["-Sy"]),
	)
	.how(XFER_ROOT)
	.without(conf("XferCommand = /nonexistent/dl %u %o\n", &core_http)));
	// not found: absolute and through PATH; non-zero exit (curl -f on
	// a 404 exits 22); each failed fetch waits 2 s
	for (label, cmd) in [
		("not found: absolute", "/nonexistent/dl -o %o %u"),
		("not found: through PATH", "no-such-downloader -o %o %u"),
		("not executable", "/etc/hostname %u %o"),
	] {
		cases.push(Case::new(
			label,
			conf(&format!("XferCommand = {cmd}\n"), &core_http),
			args(&["-Sy", "--debug"]),
		)
		.how(XFER_ROOT)
		.without(conf("", &core_http)));
	}
	let none = format!("Server = {}/none/core\n", w.srv.base());
	cases.push(Case::new(
		"exit 22 on a 404",
		conf(
			"XferCommand = /usr/bin/curl -sSf -o %o %u\n",
			&[("core", &none)],
		),
		args(&["-Sy", "--debug"]),
	)
	.how(XFER_ROOT)
	.without(conf("", &[("core", &none)])));
	// a partial file then a failure: the .part stays, the next server
	// resumes it with -C - (Range at the server), or overwrites it
	let beta_body =
		fs::read(w.dir().join("mirror/core").join(filename(&BETA)))
			.unwrap();
	let truncated = Reply::Truncated {
		body: beta_body.clone(),
		sent: 100,
	};
	let two =
		format!("Server = {}/cut/core\n{}", w.srv.base(), http("core"));
	for (label, cmd) in [
		(
			"partial then next server: resumed",
			"/usr/bin/curl -sSf -C - -o %o %u",
		),
		(
			"partial then next server: restarted",
			"/usr/bin/curl -sSf -o %o %u",
		),
	] {
		cases.push(Case::new(
			label,
			conf(
				&format!("XferCommand = {cmd}\n"),
				&[("core", &two)],
			),
			args(&["-Sw", "--noconfirm", "beta"]),
		)
		.how(XFER_ROOT)
		.route(
			&format!("/cut/core/{}", filename(&BETA)),
			vec![truncated.clone()],
		)
		.route(
			"/cut/core/core.db",
			vec![Reply::Status(404, Vec::new())],
		)
		.without(conf("", &[("core", &two)])));
	}
	// a .part already in the cache: resumed from its size, or refused
	// by curl where the server has no ranges (exit 33)
	let seed_part: fn(&World) = |w| {
		let body = fs::read(
			w.dir().join("mirror/core").join(filename(&BETA)),
		)
		.unwrap();
		let part =
			w.w().join("cache")
				.join(format!("{}.part", filename(&BETA)));
		fs::write(part, &body[..50]).unwrap();
	};
	cases.push(Case::new(
		"resume an existing .part",
		conf(
			"XferCommand = /usr/bin/curl -sSf -C - -o %o %u\n",
			&core_http,
		),
		args(&["-Sw", "--noconfirm", "beta"]),
	)
	.how(XFER_ROOT)
	.prep(seed_part)
	.without(conf(
		"XferCommand = /usr/bin/curl -sSf -o %o %u\n",
		&core_http,
	)));
	let noranges = Reply::File {
		body: beta_body.clone(),
		ranges: false,
		mtime: Some(1_000_000_000),
	};
	cases.push(Case::new(
		"resume where the server has no ranges",
		conf(
			"XferCommand = /usr/bin/curl -sSf -C - -o %o %u\n",
			&core_http,
		),
		args(&["-Sw", "--noconfirm", "beta"]),
	)
	.how(XFER_ROOT)
	.prep(seed_part)
	.route(&format!("/m/core/{}", filename(&BETA)), vec![noranges])
	.without(conf(
		"XferCommand = /usr/bin/curl -sSf -o %o %u\n",
		&core_http,
	)));
	// a .sig next to the db: Optional fetches it and goes on without,
	// Required with the keyring verifies what the command fetched
	let pgp = lossy(&w.gpg.home(Home::Pgp));
	let signed = format!("Server = {}/sfull\n", w.srv.base());
	let curl = "XferCommand = /usr/bin/curl -sSf -o %o %u\n";
	cases.push(Case::new(
		"sig: DatabaseOptional fetches the .sig",
		format!(
			"[options]\nSigLevel = DatabaseOptional\n{curl}[core]\n{}",
			http("core")
		),
		args(&["-Sy"]),
	)
	.how(XFER_ROOT)
	.without(format!(
		"[options]\nSigLevel = Never\n{curl}[core]\n{}",
		http("core")
	)));
	cases.push(Case::new(
		"sig: Required verifies the fetched .sig",
		format!(
			"[options]\nSigLevel = Required\n{curl}[core]\n{signed}"
		),
		[
			strs(&["-Sy"]),
			w.paths(&["--gpgdir"]),
			vec![format!("--gpgdir={pgp}")],
		]
		.concat(),
	)
	.how(XFER_ROOT)
	.without(format!("[options]\nSigLevel = Required\n[core]\n{signed}")));
	// DownloadUser: the command runs as the user through the sandbox
	// exec path (fakeroot fakes the switch on both sides)
	cases.push(Case::new(
		"DownloadUser with XferCommand: -Sy",
		conf(&format!("{curl}DownloadUser = nobody\n"), &core_http),
		args(&["-Sy"]),
	)
	.how(XFER_ROOT)
	.without(conf("DownloadUser = nobody\nDisableSandbox\n", &core_http)));
	cases.push(Case::new(
		"DownloadUser with XferCommand: -Sw",
		conf(&format!("{curl}DownloadUser = nobody\n"), &core_http),
		args(&["-Sw", "--noconfirm", "beta"]),
	)
	.how(XFER_ROOT)
	.without(conf("DownloadUser = nobody\nDisableSandbox\n", &core_http)));
	// ParallelDownloads: the command runs one file at a time
	let stall = |p: &Pkg| {
		let body =
			fs::read(w.dir().join("mirror/core").join(filename(p)))
				.unwrap();
		Reply::Stall {
			body,
			at: 0,
			pause: Duration::from_millis(700),
			finish: true,
		}
	};
	cases.push(Case::new(
		"ParallelDownloads with XferCommand: serial",
		conf(&format!("{curl}ParallelDownloads = 5\n"), &core_http),
		args(&["-Sw", "--noconfirm", "alpha", "beta", "gamma"]),
	)
	.how(XFER_ROOT)
	.route(
		&format!("/m/core/{}", filename(&ALPHA2)),
		vec![stall(&ALPHA2)],
	)
	.route(&format!("/m/core/{}", filename(&BETA)), vec![stall(&BETA)])
	.route(
		&format!("/m/core/{}", filename(&GAMMA)),
		vec![stall(&GAMMA)],
	)
	.without(conf("ParallelDownloads = 5\n", &core_http)));
	// DisableDownloadTimeout: no effect on the command (its own
	// timeouts); the proof is its absence making no difference, so
	// none is asked
	cases.push(Case::new(
		"DisableDownloadTimeout with XferCommand: no effect",
		conf(&format!("{curl}DisableDownloadTimeout\n"), &core_http),
		args(&["-Sy"]),
	)
	.how(XFER_ROOT)
	.route("/m/core/core.db", vec![stall_db(&w, 1500)]));
	cases.push(Case::new(
		"XferCommand alone on the same stall",
		conf(curl, &core_http),
		args(&["-Sy"]),
	)
	.how(XFER_ROOT)
	.route("/m/core/core.db", vec![stall_db(&w, 1500)]));
	// the environment the command sees (HTTP_USER_AGENT apart: the C
	// sets it, the port not yet, PORTING.md handover row)
	let env = env_script(&w);
	cases.push(Case::new(
		"environment of the command",
		conf(&format!("XferCommand = {env} %u %o\n"), &core_http),
		args(&["-Sy"]),
	)
	.how(XFER_ROOT)
	.without(conf("", &core_http)));
	cases.push(Case::new(
		"environment of the command as DownloadUser",
		conf(
			&format!(
				"XferCommand = {env} %u %o\nDownloadUser = nobody\n"
			),
			&core_http,
		),
		args(&["-Sy"]),
	)
	.how(XFER_ROOT)
	.without(conf("", &core_http)));
	compare(&w, cases);
}

fn stall_db(w: &World, ms: u64) -> Reply {
	Reply::Stall {
		body: fs::read(w.dir().join("mirror/core/core.db")).unwrap(),
		at: 0,
		pause: Duration::from_millis(ms),
		finish: true,
	}
}

// what the C's HTTP_USER_AGENT is and whether the port sets one: read
// from the environment dump of the xfercommand cases, reported, not
// compared (PORTING.md handover row)
#[test]
fn user_agent_note() {
	let w = World::new("cm-agent");
	let env = env_script(&w);
	let core = [("core", format!("Server = {}\n", w.http_mirror("core")))];
	let core: Vec<(&str, &str)> =
		core.iter().map(|(n, s)| (*n, s.as_str())).collect();
	let case = Case::new(
		"agent",
		conf(&format!("XferCommand = {env} %u %o\n"), &core),
		[strs(&["-Sy"]), w.paths(&[])].concat(),
	)
	.how(XFER_ROOT);
	fs::write(w.dir().join("orig/pacman.conf"), &case.conf).unwrap();
	for (side, bin) in [("C", c_pacman()), ("Rust", rust_pacman())] {
		let _ = run(&bin, &case, &w);
		let env = fs::read_to_string(w.w().join("xfer.env")).unwrap();
		let agent =
			env.lines().find(|l| l.starts_with("HTTP_USER_AGENT="));
		println!("{side}: {}", agent.unwrap_or("no HTTP_USER_AGENT"));
	}
}
