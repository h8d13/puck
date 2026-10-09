// a hostile package mirror and a twin-run harness for the two package
// managers under test (C pacman at PACMAN_BUILD, puck). the adversarial
// sibling of the dload/sandbox difftests: instead of checking that a
// well-formed download is handled right, it serves malformed protocol
// and metadata (transport lies, metadata lies, archive attacks,
// signature attacks) and asserts BOTH binaries end in a safe state: a
// nonzero exit, no package registered in the local db, and nothing
// written outside the configured root. where C and puck differ, the
// harness records it; only one side failing the safe-state invariant is
// a real security-relevant divergence.
//
// the struct name is the one the user asked for. the joke: an "evil
// mirror pkger" packages nothing real, only lies, and it is ironic
// because a package manager's whole job is to trust a mirror just
// enough. it binds 127.0.0.1 on an ephemeral port, started and stopped
// in-process, and talks only to the two binaries under test.
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::add_commit::ac_owner;
use crate::dload::{Reply, Server};
use crate::fixtures::{
	Comp, Node, TempRoot, compress_bytes, section, snapshot, ustar_owned,
};
use crate::fixtures::{TarNode, c_pacman, rust_pacman, unstamp};
use crate::output_capped;
use crate::signing::{GpgFixture, Home};

// per-binary result of one run on the fixture root
#[derive(Debug)]
pub struct Outcome {
	pub rc: i32,
	pub out: Vec<u8>,
	pub err: Vec<u8>,
	// the install root and local db after the run, for divergence
	pub root: Node,
	pub local: Vec<String>,
}

// one case run on both binaries, for the report table
#[derive(Debug)]
pub struct Verdict {
	pub name: String,
	pub c: Outcome,
	pub puck: Outcome,
	// normalized (rc, stdout, stderr, root, local db) equal
	pub same: bool,
}

// the ironically-named hostile mirror plus the fixture root both
// binaries run against
pub struct IronicEvilMirrorPkger {
	fx: TempRoot,
	srv: Server,
	repo: String,
}

// a sync db desc entry, every field a raw string so a case can lie
pub struct Desc {
	pub name: String,
	pub version: String,
	pub filename: String,
	pub csize: String,
	pub isize: String,
	pub sha256: String,
	pub pgpsig: Option<String>,
}

impl Desc {
	// a desc that truthfully describes pkg_bytes served as filename
	pub fn truthful(
		name: &str,
		version: &str,
		filename: &str,
		body: &[u8],
	) -> Desc {
		Desc {
			name: name.into(),
			version: version.into(),
			filename: filename.into(),
			csize: body.len().to_string(),
			isize: "2".into(),
			sha256: sha256_hex(body),
			pgpsig: None,
		}
	}

	fn text(&self) -> Vec<u8> {
		let one = |s: &str| vec![s.to_string()];
		let mut t = [
			section("FILENAME", &one(&self.filename)),
			section("NAME", &one(&self.name)),
			section("BASE", &one(&self.name)),
			section("VERSION", &one(&self.version)),
			section("CSIZE", &one(&self.csize)),
			section("ISIZE", &one(&self.isize)),
			section("SHA256SUM", &one(&self.sha256)),
			section("ARCH", &one("x86_64")),
			section("BUILDDATE", &one("1700000000")),
			section("PACKAGER", &one("A B <a@b.org>")),
		]
		.concat();
		if let Some(sig) = &self.pgpsig {
			t.push_str(&section("PGPSIG", &one(sig)));
		}
		t.into_bytes()
	}
}

// sha256 as lowercase hex, via the alpm-core digest the port uses
fn sha256_hex(data: &[u8]) -> String {
	use alpm_core::digest::{Digest, Sha256, hex};
	let mut h = Sha256::new();
	h.update(data);
	String::from_utf8(hex(&h.finalize())).unwrap()
}

// a minimal but valid .PKGINFO; name/version/size are what a case lies
// about by passing a different Desc or a traversal filename
fn pkginfo(name: &str, version: &str, isize: u64) -> Vec<u8> {
	format!("pkgname = {name}\npkgbase = {name}\npkgver = {version}\n\
		pkgdesc = evil\nurl = https://example.org/\n\
		builddate = 1700000000\npackager = A B <a@b.org>\n\
		size = {isize}\narch = x86_64\n")
	.into_bytes()
}

// a package tarball: .PKGINFO first, then nodes, compressed with comp
pub fn package(
	name: &str,
	version: &str,
	nodes: &[TarNode],
	comp: Comp,
) -> Vec<u8> {
	let mut all = vec![TarNode {
		name: b".PKGINFO".to_vec(),
		kind: b'0',
		mode: 0o644,
		link: Vec::new(),
		data: pkginfo(name, version, 2),
	}];
	all.extend_from_slice(nodes);
	compress_bytes(comp, &ustar_owned(&all, ac_owner()), false)
}

// a plain file node under usr/bin, owned by the running user
pub fn file_node(path: &str, data: &[u8]) -> TarNode {
	TarNode {
		name: path.as_bytes().to_vec(),
		kind: b'0',
		mode: 0o644,
		link: Vec::new(),
		data: data.to_vec(),
	}
}

// a one-file ordinary package
pub fn good_package(name: &str, version: &str, comp: Comp) -> Vec<u8> {
	package(name, version, &[file_node("usr/bin/evil", b"x\n")], comp)
}

// a raw 200 whose Content-Length may lie: declared > body stalls the
// client waiting for bytes that never come, declared < body hands it a
// truncated file. Connection: close frames it
pub fn raw_cl(declared: i64, body: &[u8]) -> Reply {
	let mut r =
		format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\n\
		Connection: close\r\n\r\n")
		.into_bytes();
	r.extend_from_slice(body);
	Reply::Raw(r)
}

// a detached signature of data by the named GpgFixture key, made once
pub fn sign_bytes(
	gpg: &GpgFixture,
	dir: &Path,
	data: &[u8],
	key: &str,
) -> Vec<u8> {
	let tmp = dir.join("sign.tmp");
	fs::write(&tmp, data).unwrap();
	let sig = gpg.sign_file(&[key], &tmp);
	fs::remove_file(&tmp).unwrap();
	sig
}

const PATHDIRS: [&str; 7] = [
	"root", "db/sync", "db/local", "cache", "gnupg", "log", "hooks",
];

// the fixture subtrees a run is allowed to change; everything else must
// be untouched (the "nothing outside root" invariant)
const ALLOWED: [&str; 5] = ["root", "db", "cache", "gnupg", "log"];

impl IronicEvilMirrorPkger {
	pub fn new(tag: &str) -> Self {
		let fx = TempRoot::new(tag);
		for d in PATHDIRS {
			fs::create_dir_all(fx.dir().join(d)).unwrap();
		}
		let srv = Server::start();
		IronicEvilMirrorPkger {
			fx,
			srv,
			repo: "evil".into(),
		}
	}

	pub fn dir(&self) -> &Path {
		self.fx.dir()
	}

	pub fn server(&self) -> &Server {
		&self.srv
	}

	// http://127.0.0.1:<port>/evil/<name>
	pub fn url(&self, name: &str) -> String {
		format!("{}/{}/{name}", self.srv.base(), self.repo)
	}

	// write db/sync/evil.db listing these descs (uncompressed ustar,
	// libalpm autodetects); the matching .files kept empty
	pub fn sync_db(&self, descs: &[Desc]) {
		use crate::fixtures::{TarEntry, tar_dir, tar_file, ustar};
		let mut entries: Vec<TarEntry> = Vec::new();
		for d in descs {
			let dir = format!("{}-{}/", d.name, d.version);
			entries.push(tar_dir(&dir));
			entries.push(tar_file(
				&format!("{dir}desc"),
				&d.text(),
			));
		}
		let tar = ustar(&entries);
		fs::write(self.fx.dir().join("db/sync/evil.db"), &tar).unwrap();
		fs::write(self.fx.dir().join("db/sync/evil.files"), ustar(&[]))
			.unwrap();
	}

	// route a reply for /evil/<name>
	pub fn route(&self, name: &str, replies: Vec<Reply>) {
		self.srv.route(&format!("/{}/{name}", self.repo), replies);
	}

	// pacman.conf: SigLevel, the repo's Server at the hostile mirror
	pub fn conf(&self, siglevel: &str) {
		self.conf_opts(siglevel, "");
	}

	// conf with extra [options] lines (CheckSpace, ...)
	pub fn conf_opts(&self, siglevel: &str, extra: &str) {
		let dir = self.fx.dir();
		let conf = format!(
			"[options]\nArchitecture = x86_64\nSigLevel = {siglevel}\n\
			{extra}[{}]\nServer = {}/{}\n",
			self.repo,
			self.srv.base(),
			self.repo
		);
		fs::write(dir.join("pacman.conf"), conf).unwrap();
	}

	fn paths(&self) -> Vec<String> {
		let dir = self.fx.dir();
		let p = |r: &str| dir.join(r).display().to_string();
		vec![
			format!("--config={}", p("pacman.conf")),
			format!("--root={}", p("root")),
			format!("--dbpath={}", p("db")),
			format!("--cachedir={}", p("cache")),
			format!("--hookdir={}", p("hooks")),
			format!("--gpgdir={}", p("gnupg")),
			format!("--logfile={}", p("log/pacman.log")),
			"--noconfirm".into(),
		]
	}

	// a fresh empty root, local db and cache before each binary run
	fn reset_root(&self) {
		let dir = self.fx.dir();
		for d in ["root", "cache"] {
			let p = dir.join(d);
			let _ = fs::remove_dir_all(&p);
			fs::create_dir_all(&p).unwrap();
		}
		let local = dir.join("db/local");
		let _ = fs::remove_dir_all(&local);
		fs::create_dir_all(&local).unwrap();
		fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
	}

	// set the gpgdir to a GpgFixture keyring (dirmngr disabled there)
	pub fn use_keyring(&self, gpg: &GpgFixture) {
		let home = gpg.home(Home::Pgp);
		let src = Path::new(std::str::from_utf8(&home).unwrap());
		let dst = self.fx.dir().join("gnupg");
		let _ = fs::remove_dir_all(&dst);
		copy_tree(src, &dst);
	}

	fn run(&self, bin: &Path, args: &[String]) -> Outcome {
		self.reset_root();
		let dir = self.fx.dir();
		let mut cmd = Command::new("fakeroot");
		cmd.arg(bin).arg0("pacman");
		cmd.args(args).current_dir(dir).env_clear();
		cmd.env("TZ", "UTC")
			.env("LC_ALL", "C.UTF-8")
			.env("COLUMNS", "80")
			.env("PATH", "/usr/bin:/bin");
		// the binary's own network timeouts keep the hang/stall cases
		// short; 90 s is a backstop so a true hang fails loudly
		let o = output_capped(&mut cmd, 90);
		Outcome {
			rc: o.status.code().unwrap_or(-1),
			out: o.stdout,
			err: o.stderr,
			root: snapshot(&dir.join("root")),
			local: local_pkgs(&dir.join("db/local")),
		}
	}

	// run both binaries on args, after the case has set up conf, db and
	// routes; returns the verdict and the baseline of everything outside
	// the pm's own dirs (to assert nothing escaped)
	pub fn twin(&self, name: &str, args: &[String]) -> Verdict {
		let mut full = args.to_vec();
		full.extend(self.paths());
		let base = outside_root(self.fx.dir());
		let c = self.run(&c_pacman(), &full);
		self.assert_no_escape(name, "C", &base);
		self.srv.reset();
		let puck = self.run(&rust_pacman(), &full);
		self.assert_no_escape(name, "puck", &base);
		self.srv.reset();
		let same = norm(&c.err) == norm(&puck.err)
			&& c.rc == puck.rc && c.out == puck.out
			&& c.root == puck.root
			&& c.local == puck.local;
		Verdict {
			name: name.into(),
			c,
			puck,
			same,
		}
	}

	// nothing was created outside root/cache/db/gnupg/log, inside the
	// fixture or (via a canary) beyond it
	fn assert_no_escape(
		&self,
		case: &str,
		side: &str,
		base: &BTreeMap<PathBuf, u8>,
	) {
		let now = outside_root(self.fx.dir());
		assert_eq!(
			&now, base,
			"{case}/{side}: wrote outside the configured root \
			(path traversal escaped the install root)"
		);
	}
}

// the safe-state invariants for one side of a case: nonzero exit, no
// package registered as installed. (escape is asserted in twin.) the
// message quotes the case and the binary's stderr
pub fn assert_safe(case: &str, side: &str, o: &Outcome) {
	assert!(
		o.rc != 0,
		"{case}/{side}: exit 0 on a hostile input\n{}",
		String::from_utf8_lossy(&o.err)
	);
	assert_eq!(
		o.local,
		Vec::<String>::new(),
		"{case}/{side}: a package was registered in the local db \
		from a hostile input\n{}",
		String::from_utf8_lossy(&o.err)
	);
}

// package dirs registered under db/local (ALPM_DB_VERSION aside), sorted
fn local_pkgs(local: &Path) -> Vec<String> {
	let Ok(rd) = fs::read_dir(local) else {
		return Vec::new();
	};
	let mut v: Vec<String> = rd
		.filter_map(|e| {
			let e = e.unwrap();
			let n = e.file_name().to_string_lossy().into_owned();
			(e.path().is_dir()).then_some(n)
		})
		.collect();
	v.sort();
	v
}

// every path under fixture that the pm's own dirs do not cover, as a
// name->kind map (presence catches a traversal that lands here)
fn outside_root(fixture: &Path) -> BTreeMap<PathBuf, u8> {
	let mut out = BTreeMap::new();
	walk_outside(fixture, fixture, &mut out);
	out
}

fn walk_outside(fixture: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, u8>) {
	let Ok(rd) = fs::read_dir(dir) else {
		return;
	};
	for e in rd {
		let e = e.unwrap();
		let path = e.path();
		let rel = path.strip_prefix(fixture).unwrap();
		if ALLOWED.iter().any(|a| rel.starts_with(a)) {
			continue;
		}
		let md = e.file_type().unwrap();
		let kind = if md.is_dir() {
			b'd'
		} else if md.is_symlink() {
			b'l'
		} else {
			b'f'
		};
		out.insert(rel.to_path_buf(), kind);
		if md.is_dir() {
			walk_outside(fixture, &path, out);
		}
	}
}

// a recursive copy preserving modes, for the keyring home
fn copy_tree(from: &Path, to: &Path) {
	use std::os::unix::fs::PermissionsExt;
	fs::create_dir_all(to).unwrap();
	fs::set_permissions(to, fs::Permissions::from_mode(0o700)).unwrap();
	for e in fs::read_dir(from).unwrap() {
		let e = e.unwrap();
		let dst = to.join(e.file_name());
		if e.file_type().unwrap().is_dir() {
			copy_tree(&e.path(), &dst);
		} else {
			fs::copy(e.path(), &dst).unwrap();
		}
	}
}

// stderr for divergence recording: PACMAN_DEBUG stamps dropped, the
// fixture path masked, the C's file:line GOTO_ERR lines dropped
pub fn norm(err: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	for line in unstamp(err).split_inclusive(|&c| c == b'\n') {
		if line.starts_with(b"debug: returning error ") || is_goto(line)
		{
			continue;
		}
		out.extend_from_slice(line);
	}
	out
}

fn is_goto(line: &[u8]) -> bool {
	let key = b"got error ";
	let Some(i) = line.windows(key.len()).position(|w| w == key) else {
		return false;
	};
	let rest = &line[i + key.len()..];
	let n = rest.iter().take_while(|c| c.is_ascii_digit()).count();
	n > 0 && rest[n..].starts_with(b" at ")
}

// the first stderr line mentioning an error, for the report table
pub fn reason(o: &Outcome) -> String {
	let text = String::from_utf8_lossy(&o.err);
	for line in text.lines() {
		let l = line.trim();
		if l.to_ascii_lowercase().contains("error") && !l.is_empty() {
			return l.to_string();
		}
	}
	text.lines()
		.map(str::trim)
		.find(|l| !l.is_empty())
		.unwrap_or("(no stderr)")
		.to_string()
}
