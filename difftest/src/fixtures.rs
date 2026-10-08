// fixture trees shared by the db difftests: a temp root with root/ and
// db/{local,sync}/, local db entries (desc, files, install) and sync db
// archives (ustar, every compression alpm-compress writes), and the
// read-only sync worlds (SyncWorld). no C here, what goes into the
// files is up to each test's generators.
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_compress::compression::{
	Bzip2CompressionLevel, CompressionEncoder, CompressionSettings,
	GzipCompressionLevel, XzCompressionLevel, ZstdCompressionLevel,
	ZstdThreads,
};

use crate::Rng;

// the C binary of PACMAN_BUILD
pub fn c_pacman() -> PathBuf {
	let dir = match std::env::var_os("PACMAN_BUILD") {
		Some(d) => PathBuf::from(d),
		None => Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("../pacman/build"),
	};
	dir.join("pacman")
}

// target/<profile>/deps/cli_binary-<hash> -> target/<profile>/pacman
pub fn rust_pacman() -> PathBuf {
	let exe = std::env::current_exe().unwrap();
	let bin = exe.parent().unwrap().parent().unwrap().join("pacman");
	assert!(
		bin.exists(),
		"{} missing: cargo build --release -p pacman-cli",
		bin.display()
	);
	bin
}

// <tmp>/difftest-<tag>-<pid>-<n>/ holding root/ and db/sync/, resolved
// like alpm_initialize resolves it, removed on drop
pub struct TempRoot(PathBuf);

impl TempRoot {
	pub fn new(tag: &str) -> Self {
		static N: AtomicUsize = AtomicUsize::new(0);
		let n = N.fetch_add(1, Ordering::Relaxed);
		let dir = std::env::temp_dir().join(format!(
			"difftest-{tag}-{}-{n}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("root")).unwrap();
		fs::create_dir_all(dir.join("db/sync")).unwrap();
		TempRoot(dir.canonicalize().unwrap())
	}

	pub fn dir(&self) -> &Path {
		&self.0
	}

	pub fn path(&self, rel: &str) -> Vec<u8> {
		self.0.join(rel).as_os_str().as_bytes().to_vec()
	}

	pub fn root(&self) -> Vec<u8> {
		self.path("root")
	}

	// handle->dbpath: resolved, with the '/' alpm_initialize appends
	pub fn dbpath(&self) -> Vec<u8> {
		[&self.path("db")[..], b"/"].concat()
	}

	pub fn local(&self) -> PathBuf {
		self.0.join("db/local")
	}

	pub fn sync_file(&self, tree: &str, ext: &str) -> PathBuf {
		self.0.join(format!("db/sync/{tree}{ext}"))
	}

	// fresh empty local/ with a version file
	pub fn reset_local(&self) {
		let local = self.local();
		if local.exists() {
			fs::remove_dir_all(&local).unwrap();
		}
		fs::create_dir(&local).unwrap();
		fs::write(local.join("ALPM_DB_VERSION"), "9\n").unwrap();
	}

	// entries written under local/, which must exist
	pub fn write_local(&self, entries: &[LocalEntry]) {
		for e in entries {
			e.write(&self.local());
		}
	}
}

impl Drop for TempRoot {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

// one local/<dir>/ entry, None leaves the file out
#[derive(Clone, Debug, Default)]
pub struct LocalEntry {
	pub dir: String,
	pub desc: Option<Vec<u8>>,
	pub files: Option<Vec<u8>>,
	pub install: bool,
}

impl LocalEntry {
	fn write(&self, local: &Path) {
		let dir = local.join(&self.dir);
		fs::create_dir(&dir).unwrap();
		if let Some(d) = &self.desc {
			fs::write(dir.join("desc"), d).unwrap();
		}
		if let Some(f) = &self.files {
			fs::write(dir.join("files"), f).unwrap();
		}
		if self.install {
			fs::write(dir.join("install"), "post_install() {}\n")
				.unwrap();
		}
	}
}

// "%KEY%\nv1\nv2\n\n" of a desc/files text, nothing for no values
pub fn section(key: &str, values: &[String]) -> String {
	if values.is_empty() {
		return String::new();
	}
	format!("%{key}%\n{}\n\n", values.join("\n"))
}

// desc sections a test does not look at, as the C reads them: each of
// keys (with its typical value) left out now and then, or its value
// empty, blank, oddly spaced or not a number; sometimes a key the reader
// does not know (warned about, its lines skipped)
pub fn loose_sections(rng: &mut Rng, keys: &[(&str, &str)]) -> String {
	const ODD: [&str; 8] = [" ", "\t", "a  b ", " x", "-1", "abc", "é", ""];
	const UNKNOWN: [&str; 3] =
		["%FOO%\nbar\nbaz\n\n", "%%\n\n", "%name%\nx\n\n"];
	let mut out = String::new();
	for (key, typical) in keys {
		let value = match rng.below(8) {
			0 => continue,
			1 | 2 => ODD[rng.below(ODD.len())],
			_ => typical,
		};
		out += &format!("%{key}%\n{value}\n\n");
	}
	if rng.below(6) == 0 {
		out += UNKNOWN[rng.below(UNKNOWN.len())];
	}
	out
}

// tar entry: regular file or directory
#[derive(Clone, Debug)]
pub struct TarEntry {
	pub name: Vec<u8>,
	pub dir: bool,
	pub data: Vec<u8>,
}

pub fn tar_file(name: &str, data: &[u8]) -> TarEntry {
	TarEntry {
		name: name.as_bytes().to_vec(),
		dir: false,
		data: data.to_vec(),
	}
}

pub fn tar_dir(name: &str) -> TarEntry {
	TarEntry {
		name: name.as_bytes().to_vec(),
		dir: true,
		data: Vec::new(),
	}
}

// octal field of width w, nul terminated
fn octal(field: &mut [u8], v: u64) {
	let w = field.len() - 1;
	let s = format!("{v:0w$o}");
	field[..w].copy_from_slice(s.as_bytes());
}

// any tar entry: type flag, permission bits, link target (symlink or
// hard link), data. mtime fixed, owner and device numbers 0 unless
// ustar_owned
#[derive(Clone, Debug)]
pub struct TarNode {
	pub name: Vec<u8>,
	pub kind: u8,
	pub mode: u32,
	pub link: Vec<u8>,
	pub data: Vec<u8>,
}

fn header(
	name: &[u8],
	link: &[u8],
	mode: u32,
	size: usize,
	kind: u8,
	(uid, gid): (u32, u32),
) -> [u8; 512] {
	let mut h = [0u8; 512];
	h[..name.len()].copy_from_slice(name);
	octal(&mut h[100..108], u64::from(mode));
	octal(&mut h[108..116], u64::from(uid));
	octal(&mut h[116..124], u64::from(gid));
	octal(&mut h[124..136], size as u64);
	octal(&mut h[136..148], 1_700_000_000);
	h[156] = kind;
	h[157..157 + link.len()].copy_from_slice(link);
	h[257..263].copy_from_slice(b"ustar\0");
	h[263..265].copy_from_slice(b"00");
	h[148..156].fill(b' ');
	let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
	octal(&mut h[148..155], sum);
	h
}

fn push_data(out: &mut Vec<u8>, data: &[u8]) {
	out.extend_from_slice(data);
	out.resize(out.len().next_multiple_of(512), 0);
}

// GNU long name/link entry ('L'/'K') for a field past 100 bytes, the
// field itself cut to 100
fn long_field<'a>(out: &mut Vec<u8>, field: &'a [u8], kind: u8) -> &'a [u8] {
	if field.len() <= 100 {
		return field;
	}
	let long = [field, b"\0"].concat();
	out.extend_from_slice(&header(
		b"././@LongLink",
		b"",
		0o644,
		long.len(),
		kind,
		(0, 0),
	));
	push_data(out, &long);
	&field[..100]
}

// ustar archive of any entries
pub fn ustar_nodes(nodes: &[TarNode]) -> Vec<u8> {
	ustar_owned(nodes, (0, 0))
}

// ustar archive of any entries, every one owned by uid:gid
pub fn ustar_owned(nodes: &[TarNode], owner: (u32, u32)) -> Vec<u8> {
	let mut out = Vec::new();
	for n in nodes {
		let name = long_field(&mut out, &n.name, b'L');
		let link = long_field(&mut out, &n.link, b'K');
		let size = n.data.len();
		let h = header(name, link, n.mode, size, n.kind, owner);
		out.extend_from_slice(&h);
		push_data(&mut out, &n.data);
	}
	out.resize(out.len() + 1024, 0);
	out
}

// ustar archive, names past 100 bytes through a GNU longname entry
pub fn ustar(entries: &[TarEntry]) -> Vec<u8> {
	let nodes: Vec<TarNode> = entries
		.iter()
		.map(|e| TarNode {
			name: e.name.clone(),
			kind: if e.dir { b'5' } else { b'0' },
			mode: if e.dir { 0o755 } else { 0o644 },
			link: Vec::new(),
			data: e.data.clone(),
		})
		.collect();
	ustar_nodes(&nodes)
}

// a tree as compared between the C and the port: types, permission
// bits, contents, link targets. entries sorted by name
#[derive(Debug, PartialEq, Eq)]
pub enum Node {
	// mode, link count, contents
	File(u32, u64, Vec<u8>),
	// mode, None when the listing failed (no permission)
	Dir(u32, Option<Vec<(Vec<u8>, Node)>>),
	Link(Vec<u8>),
	// fifo or device: mode with its type bits
	Special(u32),
	Unreadable(u32),
}

pub fn snapshot(path: &Path) -> Node {
	let meta = fs::symlink_metadata(path).unwrap();
	let mode = meta.permissions().mode() & 0o7777;
	let kind = meta.file_type();
	if kind.is_symlink() {
		let t = fs::read_link(path).unwrap();
		return Node::Link(t.as_os_str().as_bytes().to_vec());
	}
	if kind.is_file() {
		return match fs::read(path) {
			Ok(data) => Node::File(mode, meta.nlink(), data),
			Err(_) => Node::Unreadable(mode),
		};
	}
	if !kind.is_dir() {
		return Node::Special(meta.mode());
	}
	let Ok(rd) = fs::read_dir(path) else {
		return Node::Dir(mode, None);
	};
	let mut entries: Vec<_> = rd
		.map(|e| {
			let e = e.unwrap();
			let name = e.file_name().as_bytes().to_vec();
			(name, snapshot(&e.path()))
		})
		.collect();
	entries.sort_by(|a, b| a.0.cmp(&b.0));
	Node::Dir(mode, Some(entries))
}

// rm -rf, also through directories left without permissions
pub fn force_remove(path: &Path) {
	let Ok(meta) = fs::symlink_metadata(path) else {
		return;
	};
	if !meta.is_dir() {
		fs::remove_file(path).unwrap();
		return;
	}
	fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
	for e in fs::read_dir(path).unwrap() {
		force_remove(&e.unwrap().path());
	}
	fs::remove_dir(path).unwrap();
}

#[derive(Clone, Copy, Debug)]
pub enum Comp {
	None,
	Gzip,
	Bzip2,
	Xz,
	Zstd,
}

pub const COMPS: [Comp; 5] =
	[Comp::None, Comp::Gzip, Comp::Bzip2, Comp::Xz, Comp::Zstd];

// tar compressed with comp into path
pub fn write_db(path: &Path, comp: Comp, tar: &[u8]) {
	let settings = match comp {
		Comp::None => CompressionSettings::None,
		Comp::Gzip => CompressionSettings::Gzip {
			compression_level: GzipCompressionLevel::default(),
		},
		Comp::Bzip2 => CompressionSettings::Bzip2 {
			compression_level: Bzip2CompressionLevel::default(),
		},
		Comp::Xz => CompressionSettings::Xz {
			compression_level: XzCompressionLevel::default(),
		},
		Comp::Zstd => CompressionSettings::Zstd {
			compression_level: ZstdCompressionLevel::default(),
			threads: ZstdThreads::new(1),
		},
	};
	let f = fs::File::create(path).unwrap();
	let mut enc = CompressionEncoder::new(f, &settings).unwrap();
	enc.write_all(tar).unwrap();
	enc.finish().unwrap();
}

// ---- sync worlds (sync_ro, files_op, database) ----

// generated worlds: a few repos sharing package and group names with
// each other and the local db, so -Sl markers, group merges and
// requiredby across dbs come up. desc/files texts are what repo-add and
// pacman write (be_sync and be_local cover the odd ones)

pub const REPOS: [&str; 3] = ["core", "extra", "multilib"];
pub const NAMES: [&str; 8] =
	["a", "b", "foo", "bar", "x-y", "lib32-z", "q", "foo2"];
pub const GROUPS: [&str; 4] = ["base", "kde", "g1", "g-2"];
// file names, case pairs of the same UTF-8 length (see regex in
// PORTING.md)
pub const BASENAMES: [&str; 9] = [
	"foo",
	"Foo",
	"bar",
	"a.conf",
	"libx.so.1",
	"x+y",
	"caf\u{e9}",
	"CAF\u{c9}",
	"README",
];
pub const DIRS: [&str; 5] =
	["usr/", "usr/bin/", "usr/lib/", "etc/", "usr/share/foo/"];

fn pick<'a>(rng: &mut Rng, items: &[&'a str]) -> &'a str {
	items[rng.below(items.len())]
}

fn word(rng: &mut Rng, min: usize, max: usize) -> String {
	const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789XYZ";
	let n = min + rng.below(max - min + 1);
	(0..n).map(|_| rng.pick(ALNUM) as char).collect()
}

fn version(rng: &mut Rng) -> String {
	let epoch = if rng.below(6) == 0 { "1:" } else { "" };
	format!(
		"{epoch}{}.{}-{}",
		rng.below(3),
		rng.below(3),
		1 + rng.below(2)
	)
}

fn relation(rng: &mut Rng) -> String {
	let name = pick(rng, &NAMES);
	match rng.below(3) {
		0 => name.to_string(),
		_ => {
			let op = pick(rng, &["=", ">=", "<=", ">", "<"]);
			format!("{name}{op}{}.{}", rng.below(3), rng.below(3))
		}
	}
}

fn optdepend(rng: &mut Rng) -> String {
	let name = pick(rng, &NAMES);
	match rng.below(2) {
		0 => name.to_string(),
		_ => format!("{name}: {}", description(rng)),
	}
}

fn description(rng: &mut Rng) -> String {
	let words: Vec<String> = (0..1 + rng.below(14))
		.map(|_| match rng.below(10) {
			0 => "caf\u{e9}".to_string(),
			1 => "(GTK+)".to_string(),
			_ => word(rng, 1, 9),
		})
		.collect();
	words.join(" ")
}

fn list(rng: &mut Rng, max: usize, f: fn(&mut Rng) -> String) -> Vec<String> {
	(0..rng.below(max + 1)).map(|_| f(rng)).collect()
}

// sorted, unique, every parent dir listed, some top-level files
fn file_list(rng: &mut Rng) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	for _ in 0..rng.below(7) {
		let base = pick(rng, &BASENAMES);
		if rng.below(5) == 0 {
			out.push(base.to_string());
			continue;
		}
		let dir = pick(rng, &DIRS);
		let mut parent = String::new();
		for part in dir.split_inclusive('/') {
			parent.push_str(part);
			out.push(parent.clone());
		}
		out.push(format!("{dir}{base}"));
	}
	out.sort();
	out.dedup();
	out
}

// one sync package: name, version, groups, its desc and files texts
#[derive(Clone, Debug)]
pub struct GenPkg {
	pub name: String,
	pub version: String,
	pub groups: Vec<String>,
	pub files: Vec<String>,
	desc: String,
}

fn gen_pkg(rng: &mut Rng, name: &str) -> GenPkg {
	let version = version(rng);
	let arch = pick(rng, &["x86_64", "any"]);
	// repeats on purpose: load_grpcache's duplicate handling
	let groups: Vec<String> = (0..rng.below(4))
		.map(|_| pick(rng, &GROUPS).to_string())
		.collect();
	let one = |s: String| vec![s];
	let mut desc = [
		section(
			"FILENAME",
			&one(format!("{name}-{version}-{arch}.pkg.tar.zst")),
		),
		section("NAME", &one(name.to_string())),
		section("BASE", &one(name.to_string())),
		section("VERSION", &one(version.clone())),
		section("CSIZE", &one(format!("{}", rng.next_u64() >> 34))),
		section("ISIZE", &one(format!("{}", rng.next_u64() >> 30))),
		section("SHA256SUM", &one("ab".repeat(32))),
		section("ARCH", &one(arch.to_string())),
		// localtime takes these, see UPSTREAM.md
		section("BUILDDATE", &one(format!("{}", rng.next_u64() >> 31))),
		section("PACKAGER", &one("A B <a@b.org>".to_string())),
		section("GROUPS", &groups),
		section(
			"LICENSE",
			&list(rng, 2, |r| {
				pick(r, &["MIT", "GPL-2.0-or-later"])
					.to_string()
			}),
		),
		section("DEPENDS", &list(rng, 3, relation)),
		section("OPTDEPENDS", &list(rng, 2, optdepend)),
		section("PROVIDES", &list(rng, 1, relation)),
		section("CONFLICTS", &list(rng, 1, relation)),
		section("REPLACES", &list(rng, 1, relation)),
	]
	.concat();
	if rng.below(4) != 0 {
		desc.push_str(&section("DESC", &one(description(rng))));
	}
	if rng.below(2) == 0 {
		let url = format!(
			"https://{}.org/{}",
			word(rng, 1, 6).to_lowercase(),
			word(rng, 1, 6)
		);
		desc.push_str(&section("URL", &one(url)));
	}
	GenPkg {
		name: name.to_string(),
		version,
		groups,
		files: file_list(rng),
		desc,
	}
}

// what a repo's .db and .files hold
#[derive(Clone, Debug)]
pub enum DbFile {
	Valid(Vec<GenPkg>),
	Absent,
	Empty,
	// a valid archive cut short: archive error on both sides
	Truncated,
}

pub(crate) fn sync_tar(pkgs: &[GenPkg], files: bool) -> Vec<u8> {
	let mut entries: Vec<TarEntry> = Vec::new();
	for p in pkgs {
		let dir = format!("{}-{}/", p.name, p.version);
		entries.push(tar_dir(&dir));
		entries.push(tar_file(
			&format!("{dir}desc"),
			p.desc.as_bytes(),
		));
		if files {
			let text = match p.files.is_empty() {
				true => "%FILES%\n".to_string(),
				false => format!(
					"%FILES%\n{}\n\n",
					p.files.join("\n")
				),
			};
			entries.push(tar_file(
				&format!("{dir}files"),
				text.as_bytes(),
			));
		}
	}
	ustar(&entries)
}

pub(crate) fn gen_pkgs(rng: &mut Rng, min: usize, max: usize) -> Vec<GenPkg> {
	let mut names: Vec<&str> = NAMES.to_vec();
	let n = min + rng.below(max - min + 1);
	(0..n).map(|_| {
		let name = names.remove(rng.below(names.len()));
		gen_pkg(rng, name)
	})
	.collect()
}

fn local_desc(name: &str, version: &str, groups: &[String]) -> String {
	format!(
		"%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%BASE%\n{name}\n\n\
		%DESC%\nA package\n\n%URL%\nhttps://example.org/\n\n\
		%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n\
		%INSTALLDATE%\n1700000001\n\n%PACKAGER%\nA B <a@b.org>\n\n\
		%SIZE%\n42\n\n%VALIDATION%\npgp\n\n{}",
		section("GROUPS", groups)
	)
}

// a fixture root: registered repos in order, each with a .db and a
// .files of the same state, and a local db. log describes it for
// assert messages
pub struct SyncWorld {
	pub fx: TempRoot,
	pub repos: Vec<&'static str>,
	pub dbs: Vec<DbFile>,
	pub log: String,
}

impl SyncWorld {
	pub fn generate(rng: &mut Rng, tag: &str) -> SyncWorld {
		let fx = TempRoot::new(tag);
		let mut log = String::new();
		let mut pool = REPOS.to_vec();
		// none now and then: "no usable package repositories"
		let n = match rng.below(12) {
			0 => 0,
			_ => 1 + rng.below(REPOS.len()),
		};
		let repos: Vec<&str> = (0..n)
			.map(|_| pool.remove(rng.below(pool.len())))
			.collect();
		let mut dbs = Vec::new();
		for repo in &repos {
			let db = match rng.below(10) {
				0 => DbFile::Absent,
				1 => DbFile::Empty,
				2 => DbFile::Truncated,
				_ => DbFile::Valid(gen_pkgs(rng, 0, 6)),
			};
			for (ext, files) in [(".db", false), (".files", true)] {
				let path = fx.sync_file(repo, ext);
				match &db {
					DbFile::Absent => {}
					DbFile::Empty => {
						fs::write(path, b"").unwrap()
					}
					DbFile::Truncated => {
						let pkgs = gen_pkgs(
							&mut Rng::new(7),
							1,
							2,
						);
						let mut tar =
							sync_tar(&pkgs, files);
						tar.truncate(700);
						fs::write(path, tar).unwrap();
					}
					DbFile::Valid(pkgs) => fs::write(
						path,
						sync_tar(pkgs, files),
					)
					.unwrap(),
				}
			}
			writeln!(log, "{repo}: {db:?}").unwrap();
			dbs.push(db);
		}

		// installed: some names, versions often matching a repo's
		fx.reset_local();
		let mut entries = Vec::new();
		for name in NAMES {
			if rng.below(3) != 0 {
				continue;
			}
			let synced = dbs.iter().find_map(|d| match d {
				DbFile::Valid(p) => {
					p.iter().find(|p| p.name == name)
				}
				_ => None,
			});
			let version = match synced {
				Some(p) if rng.below(3) != 0 => {
					p.version.clone()
				}
				_ => version(rng),
			};
			let groups: Vec<String> = (0..rng.below(2))
				.map(|_| pick(rng, &GROUPS).to_string())
				.collect();
			let desc = local_desc(name, &version, &groups);
			writeln!(log, "local: {name} {version}").unwrap();
			entries.push(LocalEntry {
				dir: format!("{name}-{version}"),
				desc: Some(desc.into_bytes()),
				files: None,
				install: false,
			});
		}
		fx.write_local(&entries);
		SyncWorld {
			fx,
			repos,
			dbs,
			log,
		}
	}

	// names of the packages in valid repos, for targets
	pub fn pkg_names(&self) -> Vec<&str> {
		let mut out = Vec::new();
		for d in &self.dbs {
			if let DbFile::Valid(pkgs) = d {
				out.extend(pkgs
					.iter()
					.map(|p| p.name.as_str()));
			}
		}
		out
	}
}
