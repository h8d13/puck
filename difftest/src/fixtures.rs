// fixture trees shared by the db difftests: a temp root with root/ and
// db/{local,sync}/, local db entries (desc, files, install) and sync db
// archives (ustar, every compression pacman reads; libarchive's writers
// for those alpm-compress has no encoder for). what goes into the files
// is up to each test's generators.
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

use crate::{Rng, c_filter_write};

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

// drops the "[HH:MM:SS] " PACMAN_DEBUG puts before stamped lines: the C
// and the port read the wall clock separately
pub fn unstamp(err: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	for line in err.split_inclusive(|&c| c == b'\n') {
		let stamped = line.len() >= 11
			&& line[0] == b'[' && line[3] == b':'
			&& line[6] == b':' && line[9] == b']';
		out.extend_from_slice(if stamped { &line[11..] } else { line });
	}
	out
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
	let mut out = ustar_entries(nodes, owner);
	out.resize(out.len() + 1024, 0);
	out
}

// the members of ustar_owned without the end-of-archive blocks
pub fn ustar_entries(nodes: &[TarNode], owner: (u32, u32)) -> Vec<u8> {
	let mut out = Vec::new();
	for n in nodes {
		let name = long_field(&mut out, &n.name, b'L');
		let link = long_field(&mut out, &n.link, b'K');
		let size = n.data.len();
		let h = header(name, link, n.mode, size, n.kind, owner);
		out.extend_from_slice(&h);
		push_data(&mut out, &n.data);
	}
	out
}

// one pax record, "len key=value\n" with len counting itself
pub fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
	let rest = key.len() + value.len() + 3;
	let mut len = rest + 1;
	while len != rest + len.to_string().len() {
		len = rest + len.to_string().len();
	}
	[len.to_string().as_bytes(), b" ", key, b"=", value, b"\n"].concat()
}

// an extension member of type kind ('x', 'g', 'A', 'L', ...) with this
// body, for the member after it
pub fn ext_member(kind: u8, body: &[u8]) -> Vec<u8> {
	let mut out =
		header(b"././@PaxHeader", b"", 0o644, body.len(), kind, (0, 0))
			.to_vec();
	push_data(&mut out, body);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comp {
	None,
	Gzip,
	Bzip2,
	Xz,
	Zstd,
	// makepkg's other PKGEXTs libarchive reads itself (.Z, .lzma, .lz,
	// .lz4), and a stack of two filters
	Compress,
	Lzma,
	Lzip,
	Lz4,
	GzipInGzip,
}

pub const COMPS: [Comp; 10] = [
	Comp::None,
	Comp::Gzip,
	Comp::Bzip2,
	Comp::Xz,
	Comp::Zstd,
	Comp::Compress,
	Comp::Lzma,
	Comp::Lzip,
	Comp::Lz4,
	Comp::GzipInGzip,
];

// every compressed one
pub const FILTERED: [Comp; 9] = [
	Comp::Gzip,
	Comp::Bzip2,
	Comp::Xz,
	Comp::Zstd,
	Comp::Compress,
	Comp::Lzma,
	Comp::Lzip,
	Comp::Lz4,
	Comp::GzipInGzip,
];

// data compressed with comp: alpm-compress's encoders (fast: their
// lowest levels), libarchive's write filters for the rest (filter.rs)
pub fn compress_bytes(comp: Comp, data: &[u8], fast: bool) -> Vec<u8> {
	let level = |low: u8, default: u8| if fast { low } else { default };
	let settings = match comp {
		Comp::None => return data.to_vec(),
		Comp::Gzip => CompressionSettings::Gzip {
			compression_level: GzipCompressionLevel::new(level(
				1, 6,
			))
			.unwrap(),
		},
		Comp::Bzip2 => CompressionSettings::Bzip2 {
			compression_level: Bzip2CompressionLevel::new(level(
				1, 9,
			))
			.unwrap(),
		},
		Comp::Xz => CompressionSettings::Xz {
			compression_level: XzCompressionLevel::new(level(0, 6))
				.unwrap(),
		},
		Comp::Zstd => CompressionSettings::Zstd {
			compression_level: ZstdCompressionLevel::new(level(
				1, 3,
			))
			.unwrap(),
			threads: ZstdThreads::new(1),
		},
		Comp::Compress => return c_filter_write("compress", "", data),
		Comp::Lzma => return c_filter_write("lzma", "", data),
		Comp::Lzip => return c_filter_write("lzip", "", data),
		// libarchive's lz4 writer crashes on no data (UPSTREAM.md)
		Comp::Lz4 if data.is_empty() => {
			let enc =
				lz4_flex::frame::FrameEncoder::new(Vec::new());
			return enc.finish().unwrap();
		}
		Comp::Lz4 => return c_filter_write("lz4", "", data),
		Comp::GzipInGzip => {
			let inner = compress_bytes(Comp::Gzip, data, fast);
			return compress_bytes(Comp::Gzip, &inner, fast);
		}
	};
	// the encoders write to a File only
	static N: AtomicUsize = AtomicUsize::new(0);
	let n = N.fetch_add(1, Ordering::Relaxed);
	let path = std::env::temp_dir()
		.join(format!("difftest-comp-{}-{n}", std::process::id()));
	let f = fs::File::create(&path).unwrap();
	let mut enc = CompressionEncoder::new(f, &settings).unwrap();
	enc.write_all(data).unwrap();
	enc.finish().unwrap();
	let out = fs::read(&path).unwrap();
	fs::remove_file(&path).unwrap();
	out
}

// tar compressed with comp into path
pub fn write_db(path: &Path, comp: Comp, tar: &[u8]) {
	fs::write(path, compress_bytes(comp, tar, false)).unwrap();
}
