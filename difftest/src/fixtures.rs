// fixture trees shared by the db difftests: a temp root with root/ and
// db/{local,sync}/, local db entries (desc, files, install) and sync db
// archives (ustar, every compression alpm-compress writes). no C here,
// what goes into the files is up to each test's generators.
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_compress::compression::{
	Bzip2CompressionLevel, CompressionEncoder, CompressionSettings,
	GzipCompressionLevel, XzCompressionLevel, ZstdCompressionLevel,
	ZstdThreads,
};

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

fn header(name: &[u8], size: usize, kind: u8) -> [u8; 512] {
	let mut h = [0u8; 512];
	h[..name.len()].copy_from_slice(name);
	octal(&mut h[100..108], if kind == b'5' { 0o755 } else { 0o644 });
	octal(&mut h[108..116], 0);
	octal(&mut h[116..124], 0);
	octal(&mut h[124..136], size as u64);
	octal(&mut h[136..148], 1_700_000_000);
	h[156] = kind;
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

// ustar archive, names past 100 bytes through a GNU longname entry
pub fn ustar(entries: &[TarEntry]) -> Vec<u8> {
	let mut out = Vec::new();
	for e in entries {
		let mut name = &e.name[..];
		if name.len() > 100 {
			let long = [name, b"\0"].concat();
			out.extend_from_slice(&header(
				b"././@LongLink",
				long.len(),
				b'L',
			));
			push_data(&mut out, &long);
			name = &name[..100];
		}
		let kind = if e.dir { b'5' } else { b'0' };
		out.extend_from_slice(&header(name, e.data.len(), kind));
		push_data(&mut out, &e.data);
	}
	out.resize(out.len() + 1024, 0);
	out
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
