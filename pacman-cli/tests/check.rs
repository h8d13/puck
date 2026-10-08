// unit tests for pacman_cli::check on a small tree, with an env serving
// fixed mtree entries
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::PathBuf;

use alpm_core::backup::Backup;
use alpm_core::be_local::{MtreeEntry, MtreeError, MtreeType, Sha256Checksum};
use alpm_core::filelist::{File, FileList};
use alpm_core::package::Package;
use pacman_cli::check::*;
use pacman_cli::conf::{ColStr, Config};
use pacman_cli::util::Output;

// <tmp>/pacman-cli-check-<pid>-<name>/ with root/, removed on drop
struct Tmp(PathBuf);

impl Tmp {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"pacman-cli-check-{}-{name}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("root/d")).unwrap();
		fs::write(dir.join("root/a"), b"hello\n").unwrap();
		fs::write(dir.join("root/b"), b"changed\n").unwrap();
		symlink("elsewhere", dir.join("root/l")).unwrap();
		Tmp(dir)
	}

	fn root(&self) -> Vec<u8> {
		[self.0.join("root").as_os_str().as_bytes(), b"/"].concat()
	}

	fn mtime(&self, rel: &str) -> i64 {
		fs::symlink_metadata(self.0.join("root").join(rel))
			.unwrap()
			.mtime()
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

struct Env {
	root: Vec<u8>,
	mtree: Option<Vec<MtreeEntry>>,
}

impl CheckEnv for Env {
	fn root(&self) -> &[u8] {
		&self.root
	}

	fn dbpath(&self) -> &[u8] {
		b"/nonexistent/db/"
	}

	fn match_noextract(&self, path: &[u8]) -> Option<bool> {
		(path == b"skipped").then_some(false)
	}

	fn mtree(&self, _: &Package) -> Result<Vec<MtreeEntry>, MtreeError> {
		self.mtree.clone().ok_or(MtreeError::Missing)
	}
}

fn pkg(files: &[&str], backup: &[&str]) -> Package {
	Package {
		name: Some(b"p".to_vec()),
		version: Some(b"1-1".to_vec()),
		files: FileList {
			files: files
				.iter()
				.map(|f| File {
					name: f.as_bytes().to_vec(),
					..File::default()
				})
				.collect(),
		},
		backup: backup
			.iter()
			.map(|b| Backup {
				name: b.as_bytes().to_vec(),
				hash: None,
			})
			.collect(),
		..Package::default()
	}
}

fn cfg(quiet: bool) -> Config {
	let mut c = Config::new();
	c.quiet = u16::from(quiet);
	c.colstr = ColStr::PLAIN;
	c
}

fn entry(t: &Tmp, rel: &str, kind: MtreeType, content: &[u8]) -> MtreeEntry {
	let me = fs::metadata(&t.0).unwrap();
	MtreeEntry {
		path: format!("./{rel}").into_bytes(),
		kind,
		mode: match kind {
			MtreeType::Dir => 0o755,
			MtreeType::Link => 0o777,
			_ => 0o644,
		},
		uid: me.uid().into(),
		gid: me.gid().into(),
		size: content.len() as u64,
		mtime: t.mtime(rel),
		link: (kind == MtreeType::Link).then(|| b"target".to_vec()),
		sha256: (kind == MtreeType::File)
			.then(|| Sha256Checksum::calculate_from(content)),
		md5: None,
		warned: false,
	}
}

fn s(v: &[u8]) -> String {
	String::from_utf8_lossy(v).into_owned()
}

#[test]
fn fast() {
	let t = Tmp::new("fast");
	let env = Env {
		root: t.root(),
		mtree: None,
	};
	let p = pkg(&["a", "d/", "a/", "m", "skipped"], &[]);
	let mut o = Output::default();
	assert_eq!(check_pkg_fast(&mut o, &cfg(false), &env, &p), 1);
	let root = s(&t.root());
	assert_eq!(s(&o.stdout), "p: 5 total files, 2 missing files\n");
	assert_eq!(
		s(&o.stderr),
		format!("warning: p: {root}a/ (File type mismatch)\n\
			warning: p: {root}m (No such file or directory)\n")
	);

	// quiet: missing files on stdout, the type warning stays
	let mut o = Output::default();
	assert_eq!(check_pkg_fast(&mut o, &cfg(true), &env, &p), 1);
	assert_eq!(s(&o.stdout), format!("p {root}m\n"));
	assert!(s(&o.stderr).contains("(File type mismatch)"));

	let mut o = Output::default();
	let one = pkg(&["a"], &[]);
	assert_eq!(check_pkg_fast(&mut o, &cfg(false), &env, &one), 0);
	assert_eq!(s(&o.stdout), "p: 1 total file, 0 missing files\n");
}

#[test]
fn full() {
	let t = Tmp::new("full");
	let mut b = entry(&t, "b", MtreeType::File, b"original\n");
	b.mtime += 1;
	let mut d = entry(&t, "d", MtreeType::Dir, b"");
	d.mode = 0o700;
	let mtree = vec![
		entry(&t, "a", MtreeType::File, b"hello\n"),
		b,
		d,
		entry(&t, "l", MtreeType::Link, b""),
		MtreeEntry {
			path: b"./.PKGINFO".to_vec(),
			..entry(&t, "a", MtreeType::File, b"")
		},
	];
	let env = Env {
		root: t.root(),
		mtree: Some(mtree),
	};
	let root = s(&t.root());
	let p = pkg(&[], &["b"]);
	let mut o = Output::default();
	assert_eq!(check_pkg_full(&mut o, &cfg(false), &env, &p), 1);
	assert_eq!(
		s(&o.stdout),
		format!(
			"backup file: p: {root}b (Modification time mismatch)\n\
			backup file: p: {root}b (Size mismatch)\n\
			backup file: p: {root}b (SHA256 checksum mismatch)\n\
			p: 4 total files, 2 altered files\n"
		)
	);
	assert_eq!(
		s(&o.stderr),
		format!("warning: p: {root}d (Permissions mismatch)\n\
			warning: p: {root}l (Symlink path mismatch)\n")
	);

	// quiet: one line per altered file, backup notes dropped
	let mut o = Output::default();
	assert_eq!(check_pkg_full(&mut o, &cfg(true), &env, &p), 1);
	assert_eq!(s(&o.stdout), format!("p {root}d\np {root}l\n"));
	assert_eq!(s(&o.stderr), "");

	let env = Env {
		root: t.root(),
		mtree: None,
	};
	let mut o = Output::default();
	assert_eq!(check_pkg_full(&mut o, &cfg(false), &env, &p), 0);
	assert_eq!(s(&o.stdout), "p: no mtree file\n");
}
