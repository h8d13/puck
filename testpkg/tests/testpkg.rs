// testpkg::run on what needs no package: usage, alpm_initialize
// failures, a missing file. the loads are compared with the C by the
// equivalence tests
use std::fs;
use std::path::PathBuf;

use testpkg::{Output, Setup, run};

// root/ and db/ under a fresh temp dir, removed on drop
struct Dirs(PathBuf);

impl Dirs {
	fn new(tag: &str) -> Self {
		let d = std::env::temp_dir()
			.join(format!("testpkg-{tag}-{}", std::process::id()));
		for sub in ["root", "db"] {
			fs::create_dir_all(d.join(sub)).unwrap();
		}
		Dirs(d)
	}

	fn path(&self, rel: &str) -> Vec<u8> {
		self.0.join(rel).into_os_string().into_encoded_bytes()
	}
}

impl Drop for Dirs {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn args(v: &[&str]) -> Vec<Vec<u8>> {
	v.iter().map(|s| s.as_bytes().to_vec()).collect()
}

#[test]
fn usage() {
	let want = "testpkg (pacman) v7.1.0\n\n\
		Test a pacman package for validity.\n\n\
		Usage: testpkg <package file>\n";
	for a in [&[][..], &["a", "b"]] {
		let mut o = Output::default();
		assert_eq!(run(&args(a), &Setup::DEFAULT, &mut o), 1);
		assert_eq!(String::from_utf8_lossy(&o.err), want);
		assert!(o.out.is_empty());
	}
}

#[test]
fn init_failure() {
	let d = Dirs::new("init");
	let (root, nope) = (d.path("root"), d.path("nope"));
	for (r, db) in [(&nope, &root), (&root, &nope)] {
		let setup = Setup {
			root: r,
			dbpath: db,
			..Setup::DEFAULT
		};
		let mut o = Output::default();
		assert_eq!(run(&args(&["x"]), &setup, &mut o), 1);
		assert_eq!(
			String::from_utf8_lossy(&o.err),
			"cannot initialize alpm: could not find or read directory\n"
		);
	}
}

#[test]
fn missing_file() {
	let d = Dirs::new("missing");
	let (root, db) = (d.path("root"), d.path("db"));
	let setup = Setup {
		root: &root,
		dbpath: &db,
		gpgdir: &root,
		..Setup::DEFAULT
	};
	let mut o = Output::default();
	let file = d.path("nope.pkg.tar");
	assert_eq!(run(&[file], &setup, &mut o), 1);
	assert_eq!(o.out, b"Cannot find the given file.\n");
	assert!(o.err.is_empty());
}
