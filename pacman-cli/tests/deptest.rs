// unit tests for pacman_cli::deptest on a local db written here: foo 1-1
// providing libfoo=2
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::handle::Handle;
use pacman_cli::deptest::pacman_deptest;
use pacman_cli::util::Output;

// <tmp>/pacman-cli-deptest-<pid>/ with root/ and db/, removed on drop
struct Tmp(PathBuf);

impl Tmp {
	fn new() -> Self {
		let dir = std::env::temp_dir().join(format!(
			"pacman-cli-deptest-{}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("root")).unwrap();
		let pkg = dir.join("db/local/foo-1-1");
		fs::create_dir_all(&pkg).unwrap();
		fs::write(dir.join("db/local/ALPM_DB_VERSION"), "9\n").unwrap();
		let desc = "%NAME%\nfoo\n\n%VERSION%\n1-1\n\n%BASE%\nfoo\n\n\
			%DESC%\nd\n\n%URL%\nhttps://e.org/\n\n%ARCH%\nany\n\n\
			%BUILDDATE%\n1\n\n%INSTALLDATE%\n2\n\n\
			%PACKAGER%\nA B <a@b.org>\n\n%SIZE%\n1\n\n\
			%VALIDATION%\nnone\n\n%PROVIDES%\nlibfoo=2\n\n";
		fs::write(pkg.join("desc"), desc).unwrap();
		Tmp(dir)
	}

	fn handle(&self) -> Handle {
		let p = |rel: &str| {
			self.0.join(rel).as_os_str().as_bytes().to_vec()
		};
		Handle::initialize(&p("root"), &p("db")).unwrap()
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn deptest(h: &mut Handle, targets: &[&str]) -> (i32, String) {
	let targets: Vec<Vec<u8>> =
		targets.iter().map(|t| t.as_bytes().to_vec()).collect();
	let mut o = Output::default();
	let ret = pacman_deptest(h, &targets, &mut o);
	assert!(o.stderr.is_empty());
	(ret, String::from_utf8(o.stdout).unwrap())
}

#[test]
fn satisfied_or_listed() {
	let t = Tmp::new();
	let mut h = t.handle();
	assert_eq!(deptest(&mut h, &[]), (0, String::new()));
	let all = ["foo", "foo>=1", "libfoo", "libfoo>1"];
	assert_eq!(deptest(&mut h, &all), (0, String::new()));
	// by name only for an exact name: "foo>=2" goes to the satisfier
	let r = deptest(&mut h, &["foo>=2", "libfoo<2", "bar", "foo"]);
	assert_eq!(r, (127, "foo>=2\nlibfoo<2\nbar\n".into()));
}
