// the required C-ABI gate: the installed pyalpm (a BIND_NOW C extension)
// runs the same read-path driver against puck's libalpm.so.16 and against
// the real libalpm; identical output is the pass. skipped when python3 or
// pyalpm is unavailable, so the workspace suite stays green anywhere.
//
// the "real" side is the system libalpm pyalpm was built for, not
// $PACMAN_BUILD: that reference build dropped alpm_pkg_get_md5sum, which
// this pyalpm references, so BIND_NOW makes it fail to load there (see
// PORTING.md C ABI findings). both are a real libalpm 16.0.1.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn tests_dir() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn workspace_target() -> PathBuf {
	std::env::var_os("CARGO_TARGET_DIR")
		.map(PathBuf::from)
		.unwrap_or_else(|| {
			Path::new(env!("CARGO_MANIFEST_DIR")).join("../target")
		})
}

// run the driver; LD_LIBRARY_PATH picks the libalpm, None = the system one
fn drive(
	driver: &Path,
	root: &Path,
	db: &Path,
	libdir: Option<&Path>,
) -> String {
	let mut cmd = Command::new("python3");
	cmd.arg("-I").arg(driver).arg(root).arg(db);
	if let Some(dir) = libdir {
		cmd.env("LD_LIBRARY_PATH", dir);
	}
	let out = cmd.output().expect("run driver");
	assert!(
		out.status.success(),
		"driver failed ({:?}):\n{}",
		libdir,
		String::from_utf8_lossy(&out.stderr)
	);
	String::from_utf8(out.stdout).expect("utf8")
}

// pyalpm importable against the system lib? (skip gate)
fn pyalpm_available() -> bool {
	Command::new("python3")
		.args(["-I", "-c", "import pyalpm"])
		.status()
		.map(|s| s.success())
		.unwrap_or(false)
}

#[test]
fn pyalpm_read_path_matches_real_libalpm() {
	if !pyalpm_available() {
		eprintln!("skip: python3/pyalpm not available");
		return;
	}

	// build puck's cdylib (release) and expose it as libalpm.so.16
	let built = Command::new(env!("CARGO"))
		.args(["build", "-p", "alpm-capi", "--release"])
		.status()
		.expect("cargo build");
	assert!(built.success(), "building alpm-capi failed");
	let lib = workspace_target().join("release/libalpm.so");
	assert!(lib.exists(), "missing {}", lib.display());

	let scratch = std::env::temp_dir()
		.join(format!("capi-pyalpm-{}", std::process::id()));
	let _ = fs::remove_dir_all(&scratch);
	fs::create_dir_all(&scratch).unwrap();
	let libdir = scratch.join("lib");
	fs::create_dir_all(&libdir).unwrap();
	for name in ["libalpm.so", "libalpm.so.16"] {
		let link = libdir.join(name);
		let _ = fs::remove_file(&link);
		std::os::unix::fs::symlink(&lib, &link).unwrap();
	}

	// build the fixture both libs read
	let fix = scratch.join("fix");
	fs::create_dir_all(&fix).unwrap();
	let mk = Command::new("python3")
		.arg("-I")
		.arg(tests_dir().join("mkfixture.py"))
		.arg(&fix)
		.status()
		.expect("mkfixture");
	assert!(mk.success(), "mkfixture failed");
	let (root, db) = (fix.join("root"), fix.join("db"));

	let driver = tests_dir().join("driver.py");
	let real = drive(&driver, &root, &db, None);
	let puck = drive(&driver, &root, &db, Some(&libdir));

	let _ = fs::remove_dir_all(&scratch);
	assert_eq!(real, puck, "pyalpm read path diverged (real vs puck)");
	assert!(
		real.contains("alpha|1.0-1|first package"),
		"fixture not read"
	);
}
