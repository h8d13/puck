// alpm_core::internals::util::{compute_md5sum, compute_sha256sum, test_checksum}
// against util.c on temp files: sizes around the md5/sha256 block (64)
// and the C read buffer (8192), random sizes, and paths that fail to open
// or read
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use alpm_core::internals::package::{
	PKG_VALIDATION_MD5SUM, PKG_VALIDATION_SHA256SUM,
};
use alpm_core::internals::util::{
	compute_md5sum, compute_sha256sum, test_checksum,
};
use difftest::{
	Rng, c_compute_md5sum, c_compute_sha256sum, c_test_checksum, iters,
};

const SIZES: [usize; 14] = [
	0, 1, 55, 56, 63, 64, 65, 127, 8191, 8192, 8193, 16384, 24593, 65536,
];
// _alpm_test_checksum kinds: the two digests, then -1 for anything else
const KINDS: [i32; 6] = [
	PKG_VALIDATION_MD5SUM,
	PKG_VALIDATION_SHA256SUM,
	0,
	1,
	8,
	PKG_VALIDATION_MD5SUM | PKG_VALIDATION_SHA256SUM,
];

// fresh dir under /tmp, removed on drop
struct Dir(PathBuf);

impl Dir {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"difftest-checksum-{name}-{}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir(&dir).unwrap();
		Dir(dir)
	}
}

impl Drop for Dir {
	fn drop(&mut self) {
		let locked = self.0.join("locked");
		if locked.exists() {
			let mode = fs::Permissions::from_mode(0o600);
			fs::set_permissions(locked, mode).unwrap();
		}
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn bytes(p: &Path) -> Vec<u8> {
	p.as_os_str().as_bytes().to_vec()
}

// expected values around the right one: itself, uppercase, cut, empty,
// the other digest, NULL
fn expectations(
	md5: &Option<Vec<u8>>,
	sha: &Option<Vec<u8>>,
) -> Vec<Option<Vec<u8>>> {
	let mut out = vec![None, Some(Vec::new())];
	for h in [md5, sha].into_iter().flatten() {
		out.push(Some(h.clone()));
		out.push(Some(h.to_ascii_uppercase()));
		out.push(Some(h[..h.len() - 1].to_vec()));
	}
	out
}

fn check(path: &[u8]) -> Option<Vec<u8>> {
	let md5 = c_compute_md5sum(path);
	assert_eq!(md5, compute_md5sum(path), "md5 {path:?}");
	let sha = c_compute_sha256sum(path);
	assert_eq!(sha, compute_sha256sum(path), "sha256 {path:?}");
	for e in expectations(&md5, &sha) {
		for kind in KINDS {
			let r = match test_checksum(path, e.as_deref(), kind) {
				Some(true) => 0,
				Some(false) => 1,
				None => -1,
			};
			let c = c_test_checksum(path, e.as_deref(), kind);
			assert_eq!(c, r, "{path:?} {e:?} {kind}");
		}
	}
	md5
}

#[test]
fn checksum_sizes() {
	let dir = Dir::new("sizes");
	let mut rng = Rng::new(0xc5);
	for size in SIZES {
		let f = dir.0.join(format!("f{size}"));
		let data: Vec<u8> =
			(0..size).map(|_| rng.next_u64() as u8).collect();
		fs::write(&f, &data).unwrap();
		assert!(check(&bytes(&f)).is_some());
	}
}

// open fails (missing, ELOOP, ENOTDIR, EACCES unless root), read fails
// (a directory opens, read gives EISDIR)
#[test]
fn checksum_failures() {
	let dir = Dir::new("fail");
	let file = dir.0.join("file");
	fs::write(&file, b"x").unwrap();
	symlink("loop", dir.0.join("loop")).unwrap();
	let locked = dir.0.join("locked");
	fs::write(&locked, b"secret").unwrap();
	fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))
		.unwrap();
	for p in [
		dir.0.join("none"),
		dir.0.join("loop"),
		file.join("x"),
		dir.0.clone(),
		locked,
	] {
		check(&bytes(&p));
	}
	assert!(check(&bytes(&dir.0)).is_none());
	assert!(check(b"").is_none());
}

// one file per case: iters() / 20
#[test]
fn checksum_fuzz() {
	let dir = Dir::new("fuzz");
	let mut rng = Rng::new(0xc5f);
	let f = dir.0.join("f");
	for _ in 0..iters() / 20 {
		let size = match rng.below(3) {
			0 => rng.below(200),
			1 => 8192 * rng.below(4) + rng.below(130),
			_ => rng.below(40_000),
		};
		let data: Vec<u8> =
			(0..size).map(|_| rng.next_u64() as u8).collect();
		fs::write(&f, &data).unwrap();
		assert!(check(&bytes(&f)).is_some(), "{size}");
	}
}
