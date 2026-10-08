// C side of -Sc/-Scc in src/pacman/sync.c (sync_cleancache,
// sync_cleandb_all through pacman_sync, frontend objects), and the
// fixture worlds both sides clean
//
// a CleanWorld is a fixture root generated from a seed, so two of them
// from one seed hold the same files in the same creation order (readdir
// order follows it on the same filesystem): a local db, sync db files of
// registered and unregistered repos with junk next to them, cache dirs
// with installed, older, newer and foreign packages, .sig/.part files,
// non-package files and subdirs. c_pacman_sync_clean runs pacman_sync on
// a FrontHandle over it with the cache dirs added and the frontend's
// cb_log, stdin reading the given answers.
use std::ffi::c_int;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::ptr;

use pacman_cli::conf::Config;

use crate::callback::cb_log;
use crate::cli_util::{config, init};
use crate::cli_util2::{CIo, run};
use crate::fixtures::{
	Comp, LocalEntry, TarEntry, TempRoot, section, tar_dir, tar_file,
	ustar, write_db,
};
use crate::handle::{ALPM, alpm_option_add_cachedir, alpm_option_set_logcb};
use crate::sync_ro::{FrontHandle, pacman_sync};
use crate::{Rng, cstr};

pub const CLEAN_REPOS: [&str; 3] = ["core", "extra", "multi"];
const NAMES: [&str; 5] = ["a", "b", "c", "lib-d", "e"];
const VERSIONS: [&str; 4] = ["1.0-1", "1.0-2", "2.0-1", "1:0.5-1"];

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

fn one(s: &str) -> Vec<String> {
	vec![s.to_string()]
}

fn local_desc(name: &str, version: &str) -> String {
	[
		section("NAME", &one(name)),
		section("VERSION", &one(version)),
		section("BASE", &one(name)),
		section("DESC", &one("installed")),
		// alpm-db wants a URL (PORTING.md, ALPM divergences)
		section("URL", &one("https://example.org/")),
		section("ARCH", &one("x86_64")),
		section("BUILDDATE", &one("1700000000")),
		section("INSTALLDATE", &one("1700000001")),
		section("PACKAGER", &one("A B <a@b.org>")),
		section("SIZE", &one("1")),
		section("VALIDATION", &one("none")),
	]
	.concat()
}

fn sync_desc(name: &str, version: &str) -> String {
	let file = format!("{name}-{version}-x86_64.pkg.tar.zst");
	[
		section("FILENAME", &one(&file)),
		section("NAME", &one(name)),
		section("BASE", &one(name)),
		section("VERSION", &one(version)),
		section("CSIZE", &one("1")),
		section("ISIZE", &one("1")),
		section("SHA256SUM", &one(&"ab".repeat(32))),
		section("ARCH", &one("x86_64")),
		section("BUILDDATE", &one("3")),
		section("PACKAGER", &one("A B <a@b.org>")),
	]
	.concat()
}

// a package file: .PKGINFO (pkgver as given, also invalid ones) and one
// payload file
pub fn package_bytes(name: &str, pkgver: &str) -> Vec<u8> {
	let info = [
		format!("pkgname = {name}"),
		format!("pkgbase = {name}"),
		format!("pkgver = {pkgver}"),
		"pkgdesc = A cached package".to_string(),
		"url = https://example.org/".to_string(),
		"builddate = 1700000000".to_string(),
		"packager = A B <a@b.org>".to_string(),
		"size = 1".to_string(),
		"arch = x86_64".to_string(),
	]
	.join("\n") + "\n";
	ustar(&[
		tar_file(".PKGINFO", info.as_bytes()),
		tar_dir("usr/"),
		tar_file(&format!("usr/{name}"), b"x"),
	])
}

// package_bytes compressed into path
pub fn write_package(path: &Path, name: &str, pkgver: &str, comp: Comp) {
	write_db(path, comp, &package_bytes(name, pkgver));
}

// the files and dirs of a world, removed on drop (dirs made read-only
// for the failure paths are made writable first)
pub struct CleanWorld {
	pub fx: TempRoot,
	pub repos: Vec<&'static str>,
	// absolute, '/' appended by the handles
	pub cachedirs: Vec<Vec<u8>>,
	pub log: String,
	readonly: Vec<PathBuf>,
}

impl Drop for CleanWorld {
	fn drop(&mut self) {
		for d in &self.readonly {
			let mode = fs::Permissions::from_mode(0o755);
			fs::set_permissions(d, mode).unwrap();
		}
	}
}

impl CleanWorld {
	// the world of seed under a fresh root tagged tag
	pub fn generate(seed: u64, tag: &str) -> CleanWorld {
		let mut rng = Rng::new(seed);
		let fx = TempRoot::new(tag);
		let mut w = CleanWorld {
			fx,
			repos: Vec::new(),
			cachedirs: Vec::new(),
			log: String::new(),
			readonly: Vec::new(),
		};
		w.local(&mut rng);
		w.sync(&mut rng);
		let n = 1 + rng.below(3);
		for i in 0..n {
			w.cachedir(&mut rng, i);
		}
		w
	}

	fn note(&mut self, s: String) {
		writeln!(self.log, "{s}").unwrap();
	}

	fn local(&mut self, rng: &mut Rng) {
		self.fx.reset_local();
		let mut entries = Vec::new();
		for name in NAMES {
			if rng.below(3) == 0 {
				continue;
			}
			let version = pick(rng, &VERSIONS);
			self.note(format!("local {name} {version}"));
			entries.push(LocalEntry {
				dir: format!("{name}-{version}"),
				desc: Some(
					local_desc(name, version).into_bytes()
				),
				files: Some(Vec::new()),
				install: false,
			});
		}
		self.fx.write_local(&entries);
	}

	// db files of every repo name, registered or not, and junk
	fn sync(&mut self, rng: &mut Rng) {
		let mut pool = CLEAN_REPOS.to_vec();
		for _ in 0..rng.below(4) {
			self.repos.push(pool.remove(rng.below(pool.len())));
		}
		let repos = self.repos.clone();
		self.note(format!("registered {repos:?}"));
		let sync = self.fx.dir().join("db/sync");
		for repo in CLEAN_REPOS {
			if rng.below(4) != 0 {
				let mut tar: Vec<TarEntry> = Vec::new();
				for name in NAMES {
					if rng.below(2) == 0 {
						continue;
					}
					let v = pick(rng, &VERSIONS);
					self.note(format!("{repo} {name} {v}"));
					let dir = format!("{name}-{v}/");
					tar.push(tar_dir(&dir));
					let desc = sync_desc(name, v);
					let f = format!("{dir}desc");
					tar.push(tar_file(&f, desc.as_bytes()));
				}
				let path = self.fx.sync_file(repo, ".db");
				write_db(&path, Comp::None, &ustar(&tar));
			}
			for ext in [".db.sig", ".files", ".files.sig"] {
				if rng.below(3) == 0 {
					let p = self.fx.sync_file(repo, ext);
					fs::write(p, b"x").unwrap();
				}
			}
		}
		let junk = [
			"README",
			"core.db.part",
			".db",
			".files.sig",
			"old.db.bak",
			"zz.db",
			"zz.files.sig",
		];
		for name in junk {
			if rng.below(3) == 0 {
				fs::write(sync.join(name), b"junk").unwrap();
			}
		}
		if rng.below(3) == 0 {
			let d = sync.join("tmp.db");
			fs::create_dir_all(d.join("deep/er")).unwrap();
			fs::write(d.join("deep/er/f"), b"x").unwrap();
			fs::write(d.join("g"), b"x").unwrap();
		}
		// a dir rmrf cannot empty: "could not remove ...: Directory
		// not empty" (not as root)
		if rng.below(5) == 0 {
			let d = sync.join("stuck");
			fs::create_dir(&d).unwrap();
			fs::write(d.join("f"), b"x").unwrap();
			self.read_only(&d);
		}
		// links that resolve (a dangling one is undefined in the C)
		if rng.below(4) == 0 {
			symlink("README.target", sync.join("link.db")).unwrap();
			fs::write(sync.join("README.target"), b"t").unwrap();
		}
		if rng.below(4) == 0 {
			fs::create_dir(sync.join("adir")).unwrap();
			symlink("adir", sync.join("dirlink")).unwrap();
		}
	}

	fn read_only(&mut self, d: &Path) {
		let mode = fs::Permissions::from_mode(0o555);
		fs::set_permissions(d, mode).unwrap();
		self.readonly.push(d.to_path_buf());
	}

	// cache<i>/: missing, a file, read-only or a dir of cache entries
	fn cachedir(&mut self, rng: &mut Rng, i: usize) {
		let dir = self.fx.dir().join(format!("cache{i}"));
		self.cachedirs.push(self.fx.path(&format!("cache{i}")));
		match rng.below(10) {
			0 => {
				self.note(format!("cache{i} missing"));
				return;
			}
			1 => {
				self.note(format!("cache{i} a file"));
				fs::write(&dir, b"x").unwrap();
				return;
			}
			_ => fs::create_dir(&dir).unwrap(),
		}
		for _ in 0..rng.below(10) {
			self.cache_entry(rng, &dir);
		}
		if rng.below(6) == 0 {
			self.note(format!("cache{i} read-only"));
			self.read_only(&dir);
		}
	}

	fn cache_entry(&mut self, rng: &mut Rng, dir: &Path) {
		let comp = pick(rng, &[Comp::Gzip, Comp::Zstd, Comp::None]);
		let ext = match comp {
			Comp::Gzip => ".gz",
			Comp::Zstd => ".zst",
			_ => "",
		};
		let name = pick(rng, &NAMES);
		let version = pick(rng, &VERSIONS);
		let file = format!("{name}-{version}-x86_64.pkg.tar{ext}");
		let what = match rng.below(14) {
			0..=4 => {
				write_package(
					&dir.join(&file),
					name,
					version,
					comp,
				);
				if rng.below(2) == 0 {
					let sig = format!("{file}.sig");
					fs::write(dir.join(sig), b"sig")
						.unwrap();
				}
				file
			}
			5 => {
				let f = "zz-1.0-1-any.pkg.tar.gz".to_string();
				write_package(
					&dir.join(&f),
					"zz",
					"1.0-1",
					comp,
				);
				f
			}
			6 => {
				// a download cut short, or one that loads whole
				let f = format!("{file}.part");
				let mut data = package_bytes(name, version);
				// cut inside the first header: a cut in the .PKGINFO
				// data is logged by the C only (be_package)
				if rng.below(2) == 0 {
					data.truncate(rng.below(512));
				}
				fs::write(dir.join(&f), data).unwrap();
				f
			}
			7 => {
				let f = format!("{file}.sig");
				fs::write(dir.join(&f), b"orphan").unwrap();
				f
			}
			8 => {
				let f = pick(
					rng,
					&["notes.txt", "empty.pkg.tar"],
				);
				let data: &[u8] = match f {
					"notes.txt" => b"not a package\n",
					_ => b"",
				};
				fs::write(dir.join(f), data).unwrap();
				f.to_string()
			}
			9 => {
				let f = "nometa.pkg.tar".to_string();
				let tar = ustar(&[tar_file("x", b"x")]);
				fs::write(dir.join(&f), tar).unwrap();
				f
			}
			10 => {
				// equal to 1.0-1 for vercmp, not for strcmp
				let v = pick(
					rng,
					&["1.00-1", "0:1.0-1", "1.0-01"],
				);
				let f = format!("{name}-{v}-any.pkg.tar");
				write_package(
					&dir.join(&f),
					name,
					v,
					Comp::None,
				);
				f
			}
			11 => {
				let f = "sub".to_string();
				let d = dir.join(&f);
				if !d.exists() {
					fs::create_dir(&d).unwrap();
					fs::write(d.join("inner"), b"x")
						.unwrap();
				}
				f
			}
			_ => {
				// what -c skips by name
				let f = pick(
					rng,
					&[
						"core.db",
						"core.db.tar.gz",
						"x.files.tar",
						"y-1-1.src.tar.gz",
					],
				);
				fs::write(dir.join(f), b"skip").unwrap();
				f.to_string()
			}
		};
		self.note(format!("{}: {what}", dir.display()));
	}

	// the C handle: repos registered, cache dirs added, then cb_log
	pub fn c_handle(&self) -> FrontHandle {
		// the callbacks read config, also when alpm_release logs
		init();
		let (root, dbpath) = (self.fx.root(), self.fx.dbpath());
		let fh = FrontHandle::open(&root, &dbpath, b".db", &self.repos);
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let (h, _) = fh.raw();
		// SAFETY: h is live, the C copies the paths; cb_log reads the
		// C config like in pacman
		unsafe {
			for d in &self.cachedirs {
				let d = cstr(d);
				let ret =
					alpm_option_add_cachedir(h, d.as_ptr());
				assert_eq!(ret, 0);
			}
			alpm_option_set_logcb(h, Some(cb_log), ptr::null_mut());
		}
		fh
	}
}

// pacman_sync with -c/-cc (cfg.op_s_clean, cfg.cleanmethod) on fh, also
// noconfirm, logmask and colstr from cfg, stdin reading input: its
// return value, what it printed and read
pub fn c_pacman_sync_clean(
	fh: &FrontHandle,
	cfg: &Config,
	input: &[u8],
) -> (c_int, CIo) {
	assert!(cfg.op_s_clean != 0, "not -Sc");
	let mut ret = 0;
	let (h, _) = fh.raw();
	let io = run(cfg, 0, input, || {
		// SAFETY: run holds FRONTEND, config is valid; the fields set
		// here are put back after the call. pacman_sync takes no
		// targets on this branch
		unsafe {
			let c = &mut *config;
			let old = (c.handle, c.op_s_clean, c.cleanmethod);
			c.handle = h;
			c.op_s_clean = cfg.op_s_clean;
			c.cleanmethod = cfg.cleanmethod;
			ret = pacman_sync(ptr::null_mut());
			(c.handle, c.op_s_clean, c.cleanmethod) = old;
		}
	});
	(ret, io)
}
