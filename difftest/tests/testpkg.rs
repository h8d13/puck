// src/util/testpkg.c. binary: the C testpkg (PACMAN_BUILD) and the Rust
// one (target/<profile>/testpkg) on generated package files (valid in
// every compression, corrupted, truncated, unreadable, signed by the gpg
// fixture's keys against the system keyring config.h names), stdout,
// stderr and exit status compared, each run capped at 60 s. module:
// testpkg::run with the fixture root and keyrings against the C load
// on a CSigHandle (difftest/src/testpkg.rs) at every package siglevel,
// signed and unsigned files. scripts/cli-parity-fixtures.sh runs it
// with the table shown
use std::ffi::c_int;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use alpm_core::signing::{
	SIG_PACKAGE, SIG_PACKAGE_MARGINAL_OK, SIG_PACKAGE_OPTIONAL,
	SIG_PACKAGE_UNKNOWN_OK,
};
use difftest::{
	COMPS, CSigHandle, FILES, GpgFixture, Home, c_testpkg, output_capped,
	tar_dir, tar_file, ustar, write_db,
};
use testpkg::{Output, Setup, run};

fn c_bin() -> PathBuf {
	let dir = match std::env::var_os("PACMAN_BUILD") {
		Some(d) => PathBuf::from(d),
		None => Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("../pacman/build"),
	};
	dir.join("testpkg")
}

// target/<profile>/deps/testpkg-<hash> -> target/<profile>/testpkg
fn rust_bin() -> PathBuf {
	let exe = std::env::current_exe().unwrap();
	let bin = exe.parent().unwrap().parent().unwrap().join("testpkg");
	assert!(
		bin.exists(),
		"{} missing: cargo build --release -p testpkg",
		bin.display()
	);
	bin
}

#[derive(Debug, PartialEq, Eq)]
struct Run {
	status: i32,
	out: Vec<u8>,
	err: Vec<u8>,
}

fn run_bin(bin: &Path, args: &[&[u8]]) -> Run {
	let mut cmd = Command::new(bin);
	cmd.args(args.iter().map(|a| std::ffi::OsStr::from_bytes(a)))
		.env_clear()
		.env("LC_ALL", "C.UTF-8")
		.env("PATH", "/usr/bin:/bin");
	let o = output_capped(&mut cmd, 60);
	Run {
		status: o.status.code().expect("killed by a signal"),
		out: o.stdout,
		err: o.stderr,
	}
}

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

const PKGINFO: &str = "pkgname = t\npkgbase = t\nxdata = pkgtype=pkg\n\
	pkgver = 1.0-1\npkgdesc = test package\nurl = https://example.org/\n\
	builddate = 1720811171\npackager = A B <a@b.org>\nsize = 4\n\
	arch = any\nlicense = MIT\n";

fn pkg_tar(pkginfo: &str) -> Vec<u8> {
	ustar(&[
		tar_file(".PKGINFO", pkginfo.as_bytes()),
		tar_dir("usr/"),
		tar_file("usr/x", b"abc\n"),
	])
}

// the generated package files under dir: (label, path)
fn packages(dir: &Path) -> Vec<(String, PathBuf)> {
	fs::create_dir_all(dir).unwrap();
	let mut v = Vec::new();
	let mut add = |name: &str, data: &[u8]| {
		let p = dir.join(name);
		fs::write(&p, data).unwrap();
		v.push((name.to_string(), p));
	};
	let tar = pkg_tar(PKGINFO);
	add("plain.pkg.tar", &tar);
	add("empty.pkg.tar", b"");
	add("garbage.pkg.tar", &[0x5a; 700]);
	add("half.pkg.tar", &tar[..tar.len() / 2]);
	add("cut512.pkg.tar", &tar[..512]);
	add("noinfo.pkg.tar", &ustar(&[tar_file("usr/x", b"x")]));
	add("noname.pkg.tar", &pkg_tar("pkgver = 1.0-1\n"));
	add("badver.pkg.tar", &pkg_tar("pkgname = t\npkgver = 1.0\n"));
	add("badsize.pkg.tar", &pkg_tar(&PKGINFO.replace("4\n", "x\n")));
	// .sig files next to unsigned content
	add("emptysig.pkg.tar", &tar);
	add("emptysig.pkg.tar.sig", b"");
	add("junksig.pkg.tar", &tar);
	add("junksig.pkg.tar.sig", &[0x89; 120]);
	for (i, comp) in COMPS.iter().enumerate() {
		let p = dir.join(format!("c{i}.pkg.tar.x"));
		write_db(&p, *comp, &tar);
		let data = fs::read(&p).unwrap();
		v.push((format!("{comp:?}"), p.clone()));
		let cut = dir.join(format!("c{i}-cut.pkg.tar.x"));
		fs::write(&cut, &data[..data.len() * 2 / 3]).unwrap();
		v.push((format!("{comp:?} cut"), cut));
	}
	v.retain(|(n, _)| !n.ends_with(".sig"));
	let unreadable = dir.join("unreadable.pkg.tar");
	fs::write(&unreadable, &tar).unwrap();
	fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))
		.unwrap();
	v.push(("unreadable".into(), unreadable));
	let sub = dir.join("dir.pkg.tar");
	fs::create_dir_all(&sub).unwrap();
	v.push(("directory".into(), sub));
	v.push(("missing".into(), dir.join("nope.pkg.tar")));
	v
}

// a passwd-like text file: libarchive's mtree reader bids on it and
// fails the read ("Package is invalid."), the port's archive sniffing
// refuses to open it ("Cannot open"). be_package's pinned "text file"
// input; plain prose is refused by both
fn known(label: &str) -> bool {
	label == "text file"
}

// testpkg's own line: the verdict after the library's log lines
fn verdict(out: &[u8]) -> &[u8] {
	let body = out.strip_suffix(b"\n").unwrap_or(out);
	let start = body.iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1);
	&out[start..]
}

// equal but for the "error: " lines be_package logs: the port leaves
// out libarchive's error texts ("could not open file ...: <text>",
// "error while reading package ...: <text>") and logs .PKGINFO/check_meta
// refusals through its own reader (PORTING.md be_package row, the
// pkgreader unit). status, stderr and the verdict must still match
fn same_verdict(c: (i32, &[u8], &[u8]), r: (i32, &[u8], &[u8])) -> bool {
	c.0 == r.0 && c.2 == r.2 && verdict(c.1) == verdict(r.1)
}

#[derive(Default)]
struct Tally {
	equal: usize,
	logs: usize,
	total: usize,
	failures: Vec<String>,
}

impl Tally {
	fn check(&mut self, label: &str, args: &[&[u8]]) {
		let c = run_bin(&c_bin(), args);
		let r = run_bin(&rust_bin(), args);
		self.total += 1;
		let ok = c == r;
		let logs = !ok && same_verdict(
			(c.status, &c.out, &c.err),
			(r.status, &r.out, &r.err),
		);
		self.equal += usize::from(ok);
		self.logs += usize::from(logs);
		let mark = match (ok, logs) {
			(true, _) => "equal",
			(_, true) => "LOGS",
			_ => "DIFF",
		};
		let (o, e) = (c.out.len(), c.err.len());
		println!("{mark:5}  {label}  [{} {o}/{e}]", c.status);
		if !ok && !logs && !known(label) {
			self.failures.push(format!(
				"{label}\nstatus C {} Rust {}\n-- C out\n{}\
				-- Rust out\n{}-- C err\n{}-- Rust err\n{}",
				c.status,
				r.status,
				lossy(&c.out),
				lossy(&r.out),
				lossy(&c.err),
				lossy(&r.err)
			));
		}
	}

	fn finish(self, what: &str) {
		println!(
			"== {what}: {}/{} equal, {} with be_package log lines only",
			self.equal, self.total, self.logs
		);
		assert!(
			self.failures.is_empty(),
			"{}",
			self.failures.join("\n")
		);
	}
}

#[test]
fn binary() {
	let fx = GpgFixture::new("testpkg-bin");
	let dir = fx.dir().join("t");
	let mut t = Tally::default();
	t.check("no args", &[]);
	t.check("two args", &[b"a", b"b"]);
	t.check("empty path", &[b""]);
	let text = dir.join("text");
	fs::create_dir_all(&dir).unwrap();
	fs::write(
		&text,
		b"root:x:0:0::/root:/bin/bash\nbin:x:1:1::/:/usr/bin/nologin\n",
	)
	.unwrap();
	t.check("text file", &[text.as_os_str().as_bytes()]);
	for (label, p) in packages(&dir) {
		t.check(&label, &[p.as_os_str().as_bytes()]);
	}
	// fixture keys are unknown to the system keyring
	for name in FILES {
		let p = fx.file(name);
		t.check(&format!("signed {name}"), &[&p]);
	}
	t.finish("testpkg binary");
}

const LEVELS: &[c_int] = &[
	0,
	SIG_PACKAGE,
	SIG_PACKAGE | SIG_PACKAGE_OPTIONAL,
	SIG_PACKAGE | SIG_PACKAGE_MARGINAL_OK,
	SIG_PACKAGE | SIG_PACKAGE_UNKNOWN_OK,
	SIG_PACKAGE | SIG_PACKAGE_OPTIONAL | SIG_PACKAGE_MARGINAL_OK,
	SIG_PACKAGE | SIG_PACKAGE_OPTIONAL | SIG_PACKAGE_UNKNOWN_OK,
	SIG_PACKAGE
		| SIG_PACKAGE_OPTIONAL
		| SIG_PACKAGE_MARGINAL_OK
		| SIG_PACKAGE_UNKNOWN_OK,
	// optional without SIG_PACKAGE: no check at all
	SIG_PACKAGE_OPTIONAL,
];

// run() with the fixture's root, dbpath and a keyring against the C
// load on a handle with the same paths
#[test]
fn module() {
	let fx = GpgFixture::new("testpkg-mod");
	let mut files: Vec<(String, Vec<u8>)> = FILES
		.iter()
		.map(|n| (format!("signed {n}"), fx.file(n)))
		.collect();
	for (label, p) in packages(&fx.dir().join("t")) {
		files.push((label, p.as_os_str().as_bytes().to_vec()));
	}
	let (root, db) = (fx.root_dir(), fx.db_dir());
	let root_b = root.as_os_str().as_bytes().to_vec();
	let db_b = db.as_os_str().as_bytes().to_vec();
	let (mut equal, mut logs_only, mut total) = (0, 0, 0);
	let mut failures = Vec::new();
	for home in [Home::Pgp, Home::Direct, Home::ReadOnly] {
		let gpgdir = fx.home(home);
		let h = CSigHandle::new(&root, &db, &gpgdir);
		// every level on the pacman-key keyring, the testpkg one on
		// the others
		let levels = match home {
			Home::Pgp => LEVELS,
			_ => &LEVELS[2..3],
		};
		for &level in levels {
			for (label, path) in &files {
				let c = c_testpkg(&h, path, level);
				let setup = Setup {
					root: &root_b,
					dbpath: &db_b,
					gpgdir: &gpgdir,
					siglevel: level,
				};
				let mut o = Output::default();
				let ret = run(
					std::slice::from_ref(path),
					&setup,
					&mut o,
				);
				total += 1;
				let ok = c == (ret, o.out.clone())
					&& o.err.is_empty();
				let logs = !ok && same_verdict(
					(c.0, &c.1, b""),
					(ret, &o.out, &o.err),
				);
				equal += usize::from(ok);
				logs_only += usize::from(logs);
				if !ok && !logs && !known(label) {
					failures.push(format!(
						"{home:?} level {level:#x} {label}\n\
						C {} {}\nRust {ret} {}{}",
						c.0,
						lossy(&c.1),
						lossy(&o.out),
						lossy(&o.err)
					));
				}
			}
		}
	}
	println!(
		"== testpkg module: {equal}/{total} equal, {logs_only} with \
		be_package log lines only"
	);
	assert!(failures.is_empty(), "{}", failures.join("\n"));
}
