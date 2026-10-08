// alpm_core::diskspace against the C. check_diskspace and
// check_downloadspace run on a C handle and a Rust Handle over the same
// fixture (root tree with real files, local db) under /tmp, both reading
// the real mount table and statvfs; return value, pm_errno and every
// logcb/progresscb call (debug included) are compared. free space on a
// shared mount moves while tests run, so a mismatch is retried a few
// times before it counts. parse_mntent is compared with glibc getmntent
// on synthetic mtab files and the system's own tables.
use std::ffi::c_int;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use alpm_core::be_local::INFRQ_FILES;
use alpm_core::callbacks::{Callbacks, LogLevel, Progress};
use alpm_core::diskspace::{
	FsInfo, Mounts, SpaceError, System, check_diskspace,
	check_downloadspace, match_mount_point, mount_point_list, parse_mntent,
};
use alpm_core::filelist::{File, FileList};
use alpm_core::handle::Handle;
use alpm_core::package::Package;
use alpm_core::util::hash_sdbm;
use difftest::{
	CSpace, CSpaceResult, CbEvent, LocalEntry, Rng, TempRoot, c_getmntent,
	iters, loose_sections, section,
};

const NAMES: [&str; 5] = ["a", "b", "foo", "lib-x", "z9"];
const DIRS: [&str; 6] =
	["etc/", "usr/", "usr/bin/", "usr/lib/", "var/", "var/lib/"];
const NOEXTRACT: [&str; 6] = [
	"usr/bin/missing*",
	"!usr/bin/missing1",
	"*",
	"etc/*",
	"!*",
	"var/lib/m?",
];
const MODES: [u32; 6] = [0o100644, 0o100755, 0o040755, 0o120777, 0o020644, 0];
// mounts and files of a typical system root, for cases rooted at "/"
const SYSTEM_PATHS: [&str; 14] = [
	"run/credentials/@encrypted/x",
	"run/credentials/x",
	"proc/x",
	"proc/sys/fs/binfmt_misc/x",
	"run/user/1000/gvfs/a",
	"run/user/1000/doc/a",
	"sys/fs/cgroup/x",
	"tmp/x",
	"usr/x",
	"boot/x",
	"dev/shm/x",
	"etc/hostname",
	"usr/bin/sh",
	"boot/EFI",
];

#[derive(Default)]
struct Rec(Vec<CbEvent>);

impl Callbacks for Rec {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.0.push(CbEvent::Log(level as c_int, msg.to_vec()));
	}

	fn progress(
		&mut self,
		progress: Progress,
		pkg: &[u8],
		percent: c_int,
		howmany: usize,
		current: usize,
	) {
		self.0.push(CbEvent::Progress(
			progress as c_int,
			pkg.to_vec(),
			percent,
			howmany,
			current,
		));
	}
}

// the C's return and pm_errno (reset to 0 before the call)
fn rust_result(r: Result<(), SpaceError>, ev: Rec) -> CSpaceResult {
	match r {
		Ok(()) => (0, None, ev.0),
		Err(e) => (-1, Some(e.errno().map_or(0, |e| e as c_int)), ev.0),
	}
}

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

// what the cases reached
#[derive(Default, Debug)]
struct Seen {
	ok: usize,
	too_full: usize,
	read_only: usize,
	no_info: usize,
	no_mount: usize,
	statvfs_failed: usize,
	retries: usize,
}

fn contains(m: &[u8], s: &str) -> bool {
	m.windows(s.len()).any(|w| w == s.as_bytes())
}

impl Seen {
	fn count(&mut self, r: &CSpaceResult) {
		self.ok += (r.0 == 0) as usize;
		for e in &r.2 {
			let CbEvent::Log(_, m) = e else { continue };
			let has = |s| contains(m, s) as usize;
			self.too_full += has("too full");
			self.read_only += has("read only");
			self.no_info += has("could not get file information");
			self.no_mount += has("could not determine");
			self.statvfs_failed +=
				has("could not get filesystem information");
		}
	}
}

fn show(r: &CSpaceResult) -> String {
	let ev: Vec<String> = r
		.2
		.iter()
		.map(|e| match e {
			CbEvent::Log(l, m) => {
				format!("{l} {}", String::from_utf8_lossy(m))
			}
			p => format!("{p:?}\n"),
		})
		.collect();
	format!("{} {:?}\n{}", r.0, r.1, ev.concat())
}

// the system's table and statvfs, with f_bavail of the mounts the C
// checked taken from its "partition ..., free N" trace: free space on a
// shared mount moves between the two calls
struct Pinned(Vec<(Vec<u8>, u64)>);

impl Pinned {
	fn from_c(r: &CSpaceResult) -> Self {
		let mut free = Vec::new();
		for e in &r.2 {
			let CbEvent::Log(4, m) = e else { continue };
			let Some(rest) = m.strip_prefix(b"partition ") else {
				continue;
			};
			let s = String::from_utf8_lossy(rest);
			let (Some(d), Some(f)) =
				(s.rfind(", needed "), s.rfind("free "))
			else {
				continue;
			};
			let n = s[f + 5..].trim_end().parse().unwrap();
			free.push((rest[..d].to_vec(), n));
		}
		Pinned(free)
	}
}

impl Mounts for Pinned {
	fn table(&mut self) -> std::io::Result<Vec<u8>> {
		System.table()
	}

	fn statvfs(&mut self, dir: &[u8]) -> std::io::Result<FsInfo> {
		let mut fsp = System.statvfs(dir)?;
		if let Some((_, n)) = self.0.iter().find(|(d, _)| d == dir) {
			fsp.bavail = *n;
		}
		Ok(fsp)
	}
}

// runs c then rust (on the C's f_bavail) until they agree, at most 5
// times: a statvfs between them can still see other values
fn agree(
	seen: &mut Seen,
	what: &dyn std::fmt::Debug,
	mut c: impl FnMut() -> CSpaceResult,
	mut rust: impl FnMut(&mut Pinned) -> CSpaceResult,
) {
	let mut last = None;
	for _ in 0..5 {
		let cr = c();
		let rr = rust(&mut Pinned::from_c(&cr));
		if cr == rr {
			seen.count(&cr);
			return;
		}
		seen.retries += 1;
		last = Some((cr, rr));
	}
	let (cr, rr) = last.unwrap();
	panic!("{what:?}\nC:\n{}\nRust:\n{}", show(&cr), show(&rr));
}

// a root tree under the fixture and the relative paths it offers: files
// of random (sparse) sizes, symlinks, dirs, and names that do not exist
fn build_tree(rng: &mut Rng, root: &Path) -> Vec<String> {
	let mut paths: Vec<String> =
		DIRS.iter().map(|d| d.to_string()).collect();
	for d in DIRS {
		fs::create_dir_all(root.join(d)).unwrap();
	}
	for i in 0..12 {
		let p = format!("{}f{i}", pick(rng, &DIRS));
		let size = match rng.below(5) {
			0 => pick(rng, &[0, 1, 4095, 4096, 4097, 8192]),
			1 => rng.below(1 << 20) as u64,
			2 => (rng.below(1 << 30) as u64) << rng.below(4),
			_ => rng.below(100_000) as u64,
		};
		let f = fs::File::create(root.join(&p)).unwrap();
		f.set_len(size).unwrap();
		paths.push(p);
	}
	for i in 0..3 {
		let p = format!("{}l{i}", pick(rng, &DIRS));
		std::os::unix::fs::symlink("f0", root.join(&p)).unwrap();
		paths.push(p);
	}
	for i in 0..3 {
		paths.push(format!("usr/bin/missing{i}"));
		paths.push(format!("var/lib/m{i}"));
	}
	// a dir no "etc/d/" entry names, listed as a file
	fs::create_dir(root.join("etc/d")).unwrap();
	paths.push("etc/d".into());
	paths
}

// a files list as the C reads it: parents listed or left out, a dir also
// listed without its '/', duplicates, any order (the reader sorts)
fn file_section(rng: &mut Rng, paths: &[String]) -> Vec<u8> {
	let mut all: Vec<String> = Vec::new();
	for p in paths {
		let mut end = 0;
		while let Some(i) = p[end..].find('/') {
			end += i + 1;
			match rng.below(8) {
				0 => {}
				1 => all.push(p[..end - 1].to_string()),
				_ => all.push(p[..end].to_string()),
			}
		}
		all.push(p.clone());
	}
	all.sort();
	// shared parents are listed once per path otherwise
	if rng.below(4) != 0 {
		all.dedup();
	}
	if rng.below(4) == 0 {
		for i in (1..all.len()).rev() {
			all.swap(i, rng.below(i + 1));
		}
	}
	section("FILES", &all).into_bytes()
}

fn local_desc(rng: &mut Rng, name: &str) -> Vec<u8> {
	let rest = loose_sections(
		rng,
		&[
			("BASE", name),
			("DESC", "A package"),
			("URL", "https://example.org/"),
			("ARCH", "x86_64"),
			("BUILDDATE", "1700000000"),
			("INSTALLDATE", "1700000001"),
			("PACKAGER", "A B <a@b.org>"),
			("SIZE", "42"),
			("VALIDATION", "pgp"),
		],
	);
	format!("%NAME%\n{name}\n\n%VERSION%\n1.0-1\n\n{rest}").into_bytes()
}

// local packages owning random subsets of paths, their names
fn write_local(rng: &mut Rng, fx: &TempRoot, paths: &[String]) -> Vec<String> {
	fx.reset_local();
	let mut names: Vec<String> = Vec::new();
	let mut entries = Vec::new();
	for name in NAMES {
		if rng.below(3) == 0 {
			continue;
		}
		let mut own: Vec<String> = paths.to_vec();
		own.retain(|_| rng.below(3) == 0);
		entries.push(LocalEntry {
			dir: format!("{name}-1.0-1"),
			desc: Some(local_desc(rng, name)),
			files: Some(file_section(rng, &own)),
			install: false,
		});
		names.push(name.into());
	}
	fx.write_local(&entries);
	names
}

// free bytes of the mount holding dir, to aim sizes at the boundary
fn free_bytes(dir: &[u8]) -> u64 {
	let mut ev = Rec::default();
	let mps = mount_point_list(&mut System, &mut ev);
	let i = match_mount_point(&mps, dir).unwrap();
	let fsp = System.statvfs(&mps[i].dir).unwrap();
	fsp.bavail.max(1) * fsp.bsize
}

fn file_size(rng: &mut Rng, free: u64) -> i64 {
	match rng.below(8) {
		0 => pick(rng, &[0, 1, 511, 512, 4095, 4096, 4097]),
		1 => (rng.below(64) as i64) * 4096 + pick(rng, &[-1, 0, 1]),
		2 => (free / (1 + rng.below(4) as u64)) as i64,
		3 => (free as i64) - (rng.below(1 << 26) as i64),
		4 => -(rng.below(5000) as i64),
		_ => rng.below(1 << 22) as i64,
	}
}

fn add_pkg(rng: &mut Rng, pool: &[String], free: u64) -> Package {
	let name = pick(rng, &NAMES);
	let n = rng.below(8);
	let per_file = free / n.max(1) as u64;
	let files = (0..n)
		.map(|_| {
			let name = match rng.below(8) {
				0 => pick(
					rng,
					&[".PKGINFO", ".INSTALL", ".x", ""],
				)
				.to_string(),
				_ => pool[rng.below(pool.len())].clone(),
			};
			let size = file_size(rng, per_file);
			File::new(name.into_bytes(), size, pick(rng, &MODES))
		})
		.collect();
	Package {
		name_hash: hash_sdbm(name.as_bytes()),
		name: Some(name.into()),
		version: Some(b"2.0-1".to_vec()),
		files: FileList { files },
		..Default::default()
	}
}

// local packages for the Rust remove list, files loaded
fn rust_remove(h: &mut Handle, names: &[&[u8]]) -> Vec<Package> {
	let dbext = h.dbext().to_vec();
	let db = h.localdb_mut().unwrap();
	names.iter()
		.map(|n| {
			db.load_pkg(&dbext, &mut (), n, INFRQ_FILES)
				.unwrap()
				.clone()
		})
		.collect()
}

fn noextract(rng: &mut Rng) -> Vec<Vec<u8>> {
	let mut v: Vec<Vec<u8>> =
		NOEXTRACT.iter().map(|s| s.as_bytes().to_vec()).collect();
	v.retain(|_| rng.below(3) == 0);
	v
}

struct Case {
	// declared first: the handles go before the fixture dir
	c: CSpace,
	h: Handle,
	paths: Vec<String>,
	local: Vec<String>,
	_fx: TempRoot,
}

// root "/" reads the system's own files and mounts, read only
fn case(rng: &mut Rng, system_root: bool) -> Case {
	let fx = TempRoot::new("diskspace");
	let mut paths = build_tree(rng, &fx.dir().join("root"));
	let mut root = fx.root();
	if system_root {
		root = b"/".to_vec();
		paths = SYSTEM_PATHS.iter().map(|s| s.to_string()).collect();
	}
	let local = write_local(rng, &fx, &paths);
	let mut c = CSpace::new(&root, &fx.path("db"));
	c.load_local();
	let h = Handle::initialize(&root, &fx.path("db")).unwrap();
	Case {
		c,
		h,
		paths,
		local,
		_fx: fx,
	}
}

fn run_diskspace(cases: usize, per_case: usize, system_root: bool) -> Seen {
	let mut rng = Rng::new(0xd15c + system_root as u64);
	let mut seen = Seen::default();
	let free = free_bytes(std::env::temp_dir().as_os_str().as_bytes());
	for _ in 0..cases {
		let mut k = case(&mut rng, system_root);
		for _ in 0..per_case {
			let ne = noextract(&mut rng);
			k.c.set_noextracts(&ne);
			k.h.set_noextracts(&ne);
			let add: Vec<Package> = (0..rng.below(4))
				.map(|_| add_pkg(&mut rng, &k.paths, free))
				.collect();
			let mut remove: Vec<&[u8]> = Vec::new();
			for n in &k.local {
				if rng.below(3) == 0 {
					remove.push(n.as_bytes());
				}
			}
			let rpkgs = rust_remove(&mut k.h, &remove);
			let what = (&add, &remove, &ne);
			let (c, h) = (&mut k.c, &mut k.h);
			agree(
				&mut seen,
				&what,
				|| c.check(&add, &remove),
				|m| {
					let mut ev = Rec::default();
					let r = check_diskspace(
						h, &add, &rpkgs, m, &mut ev,
					);
					rust_result(r, ev)
				},
			);
		}
	}
	seen
}

#[test]
fn diskspace_fixture_root() {
	let per_case = 50;
	let cases = (iters() / 10 / per_case).max(10);
	let seen = run_diskspace(cases, per_case, false);
	eprintln!("{seen:?}");
	let n = cases * per_case;
	assert!(seen.ok > n / 10, "{seen:?}");
	assert!(seen.too_full > n / 20, "{seen:?}");
	assert!(seen.no_info > n / 10, "{seen:?}");
	assert!(seen.no_mount == 0, "{seen:?}");
}

#[test]
fn diskspace_system_root() {
	let per_case = 50;
	let cases = (iters() / 200 / per_case).max(4);
	let seen = run_diskspace(cases, per_case, true);
	eprintln!("{seen:?}");
	// which branches the system's mounts reach depends on the machine
	assert!(seen.ok + seen.too_full > 0, "{seen:?}");
}

#[test]
fn downloadspace() {
	let mut rng = Rng::new(0xd10ad);
	let mut seen = Seen::default();
	let fx = TempRoot::new("dlspace");
	let root = fx.dir().join("root");
	fs::create_dir_all(root.join("cache/sub")).unwrap();
	std::os::unix::fs::symlink("/", root.join("toslash")).unwrap();
	std::os::unix::fs::symlink("cache", root.join("tocache")).unwrap();
	let base = fx.root();
	let s = |rel: &str| [&base[..], rel.as_bytes()].concat();
	let dirs = [
		s("/cache"),
		s("/cache/sub/../"),
		s("/tocache/"),
		s("/toslash"),
		s("/nope/x"),
		b"nope/rel".to_vec(),
		Vec::new(),
		b"/".to_vec(),
		b"/proc".to_vec(),
		b"/run/credentials/@encrypted".to_vec(),
	];
	let free = free_bytes(&base);
	let mut c = CSpace::new(&base, &fx.path("db"));
	let n = (iters() / 10).max(1000);
	for _ in 0..n {
		let dir = &dirs[rng.below(dirs.len())];
		let k = rng.below(6);
		let per_file = free / k.max(1) as u64;
		let sizes: Vec<i64> =
			(0..k).map(|_| file_size(&mut rng, per_file)).collect();
		agree(
			&mut seen,
			&(String::from_utf8_lossy(dir), &sizes),
			|| c.check_download(dir, &sizes),
			|m| {
				let mut ev = Rec::default();
				let r = check_downloadspace(
					dir, &sizes, m, &mut ev,
				);
				rust_result(r, ev)
			},
		);
	}
	drop(c);
	eprintln!("{seen:?}");
	assert!(seen.ok > n / 10, "{seen:?}");
	assert!(seen.too_full > n / 10, "{seen:?}");
	assert!(seen.no_mount > n / 20, "{seen:?}");
}

// tokens the glibc parser special-cases
const MNT_TOKENS: [&[u8]; 22] = [
	b"a", b"/", b"/mnt", b" ", b"\t", b"  \t", b"\\", b"\\040", b"\\011",
	b"\\012", b"\\134", b"\\\\", b"\\04", b"#", b",", b"=", b"autofs",
	b"ignore", b"\0", b"\n", b"\x80", b"0",
];

const MNT_OPTS: [&[u8]; 6] =
	[b"ignore", b"rw", b"x=1", b"ignore=y", b"", b"ign"];

fn mtab_line(rng: &mut Rng) -> Vec<u8> {
	let mut l = Vec::new();
	match rng.below(10) {
		// well formed, odd options
		0..=3 => {
			let o: Vec<&[u8]> = (0..rng.below(4))
				.map(|_| pick(rng, &MNT_OPTS))
				.collect();
			l.extend_from_slice(b"src /m");
			l.extend(rng.bytes(b"ab\\040/ ", 6));
			l.push(b' ');
			l.extend_from_slice(pick(
				rng,
				&[b"autofs" as &[u8], b"tmpfs"],
			));
			l.push(b' ');
			l.extend(o.join(&b","[..]));
			l.extend_from_slice(b" 0 0");
		}
		// around the 4096 byte buffer
		4 => {
			let n = pick(
				rng,
				&[4090, 4093, 4094, 4095, 4096, 5200, 9000],
			);
			l.extend_from_slice(b"a /");
			l.resize(n, b'x');
			l.extend_from_slice(pick(
				rng,
				&[b" t o" as &[u8], b"", b"\0z"],
			));
		}
		_ => {
			for _ in 0..rng.below(12) {
				l.extend_from_slice(pick(rng, &MNT_TOKENS));
			}
		}
	}
	l.push(b'\n');
	l
}

#[test]
fn getmntent_synthetic() {
	let mut rng = Rng::new(0x3a7e);
	let fx = TempRoot::new("mntent");
	let file = fx.dir().join("mtab");
	let path = file.as_os_str().as_bytes().to_vec();
	let mut entries = 0;
	for _ in 0..iters() {
		let mut t = Vec::new();
		for _ in 0..rng.below(6) {
			t.extend(mtab_line(&mut rng));
		}
		if rng.below(4) == 0 {
			t.pop();
		}
		fs::write(&file, &t).unwrap();
		let c = c_getmntent(&path);
		let lossy = String::from_utf8_lossy(&t);
		assert_eq!(parse_mntent(&t), c, "{lossy:?}");
		entries += c.len();
	}
	assert!(entries > iters(), "{entries}");
}

#[test]
fn getmntent_system_tables() {
	for p in ["/etc/mtab", "/proc/self/mounts"] {
		let t = fs::read(p).unwrap();
		let c = c_getmntent(p.as_bytes());
		assert!(!c.is_empty());
		assert_eq!(parse_mntent(&t), c, "{p}");
	}
}
