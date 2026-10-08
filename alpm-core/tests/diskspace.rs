use std::ffi::c_int;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use alpm_core::callbacks::{Callbacks, LogLevel, Progress};
use alpm_core::diskspace::{
	FsInfo, FsInfoState, MountEntry, MountPoint, Mounts, SpaceError,
	System, USED_INSTALL, USED_REMOVE, calculate_installed_size,
	calculate_removed_size, check_diskspace, check_downloadspace,
	check_mountpoint, load_fsinfo, match_mount_point, mount_point_list,
	parse_mntent,
};
use alpm_core::error::Errno;
use alpm_core::filelist::{File, FileList};
use alpm_core::handle::Handle;
use alpm_core::package::Package;

#[derive(Debug, PartialEq, Eq)]
enum Ev {
	Log(LogLevel, String),
	Progress(c_int, usize, usize),
}

#[derive(Default)]
struct Rec(Vec<Ev>);

impl Callbacks for Rec {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		let msg = String::from_utf8(msg.to_vec()).unwrap();
		self.0.push(Ev::Log(level, msg));
	}

	fn progress(
		&mut self,
		progress: Progress,
		pkg: &[u8],
		percent: c_int,
		howmany: usize,
		current: usize,
	) {
		assert_eq!(
			(progress, pkg),
			(Progress::DiskspaceStart, &b""[..])
		);
		self.0.push(Ev::Progress(percent, howmany, current));
	}
}

impl Rec {
	fn errors(&self) -> Vec<&str> {
		self.0.iter()
			.filter_map(|e| match e {
				Ev::Log(LogLevel::Error, m) => Some(m.as_str()),
				_ => None,
			})
			.collect()
	}
}

// synthetic table and statvfs results, errno for failures
struct Fake {
	table: Result<Vec<u8>, i32>,
	fs: Vec<(Vec<u8>, Result<FsInfo, i32>)>,
	stats: usize,
}

impl Mounts for Fake {
	fn table(&mut self) -> io::Result<Vec<u8>> {
		self.table.clone().map_err(io::Error::from_raw_os_error)
	}

	fn statvfs(&mut self, dir: &[u8]) -> io::Result<FsInfo> {
		self.stats += 1;
		let hit = self.fs.iter().find(|(d, _)| d == dir);
		let r = hit.map_or(Err(2), |(_, r)| *r);
		r.map_err(io::Error::from_raw_os_error)
	}
}

fn fs(bsize: u64, blocks: u64, bavail: u64) -> FsInfo {
	FsInfo {
		bsize,
		blocks,
		bavail,
		read_only: false,
	}
}

fn entry(fsname: &str, dir: &str, kind: &str, opts: &str) -> MountEntry {
	MountEntry {
		fsname: fsname.into(),
		dir: dir.into(),
		kind: kind.into(),
		opts: opts.into(),
	}
}

fn dirs(table: &[u8]) -> Vec<Vec<u8>> {
	parse_mntent(table).into_iter().map(|e| e.dir).collect()
}

#[test]
fn mntent_fields_and_escapes() {
	let t = b"/dev/a / ext4 rw,relatime 0 1\n\
		  # comment\n\
		  \n \t \n\
		  \t  x\\040y /mnt/my\\040disk\\011t vfat ro\\134x 0 0  \n\
		  a /b\\\\c\\012 t o\n\
		  a /k\\041\\ t\n";
	assert_eq!(
		parse_mntent(t),
		vec![
			entry("/dev/a", "/", "ext4", "rw,relatime"),
			entry("x y", "/mnt/my disk\tt", "vfat", "ro\\x"),
			entry("a", "/b\\c\n", "t", "o"),
			entry("a", "/k\\041\\", "t", ""),
		]
	);
	// missing fields are "", a lone field leaves dir empty
	assert_eq!(parse_mntent(b"one\n"), vec![entry("one", "", "", "")]);
	// last line without newline is read untrimmed
	assert_eq!(dirs(b"a /x \t"), vec![b"/x".to_vec()]);
	assert_eq!(dirs(b"a /x\t\t/y"), vec![b"/x".to_vec()]);
}

#[test]
fn mntent_autofs_ignore() {
	let t = b"s /a autofs ignore\ns /b autofs x,ignore=1\n\
		  s /c autofs noignore\ns /d nfs ignore\ns /e autofs ign\n\
		  s /f autofs ignore,x\ns /g autofs xignore,ignore\n";
	assert_eq!(dirs(t), ["/c", "/d", "/e"].map(|s| s.as_bytes().to_vec()));
}

#[test]
fn mntent_long_lines_and_nul() {
	// 4095 bytes fit the buffer, the newline then drains as a long line
	let mut t = b"a /".to_vec();
	t.resize(4095, b'x');
	t.extend_from_slice(b"\nb /next\n");
	let d = dirs(&t);
	assert_eq!(d.len(), 2);
	assert_eq!(d[0].len(), 4093);
	assert_eq!(d[1], b"/next");
	// past the buffer: the rest is dropped, the next line read
	let mut t = b"a /".to_vec();
	t.resize(5000, b'y');
	t.extend_from_slice(b" t o\nb /next\n");
	let d = dirs(&t);
	assert_eq!(d[0].len(), 4093);
	assert_eq!(d[1], b"/next");
	// a nul hides the newline: the following line is drained too
	let d = dirs(b"a /x\0 t\nb /lost\nc /kept\n");
	assert_eq!(d, [b"/x".to_vec(), b"/kept".to_vec()]);
	assert_eq!(dirs(b"\0\nb /lost\nc /kept\n"), [b"/kept".to_vec()]);
}

#[test]
fn list_sorted_before_parents() {
	let mut f = Fake {
		table: Ok(
			b"a / r\nb /tmp r\nc /tmp/x r\nd /tmpfoo r\ne /tmp r\n"
				.to_vec(),
		),
		fs: Vec::new(),
		stats: 0,
	};
	let mut ev = Rec::default();
	let mps = mount_point_list(&mut f, &mut ev);
	let got: Vec<&[u8]> = mps.iter().map(|m| &m.dir[..]).collect();
	assert_eq!(got, [&b"/tmpfoo"[..], b"/tmp/x", b"/tmp", b"/tmp", b"/"]);
	assert_eq!(ev.0.len(), 5);
	assert_eq!(
		ev.0[0],
		Ev::Log(
			LogLevel::Debug,
			"discovered mountpoint: /tmpfoo\n".into()
		)
	);
	assert_eq!(f.stats, 0, "fsinfo loads lazily");
}

#[test]
fn list_open_failure_and_empty() {
	let mut f = Fake {
		table: Err(13),
		fs: Vec::new(),
		stats: 0,
	};
	let mut ev = Rec::default();
	assert!(mount_point_list(&mut f, &mut ev).is_empty());
	assert_eq!(
		ev.errors(),
		["could not open file: /etc/mtab: Permission denied\n"]
	);
	let mut ev = Rec::default();
	let r = check_downloadspace(b"/x", &[1], &mut f, &mut ev);
	assert_eq!(r, Err(SpaceError::MountPoints));
	assert_eq!(r.unwrap_err().errno(), None);
	f.table = Ok(b"# nothing\n".to_vec());
	let mut ev = Rec::default();
	let r = check_downloadspace(b"/x", &[1], &mut f, &mut ev);
	assert_eq!(r, Err(SpaceError::MountPoints));
	assert_eq!(
		ev.errors(),
		["could not determine filesystem mount points\n"]
	);
}

fn mps(dirs: &[&str]) -> Vec<MountPoint> {
	let mut v: Vec<MountPoint> =
		dirs.iter().map(|d| MountPoint::new(d.as_bytes())).collect();
	v.sort_by(|a, b| b.dir.cmp(&a.dir));
	v
}

fn matched<'a>(mps: &'a [MountPoint], path: &str) -> Option<&'a str> {
	let i = match_mount_point(mps, path.as_bytes())?;
	Some(std::str::from_utf8(&mps[i].dir).unwrap())
}

#[test]
fn match_longest_prefix() {
	let m = mps(&["/", "/e", "/etc", "/etc/x", "/usr/", "/a b"]);
	assert_eq!(matched(&m, "/etc/myconfig"), Some("/etc"));
	assert_eq!(matched(&m, "/etc"), Some("/etc"));
	assert_eq!(matched(&m, "/etc/x/y"), Some("/etc/x"));
	assert_eq!(matched(&m, "/etcx"), Some("/"));
	assert_eq!(matched(&m, "/e/f"), Some("/e"));
	assert_eq!(matched(&m, "/usr/bin"), Some("/usr/"));
	// a trailing '/' on the mount skips the boundary check
	assert_eq!(matched(&m, "/usr/"), Some("/usr/"));
	assert_eq!(matched(&m, "/usr"), Some("/"));
	assert_eq!(matched(&m, "/a b/c"), Some("/a b"));
	assert_eq!(matched(&m, "rel/path"), None);
	assert_eq!(matched(&m, ""), None);
	// path read as a C string
	assert_eq!(matched(&m, "/etc\0/x/y"), Some("/etc"));
	let m = mps(&["/mnt"]);
	assert_eq!(matched(&m, "/"), None);
	// empty dir: next byte of the path must end it
	let m = mps(&[""]);
	assert_eq!(matched(&m, "/x"), Some(""));
	assert_eq!(matched(&m, "x"), None);
}

fn loaded(dir: &str, fsp: FsInfo, max: i64) -> MountPoint {
	MountPoint {
		dir: dir.into(),
		max_blocks_needed: max,
		fsinfo: FsInfoState::Loaded,
		fsp,
		..Default::default()
	}
}

fn too_full(mp: &MountPoint) -> (bool, Rec) {
	let mut ev = Rec::default();
	(check_mountpoint(mp, &mut ev), ev)
}

#[test]
fn cushion_five_percent_or_twenty_mib() {
	// 5%: 1000 / 20 + 1 = 51 blocks, 20 MiB of 4 KiB = 5121
	let (full, ev) = too_full(&loaded("/m", fs(4096, 1000, 100), 49));
	assert!(!full);
	assert_eq!(
		ev.0,
		[Ev::Log(
			LogLevel::Debug,
			"partition /m, needed 49, cushion 51, free 100\n"
				.into()
		)]
	);
	let (full, ev) = too_full(&loaded("/m", fs(4096, 1000, 100), 50));
	assert!(full);
	assert_eq!(
		ev.errors(),
		["Partition /m too full: 101 blocks needed, 100 blocks free\n"]
	);
	// big disk: 20 MiB wins
	let big = fs(4096, 1 << 30, 10_000);
	assert!(!too_full(&loaded("/m", big, 10_000 - 5121)).0);
	assert!(too_full(&loaded("/m", big, 10_000 - 5120)).0);
	// 1 KiB blocks: 20481
	let small = fs(1024, 1 << 30, 30_000);
	assert!(!too_full(&loaded("/m", small, 30_000 - 20481)).0);
	assert!(too_full(&loaded("/m", small, 30_000 - 20480)).0);
	// freed space (negative need) never fails
	assert!(!too_full(&loaded("/m", fs(4096, 0, 0), -2)).0);
	assert!(too_full(&loaded("/m", fs(4096, 0, 0), 0)).0);
	// a sum wrapping negative is not checked
	assert!(!too_full(&loaded("/m", fs(4096, 0, 0), i64::MAX)).0);
	// bsize 0: no division, cushion is the 5% term
	let (_, ev) = too_full(&loaded("/m", fs(0, 400, 1000), 1));
	assert_eq!(
		ev.0[0],
		Ev::Log(
			LogLevel::Debug,
			"partition /m, needed 1, cushion 21, free 1000\n"
				.into()
		)
	);
}

// a fixture dir in /tmp with root/ and db/, removed on drop
struct Tmp(PathBuf);

impl Tmp {
	fn new(tag: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"alpm-diskspace-{tag}-{}",
			std::process::id()
		));
		if dir.exists() {
			fs::remove_dir_all(&dir).unwrap();
		}
		fs::create_dir_all(dir.join("root")).unwrap();
		fs::create_dir_all(dir.join("db")).unwrap();
		Tmp(dir.canonicalize().unwrap())
	}

	fn handle(&self) -> Handle {
		let p = |s| self.0.join(s).as_os_str().as_bytes().to_vec();
		Handle::initialize(&p("root"), &p("db")).unwrap()
	}

	fn root(&self) -> String {
		format!("{}/root", self.0.display())
	}
}

impl Drop for Tmp {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn file(name: &str, size: i64, mode: u32) -> File {
	File::new(name.into(), size, mode)
}

fn files(list: &[File]) -> FileList {
	FileList {
		files: list.to_vec(),
	}
}

// root on its own synthetic mount, with usr/ on another
fn fake_for(tmp: &Tmp, root: FsInfo, usr: FsInfo) -> Fake {
	let r = tmp.root();
	let table = format!("a / x\nb {r} x\nc {r}/usr x\n");
	Fake {
		table: Ok(table.into_bytes()),
		fs: vec![
			(r.clone().into_bytes(), Ok(root)),
			(format!("{r}/usr").into_bytes(), Ok(usr)),
		],
		stats: 0,
	}
}

#[test]
fn installed_blocks_round_up() {
	let tmp = Tmp::new("inst");
	let h = tmp.handle();
	let mut f = fake_for(&tmp, fs(4096, 1000, 1000), fs(512, 10, 10));
	let mut ev = Rec::default();
	let mut m = mount_point_list(&mut f, &mut ev);
	let list = files(&[
		file("a", 0, 0o100644),
		file("b", 1, 0o100644),
		file("c", 4096, 0o100644),
		file("d", 4097, 0o100644),
		file("dir/", 99999, 0o040755),
		file("link", 99999, 0o120777),
		file("usr/x", 513, 0o100644),
		// counts on dbpath joined to the root, the root mount here
		file(".PKGINFO", 1, 0o100644),
	]);
	calculate_installed_size(&h, &mut m, &list, &mut f, &mut ev);
	let get = |d: String| m.iter().find(|x| x.dir == d.as_bytes()).unwrap();
	let root = get(tmp.root());
	assert_eq!(root.blocks_needed, 1 + 1 + 2 + 1);
	assert_eq!(root.used, USED_INSTALL);
	assert_eq!(get(format!("{}/usr", tmp.root())).blocks_needed, 2);
	assert_eq!(get("/".into()).used, 0);
	assert_eq!(f.stats, 2, "one statvfs per mount");
}

#[test]
fn removed_blocks_from_lstat() {
	let tmp = Tmp::new("rm");
	let r = tmp.root();
	fs::create_dir_all(format!("{r}/usr/d")).unwrap();
	fs::File::create(format!("{r}/f1"))
		.unwrap()
		.set_len(4097)
		.unwrap();
	fs::File::create(format!("{r}/usr/f2"))
		.unwrap()
		.set_len(512)
		.unwrap();
	std::os::unix::fs::symlink("f1", format!("{r}/ln")).unwrap();
	let mut h = tmp.handle();
	h.add_noextract(b"quiet*");
	let mut f = fake_for(&tmp, fs(4096, 1000, 1000), fs(512, 10, 10));
	let mut ev = Rec::default();
	let mut m = mount_point_list(&mut f, &mut ev);
	ev.0.clear();
	let list = files(&[
		file("f1", 0, 0),
		file("f1/", 0, 0),
		file("usr/", 0, 0),
		file("usr/d/", 0, 0),
		file("usr/f2", 0, 0),
		file("ln", 0, 0),
		file("missing", 0, 0),
		file("quiet-missing", 0, 0),
	]);
	calculate_removed_size(&h, &mut m, &list, &mut f, &mut ev);
	let root = m.iter().find(|x| x.dir == r.as_bytes()).unwrap();
	// f1 twice (trailing '/' stripped by llstat)
	assert_eq!(root.blocks_needed, -4);
	assert_eq!(root.used, USED_REMOVE);
	let usr = format!("{r}/usr");
	let usr = m.iter().find(|x| x.dir == usr.as_bytes()).unwrap();
	assert_eq!(usr.blocks_needed, -1);
	let warn: Vec<&Ev> =
		ev.0.iter()
			.filter(|e| matches!(e, Ev::Log(LogLevel::Warning, _)))
			.collect();
	assert_eq!(
		warn,
		[&Ev::Log(
			LogLevel::Warning,
			"could not get file information for missing\n".into()
		)]
	);
}

#[test]
fn statvfs_failure_skips_mount() {
	let tmp = Tmp::new("fail");
	let h = tmp.handle();
	let mut f = fake_for(&tmp, fs(4096, 1000, 1000), fs(512, 10, 10));
	f.fs.clear();
	let mut ev = Rec::default();
	let mut m = mount_point_list(&mut f, &mut ev);
	ev.0.clear();
	let list = files(&[file("a", 1, 0), file("b", 1, 0)]);
	calculate_installed_size(&h, &mut m, &list, &mut f, &mut ev);
	assert_eq!(f.stats, 1, "a failed mount is not retried");
	let msg = format!(
		"could not get filesystem information for {}: \
		No such file or directory\n",
		tmp.root()
	);
	assert_eq!(ev.0, [Ev::Log(LogLevel::Warning, msg)]);
	assert!(m.iter().all(|x| x.used == 0));
	assert!(m.iter().any(|x| x.fsinfo == FsInfoState::Failed));
}

#[test]
fn diskspace_read_only_and_full() {
	let tmp = Tmp::new("check");
	let mut h = tmp.handle();
	let mut ro = fs(4096, 1000, 1000);
	ro.read_only = true;
	let mut f = fake_for(&tmp, fs(4096, 1000, 100), ro);
	let pkg = Package {
		name: Some(b"p"[..].into()),
		files: files(&[file("usr/x", 1, 0), file("big", 49 * 4096, 0)]),
		..Default::default()
	};
	let mut ev = Rec::default();
	let r = check_diskspace(
		&mut h,
		std::slice::from_ref(&pkg),
		&[],
		&mut f,
		&mut ev,
	);
	assert_eq!(r, Err(SpaceError::DiskSpace));
	assert_eq!(r.unwrap_err().errno(), Some(Errno::DiskSpace));
	let usr = format!("{}/usr", tmp.root());
	assert_eq!(
		ev.errors(),
		[format!("Partition {usr} is mounted read only\n")]
	);
	// 49 + cushion 51 = 100 fits, 50 does not
	let mut f = fake_for(&tmp, fs(4096, 1000, 100), fs(4096, 1000, 1000));
	let mut ev = Rec::default();
	assert_eq!(
		check_diskspace(&mut h, &[pkg], &[], &mut f, &mut ev),
		Ok(())
	);
	let pkg = Package {
		name: Some(b"p"[..].into()),
		files: files(&[file("big", 50 * 4096, 0)]),
		..Default::default()
	};
	let mut ev = Rec::default();
	let r = check_diskspace(&mut h, &[pkg], &[], &mut f, &mut ev);
	assert_eq!(r, Err(SpaceError::DiskSpace));
	assert_eq!(
		ev.errors(),
		[format!(
			"Partition {} too full: 101 blocks needed, 100 blocks free\n",
			tmp.root()
		)]
	);
}

#[test]
fn diskspace_removal_only_on_read_only() {
	// a read-only mount only touched by removals still fails
	let tmp = Tmp::new("rmro");
	let r = tmp.root();
	fs::create_dir_all(format!("{r}/usr")).unwrap();
	fs::write(format!("{r}/usr/f"), b"x").unwrap();
	let mut h = tmp.handle();
	let mut ro = fs(4096, 1000, 1000);
	ro.read_only = true;
	let mut f = fake_for(&tmp, fs(4096, 1000, 1000), ro);
	let old = Package {
		name: Some(b"old"[..].into()),
		files: files(&[file("usr/f", 0, 0)]),
		..Default::default()
	};
	let mut ev = Rec::default();
	let res = check_diskspace(&mut h, &[], &[old], &mut f, &mut ev);
	assert_eq!(res, Err(SpaceError::DiskSpace));
	let p: Vec<&Ev> =
		ev.0.iter()
			.filter(|e| matches!(e, Ev::Progress(..)))
			.collect();
	assert_eq!(p, [&Ev::Progress(0, 1, 0), &Ev::Progress(100, 1, 1)]);
}

#[test]
fn diskspace_progress_and_max() {
	let tmp = Tmp::new("prog");
	let mut h = tmp.handle();
	let mut f = fake_for(&tmp, fs(4096, 1000, 1000), fs(4096, 1000, 1000));
	let pkg = |n: &str, size| Package {
		name: Some(n.as_bytes().into()),
		files: files(&[file("f", size, 0)]),
		..Default::default()
	};
	let add = [pkg("a", 4096 * 3), pkg("b", 0), pkg("c", 4096)];
	let mut ev = Rec::default();
	assert_eq!(check_diskspace(&mut h, &add, &[], &mut f, &mut ev), Ok(()));
	let p: Vec<&Ev> =
		ev.0.iter()
			.filter(|e| matches!(e, Ev::Progress(..)))
			.collect();
	assert_eq!(
		p,
		[
			&Ev::Progress(0, 3, 0),
			&Ev::Progress(33, 3, 1),
			&Ev::Progress(66, 3, 2),
			&Ev::Progress(100, 3, 3),
		]
	);
	let r = tmp.root();
	let want = format!("partition {r}, needed 4, cushion 51, free 1000\n");
	assert!(ev.0.contains(&Ev::Log(LogLevel::Debug, want)), "{:?}", ev.0);
}

#[test]
fn diskspace_root_without_mount() {
	let tmp = Tmp::new("noroot");
	let mut h = tmp.handle();
	let mut f = Fake {
		table: Ok(b"a /elsewhere x\n".to_vec()),
		fs: Vec::new(),
		stats: 0,
	};
	let mut ev = Rec::default();
	let r = check_diskspace(&mut h, &[], &[], &mut f, &mut ev);
	assert_eq!(r, Err(SpaceError::DiskSpace));
	let root = format!("{}/", tmp.root());
	assert_eq!(
		ev.errors(),
		[format!("could not determine root mount point {root}\n")]
	);
}

#[test]
fn downloadspace_rounding() {
	let mut f = Fake {
		table: Ok(b"a / x\nb /cache x\n".to_vec()),
		fs: vec![(b"/cache".to_vec(), Ok(fs(4096, 1000, 100)))],
		stats: 0,
	};
	// (size + bsize + 1) / bsize: 0 -> 1, 4094 -> 1, 4095 -> 2
	let run = |f: &mut Fake, sizes: &[i64]| {
		let mut ev = Rec::default();
		let r = check_downloadspace(b"/cache/pkg", sizes, f, &mut ev);
		(r, ev)
	};
	let (r, ev) = run(&mut f, &[0, 4094, 4095]);
	assert_eq!(r, Ok(()));
	let want = "partition /cache, needed 4, cushion 51, free 100\n";
	assert!(ev.0.contains(&Ev::Log(LogLevel::Debug, want.into())));
	// 49 blocks + 51 = 100 fits
	let (r, _) = run(&mut f, &[49 * 4096 - 2]);
	assert_eq!(r, Ok(()));
	let (r, ev) = run(&mut f, &[49 * 4096 - 1]);
	assert_eq!(r, Err(SpaceError::DiskSpace));
	assert_eq!(
		ev.errors(),
		[
			"Partition /cache too full: 101 blocks needed, 100 blocks free\n"
		]
	);
	let (r, ev) = run(&mut f, &[]);
	assert_eq!(r, Ok(()));
	assert!(ev.0.contains(&Ev::Log(
		LogLevel::Debug,
		"partition /cache, needed 0, cushion 51, free 100\n".into()
	)));
	// no mount for a relative path, statvfs failure
	let mut ev = Rec::default();
	let r = check_downloadspace(b"rel/x", &[1], &mut f, &mut ev);
	assert_eq!(r, Err(SpaceError::DiskSpace));
	assert_eq!(
		ev.errors(),
		["could not determine cachedir mount point rel/x\n"]
	);
	let mut ev = Rec::default();
	let r = check_downloadspace(b"/nonexistent/x", &[1], &mut f, &mut ev);
	assert_eq!(r, Err(SpaceError::DiskSpace));
	assert!(matches!(&ev.0.last(), Some(Ev::Log(LogLevel::Warning, _))));
}

#[test]
fn load_fsinfo_sets_read_only() {
	let mut ro = fs(4096, 1, 1);
	ro.read_only = true;
	let mut f = Fake {
		table: Ok(Vec::new()),
		fs: vec![(b"/r".to_vec(), Ok(ro))],
		stats: 0,
	};
	let mut mp = MountPoint::new(b"/r");
	let mut ev = Rec::default();
	assert!(load_fsinfo(&mut mp, &mut f, &mut ev));
	assert!(mp.read_only);
	assert_eq!(mp.fsinfo, FsInfoState::Loaded);
	assert_eq!(
		ev.0,
		[Ev::Log(LogLevel::Debug, "loading fsinfo for /r\n".into())]
	);
}

// read only against the running system
#[test]
fn system_mounts() {
	let mut ev = Rec::default();
	let mut m = mount_point_list(&mut System, &mut ev);
	assert!(!m.is_empty(), "{:?}", ev.0);
	let tmp = std::env::temp_dir().canonicalize().unwrap();
	let i = match_mount_point(&m, tmp.as_os_str().as_bytes()).unwrap();
	assert!(load_fsinfo(&mut m[i], &mut System, &mut ev), "{:?}", ev.0);
	assert!(m[i].fsp.bsize > 0);
	let tmp = tmp.as_os_str().as_bytes().to_vec();
	let r = check_downloadspace(
		&tmp,
		&[0],
		&mut System,
		&mut Rec::default(),
	);
	assert!(r.is_ok() || r == Err(SpaceError::DiskSpace));
}
