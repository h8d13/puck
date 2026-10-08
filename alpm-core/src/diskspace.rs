// port of lib/libalpm/diskspace.c, the linux branch: getmntent(3) over
// MOUNTED, statvfs(3) per mount point loaded lazily, block accounting of
// a transaction and of downloads.
//
// the mount table and statvfs come through Mounts (System reads
// /etc/mtab and calls rustix statvfs), _alpm_log and PROGRESS through
// Callbacks (progress is ALPM_PROGRESS_DISKSPACE_START with an empty
// package name). the transaction is passed as its add/remove package
// lists, the handle gives root, dbpath, noextract and the local db for
// upgrades.
// pm_errno is not modelled, see SpaceError. getmntent is reimplemented
// on the bytes of the table (glibc misc/mntent_r.c, getmntent's 4096
// byte line buffer); mnt_freq/mnt_passno are not parsed, nothing here
// reads them.

use std::ffi::{OsStr, c_int};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use rustix::fs::StatVfsMountFlags;

use crate::be_local::INFRQ_FILES;
use crate::callbacks::{Callbacks, LogLevel, Progress};
use crate::error::Errno;
use crate::filelist::FileList;
use crate::handle::Handle;
use crate::package::Package;
use crate::util::{llstat, strerror, until_nul};

const DISKSPACE: Progress = Progress::DiskspaceStart;

// _PATH_MOUNTED, what setmntent(MOUNTED, "r") opens
pub const MOUNTED: &[u8] = b"/etc/mtab";
// limits.h, the char path[PATH_MAX] buffers
const PATH_MAX: usize = 4096;
// getmntent's static line buffer, BUFFER_SIZE in glibc misc/mntent.c
const MNT_BUFSIZ: usize = 4096;
// char tmp[1024] get_mnt_entry drains the rest of a long line with
const MNT_DRAIN: usize = 1024;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

// enum mount_used_level bits of MountPoint::used
pub const USED_REMOVE: u8 = 1;
pub const USED_INSTALL: u8 = 1 << 1;

// the fields of struct statvfs diskspace.c reads: f_bsize, f_blocks,
// f_bavail and f_flag & ST_RDONLY
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsInfo {
	pub bsize: u64,
	pub blocks: u64,
	pub bavail: u64,
	pub read_only: bool,
}

// where the mount table and filesystem usage come from
pub trait Mounts {
	// the whole stream getmntent reads, Err when setmntent cannot open it
	fn table(&mut self) -> io::Result<Vec<u8>>;
	// statvfs(dir)
	fn statvfs(&mut self, dir: &[u8]) -> io::Result<FsInfo>;
}

// the running system: MOUNTED and statvfs(2) through rustix
pub struct System;

impl Mounts for System {
	// a read error ends the table like getmntent's NULL, what was read
	// stays (read_to_end keeps it)
	fn table(&mut self) -> io::Result<Vec<u8>> {
		let mut f = File::open(OsStr::from_bytes(MOUNTED))?;
		let mut buf = Vec::new();
		let _ = f.read_to_end(&mut buf);
		Ok(buf)
	}

	fn statvfs(&mut self, dir: &[u8]) -> io::Result<FsInfo> {
		let st = rustix::fs::statvfs(OsStr::from_bytes(dir))?;
		Ok(FsInfo {
			bsize: st.f_bsize,
			blocks: st.f_blocks,
			bavail: st.f_bavail,
			read_only: st
				.f_flag
				.contains(StatVfsMountFlags::RDONLY),
		})
	}
}

// struct mntent without mnt_freq/mnt_passno, fields decoded
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountEntry {
	pub fsname: Vec<u8>,
	pub dir: Vec<u8>,
	pub kind: Vec<u8>,
	pub opts: Vec<u8>,
}

// fgets(3) into a buffer of size bytes, reading data from *pos: at most
// size - 1 bytes, up to and including the first '\n'. None at the end
fn fgets<'a>(data: &'a [u8], pos: &mut usize, size: usize) -> Option<&'a [u8]> {
	let rest = data.get(*pos..).filter(|r| !r.is_empty())?;
	let max = rest.len().min(size - 1);
	let n = rest[..max]
		.iter()
		.position(|&c| c == b'\n')
		.map_or(max, |i| i + 1);
	*pos += n;
	Some(&rest[..n])
}

fn is_blank(c: &u8) -> bool {
	matches!(c, b' ' | b'\t')
}

// head + strspn(head, " \t")
fn skip_blank(s: &[u8]) -> &[u8] {
	&s[s.iter().take_while(|c| is_blank(c)).count()..]
}

// get_mnt_entry's line loop: the next line that is neither blank nor a
// comment, as the C string the parser sees (cut at the first nul,
// newline and the blanks before it trimmed, leading blanks skipped)
fn next_line<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
	loop {
		let line = until_nul(fgets(data, pos, MNT_BUFSIZ)?);
		let line = match line.iter().position(|&c| c == b'\n') {
			Some(end) => {
				let line = &line[..end];
				let blanks = line
					.iter()
					.rev()
					.take_while(|c| is_blank(c));
				&line[..line.len() - blanks.count()]
			}
			// no newline before the first nul (long line, nul byte,
			// eof): the stream is drained up to the next chunk whose
			// C string holds a newline, the buffer kept untrimmed
			None => {
				while let Some(t) = fgets(data, pos, MNT_DRAIN)
				{
					if until_nul(t).contains(&b'\n') {
						break;
					}
				}
				line
			}
		};
		let head = skip_blank(line);
		if !matches!(head.first(), None | Some(b'#')) {
			return Some(head);
		}
	}
}

// decode_name: \040 \011 \012 \134 and \\, tried in that order, other
// backslashes stay
fn decode_name(s: &[u8]) -> Vec<u8> {
	const ESC: [(&[u8], u8); 5] = [
		(b"\\040", b' '),
		(b"\\011", b'\t'),
		(b"\\012", b'\n'),
		(b"\\\\", b'\\'),
		(b"\\134", b'\\'),
	];
	let mut out = Vec::with_capacity(s.len());
	let mut i = 0;
	while i < s.len() {
		let esc = ESC.iter().find(|(seq, _)| s[i..].starts_with(seq));
		let (c, n) = esc.map_or((s[i], 1), |(seq, c)| (*c, seq.len()));
		out.push(c);
		i += n;
	}
	out
}

// strsep(&head, " \t"), then head += strspn(head, " \t"). a NULL head
// gives "" like the C's (char *) ""
fn next_field(head: &mut Option<&[u8]>) -> Vec<u8> {
	let Some(h) = *head else {
		return Vec::new();
	};
	match h.iter().position(is_blank) {
		Some(i) => {
			*head = Some(skip_blank(&h[i + 1..]));
			decode_name(&h[..i])
		}
		None => {
			*head = None;
			decode_name(h)
		}
	}
}

// hasmntopt(3): opt as a whole comma separated option, alone or followed
// by '='. after a miss the search goes on past the next ',' from the
// candidate
fn has_mnt_opt(opts: &[u8], opt: &[u8]) -> bool {
	let find = |from: usize| {
		opts[from..]
			.windows(opt.len())
			.position(|w| w == opt)
			.map(|i| from + i)
	};
	let mut rest = 0;
	while let Some(p) = find(rest) {
		let start = p == rest || opts[p - 1] == b',';
		let end = opts.get(p + opt.len());
		if start && matches!(end, None | Some(b'=' | b',')) {
			return true;
		}
		match opts[p..].iter().position(|&c| c == b',') {
			Some(i) => rest = p + i + 1,
			None => break,
		}
	}
	false
}

// every entry getmntent(3) returns for this stream. autofs entries with
// an "ignore" option are skipped like glibc does
pub fn parse_mntent(table: &[u8]) -> Vec<MountEntry> {
	let mut pos = 0;
	let mut out = Vec::new();
	while let Some(line) = next_line(table, &mut pos) {
		let mut head = Some(line);
		// fields are read in declaration order
		let e = MountEntry {
			fsname: next_field(&mut head),
			dir: next_field(&mut head),
			kind: next_field(&mut head),
			opts: next_field(&mut head),
		};
		if e.kind == b"autofs" && has_mnt_opt(&e.opts, b"ignore") {
			continue;
		}
		out.push(e);
	}
	out
}

// enum mount_fsinfo
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FsInfoState {
	#[default]
	Unloaded,
	Loaded,
	Failed,
}

// alpm_mountpoint_t, mount_dir_len is dir.len()
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountPoint {
	pub dir: Vec<u8>,
	pub blocks_needed: i64,
	pub max_blocks_needed: i64,
	// USED_* bits
	pub used: u8,
	pub read_only: bool,
	pub fsinfo: FsInfoState,
	pub fsp: FsInfo,
}

impl MountPoint {
	pub fn new(dir: &[u8]) -> Self {
		MountPoint {
			dir: dir.to_vec(),
			..Default::default()
		}
	}
}

// why a check failed
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpaceError {
	// no mount points: the C returns -1, pm_errno untouched
	MountPoints,
	// ALPM_ERR_DISK_SPACE
	DiskSpace,
}

impl SpaceError {
	// the pm_errno the C sets, None where it leaves it alone
	pub fn errno(self) -> Option<Errno> {
		match self {
			SpaceError::MountPoints => None,
			SpaceError::DiskSpace => Some(Errno::DiskSpace),
		}
	}
}

// snprintf(path, PATH_MAX, "%s%s", a, b): cut to PATH_MAX - 1 bytes
fn join_path(a: &[u8], b: &[u8]) -> Vec<u8> {
	let mut p = [until_nul(a), until_nul(b)].concat();
	p.truncate(PATH_MAX - 1);
	p
}

// (size + bsize - 1) / bsize in unsigned long, stored in a blkcnt_t. the
// C divides by zero for bsize 0, 0 blocks here
fn ceil_blocks(size: i64, bsize: u64) -> i64 {
	let n = (size as u64).wrapping_add(bsize).wrapping_sub(1);
	n.checked_div(bsize).unwrap_or(0) as i64
}

// mount_point_load_fsinfo: false (C -1) when statvfs fails, the mount is
// then marked Failed
pub fn load_fsinfo(
	mp: &mut MountPoint,
	mounts: &mut impl Mounts,
	ev: &mut dyn Callbacks,
) -> bool {
	match mounts.statvfs(&mp.dir) {
		Err(e) => {
			let msg = [
				b"could not get filesystem information for ",
				&mp.dir[..],
				b": ",
				&strerror(&e),
				b"\n",
			];
			ev.log(LogLevel::Warning, &msg.concat());
			mp.fsinfo = FsInfoState::Failed;
			false
		}
		Ok(fs) => {
			let msg = [b"loading fsinfo for ", &mp.dir[..], b"\n"];
			ev.log(LogLevel::Debug, &msg.concat());
			mp.read_only = fs.read_only;
			mp.fsp = fs;
			mp.fsinfo = FsInfoState::Loaded;
			true
		}
	}
}

// mount_point_list: the table's mount dirs, fsinfo unloaded, sorted so
// every mount comes before its parent. empty when the table cannot be
// opened or has no entries (the C's NULL list)
pub fn mount_point_list(
	mounts: &mut impl Mounts,
	ev: &mut dyn Callbacks,
) -> Vec<MountPoint> {
	let table = match mounts.table() {
		Ok(t) => t,
		Err(e) => {
			let msg = [
				b"could not open file: ",
				MOUNTED,
				b": ",
				&strerror(&e),
				b"\n",
			];
			ev.log(LogLevel::Error, &msg.concat());
			return Vec::new();
		}
	};
	let mut mps: Vec<MountPoint> = parse_mntent(&table)
		.into_iter()
		.map(|e| MountPoint::new(&e.dir))
		.collect();
	// mount_point_cmp is -strcmp, alpm_list_msort is stable like sort_by
	mps.sort_by(|a, b| b.dir.cmp(&a.dir));
	for mp in &mps {
		let msg = [b"discovered mountpoint: ", &mp.dir[..], b"\n"];
		ev.log(LogLevel::Debug, &msg.concat());
	}
	mps
}

// match_mount_point: the first mount (in list order) whose dir is a
// prefix of path ending at a '/' of either. the C reads the byte before
// an empty dir, taken as not '/' here
pub fn match_mount_point(mps: &[MountPoint], path: &[u8]) -> Option<usize> {
	let path = until_nul(path);
	mps.iter().position(|mp| {
		let dir = &mp.dir[..];
		path.starts_with(dir)
			&& (dir.last() == Some(&b'/')
				|| matches!(
					path.get(dir.len()),
					None | Some(b'/')
				))
	})
}

// the mount of path with its fsinfo loaded, None when there is none
// (logged with filename) or statvfs fails
fn loaded_mount<'a>(
	mps: &'a mut [MountPoint],
	path: &[u8],
	filename: &[u8],
	mounts: &mut impl Mounts,
	ev: &mut dyn Callbacks,
) -> Option<&'a mut MountPoint> {
	let Some(i) = match_mount_point(mps, path) else {
		let msg = [
			b"could not determine mount point for file ",
			filename,
			b"\n",
		];
		ev.log(LogLevel::Warning, &msg.concat());
		return None;
	};
	let mp = &mut mps[i];
	match mp.fsinfo {
		FsInfoState::Failed => None,
		FsInfoState::Loaded => Some(mp),
		FsInfoState::Unloaded => {
			load_fsinfo(mp, mounts, ev).then_some(mp)
		}
	}
}

// calculate_removed_size: blocks of the listed files present under the
// root (lstat sizes) freed on their mounts. missing files are logged
// unless noextract matches them, directories and symlinks skipped
pub fn calculate_removed_size(
	handle: &Handle,
	mps: &mut [MountPoint],
	files: &FileList,
	mounts: &mut impl Mounts,
	ev: &mut dyn Callbacks,
) {
	for file in &files.files {
		let filename = until_nul(&file.name);
		let path = join_path(handle.root(), filename);
		let Ok(st) = llstat(&path) else {
			// alpm_option_match_noextract is nonzero unless a
			// pattern matches without '!'
			if handle.match_noextract(filename) != Some(false) {
				let msg = [
					b"could not get file information for ",
					filename,
					b"\n",
				];
				ev.log(LogLevel::Warning, &msg.concat());
			}
			continue;
		};
		let ft = st.file_type();
		if ft.is_dir() || ft.is_symlink() {
			continue;
		}
		let Some(mp) = loaded_mount(mps, &path, filename, mounts, ev)
		else {
			continue;
		};
		let size = ceil_blocks(st.len() as i64, mp.fsp.bsize);
		mp.blocks_needed = mp.blocks_needed.wrapping_sub(size);
		mp.used |= USED_REMOVE;
	}
}

// calculate_installed_size: blocks of the file list sizes needed on
// their mounts, directories and symlinks (by mode) skipped. names
// starting with '.' (.PKGINFO, .INSTALL, ...) count on the dbpath, still
// joined to the root like the C
pub fn calculate_installed_size(
	handle: &Handle,
	mps: &mut [MountPoint],
	files: &FileList,
	mounts: &mut impl Mounts,
	ev: &mut dyn Callbacks,
) {
	for file in &files.files {
		let kind = file.mode & S_IFMT;
		if kind == S_IFDIR || kind == S_IFLNK {
			continue;
		}
		let mut filename = until_nul(&file.name);
		if filename.first() == Some(&b'.') {
			filename = handle.dbpath();
		}
		let path = join_path(handle.root(), filename);
		let Some(mp) = loaded_mount(mps, &path, filename, mounts, ev)
		else {
			continue;
		};
		let size = ceil_blocks(file.size, mp.fsp.bsize);
		mp.blocks_needed = mp.blocks_needed.wrapping_add(size);
		mp.used |= USED_INSTALL;
	}
}

// check_mountpoint: true (C 1) when max_blocks_needed plus the cushion,
// min(5% of the blocks, 20 MiB) + 1 block, exceeds f_bavail
pub fn check_mountpoint(mp: &MountPoint, ev: &mut dyn Callbacks) -> bool {
	let fs = &mp.fsp;
	let fivepc = fs.blocks / 20 + 1;
	// bsize 0 divides by zero in the C, no 20 MiB term here
	let twentymb = (20 * 1024 * 1024u64).checked_div(fs.bsize);
	let cushion = twentymb.map_or(fivepc, |t| fivepc.min(t + 1));
	// blkcnt_t + fsblkcnt_t is unsigned, stored back in a blkcnt_t
	let needed = (mp.max_blocks_needed as u64).wrapping_add(cushion) as i64;
	let (dir, max, free) = (&mp.dir[..], mp.max_blocks_needed, fs.bavail);
	let tail = format!(", needed {max}, cushion {cushion}, free {free}\n");
	ev.log(
		LogLevel::Debug,
		&[b"partition ", dir, tail.as_bytes()].concat(),
	);
	if needed >= 0 && needed as u64 > free {
		let tail = format!(
			" too full: {needed} blocks needed, {free} blocks free\n"
		);
		let msg = [b"Partition ", dir, tail.as_bytes()].concat();
		ev.log(LogLevel::Error, &msg);
		return true;
	}
	false
}

// realpath(3) into char[PATH_MAX], None on failure
fn realpath(path: &[u8]) -> Option<Vec<u8>> {
	let real = fs::canonicalize(OsStr::from_bytes(path)).ok()?;
	let real = real.into_os_string().into_vec();
	(real.len() < PATH_MAX).then_some(real)
}

// _alpm_check_downloadspace: the files of file_sizes fit on the mount of
// cachedir (resolved when realpath can, else as given), with the cushion
pub fn check_downloadspace(
	cachedir: &[u8],
	file_sizes: &[i64],
	mounts: &mut impl Mounts,
	ev: &mut dyn Callbacks,
) -> Result<(), SpaceError> {
	let cachedir = until_nul(cachedir);
	let resolved = realpath(cachedir);
	let cachedir = resolved.as_deref().unwrap_or(cachedir);
	let mut mps = mount_point_list(mounts, ev);
	if mps.is_empty() {
		let msg = b"could not determine filesystem mount points\n";
		ev.log(LogLevel::Error, msg);
		return Err(SpaceError::MountPoints);
	}
	let Some(i) = match_mount_point(&mps, cachedir) else {
		let msg = [
			b"could not determine cachedir mount point ",
			cachedir,
			b"\n",
		];
		ev.log(LogLevel::Error, &msg.concat());
		return Err(SpaceError::DiskSpace);
	};
	let mp = &mut mps[i];
	if mp.fsinfo == FsInfoState::Unloaded && !load_fsinfo(mp, mounts, ev) {
		return Err(SpaceError::DiskSpace);
	}
	let bsize = mp.fsp.bsize;
	for &size in file_sizes {
		// (size + bsize + 1) / bsize in unsigned long like the C
		let n = (size as u64).wrapping_add(bsize).wrapping_add(1);
		let blocks = n.checked_div(bsize).unwrap_or(0);
		mp.max_blocks_needed = (mp.max_blocks_needed as u64)
			.wrapping_add(blocks) as i64;
	}
	match check_mountpoint(mp, ev) {
		true => Err(SpaceError::DiskSpace),
		false => Ok(()),
	}
}

// the files of the local package named like pkg, lazily loaded like
// alpm_pkg_get_files on the _alpm_db_get_pkgfromcache result
fn local_files(handle: &mut Handle, pkg: &Package) -> Option<FileList> {
	let dbext = handle.dbext().to_vec();
	let db = handle.localdb_mut()?;
	let local = db.load_pkg(&dbext, pkg.name_bytes(), INFRQ_FILES).ok()?;
	Some(local.files.clone())
}

// _alpm_check_diskspace on trans->add and trans->remove. remove
// packages must have their files loaded (the C getter lazy-loads them),
// the local package an add target replaces is loaded here
pub fn check_diskspace(
	handle: &mut Handle,
	add: &[Package],
	remove: &[Package],
	mounts: &mut impl Mounts,
	ev: &mut dyn Callbacks,
) -> Result<(), SpaceError> {
	let mut numtargs = add.len();
	let mut mps = mount_point_list(mounts, ev);
	if mps.is_empty() {
		let msg = b"could not determine filesystem mount points\n";
		ev.log(LogLevel::Error, msg);
		return Err(SpaceError::MountPoints);
	}
	if match_mount_point(&mps, handle.root()).is_none() {
		let msg = [
			b"could not determine root mount point ",
			handle.root(),
			b"\n",
		];
		ev.log(LogLevel::Error, &msg.concat());
		return Err(SpaceError::DiskSpace);
	}
	numtargs += remove.len();
	let mut current = 0;
	// size_t arithmetic, the result fits an int
	let percent = |current: usize| (current * 100 / numtargs) as c_int;
	for pkg in remove {
		ev.progress(
			DISKSPACE,
			b"",
			percent(current),
			numtargs,
			current,
		);
		calculate_removed_size(
			handle, &mut mps, &pkg.files, mounts, ev,
		);
		current += 1;
	}
	for pkg in add {
		ev.progress(
			DISKSPACE,
			b"",
			percent(current),
			numtargs,
			current,
		);
		if let Some(files) = local_files(handle, pkg) {
			calculate_removed_size(
				handle, &mut mps, &files, mounts, ev,
			);
		}
		calculate_installed_size(
			handle, &mut mps, &pkg.files, mounts, ev,
		);
		for mp in &mut mps {
			mp.max_blocks_needed =
				mp.max_blocks_needed.max(mp.blocks_needed);
		}
		current += 1;
	}
	ev.progress(DISKSPACE, b"", 100, numtargs, current);
	let mut error = false;
	for mp in &mps {
		if mp.used != 0 && mp.read_only {
			let msg = [
				b"Partition ",
				&mp.dir[..],
				b" is mounted read only\n",
			];
			ev.log(LogLevel::Error, &msg.concat());
			error = true;
		} else if mp.used & USED_INSTALL != 0
			&& check_mountpoint(mp, ev)
		{
			error = true;
		}
	}
	match error {
		true => Err(SpaceError::DiskSpace),
		false => Ok(()),
	}
}
