// port of the scriptlet part of lib/libalpm/trans.c: _alpm_runscriptlet
// and its grep helper. the transaction itself is a separate unit; root
// and the handle callbacks come in as parameters.

use std::collections::hash_map::RandomState;
use std::fs::{self, DirBuilder, File};
use std::hash::{BuildHasher, Hasher};
use std::io::{BufReader, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use pacman_common::util_common::safe_fgets;
use rustix::fs::{Access, AtFlags, CWD, accessat};

use crate::deps::LogLevel;
use crate::util::{
	ChrootCb, SCRIPTLET_SHELL, copyfile, makepath_mode, run_chroot,
	strerror, unpack_single, until_nul,
};

// limits.h on linux
const PATH_MAX: usize = 4096;

fn os(path: &[u8]) -> &Path {
	Path::new(std::ffi::OsStr::from_bytes(until_nul(path)))
}

fn logv(cb: &mut impl ChrootCb, level: LogLevel, parts: &[&[u8]]) {
	cb.log(level, &parts.concat());
}

// grep (static in C): needle in a chunk of the file read like
// safe_fgets(line, 1024), cut at its first nul and first '#'. a needle
// split over two chunks is missed like in the C. a read error ends the
// search (the C's feof loop would spin on it)
fn grep(path: &[u8], needle: &[u8]) -> bool {
	let Ok(f) = File::open(os(path)) else {
		return false;
	};
	let needle = until_nul(needle);
	let mut r = BufReader::new(f);
	while let Ok(Some(chunk)) = safe_fgets(&mut r, 1024) {
		let line = until_nul(&chunk);
		let line = match line.iter().position(|&c| c == b'#') {
			Some(i) => &line[..i],
			None => line,
		};
		if needle.is_empty()
			|| line.windows(needle.len()).any(|w| w == needle)
		{
			return true;
		}
	}
	false
}

// mkdtemp(3): template ending in "XXXXXX", made mode 0700 with the X's
// replaced by letters and digits, retried while the name exists
fn mkdtemp(template: &[u8]) -> Option<Vec<u8>> {
	const CHARS: &[u8] =
		b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	let stem = template.strip_suffix(b"XXXXXX")?;
	// glibc's TMP_MAX attempts
	for _ in 0..238_328 {
		let mut h = RandomState::new().build_hasher();
		h.write(stem);
		let mut v = h.finish();
		let mut path = stem.to_vec();
		for _ in 0..6 {
			path.push(CHARS[(v % CHARS.len() as u64) as usize]);
			v /= CHARS.len() as u64;
		}
		match DirBuilder::new().mode(0o700).create(os(&path)) {
			Ok(()) => return Some(path),
			Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
			Err(_) => return None,
		}
	}
	None
}

// "is not readable" debug line of _alpm_access with a NULL dir
fn readable(path: &[u8], cb: &mut impl ChrootCb) -> bool {
	let flags = AtFlags::SYMLINK_NOFOLLOW;
	let Err(e) = accessat(CWD, os(path), Access::READ_OK, flags) else {
		return true;
	};
	let e = strerror(&e.into());
	logv(
		cb,
		LogLevel::Debug,
		&[b"\"", path, b"\" is not readable: ", &e, b"\n"],
	);
	false
}

// _alpm_runscriptlet: runs `. <copy>; <script> <ver> [<oldver>]` with
// SCRIPTLET_SHELL -c under root (with its trailing '/'), the copy being
// filepath (or its .INSTALL entry when is_archive) placed in a fresh
// root/tmp/alpm_XXXXXX. a missing filepath or a script name that does
// not appear in it runs nothing. true unless something failed (C 0)
pub fn runscriptlet(
	root: &[u8],
	filepath: &[u8],
	script: &[u8],
	ver: &[u8],
	oldver: Option<&[u8]>,
	is_archive: bool,
	cb: &mut impl ChrootCb,
) -> bool {
	let (root, filepath) = (until_nul(root), until_nul(filepath));
	let (script, ver) = (until_nul(script), until_nul(ver));
	if !readable(filepath, cb) {
		logv(
			cb,
			LogLevel::Debug,
			&[b"scriptlet '", filepath, b"' not found\n"],
		);
		return true;
	}
	// only a plain file can be checked before it is copied
	if !is_archive && !grep(filepath, script) {
		return true;
	}

	let tmp = [root, b"tmp/"].concat();
	if !os(&tmp).exists() {
		let _ = makepath_mode(&tmp, 0o1777);
	}
	let Some(tmpdir) = mkdtemp(&[root, b"tmp/alpm_XXXXXX"].concat()) else {
		cb.log(LogLevel::Error, b"could not create temp directory\n");
		return false;
	};
	let scriptfn = [&tmpdir[..], b"/.INSTALL"].concat();
	let mut ok = if is_archive {
		unpack_single(filepath, &tmpdir, b".INSTALL", cb)
	} else if let Err(e) = copyfile(filepath, &scriptfn) {
		logv(
			cb,
			LogLevel::Error,
			&[
				b"could not copy tempfile to ",
				&scriptfn,
				b" (",
				&strerror(&e),
				b")\n",
			],
		);
		false
	} else {
		true
	};

	if ok && (!is_archive || grep(&scriptfn, script)) {
		// the tmpdir as seen inside the chroot
		let scriptpath = &scriptfn[root.len().saturating_sub(1)..];
		let mut cmdline =
			[b". ", scriptpath, b"; ", script, b" ", ver].concat();
		if let Some(old) = oldver {
			cmdline.extend_from_slice(b" ");
			cmdline.extend_from_slice(until_nul(old));
		}
		// snprintf into char[PATH_MAX]
		cmdline.truncate(PATH_MAX - 1);
		logv(
			cb,
			LogLevel::Debug,
			&[b"executing \"", &cmdline, b"\"\n"],
		);
		let argv: [&[u8]; 3] = [SCRIPTLET_SHELL, b"-c", &cmdline];
		ok = run_chroot(root, Some(SCRIPTLET_SHELL), &argv, None, cb);
	}

	if fs::remove_file(os(&scriptfn)).is_err() {
		logv(
			cb,
			LogLevel::Warning,
			&[b"could not remove ", &scriptfn, b"\n"],
		);
	}
	if fs::remove_dir(os(&tmpdir)).is_err() {
		logv(
			cb,
			LogLevel::Warning,
			&[b"could not remove tmpdir ", &tmpdir, b"\n"],
		);
	}
	ok
}
