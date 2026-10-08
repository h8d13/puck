// port of src/pacman/query.c: -Q and its options (-Qi/-Qii, -Ql, -Qo,
// -Qs, -Qg, -Qc, -Qk/-Qkk, -Qp), the -Qd/-Qe/-Qm/-Qn/-Qt/-Qtt/-Qu
// filters and -q
//
// config->handle is the Handle passed in, its local and sync dbs answer
// what the C asks libalpm. a local package is cloned out of the db cache
// and reloaded in place where a getter the C calls on it (desc, files,
// scriptlet) lazy-loads, so filters and displays can walk the caches
// again (requiredby, sync lookups) while it is shown. stdout and stderr
// go into an Output like check.rs, pm_printf filtered by the config's
// logmask. getcols() and getenv("PATH") come in through QueryEnv.
// messages are the untranslated msgids.
//
// libalpm's log lines (lazy-load errors, debug lines) go to the handle's
// callbacks, which print at once. the C's stderr is unbuffered, so the
// Output is flushed before every load and at each package or target:
// the op's lines and the callbacks' come out in the C's order.
use std::ffi::{OsStr, c_int};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::ops::ControlFlow;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use alpm_core::backup::Backup;
use alpm_core::be_local::{
	INFRQ_DESC, INFRQ_FILES, INFRQ_SCRIPTLET, MtreeEntry, MtreeError,
};
use alpm_core::be_package::{self, pkg_load_level};
use alpm_core::db::{DB_USAGE_UPGRADE, Db};
use alpm_core::deps::depcmp_literal;
use alpm_core::error::Errno;
use alpm_core::filelist;
use alpm_core::handle::Handle;
use alpm_core::package::{
	DbCaches, Package, PkgFrom, PkgReason, compute_optionalfor,
	compute_requiredby, pkg_should_ignore,
};
use alpm_core::signing::{self, pkg_check_pgp_signature};
use alpm_core::sync::sync_get_new_version;
use alpm_core::util::{compute_md5sum, fnmatch, until_nul};
use pacman_common::util_common::{PATH_MAX, mbasename, mdirname};

use crate::check::{CheckEnv, check_pkg_fast, check_pkg_full, is_backup};
use crate::conf::{Config, LOG_ERROR, LOG_WARNING, cat};
use crate::package::{
	FileProbe, PkgEnv, dump_pkg_changelog, dump_pkg_files, dump_pkg_full,
	dump_pkg_search,
};
use crate::pacman::{PKG_LOCALITY_FOREIGN, PKG_LOCALITY_NATIVE};
use crate::util::{
	Output, SigResult, SigStatus, SigValidity, check_syncdbs, pm_printf,
};
const LOCAL_PREFIX: &[u8] = b"local/";
// fcntl.h on linux: the access(R_OK) probes open without blocking on a
// fifo
const O_NONBLOCK: i32 = 0o4000;

// what query.c reads from the process
#[derive(Clone, Debug, Default)]
pub struct QueryEnv {
	// getcols()
	pub cols: u16,
	// getenv("PATH"), None when unset
	pub path: Option<Vec<u8>>,
}

fn os(path: &[u8]) -> &Path {
	Path::new(OsStr::from_bytes(path))
}

// open(O_RDONLY) for access(path, R_OK): same permission check
fn open_read(path: &[u8]) -> io::Result<File> {
	OpenOptions::new()
		.read(true)
		.custom_flags(O_NONBLOCK)
		.open(os(path))
}

fn readable(path: &[u8]) -> bool {
	open_read(path).is_ok()
}

fn version(pkg: &Package) -> &[u8] {
	until_nul(pkg.version.as_deref().unwrap_or_default())
}

// the libalpm calls of package.c on config->handle, pos the list position
// of a local package's cache entry. pm_printf output is kept apart and
// appended to stderr after the display, which writes nothing else there
struct Env<'a> {
	handle: &'a mut Handle,
	config: &'a Config,
	pos: Option<usize>,
	err: Vec<u8>,
}

impl Env<'_> {
	// the cache entry with req loaded. the Output was flushed before the
	// display, which only writes stdout and err up to here
	fn loaded(&mut self, req: c_int) -> Option<&Package> {
		let dbs = self.handle.dbs_mut();
		dbs.local?.load_pkg_at(dbs.dbext, dbs.cb, self.pos?, req)
	}
}

impl DbCaches for Env<'_> {
	fn local_cache(&mut self) -> Vec<&Package> {
		self.handle.local_cache()
	}

	fn sync_caches(&mut self) -> Vec<Vec<&Package>> {
		self.handle.sync_caches()
	}
}

impl PkgEnv for Env<'_> {
	// only local and file packages are shown by -Q
	fn db_name(&mut self, pkg: &Package) -> Option<Vec<u8>> {
		match pkg.origin {
			Some(PkgFrom::LocalDb) => Some(b"local".to_vec()),
			_ => None,
		}
	}

	// asked for sync packages only, which -Q never shows
	fn sig_keys(&mut self, _: &Package, _: &[u8]) -> Vec<Vec<u8>> {
		Vec::new()
	}

	// alpm_pkg_check_pgp_signature on the handle's keyring, logging
	// through its callbacks
	fn check_signature(
		&mut self,
		pkg: &Package,
	) -> Result<Vec<SigResult>, Errno> {
		let results = self.handle.with_callbacks(|h, cb| {
			pkg_check_pgp_signature(h.keyring_mut(), cb, pkg)
		})?;
		Ok(results.iter().map(sig_result).collect())
	}

	fn root(&mut self) -> Vec<u8> {
		self.handle.root().to_vec()
	}

	fn probe_file(&mut self, path: &[u8]) -> FileProbe {
		match open_read(path) {
			Ok(_) => FileProbe::Readable(compute_md5sum(path)),
			Err(e) => match e.raw_os_error() {
				// EACCES, ENOENT
				Some(13) => FileProbe::Denied,
				Some(2) => FileProbe::Missing,
				_ => FileProbe::Failed,
			},
		}
	}

	// local: the db's "changelog" file, fread until it fails like the
	// C. file packages: the .CHANGELOG entry
	fn changelog(&mut self, pkg: &Package) -> Option<Vec<u8>> {
		match pkg.origin {
			Some(PkgFrom::File(_)) => {
				let cb = self.handle.callbacks();
				be_package::changelog(cb, pkg).ok()
			}
			Some(PkgFrom::LocalDb) => {
				let local = self.handle.localdb()?.local()?;
				let path = local.pkgpath(pkg, b"changelog");
				let mut f = File::open(os(&path)).ok()?;
				let mut log = Vec::new();
				let _ = f.read_to_end(&mut log);
				Some(log)
			}
			_ => None,
		}
	}

	fn error(&mut self, msg: &[u8]) {
		pm_printf(&mut self.err, self.config, LOG_ERROR, msg);
	}

	fn has_scriptlet(&mut self, pkg: &Package) -> bool {
		let p = self.loaded(INFRQ_SCRIPTLET).unwrap_or(pkg);
		p.scriptlet != 0
	}

	fn backup(&mut self, pkg: &Package) -> Vec<Backup> {
		let p = self.loaded(INFRQ_FILES).unwrap_or(pkg);
		p.backup.clone()
	}
}

// the part of an alpm_sigresult_t signature_display reads
fn sig_result(r: &signing::SigResult) -> SigResult {
	use signing::{SigStatus as S, SigValidity as V};
	let status = match r.status {
		S::Valid => SigStatus::Valid,
		S::KeyExpired => SigStatus::KeyExpired,
		S::SigExpired => SigStatus::SigExpired,
		S::KeyUnknown => SigStatus::KeyUnknown,
		S::KeyDisabled => SigStatus::KeyDisabled,
		S::Invalid => SigStatus::Invalid,
	};
	let validity = match r.validity {
		V::Full => SigValidity::Full,
		V::Marginal => SigValidity::Marginal,
		V::Never => SigValidity::Never,
		V::Unknown => SigValidity::Unknown,
	};
	SigResult {
		status,
		validity,
		uid: r.key.uid.clone(),
		fingerprint: r.key.fingerprint.clone().unwrap_or_default(),
	}
}

// check.c on config->handle, pos as in Env. file packages keep libalpm's
// default ops, whose mtree_open returns NULL
struct Checks<'a> {
	handle: &'a mut Handle,
	pos: Option<usize>,
	// alpm_pkg_get_backup once loaded
	backup: Option<Vec<Backup>>,
}

impl CheckEnv for Checks<'_> {
	fn root(&self) -> &[u8] {
		self.handle.root()
	}

	fn dbpath(&self) -> &[u8] {
		self.handle.dbpath()
	}

	fn match_noextract(&self, path: &[u8]) -> Option<bool> {
		self.handle.match_noextract(path)
	}

	// the entry is loaded in place, not copied out like local_at
	// would (every field, every name) per -Qk entry
	fn load_files(&mut self, o: &mut Output, _: &Package) {
		if let Some(i) = self.pos {
			o.flush();
			let dbs = self.handle.dbs_mut();
			if let Some(db) = dbs.local {
				db.load_pkg_at(
					dbs.dbext,
					dbs.cb,
					i,
					INFRQ_FILES,
				);
			}
		}
	}

	// the cache entry load_files loaded, pkg if there is none
	fn files<'a>(&'a self, pkg: &'a Package) -> &'a [filelist::File] {
		let entry = self.pos.and_then(|i| {
			self.handle.localdb()?.loaded_pkgcache()?.at(i)
		});
		&entry.unwrap_or(pkg).files.files
	}

	fn is_backup(
		&mut self,
		o: &mut Output,
		pkg: &Package,
		path: &[u8],
	) -> bool {
		if self.backup.is_none() {
			let loaded = self.pos.and_then(|i| {
				local_at(self.handle, o, i, INFRQ_FILES)
			});
			let p = loaded.as_ref().unwrap_or(pkg);
			self.backup = Some(p.backup.clone());
		}
		is_backup(self.backup.as_deref().unwrap_or_default(), path)
	}

	fn mtree(
		&mut self,
		pkg: &Package,
	) -> Result<Vec<MtreeEntry>, MtreeError> {
		let dbs = self.handle.dbs_mut();
		let local = dbs.local.as_deref().and_then(Db::local);
		match (&pkg.origin, local) {
			(Some(PkgFrom::LocalDb), Some(local)) => {
				local.mtree(pkg, dbs.cb)
			}
			_ => Err(MtreeError::Missing),
		}
	}
}

// a package -Q shows: the copy filter and display read and, for a local
// one, the list position of its cache entry
struct Shown {
	pos: Option<usize>,
	pkg: Package,
}

// the local cache entry at list position i with req loaded, copied out.
// None past the end. the op's output goes out first, the load logs
// through the callbacks
fn local_at(
	handle: &mut Handle,
	o: &mut Output,
	i: usize,
	req: c_int,
) -> Option<Package> {
	o.flush();
	let dbs = handle.dbs_mut();
	dbs.local?.load_pkg_at(dbs.dbext, dbs.cb, i, req).cloned()
}

impl Shown {
	// a getter of req on a local package: the entry loads, the copy
	// follows it
	fn load(&mut self, handle: &mut Handle, o: &mut Output, req: c_int) {
		let pos = self.pos;
		if let Some(pkg) = pos.and_then(|i| local_at(handle, o, i, req))
		{
			self.pkg = pkg;
		}
	}
}

// the loads of find_requiredby on the local cache: every entry's desc in
// list order for its depends, the shown package's own for its provides
// at the first depend it does not match by name and version, at its own
// list position the latest
fn requiredby_loads(handle: &mut Handle, o: &mut Output, s: &mut Shown) {
	let Some(pos) = s.pos else {
		return;
	};
	o.flush();
	let dbs = handle.dbs_mut();
	let Some(db) = dbs.local else {
		return;
	};
	let mut own = false;
	for j in 0.. {
		let Some(p) = db.load_pkg_at(dbs.dbext, dbs.cb, j, INFRQ_DESC)
		else {
			break;
		};
		own |= j == pos;
		if !own && p.depends.iter().any(|d| !depcmp_literal(&s.pkg, d))
		{
			let _ = db.load_pkg_at(
				dbs.dbext, dbs.cb, pos, INFRQ_DESC,
			);
			own = true;
		}
	}
	s.load(handle, o, INFRQ_DESC);
}

// pkg_get_locality: native when a sync db has a package of that name
fn locality(handle: &mut Handle, pkg: &Package) -> u16 {
	let name = pkg.name_bytes();
	let d = handle.dbs_mut();
	let mut dbs = d.sync.iter_mut();
	match dbs.any(|db| db.get_pkg(d.dbext, d.cb, name).is_ok()) {
		true => PKG_LOCALITY_NATIVE,
		false => PKG_LOCALITY_FOREIGN,
	}
}

// is_unrequired: nothing depends on pkg, at level 1 nothing optionally
// either
fn is_unrequired(handle: &mut Handle, pkg: &Package, level: u16) -> bool {
	if !compute_requiredby(pkg, handle).is_empty() {
		return false;
	}
	level != 1 || compute_optionalfor(pkg, handle).is_empty()
}

fn filter(
	c: &Config,
	handle: &mut Handle,
	o: &mut Output,
	s: &mut Shown,
) -> bool {
	// alpm_pkg_get_reason
	if c.op_q_explicit != 0 || c.op_q_deps != 0 {
		s.load(handle, o, INFRQ_DESC);
	}
	if c.op_q_explicit != 0 && s.pkg.reason != PkgReason::Explicit {
		return false;
	}
	if c.op_q_deps != 0 && s.pkg.reason != PkgReason::Depend {
		return false;
	}
	if c.op_q_locality != 0 && c.op_q_locality != locality(handle, &s.pkg) {
		return false;
	}
	if c.op_q_unrequired != 0 {
		requiredby_loads(handle, o, s);
		if !is_unrequired(handle, &s.pkg, c.op_q_unrequired) {
			return false;
		}
	}
	if c.op_q_upgrade != 0 && sync_get_new_version(handle, &s.pkg).is_none()
	{
		return false;
	}
	true
}

// the plain line: "name version", with -Qu " -> newversion" and
// " [ignored]" for an ignored package or a db not used for upgrades
fn plain_line(
	c: &Config,
	handle: &mut Handle,
	o: &mut Output,
	s: &mut Shown,
) -> Vec<u8> {
	let cs = &c.colstr;
	if c.quiet != 0 {
		return cat(&[s.pkg.name_bytes(), b"\n"]);
	}
	let (name, ver) = (s.pkg.name_bytes(), version(&s.pkg));
	let mut out = cat(&[cs.title, name, b" ", cs.version, ver, cs.nocolor]);
	// filter made sure there is a newer version
	if c.op_q_upgrade != 0
		&& let Some((i, newpkg)) = sync_get_new_version(handle, &s.pkg)
	{
		let usage = handle.syncdbs()[i].usage();
		let newver = version(&newpkg);
		out.extend(cat(&[b" -> ", cs.version, newver, cs.nocolor]));
		// alpm_pkg_should_ignore reads the groups of a name IgnorePkg
		// does not match
		let name = s.pkg.name_bytes();
		if !handle.ignorepkgs().iter().any(|p| fnmatch(p, name)) {
			s.load(handle, o, INFRQ_DESC);
		}
		if pkg_should_ignore(handle, &s.pkg)
			|| usage & DB_USAGE_UPGRADE == 0
		{
			out.extend_from_slice(b" [ignored]");
		}
	}
	out.push(b'\n');
	out
}

// display: each part loads what its getters ask for, in the C's order
fn display(
	c: &Config,
	handle: &mut Handle,
	env: &QueryEnv,
	s: &mut Shown,
	o: &mut Output,
) -> i32 {
	let mut ret = 0;
	if c.op_q_info != 0 {
		// alpm_pkg_get_builddate first, scriptlet and backup through
		// Env where dump_pkg_full asks
		s.load(handle, o, INFRQ_DESC);
		let mut penv = Env {
			handle,
			config: c,
			pos: s.pos,
			err: Vec::new(),
		};
		let (extra, out) = (c.op_q_info > 1, &mut o.stdout);
		dump_pkg_full(
			out, &mut penv, &s.pkg, extra, env.cols, &c.colstr,
		);
		o.stderr.append(&mut penv.err);
	}
	if c.op_q_list != 0 {
		s.load(handle, o, INFRQ_FILES);
		let (root, quiet) = (handle.root(), c.quiet != 0);
		dump_pkg_files(&mut o.stdout, &s.pkg, root, quiet, &c.colstr);
	}
	if c.op_q_changelog != 0 {
		let mut penv = Env {
			handle,
			config: c,
			pos: s.pos,
			err: Vec::new(),
		};
		dump_pkg_changelog(&mut o.stdout, &mut penv, &s.pkg);
		o.stderr.append(&mut penv.err);
	}
	if c.op_q_check != 0 {
		// before the mtree open logs
		o.flush();
		let mut checks = Checks {
			handle,
			pos: s.pos,
			backup: None,
		};
		ret = match c.op_q_check {
			1 => check_pkg_fast(o, c, &mut checks, &s.pkg),
			_ => check_pkg_full(o, c, &mut checks, &s.pkg),
		};
	}
	if c.op_q_info == 0
		&& c.op_q_list == 0
		&& c.op_q_changelog == 0
		&& c.op_q_check == 0
	{
		let line = plain_line(c, handle, o, s);
		o.stdout.extend(line);
	}
	ret
}

// search_path: the first "<dir>/<filename>" of PATH lstat finds. each
// dir loses its trailing '/', an empty one gives "/<filename>"
fn search_path(
	path_env: Option<&[u8]>,
	filename: &[u8],
) -> Option<(Vec<u8>, Metadata)> {
	for dir in path_env?.split(|&b| b == b':') {
		let mut dir = dir;
		while let Some(d) = dir.strip_suffix(b"/") {
			dir = d;
		}
		let full = cat(&[dir, b"/", filename]);
		if let Ok(st) = fs::symlink_metadata(os(&full)) {
			return Some((full, st));
		}
	}
	None
}

fn realpath(path: &[u8]) -> Option<Vec<u8>> {
	let real = fs::canonicalize(os(path)).ok()?;
	Some(real.into_os_string().into_vec())
}

// lrealpath: realpath of the directory part, the last component kept as
// is (a symlink there is not followed); "." and ".." resolve the whole
// path. None where realpath fails
fn lrealpath(path: &[u8]) -> Option<Vec<u8>> {
	let bname = mbasename(path);
	if bname == b"." || bname == b".." {
		return realpath(path);
	}
	let mut rpath = realpath(&mdirname(path))?;
	if rpath.last() != Some(&b'/') {
		rpath.push(b'/');
	}
	rpath.extend_from_slice(bname);
	Some(rpath)
}

// print_query_fileowner
fn print_owner(c: &Config, out: &mut Vec<u8>, file: &[u8], pkg: &Package) {
	let cs = &c.colstr;
	let name = pkg.name_bytes();
	if c.quiet != 0 {
		out.extend(cat(&[name, b"\n"]));
		return;
	}
	let ver = version(pkg);
	out.extend(cat(&[
		file,
		b" is owned by ",
		cs.title,
		name,
		b" ",
		cs.version,
		ver,
		cs.nocolor,
		b"\n",
	]));
}

// one target of query_fileowner, true when a package owns it. the
// target is resolved like the C: trailing '/' dropped (marks a
// directory), a bare name missing here looked up in PATH, the directory
// part canonicalized, then made relative to the root; directories end
// in '/' and every owner is listed, files stop at the first
fn query_owner(
	c: &Config,
	handle: &mut Handle,
	env: &QueryEnv,
	target: &[u8],
	o: &mut Output,
) -> bool {
	let root = handle.root().to_vec();
	let mut filename = until_nul(target).to_vec();
	if filename.is_empty() {
		let msg = b"empty string passed to file owner query\n";
		pm_printf(&mut o.stderr, c, LOG_ERROR, msg);
		return false;
	}
	let mut is_dir = false;
	while filename.len() > 1 && filename.last() == Some(&b'/') {
		filename.pop();
		// a non-directory that exists corrects this below
		is_dir = true;
	}
	let mut st = fs::symlink_metadata(os(&filename)).ok();
	if st.is_none() && !filename.contains(&b'/') {
		let found = search_path(env.path.as_deref(), &filename);
		if let Some((full, m)) = found {
			filename = full;
			st = Some(m);
		}
	}
	// can't canonicalize, try to proceed anyway
	let mut rpath =
		lrealpath(&filename).unwrap_or_else(|| filename.clone());
	let not_owned = cat(&[b"No package owns ", &filename, b"\n"]);
	if !rpath.starts_with(&root) {
		pm_printf(&mut o.stderr, c, LOG_ERROR, &not_owned);
		return false;
	}
	let is_dir = st.as_ref().map_or(is_dir, Metadata::is_dir);
	if is_dir {
		if rpath.len() + 2 >= PATH_MAX {
			let msg = cat(&[b"path too long: ", &rpath, b"/\n"]);
			pm_printf(&mut o.stderr, c, LOG_ERROR, &msg);
			return false;
		}
		rpath.push(b'/');
	}
	// the C calls alpm_pkg_get_files on each package it visits
	let rel = &rpath[root.len()..];
	let mut found = false;
	let dbs = handle.dbs_mut();
	if let Some(db) = dbs.local {
		let _ = db.walk(dbs.dbext, dbs.cb, INFRQ_FILES, |_, pkg| {
			if pkg.files.contains(rel).is_some() {
				print_owner(c, &mut o.stdout, &rpath, pkg);
				found = true;
				if !is_dir {
					return ControlFlow::Break(());
				}
			}
			ControlFlow::Continue(())
		});
	}
	if !found {
		pm_printf(&mut o.stderr, c, LOG_ERROR, &not_owned);
	}
	found
}

// query_fileowner: the number of targets nobody owns
fn query_fileowner(
	c: &Config,
	handle: &mut Handle,
	env: &QueryEnv,
	targets: &[Vec<u8>],
	o: &mut Output,
) -> i32 {
	// this code is here for safety only
	if targets.is_empty() {
		let msg = b"no file was specified for --owns\n";
		pm_printf(&mut o.stderr, c, LOG_ERROR, msg);
		return 1;
	}
	// alpm_db_get_pkgcache before the first target
	let dbs = handle.dbs_mut();
	if let Some(db) = dbs.local {
		let _ = db.pkgcache(dbs.dbext, dbs.cb);
	}
	let mut ret = 0;
	for t in targets {
		// the last target's lines before this one's loads
		o.flush();
		if !query_owner(c, handle, env, t, o) {
			ret += 1;
		}
	}
	ret
}

// query_search: dump_pkg_search on the local db, a bad regex fails
fn query_search(
	c: &Config,
	handle: &mut Handle,
	env: &QueryEnv,
	targets: &[Vec<u8>],
	o: &mut Output,
) -> i32 {
	let dbs = handle.dbs_mut();
	let Some(db) = dbs.local else {
		return 1;
	};
	let (dbext, cb) = (dbs.dbext, dbs.cb);
	let quiet = c.quiet != 0;
	// the whole cache: groups and desc are only read when not quiet
	let req = if quiet { 0 } else { INFRQ_DESC };
	let results: Vec<&Package> = if targets.is_empty() {
		match db.load_all(dbext, cb, req) {
			Ok(cache) => cache.iter().collect(),
			Err(_) => Vec::new(),
		}
	} else {
		match db.search(dbext, cb, targets) {
			Ok(r) => r,
			Err(e) => {
				let why = e.strerror().as_bytes();
				let msg =
					cat(&[b"search failed: ", why, b"\n"]);
				pm_printf(&mut o.stderr, c, LOG_ERROR, &msg);
				return 1;
			}
		}
	};
	let shown = dump_pkg_search(
		&mut o.stdout,
		b"local",
		&results,
		None,
		quiet,
		env.cols,
		&c.colstr,
	);
	i32::from(!shown)
}

// the members of a local group (alpm_db_get_group, or every group of
// the group cache), copied out
fn groups(
	handle: &mut Handle,
	name: Option<&[u8]>,
) -> Vec<(Vec<u8>, Vec<Package>)> {
	let dbs = handle.dbs_mut();
	let Some(db) = dbs.local else {
		return Vec::new();
	};
	let groups = match name {
		None => db.groupcache(dbs.dbext, dbs.cb).unwrap_or_default(),
		Some(name) => match db.get_group(dbs.dbext, dbs.cb, name) {
			Ok(Some(g)) => vec![g],
			_ => Vec::new(),
		},
	};
	let copy = |g: alpm_core::group::Group<&Package>| {
		(g.name, g.packages.into_iter().cloned().collect())
	};
	groups.into_iter().map(copy).collect()
}

// filter on a group member: the group cache loaded every desc
fn member(c: &Config, h: &mut Handle, o: &mut Output, pkg: &Package) -> bool {
	let mut s = Shown {
		pos: None,
		pkg: pkg.clone(),
	};
	filter(c, h, o, &mut s)
}

fn query_group(
	c: &Config,
	handle: &mut Handle,
	targets: &[Vec<u8>],
	o: &mut Output,
) -> i32 {
	if targets.is_empty() {
		for (name, pkgs) in groups(handle, None) {
			for pkg in pkgs.iter() {
				if !member(c, handle, o, pkg) {
					continue;
				}
				let line = [
					&name[..],
					b" ",
					pkg.name_bytes(),
					b"\n",
				];
				o.stdout.extend(cat(&line));
			}
		}
		return 0;
	}
	let mut ret = 0;
	for grpname in targets {
		// the last target's lines before this one's loads
		o.flush();
		let grpname = until_nul(grpname);
		let found = groups(handle, Some(grpname));
		let Some((_, pkgs)) = found.into_iter().next() else {
			let msg = [b"group '", grpname, b"' was not found\n"];
			pm_printf(&mut o.stderr, c, LOG_ERROR, &cat(&msg));
			ret += 1;
			continue;
		};
		for pkg in pkgs.iter() {
			if !member(c, handle, o, pkg) {
				continue;
			}
			let name = pkg.name_bytes();
			match c.quiet {
				0 => o.stdout
					.extend(cat(&[grpname, b" ", name])),
				_ => o.stdout.extend_from_slice(name),
			}
			o.stdout.push(b'\n');
		}
	}
	ret
}

// a package of the local db by name, else the first satisfier of name
// in the cache: its list position
fn find_local(handle: &mut Handle, name: &[u8]) -> Option<usize> {
	let dbs = handle.dbs_mut();
	let (dbext, cb, db) = (dbs.dbext, dbs.cb, dbs.local?);
	let Ok(pkg) = db.get_pkg(dbext, cb, name) else {
		return db.find_satisfier(dbext, cb, name);
	};
	let pkg: *const Package = pkg;
	let cache = db.pkgcache(dbext, cb).ok()?;
	cache.iter().position(|p| std::ptr::eq(p, pkg))
}

// a package -Q shows: a local cache entry by list position, or a
// package file
enum Target {
	Local(usize),
	File(Box<Package>),
}

// a -Q/-Qp target: the package or the error the C prints for it
fn target_pkg(
	c: &Config,
	handle: &mut Handle,
	target: &[u8],
	o: &mut Output,
) -> Option<Target> {
	let strname = until_nul(target);
	if c.op_q_isfile != 0 {
		// alpm_pkg_load(handle, strname, 1, 0): logs through the handle
		let loaded = handle.with_callbacks(|h, cb| {
			pkg_load_level(h.keyring_mut(), cb, strname, true, 0)
		});
		return match loaded {
			Ok(pkg) => Some(Target::File(Box::new(pkg))),
			Err(e) => {
				let why = e.errno().strerror().as_bytes();
				let msg = cat(&[
					b"could not load package '",
					strname,
					b"': ",
					why,
					b"\n",
				]);
				pm_printf(&mut o.stderr, c, LOG_ERROR, &msg);
				None
			}
		};
	}
	let strname = strname.strip_prefix(LOCAL_PREFIX).unwrap_or(strname);
	let found = find_local(handle, strname).map(Target::Local);
	if found.is_none() {
		let msg = cat(&[b"package '", strname, b"' was not found\n"]);
		pm_printf(&mut o.stderr, c, LOG_ERROR, &msg);
		if readable(strname) {
			let msg = cat(&[
				b"'",
				strname,
				b"' is a file, you might want to use -p/--file.\n",
			]);
			pm_printf(&mut o.stderr, c, LOG_WARNING, &msg);
		}
	}
	found
}

// filter + display of one package. None past the end of the cache,
// Some(None) when filtered out, else the display result
fn show(
	c: &Config,
	handle: &mut Handle,
	env: &QueryEnv,
	target: Target,
	o: &mut Output,
) -> Option<Option<i32>> {
	let mut s = match target {
		Target::Local(i) => Shown {
			pos: Some(i),
			pkg: local_at(handle, o, i, 0)?,
		},
		Target::File(pkg) => Shown {
			pos: None,
			pkg: *pkg,
		},
	};
	if !filter(c, handle, o, &mut s) {
		return Some(None);
	}
	Some(Some(display(c, handle, env, &mut s, o)))
}

// pacman_query: the -Q operation on targets, returns the exit status
pub fn pacman_query(
	c: &Config,
	handle: &mut Handle,
	env: &QueryEnv,
	targets: &[Vec<u8>],
	o: &mut Output,
) -> i32 {
	// first: operations that do not require targets
	if c.op_q_search != 0 {
		return query_search(c, handle, env, targets, o);
	}
	if c.group != 0 {
		return query_group(c, handle, targets, o);
	}
	if (c.op_q_locality != 0 || c.op_q_upgrade != 0)
		&& check_syncdbs(&mut o.stderr, c, handle, true, true) != 0
	{
		return 1;
	}
	// ret and match of the C
	let (mut ret, mut matched) = (0, false);
	let mut tally = |shown: Option<i32>, ret: &mut i32| {
		if let Some(value) = shown {
			if value != 0 {
				*ret = 1;
			}
			matched = true;
		}
	};
	if targets.is_empty() {
		if c.op_q_isfile != 0 || c.op_q_owns != 0 {
			let msg = b"no targets specified (use -h for help)\n";
			pm_printf(&mut o.stderr, c, LOG_ERROR, msg);
			return 1;
		}
		for i in 0.. {
			let Some(shown) =
				show(c, handle, env, Target::Local(i), o)
			else {
				break;
			};
			tally(shown, &mut ret);
		}
	} else if c.op_q_owns != 0 {
		// second: operations that require target(s)
		return query_fileowner(c, handle, env, targets, o);
	} else {
		for t in targets {
			// the last target's lines before this one's loads
			o.flush();
			match target_pkg(c, handle, t, o) {
				Some(target) => {
					let shown =
						show(c, handle, env, target, o);
					tally(shown.flatten(), &mut ret);
				}
				None => ret = 1,
			}
		}
	}
	if !matched {
		ret = 1;
	}
	ret
}
