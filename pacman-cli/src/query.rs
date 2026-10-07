// port of src/pacman/query.c: -Q and its options (-Qi/-Qii, -Ql, -Qo,
// -Qs, -Qg, -Qc, -Qk/-Qkk, -Qp), the -Qd/-Qe/-Qm/-Qn/-Qt/-Qtt/-Qu
// filters and -q
//
// config->handle is the Handle passed in, its local and sync dbs answer
// what the C asks libalpm. a package is cloned out of the db cache once
// the getters the C calls on it (desc, files, scriptlet) loaded it in
// place, so filters and displays can walk the caches again (requiredby,
// sync lookups) while it is shown. stdout and stderr go into an Output
// like check.rs, pm_printf filtered by the config's logmask. getcols()
// and getenv("PATH") come in through QueryEnv. messages are the
// untranslated msgids.
//
// not modelled: libalpm logging (the frontend's log callback prints
// lazy-load errors), gpgme checks of package files with a .sig (-Qpi
// reports ALPM_ERR_GPGME there).
use std::ffi::{OsStr, c_int};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::ops::ControlFlow;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use alpm_core::be_local::{
	INFRQ_DESC, INFRQ_FILES, INFRQ_SCRIPTLET, MtreeEntry, MtreeError,
};
use alpm_core::be_package::{self, pkg_load};
use alpm_core::db::{DB_USAGE_UPGRADE, Db};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::package::{
	DbCaches, Package, PkgFrom, PkgReason, compute_optionalfor,
	compute_requiredby, pkg_compare_versions, pkg_should_ignore,
};
use alpm_core::util::{compute_md5sum, fnmatch, until_nul};
use pacman_common::util_common::{mbasename, mdirname};

use crate::check::{CheckEnv, Output, check_pkg_fast, check_pkg_full};
use crate::conf::{Config, LOG_ERROR, LOG_WARNING, cat};
use crate::package::{
	FileProbe, PkgEnv, dump_pkg_changelog, dump_pkg_files, dump_pkg_full,
	dump_pkg_search,
};
use crate::pacman::{PKG_LOCALITY_FOREIGN, PKG_LOCALITY_NATIVE};
use crate::util::SigResult;

// limits.h, the rpath buffer of query_fileowner
const PATH_MAX: usize = 4096;
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

// pm_printf(level, ...) to stderr: logmask filter, then the prefix
fn pm_printf(err: &mut Vec<u8>, c: &Config, level: u16, msg: &[u8]) {
	if c.logmask & level == 0 {
		return;
	}
	let cs = &c.colstr;
	let prefix: &[&[u8]] = match level {
		LOG_ERROR => &[cs.err, b"error: ", cs.nocolor],
		_ => &[cs.warn, b"warning: ", cs.nocolor],
	};
	err.extend(prefix.concat());
	err.extend_from_slice(msg);
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

// the libalpm calls of package.c on config->handle. pm_printf output is
// kept apart and appended to stderr after the display, which writes
// nothing else there
struct Env<'a> {
	handle: &'a mut Handle,
	config: &'a Config,
	err: Vec<u8>,
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

	// _alpm_gpgme_checksig up to gpgme: the file must be readable, then
	// a base64 signature or a readable "<file>.sig" is needed
	fn check_signature(
		&mut self,
		pkg: &Package,
	) -> Result<Vec<SigResult>, Errno> {
		let file =
			until_nul(pkg.filename.as_deref().unwrap_or_default());
		if !readable(file) {
			return Err(Errno::NotAFile);
		}
		let sig = cat(&[file, b".sig"]);
		if pkg.base64_sig.is_none() && !readable(&sig) {
			return Err(Errno::SigMissing);
		}
		// gpgme verification is not ported
		Err(Errno::Gpgme)
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
				be_package::changelog(pkg).ok()
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
}

// check.c on config->handle. file packages keep libalpm's default ops,
// whose mtree_open returns NULL
struct Checks<'a> {
	handle: &'a Handle,
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

	fn mtree(&self, pkg: &Package) -> Result<Vec<MtreeEntry>, MtreeError> {
		let local = self.handle.localdb().and_then(Db::local);
		match (&pkg.origin, local) {
			(Some(PkgFrom::LocalDb), Some(local)) => {
				local.mtree(pkg)
			}
			_ => Err(MtreeError::Missing),
		}
	}
}

// the getters filter calls on a local package: the reason (-Qe/-Qd)
// and its provides (-Qt requiredby)
fn filter_req(c: &Config) -> c_int {
	match c.op_q_explicit != 0 || c.op_q_deps != 0 || c.op_q_unrequired != 0
	{
		true => INFRQ_DESC,
		false => 0,
	}
}

// the getters display calls once filter passed, in the C's order: -i
// (desc, scriptlet) and the groups of -Qu's ignore check (skipped for a
// name in IgnorePkg), then files (-ii backup, -l, -k). a failed read is
// sticky, so the order decides what a broken entry still shows. -Qkk
// loads files up front, the C only once an mtree entry reaches the
// backup check
fn display_req(c: &Config, handle: &Handle, pkg: &Package) -> [c_int; 2] {
	let plain = c.op_q_info == 0
		&& c.op_q_list == 0
		&& c.op_q_changelog == 0
		&& c.op_q_check == 0;
	let ignored = || {
		let name = pkg.name_bytes();
		handle.ignorepkgs().iter().any(|p| fnmatch(p, name))
	};
	let mut first = 0;
	if c.op_q_upgrade != 0 && plain && c.quiet == 0 && !ignored() {
		first |= INFRQ_DESC;
	}
	if c.op_q_info != 0 {
		first |= INFRQ_DESC | INFRQ_SCRIPTLET;
	}
	let files = c.op_q_list != 0 || c.op_q_check != 0 || c.op_q_info > 1;
	[first, if files { INFRQ_FILES } else { 0 }]
}

// the local cache entry at list position i with each of reqs loaded in
// turn, copied out. None past the end
fn local_at(handle: &mut Handle, i: usize, reqs: &[c_int]) -> Option<Package> {
	let dbext = handle.dbext().to_vec();
	let db = handle.localdb_mut()?;
	let mut pkg = None;
	for &req in reqs {
		pkg = db.load_pkg_at(&dbext, i, req);
	}
	pkg.cloned()
}

// check_syncdbs(1, 1) of util.c: sync dbs registered and all valid
fn check_syncdbs(c: &Config, handle: &Handle, err: &mut Vec<u8>) -> i32 {
	let dbs = handle.syncdbs();
	if dbs.is_empty() {
		let msg = b"no usable package repositories configured.\n";
		pm_printf(err, c, LOG_ERROR, msg);
		return 1;
	}
	let mut ret = 0;
	for db in dbs {
		if let Err(e) = db.valid() {
			let why = e.strerror().as_bytes();
			let msg = cat(&[
				b"database '",
				db.name(),
				b"' is not valid (",
				why,
				b")\n",
			]);
			pm_printf(err, c, LOG_ERROR, &msg);
			ret = 1;
		}
	}
	ret
}

// pkg_get_locality: native when a sync db has a package of that name
fn locality(handle: &mut Handle, pkg: &Package) -> u16 {
	let dbext = handle.dbext().to_vec();
	let name = pkg.name_bytes();
	let mut dbs = handle.syncdbs_mut().iter_mut();
	match dbs.any(|db| db.get_pkg(&dbext, name).is_ok()) {
		true => PKG_LOCALITY_NATIVE,
		false => PKG_LOCALITY_FOREIGN,
	}
}

// alpm_sync_get_new_version: the first sync db holding a package of
// that name decides. its version and the db's usage when it is newer
fn new_version(handle: &mut Handle, pkg: &Package) -> Option<(Vec<u8>, c_int)> {
	let dbext = handle.dbext().to_vec();
	for db in handle.syncdbs_mut() {
		let usage = db.usage();
		let Ok(spkg) = db.get_pkg(&dbext, pkg.name_bytes()) else {
			continue;
		};
		let newer = pkg_compare_versions(spkg, pkg).is_gt();
		return newer.then(|| (version(spkg).to_vec(), usage));
	}
	None
}

// is_unrequired: nothing depends on pkg, at level 1 nothing optionally
// either
fn is_unrequired(handle: &mut Handle, pkg: &Package, level: u16) -> bool {
	if !compute_requiredby(pkg, handle).is_empty() {
		return false;
	}
	level != 1 || compute_optionalfor(pkg, handle).is_empty()
}

fn filter(c: &Config, handle: &mut Handle, pkg: &Package) -> bool {
	if c.op_q_explicit != 0 && pkg.reason != PkgReason::Explicit {
		return false;
	}
	if c.op_q_deps != 0 && pkg.reason != PkgReason::Depend {
		return false;
	}
	if c.op_q_locality != 0 && c.op_q_locality != locality(handle, pkg) {
		return false;
	}
	if c.op_q_unrequired != 0
		&& !is_unrequired(handle, pkg, c.op_q_unrequired)
	{
		return false;
	}
	if c.op_q_upgrade != 0 && new_version(handle, pkg).is_none() {
		return false;
	}
	true
}

// the plain line: "name version", with -Qu " -> newversion" and
// " [ignored]" for an ignored package or a db not used for upgrades
fn plain_line(c: &Config, handle: &mut Handle, pkg: &Package) -> Vec<u8> {
	let cs = &c.colstr;
	if c.quiet != 0 {
		return cat(&[pkg.name_bytes(), b"\n"]);
	}
	let (name, ver) = (pkg.name_bytes(), version(pkg));
	let mut out = cat(&[cs.title, name, b" ", cs.version, ver, cs.nocolor]);
	// filter made sure there is a newer version
	if c.op_q_upgrade != 0
		&& let Some((newver, usage)) = new_version(handle, pkg)
	{
		out.extend(cat(&[b" -> ", cs.version, &newver, cs.nocolor]));
		if pkg_should_ignore(handle, pkg)
			|| usage & DB_USAGE_UPGRADE == 0
		{
			out.extend_from_slice(b" [ignored]");
		}
	}
	out.push(b'\n');
	out
}

fn display(
	c: &Config,
	handle: &mut Handle,
	env: &QueryEnv,
	pkg: &Package,
	o: &mut Output,
) -> i32 {
	let mut ret = 0;
	let mut penv = Env {
		handle,
		config: c,
		err: Vec::new(),
	};
	if c.op_q_info != 0 {
		let extra = c.op_q_info > 1;
		let out = &mut o.stdout;
		dump_pkg_full(out, &mut penv, pkg, extra, env.cols, &c.colstr);
		o.stderr.append(&mut penv.err);
	}
	if c.op_q_list != 0 {
		let root = penv.handle.root();
		let quiet = c.quiet != 0;
		dump_pkg_files(&mut o.stdout, pkg, root, quiet, &c.colstr);
	}
	if c.op_q_changelog != 0 {
		dump_pkg_changelog(&mut o.stdout, &mut penv, pkg);
		o.stderr.append(&mut penv.err);
	}
	let handle = penv.handle;
	if c.op_q_check != 0 {
		let checks = Checks { handle };
		ret = match c.op_q_check {
			1 => check_pkg_fast(o, c, &checks, pkg),
			_ => check_pkg_full(o, c, &checks, pkg),
		};
	}
	if c.op_q_info == 0
		&& c.op_q_list == 0
		&& c.op_q_changelog == 0
		&& c.op_q_check == 0
	{
		let line = plain_line(c, handle, pkg);
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
	let (rel, dbext) = (&rpath[root.len()..], handle.dbext().to_vec());
	let mut found = false;
	if let Some(db) = handle.localdb_mut() {
		let _ = db.walk(&dbext, INFRQ_FILES, |_, pkg| {
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
	let mut ret = 0;
	for t in targets {
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
	let dbext = handle.dbext().to_vec();
	let Some(db) = handle.localdb_mut() else {
		return 1;
	};
	let quiet = c.quiet != 0;
	// the whole cache: groups and desc are only read when not quiet
	let req = if quiet { 0 } else { INFRQ_DESC };
	let results: Vec<&Package> = if targets.is_empty() {
		match db.load_all(&dbext, req) {
			Ok(cache) => cache.iter().collect(),
			Err(_) => Vec::new(),
		}
	} else {
		match db.search(&dbext, targets) {
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
	let dbext = handle.dbext().to_vec();
	let Some(db) = handle.localdb_mut() else {
		return Vec::new();
	};
	let groups = match name {
		None => db.groupcache(&dbext).unwrap_or_default(),
		Some(name) => match db.get_group(&dbext, name) {
			Ok(Some(g)) => vec![g],
			_ => Vec::new(),
		},
	};
	let copy = |g: alpm_core::group::Group<&Package>| {
		(g.name, g.packages.into_iter().cloned().collect())
	};
	groups.into_iter().map(copy).collect()
}

fn query_group(
	c: &Config,
	handle: &mut Handle,
	targets: &[Vec<u8>],
	o: &mut Output,
) -> i32 {
	if targets.is_empty() {
		for (name, pkgs) in groups(handle, None) {
			for pkg in pkgs.iter().filter(|p| filter(c, handle, p))
			{
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
		let grpname = until_nul(grpname);
		let found = groups(handle, Some(grpname));
		let Some((_, pkgs)) = found.into_iter().next() else {
			let msg = [b"group '", grpname, b"' was not found\n"];
			pm_printf(&mut o.stderr, c, LOG_ERROR, &cat(&msg));
			ret += 1;
			continue;
		};
		for pkg in pkgs.iter().filter(|p| filter(c, handle, p)) {
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
	let dbext = handle.dbext().to_vec();
	let db = handle.localdb_mut()?;
	let Ok(pkg) = db.get_pkg(&dbext, name) else {
		return db.find_satisfier(&dbext, name);
	};
	let pkg: *const Package = pkg;
	let cache = db.pkgcache(&dbext).ok()?;
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
		return match pkg_load(strname, true) {
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

// filter + display of one package, local entries loaded by what each
// asks for. None past the end of the cache, Some(None) when filtered
// out, else the display result
fn show(
	c: &Config,
	handle: &mut Handle,
	env: &QueryEnv,
	target: Target,
	o: &mut Output,
) -> Option<Option<i32>> {
	let (i, pkg) = match target {
		Target::Local(i) => {
			(Some(i), local_at(handle, i, &[filter_req(c)])?)
		}
		Target::File(pkg) => (None, *pkg),
	};
	if !filter(c, handle, &pkg) {
		return Some(None);
	}
	let pkg = match i {
		Some(i) => {
			let reqs = display_req(c, handle, &pkg);
			local_at(handle, i, &reqs)?
		}
		None => pkg,
	};
	Some(Some(display(c, handle, env, &pkg, o)))
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
		&& check_syncdbs(c, handle, &mut o.stderr) != 0
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
