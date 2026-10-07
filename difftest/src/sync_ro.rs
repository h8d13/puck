// C side of the read-only ops of src/pacman/sync.c (frontend objects, see
// build.rs), and the fixture worlds shared with files_op
//
// pacman_sync reads config (flags, colstr, logmask, handle) and prints to
// the C stdout and, through pm_printf, to stderr. a FrontHandle is a real
// handle on a fixture root with its sync dbs registered (siglevel 0, the
// dbext set first like setup_libalpm). each run holds FRONTEND, puts the
// handle and the flags of a pacman_cli Config into `config`, swaps both
// streams for open_memstreams and puts everything back afterwards. only
// flags that keep pacman_sync away from transactions, downloads and the
// cache dirs are accepted (asserted before the call).
use std::ffi::{CString, c_int, c_void};
use std::fmt::Write as _;
use std::fs;
use std::ptr;

use pacman_cli::conf::Config;

use crate::cli_util::{FRONTEND, config, init};
use crate::conf::ColStrC;
use crate::fixtures::{
	LocalEntry, TarEntry, TempRoot, section, tar_dir, tar_file, ustar,
};
use crate::handle::{
	ALPM, CDb, alpm_db_get_pkgcache, alpm_errno, alpm_initialize,
	alpm_option_set_dbext, alpm_register_syncdb, alpm_release,
};
use crate::pkg_show::{c_strftime_c, columns_cache_reset};
use crate::{
	CList, Rng, alpm_list_add, alpm_list_free, c_free, cstr, fclose,
	fflush, open_memstream, stderr, stdout,
};

unsafe extern "C" {
	fn pacman_sync(targets: *mut CList) -> c_int;
}

// a real handle on a fixture, released on drop
pub struct FrontHandle {
	h: *mut c_void,
	dbs: Vec<*mut CDb>,
}

impl FrontHandle {
	// alpm_initialize on root/dbpath (existing dirs), dbext set, then
	// repos registered in order without signature checks
	pub fn open(
		root: &[u8],
		dbpath: &[u8],
		dbext: &[u8],
		repos: &[&str],
	) -> Self {
		let (root, dbpath, ext) =
			(cstr(root), cstr(dbpath), cstr(dbext));
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let mut err = 0;
		// SAFETY: valid C strings, err is writable; the handle copies
		// dbext and the names
		unsafe {
			let h = alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			);
			assert!(!h.is_null(), "alpm_initialize: {err}");
			assert_eq!(alpm_option_set_dbext(h, ext.as_ptr()), 0);
			let dbs = repos
				.iter()
				.map(|r| {
					let n = cstr(r.as_bytes());
					let db = alpm_register_syncdb(
						h,
						n.as_ptr(),
						0,
					);
					assert!(
						!db.is_null(),
						"register {r}: {}",
						alpm_errno(h)
					);
					db
				})
				.collect();
			FrontHandle { h, dbs }
		}
	}

	// alpm_db_get_pkgcache on every sync db, so a broken db file is
	// already marked invalid when the op starts
	pub fn warm(&self) {
		for &db in &self.dbs {
			// SAFETY: db belongs to the live handle
			unsafe { alpm_db_get_pkgcache(db) };
		}
	}
}

impl Drop for FrontHandle {
	fn drop(&mut self) {
		let _guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		// SAFETY: h came from alpm_initialize, no transaction, nothing
		// of it is used afterwards
		unsafe { alpm_release(self.h) };
	}
}

// what an op returned and printed
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CRun {
	pub ret: i32,
	pub stdout: Vec<u8>,
	pub stderr: Vec<u8>,
}

// the first line where two outputs part, with the lines before it
fn first_diff(what: &str, a: &[u8], b: &[u8]) -> Option<String> {
	if a == b {
		return None;
	}
	let la: Vec<&[u8]> = a.split_inclusive(|&c| c == b'\n').collect();
	let lb: Vec<&[u8]> = b.split_inclusive(|&c| c == b'\n').collect();
	let i = la.iter().zip(&lb).take_while(|(x, y)| x == y).count();
	let show = |l: &[&[u8]]| -> String {
		let from = i.saturating_sub(3);
		let to = (i + 3).min(l.len());
		l[from..to]
			.iter()
			.map(|x| format!("{:?}\n", String::from_utf8_lossy(x)))
			.collect()
	};
	Some(format!(
		"{what} differs at line {i}\nC:\n{}Rust:\n{}",
		show(&la),
		show(&lb)
	))
}

impl CRun {
	// None when equal, else what differs (C self, Rust other)
	pub fn diff(&self, other: &CRun) -> Option<String> {
		let parts = [
			(self.ret != other.ret).then(|| {
				format!("ret C {} Rust {}", self.ret, other.ret)
			}),
			first_diff("stdout", &self.stdout, &other.stdout),
			first_diff("stderr", &self.stderr, &other.stderr),
		];
		let d: Vec<String> = parts.into_iter().flatten().collect();
		(!d.is_empty()).then(|| d.join("\n"))
	}
}

// the config_t fields sync.c and files.c read, besides handle and colstr
#[derive(Clone, Copy)]
struct Flags {
	quiet: u16,
	logmask: u16,
	op_q_list: u16,
	op_s_clean: u16,
	op_s_info: u16,
	op_s_sync: u16,
	op_s_search: u16,
	op_s_upgrade: u16,
	op_f_regex: u16,
	op_f_machinereadable: u16,
	group: u16,
}

impl Flags {
	fn of(c: &Config) -> Flags {
		Flags {
			quiet: c.quiet,
			logmask: c.logmask,
			op_q_list: c.op_q_list,
			op_s_clean: c.op_s_clean,
			op_s_info: c.op_s_info,
			op_s_sync: c.op_s_sync,
			op_s_search: c.op_s_search,
			op_s_upgrade: c.op_s_upgrade,
			op_f_regex: c.op_f_regex,
			op_f_machinereadable: c.op_f_machinereadable,
			group: c.group,
		}
	}

	// SAFETY (callers): FRONTEND held, config valid
	unsafe fn swap(self) -> Flags {
		// SAFETY: see above
		let c = unsafe { &mut *config };
		let old = Flags {
			quiet: c.quiet,
			logmask: c.logmask,
			op_q_list: c.op_q_list,
			op_s_clean: c.op_s_clean,
			op_s_info: c.op_s_info,
			op_s_sync: c.op_s_sync,
			op_s_search: c.op_s_search,
			op_s_upgrade: c.op_s_upgrade,
			op_f_regex: c.op_f_regex,
			op_f_machinereadable: c.op_f_machinereadable,
			group: c.group,
		};
		c.quiet = self.quiet;
		c.logmask = self.logmask;
		c.op_q_list = self.op_q_list;
		c.op_s_clean = self.op_s_clean;
		c.op_s_info = self.op_s_info;
		c.op_s_sync = self.op_s_sync;
		c.op_s_search = self.op_s_search;
		c.op_s_upgrade = self.op_s_upgrade;
		c.op_f_regex = self.op_f_regex;
		c.op_f_machinereadable = self.op_f_machinereadable;
		c.group = self.group;
		old
	}
}

// runs op(targets) with config set from cfg, config->handle = fh and
// COLUMNS = cols (getcols), both C streams captured. TZ=UTC for the
// dates of -Si
pub(crate) fn run_op<S: AsRef<[u8]>>(
	fh: &FrontHandle,
	cfg: &Config,
	cols: u16,
	targets: &[S],
	op: unsafe extern "C" fn(*mut CList) -> c_int,
) -> CRun {
	init();
	// sets TZ=UTC once, takes FRONTEND itself
	c_strftime_c(0);
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	let cs = &cfg.colstr;
	let c = [
		cs.colon, cs.title, cs.repo, cs.version, cs.groups, cs.meta,
		cs.warn, cs.err, cs.faint, cs.nocolor,
	]
	.map(cstr);
	let targs: Vec<CString> =
		targets.iter().map(|t| cstr(t.as_ref())).collect();
	let (mut obuf, mut osize) = (ptr::null_mut(), 0usize);
	let (mut ebuf, mut esize) = (ptr::null_mut(), 0usize);
	// SAFETY: FRONTEND serializes every access to config, stdout,
	// stderr and the environment from C. config is valid after init;
	// the colstr strings and targets outlive the call, the old colstr
	// (static literals) and flags are put back before they drop. the
	// target list nodes are freed after, the strings stay ours (sync.c
	// and files.c only read or strdup them). the memstreams replace the
	// streams only while op runs, their buffers are malloc'd and valid
	// for size bytes after fclose
	unsafe {
		std::env::set_var("COLUMNS", cols.to_string());
		columns_cache_reset();
		let mut list: *mut CList = ptr::null_mut();
		for t in &targs {
			list = alpm_list_add(
				list,
				t.as_ptr().cast_mut().cast(),
			);
		}
		let old_colstr = std::mem::replace(
			&mut (*config).colstr,
			ColStrC {
				colon: c[0].as_ptr(),
				title: c[1].as_ptr(),
				repo: c[2].as_ptr(),
				version: c[3].as_ptr(),
				groups: c[4].as_ptr(),
				meta: c[5].as_ptr(),
				warn: c[6].as_ptr(),
				err: c[7].as_ptr(),
				faint: c[8].as_ptr(),
				nocolor: c[9].as_ptr(),
			},
		);
		let old_flags = Flags::of(cfg).swap();
		(*config).handle = fh.h;
		let out = open_memstream(&mut obuf, &mut osize);
		let err = open_memstream(&mut ebuf, &mut esize);
		assert!(!out.is_null() && !err.is_null());
		let (real_out, real_err) = (stdout, stderr);
		fflush(real_out);
		fflush(real_err);
		stdout = out;
		stderr = err;
		let ret = op(list);
		fflush(out);
		fflush(err);
		stdout = real_out;
		stderr = real_err;
		fclose(out);
		fclose(err);
		(*config).handle = ptr::null_mut();
		old_flags.swap();
		(*config).colstr = old_colstr;
		alpm_list_free(list);
		let o = std::slice::from_raw_parts(obuf.cast::<u8>(), osize)
			.to_vec();
		let e = std::slice::from_raw_parts(ebuf.cast::<u8>(), esize)
			.to_vec();
		c_free(obuf.cast());
		c_free(ebuf.cast());
		CRun {
			ret,
			stdout: o,
			stderr: e,
		}
	}
}

// pacman_sync reaches only -Sg, -Si, -Sl or the "no targets" error with
// these flags: no -Sc (trans_init, cache dirs), -Sy (downloads), -Ss
// (left to the search port) or sync_trans
pub fn sync_read_only<S>(cfg: &Config, targets: &[S]) -> bool {
	let op = cfg.group != 0 || cfg.op_s_info != 0 || cfg.op_q_list != 0;
	cfg.op_s_clean == 0
		&& cfg.op_s_sync == 0
		&& cfg.op_s_search == 0
		&& (op || (targets.is_empty() && cfg.op_s_upgrade == 0))
}

// pacman_sync(targets) on fh. C preconditions: sync_read_only, and the
// dump_pkg_full ones of PkgWorld::dump_full for every package -Si shows
// (the generated worlds keep to them: dates localtime takes, no ESC,
// no %PGPSIG%)
pub fn c_pacman_sync<S: AsRef<[u8]>>(
	fh: &FrontHandle,
	cfg: &Config,
	targets: &[S],
	cols: u16,
) -> CRun {
	assert!(sync_read_only(cfg, targets), "op would leave read-only");
	run_op(fh, cfg, cols, targets, pacman_sync)
}

// generated worlds: a few repos sharing package and group names with
// each other and the local db, so -Sl markers, group merges and
// requiredby across dbs come up. desc/files texts stay within what
// alpm-repo-db/alpm-db accept (be_sync and be_local pin the rest)

pub const REPOS: [&str; 3] = ["core", "extra", "multilib"];
pub const NAMES: [&str; 8] =
	["a", "b", "foo", "bar", "x-y", "lib32-z", "q", "foo2"];
pub const GROUPS: [&str; 4] = ["base", "kde", "g1", "g-2"];
// file names, case pairs of the same UTF-8 length (see regex in
// PORTING.md)
pub const BASENAMES: [&str; 9] = [
	"foo",
	"Foo",
	"bar",
	"a.conf",
	"libx.so.1",
	"x+y",
	"caf\u{e9}",
	"CAF\u{c9}",
	"README",
];
pub const DIRS: [&str; 5] =
	["usr/", "usr/bin/", "usr/lib/", "etc/", "usr/share/foo/"];

fn pick<'a>(rng: &mut Rng, items: &[&'a str]) -> &'a str {
	items[rng.below(items.len())]
}

fn word(rng: &mut Rng, min: usize, max: usize) -> String {
	const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789XYZ";
	let n = min + rng.below(max - min + 1);
	(0..n).map(|_| rng.pick(ALNUM) as char).collect()
}

fn version(rng: &mut Rng) -> String {
	let epoch = if rng.below(6) == 0 { "1:" } else { "" };
	format!(
		"{epoch}{}.{}-{}",
		rng.below(3),
		rng.below(3),
		1 + rng.below(2)
	)
}

fn relation(rng: &mut Rng) -> String {
	let name = pick(rng, &NAMES);
	match rng.below(3) {
		0 => name.to_string(),
		_ => {
			let op = pick(rng, &["=", ">=", "<=", ">", "<"]);
			format!("{name}{op}{}.{}", rng.below(3), rng.below(3))
		}
	}
}

fn optdepend(rng: &mut Rng) -> String {
	let name = pick(rng, &NAMES);
	match rng.below(2) {
		0 => name.to_string(),
		_ => format!("{name}: {}", description(rng)),
	}
}

fn description(rng: &mut Rng) -> String {
	let words: Vec<String> = (0..1 + rng.below(14))
		.map(|_| match rng.below(10) {
			0 => "caf\u{e9}".to_string(),
			1 => "(GTK+)".to_string(),
			_ => word(rng, 1, 9),
		})
		.collect();
	words.join(" ")
}

fn list(rng: &mut Rng, max: usize, f: fn(&mut Rng) -> String) -> Vec<String> {
	(0..rng.below(max + 1)).map(|_| f(rng)).collect()
}

// sorted, unique, every parent dir listed, some top-level files
fn file_list(rng: &mut Rng) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	for _ in 0..rng.below(7) {
		let base = pick(rng, &BASENAMES);
		if rng.below(5) == 0 {
			out.push(base.to_string());
			continue;
		}
		let dir = pick(rng, &DIRS);
		let mut parent = String::new();
		for part in dir.split_inclusive('/') {
			parent.push_str(part);
			out.push(parent.clone());
		}
		out.push(format!("{dir}{base}"));
	}
	out.sort();
	out.dedup();
	out
}

// one sync package: name, version, groups, its desc and files texts
#[derive(Clone, Debug)]
pub struct GenPkg {
	pub name: String,
	pub version: String,
	pub groups: Vec<String>,
	pub files: Vec<String>,
	desc: String,
}

fn gen_pkg(rng: &mut Rng, name: &str) -> GenPkg {
	let version = version(rng);
	let arch = pick(rng, &["x86_64", "any"]);
	// repeats on purpose: load_grpcache's duplicate handling
	let groups: Vec<String> = (0..rng.below(4))
		.map(|_| pick(rng, &GROUPS).to_string())
		.collect();
	let one = |s: String| vec![s];
	let mut desc = [
		section(
			"FILENAME",
			&one(format!("{name}-{version}-{arch}.pkg.tar.zst")),
		),
		section("NAME", &one(name.to_string())),
		section("BASE", &one(name.to_string())),
		section("VERSION", &one(version.clone())),
		section("CSIZE", &one(format!("{}", rng.next_u64() >> 34))),
		section("ISIZE", &one(format!("{}", rng.next_u64() >> 30))),
		section("SHA256SUM", &one("ab".repeat(32))),
		section("ARCH", &one(arch.to_string())),
		// localtime takes these, see UPSTREAM.md
		section("BUILDDATE", &one(format!("{}", rng.next_u64() >> 31))),
		section("PACKAGER", &one("A B <a@b.org>".to_string())),
		section("GROUPS", &groups),
		section(
			"LICENSE",
			&list(rng, 2, |r| {
				pick(r, &["MIT", "GPL-2.0-or-later"])
					.to_string()
			}),
		),
		section("DEPENDS", &list(rng, 3, relation)),
		section("OPTDEPENDS", &list(rng, 2, optdepend)),
		section("PROVIDES", &list(rng, 1, relation)),
		section("CONFLICTS", &list(rng, 1, relation)),
		section("REPLACES", &list(rng, 1, relation)),
	]
	.concat();
	if rng.below(4) != 0 {
		desc.push_str(&section("DESC", &one(description(rng))));
	}
	if rng.below(2) == 0 {
		// lowercase host with a path: alpm-repo-db lowercases the host
		// and appends '/' to a bare one
		let url = format!(
			"https://{}.org/{}",
			word(rng, 1, 6).to_lowercase(),
			word(rng, 1, 6)
		);
		desc.push_str(&section("URL", &one(url)));
	}
	GenPkg {
		name: name.to_string(),
		version,
		groups,
		files: file_list(rng),
		desc,
	}
}

// what a repo's .db and .files hold
#[derive(Clone, Debug)]
pub enum DbFile {
	Valid(Vec<GenPkg>),
	Absent,
	Empty,
	// a valid archive cut short: archive error on both sides
	Truncated,
}

fn sync_tar(pkgs: &[GenPkg], files: bool) -> Vec<u8> {
	let mut entries: Vec<TarEntry> = Vec::new();
	for p in pkgs {
		let dir = format!("{}-{}/", p.name, p.version);
		entries.push(tar_dir(&dir));
		entries.push(tar_file(
			&format!("{dir}desc"),
			p.desc.as_bytes(),
		));
		if files {
			let text = match p.files.is_empty() {
				true => "%FILES%\n".to_string(),
				false => format!(
					"%FILES%\n{}\n\n",
					p.files.join("\n")
				),
			};
			entries.push(tar_file(
				&format!("{dir}files"),
				text.as_bytes(),
			));
		}
	}
	ustar(&entries)
}

fn gen_pkgs(rng: &mut Rng, min: usize, max: usize) -> Vec<GenPkg> {
	let mut names: Vec<&str> = NAMES.to_vec();
	let n = min + rng.below(max - min + 1);
	(0..n).map(|_| {
		let name = names.remove(rng.below(names.len()));
		gen_pkg(rng, name)
	})
	.collect()
}

fn local_desc(name: &str, version: &str, groups: &[String]) -> String {
	format!(
		"%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%BASE%\n{name}\n\n\
		%DESC%\nA package\n\n%URL%\nhttps://example.org/\n\n\
		%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n\
		%INSTALLDATE%\n1700000001\n\n%PACKAGER%\nA B <a@b.org>\n\n\
		%SIZE%\n42\n\n%VALIDATION%\npgp\n\n{}",
		section("GROUPS", groups)
	)
}

// a fixture root: registered repos in order, each with a .db and a
// .files of the same state, and a local db. log describes it for
// assert messages
pub struct SyncWorld {
	pub fx: TempRoot,
	pub repos: Vec<&'static str>,
	pub dbs: Vec<DbFile>,
	pub log: String,
}

impl SyncWorld {
	pub fn generate(rng: &mut Rng, tag: &str) -> SyncWorld {
		let fx = TempRoot::new(tag);
		let mut log = String::new();
		let mut pool = REPOS.to_vec();
		// none now and then: "no usable package repositories"
		let n = match rng.below(12) {
			0 => 0,
			_ => 1 + rng.below(REPOS.len()),
		};
		let repos: Vec<&str> = (0..n)
			.map(|_| pool.remove(rng.below(pool.len())))
			.collect();
		let mut dbs = Vec::new();
		for repo in &repos {
			let db = match rng.below(10) {
				0 => DbFile::Absent,
				1 => DbFile::Empty,
				2 => DbFile::Truncated,
				_ => DbFile::Valid(gen_pkgs(rng, 0, 6)),
			};
			for (ext, files) in [(".db", false), (".files", true)] {
				let path = fx.sync_file(repo, ext);
				match &db {
					DbFile::Absent => {}
					DbFile::Empty => {
						fs::write(path, b"").unwrap()
					}
					DbFile::Truncated => {
						let pkgs = gen_pkgs(
							&mut Rng::new(7),
							1,
							2,
						);
						let mut tar =
							sync_tar(&pkgs, files);
						tar.truncate(700);
						fs::write(path, tar).unwrap();
					}
					DbFile::Valid(pkgs) => fs::write(
						path,
						sync_tar(pkgs, files),
					)
					.unwrap(),
				}
			}
			writeln!(log, "{repo}: {db:?}").unwrap();
			dbs.push(db);
		}

		// installed: some names, versions often matching a repo's
		fx.reset_local();
		let mut entries = Vec::new();
		for name in NAMES {
			if rng.below(3) != 0 {
				continue;
			}
			let synced = dbs.iter().find_map(|d| match d {
				DbFile::Valid(p) => {
					p.iter().find(|p| p.name == name)
				}
				_ => None,
			});
			let version = match synced {
				Some(p) if rng.below(3) != 0 => {
					p.version.clone()
				}
				_ => version(rng),
			};
			let groups: Vec<String> = (0..rng.below(2))
				.map(|_| pick(rng, &GROUPS).to_string())
				.collect();
			let desc = local_desc(name, &version, &groups);
			writeln!(log, "local: {name} {version}").unwrap();
			entries.push(LocalEntry {
				dir: format!("{name}-{version}"),
				desc: Some(desc.into_bytes()),
				files: None,
				install: false,
			});
		}
		fx.write_local(&entries);
		SyncWorld {
			fx,
			repos,
			dbs,
			log,
		}
	}

	// C handle on this world with dbext
	pub fn c_handle(&self, dbext: &[u8]) -> FrontHandle {
		FrontHandle::open(
			&self.fx.root(),
			&self.fx.dbpath(),
			dbext,
			&self.repos,
		)
	}

	// names of the packages in valid repos, for targets
	pub fn pkg_names(&self) -> Vec<&str> {
		let mut out = Vec::new();
		for d in &self.dbs {
			if let DbFile::Valid(pkgs) = d {
				out.extend(pkgs
					.iter()
					.map(|p| p.name.as_str()));
			}
		}
		out
	}
}
