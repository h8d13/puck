// port of src/pacman/files.c: -F (owner search by file name or path),
// -Fx (the same with POSIX EREs), -Fl (file lists), -Fq, and
// --machinereadable, on the sync dbs. pacman reads those from the .files
// dbs: the caller sets handle's dbext to ".files" before registering
// them, like setup_libalpm does for -F.
//
// output goes into an Output like sync.rs, messages are the untranslated
// msgids. -Fy is sync.rs's sync_syncdbs.

use alpm_core::callbacks::Callbacks;
use alpm_core::db::Db;
use alpm_core::handle::Handle;
use alpm_core::package::Package;
use alpm_core::regex::{Flags, Regex};
use alpm_core::util::until_nul;

use crate::conf::{Config, cat};
use crate::package::{print_groups, print_installed};
use crate::sync::{cache_list, error, refresh};
use crate::util::{Output, check_syncdbs};

// print_line_machinereadable: repo, name, version, file, nul separated
fn machine_line(out: &mut Vec<u8>, repo: &[u8], pkg: &Package, file: &[u8]) {
	let version = pkg.version.as_deref().unwrap_or_default();
	out.extend(cat(&[
		repo,
		b"\0",
		pkg.name_bytes(),
		b"\0",
		until_nul(version),
		b"\0",
		until_nul(file),
		b"\n",
	]));
}

// a package with its matching files, printed once the db is searched
struct Match<'p> {
	pkg: &'p Package,
	files: Vec<Vec<u8>>,
}

// handle->db_local with what alpm_db_get_pkg on it takes
struct Local<'h> {
	db: Option<&'h mut Db>,
	dbext: &'h [u8],
	cb: &'h mut dyn Callbacks,
}

// print_match
fn print_match(
	config: &Config,
	local: &mut Local,
	repo: &[u8],
	m: &Match,
	exact_file: bool,
	out: &mut Vec<u8>,
) {
	let c = &config.colstr;
	let pkg = m.pkg;
	if config.op_f_machinereadable != 0 {
		for f in &m.files {
			machine_line(out, repo, pkg, f);
		}
	} else if config.quiet != 0 {
		out.extend(cat(&[repo, b"/", pkg.name_bytes(), b"\n"]));
	} else if exact_file {
		let version = pkg.version.as_deref().unwrap_or_default();
		for f in &m.files {
			out.extend(cat(&[
				until_nul(f),
				b" is owned by ",
				c.repo,
				repo,
				b"/",
				c.title,
				pkg.name_bytes(),
				b" ",
				c.version,
				until_nul(version),
				c.nocolor,
				b"\n",
			]));
		}
	} else {
		let version = pkg.version.as_deref().unwrap_or_default();
		out.extend(cat(&[
			c.repo,
			repo,
			b"/",
			c.title,
			pkg.name_bytes(),
			b" ",
			c.version,
			until_nul(version),
			c.nocolor,
		]));
		print_groups(out, pkg, c);
		let (dbext, name) = (local.dbext, pkg.name_bytes());
		let local = local
			.db
			.as_deref_mut()
			.and_then(|l| l.get_pkg(dbext, local.cb, name).ok());
		print_installed(out, local, pkg, c);
		out.push(b'\n');
		for f in &m.files {
			out.extend(cat(&[b"    ", until_nul(f), b"\n"]));
		}
	}
}

// struct filetarget
struct FileTarget<'a> {
	targ: &'a [u8],
	exact_file: bool,
	reg: Option<Regex>,
}

// the files of pkg that ftarg matches: a target with '/' is a path
// (regex: matched against whole paths), else a file name compared with
// the part after the last '/' (paths ending in '/' and top-level names
// have none)
fn matches(ftarg: &FileTarget, pkg: &Package) -> Vec<Vec<u8>> {
	let files = &pkg.files;
	if ftarg.exact_file && ftarg.reg.is_none() {
		return match files.contains(ftarg.targ) {
			Some(_) => vec![ftarg.targ.to_vec()],
			None => Vec::new(),
		};
	}
	let hit = |s: &[u8]| match &ftarg.reg {
		Some(r) => r.is_match(s),
		None => s == ftarg.targ,
	};
	let mut found = Vec::new();
	for f in &files.files {
		let name = until_nul(&f.name);
		let s = match ftarg.exact_file {
			true => name,
			false => match name.iter().rposition(|&c| c == b'/') {
				Some(i) if i + 1 < name.len() => &name[i + 1..],
				_ => continue,
			},
		};
		if hit(s) {
			found.push(name.to_vec());
		}
	}
	found
}

// files_search: every target compiled first (a bad regex reports and
// fails the whole search), then searched in every db; 1 when one of
// them matches nothing
pub fn files_search<S: AsRef<[u8]>>(
	config: &Config,
	handle: &mut Handle,
	targets: &[S],
	regex: bool,
	out: &mut Output,
) -> i32 {
	let mut ret = 0;
	let mut ftargs = Vec::new();
	for t in targets {
		let mut targ = until_nul(t.as_ref());
		let exact_file = targ.contains(&b'/');
		if exact_file {
			// leading '/' dropped, a lone "/" stays
			while targ.len() > 1 && targ[0] == b'/' {
				targ = &targ[1..];
			}
		}
		let mut reg = None;
		if regex {
			let flags = Flags {
				icase: true,
				newline: true,
			};
			match Regex::new(targ, flags) {
				Ok(r) => reg = Some(r),
				Err(_) => {
					let msg: [&[u8]; 3] = [
						b"invalid regular expression '",
						targ,
						b"'\n",
					];
					error(out, config, &msg);
					ret = 1;
					continue;
				}
			}
		}
		ftargs.push(FileTarget {
			targ,
			exact_file,
			reg,
		});
	}
	if ret != 0 {
		return ret;
	}

	for ftarg in &ftargs {
		let mut found = false;
		let dbs = handle.dbs_mut();
		let mut local = Local {
			db: dbs.local,
			dbext: dbs.dbext,
			cb: dbs.cb,
		};
		for db in dbs.sync {
			let repo = db.name().to_vec();
			let hits: Vec<Match> =
				cache_list(db, local.dbext, local.cb)
					.into_iter()
					.filter_map(|p| {
						let files = matches(ftarg, p);
						(!files.is_empty()).then_some(
							Match { pkg: p, files },
						)
					})
					.collect();
			found |= !hits.is_empty();
			for m in &hits {
				let exact = ftarg.exact_file;
				let o = &mut out.stdout;
				print_match(
					config, &mut local, &repo, m, exact, o,
				);
			}
		}
		if !found {
			ret = 1;
		}
	}
	ret
}

// dump_file_list, or dump_pkg_machinereadable when asked
fn dump_files(config: &Config, repo: &[u8], pkg: &Package, out: &mut Vec<u8>) {
	let c = &config.colstr;
	for f in &pkg.files.files {
		if config.op_f_machinereadable != 0 {
			machine_line(out, repo, pkg, &f.name);
			continue;
		}
		if config.quiet == 0 {
			out.extend(cat(&[
				c.title,
				pkg.name_bytes(),
				c.nocolor,
				b" ",
			]));
		}
		out.extend(cat(&[until_nul(&f.name), b"\n"]));
	}
}

// files_list: "[repo/]name" targets, the first db holding the package
// lists it. "repo/" is an invalid package; every miss is reported and
// counted. without targets every package of every db
pub fn files_list<S: AsRef<[u8]>>(
	config: &Config,
	handle: &mut Handle,
	targets: &[S],
	out: &mut Output,
) -> i32 {
	if targets.is_empty() {
		let dbs = handle.dbs_mut();
		for db in dbs.sync {
			let repo = db.name().to_vec();
			for pkg in cache_list(db, dbs.dbext, dbs.cb) {
				dump_files(config, &repo, pkg, &mut out.stdout);
			}
		}
		return 0;
	}

	let mut ret = 0;
	for t in targets {
		let full = until_nul(t.as_ref());
		let (repo, targ) = match full.iter().position(|&c| c == b'/') {
			Some(i) if i + 1 == full.len() => {
				let msg: [&[u8]; 3] =
					[b"invalid package: '", full, b"'\n"];
				error(out, config, &msg);
				ret += 1;
				continue;
			}
			Some(i) => (Some(&full[..i]), &full[i + 1..]),
			None => (None, full),
		};
		let mut found = false;
		let dbs = handle.dbs_mut();
		for db in dbs.sync {
			if repo.is_some_and(|r| r != db.name()) {
				continue;
			}
			let repo = db.name().to_vec();
			// an empty name is WrongArgs, not found either
			if let Ok(pkg) = db.get_pkg(dbs.dbext, dbs.cb, targ) {
				dump_files(config, &repo, pkg, &mut out.stdout);
				found = true;
				break;
			}
		}
		if !found {
			let msg: [&[u8]; 3] =
				[b"package '", full, b"' was not found\n"];
			error(out, config, &msg);
			ret += 1;
		}
	}
	ret
}

// pacman_files, the C return value
pub fn pacman_files<S: AsRef<[u8]>>(
	config: &Config,
	handle: &mut Handle,
	targets: &[S],
	out: &mut Output,
) -> i32 {
	if check_syncdbs(&mut out.stderr, config, handle, true, false) != 0 {
		return 1;
	}
	if config.op_s_sync != 0 && !refresh(config, handle, out) {
		return 1;
	}
	if config.op_q_list != 0 {
		return files_list(config, handle, targets, out);
	}
	if targets.is_empty() && config.op_s_sync == 0 {
		let msg: &[u8] = b"no targets specified (use -h for help)\n";
		error(out, config, &[msg]);
		return 1;
	}
	let regex = config.op_f_regex != 0;
	files_search(config, handle, targets, regex, out)
}
