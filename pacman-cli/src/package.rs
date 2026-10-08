// port of src/pacman/package.c: package details for -Qi/-Si (-ii/-Sii),
// backup file states, -Ql file lists, -Qc changelogs and the -Ss/-Qs
// search lines
//
// output is appended to `out` like util.rs. what the C asks libalpm or
// the system for (the db caches reverse dependencies and satisfiers are
// computed from, the db of a sync package, keyids of a signature, gpgme
// checks, files under the root, the changelog, the local time) goes
// through PkgEnv, so this needs no handle or db.
// messages and titles are the untranslated msgids, gettext is not ported.
//
// dates: the C formats with strftime("%c") on localtime(), so the output
// follows LC_TIME and TZ. format_date_utc is that for LC_TIME=C.UTF-8
// (and C) with TZ=UTC; PkgEnv::format_date is where another time zone or
// locale plugs in.

use alpm_core::backup::Backup;
use alpm_core::deps::{Depend, dep_compute_string, find_satisfier};
use alpm_core::error::Errno;
use alpm_core::package::{
	DbCaches, PKG_VALIDATION_NONE, PKG_VALIDATION_SHA256SUM,
	PKG_VALIDATION_SIGNATURE, Package, PkgFrom, PkgReason,
	compute_optionalfor, compute_requiredby,
};
use alpm_core::util::until_nul;
use time::OffsetDateTime;

use crate::util::{
	ColStr, SigResult, humanize_size, indentprint, list_display,
	list_display_linebreak, signature_display, string_display,
	string_length,
};

// access(path, R_OK), then alpm_compute_md5sum when readable
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileProbe {
	// readable, the hex md5 or None when the checksum failed
	Readable(Option<Vec<u8>>),
	// EACCES
	Denied,
	// ENOENT
	Missing,
	// any other errno
	Failed,
}

// the libalpm and system calls of package.c, implemented by the caller.
// reverse dependencies and satisfiers are computed here from the db
// caches (DbCaches)
pub trait PkgEnv: DbCaches {
	// alpm_db_get_name(alpm_pkg_get_db(pkg)), None for NULL
	fn db_name(&mut self, pkg: &Package) -> Option<Vec<u8>>;
	// alpm_decode_signature + alpm_extract_keyid: keyids found before
	// the first error, none if the base64 does not decode
	fn sig_keys(
		&mut self,
		pkg: &Package,
		base64_sig: &[u8],
	) -> Vec<Vec<u8>>;
	// alpm_pkg_check_pgp_signature, Err is the pm_errno it leaves
	fn check_signature(
		&mut self,
		pkg: &Package,
	) -> Result<Vec<SigResult>, Errno>;
	// alpm_option_get_root
	fn root(&mut self) -> Vec<u8>;
	// access + alpm_compute_md5sum on a path under the root
	fn probe_file(&mut self, path: &[u8]) -> FileProbe;
	// alpm_pkg_changelog_open/read, None when there is none
	fn changelog(&mut self, pkg: &Package) -> Option<Vec<u8>>;
	// pm_printf(ALPM_LOG_ERROR, msg), msg ends in '\n'
	fn error(&mut self, msg: &[u8]);
	// strftime("%c", localtime(&t)); None where localtime fails
	fn format_date(&mut self, t: i64) -> Option<Vec<u8>> {
		format_date_utc(t)
	}
	// alpm_pkg_get_validation: the stored value, a sync db computes it
	// on first use
	fn validation(&mut self, pkg: &Package) -> i32 {
		pkg.validation
	}
	// alpm_pkg_has_scriptlet: a local package lazy-loads it here
	fn has_scriptlet(&mut self, pkg: &Package) -> bool {
		pkg.scriptlet != 0
	}
	// alpm_pkg_get_backup: a local package lazy-loads its files here
	fn backup(&mut self, pkg: &Package) -> Vec<Backup> {
		pkg.backup.clone()
	}
}

// the C title enum, alphabetical like the msgids
#[derive(Clone, Copy)]
enum T {
	Architecture,
	BackupFiles,
	BuildDate,
	CompressedSize,
	ConflictsWith,
	DependsOn,
	Description,
	DownloadSize,
	Groups,
	InstallDate,
	InstallReason,
	InstallScript,
	InstalledSize,
	Licenses,
	Name,
	OptionalDeps,
	OptionalFor,
	Packager,
	Provides,
	Replaces,
	Repository,
	RequiredBy,
	Sha256Sum,
	Signatures,
	Url,
	ValidatedBy,
	Version,
}

const LABELS: [&str; 27] = [
	"Architecture",
	"Backup Files",
	"Build Date",
	"Compressed Size",
	"Conflicts With",
	"Depends On",
	"Description",
	"Download Size",
	"Groups",
	"Install Date",
	"Install Reason",
	"Install Script",
	"Installed Size",
	"Licenses",
	"Name",
	"Optional Deps",
	"Optional For",
	"Packager",
	"Provides",
	"Replaces",
	"Repository",
	"Required By",
	"SHA-256 Sum",
	"Signatures",
	"URL",
	"Validated By",
	"Version",
];

// make_aligned_titles: each label padded with spaces to the widest one
// (display columns), then " :". the C truncates labels at 50 characters,
// none of the msgids comes close
struct Titles(Vec<Vec<u8>>);

impl Titles {
	fn new() -> Self {
		let widths = LABELS.map(|l| string_length(l.as_bytes()));
		let maxcol = widths.iter().copied().max().unwrap_or(0);
		let titles = LABELS
			.iter()
			.zip(widths)
			.map(|(l, w)| {
				let mut t = l.as_bytes().to_vec();
				t.resize(t.len() + (maxcol - w), b' ');
				t.extend_from_slice(b" :");
				t
			})
			.collect();
		Titles(titles)
	}

	fn get(&self, t: T) -> Option<&[u8]> {
		Some(&self.0[t as usize])
	}
}

// strftime("%c", localtime(&t)) with TZ=UTC in the C.UTF-8 (or C) locale:
// "%a %b %e %H:%M:%S %Y", the English names cut to 3 letters. %Y is the
// plain year, no padding, '-' for years before 1. None outside the years
// time covers (-9999 to 9999), where glibc localtime goes on to tm_year
// (year - 1900) past int
pub fn format_date_utc(t: i64) -> Option<Vec<u8>> {
	let d = OffsetDateTime::from_unix_timestamp(t).ok()?;
	let s = format!(
		"{:.3} {:.3} {:>2} {:02}:{:02}:{:02} {}",
		d.weekday(),
		d.month(),
		d.day(),
		d.hour(),
		d.minute(),
		d.second(),
		d.year(),
	);
	Some(s.into_bytes())
}

// deplist_display
fn deplist_display(
	out: &mut Vec<u8>,
	title: Option<&[u8]>,
	deps: &[Depend],
	cols: u16,
	colstr: &ColStr,
) {
	let text: Vec<Vec<u8>> = deps.iter().map(dep_compute_string).collect();
	list_display(out, title, &text, cols, colstr);
}

// optdeplist_display: local packages mark satisfied optdepends
fn optdeplist_display(
	out: &mut Vec<u8>,
	env: &mut impl PkgEnv,
	pkg: &Package,
	title: Option<&[u8]>,
	cols: u16,
	colstr: &ColStr,
) {
	let local = pkg.origin == Some(PkgFrom::LocalDb);
	let text: Vec<Vec<u8>> = pkg
		.optdepends
		.iter()
		.map(|d| {
			let mut s = dep_compute_string(d);
			if local && find_satisfier(env.local_cache(), &s)
				.is_some()
			{
				s.extend_from_slice(b" [installed]");
			}
			s
		})
		.collect();
	list_display_linebreak(out, title, &text, cols, colstr);
}

fn validation_list(v: i32) -> Vec<&'static [u8]> {
	let mut list: Vec<&[u8]> = Vec::new();
	if v == 0 {
		list.push(b"Unknown");
	} else if v & PKG_VALIDATION_NONE != 0 {
		list.push(b"None");
	} else {
		// MD5SUM alone leaves the list empty
		if v & PKG_VALIDATION_SHA256SUM != 0 {
			list.push(b"SHA-256 Sum");
		}
		if v & PKG_VALIDATION_SIGNATURE != 0 {
			list.push(b"Signature");
		}
	}
	list
}

// "<title> %.2f <unit>\n"
fn size_line(
	out: &mut Vec<u8>,
	title: &[u8],
	size: (f64, &str),
	colstr: &ColStr,
) {
	out.extend_from_slice(until_nul(colstr.title));
	out.extend_from_slice(title);
	out.extend_from_slice(until_nul(colstr.nocolor));
	out.extend_from_slice(
		format!(" {:.2} {}\n", size.0, size.1).as_bytes(),
	);
}

fn opt(s: &Option<Vec<u8>>) -> &[u8] {
	s.as_deref().unwrap_or_default()
}

// dump_pkg_full: the -i view. extra (-ii) adds reverse dependencies for
// every origin, keyids for sync packages, backup file states for local
// ones and the extended data
pub fn dump_pkg_full(
	out: &mut Vec<u8>,
	env: &mut impl PkgEnv,
	pkg: &Package,
	extra: bool,
	cols: u16,
	colstr: &ColStr,
) {
	let t = Titles::new();
	let from = pkg.origin.as_ref();
	let local = from == Some(&PkgFrom::LocalDb);
	let sync = from == Some(&PkgFrom::SyncDb);
	let file = matches!(from, Some(PkgFrom::File(_)));

	// -1 means unset, any other value goes through localtime
	let mut date = |d: i64| {
		if d == -1 {
			return Vec::new();
		}
		env.format_date(d).unwrap_or_default()
	};
	let bdate = date(pkg.builddate);
	let idate = date(pkg.installdate);
	let reason: &[u8] = match pkg.reason {
		PkgReason::Explicit => b"Explicitly installed",
		PkgReason::Depend => {
			b"Installed as a dependency for another package"
		}
		PkgReason::Unknown => b"Unknown",
	};
	let validation = validation_list(env.validation(pkg));
	// computed before any output, like the C
	let (requiredby, optionalfor) = if extra || local {
		(compute_requiredby(pkg, env), compute_optionalfor(pkg, env))
	} else {
		(Vec::new(), Vec::new())
	};

	let s = |out: &mut Vec<u8>, title: T, v: &[u8]| {
		string_display(out, t.get(title), v, cols, colstr)
	};
	if sync {
		let db = env.db_name(pkg);
		s(out, T::Repository, opt(&db));
	}
	s(out, T::Name, opt(&pkg.name));
	s(out, T::Version, opt(&pkg.version));
	s(out, T::Description, opt(&pkg.desc));
	s(out, T::Architecture, opt(&pkg.arch));
	s(out, T::Url, opt(&pkg.url));
	list_display(out, t.get(T::Licenses), &pkg.licenses, cols, colstr);
	list_display(out, t.get(T::Groups), &pkg.groups, cols, colstr);
	deplist_display(out, t.get(T::Provides), &pkg.provides, cols, colstr);
	deplist_display(out, t.get(T::DependsOn), &pkg.depends, cols, colstr);
	optdeplist_display(out, env, pkg, t.get(T::OptionalDeps), cols, colstr);
	if extra || local {
		list_display(
			out,
			t.get(T::RequiredBy),
			&requiredby,
			cols,
			colstr,
		);
		list_display(
			out,
			t.get(T::OptionalFor),
			&optionalfor,
			cols,
			colstr,
		);
	}
	deplist_display(
		out,
		t.get(T::ConflictsWith),
		&pkg.conflicts,
		cols,
		colstr,
	);
	deplist_display(out, t.get(T::Replaces), &pkg.replaces, cols, colstr);

	// local (and unset) origins autodetect the unit of Installed Size,
	// the others reuse the unit of their download/compressed size
	let mut unit = 0;
	let size = humanize_size(pkg.size, 0, 2);
	if sync || file {
		let title = if sync {
			T::DownloadSize
		} else {
			T::CompressedSize
		};
		size_line(out, &t.0[title as usize], size, colstr);
		unit = size.1.as_bytes()[0];
	}
	let isize = humanize_size(pkg.isize, unit, 2);
	size_line(out, &t.0[T::InstalledSize as usize], isize, colstr);

	s(out, T::Packager, opt(&pkg.packager));
	s(out, T::BuildDate, &bdate);
	if local {
		s(out, T::InstallDate, &idate);
		s(out, T::InstallReason, reason);
	}
	if file || local {
		let yes: &[u8] = if env.has_scriptlet(pkg) {
			b"Yes"
		} else {
			b"No"
		};
		s(out, T::InstallScript, yes);
	}

	if sync && extra {
		let keys = match &pkg.base64_sig {
			Some(sig) => env.sig_keys(pkg, until_nul(sig)),
			None => vec![b"None".to_vec()],
		};
		s(out, T::Sha256Sum, opt(&pkg.sha256sum));
		list_display(out, t.get(T::Signatures), &keys, cols, colstr);
	} else {
		let title = t.get(T::ValidatedBy);
		list_display(out, title, &validation, cols, colstr);
	}

	if file {
		match env.check_signature(pkg) {
			Err(Errno::SigMissing) => {
				s(out, T::Signatures, b"None")
			}
			Err(e) => {
				s(out, T::Signatures, e.strerror().as_bytes())
			}
			Ok(sigs) => {
				let title = t.get(T::Signatures);
				signature_display(
					out, title, &sigs, cols, colstr,
				)
			}
		}
	}

	if local && extra {
		backups(out, env, pkg, t.get(T::BackupFiles), cols, colstr);
	}

	if extra {
		let text: Vec<Vec<u8>> = pkg
			.xdata
			.iter()
			.map(|x| {
				let (n, v) = (
					until_nul(&x.name),
					until_nul(&x.value),
				);
				[n, b"=", v].concat()
			})
			.collect();
		// not one of the aligned titles in the C
		let title = Some(&b"Extended Data   :"[..]);
		list_display_linebreak(out, title, &text, cols, colstr);
	}

	// final newline to separate packages
	out.push(b'\n');
}

// get_backup_file_status. None where the C has no status: the checksum
// failed, the C logs it and then passes NULL to strlen
fn backup_file_status(
	env: &mut impl PkgEnv,
	path: &[u8],
	hash: &[u8],
) -> Option<&'static [u8]> {
	// snprintf into char[PATH_MAX]
	let path = &path[..path.len().min(4095)];
	let status: &[u8] = match env.probe_file(path) {
		FileProbe::Readable(Some(md5)) if until_nul(&md5) == hash => {
			b"[unmodified]"
		}
		FileProbe::Readable(Some(_)) => b"[modified]",
		FileProbe::Readable(None) => {
			let msg = [
				b"could not calculate checksums for ",
				path,
				b"\n",
			];
			env.error(&msg.concat());
			return None;
		}
		FileProbe::Denied => b"[unreadable]",
		FileProbe::Missing => b"[missing]",
		FileProbe::Failed => b"[unknown]",
	};
	Some(status)
}

fn backups(
	out: &mut Vec<u8>,
	env: &mut impl PkgEnv,
	pkg: &Package,
	title: Option<&[u8]>,
	cols: u16,
	colstr: &ColStr,
) {
	let root = env.root();
	let root = until_nul(&root);
	let mut text = Vec::new();
	// entries without a hash are not backup files to check
	for b in &env.backup(pkg) {
		let Some(hash) = &b.hash else {
			continue;
		};
		let path = [root, until_nul(&b.name)].concat();
		let Some(status) =
			backup_file_status(env, &path, until_nul(hash))
		else {
			continue;
		};
		text.push([&path[..], b" ", status].concat());
	}
	list_display_linebreak(out, title, &text, cols, colstr);
}

// dump_pkg_backups: "<root><file> [state]" per backup entry with a hash
pub fn dump_pkg_backups(
	out: &mut Vec<u8>,
	env: &mut impl PkgEnv,
	pkg: &Package,
	cols: u16,
	colstr: &ColStr,
) {
	let t = Titles::new();
	backups(out, env, pkg, t.get(T::BackupFiles), cols, colstr);
}

// dump_pkg_files: "<name> <root><file>" per file, the name left out when
// quiet
pub fn dump_pkg_files(
	out: &mut Vec<u8>,
	pkg: &Package,
	root: &[u8],
	quiet: bool,
	colstr: &ColStr,
) {
	let root = until_nul(root);
	for f in &pkg.files.files {
		if !quiet {
			out.extend_from_slice(until_nul(colstr.title));
			out.extend_from_slice(pkg.name_bytes());
			out.extend_from_slice(until_nul(colstr.nocolor));
			out.push(b' ');
		}
		out.extend_from_slice(root);
		out.extend_from_slice(until_nul(&f.name));
		out.push(b'\n');
	}
}

// dump_pkg_changelog: the changelog bytes as read, then a newline
pub fn dump_pkg_changelog(
	out: &mut Vec<u8>,
	env: &mut impl PkgEnv,
	pkg: &Package,
) {
	let name = pkg.name_bytes();
	let Some(log) = env.changelog(pkg) else {
		let msg = [b"no changelog available for '", name, b"'.\n"];
		env.error(&msg.concat());
		return;
	};
	out.extend_from_slice(b"Changelog for ");
	out.extend_from_slice(name);
	out.extend_from_slice(b":\n");
	out.extend_from_slice(&log);
	out.push(b'\n');
}

// print_installed: local is the package of the same name in the local
// db, if any. the C strcmps the versions, NULL reads as empty here
pub fn print_installed(
	out: &mut Vec<u8>,
	local: Option<&Package>,
	pkg: &Package,
	colstr: &ColStr,
) {
	let Some(lpkg) = local else {
		return;
	};
	let lver = until_nul(opt(&lpkg.version));
	out.push(b' ');
	out.extend_from_slice(until_nul(colstr.meta));
	out.extend_from_slice(b"[installed");
	if lver != until_nul(opt(&pkg.version)) {
		out.extend_from_slice(b": ");
		out.extend_from_slice(lver);
	}
	out.push(b']');
	out.extend_from_slice(until_nul(colstr.nocolor));
}

// print_groups: " (g1 g2)", nothing without groups
pub fn print_groups(out: &mut Vec<u8>, pkg: &Package, colstr: &ColStr) {
	if pkg.groups.is_empty() {
		return;
	}
	out.push(b' ');
	out.extend_from_slice(until_nul(colstr.groups));
	out.push(b'(');
	let groups: Vec<&[u8]> =
		pkg.groups.iter().map(|g| until_nul(g)).collect();
	out.extend_from_slice(&groups.join(&b' '));
	out.push(b')');
	out.extend_from_slice(until_nul(colstr.nocolor));
}

// alpm_db_get_pkg on the local db: the package of that name, if any
pub type LocalLookup<'a> = dyn Fn(&[u8]) -> Option<&'a Package> + 'a;

// dump_pkg_search: one entry per package of results (the alpm_db_search
// matches, or the whole db cache without targets), in that order.
// local is given for show_status. false when there is nothing to show
// (the C returns 1); a failed search (-1) stays with the caller
pub fn dump_pkg_search<'a>(
	out: &mut Vec<u8>,
	db_name: &[u8],
	results: &[&Package],
	local: Option<&LocalLookup<'a>>,
	quiet: bool,
	cols: u16,
	colstr: &ColStr,
) -> bool {
	if results.is_empty() {
		return false;
	}
	for pkg in results {
		if quiet {
			out.extend_from_slice(pkg.name_bytes());
			out.push(b'\n');
			continue;
		}
		let parts = [
			colstr.repo,
			db_name,
			b"/",
			colstr.title,
			pkg.name_bytes(),
			b" ",
			colstr.version,
			opt(&pkg.version),
			colstr.nocolor,
		];
		for p in parts {
			out.extend_from_slice(until_nul(p));
		}
		print_groups(out, pkg, colstr);
		if let Some(find) = local {
			print_installed(
				out,
				find(pkg.name_bytes()),
				pkg,
				colstr,
			);
		}
		// newline and initial indent first
		out.extend_from_slice(b"\n    ");
		if let Some(desc) = &pkg.desc {
			indentprint(out, desc, 4, cols);
		}
		out.push(b'\n');
	}
	true
}
