// unit tests for pacman_cli::package, the parts the C comparison cannot
// reach (gpgme results, checksum failures, changelogs)
use alpm_core::backup::Backup;
use alpm_core::deps::dep_from_string;
use alpm_core::error::Errno;
use alpm_core::package::{DbCaches, Package, PkgFrom};
use alpm_core::util::hash_sdbm;
use pacman_cli::package::*;
use pacman_cli::util::{ColStr, SigResult, SigStatus, SigValidity};

struct Env {
	sig: Option<Result<Vec<SigResult>, Errno>>,
	probe: Option<FileProbe>,
	changelog: Option<Vec<u8>>,
	errors: Vec<Vec<u8>>,
	dependent: Package,
}

impl Default for Env {
	fn default() -> Self {
		Env {
			sig: None,
			probe: None,
			changelog: None,
			errors: Vec::new(),
			dependent: Package {
				name: Some(b"dependent"[..].into()),
				depends: vec![dep_from_string(b"foo")].into(),
				..Package::default()
			},
		}
	}
}

impl DbCaches for Env {
	// "dependent" depends on foo
	fn local_cache(&mut self) -> Vec<&Package> {
		vec![&self.dependent]
	}

	fn sync_caches(&mut self) -> Vec<Vec<&Package>> {
		Vec::new()
	}
}

impl PkgEnv for Env {
	fn db_name(&mut self, _: &Package) -> Option<Vec<u8>> {
		None
	}

	// TZ=UTC, whatever the test's zone
	fn format_date(&mut self, t: i64) -> Option<Vec<u8>> {
		format_date_at(t, 0)
	}

	fn sig_keys(&mut self, _: &Package, _: &[u8]) -> Vec<Vec<u8>> {
		Vec::new()
	}

	fn check_signature(
		&mut self,
		_: &Package,
	) -> Result<Vec<SigResult>, Errno> {
		self.sig.clone().unwrap()
	}

	fn root(&mut self) -> Vec<u8> {
		b"/r/".to_vec()
	}

	fn probe_file(&mut self, _: &[u8]) -> FileProbe {
		self.probe.clone().unwrap()
	}

	fn changelog(&mut self, _: &Package) -> Option<Vec<u8>> {
		self.changelog.clone()
	}

	fn error(&mut self, msg: &[u8]) {
		self.errors.push(msg.to_vec());
	}
}

fn pkg(origin: Option<PkgFrom>) -> Package {
	Package {
		name_hash: hash_sdbm(b"foo"),
		name: Some(b"foo"[..].into()),
		version: Some(b"1-1"[..].into()),
		builddate: -1,
		installdate: -1,
		origin,
		..Package::default()
	}
}

fn full(env: &mut Env, p: &Package, extra: bool) -> String {
	let mut out = Vec::new();
	dump_pkg_full(&mut out, env, p, extra, 80, &ColStr::PLAIN);
	String::from_utf8(out).unwrap()
}

fn line<'a>(out: &'a str, title: &str) -> Option<&'a str> {
	out.lines().find(|l| l.starts_with(title))
}

#[test]
fn dates() {
	let d = |t| String::from_utf8(format_date_at(t, 0).unwrap()).unwrap();
	assert_eq!(d(0), "Thu Jan  1 00:00:00 1970");
	assert_eq!(d(1_700_000_000), "Tue Nov 14 22:13:20 2023");
	assert_eq!(d(-1), "Wed Dec 31 23:59:59 1969");
	// year 0 and before, no padding
	assert_eq!(d(-62_167_219_200), "Sat Jan  1 00:00:00 0");
	assert_eq!(d(-62_198_755_200), "Fri Jan  1 00:00:00 -1");
	assert_eq!(d(253_402_300_799), "Fri Dec 31 23:59:59 9999");
	assert_eq!(d(253_402_300_800), "Sat Jan  1 00:00:00 10000");
	assert_eq!(d(-377_705_116_801), "Sun Dec 31 23:59:59 -10000");
	// the last year localtime takes; %Y's tm_year + 1900 wraps in int
	// like glibc's
	assert_eq!(
		d(67_768_036_191_676_799),
		"Wed Dec 31 23:59:59 -2147481749"
	);
	// tm_year past int: localtime fails
	assert_eq!(format_date_at(67_768_036_191_676_800, 0), None);
	assert_eq!(format_date_at(i64::MAX, 0), None);
}

#[test]
fn titles_and_empty_values() {
	let mut env = Env::default();
	let out = full(&mut env, &pkg(None), false);
	let first = out.lines().next().unwrap();
	// widest msgid is "Compressed Size"
	assert_eq!(first, "Name            : foo");
	assert_eq!(line(&out, "Build Date").unwrap(), "Build Date      : None");
	assert_eq!(
		line(&out, "Validated By").unwrap(),
		"Validated By    : Unknown"
	);
	assert!(line(&out, "Repository").is_none());
	assert!(line(&out, "Required By").is_none());
	assert!(out.ends_with("\n\n"));
	// MD5SUM alone has no text
	let p = Package {
		validation: 2,
		..pkg(None)
	};
	let out = full(&mut env, &p, false);
	assert_eq!(
		line(&out, "Validated By").unwrap(),
		"Validated By    : None"
	);
}

#[test]
fn file_signatures() {
	let p = pkg(Some(PkgFrom::File(b"/x.pkg"[..].into())));
	let mut env = Env {
		sig: Some(Err(Errno::SigMissing)),
		..Env::default()
	};
	let out = full(&mut env, &p, false);
	assert_eq!(line(&out, "Signatures").unwrap(), "Signatures      : None");
	env.sig = Some(Err(Errno::NotAFile));
	let out = full(&mut env, &p, false);
	assert_eq!(
		line(&out, "Signatures").unwrap(),
		"Signatures      : could not find or read file"
	);
	env.sig = Some(Ok(vec![SigResult {
		status: SigStatus::Valid,
		validity: SigValidity::Full,
		uid: Some(b"Me <me@x>".to_vec()),
		fingerprint: b"ABCD".to_vec(),
	}]));
	let out = full(&mut env, &p, false);
	assert_eq!(
		line(&out, "Signatures").unwrap(),
		"Signatures      : Valid, full trust from \"Me <me@x>\""
	);
	// the reverse dependencies are only asked with -ii for file origins
	assert!(line(&out, "Required By").is_none());
	let out = full(&mut env, &p, true);
	assert_eq!(
		line(&out, "Required By").unwrap(),
		"Required By     : dependent"
	);
}

#[test]
fn backup_states() {
	let p = Package {
		backup: vec![
			Backup {
				name: b"etc/a"[..].into(),
				hash: Some(b"abc"[..].into()),
			},
			Backup {
				name: b"etc/nohash"[..].into(),
				hash: None,
			},
		]
		.into(),
		..pkg(Some(PkgFrom::LocalDb))
	};
	let cases = [
		(FileProbe::Readable(Some(b"abc".to_vec())), "[unmodified]"),
		(FileProbe::Readable(Some(b"abd".to_vec())), "[modified]"),
		(FileProbe::Denied, "[unreadable]"),
		(FileProbe::Missing, "[missing]"),
		(FileProbe::Failed, "[unknown]"),
	];
	for (probe, state) in cases {
		let mut env = Env {
			probe: Some(probe),
			..Env::default()
		};
		let mut out = Vec::new();
		dump_pkg_backups(&mut out, &mut env, &p, 80, &ColStr::PLAIN);
		let want = format!("Backup Files    : /r/etc/a {state}\n");
		assert_eq!(String::from_utf8(out).unwrap(), want);
	}
	// checksum failure: logged and left out, the C crashes there
	let mut env = Env {
		probe: Some(FileProbe::Readable(None)),
		..Env::default()
	};
	let out = full(&mut env, &p, true);
	assert_eq!(
		line(&out, "Backup Files").unwrap(),
		"Backup Files    : None"
	);
	assert_eq!(
		env.errors,
		[b"could not calculate checksums for /r/etc/a\n"]
	);
}

#[test]
fn changelog() {
	let p = pkg(None);
	let mut env = Env::default();
	let mut out = Vec::new();
	dump_pkg_changelog(&mut out, &mut env, &p);
	assert!(out.is_empty());
	assert_eq!(env.errors, [b"no changelog available for 'foo'.\n"]);
	env.changelog = Some(b"* 1-1\n".to_vec());
	dump_pkg_changelog(&mut out, &mut env, &p);
	assert_eq!(out, b"Changelog for foo:\n* 1-1\n\n");
}

#[test]
fn installed_groups_files() {
	let p = Package {
		groups: vec![b"g1"[..].into(), b"g2"[..].into()].into(),
		..pkg(None)
	};
	let mut out = Vec::new();
	print_installed(&mut out, None, &p, &ColStr::PLAIN);
	assert!(out.is_empty());
	print_installed(&mut out, Some(&p), &p, &ColStr::PLAIN);
	let other = Package {
		version: Some(b"2-1"[..].into()),
		..pkg(None)
	};
	print_installed(&mut out, Some(&other), &p, &ColStr::PLAIN);
	print_groups(&mut out, &p, &ColStr::PLAIN);
	assert_eq!(out, b" [installed] [installed: 2-1] (g1 g2)");
}

#[test]
fn search() {
	let p = Package {
		desc: Some(b"text"[..].into()),
		..pkg(None)
	};
	let mut out = Vec::new();
	let cs = ColStr::PLAIN;
	assert!(!dump_pkg_search(
		&mut out,
		b"core",
		&[],
		None,
		false,
		80,
		&cs
	));
	assert!(out.is_empty());
	assert!(dump_pkg_search(
		&mut out,
		b"core",
		&[&p],
		None,
		true,
		80,
		&cs
	));
	assert_eq!(out, b"foo\n");
	out.clear();
	let find = |_: &[u8]| Some(&p);
	let found = dump_pkg_search(
		&mut out,
		b"core",
		&[&p],
		Some(&find),
		false,
		80,
		&cs,
	);
	assert!(found);
	assert_eq!(out, b"core/foo 1-1 [installed]\n    text\n");
}
