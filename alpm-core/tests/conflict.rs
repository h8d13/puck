// unit tests for alpm_core::conflict
use std::ffi::c_int;
use std::fs;

use alpm_core::callbacks::{Callbacks, Progress};
use alpm_core::conflict::*;
use alpm_core::deps::dep_from_string;
use alpm_core::filelist::{File, FileList};
use alpm_core::package::{Package, PkgFrom};
use alpm_core::pkghash::PkgHash;
use alpm_core::util::hash_sdbm;

fn pkg(name: &str, conflicts: &[&str], files: &[&str]) -> Package {
	let mut files: Vec<File> = files
		.iter()
		.map(|f| File::new(f.as_bytes().to_vec(), 0, 0))
		.collect();
	files.sort_by(|a, b| a.name().cmp(b.name()));
	Package {
		name_hash: hash_sdbm(name.as_bytes()),
		name: Some(name.as_bytes().to_vec()),
		version: Some(b"1.0-1".to_vec()),
		conflicts: conflicts
			.iter()
			.map(|c| dep_from_string(c.as_bytes()))
			.collect(),
		files: FileList { files },
		origin: Some(PkgFrom::SyncDb),
		..Package::default()
	}
}

fn local(pkgs: Vec<Package>) -> PkgHash<Package> {
	let mut h = PkgHash::new(pkgs.len() as u32).unwrap();
	for mut p in pkgs {
		p.origin = Some(PkgFrom::LocalDb);
		h.add_sorted(p).unwrap();
	}
	h
}

fn pairs(c: &[Conflict]) -> Vec<(&[u8], &[u8])> {
	c.iter().map(|c| (c.package1.name_bytes(), c.package2.name_bytes()))
		.collect()
}

#[test]
fn inner_dedups_by_name_pair() {
	let a = pkg("a", &["b", "a"], &[]);
	let b = pkg("b", &["a>=2"], &[]);
	let b2 = pkg("b", &["a"], &[]);
	let got = innerconflicts(&[&a, &b, &b2], &mut ());
	assert_eq!(pairs(&got), [(&b"a"[..], &b"b"[..]), (b"b", b"a")]);
	assert_eq!(got[1].reason, dep_from_string(b"a"));
	assert_eq!(checkconflicts(&[&a, &b, &b2], &mut ()), got);
}

#[test]
fn outer_checks_both_directions() {
	let db = local(vec![pkg("x", &["t"], &[]), pkg("t", &["u"], &[])]);
	let t = pkg("t", &[], &[]);
	let u = pkg("u", &["x"], &[]);
	// t replaces the local t, so only x takes part
	let got = outerconflicts(&db, &[&t, &u], &mut ());
	assert_eq!(pairs(&got), [(&b"u"[..], &b"x"[..]), (b"t", b"x")]);
}

#[derive(Default)]
struct Rec(Vec<(Progress, c_int, usize, usize)>);

impl Callbacks for Rec {
	fn progress(
		&mut self,
		p: Progress,
		pkg: &[u8],
		percent: c_int,
		howmany: usize,
		current: usize,
	) {
		assert!(pkg.is_empty());
		self.0.push((p, percent, howmany, current));
	}
}

#[test]
fn target_conflicts_and_progress() {
	let db = local(Vec::new());
	let check = FileCheck {
		root: b"/nonexistent-conflict-root/",
		local: &db,
		overwrite: &[],
	};
	let a = pkg("a", &[], &["usr/", "usr/f", "usr/d/"]);
	let b = pkg("b", &[], &["usr/", "usr/f", "usr/d"]);
	let c = pkg("c", &[], &["usr/"]);
	let mut rec = Rec::default();
	let got = check.find_fileconflicts(&[&a, &b, &c], &[], &mut rec);
	let files: Vec<&[u8]> =
		got.conflicts.iter().map(|c| &c.file[..]).collect();
	assert_eq!(
		files,
		[
			&b"/nonexistent-conflict-root/usr/d/"[..],
			b"/nonexistent-conflict-root/usr/f"
		]
	);
	assert_eq!(got.conflicts[0].conflict_type, FileConflictType::Target);
	let cs = Progress::ConflictsStart;
	assert_eq!(
		rec.0,
		[
			(cs, 0, 3, 0),
			(cs, 33, 3, 1),
			(cs, 66, 3, 2),
			(cs, 100, 3, 3)
		]
	);

	// overwrite skips the file-file pair only
	let globs = [b"usr/*".to_vec()];
	let check = FileCheck {
		overwrite: &globs,
		..check
	};
	let got = check.find_fileconflicts(&[&a, &b], &[], &mut ());
	assert_eq!(got.conflicts.len(), 1);
	assert!(check
		.find_fileconflicts(&[], &[], &mut rec)
		.conflicts
		.is_empty());
}

#[test]
fn filesystem_conflict_owner() {
	let dir = std::env::temp_dir()
		.join(format!("alpm-core-conflict-{}", std::process::id()));
	fs::create_dir_all(dir.join("etc")).unwrap();
	fs::write(dir.join("etc/f"), "x").unwrap();
	let root = [dir.to_str().unwrap().as_bytes(), b"/"].concat();
	let db = local(vec![pkg("owner", &[], &["etc/", "etc/f"])]);
	let check = FileCheck {
		root: &root,
		local: &db,
		overwrite: &[],
	};
	let t = pkg("t", &[], &["etc/", "etc/f"]);
	let got = check.find_fileconflicts(&[&t], &[], &mut ());
	let owner = db.find(b"owner").unwrap();
	let removed = check.find_fileconflicts(&[&t], &[owner], &mut ());
	fs::remove_dir_all(&dir).unwrap();
	assert_eq!(got.conflicts.len(), 1);
	assert_eq!(got.conflicts[0].ctarget, b"owner");
	assert_eq!(
		got.conflicts[0].conflict_type,
		FileConflictType::Filesystem
	);
	assert!(removed.conflicts.is_empty());
}
