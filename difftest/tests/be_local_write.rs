// alpm_core::internals::be_local writing side against be_local.c: the same op
// sequence (prepare, write, remove, set_reason, fixture breaks) runs on a
// C handle and on the port, each in its own fixture root; every op's rc
// and pm_errno and then the whole db tree (names, types, modes, contents)
// are compared
use std::ffi::c_int;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use alpm_core::filelist::{File, FileList};
use alpm_core::internals::backup::Backup;
use alpm_core::internals::be_local::{
	INFRQ_ALL, INFRQ_BASE, INFRQ_DESC, INFRQ_FILES, INFRQ_SCRIPTLET,
	LocalDb, LocalDbWriteError,
};
use alpm_core::internals::deps::{DepMod, Depend};
use alpm_core::internals::error::Errno;
use alpm_core::internals::package::{Package, PkgFrom, PkgReason, PkgXData};
use alpm_core::internals::pkghash::PkgHash;
use alpm_core::internals::util::hash_sdbm;
use difftest::{
	Break, OpResult, Rng, TempRoot, WriteOp, break_local, c_local_db_ops,
	iters, snapshot, umask_lock,
};

// a handle and two fixture roots per case
fn case_iters() -> usize {
	(iters() / 20).max(100)
}

// the port side of c_local_db_ops: the cache is populated on the first
// set_reason and kept, like the C's pkgcache
fn rust_ops(dbpath: &[u8], ops: &[WriteOp]) -> Result<Vec<OpResult>, c_int> {
	let db = LocalDb::register(dbpath).map_err(|e| e.errno() as c_int)?;
	let local =
		Path::new(std::str::from_utf8(dbpath).unwrap()).join("local");
	let mut cache: Option<PkgHash<Package>> = None;
	let res = |r: Result<(), Option<Errno>>| match r {
		Ok(()) => OpResult {
			rc: 0,
			errno: 0,
			reason: None,
		},
		Err(e) => OpResult {
			rc: -1,
			errno: e.map_or(0, |e| e as c_int),
			reason: None,
		},
	};
	let mut out = Vec::new();
	for op in ops {
		let r = match op {
			WriteOp::Prepare(p) => {
				res(db.prepare(p).map_err(|e| e.errno()))
			}
			WriteOp::Write(p, inforeq) => {
				match db.write(p, *inforeq) {
					Err(LocalDbWriteError::Write(e)) => {
						panic!("write failed: {e}")
					}
					r => res(r.map_err(|_| None)),
				}
			}
			WriteOp::Remove(p) => {
				res(db.remove(p).map_err(|_| None))
			}
			WriteOp::SetReason(name, reason) => {
				if cache.is_none() {
					cache = db.populate(&mut ()).ok();
				}
				let pkg = cache
					.as_mut()
					.and_then(|c| c.find_mut(name));
				match pkg {
					None => OpResult {
						rc: -1,
						errno: Errno::PkgNotFound
							as c_int,
						reason: None,
					},
					Some(pkg) => {
						let r = db.set_reason(
							pkg,
							*reason,
							&mut (),
						);
						OpResult {
							reason: Some(pkg.reason as c_int),
							..res(r.map_err(Some))
						}
					}
				}
			}
			WriteOp::SetReasonDetached(p, reason) => res(db
				.set_reason(&mut p.clone(), *reason, &mut ())
				.map_err(Some)),
			WriteOp::Break(how) => {
				break_local(&local, *how);
				res(Ok(()))
			}
		};
		out.push(r);
	}
	Ok(out)
}

// runs ops on both sides after setup ran on each fresh root
fn compare(
	what: &str,
	setup: &dyn Fn(&TempRoot),
	ops: &[WriteOp],
) -> Vec<OpResult> {
	let _umask = umask_lock();
	let (c, r) = (TempRoot::new("dbw-c"), TempRoot::new("dbw-r"));
	c.reset_local();
	r.reset_local();
	setup(&c);
	setup(&r);
	let cres = c_local_db_ops(&c.root(), &c.dbpath(), ops);
	let rres = rust_ops(&r.dbpath(), ops);
	assert_eq!(cres, rres, "{what}: results of {ops:#?}");
	let cres = cres.expect("fixture handle");
	let (ct, rt) = (c.dir().join("db"), r.dir().join("db"));
	assert_eq!(
		snapshot(&ct),
		snapshot(&rt),
		"{what}: trees after {ops:#?}"
	);
	// leave both removable
	for t in [&ct, &rt] {
		let local = t.join("local");
		if fs::symlink_metadata(&local).is_ok_and(|m| m.is_dir()) {
			let mode = fs::Permissions::from_mode(0o755);
			fs::set_permissions(&local, mode).unwrap();
		}
	}
	cres
}

fn none(_: &TempRoot) {}

// generators: arbitrary bytes (no nul: the mirror builds C strings),
// read back by both readers where set_reason loads the cache

const TEXT: &[u8] = b"ab %\n\t=:/<>\xc3\xa9";
const MODS: [DepMod; 6] = [
	DepMod::Any,
	DepMod::Eq,
	DepMod::Ge,
	DepMod::Le,
	DepMod::Gt,
	DepMod::Lt,
];
const REASONS: [PkgReason; 3] =
	[PkgReason::Explicit, PkgReason::Depend, PkgReason::Unknown];

fn opt(rng: &mut Rng, alphabet: &[u8], max: usize) -> Option<Vec<u8>> {
	(rng.below(3) != 0).then(|| rng.bytes(alphabet, max))
}

fn some<T>(rng: &mut Rng, max: usize, f: impl Fn(&mut Rng) -> T) -> Vec<T> {
	(0..rng.below(max + 1)).map(|_| f(rng)).collect()
}

fn int(rng: &mut Rng) -> i64 {
	match rng.below(4) {
		0 => 0,
		1 => -(rng.below(1000) as i64),
		2 => rng.next_u64() as i64,
		_ => rng.below(1 << 20) as i64,
	}
}

fn random_dep(rng: &mut Rng) -> Depend {
	let name = rng.bytes(TEXT, 6);
	Depend {
		name_hash: hash_sdbm(&name),
		name: name.into(),
		version: opt(rng, b"01.-:a", 5).map(Box::from),
		desc: opt(rng, TEXT, 6).map(Box::from),
		depmod: MODS[rng.below(MODS.len())],
	}
}

// name and version from a small set, so ops of one case hit each other
fn ident(rng: &mut Rng) -> (Vec<u8>, Vec<u8>) {
	let names: [&[u8]; 4] = [b"foo", b"bar", b"a-b", b"x/y"];
	let versions: [&[u8]; 3] = [b"1.0-1", b"2:0.1-3", b"1"];
	let name = names[rng.below(names.len())];
	let version = versions[rng.below(versions.len())];
	(name.to_vec(), version.to_vec())
}

fn random_pkg(rng: &mut Rng) -> Package {
	let (name, version) = ident(rng);
	Package {
		name_hash: hash_sdbm(&name),
		name: Some(name.into()),
		version: Some(version.into()),
		base: opt(rng, TEXT, 6).map(Box::from),
		desc: opt(rng, TEXT, 12).map(Box::from),
		url: opt(rng, TEXT, 8).map(Box::from),
		arch: opt(rng, TEXT, 5).map(Box::from),
		packager: opt(rng, TEXT, 8).map(Box::from),
		builddate: int(rng),
		installdate: int(rng),
		isize: int(rng),
		size: int(rng),
		reason: REASONS[rng.below(3)],
		groups: some(rng, 3, |r| r.bytes(TEXT, 5).into()).into(),
		licenses: some(rng, 3, |r| r.bytes(TEXT, 5).into()).into(),
		validation: rng.below(16) as c_int,
		replaces: some(rng, 2, random_dep).into(),
		depends: some(rng, 3, random_dep).into(),
		optdepends: some(rng, 2, random_dep).into(),
		conflicts: some(rng, 2, random_dep).into(),
		provides: some(rng, 2, random_dep).into(),
		// never written: checkdepends, makedepends
		checkdepends: some(rng, 2, random_dep).into(),
		makedepends: some(rng, 2, random_dep).into(),
		xdata: some(rng, 3, |r| PkgXData {
			name: r.bytes(TEXT, 5).into(),
			value: r.bytes(TEXT, 5).into(),
		})
		.into(),
		files: FileList {
			files: some(rng, 5, |r| {
				let name = r.bytes(TEXT, 8);
				File::new(name, int(r), r.next_u64() as u32)
			}),
		},
		backup: some(rng, 3, |r| Backup {
			name: r.bytes(TEXT, 8).into(),
			hash: opt(r, b"0123456789abcdef", 8).map(Box::from),
		})
		.into(),
		..Package::default()
	}
}

const INFRQS: [c_int; 6] = [
	INFRQ_DESC,
	INFRQ_FILES,
	INFRQ_DESC | INFRQ_FILES,
	INFRQ_ALL,
	INFRQ_BASE | INFRQ_SCRIPTLET,
	0,
];

fn random_op(rng: &mut Rng, pkg: impl Fn(&mut Rng) -> Package) -> WriteOp {
	match rng.below(20) {
		0..=4 => WriteOp::Prepare(pkg(rng)),
		5..=13 => WriteOp::Write(
			pkg(rng),
			INFRQS[rng.below(INFRQS.len())],
		),
		14..=17 => WriteOp::Remove(pkg(rng)),
		18 => WriteOp::Break(
			[Break::Remove, Break::File, Break::Dangling]
				[rng.below(3)],
		),
		_ => WriteOp::SetReasonDetached(
			pkg(rng),
			REASONS[rng.below(3)],
		),
	}
}

#[test]
fn write_fuzz() {
	let mut rng = Rng::new(0x5eed_0b17e);
	let (mut written, mut failed) = (0, 0);
	for i in 0..case_iters() {
		let n = 1 + rng.below(8);
		let ops: Vec<WriteOp> = (0..n)
			.map(|_| random_op(&mut rng, random_pkg))
			.collect();
		let res = compare(&format!("write_fuzz {i}"), &none, &ops);
		for (op, r) in ops.iter().zip(&res) {
			match (op, r.rc) {
				(WriteOp::Write(..), 0) => written += 1,
				(_, 0) => {}
				_ => failed += 1,
			}
		}
	}
	let n = case_iters();
	assert!(
		written >= n / 2 && failed >= n / 2,
		"{written} written, {failed} failed"
	);
}

// packages written whole, then set_reason on them by name
#[test]
fn reason_fuzz() {
	let mut rng = Rng::new(0x5eed_4ea5);
	let names: [&[u8]; 4] = [b"foo", b"bar", b"a-b", b"nope"];
	let mut changed = 0;
	for i in 0..case_iters() {
		// a few packages before the cache loads, then anything
		let mut ops = Vec::new();
		for _ in 0..1 + rng.below(3) {
			let p = random_pkg(&mut rng);
			ops.push(WriteOp::Prepare(p.clone()));
			ops.push(WriteOp::Write(p, INFRQ_ALL));
		}
		let n = 1 + rng.below(8);
		ops.extend((0..n).flat_map(|_| match rng.below(3) {
			0 => {
				let p = random_pkg(&mut rng);
				vec![
					WriteOp::Prepare(p.clone()),
					WriteOp::Write(p, INFRQ_ALL),
				]
			}
			1 => {
				let name = names[rng.below(names.len())];
				let reason = REASONS[rng.below(2)];
				vec![WriteOp::SetReason(name.to_vec(), reason)]
			}
			_ => vec![random_op(&mut rng, random_pkg)],
		}));
		let res = compare(&format!("reason_fuzz {i}"), &none, &ops);
		for (op, r) in ops.iter().zip(&res) {
			if let (WriteOp::SetReason(..), Some(_), 0) =
				(op, r.reason, r.rc)
			{
				changed += 1;
			}
		}
	}
	assert!(
		changed >= case_iters() / 4,
		"{changed} set_reason calls found a package"
	);
}

fn pkg(name: &str, version: &str) -> Package {
	Package {
		name_hash: hash_sdbm(name.as_bytes()),
		name: Some(name.as_bytes().into()),
		version: Some(version.as_bytes().into()),
		..Package::default()
	}
}

#[test]
fn prepare_cases() {
	let foo = pkg("foo", "1.0-1");
	let prep = || vec![WriteOp::Prepare(foo.clone())];
	compare("fresh", &none, &prep());
	compare("twice", &none, &[prep(), prep()].concat());
	for how in [Break::Remove, Break::File, Break::Dangling] {
		let ops = [vec![WriteOp::Break(how)], prep()].concat();
		compare(&format!("db dir {how:?}"), &none, &ops);
	}
	compare(
		"existing file",
		&|t| fs::write(t.local().join("foo-1.0-1"), "x").unwrap(),
		&prep(),
	);
	// mkdir keeps the setgid bit of the parent
	compare(
		"setgid parent",
		&|t| {
			let mode = fs::Permissions::from_mode(0o2775);
			fs::set_permissions(t.local(), mode).unwrap();
		},
		&prep(),
	);
	compare(
		"read-only db",
		&|t| {
			let mode = fs::Permissions::from_mode(0o555);
			fs::set_permissions(t.local(), mode).unwrap();
		},
		&[prep(), vec![WriteOp::Write(foo.clone(), INFRQ_ALL)]]
			.concat(),
	);
	// "foo/bar": the parent package dir is missing
	compare("nested", &none, &[WriteOp::Prepare(pkg("foo/bar", "1-1"))]);
}

#[test]
fn write_cases() {
	let foo = pkg("foo", "1.0-1");
	let full = Package {
		base: Some(b"foo"[..].into()),
		desc: Some(b""[..].into()),
		validation: 2,
		reason: PkgReason::Unknown,
		files: FileList {
			files: vec![File::new(b"etc/".to_vec(), 0, 0)],
		},
		backup: vec![
			Backup {
				name: b"etc/a"[..].into(),
				hash: None,
			},
			Backup {
				name: b"etc/b"[..].into(),
				hash: Some(b"0123"[..].into()),
			},
		]
		.into(),
		..foo.clone()
	};
	let backup_only = Package {
		backup: full.backup.clone(),
		..foo.clone()
	};
	let prep = WriteOp::Prepare(foo.clone());
	for (what, p, inforeq) in [
		("empty", &foo, INFRQ_ALL),
		("full", &full, INFRQ_ALL),
		("full desc", &full, INFRQ_DESC),
		("full files", &full, INFRQ_FILES),
		("backup without files", &backup_only, INFRQ_FILES),
	] {
		let ops = [prep.clone(), WriteOp::Write(p.clone(), inforeq)];
		compare(what, &none, &ops);
	}
	compare(
		"no package dir",
		&none,
		&[WriteOp::Write(full.clone(), INFRQ_ALL)],
	);
	// an existing desc keeps its mode and is truncated
	compare(
		"existing desc",
		&|t| {
			let d = dir(t);
			fs::write(d.join("desc"), "x".repeat(5000)).unwrap();
			let mode = fs::Permissions::from_mode(0o600);
			fs::set_permissions(d.join("desc"), mode).unwrap();
		},
		&[WriteOp::Write(full.clone(), INFRQ_ALL)],
	);
	// desc fails, files are not tried
	compare(
		"desc is a dir",
		&|t| fs::create_dir_all(dir(t).join("desc")).unwrap(),
		&[WriteOp::Write(full.clone(), INFRQ_ALL)],
	);
	compare(
		"files is a dir",
		&|t| fs::create_dir_all(dir(t).join("files")).unwrap(),
		&[WriteOp::Write(full.clone(), INFRQ_ALL)],
	);
	compare(
		"desc dangling symlink",
		&|t| {
			let d = dir(t);
			symlink("target", d.join("desc")).unwrap();
		},
		&[WriteOp::Write(full.clone(), INFRQ_DESC)],
	);
}

// local/foo-1.0-1/, created
fn dir(t: &TempRoot) -> std::path::PathBuf {
	let d = t.local().join("foo-1.0-1");
	fs::create_dir_all(&d).unwrap();
	d
}

#[test]
fn remove_cases() {
	let foo = pkg("foo", "1.0-1");
	let rm = || vec![WriteOp::Remove(foo.clone())];
	compare("missing", &none, &rm());
	compare(
		"files",
		&|t| {
			let d = dir(t);
			for f in
				["desc", "files", "mtree", "install", ".hidden"]
			{
				fs::write(d.join(f), f).unwrap();
			}
			symlink("desc", d.join("link")).unwrap();
		},
		&rm(),
	);
	// a subdir is not unlinked, the rest goes, rmdir fails
	compare(
		"subdir",
		&|t| {
			let d = dir(t);
			fs::write(d.join("desc"), "x").unwrap();
			fs::create_dir(d.join("sub")).unwrap();
		},
		&rm(),
	);
	// failures in readdir order do not stop the others
	compare(
		"subdirs",
		&|t| {
			let d = dir(t);
			for i in 0..8 {
				fs::create_dir(d.join(format!("d{i}")))
					.unwrap();
				fs::write(d.join(format!("f{i}")), "x")
					.unwrap();
			}
		},
		&rm(),
	);
	compare(
		"db dir is a file",
		&none,
		&[vec![WriteOp::Break(Break::File)], rm()].concat(),
	);
}

const DESC: &str = "%NAME%\nfoo\n\n%VERSION%\n1.0-1\n\n%BASE%\nfoo\n\n\
%DESC%\nsome text\n\n%URL%\nhttps://example.org/x\n\n%ARCH%\nx86_64\n\n\
%BUILDDATE%\n1700000000\n\n%INSTALLDATE%\n1700000001\n\n\
%PACKAGER%\nFoo Bar <foo@bar.org>\n\n%SIZE%\n1234\n\n%VALIDATION%\npgp\n\n\
%DEPENDS%\nglibc\nbar>=1.0\n\n";

#[test]
fn set_reason_cases() {
	let with_desc = |desc: &'static str| {
		move |t: &TempRoot| {
			let d = dir(t);
			fs::write(d.join("desc"), desc).unwrap();
			fs::write(d.join("files"), "%FILES%\netc/\n\n")
				.unwrap();
		}
	};
	let set = |r: PkgReason| WriteOp::SetReason(b"foo".to_vec(), r);
	// explicit already: nothing written, the odd desc stays as it is
	let odd = "%NAME%\nfoo\n\n%VERSION%\n1.0-1\n\n%REASON%\n0\n\n";
	compare("same reason", &with_desc(odd), &[set(PkgReason::Explicit)]);
	compare("to depend", &with_desc(DESC), &[set(PkgReason::Depend)]);
	compare(
		"there and back",
		&with_desc(DESC),
		&[set(PkgReason::Depend), set(PkgReason::Explicit)],
	);
	compare("unknown", &with_desc(DESC), &[set(PkgReason::Unknown)]);
	compare(
		"no such package",
		&with_desc(DESC),
		&[WriteOp::SetReason(b"bar".to_vec(), PkgReason::Depend)],
	);
	// the desc does not load: the reason read is the default, the desc
	// written from name and version only
	compare("no desc", &|t| drop(dir(t)), &[set(PkgReason::Depend)]);
	compare(
		"no desc explicit",
		&|t| drop(dir(t)),
		&[set(PkgReason::Explicit)],
	);
	// the write fails after the package dir went away
	compare(
		"removed",
		&with_desc(DESC),
		&[
			set(PkgReason::Explicit),
			WriteOp::Remove(pkg("foo", "1.0-1")),
			set(PkgReason::Depend),
		],
	);
	let detached = Package {
		origin: Some(PkgFrom::File(b"foo.pkg.tar"[..].into())),
		..pkg("foo", "1.0-1")
	};
	compare(
		"not from the local db",
		&with_desc(DESC),
		&[WriteOp::SetReasonDetached(detached, PkgReason::Depend)],
	);
}

// pinned divergence: the C ignores fprintf/fclose results, a desc on a
// full disk is written short and reported as success
#[test]
fn write_error_divergence() {
	let _umask = umask_lock();
	let foo = pkg("foo", "1.0-1");
	let (c, r) = (TempRoot::new("dbw-c"), TempRoot::new("dbw-r"));
	for t in [&c, &r] {
		t.reset_local();
		let d = t.local().join("foo-1.0-1");
		fs::create_dir(&d).unwrap();
		symlink("/dev/full", d.join("desc")).unwrap();
	}
	let ops = [WriteOp::Write(foo.clone(), INFRQ_DESC)];
	let cres = c_local_db_ops(&c.root(), &c.dbpath(), &ops).unwrap();
	assert_eq!(cres[0].rc, 0, "C reports success");
	let db = LocalDb::register(&r.dbpath()).unwrap();
	let err = db.write(&foo, INFRQ_DESC).unwrap_err();
	assert!(matches!(err, LocalDbWriteError::Write(_)), "{err:?}");
}
