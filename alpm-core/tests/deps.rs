// unit tests for alpm_core::internals::deps
use alpm_core::internals::deps::*;
use alpm_core::internals::util::hash_sdbm;
use alpm_core::internals::version::vercmp;

fn dep(
	name: &[u8],
	depmod: DepMod,
	version: Option<&[u8]>,
	desc: Option<&[u8]>,
) -> Depend {
	Depend {
		name: name.into(),
		version: version.map(Box::from),
		desc: desc.map(Box::from),
		name_hash: hash_sdbm(name),
		depmod,
	}
}

#[test]
fn from_string_cases() {
	use DepMod::*;
	let cases: [(&[u8], Depend); 9] = [
		(b"glibc", dep(b"glibc", Any, None, None)),
		(b"sh=5.2", dep(b"sh", Eq, Some(b"5.2"), None)),
		(b"a>=1:2-3", dep(b"a", Ge, Some(b"1:2-3"), None)),
		(b"a<=1", dep(b"a", Le, Some(b"1"), None)),
		(b"a<1", dep(b"a", Lt, Some(b"1"), None)),
		(b"a>1", dep(b"a", Gt, Some(b"1"), None)),
		(b"a=", dep(b"a", Eq, Some(b""), None)),
		(b"a<=: why", dep(b"a", Le, Some(b""), Some(b"why"))),
		// '<' wins over an earlier '>'
		(b"a>1<2", dep(b"a>1", Lt, Some(b"2"), None)),
	];
	for (s, want) in cases {
		assert_eq!(dep_from_string(s), want, "{:?}", s);
	}
	let d = dep_from_string(b"python: for the scripts: really");
	assert_eq!(d.desc.as_deref(), Some(&b"for the scripts: really"[..]));
	assert_eq!(dep_from_string(b"a=1\0junk"), dep_from_string(b"a=1"));
}

#[test]
fn compute_string_cases() {
	use DepMod::*;
	let s = |d: Depend| dep_compute_string(&d);
	assert_eq!(s(dep(b"a", Ge, Some(b"1"), Some(b"x"))), b"a>=1: x");
	assert_eq!(s(dep(b"a", Any, Some(b"1"), None)), b"a");
	assert_eq!(s(dep(b"a", Lt, None, None)), b"a<");
	assert_eq!(s(dep(b"a", Eq, Some(b""), Some(b""))), b"a=: ");
	for t in [&b"a"[..], b"a<=1:2", b"a>1: why", b"a=: "] {
		assert_eq!(dep_compute_string(&dep_from_string(t)), t);
	}
}

// dep_vercmp is static in C: check it against vercmp semantics directly
#[test]
fn dep_vercmp_semantics() {
	use DepMod::*;
	let vs: [&[u8]; 5] = [b"1", b"1.0", b"1:0.5", b"2-1", b"1.0a"];
	for a in vs {
		for b in vs {
			let ord = vercmp(a, b);
			let (a, b) = (Some(a), Some(b));
			assert!(dep_vercmp(a, Any, b));
			assert_eq!(dep_vercmp(a, Eq, b), ord.is_eq());
			assert_eq!(dep_vercmp(a, Ge, b), ord.is_ge());
			assert_eq!(dep_vercmp(a, Le, b), ord.is_le());
			assert_eq!(dep_vercmp(a, Gt, b), ord.is_gt());
			assert_eq!(dep_vercmp(a, Lt, b), ord.is_lt());
		}
	}
	// NULL sorts first, as in alpm_pkg_vercmp
	assert!(dep_vercmp(None, Lt, Some(b"0")));
	assert!(dep_vercmp(None, Eq, None));
}

#[test]
fn provides_cases() {
	let p = [dep_from_string(b"sh=5.2"), dep_from_string(b"libfoo.so")];
	assert!(depcmp_provides(&dep_from_string(b"sh>=5"), &p));
	assert!(!depcmp_provides(&dep_from_string(b"sh<5"), &p));
	assert!(depcmp_provides(&dep_from_string(b"libfoo.so"), &p));
	// unversioned provision never satisfies a versioned dep
	assert!(!depcmp_provides(&dep_from_string(b"libfoo.so>=1"), &p));
	assert!(!depcmp_provides(&dep_from_string(b"sh"), &[]));
}

fn pkg(
	name: &[u8],
	version: &[u8],
	provides: &[&[u8]],
) -> alpm_core::internals::package::Package {
	alpm_core::internals::package::Package {
		name_hash: hash_sdbm(name),
		name: Some(name.into()),
		version: Some(version.into()),
		provides: provides.iter().map(|p| dep_from_string(p)).collect(),
		..Default::default()
	}
}

#[test]
fn depcmp_and_satisfier_cases() {
	let bash = pkg(b"bash", b"5.2-1", &[b"sh=5.2"]);
	let dash = pkg(b"dash", b"0.5-1", &[b"sh"]);
	assert!(depcmp_literal(&bash, &dep_from_string(b"bash>=5")));
	assert!(!depcmp_literal(&bash, &dep_from_string(b"sh")));
	assert!(depcmp(&bash, &dep_from_string(b"sh>=5")));
	assert!(!depcmp(&dash, &dep_from_string(b"sh>=5")));
	assert!(depcmp(&dash, &dep_from_string(b"sh")));
	// a stale hash hides the name, like the C
	let mut stale = bash.clone();
	stale.name_hash ^= 1;
	assert!(!depcmp_literal(&stale, &dep_from_string(b"bash")));
	// first in list order
	let pkgs = [dash.clone(), bash.clone()];
	let found = find_satisfier(&pkgs, b"sh").unwrap();
	assert!(std::ptr::eq(found, &pkgs[0]));
	let found = find_satisfier(&pkgs, b"sh=5.2").unwrap();
	assert!(std::ptr::eq(found, &pkgs[1]));
	assert!(find_satisfier(&pkgs, b"zsh").is_none());
}

mod resolve {
	use std::collections::VecDeque;
	use std::ffi::c_int;
	use std::fs;
	use std::path::PathBuf;

	use alpm_core::internals::callbacks::{Callbacks, LogLevel, Question};
	use alpm_core::internals::db::{DB_USAGE_ALL, DB_USAGE_SEARCH};
	use alpm_core::internals::deps::*;
	use alpm_core::internals::error::Errno;
	use alpm_core::internals::handle::Handle;
	use alpm_core::internals::package::{Package, PkgReason};
	use alpm_core::internals::pkghash::PkgHash;
	use alpm_core::internals::util::hash_sdbm;

	// a handle over an empty temp root, only its ignore lists are read
	struct Tmp(PathBuf, Handle);

	impl Tmp {
		fn new(tag: &str) -> Self {
			let dir = std::env::temp_dir().join(format!(
				"alpm-core-deps-{tag}-{}",
				std::process::id()
			));
			fs::create_dir_all(dir.join("db")).unwrap();
			let p = |s: &str| {
				dir.join(s)
					.to_str()
					.unwrap()
					.as_bytes()
					.to_vec()
			};
			let h = Handle::initialize(&p(""), &p("db")).unwrap();
			Tmp(dir, h)
		}
	}

	impl Drop for Tmp {
		fn drop(&mut self) {
			fs::remove_dir_all(&self.0).unwrap();
		}
	}

	fn pkg(name: &str, depends: &[&str], provides: &[&str]) -> Package {
		let deps = |l: &[&str]| {
			l.iter().map(|s| dep_from_string(s.as_bytes()))
				.collect()
		};
		Package {
			name_hash: hash_sdbm(name.as_bytes()),
			name: Some(name.as_bytes().into()),
			version: Some(b"1.0-1"[..].into()),
			depends: deps(depends),
			provides: deps(provides),
			reason: PkgReason::Depend,
			..Package::default()
		}
	}

	fn hash(pkgs: Vec<Package>) -> PkgHash<Package> {
		let mut h = PkgHash::new(pkgs.len() as u32).unwrap();
		for p in pkgs {
			h.add_sorted(p).unwrap();
		}
		h
	}

	fn names(pkgs: &[&Package]) -> Vec<String> {
		let n = |p: &Package| {
			String::from_utf8_lossy(p.name_bytes()).into()
		};
		pkgs.iter().map(|p| n(p)).collect()
	}

	// scripted answers, records questions and log lines
	#[derive(Default)]
	struct Cb {
		answers: VecDeque<c_int>,
		asked: Vec<String>,
		logs: Vec<(LogLevel, String)>,
	}

	impl Callbacks for Cb {
		fn question(&mut self, q: &mut Question<'_>) {
			let a = self.answers.pop_front();
			match q {
				Question::InstallIgnorepkg { install, pkg } => {
					let n = String::from_utf8_lossy(
						pkg.name_bytes(),
					);
					self.asked.push(format!("ignore {n}"));
					*install = a.unwrap_or(*install);
				}
				Question::SelectProvider {
					use_index,
					providers,
					..
				} => {
					let n = names(providers).join(",");
					self.asked.push(format!("select {n}"));
					*use_index = a.unwrap_or(*use_index);
				}
				_ => unreachable!("deps asks two questions"),
			}
		}

		fn log(&mut self, level: LogLevel, msg: &[u8]) {
			let m = String::from_utf8_lossy(msg).into_owned();
			self.logs.push((level, m));
		}
	}

	fn env<'a>(
		h: &'a Handle,
		local: &'a PkgHash<Package>,
		sync: &'a [DbPkgs<'a>],
	) -> DepsEnv<'a> {
		DepsEnv {
			opts: h.deps_opts(),
			nodepversion: false,
			local: DbPkgs {
				usage: DB_USAGE_ALL,
				cache: local,
				name: b"local",
			},
			sync,
		}
	}

	// the example of the _alpm_sortbydeps comment
	#[test]
	fn sort_example() {
		let t = Tmp::new("sort");
		let local = hash(Vec::new());
		let e = env(&t.1, &local, &[]);
		let (a, b) = (pkg("A", &["C"], &[]), pkg("B", &["A"], &[]));
		let (c, d) = (pkg("C", &[], &[]), pkg("D", &[], &[]));
		let targets = [&a, &b, &c, &d];
		let sorted = sortbydeps(&e, &targets, &[], false, &mut ());
		assert_eq!(names(&sorted), ["C", "A", "B", "D"]);
		let sorted = sortbydeps(&e, &targets, &[], true, &mut ());
		assert_eq!(names(&sorted), ["D", "B", "A", "C"]);
		assert!(sortbydeps(&e, &[], &[], false, &mut ()).is_empty());
	}

	#[test]
	fn sort_cycle_logged() {
		let t = Tmp::new("cycle");
		let local = hash(Vec::new());
		let e = env(&t.1, &local, &[]);
		let (a, b) = (pkg("A", &["B"], &[]), pkg("B", &["A"], &[]));
		let mut cb = Cb::default();
		let sorted = sortbydeps(&e, &[&a, &b], &[], false, &mut cb);
		assert_eq!(names(&sorted), ["B", "A"]);
		let msgs: Vec<&str> =
			cb.logs.iter().map(|l| &l.1[..]).collect();
		assert_eq!(
			msgs,
			[
				"started sorting dependencies\n",
				"dependency cycle detected:\n",
				"B will be installed before its A dependency\n",
				"sorting dependencies finished\n",
			]
		);
	}

	// a local package only links targets, it is not returned
	#[test]
	fn sort_through_local() {
		let t = Tmp::new("local");
		let local = hash(vec![pkg("L", &["C"], &[])]);
		let e = env(&t.1, &local, &[]);
		let (a, c) = (pkg("A", &["L"], &[]), pkg("C", &[], &[]));
		let sorted = sortbydeps(&e, &[&a, &c], &[], false, &mut ());
		assert_eq!(names(&sorted), ["C", "A"]);
		// ignored: the link is gone
		let l = pkg("L", &[], &[]);
		let sorted = sortbydeps(&e, &[&a, &c], &[&l], false, &mut ());
		assert_eq!(names(&sorted), ["A", "C"]);
	}

	#[test]
	fn checkdeps_missing_and_broken() {
		let mut t = Tmp::new("check");
		let local = hash(Vec::new());
		let e = env(&t.1, &local, &[]);
		let (a, b) = (pkg("a", &["b>=2"], &[]), pkg("b", &[], &[]));
		let c = pkg("c", &["b"], &[]);
		let miss =
			checkdeps(&e, &[&b, &c], &[&b], &[&a], true, &mut ());
		assert_eq!(miss.len(), 2);
		assert_eq!(miss[0].target, b"a");
		assert_eq!(dep_compute_string(&miss[0].depend), b"b>=2");
		assert_eq!(miss[0].causingpkg, None);
		assert_eq!(miss[1].target, b"c");
		assert_eq!(miss[1].causingpkg.as_deref(), Some(&b"b"[..]));
		// NODEPVERSION keeps the ANY copy
		let e = DepsEnv {
			nodepversion: true,
			..e
		};
		let miss = checkdeps(&e, &[], &[], &[&a], false, &mut ());
		assert_eq!(dep_compute_string(&miss[0].depend), b"b");
		// assumeinstalled satisfies
		let assume = [dep_from_string(b"b=2")];
		t.1.set_assumeinstalled(&assume).unwrap();
		let e = env(&t.1, &local, &[]);
		assert!(checkdeps(&e, &[], &[], &[&a], false, &mut ())
			.is_empty());
	}

	#[test]
	fn providers_and_ignored() {
		let mut t = Tmp::new("prov");
		t.1.set_ignorepkgs(&[b"p1".to_vec()]);
		let local = hash(Vec::new());
		let sync = hash(vec![
			pkg("p1", &[], &["v"]),
			pkg("p2", &[], &["v"]),
			pkg("p3", &[], &["v"]),
		]);
		let dbs = [DbPkgs {
			usage: DB_USAGE_ALL,
			cache: &sync,
			name: b"core",
		}];
		let e = env(&t.1, &local, &dbs);
		let mut cb = Cb {
			answers: [1, 1].into(),
			..Cb::default()
		};
		let p = find_dbs_satisfier(&e, &dbs, b"v", &mut cb).unwrap();
		assert_eq!(p.name_bytes(), b"p2");
		assert_eq!(cb.asked, ["ignore p1", "select p1,p2,p3"]);
		// out of range: none, the skipped p1 makes it "ignored"
		let mut cb = Cb {
			answers: [0, 5].into(),
			..Cb::default()
		};
		let r = find_dbs_satisfier(&e, &dbs, b"v", &mut cb);
		assert_eq!(r.err(), Some(Errno::PkgIgnored));
		assert_eq!(cb.asked, ["ignore p1", "select p2,p3"]);
		let r = find_dbs_satisfier(&e, &dbs, b"p1", &mut ());
		assert_eq!(r.err(), Some(Errno::PkgIgnored));
		let search = [DbPkgs {
			usage: DB_USAGE_SEARCH,
			..dbs[0]
		}];
		let r = find_dbs_satisfier(&e, &search, b"p2", &mut ());
		assert_eq!(r.err(), Some(Errno::PkgNotFound));
		let r = find_dbs_satisfier(&e, &[], b"p2", &mut ());
		assert_eq!(r.err(), Some(Errno::WrongArgs));
	}

	#[test]
	fn resolve_pulls_and_restores() {
		let t = Tmp::new("res");
		let local = hash(vec![pkg("inst", &[], &[])]);
		let sync = hash(vec![
			pkg("a", &["b", "inst"], &[]),
			pkg("b", &["c"], &[]),
			pkg("c", &[], &[]),
			pkg("x", &["nope"], &[]),
		]);
		let dbs = [DbPkgs {
			usage: DB_USAGE_ALL,
			cache: &sync,
			name: b"core",
		}];
		let e = env(&t.1, &local, &dbs);
		let localpkgs: Vec<&Package> = local.iter().collect();
		let a = sync.find(b"a").unwrap();
		let (mut packages, mut data) = (Vec::new(), Vec::new());
		let r = resolvedeps(
			&e,
			&localpkgs,
			a,
			&[],
			&mut packages,
			&[],
			&mut data,
			&mut (),
		);
		assert_eq!(r, Ok(()));
		assert_eq!(names(&packages), ["a", "b", "c"]);
		// installed only counts outside rem
		let x = sync.find(b"x").unwrap();
		let mut cb = Cb::default();
		let r = resolvedeps(
			&e,
			&localpkgs,
			x,
			&[],
			&mut packages,
			&[],
			&mut data,
			&mut cb,
		);
		assert_eq!(r, Err(Errno::UnsatisfiedDeps));
		assert_eq!(names(&packages), ["a", "b", "c"]);
		assert_eq!(data.len(), 1);
		assert_eq!(data[0].target, b"x");
		let warn = (
			LogLevel::Warning,
			"cannot resolve \"nope\", a dependency of \"x\"\n"
				.to_string(),
		);
		assert!(cb.logs.contains(&warn));
	}

	#[test]
	fn recursedeps_cascade() {
		let mut explicit = pkg("e", &[], &[]);
		explicit.reason = PkgReason::Explicit;
		let db = hash(vec![
			pkg("t", &["d1", "e"], &[]),
			pkg("d1", &["d2"], &[]),
			pkg("d2", &[], &[]),
			explicit,
			pkg("keeper", &["d2"], &[]),
		]);
		let t = db.find(b"t").unwrap().clone();
		let mut targs = vec![t.clone()];
		recursedeps(&db, &mut targs, false, &mut ());
		let n: Vec<&Package> = targs.iter().collect();
		// d2 is still needed by keeper
		assert_eq!(names(&n), ["t", "d1"]);
		let mut targs = vec![t];
		recursedeps(&db, &mut targs, true, &mut ());
		let n: Vec<&Package> = targs.iter().collect();
		assert_eq!(names(&n), ["t", "d1", "e"]);
	}
}
