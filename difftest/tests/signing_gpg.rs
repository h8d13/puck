// alpm_core::internals::signing (+ the signature parts of be_package and be_sync)
// against C signing.c with gpgme: throwaway keyrings under /tmp (pgp
// trust like pacman-key, direct trust for "never", a read-only pubring),
// files signed by trusted, marginal, unknown-trust, never-trusted,
// disabled, revoked, expired and unknown keys, expired, bad, garbage,
// truncated, armored, missing and unreadable signatures. both sides run
// the same gpg on the same keyring; results, return codes, pm_errno,
// questions and logs are compared. no network: the shared keyrings
// set disable-dirmngr, so WKD and keyserver lookups fail there; the
// net keyrings (one per side) get their keys from the fixture's HKP
// server on loopback, WKD is never tried on them (the uid's domain
// would go to the system resolver). WKD success is untested: dirmngr
// trusts only the system CAs for it (PORTING.md).
//
// gpg runs a few times per call: the fuzz does DIFFTEST_ITERS / 1000
// calls (200 at 200000).
use std::collections::BTreeMap;
use std::ffi::c_int;
use std::fs;

use alpm_core::digest::{Digest, Sha256, hex};
use alpm_core::internals::be_package::{pkg_load_level, pkg_validate};
use alpm_core::internals::db::Db;
use alpm_core::internals::error::Errno;
use alpm_core::internals::package::Package;
use alpm_core::internals::signing::*;
use difftest::{
	CSigHandle, FILES, GpgFixture, HOMES, Home, RecordingCallbacks, Rng,
	Served, Side, SigCall, c_gpgme_strerror, encode_base64, iters,
	keyid_input_defined, write_gpg_logger,
};

// gpg calls are slow: one fuzz call per 1000 iterations
fn gpg_iters() -> usize {
	(iters() / 1000).max(20)
}

fn lossy(b: &[u8]) -> String {
	String::from_utf8_lossy(b).into_owned()
}

// both sides on one fixture: the C handle and the Rust keyring follow
// the same gpgdir changes, so their known-key caches stay alike
struct Bench {
	fx: GpgFixture,
	c: CSigHandle,
	kr: Keyring,
	answer: bool,
}

fn rust<T>(
	rc: c_int,
	errno: Errno,
	value: T,
	cb: RecordingCallbacks,
) -> SigCall<T> {
	SigCall {
		rc,
		errno: errno as c_int,
		value,
		events: cb.events,
	}
}

// Ok/Err of a call returning results, the C's 0/-1 and pm_errno
fn listed(
	r: Result<Vec<SigResult>, Errno>,
	cb: RecordingCallbacks,
) -> SigCall<Vec<SigResult>> {
	match r {
		Ok(l) => rust(0, Errno::Ok, l, cb),
		Err(e) => rust(-1, e, Vec::new(), cb),
	}
}

// the parts of a loaded package the signature path decides
type Loaded = Option<(Option<Box<[u8]>>, Option<Box<[u8]>>, c_int)>;

fn loaded(p: Option<&Package>) -> Loaded {
	p.map(|p| (p.name.clone(), p.version.clone(), p.validation))
}

impl Bench {
	fn new(tag: &str) -> Self {
		let fx = GpgFixture::new(tag);
		let home = fx.home(Home::Pgp);
		let c = CSigHandle::new(&fx.root_dir(), &fx.db_dir(), &home);
		// init_gpgme ran on the C side before recording (once per
		// process there), so here too
		let mut kr = Keyring::new(&home);
		key_in_keychain(&mut kr, &mut (), b"init");
		Bench {
			fx,
			c,
			kr,
			answer: false,
		}
	}

	fn home(&mut self, h: Home) {
		let dir = self.fx.home(h);
		self.c.set_gpgdir(&dir);
		self.kr.set_gpgdir(&dir);
	}

	// each side on its own net keyring: imports change them
	fn net(&mut self) {
		self.c.set_gpgdir(&self.fx.home(Home::Net(Side::C)));
		self.kr.set_gpgdir(&self.fx.home(Home::Net(Side::Rust)));
	}

	// what both sides asked the HKP server since the last call: the C
	// ran first, so the port's requests must repeat the C's
	fn traffic(&self, what: &str) -> Vec<String> {
		let reqs = self.fx.requests();
		let (c, r) = reqs.split_at(reqs.len() / 2);
		assert_eq!(c, r, "{what}: keyserver requests");
		c.to_vec()
	}

	fn answer(&mut self, yes: bool) {
		self.c.set_answer(yes);
		self.answer = yes;
	}

	fn cb(&self) -> RecordingCallbacks {
		RecordingCallbacks {
			answer: self.answer,
			..RecordingCallbacks::default()
		}
	}

	fn pkg_check(&mut self, pkg: &Package, what: &str) -> Vec<SigResult> {
		let c = self.c.pkg_check(pkg);
		let mut cb = self.cb();
		let r = pkg_check_pgp_signature(&mut self.kr, &mut cb, pkg);
		assert_eq!(c, listed(r, cb), "pkg_check {what}");
		c.value
	}

	fn db_check(&mut self, name: &str) -> Vec<SigResult> {
		let c = self.c.db_check(name.as_bytes());
		let dbpath = self.fx.dbpath();
		let (kr, n) = (&mut self.kr, name.as_bytes());
		let db = Db::register_sync(
			&dbpath,
			b".db",
			n,
			0,
			0,
			kr,
			&mut (),
		);
		let mut cb = self.cb();
		let r = db_check_pgp_signature(&mut self.kr, &mut cb, &db);
		assert_eq!(c, listed(r, cb), "db_check {name}");
		c.value
	}

	fn helper(
		&mut self,
		name: &str,
		b64: Option<&[u8]>,
		flags: [bool; 3],
		process: bool,
		what: &str,
	) -> SigCall<(Vec<SigResult>, Option<c_int>)> {
		let path = self.fx.file(name);
		let ident = process.then_some(name.as_bytes());
		let c = self.c.helper(&path, b64, flags, ident);
		let mut cb = self.cb();
		let [o, m, u] = flags;
		let kr = &mut self.kr;
		let (ok, list) = check_pgp_helper(
			kr,
			&mut cb,
			Some(&path),
			b64,
			o,
			m,
			u,
		);
		let retry = ident.map(|id| {
			c_int::from(process_siglist(
				kr, &mut cb, id, &list, o, m, u,
			))
		});
		let (rc, errno) = match ok {
			Ok(()) => (0, Errno::Ok),
			Err(e) => (-1, e.unwrap_or(Errno::Ok)),
		};
		let r = rust(rc, errno, (list, retry), cb);
		assert_eq!(c, r, "helper {what}");
		c
	}

	fn validate(
		&mut self,
		name: &str,
		sync: Option<&Package>,
		level: c_int,
		what: &str,
	) -> SigCall<(c_int, Option<Vec<SigResult>>)> {
		let path = self.fx.file(name);
		let c = self.c.validate(&path, sync, level);
		let mut cb = self.cb();
		let r = pkg_validate(&mut self.kr, &mut cb, &path, sync, level);
		use alpm_core::internals::be_package::PkgLoadError;
		let r = match r {
			Ok(v) => rust(
				0,
				Errno::Ok,
				(v.validation, v.siglist),
				cb,
			),
			Err(e) => {
				let list = match &e {
					PkgLoadError::InvalidSig(l) => {
						Some(l.clone())
					}
					_ => None,
				};
				// the C leaves validation as far as it got,
				// compared only on success
				rust(-1, e.errno(), (c.value.0, list), cb)
			}
		};
		assert_eq!(c, r, "validate {what} level {level:#x}");
		c
	}

	fn load(&mut self, name: &str, full: bool, level: c_int) -> c_int {
		let path = self.fx.file(name);
		let c = self.c.pkg_load(&path, full, level);
		let c = SigCall {
			rc: c.rc,
			errno: c.errno,
			value: loaded(c.value.as_ref()),
			events: c.events,
		};
		let mut cb = self.cb();
		let kr = &mut self.kr;
		let r = pkg_load_level(kr, &mut cb, &path, full, level);
		let r = match r {
			Ok(p) => rust(0, Errno::Ok, loaded(Some(&p)), cb),
			Err(e) => rust(-1, e.errno(), None, cb),
		};
		assert_eq!(
			c, r,
			"pkg_load {name} full {full} level {level:#x}"
		);
		c.rc
	}

	fn register(&mut self, name: &str, level: c_int) -> c_int {
		let c = self.c.register(name.as_bytes(), level);
		let dbpath = self.fx.dbpath();
		let mut cb = self.cb();
		let kr = &mut self.kr;
		let n = name.as_bytes();
		let db = Db::register_sync(
			&dbpath, b".db", n, level, 0, kr, &mut cb,
		);
		let valid = db.valid();
		db.unregister(&mut cb);
		let r = match valid {
			Ok(()) => rust(0, Errno::Ok, (), cb),
			Err(e) => rust(-1, e, (), cb),
		};
		assert_eq!(c, r, "register {name} level {level:#x}");
		c.rc
	}

	fn in_keychain(&mut self, fpr: &[u8]) -> c_int {
		let c = self.c.in_keychain(fpr);
		let mut cb = self.cb();
		let rc = match key_in_keychain(&mut self.kr, &mut cb, fpr) {
			Some(true) => 1,
			Some(false) => 0,
			None => -1,
		};
		assert_eq!(
			c,
			rust(rc, Errno::Ok, (), cb),
			"in_keychain {}",
			lossy(fpr)
		);
		c.rc
	}

	fn key_import(&mut self, uid: Option<&[u8]>, fpr: &[u8]) -> c_int {
		let c = self.c.key_import(uid, fpr);
		let mut cb = self.cb();
		let ok = key_import(&mut self.kr, &mut cb, uid, fpr);
		let r = rust(if ok { 0 } else { -1 }, Errno::Ok, (), cb);
		assert_eq!(
			c,
			r,
			"key_import {:?} {}",
			uid.map(lossy),
			lossy(fpr)
		);
		c.rc
	}

	fn pkg(&self, name: &str, b64: Option<Vec<u8>>) -> Package {
		Package {
			filename: Some(self.fx.file(name).into()),
			base64_sig: b64.map(Box::from),
			..Package::default()
		}
	}

	fn sha256(&self, name: &str) -> Vec<u8> {
		let data = fs::read(
			String::from_utf8(self.fx.file(name)).unwrap(),
		);
		hex(&Sha256::digest(data.unwrap()))
	}
}

fn flags(bits: usize) -> [bool; 3] {
	[bits & 1 != 0, bits & 2 != 0, bits & 4 != 0]
}

fn pkg_level(bits: usize) -> c_int {
	let [o, m, u] = flags(bits);
	SIG_PACKAGE
		| if o { SIG_PACKAGE_OPTIONAL } else { 0 }
		| if m { SIG_PACKAGE_MARGINAL_OK } else { 0 }
		| if u { SIG_PACKAGE_UNKNOWN_OK } else { 0 }
}

fn db_level(bits: usize) -> c_int {
	let [o, m, u] = flags(bits);
	SIG_DATABASE
		| if o { SIG_DATABASE_OPTIONAL } else { 0 }
		| if m { SIG_DATABASE_MARGINAL_OK } else { 0 }
		| if u { SIG_DATABASE_UNKNOWN_OK } else { 0 }
}

// what each signed file must give in the pgp keyring: (status, validity)
// per signature. pins the fixtures, both sides already agree
fn expected(name: &str) -> Option<Vec<(SigStatus, SigValidity)>> {
	use SigStatus::*;
	use SigValidity::*;
	Some(match name {
		"full" | "never" | "mbox" | "odd" | "master" | "armor" => {
			vec![(Valid, Full)]
		}
		"marg" => vec![(Valid, Marginal)],
		"unk" => vec![(Valid, Unknown)],
		"dis" => vec![(KeyDisabled, Full)],
		"rev" => vec![(Invalid, Unknown)],
		"exp" => vec![(KeyExpired, Unknown)],
		"sigexp" => vec![(SigExpired, Full)],
		"stranger" => vec![(KeyUnknown, Unknown)],
		"two" => vec![(Valid, Full), (Valid, Marginal)],
		"mixed" => vec![(Valid, Full), (KeyUnknown, Unknown)],
		"bad" | "pubkey" => vec![(Invalid, Unknown)],
		_ => return None,
	})
}

fn shape(list: &[SigResult]) -> Vec<(SigStatus, SigValidity)> {
	list.iter().map(|r| (r.status, r.validity)).collect()
}

// files whose signatures meet every trust branch: all policy
// combinations run on them
const POLICY: &[&str] = &["full", "marg", "unk", "exp", "dis", "nosig"];

// every file once in the pgp keyring, the trust-sensitive ones in the
// direct keyring, the import paths with the read-only pubring
fn home_files(home: Home) -> &'static [&'static str] {
	match home {
		Home::Pgp => FILES,
		Home::Direct => &["never", "intro", "marg", "unk", "master"],
		Home::ReadOnly => &["stranger", "exp", "mixed"],
		Home::Net(_) => &[],
	}
}

#[test]
fn fixed_cases_against_c() {
	let mut b = Bench::new("signing-fixed");
	let mut seen: BTreeMap<String, usize> = BTreeMap::new();
	let mut count = |k: String| *seen.entry(k).or_default() += 1;
	for home in HOMES {
		b.home(home);
		for &name in home_files(home) {
			let what = format!("{name} in {home:?}");
			let sigs = b.pkg_check(&b.pkg(name, None), &what);
			let want = match (home, name) {
				(Home::Pgp, _) => expected(name),
				(Home::Direct, "never") => Some(vec![(
					SigStatus::Valid,
					SigValidity::Never,
				)]),
				_ => None,
			};
			if let Some(want) = want {
				assert_eq!(shape(&sigs), want, "{what}");
			}
			for r in &sigs {
				count(format!(
					"{:?}/{:?}",
					r.status, r.validity
				));
			}
			let combos: &[usize] = match POLICY.contains(&name) {
				true if home == Home::Pgp => {
					&[0, 1, 2, 3, 4, 5, 6, 7]
				}
				_ => &[0, 7],
			};
			for (i, &bits) in combos.iter().enumerate() {
				b.answer(i % 2 == 1);
				b.helper(name, None, flags(bits), true, &what);
			}
			if home != Home::Pgp {
				count(format!(
					"load {}",
					b.load(name, false, SIG_PACKAGE)
				));
				continue;
			}
			b.db_check(name);
			// the file's signature again, from base64
			let sig =
				b.fx.sig_bytes(name).filter(|_| name != "big");
			if let Some(sig) = sig {
				let enc = encode_base64(&sig);
				b.pkg_check(&b.pkg(name, Some(enc)), &what);
			}
			for bits in [0, 7] {
				b.validate(name, None, pkg_level(bits), &what);
				let rc = b.register(name, db_level(bits));
				count(format!("register {rc}"));
			}
			count(format!(
				"load {}",
				b.load(name, false, SIG_PACKAGE)
			));
		}
	}
	println!("{seen:?}");
	for k in [
		"Valid/Full",
		"Valid/Marginal",
		"Valid/Unknown",
		"Valid/Never",
		"KeyExpired/Unknown",
		"SigExpired/Full",
		"KeyUnknown/Unknown",
		"KeyDisabled/Full",
		"Invalid/Unknown",
		"load 0",
		"load -1",
		"register 0",
		"register -1",
	] {
		assert!(seen.contains_key(k), "{k} never seen");
	}
}

// base64 signatures and sha256sums of a sync package
#[test]
fn sync_package_validation_against_c() {
	let mut b = Bench::new("signing-sync");
	let full = b.fx.sig_bytes("full").unwrap();
	let stranger = b.fx.sig_bytes("stranger").unwrap();
	let sigs: [(&str, Option<Vec<u8>>); 6] = [
		("none", None),
		("full", Some(encode_base64(&full))),
		("stranger", Some(encode_base64(&stranger))),
		("broken", Some(b"!!!!".to_vec())),
		("unpadded", Some(b"Zg".to_vec())),
		("empty", Some(Vec::new())),
	];
	for name in ["full", "bad", "nosig", "marg"] {
		let good = b.sha256(name);
		for (label, sig) in &sigs {
			for sha in
				[None, Some(good.clone()), Some(b"00".to_vec())]
			{
				let sync = Package {
					base64_sig: sig.clone().map(Box::from),
					sha256sum: sha.clone().map(Box::from),
					..Package::default()
				};
				for bits in [0, 1, 3, 7] {
					let what = format!(
						"{name} sig {label} sha {sha:?}"
					);
					b.validate(
						name,
						Some(&sync),
						pkg_level(bits),
						&what,
					);
					let what = format!("{what} level 0");
					b.validate(name, Some(&sync), 0, &what);
				}
			}
		}
	}
}

// _alpm_key_in_keychain and _alpm_key_import on every key, by
// fingerprint, long key id and too short, in every keyring
#[test]
fn keys_against_c() {
	let mut b = Bench::new("signing-keys");
	let fprs: Vec<(String, String)> = b.fx.fprs().to_vec();
	let mut seen = BTreeMap::new();
	for home in HOMES {
		b.home(home);
		for (name, fpr) in &fprs {
			for id in [
				&fpr[..],
				&fpr[24..],
				&fpr[36..],
				"nonexistent00000",
			] {
				let rc = b.in_keychain(id.as_bytes());
				*seen.entry(format!("in {name} {rc}"))
					.or_insert(0) += 1;
			}
			let uid = format!("{name} <{name}@x.test>");
			for answer in [false, true] {
				b.answer(answer);
				for u in [
					None,
					Some(uid.as_bytes()),
					Some(&b"no email"[..]),
				] {
					b.key_import(u, fpr.as_bytes());
				}
				b.key_import(
					Some(b"<a@b>"),
					&fpr.as_bytes()[32..],
				);
			}
		}
	}
	println!("{seen:?}");
	// known (also cached), too short, unknown, expired, not imported
	for k in ["in full 1", "in full -1", "in full 0", "in exp 0"] {
		assert!(seen.contains_key(k), "{k} never seen");
	}
	assert!(seen.contains_key("in stranger 0"));
}

// the keyserver paths, each side importing into its own net keyring:
// a package signed by a key the keyring lacks, the server answering
// 404, an html page, a hang, the wrong key, then the key with the
// question answered no and yes, validation with the key present; a db
// signature whose key the index names by key id only. the requests
// dirmngr makes and the keyrings afterwards must match too
#[test]
fn keyserver_against_c() {
	use SigStatus::Valid;
	use SigValidity::Unknown;
	let mut b = Bench::new("signing-hkp");
	b.net();
	let stranger = b.fx.fpr("stranger").to_string();
	let s2 = b.fx.fpr("stranger2").to_string();
	let unknown_ok = SIG_PACKAGE | SIG_PACKAGE_UNKNOWN_OK;
	let lookup = "/pks/lookup?op=";
	let index = |fpr: &str| {
		format!(
			"{lookup}index&options=mr&fingerprint=on&search=0x{fpr}"
		)
	};
	let get = |id: &str| format!("{lookup}get&options=mr&search=0x{id}");
	// alpm_pkg_load searches the key id extract_keyid found, the
	// siglist and key_import paths the fingerprint; the retry is by
	// the last 8 characters either way
	let (keyid, short) = (&stranger[24..], &stranger[32..]);
	b.answer(true);
	b.fx.serve("stranger", Served::NotFound);
	assert_eq!(b.load("stranger", false, unknown_ok), -1);
	assert_eq!(b.traffic("404"), [index(keyid), index(short)]);
	b.fx.serve("stranger", Served::Garbage);
	assert_eq!(b.key_import(None, stranger.as_bytes()), -1);
	assert_eq!(b.traffic("garbage"), [index(&stranger), index(short)]);
	b.fx.serve("stranger", Served::Hang);
	let uid = Some(&b"no email"[..]);
	assert_eq!(b.key_import(uid, stranger.as_bytes()), -1);
	assert_eq!(b.traffic("hang"), [index(&stranger), index(short)]);
	// found, the key received is another's: the import screener
	// rejects it, nothing lands in the keyring
	b.fx.serve("stranger", Served::Wrong);
	b.helper("stranger", None, [false, false, true], true, "wrong");
	assert_eq!(b.traffic("wrong"), [index(&stranger), get(&stranger)]);
	assert_eq!(b.in_keychain(stranger.as_bytes()), 0);
	// declined: asked, nothing looked up
	b.fx.serve("stranger", Served::Key);
	b.answer(false);
	assert_eq!(b.load("stranger", false, unknown_ok), -1);
	assert!(b.traffic("declined").is_empty());
	// imported, validated at once: unknown trust, not accepted at that
	// level, known from then on
	b.answer(true);
	assert_eq!(b.load("stranger", false, SIG_PACKAGE), -1);
	assert_eq!(b.traffic("imported"), [index(keyid), get(&stranger)]);
	assert_eq!(b.in_keychain(stranger.as_bytes()), 1);
	assert_eq!(b.load("stranger", false, unknown_ok), 0);
	assert!(b.traffic("present").is_empty());
	let sigs = b.pkg_check(&b.pkg("stranger", None), "present");
	assert_eq!(shape(&sigs), [(Valid, Unknown)]);
	// a db signature, the index naming the key id only
	b.fx.serve("stranger2", Served::ShortId);
	let level = SIG_DATABASE | SIG_DATABASE_UNKNOWN_OK;
	assert_eq!(b.register("stranger2", level), 0);
	assert_eq!(b.traffic("db"), [index(&s2), get(&s2[24..])]);
	assert_eq!(shape(&b.db_check("stranger2")), [(Valid, Unknown)]);
	// both keyrings hold the same keys in the same state
	let c = b.fx.listing(Home::Net(Side::C));
	assert_eq!(c, b.fx.listing(Home::Net(Side::Rust)));
	for fpr in [&stranger, &s2] {
		let held =
			c.iter().any(|l| l == &format!("fpr:::::::::{fpr}:"));
		assert!(held, "{fpr} not in the keyring: {c:?}");
	}
}

// a random file, keyring, level, answer and call, many times
#[test]
fn fuzz_against_c() {
	let n = gpg_iters();
	let mut b = Bench::new("signing-fuzz");
	let mut rng = Rng::new(0x5167);
	let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
	let names: Vec<&str> =
		FILES.iter().copied().filter(|&f| f != "big").collect();
	for i in 0..n {
		b.home(HOMES[rng.below(HOMES.len())]);
		b.answer(rng.below(2) == 0);
		let name = names[rng.below(names.len())];
		let other = names[rng.below(names.len())];
		let b64 = match rng.below(4) {
			0 => b.fx.sig_bytes(other).map(|s| encode_base64(&s)),
			1 => Some(b"QUJD".to_vec()),
			_ => None,
		};
		let bits = rng.below(8);
		let what = format!("#{i} {name} b64 {other}");
		let op = match rng.below(7) {
			0 => {
				b.pkg_check(&b.pkg(name, b64), &what);
				"pkg_check"
			}
			1 => {
				b.db_check(name);
				"db_check"
			}
			2 => {
				b.helper(
					name,
					b64.as_deref(),
					flags(bits),
					true,
					&what,
				);
				"helper"
			}
			3 => {
				let sha = (rng.below(2) == 0)
					.then(|| b.sha256(name));
				let sync = Package {
					base64_sig: b64.map(Box::from),
					sha256sum: sha.map(Box::from),
					..Package::default()
				};
				let level = pkg_level(bits)
					& !(rng.below(2) as c_int);
				b.validate(name, Some(&sync), level, &what);
				"validate"
			}
			4 => {
				let level = pkg_level(bits)
					& !(rng.below(2) as c_int);
				b.load(name, rng.below(2) == 0, level);
				"load"
			}
			5 => {
				b.register(name, db_level(bits));
				"register"
			}
			_ => {
				let (_, fpr) = b.fx.fprs()
					[rng.below(b.fx.fprs().len())]
				.clone();
				b.in_keychain(fpr.as_bytes());
				b.key_import(None, fpr.as_bytes());
				"keys"
			}
		};
		*seen.entry(op).or_default() += 1;
	}
	println!("{seen:?}");
	for (op, got) in &seen {
		assert!(got * 7 * 2 >= n, "{op}: {got} of {n}");
	}
}

// one gpg run of a log: its arguments, without what only passes data
// around (fds, locale, display) and with the verify operands as
// placeholders, gpgme's -&N fds and the port's paths alike
fn normalize(run: &[String]) -> Vec<String> {
	let mut out = Vec::new();
	let mut it = run.iter();
	while let Some(a) = it.next() {
		match a.as_str() {
			"--status-fd" | "--logger-fd" => {
				it.next();
			}
			"--enable-special-filenames" => {}
			// one keyring per side on the net homes
			_ if a.starts_with("--homedir=") => {
				out.push("--homedir=<home>".to_string());
			}
			_ if a.starts_with("--lc-")
				|| a.starts_with("--display")
				|| a.starts_with("--tty") => {}
			"--verify" => {
				out.push(a.clone());
				out.push(it.next().unwrap().clone());
				it.next();
				it.next();
				out.extend([
					"<sig>".to_string(),
					"<data>".to_string(),
				]);
			}
			_ => out.push(a.clone()),
		}
	}
	out
}

fn runs(log: &std::path::Path) -> Vec<Vec<String>> {
	let text = fs::read_to_string(log).unwrap_or_default();
	fs::remove_file(log).ok();
	let runs = text.split("\n\n").filter(|r| !r.is_empty());
	let args =
		runs.map(|r| r.lines().map(str::to_string).collect::<Vec<_>>());
	args.filter(|a| a != &["--version"])
		.map(|a| normalize(&a))
		.collect()
}

// one scenario of invocations_match_gpgme
type Step = Box<dyn Fn(&mut Bench)>;

// the gpg command lines both sides run, through a logging wrapper: the
// same operations, options and patterns in the same order
#[test]
fn invocations_match_gpgme() {
	let mut b = Bench::new("signing-argv");
	let (cwrap, clog) = (b.fx.dir().join("cgpg"), b.fx.dir().join("c.log"));
	let (rwrap, rlog) = (b.fx.dir().join("rgpg"), b.fx.dir().join("r.log"));
	write_gpg_logger(&cwrap, &clog);
	write_gpg_logger(&rwrap, &rlog);
	b.c.set_gpg(Some(&cwrap));
	b.kr.set_gpg(&rwrap);
	b.answer(true);
	let full = encode_base64(&b.fx.sig_bytes("full").unwrap());
	let steps: Vec<(&str, Step)> = vec![
		(
			"verify file",
			Box::new(|b| {
				b.pkg_check(&b.pkg("two", None), "two");
			}),
		),
		(
			"verify base64",
			Box::new(move |b| {
				b.pkg_check(
					&b.pkg("full", Some(full.clone())),
					"b64",
				);
			}),
		),
		(
			"unknown key",
			Box::new(|b| {
				b.helper(
					"stranger", None, [false; 3], true,
					"stranger",
				);
			}),
		),
		(
			"expired key",
			Box::new(|b| {
				b.helper("exp", None, [false; 3], true, "exp");
			}),
		),
		(
			"load",
			Box::new(|b| {
				b.load("stranger", false, SIG_PACKAGE);
			}),
		),
		(
			"db",
			Box::new(|b| {
				b.register("mixed", SIG_DATABASE);
			}),
		),
		(
			"keys",
			Box::new(|b| {
				b.in_keychain(b"0123456789ABCDEF");
				b.key_import(
					Some(b"x <short@x.test>"),
					b"0123ABCD",
				);
			}),
		),
		(
			"import",
			Box::new(|b| {
				b.net();
				b.fx.serve("stranger", Served::Key);
				let fpr = b.fx.fpr("stranger").to_string();
				b.key_import(None, fpr.as_bytes());
			}),
		),
	];
	for (what, step) in &steps {
		step(&mut b);
		let (c, r) = (runs(&clog), runs(&rlog));
		assert!(!c.is_empty(), "{what}: no gpg run");
		assert_eq!(c, r, "{what}");
		for run in &c {
			let op = run.iter().skip_while(|a| {
				!a.starts_with("--with")
					&& *a != "--verify" && *a != "--recv-keys"
			});
			println!(
				"{what}: {}",
				op.cloned().collect::<Vec<_>>().join(" ")
			);
		}
	}
}

// a v4 signature packet: hashed and unhashed subpackets of random
// types and length forms, header in a random format
fn subpacket(rng: &mut Rng) -> Vec<u8> {
	let (kind, size) = match rng.below(6) {
		0 => (16, 8),
		1 => (33, 21),
		2 => (2, 4),
		3 => (16, rng.below(10)),
		4 => (rng.below(256) as u8, rng.below(12)),
		_ => (rng.below(256) as u8, 190 + rng.below(20)),
	};
	let body: Vec<u8> = std::iter::once(kind)
		.chain((0..size).map(|_| rng.next_u64() as u8))
		.collect();
	let n = body.len();
	let mut out = match rng.below(4) {
		_ if (192..8384).contains(&n) && rng.below(2) == 0 => {
			let v = n - 192;
			vec![(v >> 8) as u8 + 192, v as u8]
		}
		0 => {
			let mut v = vec![0xff];
			v.extend((n as u32).to_be_bytes());
			v
		}
		_ if n < 192 => vec![n as u8],
		_ => {
			let mut v = vec![0xff];
			v.extend((n as u32).to_be_bytes());
			v
		}
	};
	out.extend(body);
	out
}

fn area(rng: &mut Rng) -> Vec<u8> {
	let subs: Vec<u8> =
		(0..rng.below(4)).flat_map(|_| subpacket(rng)).collect();
	let mut out = (subs.len() as u16).to_be_bytes().to_vec();
	out.extend(subs);
	out
}

fn packet(rng: &mut Rng) -> Vec<u8> {
	let version = if rng.below(8) == 0 { 3 } else { 4 };
	let class = if rng.below(8) == 0 { 1 } else { 0 };
	let mut body = vec![version, class, 22, 10];
	body.extend(area(rng));
	body.extend(area(rng));
	body.extend((0..2 + rng.below(70)).map(|_| rng.next_u64() as u8));
	let mut blen = body.len();
	if rng.below(6) == 0 {
		blen = rng.below(blen + 20);
	}
	let mut out = match rng.below(7) {
		0 => vec![0x88, blen as u8],
		1 => {
			let mut v = vec![0x89];
			v.extend((blen as u16).to_be_bytes());
			v
		}
		2 => {
			let mut v = vec![0x8a];
			v.extend((blen as u32).to_be_bytes());
			v
		}
		3 => vec![0xc2, blen.min(191) as u8],
		4 if blen >= 192 => {
			let v = blen.min(8383) - 192;
			vec![0xc2, (v >> 8) as u8 + 192, v as u8]
		}
		5 => {
			let mut v = vec![0xc2, 0xff];
			v.extend((blen as u32).to_be_bytes());
			v
		}
		_ => vec![
			[0x8b, 0xc2][rng.below(2)],
			0xe0 + rng.below(31) as u8,
		],
	};
	out.extend(body);
	out
}

fn random_sig(rng: &mut Rng) -> Vec<u8> {
	let mut sig: Vec<u8> =
		(0..1 + rng.below(3)).flat_map(|_| packet(rng)).collect();
	for _ in 0..rng.below(3) {
		match rng.below(3) {
			0 => sig.truncate(rng.below(sig.len() + 1)),
			1 if !sig.is_empty() => {
				let i = rng.below(sig.len());
				sig[i] = rng.next_u64() as u8;
			}
			_ => sig.push(rng.next_u64() as u8),
		}
	}
	keyid_input_defined(&mut sig);
	sig
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
	Keys,
	NoKeys,
	Format,
	Unsupported,
}

fn keyid_same(c: &CSigHandle, sig: &[u8]) -> Kind {
	let ident = b"pkg.tar";
	let cr = c.extract_keyid(ident, sig);
	let mut cb = RecordingCallbacks::default();
	let mut keys = Vec::new();
	let r = extract_keyid(&mut cb, ident, sig, &mut keys);
	let rc = if r.is_ok() { 0 } else { -1 };
	let rr = SigCall {
		rc,
		errno: cr.errno,
		value: keys,
		events: cb.events,
	};
	assert_eq!(cr, rr, "{sig:02x?}");
	match r {
		Ok(()) if rr.value.is_empty() => Kind::NoKeys,
		Ok(()) => Kind::Keys,
		Err(KeyidError::Format) => Kind::Format,
		Err(KeyidError::Unsupported) => Kind::Unsupported,
	}
}

fn keyid_handle(tmp: &difftest::TempRoot) -> CSigHandle {
	let gpgdir = tmp.path("gnupg");
	fs::create_dir_all(tmp.dir().join("gnupg")).unwrap();
	CSigHandle::new(&tmp.dir().join("root"), &tmp.dir().join("db"), &gpgdir)
}

// alpm_extract_keyid on hand-made packets, no gpg involved
#[test]
fn extract_keyid_edge_cases_against_c() {
	let tmp = difftest::TempRoot::new("signing-keyid");
	let c = keyid_handle(&tmp);
	let issuer = [0x09, 16, 1, 2, 3, 4, 5, 6, 7, 0xab];
	let v4 = |hashed: &[u8], unhashed: &[u8], tail: &[u8]| {
		let mut body = vec![4, 0, 22, 10];
		body.extend((hashed.len() as u16).to_be_bytes());
		body.extend(hashed);
		body.extend((unhashed.len() as u16).to_be_bytes());
		body.extend(unhashed);
		body.extend(tail);
		let mut p = vec![0x88, body.len() as u8];
		p.extend(body);
		p
	};
	let good = v4(&[0x05, 2, 0, 0, 0, 1], &issuer, &[0, 0, 1, 1]);
	let cases: Vec<(&str, Vec<u8>, Kind)> = vec![
		("empty", vec![], Kind::NoKeys),
		("issuer unhashed", good.clone(), Kind::Keys),
		("issuer hashed", v4(&issuer, &[], &[0, 0]), Kind::Keys),
		("two packets", [&good[..], &good[..]].concat(), Kind::Keys),
		(
			"no issuer",
			v4(&[0x05, 2, 0, 0, 0, 1], &[], &[0, 0]),
			Kind::NoKeys,
		),
		("not a packet", vec![0x08, 0x02], Kind::Format),
		("old partial", vec![0x8b, 0x00, 4], Kind::Unsupported),
		("new partial", vec![0xc2, 0xe1, 4, 0], Kind::Unsupported),
		(
			"version 3",
			{
				let mut g = good.clone();
				g[2] = 3;
				g
			},
			Kind::Unsupported,
		),
		(
			"text class",
			{
				let mut g = good.clone();
				g[3] = 1;
				g
			},
			Kind::Format,
		),
		(
			"zero length subpacket",
			v4(&[0x00, 2], &[], &[0, 0]),
			Kind::Format,
		),
		(
			"short issuer",
			v4(&[0x05, 16, 1, 2, 3, 4], &[], &[]),
			Kind::Format,
		),
		// the hashed area ends one byte before the end: the C reads the
		// unhashed length one byte past it
		(
			"cut after hashed",
			{
				let mut g = v4(&[0x02, 2, 0], &[], &[]);
				g.truncate(g.len() - 1);
				g[1] -= 1;
				g
			},
			Kind::Format,
		),
		// body length shorter than the subpacket areas: the next
		// packet starts inside this one
		(
			"short body length",
			{
				let mut g = good.clone();
				g[1] = 4;
				g
			},
			Kind::Format,
		),
	];
	for (what, sig, want) in cases {
		assert_eq!(keyid_same(&c, &sig), want, "{what}");
	}
}

#[test]
fn extract_keyid_fuzz_against_c() {
	let n = iters();
	let tmp = difftest::TempRoot::new("signing-keyid-fuzz");
	let c = keyid_handle(&tmp);
	let mut rng = Rng::new(0x4b1d);
	let mut seen: BTreeMap<Kind, usize> = BTreeMap::new();
	for _ in 0..n {
		let sig = random_sig(&mut rng);
		*seen.entry(keyid_same(&c, &sig)).or_default() += 1;
	}
	println!("{seen:?}");
	for k in [Kind::Keys, Kind::NoKeys, Kind::Format, Kind::Unsupported] {
		let got = seen.get(&k).copied().unwrap_or(0);
		assert!(got * 50 >= n, "{k:?}: {got} of {n}");
	}
}

// the gpg_strerror table (signing/err_codes.rs) against libgpg-error
// through gpgme, every code without GPG_ERR_SYSTEM_ERROR
#[test]
fn error_texts_against_c() {
	for code in 0..0x8000 {
		let (c, r) = (c_gpgme_strerror(code), gpg_strerror(code));
		assert_eq!(lossy(&c), lossy(r), "code {code}");
	}
}
