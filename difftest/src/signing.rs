// C side of lib/libalpm/signing.c and base64.c, and the gpg fixtures the
// signature tests share: throwaway keyrings and signed files built with
// gpg(1) under /tmp, a C handle whose gpgdir points at them.
//
// init_gpgme sets gpgme's engine info once per process, from the first
// handle's gpgdir. CSigHandle sets it again before every call (same
// gpg, its gpgdir), the ALPM lock keeps that global to one handle.
use std::cell::RefCell;
use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::MutexGuard;

use alpm_core::callbacks::{Callbacks, LogLevel, Question};
use alpm_core::package::Package;
use alpm_core::signing::{PgpKey, SigResult, SigStatus, SigValidity};

use crate::fixtures::{TempRoot, tar_file, ustar};
use crate::handle::{
	_alpm_pkg_validate_internal, ALPM, CDb, alpm_db_get_valid,
	alpm_db_unregister, alpm_errno, alpm_initialize, alpm_option_get_root,
	alpm_option_set_gpgdir, alpm_option_set_logcb,
	alpm_option_set_questioncb, alpm_pkg_free, alpm_pkg_load,
	alpm_register_syncdb, alpm_release,
};
use crate::package::{CPkg, CPkgBox, field, read_pkg, take_strs};
use crate::{CList, c_free, cstr, vsnprintf};

// alpm_pgpkey_t
#[repr(C)]
struct CPgpKey {
	data: *mut c_void,
	fingerprint: *mut c_char,
	uid: *mut c_char,
	name: *mut c_char,
	email: *mut c_char,
	created: i64,
	expires: i64,
	length: c_uint,
	revoked: c_uint,
}

// alpm_sigresult_t
#[repr(C)]
struct CSigResult {
	key: CPgpKey,
	status: c_int,
	validity: c_int,
}

// alpm_siglist_t
#[repr(C)]
struct CSigList {
	count: usize,
	results: *mut CSigResult,
}

// alpm_question_import_key_t, the union member questioncb gets for it
#[repr(C)]
struct CQuestionImportKey {
	kind: c_int,
	import: c_int,
	uid: *const c_char,
	fingerprint: *const c_char,
}

const QUESTION_IMPORT_KEY: c_int = 1 << 6;
pub(crate) const GPGME_PROTOCOL_OPENPGP: c_int = 0;

unsafe extern "C" {
	fn alpm_decode_signature(
		b64: *const c_char,
		data: *mut *mut u8,
		data_len: *mut usize,
	) -> c_int;
	fn alpm_pkg_check_pgp_signature(
		pkg: *mut CPkg,
		siglist: *mut CSigList,
	) -> c_int;
	fn alpm_db_check_pgp_signature(
		db: *mut CDb,
		siglist: *mut CSigList,
	) -> c_int;
	fn alpm_siglist_cleanup(siglist: *mut CSigList) -> c_int;
	fn alpm_extract_keyid(
		handle: *mut c_void,
		identifier: *const c_char,
		sig: *const u8,
		len: usize,
		keys: *mut *mut CList,
	) -> c_int;
	fn _alpm_check_pgp_helper(
		handle: *mut c_void,
		path: *const c_char,
		base64_sig: *const c_char,
		optional: c_int,
		marginal: c_int,
		unknown: c_int,
		sigdata: *mut *mut CSigList,
	) -> c_int;
	fn _alpm_process_siglist(
		handle: *mut c_void,
		identifier: *const c_char,
		siglist: *mut CSigList,
		optional: c_int,
		marginal: c_int,
		unknown: c_int,
	) -> c_int;
	fn _alpm_key_in_keychain(
		handle: *mut c_void,
		fpr: *const c_char,
	) -> c_int;
	fn _alpm_key_import(
		handle: *mut c_void,
		uid: *const c_char,
		fpr: *const c_char,
	) -> c_int;
	pub(crate) fn gpgme_check_version(req: *const c_char) -> *const c_char;
	pub(crate) fn gpgme_set_engine_info(
		proto: c_int,
		file_name: *const c_char,
		home_dir: *const c_char,
	) -> c_uint;
}

pub struct CDecoded {
	pub rc: i32,
	pub len: usize,
	// None where the C buffer is not initialized, see UPSTREAM.md
	pub data: Option<Vec<u8>>,
}

pub fn c_decode_signature(b64: &[u8]) -> CDecoded {
	let s = cstr(b64);
	let mut data: *mut u8 = std::ptr::null_mut();
	let mut len = 0usize;
	// SAFETY: s is a valid C string, data/len are valid out pointers
	let rc = unsafe {
		alpm_decode_signature(s.as_ptr(), &mut data, &mut len)
	};

	let has_symbol = b64.iter().any(|&c| c != b'\n' && c != b'\r');
	let out = (rc == 0 && has_symbol).then(|| {
		// SAFETY: on success data holds len bytes written by base64_decode,
		// len == 0 still gives a valid malloc(0) pointer on glibc
		unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
	});
	c_free(data.cast());
	CDecoded { rc, len, data: out }
}

const ENC: &[u8] =
	b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// standard padded base64, what repo-add writes into %PGPSIG%
pub fn encode_base64(raw: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	for chunk in raw.chunks(3) {
		let mut b = [0u8; 3];
		b[..chunk.len()].copy_from_slice(chunk);
		let x = u32::from(b[0]) << 16
			| u32::from(b[1]) << 8
			| u32::from(b[2]);
		for k in 0..4 {
			if k <= chunk.len() {
				out.push(ENC
					[(x >> (18 - 6 * k)) as usize & 0x3f]);
			} else {
				out.push(b'=');
			}
		}
	}
	out
}

// what a call left on the callbacks: import questions (uid,
// fingerprint) and error/warning log lines (level, text)
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SigEvents {
	pub questions: Vec<(Option<Vec<u8>>, Vec<u8>)>,
	pub logs: Vec<(i32, Vec<u8>)>,
}

// the Rust side's callbacks: records like the C ones, same answer
#[derive(Debug, Default)]
pub struct RecordingCallbacks {
	pub answer: bool,
	pub events: SigEvents,
}

impl Callbacks for RecordingCallbacks {
	fn question(&mut self, q: &mut Question<'_>) {
		let Question::ImportKey {
			import,
			uid,
			fingerprint,
		} = q
		else {
			panic!("signing asks import_key only: {q:?}");
		};
		let item = (uid.map(<[u8]>::to_vec), fingerprint.to_vec());
		self.events.questions.push(item);
		*import = c_int::from(self.answer);
	}

	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		self.events.logs.push((level as i32, msg.to_vec()));
	}
}

#[derive(Default)]
struct Recorder {
	answer: bool,
	events: SigEvents,
}

extern "C" fn questioncb(ctx: *mut c_void, q: *mut c_void) {
	// SAFETY: ctx is the handle's live RefCell<Recorder>, q a question
	// whose type field comes first; only import_key ones are read
	unsafe {
		let rec = &*ctx.cast::<RefCell<Recorder>>();
		let q = &mut *q.cast::<CQuestionImportKey>();
		if q.kind != QUESTION_IMPORT_KEY {
			return;
		}
		let mut rec = rec.borrow_mut();
		let item = (field(q.uid), field(q.fingerprint).unwrap());
		rec.events.questions.push(item);
		q.import = c_int::from(rec.answer);
	}
}

extern "C" fn logcb(
	ctx: *mut c_void,
	level: c_int,
	fmt: *const c_char,
	ap: *mut c_void,
) {
	let wanted = LogLevel::Error as c_int | LogLevel::Warning as c_int;
	if level & wanted == 0 {
		return;
	}
	let mut buf = [0u8; 4096];
	// SAFETY: fmt and ap are _alpm_log's format and va_list, used once;
	// vsnprintf stays within buf and nul terminates
	unsafe {
		vsnprintf(buf.as_mut_ptr().cast(), buf.len(), fmt, ap);
		let rec = &*ctx.cast::<RefCell<Recorder>>();
		let msg = field(buf.as_ptr().cast()).unwrap();
		rec.borrow_mut().events.logs.push((level, msg));
	}
}

// a call's result on either side: return code, pm_errno after it, its
// value and the callback events
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigCall<T> {
	pub rc: c_int,
	pub errno: c_int,
	pub value: T,
	pub events: SigEvents,
}

fn status(s: c_int) -> SigStatus {
	use SigStatus::*;
	[
		Valid,
		KeyExpired,
		SigExpired,
		KeyUnknown,
		KeyDisabled,
		Invalid,
	][s as usize]
}

fn validity(v: c_int) -> SigValidity {
	use SigValidity::*;
	[Full, Marginal, Never, Unknown][v as usize]
}

fn read_siglist(l: &CSigList) -> Vec<SigResult> {
	(0..l.count)
		.map(|i| {
			// SAFETY: results holds count entries
			let r = unsafe { &*l.results.add(i) };
			SigResult {
				key: PgpKey {
					fingerprint: field(r.key.fingerprint),
					uid: field(r.key.uid),
					name: field(r.key.name),
					email: field(r.key.email),
					created: r.key.created,
					expires: r.key.expires,
					length: r.key.length,
					revoked: r.key.revoked,
				},
				status: status(r.status),
				validity: validity(r.validity),
			}
		})
		.collect()
}

// copies a calloc'd siglist out and frees it like the C callers
fn take_siglist(l: *mut CSigList) -> Option<Vec<SigResult>> {
	if l.is_null() {
		return None;
	}
	// SAFETY: l came from _alpm_check_pgp_helper, freed here once
	unsafe {
		let out = read_siglist(&*l);
		alpm_siglist_cleanup(l);
		c_free(l.cast());
		Some(out)
	}
}

fn opt_cstr(s: Option<&[u8]>) -> Option<CString> {
	s.map(cstr)
}

fn ptr_of(s: &Option<CString>) -> *const c_char {
	s.as_ref().map_or(ptr::null(), |s| s.as_ptr())
}

fn empty_siglist() -> CSigList {
	CSigList {
		count: 0,
		results: ptr::null_mut(),
	}
}

type QuestionCb = extern "C" fn(*mut c_void, *mut c_void);
type LogCb = extern "C" fn(*mut c_void, c_int, *const c_char, *mut c_void);

// a C handle on a fixture root with a gpgdir, question and log
// callbacks recording into a Recorder. holds the ALPM lock
pub struct CSigHandle {
	h: *mut c_void,
	rec: Box<RefCell<Recorder>>,
	gpgdir: CString,
	gpg: Option<CString>,
	// what gpgme's engine was last set to: gpgme reruns gpg --version
	// after every change
	engine: RefCell<Option<(CString, Option<CString>)>>,
	_guard: MutexGuard<'static, ()>,
}

impl CSigHandle {
	// root and dbpath must exist
	pub fn new(root: &Path, dbpath: &Path, gpgdir: &[u8]) -> Self {
		let guard = ALPM.lock().unwrap_or_else(|e| e.into_inner());
		let root = cstr(root.as_os_str().as_bytes());
		let dbpath = cstr(dbpath.as_os_str().as_bytes());
		let mut err = 0;
		// SAFETY: valid C strings, err receives the failure code
		let h = unsafe {
			alpm_initialize(
				root.as_ptr(),
				dbpath.as_ptr(),
				&mut err,
			)
		};
		assert!(!h.is_null(), "alpm_initialize failed: {err}");
		let rec = Box::new(RefCell::new(Recorder::default()));
		let ctx: *const RefCell<Recorder> = &*rec;
		let (q, l): (QuestionCb, LogCb) = (questioncb, logcb);
		// SAFETY: h is live; the callbacks match alpm_cb_question and
		// alpm_cb_log on x86_64, ctx outlives the handle (dropped after
		// alpm_release)
		unsafe {
			alpm_option_set_questioncb(
				h,
				Some(q),
				ctx.cast_mut().cast(),
			);
			alpm_option_set_logcb(
				h,
				Some(l),
				ctx.cast_mut().cast(),
			);
			gpgme_check_version(ptr::null());
		}
		let mut c = CSigHandle {
			h,
			rec,
			gpgdir: cstr(b""),
			gpg: None,
			engine: RefCell::new(None),
			_guard: guard,
		};
		c.set_gpgdir(gpgdir);
		// run init_gpgme now, so its engine setup comes before ours. a
		// pattern under 8 characters returns before gpg runs
		let fpr = cstr(b"init");
		// SAFETY: live handle, valid string
		unsafe { _alpm_key_in_keychain(c.h, fpr.as_ptr()) };
		c
	}

	// alpm_option_set_gpgdir, kept with the '/' it appends
	pub fn set_gpgdir(&mut self, gpgdir: &[u8]) {
		let dir = cstr(gpgdir);
		// SAFETY: live handle, valid string copied by the C
		let rc =
			unsafe { alpm_option_set_gpgdir(self.h, dir.as_ptr()) };
		assert_eq!(rc, 0);
		let mut d = gpgdir.to_vec();
		if d.last() != Some(&b'/') {
			d.push(b'/');
		}
		self.gpgdir = cstr(&d);
	}

	// the gpg gpgme runs, None for its default
	pub fn set_gpg(&mut self, gpg: Option<&Path>) {
		self.gpg = gpg.map(|p| cstr(p.as_os_str().as_bytes()));
	}

	pub fn set_answer(&mut self, yes: bool) {
		self.rec.borrow_mut().answer = yes;
	}

	// pm_errno reset (CHECK_HANDLE), engine pointed at the gpgdir
	fn begin(&self) {
		self.rec.borrow_mut().events = SigEvents::default();
		// SAFETY: live handle
		unsafe { alpm_option_get_root(self.h) };
		let want = (self.gpgdir.clone(), self.gpg.clone());
		if self.engine.borrow().as_ref() == Some(&want) {
			return;
		}
		// SAFETY: gpgme copies the strings
		unsafe {
			gpgme_set_engine_info(
				GPGME_PROTOCOL_OPENPGP,
				ptr_of(&self.gpg),
				self.gpgdir.as_ptr(),
			);
		}
		*self.engine.borrow_mut() = Some(want);
	}

	fn end<T>(&self, rc: c_int, value: T) -> SigCall<T> {
		SigCall {
			rc,
			// SAFETY: live handle
			errno: unsafe { alpm_errno(self.h) },
			value,
			events: std::mem::take(
				&mut self.rec.borrow_mut().events,
			),
		}
	}

	// alpm_pkg_check_pgp_signature on a package with that filename and
	// base64_sig
	pub fn pkg_check(&self, pkg: &Package) -> SigCall<Vec<SigResult>> {
		let b = CPkgBox::new(pkg);
		let mut list = empty_siglist();
		self.begin();
		// SAFETY: b.0 is live and gets this handle; list is filled by
		// the C and cleaned up after the copy
		let (rc, sigs) = unsafe {
			(*b.0).handle = self.h;
			let rc = alpm_pkg_check_pgp_signature(b.0, &mut list);
			let sigs = read_siglist(&list);
			alpm_siglist_cleanup(&mut list);
			(rc, sigs)
		};
		self.end(rc, sigs)
	}

	// alpm_db_check_pgp_signature on <dbpath>sync/<treename>.db, the db
	// registered at level 0 for the call
	pub fn db_check(&self, treename: &[u8]) -> SigCall<Vec<SigResult>> {
		let name = cstr(treename);
		let mut list = empty_siglist();
		// SAFETY: live handle; level 0 registration validates nothing
		let db = unsafe {
			alpm_register_syncdb(self.h, name.as_ptr(), 0)
		};
		assert!(!db.is_null());
		self.begin();
		// SAFETY: db is live until unregistered after the copy
		let (rc, sigs) = unsafe {
			let rc = alpm_db_check_pgp_signature(db, &mut list);
			let sigs = read_siglist(&list);
			alpm_siglist_cleanup(&mut list);
			(rc, sigs)
		};
		let out = self.end(rc, sigs);
		// SAFETY: db registered above, not used afterwards
		unsafe { alpm_db_unregister(db) };
		out
	}

	// _alpm_check_pgp_helper with [optional, marginal, unknown], then
	// _alpm_process_siglist on its sigdata under identifier when given:
	// (results, retry)
	pub fn helper(
		&self,
		path: &[u8],
		base64_sig: Option<&[u8]>,
		flags: [bool; 3],
		identifier: Option<&[u8]>,
	) -> SigCall<(Vec<SigResult>, Option<c_int>)> {
		let path = cstr(path);
		let b64 = opt_cstr(base64_sig);
		let ident = opt_cstr(identifier);
		let [o, m, u] = flags.map(c_int::from);
		let mut sigdata: *mut CSigList = ptr::null_mut();
		self.begin();
		// SAFETY: live handle and strings; sigdata is calloc'd by the
		// C and freed by take_siglist
		let rc = unsafe {
			_alpm_check_pgp_helper(
				self.h,
				path.as_ptr(),
				ptr_of(&b64),
				o,
				m,
				u,
				&mut sigdata,
			)
		};
		let retry = ident.as_ref().map(|id| {
			// SAFETY: sigdata from the helper above, live
			unsafe {
				_alpm_process_siglist(
					self.h,
					id.as_ptr(),
					sigdata,
					o,
					m,
					u,
				)
			}
		});
		let sigs = take_siglist(sigdata).expect("helper sets sigdata");
		self.end(rc, (sigs, retry))
	}

	// _alpm_pkg_validate_internal: (validation, sigdata)
	pub fn validate(
		&self,
		path: &[u8],
		syncpkg: Option<&Package>,
		level: c_int,
	) -> SigCall<(c_int, Option<Vec<SigResult>>)> {
		let path = cstr(path);
		let sync = syncpkg.map(CPkgBox::new);
		let sp = sync.as_ref().map_or(ptr::null_mut(), |b| b.0);
		let mut sigdata: *mut CSigList = ptr::null_mut();
		let mut validation = 0;
		self.begin();
		// SAFETY: live handle, package and string; sigdata stays NULL
		// or is calloc'd by the C and freed by take_siglist
		let rc = unsafe {
			if !sp.is_null() {
				(*sp).handle = self.h;
			}
			_alpm_pkg_validate_internal(
				self.h,
				path.as_ptr(),
				sp,
				level,
				(&raw mut sigdata).cast(),
				&mut validation,
			)
		};
		let sigs = take_siglist(sigdata);
		self.end(rc, (validation, sigs))
	}

	// alpm_pkg_load at level: the loaded package
	pub fn pkg_load(
		&self,
		path: &[u8],
		full: bool,
		level: c_int,
	) -> SigCall<Option<Package>> {
		let path = cstr(path);
		let full = c_int::from(full);
		let mut pkg: *mut CPkg = ptr::null_mut();
		self.begin();
		// SAFETY: live handle, valid string, pkg receives a package or
		// stays NULL; freed after the copy
		let (rc, out) = unsafe {
			let p = path.as_ptr();
			let rc =
				alpm_pkg_load(self.h, p, full, level, &mut pkg);
			let out = (!pkg.is_null()).then(|| read_pkg(pkg));
			if !pkg.is_null() {
				alpm_pkg_free(pkg);
			}
			(rc, out)
		};
		self.end(rc, out)
	}

	// alpm_register_syncdb at level (sync_db_validate runs), then
	// alpm_db_get_valid; unregistered after
	pub fn register(&self, treename: &[u8], level: c_int) -> SigCall<()> {
		let name = cstr(treename);
		self.begin();
		// SAFETY: live handle and string; db unregistered before the
		// errno is read
		let (rc, errno) = unsafe {
			let db = alpm_register_syncdb(
				self.h,
				name.as_ptr(),
				level,
			);
			assert!(!db.is_null(), "register {treename:?}");
			let rc = alpm_db_get_valid(db);
			let errno = alpm_errno(self.h);
			alpm_db_unregister(db);
			(rc, errno)
		};
		let mut out = self.end(rc, ());
		out.errno = errno;
		out
	}

	// _alpm_key_in_keychain: 1 known, 0 unknown, -1 failed
	pub fn in_keychain(&self, fpr: &[u8]) -> SigCall<()> {
		let fpr = cstr(fpr);
		self.begin();
		// SAFETY: live handle, valid string
		let rc = unsafe { _alpm_key_in_keychain(self.h, fpr.as_ptr()) };
		self.end(rc, ())
	}

	// _alpm_key_import: 0 imported, -1 not
	pub fn key_import(
		&self,
		uid: Option<&[u8]>,
		fpr: &[u8],
	) -> SigCall<()> {
		let uid = opt_cstr(uid);
		let fpr = cstr(fpr);
		self.begin();
		// SAFETY: live handle, strings valid for the call
		let rc = unsafe {
			_alpm_key_import(self.h, ptr_of(&uid), fpr.as_ptr())
		};
		self.end(rc, ())
	}

	// alpm_extract_keyid. the buffer has one byte more than len: the C
	// reads the unhashed length one byte past a signature whose hashed
	// area ends there (UPSTREAM.md), the outcome does not depend on it.
	// sig must pass keyid_input_defined
	pub fn extract_keyid(
		&self,
		identifier: &[u8],
		sig: &[u8],
	) -> SigCall<Vec<Vec<u8>>> {
		let mut check = sig.to_vec();
		keyid_input_defined(&mut check);
		assert_eq!(check, sig, "4-byte length with the top bit set");
		let ident = cstr(identifier);
		let padded = [sig, &[0]].concat();
		let mut keys: *mut CList = ptr::null_mut();
		self.begin();
		// SAFETY: live handle, padded holds sig.len() + 1 bytes, keys
		// receives strdup'd strings freed by take_strs
		let rc = unsafe {
			alpm_extract_keyid(
				self.h,
				ident.as_ptr(),
				padded.as_ptr(),
				sig.len(),
				&mut keys,
			)
		};
		let keys = take_strs(keys);
		self.end(rc, keys)
	}
}

impl Drop for CSigHandle {
	fn drop(&mut self) {
		// SAFETY: h is live and not used afterwards
		unsafe { alpm_release(self.h) };
	}
}

// makes sig an alpm_extract_keyid input the C is defined on: a 4-byte
// length (after 0xff, or after an old format tag of length type 2) with
// its top byte >= 0x80 overflows a signed int shift there (UPSTREAM.md).
// clears that bit wherever such a length could start
pub fn keyid_input_defined(sig: &mut [u8]) {
	for i in 1..sig.len() {
		let prev = sig[i - 1];
		if prev == 0xff || prev & 0xc3 == 0x82 {
			sig[i] &= 0x7f;
		}
	}
}

// homes the verifying keyrings live in
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Home {
	// pacman-key layout, trust-model pgp
	Pgp,
	// copy with trust-model direct: validity is the ownertrust
	Direct,
	// copy with a read-only pubring.gpg
	ReadOnly,
}

pub const HOMES: [Home; 3] = [Home::Pgp, Home::Direct, Home::ReadOnly];

// signer keys: name, uid, faked creation time, expiry
const SIGNERS: &[(&str, &str, Option<&str>, &str)] = &[
	("full", "Full Packager <full@x.test>", None, "never"),
	("intro", "Marg Intro <intro@x.test>", None, "never"),
	("marg", "Marginal Packager <marg@x.test>", None, "never"),
	("unk", "Unknown Trust <unk@x.test>", None, "never"),
	("never", "Never Trust <never@x.test>", None, "never"),
	("dis", "Disabled Key <dis@x.test>", None, "never"),
	("rev", "Revoked Key <rev@x.test>", None, "never"),
	("stranger", "Stranger <stranger@x.test>", None, "never"),
	("mbox", "mbox@x.test", None, "never"),
	("odd", "Odd: Name (c) <odd@x.test>", None, "never"),
	("exp", "Expired Key <exp@x.test>", Some(OLD_KEY), "1y"),
	(
		"sigexp",
		"Sig Expirer <sigexp@x.test>",
		Some(OLD_KEY),
		"never",
	),
];

// creation time of the expired keys, and when they sign
const OLD_KEY: &str = "20200101T000000";
const OLD_SIG: &str = "20200601T000000";

// signed files: f/<name>.pkg.tar with a .sig made as the name says, the
// same pair as db/sync/<name>.db(.sig)
pub const FILES: &[&str] = &[
	"full",
	"intro",
	"marg",
	"unk",
	"never",
	"dis",
	"rev",
	"stranger",
	"mbox",
	"odd",
	"exp",
	"sigexp",
	"master",
	"two",
	"mixed",
	// signature of another file
	"bad",
	"garbage",
	"empty",
	"trunc",
	// a public key export as signature
	"pubkey",
	"armor",
	// 150 signatures, over read_sigfile's limit
	"big",
	"nosig",
	"dirsig",
	"unreadable",
	"dangling",
];

const PKGINFO: &str = "\
pkgname = sigtest
pkgbase = sigtest
xdata = pkgtype=pkg
pkgver = 1.0-1
pkgdesc = a signed package
url = https://example.org/
builddate = 1720811171
packager = John Doe <john@example.org>
size = 10
arch = any
license = MIT
";

// gpg on a fixture home: batch, no passphrase, stdout returned
fn gpg(home: &Path, args: &[&str], stdin: Option<&[u8]>) -> Vec<u8> {
	let input = match stdin {
		Some(_) => Stdio::piped(),
		None => Stdio::null(),
	};
	let mut child = Command::new("gpg")
		.arg("--homedir")
		.arg(home)
		.args(["--batch", "--no-tty", "--no-permission-warning"])
		.args(["--passphrase", "", "--pinentry-mode", "loopback"])
		.args(args)
		.stdin(input)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("gpg not found");
	if let Some(data) = stdin {
		child.stdin.take().unwrap().write_all(data).unwrap();
	}
	let out = child.wait_with_output().unwrap();
	let err = String::from_utf8_lossy(&out.stderr);
	assert!(out.status.success(), "gpg {args:?}: {err}");
	out.stdout
}

fn first_fpr(colons: &[u8]) -> String {
	let text = String::from_utf8_lossy(colons);
	let line = text.lines().find(|l| l.starts_with("fpr:")).unwrap();
	line.split(':').nth(9).unwrap().to_string()
}

fn mkdir_private(p: &Path) {
	fs::create_dir_all(p).unwrap();
	fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}

fn set_mode(p: &Path, mode: u32) {
	fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

// the keyrings and signed files, removed with their gpg-agents on drop
pub struct GpgFixture {
	root: TempRoot,
	// signer name -> primary fingerprint, "master" for the pacman key
	fprs: Vec<(String, String)>,
}

impl GpgFixture {
	pub fn new(tag: &str) -> Self {
		let mut fx = GpgFixture {
			root: TempRoot::new(tag),
			fprs: Vec::new(),
		};
		fx.build_signers();
		fx.build_pgp();
		fx.build_copies();
		fx.build_files();
		fx
	}

	pub fn dir(&self) -> &Path {
		self.root.dir()
	}

	pub fn root_dir(&self) -> PathBuf {
		self.dir().join("root")
	}

	pub fn db_dir(&self) -> PathBuf {
		self.dir().join("db")
	}

	// handle->dbpath: resolved, with the '/' alpm_initialize appends
	pub fn dbpath(&self) -> Vec<u8> {
		self.root.dbpath()
	}

	// handle->gpgdir of a home, with the '/' set_gpgdir appends
	pub fn home(&self, home: Home) -> Vec<u8> {
		let name = match home {
			Home::Pgp => "pgp",
			Home::Direct => "direct",
			Home::ReadOnly => "ro",
		};
		[&self.root.path(name)[..], b"/"].concat()
	}

	pub fn fpr(&self, name: &str) -> &str {
		let f = self.fprs.iter().find(|(n, _)| n == name);
		&f.unwrap_or_else(|| panic!("no key {name}")).1
	}

	// (name, fingerprint) of every key made
	pub fn fprs(&self) -> &[(String, String)] {
		&self.fprs
	}

	// f/<name>.pkg.tar
	pub fn file(&self, name: &str) -> Vec<u8> {
		self.root.path(&format!("f/{name}.pkg.tar"))
	}

	// f/<name>.pkg.tar.sig when it is a readable file
	pub fn sig_bytes(&self, name: &str) -> Option<Vec<u8>> {
		fs::read(self.dir().join(format!("f/{name}.pkg.tar.sig"))).ok()
	}

	fn signer_home(&self) -> PathBuf {
		self.dir().join("s")
	}

	fn pgp_home(&self) -> PathBuf {
		self.dir().join("pgp")
	}

	fn build_signers(&mut self) {
		let s = self.signer_home();
		mkdir_private(&s);
		for &(name, uid, faked, expire) in SIGNERS {
			let mut args = Vec::new();
			if let Some(t) = faked {
				args.extend(["--faked-system-time", t]);
			}
			args.extend([
				"--quick-gen-key",
				uid,
				"ed25519",
				"sign",
			]);
			args.push(expire);
			gpg(&s, &args, None);
			let exact = format!("={uid}");
			let list =
				["--with-colons", "--list-keys", "--", &exact];
			let fpr = first_fpr(&gpg(&s, &list, None));
			self.fprs.push((name.to_string(), fpr));
		}
		// the introducer certifies the marginal packager
		let (intro, marg) = (self.fpr("intro"), self.fpr("marg"));
		let args = ["--default-key", intro, "--quick-sign-key", marg];
		gpg(&s, &args, None);
	}

	// like pacman-key --init and --lsign-key: a master key, packager
	// keys signed locally, ownertrust for the introducer, one key
	// disabled, one revoked
	fn build_pgp(&mut self) {
		let (s, v) = (self.signer_home(), self.pgp_home());
		mkdir_private(&v);
		fs::write(v.join("pubring.gpg"), b"").unwrap();
		gpg(&v, &["--update-trustdb"], None);
		// no network: keyserver and WKD lookups fail at once
		let conf = "no-greeting\nno-permission-warning\n\
			keyserver-options timeout=10\n\
			keyserver-options import-clean\ndisable-dirmngr\n";
		fs::write(v.join("gpg.conf"), conf).unwrap();
		let master = "Pacman Master <pm@x.test>";
		let gen_key = ["--quick-gen-key", master, "ed25519", "sign"];
		gpg(&v, &[&gen_key[..], &["never"]].concat(), None);
		let exact = format!("={master}");
		let list = ["--with-colons", "--list-keys", "--", &exact];
		let pm = first_fpr(&gpg(&v, &list, None));
		self.fprs.push(("master".to_string(), pm.clone()));
		for &(name, ..) in SIGNERS {
			if name == "stranger" {
				continue;
			}
			let key = gpg(&s, &["--export", self.fpr(name)], None);
			gpg(&v, &["--import"], Some(&key));
		}
		let lsigned = [
			"full", "intro", "dis", "never", "rev", "mbox", "odd",
			"sigexp",
		];
		for name in lsigned {
			let args = ["--default-key", &pm, "--quick-lsign-key"];
			gpg(&v, &[&args[..], &[self.fpr(name)]].concat(), None);
		}
		let (intro, never) = (self.fpr("intro"), self.fpr("never"));
		let trust = format!("{intro}:4:\n{never}:3:\n");
		gpg(&v, &["--import-ownertrust"], Some(trust.as_bytes()));
		let cmd = ["--command-fd", "0", "--edit-key", self.fpr("dis")];
		gpg(&v, &cmd, Some(b"disable\nquit\n"));
		let rev = self.fpr("rev");
		let cert = s.join(format!("openpgp-revocs.d/{rev}.rev"));
		let cert = fs::read_to_string(cert).unwrap();
		let cert = cert.replace(":-----BEGIN", "-----BEGIN");
		gpg(&v, &["--import"], Some(cert.as_bytes()));
		gpg(&v, &["--check-trustdb"], None);
	}

	// the direct-trust and read-only keyrings: copies of pgp's files
	fn build_copies(&self) {
		let v = self.pgp_home();
		let copies = [("direct", "trust-model direct\n"), ("ro", "")];
		for (name, extra) in copies {
			let d = self.dir().join(name);
			mkdir_private(&d);
			for f in ["pubring.gpg", "trustdb.gpg"] {
				fs::copy(v.join(f), d.join(f)).unwrap();
			}
			let conf =
				fs::read_to_string(v.join("gpg.conf")).unwrap();
			fs::write(d.join("gpg.conf"), conf + extra).unwrap();
			gpg(&d, &["--check-trustdb"], None);
		}
		set_mode(&self.dir().join("ro/pubring.gpg"), 0o444);
	}

	// detached signature of data by the signer keys named, for files
	// other tests serve
	pub fn sign_file(&self, keys: &[&str], data: &Path) -> Vec<u8> {
		self.sign(&self.signer_home(), keys, &[], data)
	}

	// detached signature of data by keys, extra options first
	fn sign(
		&self,
		home: &Path,
		keys: &[&str],
		extra: &[&str],
		data: &Path,
	) -> Vec<u8> {
		let out = self.dir().join("sig.tmp");
		let mut args: Vec<&str> = extra.to_vec();
		for k in keys {
			args.extend(["-u", self.fpr(k)]);
		}
		let (o, d) = (out.to_str().unwrap(), data.to_str().unwrap());
		args.extend(["--yes", "--detach-sign", "-o", o, d]);
		gpg(home, &args, None);
		let sig = fs::read(&out).unwrap();
		fs::remove_file(out).unwrap();
		sig
	}

	// the .sig of a FILES entry, None where there is no plain file
	fn make_sig(
		&self,
		name: &str,
		data: &Path,
		full: &[u8],
	) -> Option<Vec<u8>> {
		let (s, v) = (self.signer_home(), self.pgp_home());
		let old = ["--faked-system-time", OLD_SIG];
		let sig = match name {
			"exp" => self.sign(&s, &["exp"], &old, data),
			"sigexp" => {
				let extra = [
					old[0],
					old[1],
					"--default-sig-expire=1d",
				];
				self.sign(&s, &["sigexp"], &extra, data)
			}
			"master" => self.sign(&v, &["master"], &[], data),
			"two" => self.sign(&s, &["full", "marg"], &[], data),
			"mixed" => {
				self.sign(&s, &["full", "stranger"], &[], data)
			}
			"bad" => full.to_vec(),
			"garbage" => {
				let mut g: Vec<u8> = (0..100u32)
					.map(|i| {
						(i.wrapping_mul(2_654_435_761)
							>> 13) as u8
					})
					.collect();
				keyid_input_defined(&mut g);
				g
			}
			"empty" => Vec::new(),
			"trunc" => full[..60].to_vec(),
			"pubkey" => {
				gpg(&s, &["--export", self.fpr("full")], None)
			}
			"armor" => self.sign(&s, &["full"], &["--armor"], data),
			"big" => full.repeat(150),
			"nosig" | "dirsig" | "unreadable" | "dangling" => {
				return None;
			}
			signer => self.sign(&s, &[signer], &[], data),
		};
		Some(sig)
	}

	fn build_files(&self) {
		let f = self.dir().join("f");
		fs::create_dir_all(&f).unwrap();
		let pkg = |file: &[u8]| {
			ustar(&[
				tar_file(".PKGINFO", PKGINFO.as_bytes()),
				tar_file("usr/share/sigtest", file),
			])
		};
		let (a, b) = (pkg(b"a\n"), pkg(b"b\n"));
		let data = f.join("data");
		fs::write(&data, &a).unwrap();
		let full =
			self.sign(&self.signer_home(), &["full"], &[], &data);
		for &name in FILES {
			let sig = self.make_sig(name, &data, &full);
			let content = if name == "bad" { &b } else { &a };
			let pkgfile = f.join(format!("{name}.pkg.tar"));
			for file in [pkgfile, self.root.sync_file(name, ".db")]
			{
				fs::write(&file, content).unwrap();
				let sp = PathBuf::from(format!(
					"{}.sig",
					file.display()
				));
				match (name, &sig) {
					(_, Some(sig)) => {
						fs::write(&sp, sig).unwrap()
					}
					("dirsig", _) => {
						fs::create_dir(&sp).unwrap()
					}
					("unreadable", _) => {
						fs::write(&sp, &full).unwrap();
						set_mode(&sp, 0);
					}
					("dangling", _) => {
						std::os::unix::fs::symlink(
							"nowhere", &sp,
						)
						.unwrap();
					}
					_ => {}
				}
			}
		}
		fs::remove_file(data).unwrap();
	}
}

impl Drop for GpgFixture {
	fn drop(&mut self) {
		// the agents key generation and signing started; TempRoot
		// removes the tree after this
		for home in ["s", "pgp", "direct", "ro"] {
			let dir = self.dir().join(home);
			let st = Command::new("gpgconf")
				.arg("--homedir")
				.arg(&dir)
				.args(["--kill", "all"])
				.status();
			assert!(
				st.is_ok_and(|s| s.success()),
				"gpgconf {dir:?}"
			);
		}
	}
}

// a gpg wrapper logging each argv (one argument per line, a blank line
// after) to log, then running gpg
pub fn write_gpg_logger(script: &Path, log: &Path) {
	let body = format!(
		"#!/bin/sh\n{{ for a in \"$@\"; do \
		printf '%s\\n' \"$a\"; done; echo; }} >> '{}'\n\
		exec gpg \"$@\"\n",
		log.display()
	);
	fs::write(script, body).unwrap();
	set_mode(script, 0o755);
}
