// port of lib/libalpm/signing.c. gpgme is replaced by gpg(1) driven the
// way gpgme's engine-gpg drives it (METHODOLOGY.md): the same binary,
// keyring (handle->gpgdir as --homedir) and trust model, the status lines
// and colon listings gpgme parses, mapped onto what pacman reads from
// gpgme's results.
//
// gpgme reads the signature and the file itself and hands them over on
// extra fds ("--enable-special-filenames -&N"), status comes back on
// another one. std::process has stdin and stdout only: the signature is
// read here and goes over stdin, the file goes by path after a first read
// here (a read error is gpgme's error), status comes over stdout for the
// operations with no other output (verify, import). keylists print
// colons on stdout and need no status, so they get none. gpgme's
// --lc-ctype/--lc-messages/--display/--ttyname only reach pinentry, which
// no operation here starts, and are left out.
//
// handle->gpgdir and handle->known_keys live in Keyring, the question and
// the error/warning log lines go through Callbacks. pm_errno is Err as
// in the other modules. debug logging is not modelled.
// alpm_siglist_cleanup is dropping the Vec.

use std::ffi::{OsStr, OsString, c_int, c_uint};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use rustix::fs::{Access, AtFlags, CWD, accessat};

use crate::base64;
use crate::callbacks::{Callbacks, LogLevel, Question};
use crate::db::Db;
use crate::error::Errno;
use crate::package::Package;
use crate::util::until_nul;

pub use crate::db::{SIG_DATABASE, SIG_USE_DEFAULT};

// alpm_siglevel_t
pub const SIG_PACKAGE: c_int = 1;
pub const SIG_PACKAGE_OPTIONAL: c_int = 1 << 1;
pub const SIG_PACKAGE_MARGINAL_OK: c_int = 1 << 2;
pub const SIG_PACKAGE_UNKNOWN_OK: c_int = 1 << 3;
pub const SIG_DATABASE_OPTIONAL: c_int = 1 << 11;
pub const SIG_DATABASE_MARGINAL_OK: c_int = 1 << 12;
pub const SIG_DATABASE_UNKNOWN_OK: c_int = 1 << 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
	InvalidCharacter,
	// output is capped at 3/4 of the input length, so unpadded input whose
	// symbol count is not a multiple of 4 fails unless line breaks pad it
	BufferTooSmall,
}

// alpm_decode_signature
pub fn decode_signature(b64: &[u8]) -> Result<Vec<u8>, DecodeError> {
	let b64 = until_nul(b64);
	let cap = b64.len() * 3 / 4;
	let needed = base64::decoded_len(b64)
		.map_err(|_| DecodeError::InvalidCharacter)?;
	if needed > cap {
		return Err(DecodeError::BufferTooSmall);
	}
	base64::decode(b64).map_err(|_| DecodeError::InvalidCharacter)
}

// alpm_sigstatus_t
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SigStatus {
	Valid,
	KeyExpired,
	SigExpired,
	KeyUnknown,
	KeyDisabled,
	Invalid,
}

// alpm_sigvalidity_t
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SigValidity {
	Full,
	Marginal,
	Never,
	Unknown,
}

// alpm_pgpkey_t without the gpgme key behind it. a signature check fills
// fingerprint to expires, length and revoked only come from a keyserver
// search
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PgpKey {
	pub fingerprint: Option<Vec<u8>>,
	pub uid: Option<Vec<u8>>,
	pub name: Option<Vec<u8>>,
	pub email: Option<Vec<u8>>,
	pub created: i64,
	pub expires: i64,
	pub length: c_uint,
	pub revoked: c_uint,
}

// alpm_sigresult_t
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigResult {
	pub key: PgpKey,
	pub status: SigStatus,
	pub validity: SigValidity,
}

// handle->gpgdir, handle->known_keys and the gpg binary gpgme would run
#[derive(Debug, Clone)]
pub struct Keyring {
	// empty is the C's NULL gpgdir: no --homedir, files looked up in cwd
	gpgdir: Vec<u8>,
	gpg: PathBuf,
	known_keys: Vec<Vec<u8>>,
	// init_gpgme ran, its keyring warning comes once. the C flag is
	// process wide, this one per keyring
	init: bool,
}

// the gpgme_error_t texts pacman logs as "GPGME error: %s"
#[derive(Debug, Clone, PartialEq, Eq)]
enum GpgError {
	// reading a data stream failed, strerror's text
	Read(Vec<u8>),
	NoData,
	General,
	BadData,
	AmbiguousName,
	InvValue,
	// gpg could not be run or its output not read
	InvEngine,
}

impl GpgError {
	// gpgme_strerror in the C locale
	fn text(&self) -> &[u8] {
		match self {
			GpgError::Read(text) => text,
			GpgError::NoData => b"No data",
			GpgError::General => b"General error",
			GpgError::BadData => b"Bad data",
			GpgError::AmbiguousName => b"Ambiguous name",
			GpgError::InvValue => b"Invalid value",
			GpgError::InvEngine => b"Invalid crypto engine",
		}
	}
}

// gpg_err_code of gpgme_signature_t.status, as far as pacman tells
// them apart
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Code {
	NoError,
	KeyExpired,
	SigExpired,
	NoPubkey,
	// bad signature, revoked key, unsupported algorithm, general, no data
	Other,
}

// gpgme_signature_t: fpr, status, validity (gpgme's UNDEFINED is
// already UNKNOWN, ULTIMATE already FULL)
#[derive(Debug, Clone)]
struct GpgSig {
	fpr: Option<Vec<u8>>,
	code: Code,
	validity: SigValidity,
}

// gpgme_user_id_t
#[derive(Debug, Clone, Default)]
struct Uid {
	uid: Vec<u8>,
	name: Vec<u8>,
	email: Vec<u8>,
}

// gpgme_key_t, primary subkey only
#[derive(Debug, Clone, Default)]
struct Key {
	fpr: Option<Vec<u8>>,
	keyid: Vec<u8>,
	uids: Vec<Uid>,
	created: i64,
	expires: i64,
	expired: bool,
	disabled: bool,
}

// gpgme_keylist_mode_t of the three lookups
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListMode {
	Local,
	// GPGME_KEYLIST_MODE_LOCATE_EXTERNAL (WKD)
	LocateExternal,
	// GPGME_KEYLIST_MODE_EXTERN without LOCAL (keyserver)
	Extern,
}

// gpg_error_from_errno's text for a failed read: io::Error's without
// the " (os error N)" std adds
fn read_error(e: std::io::Error) -> GpgError {
	let text = e.to_string();
	let text = match text.rfind(" (os error ") {
		Some(i) => &text[..i],
		None => &text[..],
	};
	GpgError::Read(text.as_bytes().to_vec())
}

// the first read gpgme's data callback makes on the file
fn first_read(path: &[u8]) -> Result<(), GpgError> {
	let mut file = File::open(os(path)).map_err(read_error)?;
	file.read(&mut [0; 1]).map(drop).map_err(read_error)
}

fn os(b: &[u8]) -> &OsStr {
	OsStr::from_bytes(b)
}

// _alpm_access: faccessat(AT_SYMLINK_NOFOLLOW), true when allowed
fn access(path: &[u8], mode: Access) -> bool {
	let flags = AtFlags::SYMLINK_NOFOLLOW;
	accessat(CWD, until_nul(path), mode, flags).is_ok()
}

// leading decimal digits like gpgme's timestamp parsing, 0 when none
fn number(field: &[u8]) -> i64 {
	let digits = field.iter().take_while(|c| c.is_ascii_digit());
	digits.fold(0i64, |n, &c| {
		n.saturating_mul(10).saturating_add(i64::from(c - b'0'))
	})
}

fn fields(line: &[u8]) -> Vec<&[u8]> {
	line.split(|&c| c == b':').collect()
}

fn field<'a>(f: &[&'a [u8]], i: usize) -> &'a [u8] {
	f.get(i).copied().unwrap_or_default()
}

fn hex(c: u8) -> Option<u8> {
	(c as char).to_digit(16).map(|d| d as u8)
}

fn hex_byte(a: u8, b: u8) -> Option<u8> {
	Some(hex(a)? << 4 | hex(b)?)
}

// _gpgme_decode_c_string: gpg's colon escapes. a NUL byte stays "\0"
fn decode_c_string(src: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(src.len());
	let mut i = 0;
	while i < src.len() {
		if src[i] != b'\\' || i + 1 >= src.len() {
			out.push(src[i]);
			i += 1;
			continue;
		}
		let c = src[i + 1];
		let simple = match c {
			b'n' => Some(b'\n'),
			b'r' => Some(b'\r'),
			b'v' => Some(0x0b),
			b'b' => Some(0x08),
			b't' => Some(b'\t'),
			b'f' => Some(0x0c),
			b'a' => Some(0x07),
			b'\'' | b'"' | b'\\' => Some(c),
			_ => None,
		};
		let byte = match simple {
			Some(s) => Some(s),
			None if c == b'x' && i + 3 < src.len() => {
				hex_byte(src[i + 2], src[i + 3])
			}
			None => None,
		};
		match (simple, byte) {
			(Some(s), _) => {
				out.push(s);
				i += 2;
			}
			(None, Some(0)) => {
				out.extend_from_slice(b"\\0");
				i += 4;
			}
			(None, Some(b)) => {
				out.push(b);
				i += 4;
			}
			(None, None) => {
				out.extend_from_slice(&src[i..i + 2]);
				i += 2;
			}
		}
	}
	out
}

// %XX escapes of keyserver listings
fn decode_percent(src: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(src.len());
	let mut i = 0;
	while i < src.len() {
		let byte = (src[i] == b'%' && i + 2 < src.len())
			.then(|| hex_byte(src[i + 1], src[i + 2]))
			.flatten();
		match byte {
			Some(b) => {
				out.push(b);
				i += 3;
			}
			None => {
				out.push(src[i]);
				i += 1;
			}
		}
	}
	out
}

// set_user_id_part: trailing blanks dropped
fn uid_part(s: &[u8]) -> Vec<u8> {
	let end = s.iter().rposition(|&c| c != b' ' && c != b'\t');
	end.map_or_else(Vec::new, |e| s[..=e].to_vec())
}

// gpgme's parse_user_id: "Name (comment) <email>", the first of each
// part wins, nesting counted
fn parse_user_id(src: &[u8]) -> (Vec<u8>, Vec<u8>) {
	let (mut name, mut email) = (None, None);
	let (mut in_name, mut in_email, mut in_comment) = (false, 0, 0);
	let mut start = 0;
	for (i, &c) in src.iter().enumerate() {
		if in_email > 0 {
			if c == b'<' {
				in_email += 1;
			} else if c == b'>' {
				in_email -= 1;
				if in_email == 0 && email.is_none() {
					email = Some(uid_part(&src[start..i]));
				}
			}
		} else if in_comment > 0 {
			if c == b'(' {
				in_comment += 1;
			} else if c == b')' {
				in_comment -= 1;
			}
		} else if c == b'<' || c == b'(' {
			if in_name && name.is_none() {
				name = Some(uid_part(&src[start..i]));
			}
			in_name = false;
			if c == b'<' {
				in_email = 1;
			} else {
				in_comment = 1;
			}
			start = i + 1;
		} else if !in_name && c != b' ' && c != b'\t' {
			in_name = true;
			start = i;
		}
	}
	if in_name && name.is_none() {
		name = Some(uid_part(&src[start..]));
	}
	(name.unwrap_or_default(), email.unwrap_or_default())
}

// gnupg's is_valid_mailbox, as gpgme carries it
fn is_valid_mailbox(s: &[u8]) -> bool {
	const LOCAL: &[u8] = b"!#$%&'*+/=?^`{|}~";
	let valid = |c: u8| c.is_ascii_alphanumeric() || b"_-.".contains(&c);
	let mut at = false;
	for &c in s {
		if c & 0x80 != 0 {
			continue;
		}
		if c == b'@' {
			at = true;
		} else if !at && !(valid(c) || LOCAL.contains(&c))
			|| at && !valid(c)
		{
			return false;
		}
	}
	!s.is_empty()
		&& s.iter().filter(|&&c| c == b'@').count() == 1
		&& s[0] != b'@'
		&& !matches!(s.last(), Some(b'@' | b'.'))
		&& !s.windows(2).any(|w| w == b"..")
}

// _gpgme_mailbox_from_userid: the <...> part or the whole uid,
// lowercased, when it is a valid mailbox
fn mailbox_from_userid(uid: &[u8]) -> Option<Vec<u8>> {
	let mbox = match uid.iter().position(|&c| c == b'<') {
		Some(lt) => {
			let rest = &uid[lt + 1..];
			let gt = rest.iter().position(|&c| c == b'>')?;
			&rest[..gt]
		}
		None => uid,
	};
	(!mbox.is_empty() && is_valid_mailbox(mbox))
		.then(|| mbox.to_ascii_lowercase())
}

// _gpgme_key_append_name: a uid that is only a mailbox has no name and
// the lowercased mailbox as email
fn user_id(uid: Vec<u8>) -> Uid {
	let (mut name, mut email) = parse_user_id(&uid);
	if email.is_empty()
		&& let Some(addr) = mailbox_from_userid(&uid)
		&& name == addr
	{
		name.clear();
		email = addr;
	}
	Uid { uid, name, email }
}

// keylist_colon_handler for the records pacman reads: pub starts a key,
// the first fpr is the primary's, uids in order
fn parse_keylist(out: &[u8]) -> Vec<Key> {
	let mut keys: Vec<Key> = Vec::new();
	let mut in_sub = false;
	for line in out.split(|&c| c == b'\n') {
		let f = fields(line);
		let kind = field(&f, 0);
		if kind == b"pub" {
			keys.push(Key {
				keyid: field(&f, 4).to_vec(),
				created: number(field(&f, 5)),
				expires: number(field(&f, 6)),
				expired: field(&f, 1) == b"e",
				disabled: field(&f, 11).contains(&b'D'),
				..Key::default()
			});
			in_sub = false;
			continue;
		}
		let Some(key) = keys.last_mut() else {
			continue;
		};
		match kind {
			b"sub" => in_sub = true,
			b"fpr" if !in_sub && key.fpr.is_none() => {
				key.fpr = Some(field(&f, 9).to_vec());
			}
			b"uid" => {
				let uid = decode_c_string(field(&f, 9));
				key.uids.push(user_id(uid));
			}
			_ => {}
		}
	}
	keys
}

// gpg_keylist_preprocess on a keyserver listing:
// pub:<keyid or fpr>:<algo>:<len>:<created>:<expires>:<flags>, then
// uid:<%-escaped uid>:...
fn parse_extern_keylist(out: &[u8]) -> Vec<Key> {
	let mut keys: Vec<Key> = Vec::new();
	for line in out.split(|&c| c == b'\n') {
		let f = fields(line);
		let kind = field(&f, 0);
		if kind == b"pub" {
			let id = field(&f, 1);
			let flags = field(&f, 6);
			keys.push(Key {
				fpr: (id.len() == 40).then(|| id.to_vec()),
				keyid: id[id.len().saturating_sub(16)..]
					.to_vec(),
				created: number(field(&f, 4)),
				expires: number(field(&f, 5)),
				expired: flags.contains(&b'e'),
				disabled: flags.contains(&b'd'),
				..Key::default()
			});
		} else if let (b"uid", Some(key)) = (kind, keys.last_mut()) {
			key.uids.push(user_id(decode_percent(field(&f, 1))));
		}
	}
	keys
}

// the verify state of gpgme's verify_status_handler
#[derive(Default)]
struct Verify {
	sigs: Vec<GpgSig>,
	did_prepare_new_sig: bool,
	only_newsig_seen: bool,
	plaintext_seen: usize,
}

// gpg-error code of a status argument (low 16 bits)
fn err_code(n: i64) -> Code {
	match n & 0xffff {
		0 => Code::NoError,
		9 => Code::NoPubkey,
		153 => Code::KeyExpired,
		154 => Code::SigExpired,
		_ => Code::Other,
	}
}

fn digits(s: &[u8]) -> bool {
	!s.is_empty() && s.iter().all(u8::is_ascii_digit)
}

// the TRUST_* keywords, None for every other one
fn trust(kw: &[u8]) -> Option<SigValidity> {
	match kw {
		b"TRUST_UNDEFINED" => Some(SigValidity::Unknown),
		b"TRUST_NEVER" => Some(SigValidity::Never),
		b"TRUST_MARGINAL" => Some(SigValidity::Marginal),
		b"TRUST_FULLY" | b"TRUST_ULTIMATE" => Some(SigValidity::Full),
		_ => None,
	}
}

const NEW_SIG: &[&[u8]] = &[
	b"GOODSIG",
	b"EXPSIG",
	b"EXPKEYSIG",
	b"BADSIG",
	b"ERRSIG",
	b"REVKEYSIG",
];

impl Verify {
	fn prepare_new_sig(&mut self) {
		self.sigs.push(GpgSig {
			fpr: None,
			code: Code::NoError,
			validity: SigValidity::Unknown,
		});
		self.did_prepare_new_sig = true;
	}

	// parse_new_sig: GOODSIG and friends carry the long key id, ERRSIG
	// the fingerprint as 7th field when gpg knows it
	fn new_sig(&mut self, kw: &[u8], args: &[u8]) -> Result<(), GpgError> {
		if !self.did_prepare_new_sig {
			self.prepare_new_sig();
		}
		self.did_prepare_new_sig = false;
		let sig = self.sigs.last_mut().expect("just prepared");
		let mut parts = args.split(|&c| c == b' ');
		let keyid = parts.next().unwrap_or_default();
		if !keyid.is_empty() {
			sig.fpr = Some(keyid.to_vec());
		}
		sig.code = match kw {
			b"GOODSIG" => Code::NoError,
			b"EXPSIG" => Code::SigExpired,
			b"EXPKEYSIG" => Code::KeyExpired,
			_ => Code::Other,
		};
		if kw != b"ERRSIG" {
			return Ok(());
		}
		// <pkalgo> <hashalgo> <class> <time> <rc> [<fpr>]
		let rest: Vec<&[u8]> =
			parts.filter(|p| !p.is_empty()).collect();
		if rest.len() < 5 || !digits(rest[0]) || !digits(rest[1]) {
			return Ok(());
		}
		if !digits(rest[3]) {
			return Err(GpgError::InvEngine);
		}
		if rest[4] == b"9" {
			sig.code = Code::NoPubkey;
		}
		if let Some(fpr) = rest.get(5) {
			sig.fpr = Some(fpr.to_vec());
		}
		Ok(())
	}

	fn status(&mut self, kw: &[u8], args: &[u8]) -> Result<(), GpgError> {
		if kw == b"NEWSIG" {
			self.prepare_new_sig();
			self.only_newsig_seen = true;
			return Ok(());
		}
		if NEW_SIG.contains(&kw) {
			self.only_newsig_seen = false;
			return self.new_sig(kw, args);
		}
		let validity = trust(kw);
		let resets =
			[&b"VALIDSIG"[..], b"NODATA", b"UNEXPECTED", b"ERROR"];
		if validity.is_some() || resets.contains(&kw) {
			self.only_newsig_seen = false;
		}
		let sig = self.sigs.last_mut();
		match (kw, sig) {
			(b"VALIDSIG", Some(sig)) => {
				let fpr = args.split(|&c| c == b' ').next();
				let fpr = fpr.filter(|f| !f.is_empty());
				sig.fpr = Some(fpr
					.ok_or(GpgError::General)?
					.to_vec());
			}
			(b"NODATA", None) => return Err(GpgError::NoData),
			(b"UNEXPECTED", None) => return Err(GpgError::General),
			(b"NODATA" | b"UNEXPECTED", Some(sig)) => {
				sig.code = Code::Other;
			}
			(b"ERROR", sig) => return error_status(sig, args),
			(b"PLAINTEXT", _) => {
				self.plaintext_seen += 1;
				if self.plaintext_seen > 1 {
					return Err(GpgError::BadData);
				}
			}
			(b"VALIDSIG", None) => return Err(GpgError::InvEngine),
			(_, None) if validity.is_some() => {
				return Err(GpgError::InvEngine);
			}
			(_, Some(sig)) => {
				if let Some(v) = validity {
					sig.validity = v;
				}
			}
			_ => {}
		}
		Ok(())
	}

	// EOF: a last signature that only had NEWSIG is dropped
	fn finish(mut self) -> Vec<GpgSig> {
		if self.only_newsig_seen {
			self.sigs.pop();
		}
		self.sigs
	}
}

// parse_error of verify.c: ERROR <where> <code>
fn error_status(sig: Option<&mut GpgSig>, args: &[u8]) -> Result<(), GpgError> {
	let mut parts = args.split(|&c| c == b' ');
	let place = parts.next().unwrap_or_default();
	let which = parts.next().ok_or(GpgError::InvEngine)?;
	let code = number(which);
	if place == b"proc_pkt.plaintext" && code & 0xffff == 89 {
		return Err(GpgError::BadData);
	}
	if let Some(sig) = sig
		&& place == b"verify.findkey"
	{
		sig.code = err_code(code);
	}
	Ok(())
}

// verify_status_handler over the whole status output
fn parse_verify(status: &[u8]) -> Result<Vec<GpgSig>, GpgError> {
	let mut v = Verify::default();
	for line in status.split(|&c| c == b'\n') {
		let Some(rest) = line.strip_prefix(b"[GNUPG:] ") else {
			continue;
		};
		let (kw, args) = match rest.iter().position(|&c| c == b' ') {
			Some(i) => (&rest[..i], &rest[i + 1..]),
			None => (rest, &b""[..]),
		};
		v.status(kw, args)?;
	}
	Ok(v.finish())
}

// stdout of a run, stdin fed from a thread so neither pipe blocks
fn run(c: &mut Command, stdin: Option<&[u8]>) -> Result<Vec<u8>, GpgError> {
	let input = match stdin {
		Some(_) => Stdio::piped(),
		None => Stdio::null(),
	};
	let mut child = c
		.stdin(input)
		.stdout(Stdio::piped())
		.stderr(Stdio::null())
		.spawn()
		.map_err(|_| GpgError::InvEngine)?;
	let pipe = child.stdin.take();
	let mut out = Vec::new();
	let mut stdout = child.stdout.take().expect("piped");
	let read = std::thread::scope(|s| {
		if let (Some(mut pipe), Some(data)) = (pipe, stdin) {
			// gpg may stop reading early, its status says why
			s.spawn(move || pipe.write_all(data).ok());
		}
		stdout.read_to_end(&mut out)
	});
	// gpgme ignores gpg's exit status, the status lines tell
	let waited = child.wait();
	read.and(waited).map_err(|_| GpgError::InvEngine)?;
	Ok(out)
}

impl Keyring {
	// gpgdir is handle->gpgdir with its trailing '/', gpg is looked up
	// in PATH where gpgme asks gpgconf
	pub fn new(gpgdir: &[u8]) -> Keyring {
		Keyring {
			gpgdir: until_nul(gpgdir).to_vec(),
			gpg: PathBuf::from("gpg"),
			known_keys: Vec::new(),
			init: false,
		}
	}

	// gpgme_set_engine_info's file_name
	pub fn set_gpg(&mut self, gpg: impl Into<PathBuf>) {
		self.gpg = gpg.into();
	}

	pub fn gpgdir(&self) -> &[u8] {
		&self.gpgdir
	}

	// alpm_option_set_gpgdir on a handle in use: known keys stay
	pub fn set_gpgdir(&mut self, gpgdir: &[u8]) {
		self.gpgdir = until_nul(gpgdir).to_vec();
	}

	// keys _alpm_key_in_keychain found, in lookup order
	pub fn known_keys(&self) -> &[Vec<u8>] {
		&self.known_keys
	}

	fn file(&self, name: &[u8]) -> Vec<u8> {
		[&self.gpgdir[..], name].concat()
	}

	// build_argv's options for a gpg 2.x engine without a tty
	fn command(&self) -> Command {
		let mut c = Command::new(&self.gpg);
		c.arg("--batch");
		if !self.gpgdir.is_empty() {
			let mut home = OsString::from("--homedir=");
			home.push(os(&self.gpgdir));
			c.arg(home);
		}
		c.args([
			"--no-tty",
			"--charset=utf8",
			"--enable-progress-filter",
			"--exit-on-status-write-error",
		]);
		c
	}

	// gpgme_op_verify of a detached signature: --verify -- - <data>
	fn verify(
		&self,
		sig: &[u8],
		path: &[u8],
	) -> Result<Vec<GpgSig>, GpgError> {
		first_read(path)?;
		let mut c = self.command();
		c.args(["--status-fd", "1", "--verify", "--", "-"]);
		c.arg(os(path));
		parse_verify(&run(&mut c, Some(sig))?)
	}

	// gpgme_get_key: Ok(None) is GPG_ERR_EOF, two different keys are
	// ambiguous, a pattern under 8 characters is refused
	fn get_key(
		&self,
		pattern: Option<&[u8]>,
		mode: ListMode,
	) -> Result<Option<Key>, GpgError> {
		let pattern = pattern.ok_or(GpgError::InvValue)?;
		if pattern.len() < 8 {
			return Err(GpgError::InvValue);
		}
		let mut c = self.command();
		c.arg("--with-colons");
		c.arg(match mode {
			ListMode::Local => "--list-keys",
			ListMode::LocateExternal => "--locate-external-keys",
			ListMode::Extern => "--search-keys",
		});
		c.arg("--").arg(os(pattern));
		let out = run(&mut c, None)?;
		let keys = match mode {
			ListMode::Extern => parse_extern_keylist(&out),
			_ => parse_keylist(&out),
		};
		let mut keys = keys.into_iter();
		let Some(first) = keys.next() else {
			return Ok(None);
		};
		// the same fingerprint listed again is not ambiguous
		for other in keys {
			if other.fpr.is_none() || other.fpr != first.fpr {
				return Err(GpgError::AmbiguousName);
			}
		}
		Ok(Some(first))
	}

	// gpgme_op_import_keys on a keyserver key: --recv-keys with its
	// fingerprint or key id; the considered count and the first
	// import's result
	fn recv_key(&self, key: &Key) -> Result<(i64, Option<bool>), GpgError> {
		let id = key.fpr.as_deref().unwrap_or(&key.keyid);
		let mut c = self.command();
		c.args(["--status-fd", "1", "--recv-keys", "--"])
			.arg(os(id));
		let out = run(&mut c, None)?;
		let (mut considered, mut first) = (0, None);
		for line in out.split(|&c| c == b'\n') {
			let Some(rest) = line.strip_prefix(b"[GNUPG:] ") else {
				continue;
			};
			if let Some(n) = rest.strip_prefix(b"IMPORT_RES ") {
				considered = number(n);
			} else if rest.starts_with(b"IMPORT_OK ") {
				first.get_or_insert(true);
			} else if rest.starts_with(b"IMPORT_PROBLEM ") {
				first.get_or_insert(false);
			}
		}
		Ok((considered, first))
	}
}

// init_gpgme: the keyring warning, once. the C also leaves pm_errno
// NOT_A_FILE behind, which no caller reads on success
fn init_gpgme(kr: &mut Keyring, cb: &mut dyn Callbacks) {
	if kr.init {
		return;
	}
	let pubring = access(&kr.file(b"pubring.gpg"), Access::READ_OK);
	let trustdb = access(&kr.file(b"trustdb.gpg"), Access::READ_OK);
	if !pubring || !trustdb {
		cb.log(
			LogLevel::Warning,
			b"Public keyring not found; have you run \
			'pacman-key --init'?\n",
		);
	}
	kr.init = true;
}

fn gpgme_error(cb: &mut dyn Callbacks, e: GpgError) -> Errno {
	let msg = [b"GPGME error: ", e.text(), b"\n"].concat();
	cb.log(LogLevel::Error, &msg);
	Errno::Gpgme
}

// _alpm_key_in_keychain: Some(true) known (cached from then on),
// Some(false) unknown or expired, None when the lookup failed (C -1)
pub fn key_in_keychain(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	fpr: &[u8],
) -> Option<bool> {
	let fpr = until_nul(fpr);
	if kr.known_keys.iter().any(|k| k == fpr) {
		return Some(true);
	}
	init_gpgme(kr, cb);
	match kr.get_key(Some(fpr), ListMode::Local) {
		Ok(None) => Some(false),
		Ok(Some(key)) if key.expired => Some(false),
		Ok(Some(_)) => {
			kr.known_keys.push(fpr.to_vec());
			Some(true)
		}
		Err(_) => None,
	}
}

// key_import_wkd: the key at the uid's address, then fpr must be in the
// keychain (a failed lookup counts as there, the C tests nonzero)
fn key_import_wkd(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	email: &[u8],
	fpr: &[u8],
) -> bool {
	match kr.get_key(Some(email), ListMode::LocateExternal) {
		Ok(Some(_)) => key_in_keychain(kr, cb, fpr) != Some(false),
		_ => false,
	}
}

// key_search_keyserver: Ok(Some) found (C 1), Ok(None) not found (C 0),
// Err on a failed lookup (C -1). "0x" in front, keyservers want it; on
// a miss the last 8 characters are tried
fn key_search_keyserver(
	kr: &Keyring,
	fpr: &[u8],
) -> Result<Option<Key>, GpgError> {
	let full = [b"0x", fpr].concat();
	match kr.get_key(Some(&full), ListMode::Extern)? {
		Some(key) => return Ok(Some(key)),
		None if fpr.len() <= 8 => return Ok(None),
		None => {}
	}
	let short = [b"0x", &fpr[fpr.len() - 8..]].concat();
	kr.get_key(Some(&short), ListMode::Extern)
}

// _alpm_access(gpgdir, "pubring.gpg", W_OK), logged when refused
fn writable(kr: &Keyring, cb: &mut dyn Callbacks) -> bool {
	if access(&kr.file(b"pubring.gpg"), Access::WRITE_OK) {
		return true;
	}
	cb.log(LogLevel::Error, b"keyring is not writable\n");
	false
}

// key_import_keyserver: exactly one key considered and imported
fn key_import_keyserver(
	kr: &Keyring,
	cb: &mut dyn Callbacks,
	key: &Key,
) -> bool {
	writable(kr, cb) && matches!(kr.recv_key(key), Ok((1, Some(true))))
}

// email_from_uid: between the last '<' and the last '>' after it
fn email_from_uid(uid: Option<&[u8]>) -> Option<&[u8]> {
	let uid = uid?;
	let start = uid.iter().rposition(|&c| c == b'<')?;
	let end = uid[start..].iter().rposition(|&c| c == b'>')?;
	Some(&uid[start + 1..start + end])
}

// ALPM_QUESTION_IMPORT_KEY, true imports. no answer is no
fn ask_import(
	cb: &mut dyn Callbacks,
	uid: Option<&[u8]>,
	fingerprint: &[u8],
) -> bool {
	let mut q = Question::ImportKey {
		import: 0,
		uid,
		fingerprint,
	};
	cb.question(&mut q);
	q.answer() != 0
}

// _alpm_key_import: asked first, then WKD by the uid's address, then the
// keyservers. true is the C's 0
pub fn key_import(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	uid: Option<&[u8]>,
	fpr: &[u8],
) -> bool {
	let uid = uid.map(until_nul);
	let fpr = until_nul(fpr);
	if !writable(kr, cb) || !ask_import(cb, uid, fpr) {
		return false;
	}
	if let Some(email) = email_from_uid(uid)
		&& key_import_wkd(kr, cb, email, fpr)
	{
		return true;
	}
	let msg: &[u8] = match key_search_keyserver(kr, fpr) {
		Ok(Some(key)) if key_import_keyserver(kr, cb, &key) => {
			return true;
		}
		Ok(Some(_)) => b"\" could not be imported\n",
		_ => b"\" could not be looked up remotely\n",
	};
	cb.log(LogLevel::Error, &[b"key \"", fpr, msg].concat());
	false
}

// _alpm_sigpath
pub fn sigpath(path: &[u8]) -> Vec<u8> {
	[until_nul(path), b".sig"].concat()
}

// the key fields of a result and whether the key is disabled; a key
// without uids leaves them unset like the C
fn result_key(key: &Key) -> (PgpKey, bool) {
	let Some(uid) = key.uids.first() else {
		return (PgpKey::default(), false);
	};
	let pk = PgpKey {
		fingerprint: key.fpr.clone(),
		uid: Some(uid.uid.clone()),
		name: Some(uid.name.clone()),
		email: Some(uid.email.clone()),
		created: key.created,
		expires: key.expires,
		..PgpKey::default()
	};
	(pk, key.disabled)
}

// _alpm_gpgme_checksig: the signatures of the file at path, from
// base64_sig or "<path>.sig". Ok holds a result per signature, whatever
// they say; Err is the pm_errno (NotAFile, SigMissing, SigInvalid,
// Gpgme)
pub fn gpgme_checksig(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	path: Option<&[u8]>,
	base64_sig: Option<&[u8]>,
) -> Result<Vec<SigResult>, Errno> {
	let path = path.map(until_nul).ok_or(Errno::NotAFile)?;
	if !access(path, Access::READ_OK) {
		return Err(Errno::NotAFile);
	}
	let sigfile = sigpath(path);
	if base64_sig.is_none()
		&& (!access(&sigfile, Access::READ_OK)
			|| File::open(os(&sigfile)).is_err())
	{
		return Err(Errno::SigMissing);
	}
	if File::open(os(path)).is_err() {
		return Err(Errno::NotAFile);
	}
	init_gpgme(kr, cb);
	let sig = match base64_sig {
		Some(b) => {
			decode_signature(b).map_err(|_| Errno::SigInvalid)?
		}
		// gpgme_data_new_from_stream on the opened .sig
		None => std::fs::read(os(&sigfile))
			.map_err(|e| gpgme_error(cb, read_error(e)))?,
	};
	let sigs = kr.verify(&sig, path).map_err(|e| gpgme_error(cb, e))?;
	if sigs.is_empty() {
		return Err(Errno::SigMissing);
	}
	let mut results = Vec::with_capacity(sigs.len());
	for sig in sigs {
		let found = kr.get_key(sig.fpr.as_deref(), ListMode::Local);
		let (key, disabled) = match found {
			Ok(Some(k)) => result_key(&k),
			// the signature's fpr, there is no key to point at
			Ok(None) => {
				let fingerprint = sig.fpr.clone();
				(
					PgpKey {
						fingerprint,
						..PgpKey::default()
					},
					false,
				)
			}
			Err(e) => return Err(gpgme_error(cb, e)),
		};
		let status = match sig.code {
			// key disabled is not in the status code
			_ if disabled => SigStatus::KeyDisabled,
			Code::NoError => SigStatus::Valid,
			Code::KeyExpired => SigStatus::KeyExpired,
			Code::SigExpired => SigStatus::SigExpired,
			Code::NoPubkey => SigStatus::KeyUnknown,
			Code::Other => SigStatus::Invalid,
		};
		results.push(SigResult {
			key,
			status,
			validity: sig.validity,
		});
	}
	Ok(results)
}

// _alpm_check_pgp_helper: the check, then the trust policy. Err(Some)
// when the check failed with that pm_errno, Err(None) when a signature
// is not acceptable. a missing signature is fine when optional. the
// results come back either way (sigdata)
pub fn check_pgp_helper(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	path: Option<&[u8]>,
	base64_sig: Option<&[u8]>,
	optional: bool,
	marginal: bool,
	unknown: bool,
) -> (Result<(), Option<Errno>>, Vec<SigResult>) {
	let siglist = match gpgme_checksig(kr, cb, path, base64_sig) {
		Ok(list) => list,
		Err(Errno::SigMissing) if optional => {
			return (Ok(()), Vec::new());
		}
		Err(e) => return (Err(Some(e)), Vec::new()),
	};
	let trusted = |r: &SigResult| match (r.status, r.validity) {
		(SigStatus::Valid | SigStatus::KeyExpired, v) => match v {
			SigValidity::Full => true,
			SigValidity::Marginal => marginal,
			SigValidity::Unknown => unknown,
			SigValidity::Never => false,
		},
		_ => false,
	};
	let ok = siglist.iter().all(trusted);
	(if ok { Ok(()) } else { Err(None) }, siglist)
}

// _alpm_process_siglist: what the user can act on, and the import
// question for unknown and expired keys. true when an import worked and
// the validation should be retried
pub fn process_siglist(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	identifier: &[u8],
	siglist: &[SigResult],
	optional: bool,
	marginal: bool,
	unknown: bool,
) -> bool {
	let id = until_nul(identifier);
	let mut retry = false;
	if !optional && siglist.is_empty() {
		let msg = [id, b": missing required signature\n"].concat();
		cb.log(LogLevel::Error, &msg);
	}
	for result in siglist {
		let key = &result.key;
		let fpr = key.fingerprint.as_deref();
		let name = key.uid.as_deref().or(fpr).unwrap_or(b"(null)");
		let from = |what: &[u8]| {
			let q = b"\" ";
			[id, b": signature from \"", name, q, what, b"\n"]
				.concat()
		};
		let key_is = |what: &[u8]| {
			[id, b": key \"", name, b"\" ", what, b"\n"].concat()
		};
		let msg = match (result.status, result.validity) {
			(SigStatus::Valid, SigValidity::Full) => None,
			(SigStatus::Valid, SigValidity::Marginal) => {
				(!marginal).then(|| from(b"is marginal trust"))
			}
			(SigStatus::Valid, SigValidity::Unknown) => {
				(!unknown).then(|| from(b"is unknown trust"))
			}
			(SigStatus::Valid, SigValidity::Never) => {
				Some(from(b"should never be trusted"))
			}
			(SigStatus::KeyExpired | SigStatus::SigExpired, _) => {
				Some(from(b"is expired"))
			}
			// still unknown? it may have come in on an earlier call
			(SigStatus::KeyUnknown, _) => {
				let fpr = fpr.unwrap_or_default();
				if key_in_keychain(kr, cb, fpr) == Some(true) {
					continue;
				}
				Some(key_is(b"is unknown"))
			}
			(SigStatus::KeyDisabled, _) => {
				Some(key_is(b"is disabled"))
			}
			(SigStatus::Invalid, _) => Some(from(b"is invalid")),
		};
		if let Some(msg) = msg {
			cb.log(LogLevel::Error, &msg);
		}
		let importable = matches!(
			result.status,
			SigStatus::KeyExpired | SigStatus::KeyUnknown
		);
		if importable
			&& key_import(
				kr,
				cb,
				key.uid.as_deref(),
				fpr.unwrap_or_default(),
			) {
			retry = true;
		}
	}
	retry
}

// alpm_pkg_check_pgp_signature: pkg->filename and pkg->base64_sig
pub fn pkg_check_pgp_signature(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	pkg: &Package,
) -> Result<Vec<SigResult>, Errno> {
	let path = pkg.filename.as_deref();
	gpgme_checksig(kr, cb, path, pkg.base64_sig.as_deref())
}

// alpm_db_check_pgp_signature: "<db path>.sig"
pub fn db_check_pgp_signature(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	db: &Db,
) -> Result<Vec<SigResult>, Errno> {
	gpgme_checksig(kr, cb, Some(db.path()), None)
}

// why alpm_extract_keyid gave up, the two messages it logs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyidError {
	// "signature format error"
	Format,
	// "unsupported signature format": partial lengths, not version 4
	Unsupported,
}

// the packet walk of alpm_extract_keyid over sig. reads are bounds
// checked the way length_check does it (a + 1 bytes left at pos); the
// one read the C makes before checking (the unhashed length right after
// the hashed area) is checked first here, with the same outcome
struct Packets<'a> {
	sig: &'a [u8],
}

impl Packets<'_> {
	// length_check: a == 0 or fewer than a + 1 bytes at pos fail
	fn check(&self, pos: usize, a: usize) -> Result<(), KeyidError> {
		let len = self.sig.len();
		if a == 0 || pos > len || len - pos <= a {
			return Err(KeyidError::Format);
		}
		Ok(())
	}

	fn at(&self, i: usize) -> usize {
		usize::from(self.sig[i])
	}

	// four bytes big endian. the C shifts int, a top byte >= 0x80 is
	// signed overflow there; this is the unsigned value
	fn be32(&self, i: usize) -> usize {
		let b = &self.sig[i..i + 4];
		u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
	}

	fn be16(&self, i: usize) -> usize {
		self.at(i) << 8 | self.at(i + 1)
	}

	// two byte length form, 192..8383
	fn len2(&self, i: usize) -> usize {
		((self.at(i) - 192) << 8) + self.at(i + 1) + 192
	}

	// parse_subpacket: the issuer key id (type 16) as upper hex, the
	// first one ends the area
	fn subpackets(
		&self,
		pos: usize,
		plen: usize,
		keys: &mut Vec<Vec<u8>>,
	) -> Result<(), KeyidError> {
		let mut spos = pos;
		while spos < pos + plen {
			let slen;
			if self.sig[spos] < 192 {
				slen = self.at(spos);
				spos += 1;
			} else if self.sig[spos] < 255 {
				self.check(spos, 2)?;
				slen = self.len2(spos);
				spos += 2;
			} else {
				self.check(spos, 5)?;
				slen = self.be32(spos + 1);
				spos += 5;
			}
			if self.sig[spos] == 16 {
				self.check(spos, 8)?;
				let id = &self.sig[spos + 1..spos + 9];
				let hex: String = id
					.iter()
					.map(|b| format!("{b:02X}"))
					.collect();
				keys.push(hex.into_bytes());
				break;
			}
			self.check(spos, slen)?;
			spos += slen;
		}
		Ok(())
	}

	// one packet header at pos: body length and where the body starts
	fn header(&self, pos: usize) -> Result<(usize, usize), KeyidError> {
		let tag = self.sig[pos];
		if tag & 0x80 == 0 {
			return Err(KeyidError::Format);
		}
		if tag & 0x40 != 0 {
			// new packet format
			self.check(pos, 1)?;
			let pos = pos + 1;
			return match self.sig[pos] {
				0..192 => {
					self.check(pos, 1)?;
					Ok((self.at(pos), pos + 1))
				}
				192..224 => {
					self.check(pos, 2)?;
					Ok((self.len2(pos), pos + 2))
				}
				255 => {
					self.check(pos, 5)?;
					Ok((self.be32(pos + 1), pos + 5))
				}
				// partial body length
				_ => Err(KeyidError::Unsupported),
			};
		}
		// old packet format
		match tag & 0x03 {
			0 => {
				self.check(pos, 2)?;
				Ok((self.at(pos + 1), pos + 2))
			}
			1 => {
				self.check(pos, 3)?;
				Ok((self.be16(pos + 1), pos + 3))
			}
			2 => {
				self.check(pos, 5)?;
				Ok((self.be32(pos + 1), pos + 5))
			}
			// partial body length
			_ => Err(KeyidError::Unsupported),
		}
	}

	// a version 4 signature of a binary document: hashed then unhashed
	// subpackets. the next packet starts blen - hlen - 8 after the
	// unhashed area, wrapping like the C's size_t
	fn packet(
		&self,
		pos: usize,
		keys: &mut Vec<Vec<u8>>,
	) -> Result<usize, KeyidError> {
		let (blen, mut pos) = self.header(pos)?;
		self.check(pos, 2)?;
		if self.sig[pos] != 4 {
			return Err(KeyidError::Unsupported);
		}
		if self.sig[pos + 1] != 0x00 {
			return Err(KeyidError::Format);
		}
		pos += 4;
		self.check(pos, 2)?;
		let hlen = self.be16(pos);
		self.check(pos, hlen + 2)?;
		pos += 2;
		self.subpackets(pos, hlen, keys)?;
		pos += hlen;
		self.check(pos, 1)?;
		let ulen = self.be16(pos);
		self.check(pos, ulen + 2)?;
		pos += 2;
		self.subpackets(pos, ulen, keys)?;
		let skip = blen.wrapping_sub(hlen).wrapping_sub(8);
		Ok(pos.wrapping_add(skip))
	}
}

// alpm_extract_keyid: issuer key ids of the signature packets in sig,
// appended to keys (those found before an error stay, like the C list)
pub fn extract_keyid(
	cb: &mut dyn Callbacks,
	identifier: &[u8],
	sig: &[u8],
	keys: &mut Vec<Vec<u8>>,
) -> Result<(), KeyidError> {
	let walk = Packets { sig };
	let mut pos = 0;
	while pos < sig.len() {
		pos = walk.packet(pos, keys).inspect_err(|e| {
			let what: &[u8] = match e {
				KeyidError::Format => b"signature format error",
				KeyidError::Unsupported => {
					b"unsupported signature format"
				}
			};
			let id = until_nul(identifier);
			let msg = [id, b": ", what, b"\n"].concat();
			cb.log(LogLevel::Error, &msg);
		})?;
	}
	Ok(())
}
