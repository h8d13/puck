// port of lib/libalpm/signing.c. gpgme is replaced by gpg(1) driven the
// way gpgme's engine-gpg drives it: the same binary,
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
// the log lines go through Callbacks. pm_errno is Err as in the other
// modules. RET_ERR/GOTO_ERR's lines (C file and line) are not logged.
// alpm_siglist_cleanup is dropping the Vec.

use std::ffi::{OsStr, OsString, c_int, c_uint};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use rustix::fs::Access;

mod err_codes;

use crate::base64;
use crate::callbacks::{Callbacks, LogLevel, Question, logv};
use crate::db::Db;
use crate::error::Errno;
use crate::package::Package;
use crate::util::{alpm_access, strerror, until_nul};
use err_codes::ERR_CODES;

pub use crate::db::{SIG_DATABASE, SIG_USE_DEFAULT};

/// alpm_siglevel_t ALPM_SIG_PACKAGE: package signatures are checked
pub const SIG_PACKAGE: c_int = 1;
/// ALPM_SIG_PACKAGE_OPTIONAL: a missing package signature passes
pub const SIG_PACKAGE_OPTIONAL: c_int = 1 << 1;
/// ALPM_SIG_PACKAGE_MARGINAL_OK: marginal trust passes
pub const SIG_PACKAGE_MARGINAL_OK: c_int = 1 << 2;
/// ALPM_SIG_PACKAGE_UNKNOWN_OK: unknown trust passes
pub const SIG_PACKAGE_UNKNOWN_OK: c_int = 1 << 3;
/// ALPM_SIG_DATABASE_OPTIONAL: a missing db signature passes
pub const SIG_DATABASE_OPTIONAL: c_int = 1 << 11;
/// ALPM_SIG_DATABASE_MARGINAL_OK
pub const SIG_DATABASE_MARGINAL_OK: c_int = 1 << 12;
/// ALPM_SIG_DATABASE_UNKNOWN_OK
pub const SIG_DATABASE_UNKNOWN_OK: c_int = 1 << 13;

/// why alpm_decode_signature refused the base64 text
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
	InvalidCharacter,
	/// output is capped at 3/4 of the input length, so unpadded input whose
	/// symbol count is not a multiple of 4 fails unless line breaks pad it
	BufferTooSmall,
}

/// alpm_decode_signature
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

/// alpm_sigstatus_t
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

/// alpm_sigvalidity_t
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SigValidity {
	Full,
	Marginal,
	Never,
	Unknown,
}

/// alpm_pgpkey_t without the gpgme key behind it. a signature check fills
/// fingerprint to expires, length and revoked only come from a keyserver
/// search
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

/// alpm_sigresult_t
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigResult {
	pub key: PgpKey,
	pub status: SigStatus,
	pub validity: SigValidity,
}

/// handle->gpgdir, handle->known_keys and the gpg binary gpgme would run
#[derive(Debug, Clone)]
pub struct Keyring {
	/// empty is the C's NULL gpgdir: no --homedir, files looked up in cwd
	gpgdir: Vec<u8>,
	gpg: PathBuf,
	known_keys: Vec<Vec<u8>>,
	/// init_gpgme ran, its keyring warning comes once. the C flag is
	/// process wide, this one per keyring
	init: bool,
	/// what the last key lookup's gpg said on stderr, or why it did not
	/// run: logged when the lookup fails (gpgme drops gpg's stderr)
	stderr: Vec<u8>,
}

// gpg_err_code values pacman's paths tell apart
const ERR_GENERAL: u32 = 1;
const ERR_BAD_SIGNATURE: u32 = 8;
const ERR_NO_PUBKEY: u32 = 9;
const ERR_NO_DATA: u32 = 58;
const ERR_BAD_DATA: u32 = 89;
const ERR_CERT_REVOKED: u32 = 94;
const ERR_CRL_TOO_OLD: u32 = 96;
const ERR_WRONG_KEY_USAGE: u32 = 125;
const ERR_KEY_EXPIRED: u32 = 153;
const ERR_SIG_EXPIRED: u32 = 154;

/// gpg_strerror in the C locale: libgpg-error's text for the code
/// (err_codes.rs, sorted), its "Unknown error code" for an unassigned
/// one. codes with GPG_ERR_SYSTEM_ERROR (errno texts) are not mapped
pub fn gpg_strerror(code: u32) -> &'static [u8] {
	let code = code & 0xffff;
	let found = ERR_CODES.binary_search_by_key(&code, |&(c, _)| c);
	let text = found.map_or("Unknown error code", |i| ERR_CODES[i].1);
	text.as_bytes()
}

// the gpgme_error_t texts pacman logs as "GPGME error: %s" and
// "gpg error: %s"
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
	// a key lookup found nothing
	Eof,
}

impl GpgError {
	// gpgme_strerror in the C locale
	fn text(&self) -> &[u8] {
		let code = match self {
			GpgError::Read(text) => return text,
			GpgError::NoData => ERR_NO_DATA,
			GpgError::General => ERR_GENERAL,
			GpgError::BadData => ERR_BAD_DATA,
			GpgError::AmbiguousName => 107,
			GpgError::InvValue => 55,
			GpgError::InvEngine => 150,
			GpgError::Eof => 16383,
		};
		gpg_strerror(code)
	}
}

// gpgme_sigsum_t bits and list_sigsum's words for them, in its order
const SUM_VALID: u32 = 0x1;
const SUM_GREEN: u32 = 0x2;
const SUM_RED: u32 = 0x4;
const SUM_KEY_REVOKED: u32 = 0x10;
const SUM_KEY_EXPIRED: u32 = 0x20;
const SUM_SIG_EXPIRED: u32 = 0x40;
const SUM_KEY_MISSING: u32 = 0x80;
const SUM_CRL_TOO_OLD: u32 = 0x200;
const SUM_BAD_POLICY: u32 = 0x400;
const SUM_SYS_ERROR: u32 = 0x800;
const SIGSUM: [(u32, &[u8]); 11] = [
	(SUM_VALID, b"valid"),
	(SUM_GREEN, b"green"),
	(SUM_RED, b"red"),
	(SUM_KEY_REVOKED, b"key revoked"),
	(SUM_KEY_EXPIRED, b"key expired"),
	(SUM_SIG_EXPIRED, b"sig expired"),
	(SUM_KEY_MISSING, b"key missing"),
	(0x100, b"crl missing"),
	(SUM_CRL_TOO_OLD, b"crl too old"),
	(SUM_BAD_POLICY, b"bad policy"),
	(SUM_SYS_ERROR, b"sys error"),
];

// gpgme_signature_t, the fields pacman reads or logs. status and
// validity_reason are gpg error values (their low 16 bits the code);
// validity is gpgme's after parse_trust (UNDEFINED already UNKNOWN,
// ULTIMATE already FULL)
#[derive(Debug, Clone)]
struct GpgSig {
	fpr: Option<Vec<u8>>,
	status: u32,
	validity: SigValidity,
	validity_reason: u32,
	timestamp: u64,
	exp_timestamp: u64,
	wrong_key_usage: bool,
	summary: u32,
}

impl GpgSig {
	// calc_sig_summary
	fn calc_summary(&mut self) {
		let code = self.status & 0xffff;
		let good =
			matches!(code, 0 | ERR_SIG_EXPIRED | ERR_KEY_EXPIRED);
		let mut sum = match self.validity {
			SigValidity::Full if good => SUM_GREEN,
			SigValidity::Never if good => SUM_RED,
			SigValidity::Full | SigValidity::Never => 0,
			_ if code == ERR_BAD_SIGNATURE => SUM_RED,
			_ => 0,
		};
		sum |= match code {
			ERR_SIG_EXPIRED => SUM_SIG_EXPIRED,
			ERR_KEY_EXPIRED => SUM_KEY_EXPIRED,
			ERR_NO_PUBKEY => SUM_KEY_MISSING,
			ERR_CERT_REVOKED => SUM_KEY_REVOKED,
			0 | ERR_BAD_SIGNATURE => 0,
			_ => SUM_SYS_ERROR,
		};
		sum |= match self.validity_reason & 0xffff {
			ERR_CRL_TOO_OLD
				if self.validity == SigValidity::Unknown =>
			{
				SUM_CRL_TOO_OLD
			}
			ERR_CERT_REVOKED => SUM_KEY_REVOKED,
			_ => 0,
		};
		if self.wrong_key_usage {
			sum |= SUM_BAD_POLICY;
		}
		if sum == SUM_GREEN {
			sum |= SUM_VALID;
		}
		self.summary = sum;
	}
}

// string_validity, gpgme_validity_t of a signature
fn string_validity(v: SigValidity) -> &'static [u8] {
	match v {
		SigValidity::Unknown => b"unknown",
		SigValidity::Never => b"never",
		SigValidity::Marginal => b"marginal",
		SigValidity::Full => b"full",
	}
}

// string_validity of the owner_trust gpgme's set_ownertrust makes of the
// colon listing's field: letters up to the first digit, the last wins
fn owner_trust(field: &[u8]) -> &'static [u8] {
	let letters = field.iter().take_while(|c| !c.is_ascii_digit());
	letters.fold(b"unknown", |_, c| -> &'static [u8] {
		match c {
			b'n' => b"never",
			b'm' => b"marginal",
			b'f' => b"full",
			b'u' => b"ultimate",
			_ => b"unknown",
		}
	})
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
	// the colon listing's ownertrust field
	ownertrust: Vec<u8>,
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

// gpg_error_from_errno's text for a failed read
fn read_error(e: std::io::Error) -> GpgError {
	GpgError::Read(strerror(&e))
}

// the first read gpgme's data callback makes on the file
fn first_read(path: &[u8]) -> Result<(), GpgError> {
	let mut file = File::open(os(path)).map_err(read_error)?;
	file.read(&mut [0; 1]).map(drop).map_err(read_error)
}

fn os(b: &[u8]) -> &OsStr {
	OsStr::from_bytes(b)
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
				ownertrust: field(&f, 8).to_vec(),
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

fn digits(s: &[u8]) -> usize {
	s.iter().take_while(|c| c.is_ascii_digit()).count()
}

fn skip_spaces(s: &[u8]) -> &[u8] {
	let n = s.iter().take_while(|&&c| c == b' ').count();
	&s[n..]
}

// the text up to the first ' ' and what follows it, if there is one
fn split_word(s: &[u8]) -> (&[u8], Option<&[u8]>) {
	match s.iter().position(|&c| c == b' ') {
		Some(i) => (&s[..i], Some(&s[i + 1..])),
		None => (s, None),
	}
}

// a field "ends" where the C checks *tail == ' ' or *tail == '\0'
fn ends(tail: &[u8]) -> bool {
	matches!(tail.first(), None | Some(b' '))
}

// atoi: blanks, a sign, decimal digits, 0 when there are none. the
// int wraps into gpgme_error_t like the C's assignment
fn atoi(s: &[u8]) -> u32 {
	let n = s.iter().take_while(|c| c.is_ascii_whitespace()).count();
	let s = &s[n..];
	let (neg, s) = match s.first() {
		Some(b'-') => (true, &s[1..]),
		Some(b'+') => (false, &s[1..]),
		_ => (false, s),
	};
	let v = s[..digits(s)].iter().fold(0i32, |v, &c| {
		v.wrapping_mul(10).wrapping_add(i32::from(c - b'0'))
	});
	(if neg { v.wrapping_neg() } else { v }) as u32
}

// strtoul(s, &tail, 10) without its sign and blank handling (gpg
// prints none here): the value and the tail, None without digits or on
// overflow (errno)
fn strtoul(s: &[u8]) -> Option<(u64, &[u8])> {
	let n = digits(s);
	let v = s[..n].iter().try_fold(0u64, |v, &c| {
		v.checked_mul(10)?.checked_add(u64::from(c - b'0'))
	});
	(n > 0).then_some(())?;
	Some((v?, &s[n..]))
}

// strtol(s, &tail, 0) on an algorithm number: decimal, 0x hex or 0
// octal, only whether it parses matters
fn strtol0(s: &[u8]) -> Option<&[u8]> {
	let n = s.iter().take_while(|c| c.is_ascii_whitespace()).count();
	let s = &s[n..];
	let s = s.strip_prefix(b"-").or(s.strip_prefix(b"+")).unwrap_or(s);
	let hex = s.len() > 2
		&& (s.starts_with(b"0x") || s.starts_with(b"0X"))
		&& s[2].is_ascii_hexdigit();
	let (body, radix) = match hex {
		true => (&s[2..], 16),
		false if s.first() == Some(&b'0') => (s, 8),
		false => (s, 10),
	};
	let n = body
		.iter()
		.take_while(|&&c| (c as char).is_digit(radix))
		.count();
	let v = i64::from_str_radix(
		std::str::from_utf8(&body[..n]).ok()?,
		radix,
	);
	(n > 0 && v.is_ok()).then(|| &body[n..])
}

// _gpgme_parse_timestamp on a status field: leading blanks, then
// seconds since the epoch. its "yyyymmddThhmmss" form, which gpg prints
// in no status line read here, is not converted. None is the C's
// (time_t)-1 or a field without digits (end == tail)
fn parse_timestamp(s: &[u8]) -> Option<(u64, &[u8])> {
	let (v, tail) = strtoul(skip_spaces(s))?;
	(v != u64::MAX).then_some((v, tail))
}

impl Verify {
	// prepare_new_sig: a signature that only had NEWSIG is reused
	fn prepare_new_sig(&mut self) {
		let sig = GpgSig {
			fpr: None,
			status: 0,
			validity: SigValidity::Unknown,
			validity_reason: 0,
			timestamp: 0,
			exp_timestamp: 0,
			wrong_key_usage: false,
			summary: 0,
		};
		match (self.only_newsig_seen, self.sigs.last_mut()) {
			(true, Some(last)) => *last = sig,
			_ => self.sigs.push(sig),
		}
		self.did_prepare_new_sig = true;
		self.only_newsig_seen = false;
	}

	// parse_new_sig: GOODSIG and friends carry the long key id, ERRSIG
	// the fingerprint as 7th field when gpg knows it
	fn new_sig(&mut self, kw: &[u8], args: &[u8]) -> Result<(), GpgError> {
		let (keyid, end) = split_word(args);
		if !self.did_prepare_new_sig {
			self.prepare_new_sig();
		}
		self.did_prepare_new_sig = false;
		let sig = self.sigs.last_mut().expect("just prepared");
		let got_fpr = match kw {
			b"ERRSIG" => errsig(sig, end)?,
			_ => {
				sig.status = match kw {
					b"GOODSIG" => 0,
					b"EXPSIG" => ERR_SIG_EXPIRED,
					b"EXPKEYSIG" => ERR_KEY_EXPIRED,
					b"BADSIG" => ERR_BAD_SIGNATURE,
					_ => ERR_CERT_REVOKED,
				};
				false
			}
		};
		if !keyid.is_empty() && !got_fpr {
			sig.fpr = Some(keyid.to_vec());
		}
		Ok(())
	}

	fn status(&mut self, kw: &[u8], args: &[u8]) -> Result<(), GpgError> {
		let unprepared = !self.did_prepare_new_sig;
		let sig = self.sigs.last_mut();
		if kw == b"NEWSIG" {
			if let Some(sig) = sig {
				sig.calc_summary();
			}
			self.prepare_new_sig();
			self.only_newsig_seen = true;
			return Ok(());
		}
		if NEW_SIG.contains(&kw) {
			if let Some(sig) = sig.filter(|_| unprepared) {
				sig.calc_summary();
			}
			self.only_newsig_seen = false;
			return self.new_sig(kw, args);
		}
		let validity = trust(kw);
		// a TRUST_ line before any signature is ignored
		if validity.is_some() && sig.is_none() {
			return Ok(());
		}
		let resets =
			[&b"VALIDSIG"[..], b"NODATA", b"UNEXPECTED", b"ERROR"];
		if validity.is_some() || resets.contains(&kw) {
			self.only_newsig_seen = false;
		}
		match (kw, sig) {
			(b"VALIDSIG", Some(sig)) => valid_sig(sig, args)?,
			(b"VALIDSIG", None) => return Err(GpgError::InvEngine),
			(b"NODATA", None) => return Err(GpgError::NoData),
			(b"UNEXPECTED", None) => return Err(GpgError::BadData),
			(b"NODATA" | b"UNEXPECTED", Some(sig)) => {
				sig.status = ERR_NO_DATA;
			}
			(b"ERROR", sig) => return error_status(sig, args),
			(b"PLAINTEXT", _) => {
				self.plaintext_seen += 1;
				if self.plaintext_seen > 1 {
					return Err(GpgError::BadData);
				}
			}
			(_, Some(sig)) => {
				if let Some(v) = validity {
					parse_trust(sig, v, args);
				}
			}
			_ => {}
		}
		Ok(())
	}

	// EOF: the last summary, a last signature that only had NEWSIG
	// dropped; then gpgme_op_verify_result's fix for a summary still
	// empty
	fn finish(mut self) -> Vec<GpgSig> {
		if let Some(sig) = self.sigs.last_mut()
			&& !self.did_prepare_new_sig
		{
			sig.calc_summary();
		}
		if self.only_newsig_seen {
			self.sigs.pop();
		}
		for sig in self.sigs.iter_mut().filter(|s| s.summary == 0) {
			sig.summary = match sig.status & 0xffff {
				ERR_KEY_EXPIRED => SUM_KEY_EXPIRED,
				ERR_NO_PUBKEY => SUM_KEY_MISSING,
				_ => 0,
			};
		}
		self.sigs
	}
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

// parse_trust: the validity and the error code in front of the model
fn parse_trust(sig: &mut GpgSig, validity: SigValidity, args: &[u8]) {
	sig.validity = validity;
	sig.validity_reason = atoi(split_word(args).0);
}

// <pkalgo> <hashalgo> <class> of an ERRSIG line: what follows them
fn errsig_algos(s: &[u8]) -> Option<&[u8]> {
	let tail = strtol0(s).filter(|t| t.first() == Some(&b' '))?;
	let s = skip_spaces(tail);
	let tail = strtol0(s).filter(|t| t.first() == Some(&b' '))?;
	// the sig class is skipped
	let s = skip_spaces(tail);
	let i = s.iter().position(|&c| c == b' ')?;
	Some(skip_spaces(&s[i..]))
}

// parse_new_sig's ERRSIG arm on what follows the key id:
// <pkalgo> <hashalgo> <class> <time> <rc> [<fpr>]. true when a
// fingerprint came; a malformed line leaves GENERAL as status
fn errsig(sig: &mut GpgSig, end: Option<&[u8]>) -> Result<bool, GpgError> {
	let general = |sig: &mut GpgSig| {
		sig.status = ERR_GENERAL;
		Ok(false)
	};
	let Some(s) = end.and_then(errsig_algos) else {
		return general(sig);
	};
	let (ts, tail) = parse_timestamp(s).ok_or(GpgError::InvEngine)?;
	if !ends(tail) {
		return Err(GpgError::InvEngine);
	}
	sig.timestamp = ts;
	let s = skip_spaces(tail);
	let Some((rc, tail)) = strtoul(s).filter(|(_, t)| ends(t)) else {
		return general(sig);
	};
	sig.status = rc as u32;
	if tail.is_empty() {
		return Ok(false);
	}
	let s = skip_spaces(tail);
	if s.is_empty() || s[0] == b'-' && ends(&s[1..]) {
		return Ok(false);
	}
	sig.fpr = Some(s.to_vec());
	Ok(true)
}

// parse_valid_sig: <fpr> <date> <time> <exp time> ..., the algorithms
// after are not checked
fn valid_sig(sig: &mut GpgSig, args: &[u8]) -> Result<(), GpgError> {
	let (fpr, end) = split_word(args);
	if fpr.is_empty() {
		return Err(GpgError::General);
	}
	sig.fpr = Some(fpr.to_vec());
	// the creation date is skipped
	let end = end.unwrap_or_default();
	let Some(i) = end.iter().position(|&c| c == b' ') else {
		return Ok(());
	};
	let (ts, tail) =
		parse_timestamp(&end[i..]).ok_or(GpgError::InvEngine)?;
	if !ends(tail) {
		return Err(GpgError::InvEngine);
	}
	sig.timestamp = ts;
	let (exp, tail) = parse_timestamp(tail).ok_or(GpgError::InvEngine)?;
	if !ends(tail) {
		return Err(GpgError::InvEngine);
	}
	sig.exp_timestamp = exp;
	Ok(())
}

// parse_error of verify.c: ERROR <where> <code>
fn error_status(sig: Option<&mut GpgSig>, args: &[u8]) -> Result<(), GpgError> {
	let (place, which) = split_word(args);
	let which = which.ok_or(GpgError::InvEngine)?;
	let code = atoi(split_word(which).0);
	if place == b"proc_pkt.plaintext" && code & 0xffff == ERR_BAD_DATA {
		return Err(GpgError::BadData);
	}
	let Some(sig) = sig else {
		return Ok(());
	};
	match place {
		b"verify.findkey" => sig.status = code,
		b"verify.keyusage" if code & 0xffff == ERR_WRONG_KEY_USAGE => {
			sig.wrong_key_usage = true;
		}
		_ => {}
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
		let (kw, args) = split_word(rest);
		v.status(kw, args.unwrap_or_default())?;
	}
	Ok(v.finish())
}

// a gpg run's stdout, stdin fed from a thread so no pipe blocks. stderr
// goes to diag, or why gpg could not be run or read
fn run(
	c: &mut Command,
	stdin: Option<&[u8]>,
	diag: &mut Vec<u8>,
) -> Result<Vec<u8>, GpgError> {
	let input = match stdin {
		Some(_) => Stdio::piped(),
		None => Stdio::null(),
	};
	let spawned = c
		.stdin(input)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn();
	let mut child = spawned.map_err(|e| {
		*diag = [b"could not run gpg: ", &strerror(&e)[..]].concat();
		GpgError::InvEngine
	})?;
	let pipe = child.stdin.take();
	// gpgme ignores gpg's exit status, the status lines tell
	let out = std::thread::scope(|s| {
		if let (Some(mut pipe), Some(data)) = (pipe, stdin) {
			// gpg may stop reading early, its status says why
			s.spawn(move || pipe.write_all(data).ok());
		}
		child.wait_with_output()
	});
	let out = out.map_err(|e| {
		*diag = [b"could not read gpg: ", &strerror(&e)[..]].concat();
		GpgError::InvEngine
	})?;
	*diag = out.stderr;
	Ok(out.stdout)
}

impl Keyring {
	/// gpgdir is handle->gpgdir with its trailing '/', gpg is looked up
	/// in PATH where gpgme asks gpgconf
	pub fn new(gpgdir: &[u8]) -> Keyring {
		Keyring {
			gpgdir: until_nul(gpgdir).to_vec(),
			gpg: PathBuf::from("gpg"),
			known_keys: Vec::new(),
			init: false,
			stderr: Vec::new(),
		}
	}

	/// gpgme_set_engine_info's file_name
	pub fn set_gpg(&mut self, gpg: impl Into<PathBuf>) {
		self.gpg = gpg.into();
	}

	/// alpm_option_get_gpgdir
	pub fn gpgdir(&self) -> &[u8] {
		&self.gpgdir
	}

	/// alpm_option_set_gpgdir on a handle in use: known keys stay
	pub fn set_gpgdir(&mut self, gpgdir: &[u8]) {
		self.gpgdir = until_nul(gpgdir).to_vec();
	}

	// gpgme's engine file_name: the gpg Command runs, found in PATH
	fn engine_file(&self) -> Vec<u8> {
		let gpg = self.gpg.as_os_str();
		if gpg.as_bytes().contains(&b'/') {
			return gpg.as_bytes().to_vec();
		}
		let path = std::env::var_os("PATH").unwrap_or_default();
		let found = std::env::split_paths(&path)
			.map(|dir| dir.join(gpg))
			.find(|p| p.is_file());
		found.map_or_else(
			|| gpg.as_bytes().to_vec(),
			|p| p.into_os_string().into_vec(),
		)
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
		parse_verify(&run(&mut c, Some(sig), &mut Vec::new())?)
	}

	// gpgme_get_key: Ok(None) is GPG_ERR_EOF, two different keys are
	// ambiguous, a pattern under 8 characters is refused. gpg's stderr
	// kept for a failed lookup
	fn get_key(
		&mut self,
		pattern: Option<&[u8]>,
		mode: ListMode,
	) -> Result<Option<Key>, GpgError> {
		self.stderr.clear();
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
		let out = run(&mut c, None, &mut self.stderr)?;
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
		let out = run(&mut c, None, &mut Vec::new())?;
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

fn debug(cb: &mut dyn Callbacks, parts: &[&[u8]]) {
	logv(cb, LogLevel::Debug, parts);
}

// _alpm_access(handle, gpgdir, file, mode) of a keyring file
fn keyring_access(
	kr: &Keyring,
	cb: &mut dyn Callbacks,
	file: &[u8],
	mode: Access,
) -> bool {
	alpm_access(cb, Some(&kr.gpgdir), file, mode).is_ok()
}

// init_gpgme: the keyring check and the engine lines, once. the C also
// leaves pm_errno NOT_A_FILE behind, which no caller reads on success.
// there is no gpgme library whose version could be logged
fn init_gpgme(kr: &mut Keyring, cb: &mut dyn Callbacks) {
	if kr.init {
		return;
	}
	// || in the C: trustdb.gpg is only looked at with a pubring
	if !keyring_access(kr, cb, b"pubring.gpg", Access::READ_OK)
		|| !keyring_access(kr, cb, b"trustdb.gpg", Access::READ_OK)
	{
		debug(cb, &[b"Signature verification will fail!\n"]);
		cb.log(
			LogLevel::Warning,
			b"Public keyring not found; have you run \
			'pacman-key --init'?\n",
		);
	}
	debug(cb, &[b"GPGME version: none (gpg run directly)\n"]);
	let file = kr.engine_file();
	// the engine's home_dir is the gpgdir, NULL without one
	let home = Some(&kr.gpgdir[..]).filter(|g| !g.is_empty());
	let home = home.unwrap_or(b"(null)");
	let info = [&b"GPGME engine info: file="[..], &file, b", home="];
	debug(cb, &[&info.concat(), home, b"\n"]);
	kr.init = true;
}

fn gpgme_error(cb: &mut dyn Callbacks, e: GpgError) -> Errno {
	let msg = [b"GPGME error: ", e.text(), b"\n"].concat();
	cb.log(LogLevel::Error, &msg);
	Errno::Gpgme
}

fn gpg_error(cb: &mut dyn Callbacks, text: &[u8]) {
	debug(cb, &[b"gpg error: ", text, b"\n"]);
}

/// _alpm_key_in_keychain: Some(true) known (cached from then on),
/// Some(false) unknown or expired, None when the lookup failed (C -1)
pub fn key_in_keychain(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	fpr: &[u8],
) -> Option<bool> {
	let fpr = until_nul(fpr);
	if kr.known_keys.iter().any(|k| k == fpr) {
		debug(cb, &[b"key ", fpr, b" found in cache\n"]);
		return Some(true);
	}
	init_gpgme(kr, cb);
	debug(cb, &[b"looking up key ", fpr, b" locally\n"]);
	match kr.get_key(Some(fpr), ListMode::Local) {
		Ok(None) => {
			debug(cb, &[b"key lookup failed, unknown key\n"]);
			Some(false)
		}
		Ok(Some(key)) if key.expired => {
			let msg = b"key lookup success, but key is expired\n";
			debug(cb, &[msg]);
			Some(false)
		}
		Ok(Some(_)) => {
			debug(cb, &[b"key lookup success, key exists\n"]);
			kr.known_keys.push(fpr.to_vec());
			Some(true)
		}
		Err(e) => {
			gpg_error(cb, e.text());
			// not in the C (gpgme drops gpg's stderr): what gpg
			// said, so a failing lookup can be told apart
			let said = kr.stderr.split(|&c| c == b'\n');
			for line in said.filter(|l| !l.is_empty()) {
				debug(cb, &[line, b"\n"]);
			}
			None
		}
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
	debug(cb, &[b"looking up key ", email, b" using WKD\n"]);
	// None is the C's gpg_err left at GPG_ERR_NO_ERROR
	let err = match kr.get_key(Some(email), ListMode::LocateExternal) {
		Ok(Some(_)) => {
			if key_in_keychain(kr, cb, fpr) != Some(false) {
				return true;
			}
			let msg = b"key lookup failed: WKD imported wrong \
				fingerprint or key expired\n";
			debug(cb, &[msg]);
			None
		}
		Ok(None) => Some(GpgError::Eof),
		Err(e) => Some(e),
	};
	gpg_error(cb, err.as_ref().map_or(gpg_strerror(0), GpgError::text));
	false
}

// key_search_keyserver: Ok(Some) found (C 1), Ok(None) not found (C 0),
// Err on a failed lookup (C -1). "0x" in front, keyservers want it; on
// a miss the last 8 characters are tried
fn key_search_keyserver(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	fpr: &[u8],
) -> Result<Option<Key>, GpgError> {
	let full = [b"0x", fpr].concat();
	let short = fpr.len().checked_sub(8).filter(|&n| n > 0);
	let short = short.map(|n| [b"0x", &fpr[n..]].concat());
	// what is logged, what is searched: the first line shows the
	// fingerprint without its "0x"
	let tries = [Some((fpr, &full[..])), short.as_deref().map(|s| (s, s))];
	for (shown, pattern) in tries.into_iter().flatten() {
		debug(cb, &[b"looking up key ", shown, b" remotely\n"]);
		match kr.get_key(Some(pattern), ListMode::Extern) {
			Ok(Some(key)) => return Ok(Some(key)),
			Ok(None) => {
				let msg = b"key lookup failed, unknown key\n";
				debug(cb, &[msg]);
			}
			Err(e) => {
				gpg_error(cb, e.text());
				return Err(e);
			}
		}
	}
	gpg_error(cb, GpgError::Eof.text());
	Ok(None)
}

// _alpm_access(gpgdir, "pubring.gpg", W_OK), logged when refused
fn writable(kr: &Keyring, cb: &mut dyn Callbacks) -> bool {
	if keyring_access(kr, cb, b"pubring.gpg", Access::WRITE_OK) {
		return true;
	}
	cb.log(LogLevel::Error, b"keyring is not writable\n");
	false
}

// key_import_keyserver: exactly one key considered and imported. a gpg
// that cannot be run fails without a line (CHECK_ERR)
fn key_import_keyserver(
	kr: &Keyring,
	cb: &mut dyn Callbacks,
	key: &Key,
) -> bool {
	if !writable(kr, cb) {
		return false;
	}
	debug(cb, &[b"importing key\n"]);
	match kr.recv_key(key) {
		Ok((1, Some(true))) => true,
		Ok((1, Some(false))) => {
			// gpg_err is still GPG_ERR_NO_ERROR there
			gpg_error(cb, gpg_strerror(0));
			false
		}
		Ok(_) => {
			let msg = b"could not import key, 0 results\n";
			debug(cb, &[msg]);
			false
		}
		Err(_) => false,
	}
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

/// _alpm_key_import: asked first, then WKD by the uid's address, then the
/// keyservers. true is the C's 0
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
	let msg: &[u8] = match key_search_keyserver(kr, cb, fpr) {
		Ok(Some(key)) => {
			// fetch_key.uid, NULL for a key without uids
			let uid = key.uids.first().map(|u| &u.uid[..]);
			let uid = uid.unwrap_or(b"(null)");
			debug(cb, &[b"key \"", uid, b"\" on keyserver\n"]);
			if key_import_keyserver(kr, cb, &key) {
				return true;
			}
			b"\" could not be imported\n"
		}
		_ => b"\" could not be looked up remotely\n",
	};
	cb.log(LogLevel::Error, &[b"key \"", fpr, msg].concat());
	false
}

/// _alpm_sigpath
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

fn decimal(n: impl std::fmt::Display) -> Vec<u8> {
	n.to_string().into_bytes()
}

// the per-signature lines of _alpm_gpgme_checksig, before its key lookup
fn log_sig(cb: &mut dyn Callbacks, sig: &GpgSig) {
	let fpr = sig.fpr.as_deref().unwrap_or(b"(null)");
	debug(cb, &[b"fingerprint: ", fpr, b"\n"]);
	let words = SIGSUM.iter().filter(|(bit, _)| sig.summary & bit != 0);
	for (_, word) in words {
		debug(cb, &[b"summary: ", word, b"\n"]);
	}
	if sig.summary == 0 {
		debug(cb, &[b"summary: (empty)\n"]);
	}
	debug(cb, &[b"status: ", gpg_strerror(sig.status), b"\n"]);
	debug(cb, &[b"timestamp: ", &decimal(sig.timestamp), b"\n"]);
	// (time_t)timestamp > time(NULL)
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |d| d.as_secs() as i64);
	if sig.timestamp as i64 > now {
		let msg = b"signature timestamp is greater than system time.\n";
		debug(cb, &[msg]);
	}
	let exp = decimal(sig.exp_timestamp);
	debug(cb, &[b"exp_timestamp: ", &exp, b"\n"]);
	let validity = string_validity(sig.validity);
	let reason = gpg_strerror(sig.validity_reason);
	debug(cb, &[b"validity: ", validity, b"; reason: ", reason, b"\n"]);
}

// the key line of a found key with uids
fn log_key(cb: &mut dyn Callbacks, key: &Key) {
	let Some(uid) = key.uids.first() else {
		return;
	};
	let fpr = key.fpr.as_deref().unwrap_or(b"(null)");
	let trust = owner_trust(&key.ownertrust);
	let disabled: &[u8] = if key.disabled { b"1" } else { b"0" };
	let parts: [&[u8]; 8] = [
		b"key: ",
		fpr,
		b", ",
		&uid.uid,
		b", owner_trust ",
		trust,
		b", disabled ",
		disabled,
	];
	debug(cb, &[&parts.concat(), b"\n"]);
}

/// _alpm_gpgme_checksig: the signatures of the file at path, from
/// base64_sig or "<path>.sig". Ok holds a result per signature, whatever
/// they say; Err is the pm_errno (NotAFile, SigMissing, SigInvalid,
/// Gpgme)
pub fn gpgme_checksig(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	path: Option<&[u8]>,
	base64_sig: Option<&[u8]>,
) -> Result<Vec<SigResult>, Errno> {
	let path = path.map(until_nul).ok_or(Errno::NotAFile)?;
	if alpm_access(cb, None, path, Access::READ_OK).is_err() {
		return Err(Errno::NotAFile);
	}
	let sigfile = sigpath(path);
	if base64_sig.is_none()
		&& (alpm_access(cb, None, &sigfile, Access::READ_OK).is_err()
			|| File::open(os(&sigfile)).is_err())
	{
		let msg =
			[b"sig path ", &sigfile[..], b" could not be opened\n"];
		debug(cb, &msg);
		return Err(Errno::SigMissing);
	}
	if File::open(os(path)).is_err() {
		return Err(Errno::NotAFile);
	}
	init_gpgme(kr, cb);
	debug(cb, &[b"checking signature for ", path, b"\n"]);
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
		debug(cb, &[b"no signatures returned\n"]);
		return Err(Errno::SigMissing);
	}
	let count = decimal(sigs.len());
	debug(cb, &[&count, b" signatures returned\n"]);
	let mut results = Vec::with_capacity(sigs.len());
	for sig in sigs {
		log_sig(cb, &sig);
		let found = kr.get_key(sig.fpr.as_deref(), ListMode::Local);
		let (key, disabled) = match found {
			Ok(Some(k)) => {
				log_key(cb, &k);
				result_key(&k)
			}
			// the signature's fpr, there is no key to point at
			Ok(None) => {
				let msg = b"key lookup failed, unknown key\n";
				debug(cb, &[msg]);
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
		let status = match sig.status & 0xffff {
			// key disabled is not in the status code
			_ if disabled => SigStatus::KeyDisabled,
			0 => SigStatus::Valid,
			ERR_KEY_EXPIRED => SigStatus::KeyExpired,
			ERR_SIG_EXPIRED => SigStatus::SigExpired,
			ERR_NO_PUBKEY => SigStatus::KeyUnknown,
			_ => SigStatus::Invalid,
		};
		results.push(SigResult {
			key,
			status,
			validity: sig.validity,
		});
	}
	Ok(results)
}

// the trust policy on one result, with its lines
fn acceptable(
	cb: &mut dyn Callbacks,
	r: &SigResult,
	marginal: bool,
	unknown: bool,
) -> bool {
	if !matches!(r.status, SigStatus::Valid | SigStatus::KeyExpired) {
		debug(cb, &[b"signature is not valid\n"]);
		return false;
	}
	debug(cb, &[b"signature is valid\n"]);
	let (msg, ok): (&[u8], bool) = match r.validity {
		SigValidity::Full => (b"signature is fully trusted\n", true),
		SigValidity::Marginal => {
			(b"signature is marginal trust\n", marginal)
		}
		SigValidity::Unknown => {
			(b"signature is unknown trust\n", unknown)
		}
		SigValidity::Never => {
			(b"signature should never be trusted\n", false)
		}
	};
	debug(cb, &[msg]);
	ok
}

/// _alpm_check_pgp_helper: the check, then the trust policy up to the
/// first refused signature. Err(Some) when the check failed with that
/// pm_errno, Err(None) when a signature is not acceptable. a missing
/// signature is fine when optional. the results come back either way
/// (sigdata)
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
			debug(cb, &[b"missing optional signature\n"]);
			return (Ok(()), Vec::new());
		}
		Err(Errno::SigMissing) => {
			debug(cb, &[b"missing required signature\n"]);
			return (Err(Some(Errno::SigMissing)), Vec::new());
		}
		Err(e) => {
			debug(cb, &[b"signature check failed\n"]);
			return (Err(Some(e)), Vec::new());
		}
	};
	let ok = siglist.iter().all(|r| acceptable(cb, r, marginal, unknown));
	(if ok { Ok(()) } else { Err(None) }, siglist)
}

/// _alpm_process_siglist: what the user can act on, and the import
/// question for unknown and expired keys. true when an import worked and
/// the validation should be retried
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

/// alpm_pkg_check_pgp_signature: pkg->filename and pkg->base64_sig
pub fn pkg_check_pgp_signature(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	pkg: &Package,
) -> Result<Vec<SigResult>, Errno> {
	let path = pkg.filename.as_deref();
	gpgme_checksig(kr, cb, path, pkg.base64_sig.as_deref())
}

/// alpm_db_check_pgp_signature: `<db path>.sig`
pub fn db_check_pgp_signature(
	kr: &mut Keyring,
	cb: &mut dyn Callbacks,
	db: &Db,
) -> Result<Vec<SigResult>, Errno> {
	gpgme_checksig(kr, cb, Some(db.path()), None)
}

/// why alpm_extract_keyid gave up, the two messages it logs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyidError {
	/// "signature format error"
	Format,
	/// "unsupported signature format": partial lengths, not version 4
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

/// alpm_extract_keyid: issuer key ids of the signature packets in sig,
/// appended to keys (those found before an error stay, like the C list)
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
