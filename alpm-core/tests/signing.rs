// unit tests for alpm_core::signing: the paths that do not reach gpg
use alpm_core::error::Errno;
use alpm_core::signing::*;

#[test]
fn unpadded_needs_room() {
	assert_eq!(decode_signature(b"Zm9v").unwrap(), b"foo");
	assert_eq!(decode_signature(b"Zg"), Err(DecodeError::BufferTooSmall));
	// line breaks count toward the 3/4 buffer, partial group dropped
	assert_eq!(decode_signature(b"Zg\n\n").unwrap(), b"");
	assert_eq!(decode_signature(b"\n\n\n\n").unwrap(), b"");
}

// collects what the callbacks get, answers no
#[derive(Default)]
struct Log {
	questions: Vec<(Option<Vec<u8>>, Vec<u8>)>,
	lines: Vec<(LogLevel, String)>,
}

impl SigCallbacks for Log {
	fn import_key(&mut self, uid: Option<&[u8]>, fpr: &[u8]) -> bool {
		self.questions.push((uid.map(<[u8]>::to_vec), fpr.to_vec()));
		false
	}

	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		let msg = String::from_utf8_lossy(msg).into_owned();
		self.lines.push((level, msg));
	}
}

// <tmp>/<name>/ with a file "f", removed on drop. no keyring in it
struct Dir(std::path::PathBuf);

impl Dir {
	fn new(name: &str) -> Self {
		let dir = std::env::temp_dir().join(format!(
			"alpm-core-signing-{}-{name}",
			std::process::id()
		));
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::write(dir.join("f"), b"data").unwrap();
		Dir(dir)
	}

	fn path(&self, name: &str) -> Vec<u8> {
		self.0.join(name).into_os_string().into_encoded_bytes()
	}

	// a keyring that never runs gpg
	fn keyring(&self) -> Keyring {
		let mut kr =
			Keyring::new(&[&self.path("gnupg")[..], b"/"].concat());
		kr.set_gpg("/nonexistent/gpg");
		kr
	}
}

impl Drop for Dir {
	fn drop(&mut self) {
		std::fs::remove_dir_all(&self.0).unwrap();
	}
}

// v4 signature packet, old format with a one byte length
fn packet(hashed: &[u8], unhashed: &[u8]) -> Vec<u8> {
	let mut body = vec![4, 0, 22, 10];
	body.extend((hashed.len() as u16).to_be_bytes());
	body.extend(hashed);
	body.extend((unhashed.len() as u16).to_be_bytes());
	body.extend(unhashed);
	body.extend([0, 0]);
	[&[0x88, body.len() as u8][..], &body].concat()
}

#[test]
fn keyid_from_issuer_subpacket() {
	let issuer = [9, 16, 0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 0xab];
	let sig = packet(&[5, 2, 0, 0, 0, 1], &issuer);
	let (mut cb, mut keys) = (Log::default(), Vec::new());
	assert_eq!(extract_keyid(&mut cb, b"p", &sig, &mut keys), Ok(()));
	assert_eq!(keys, [b"DEADBEEF000102AB".to_vec()]);
	// two packets, two ids; nothing logged
	let two = [&sig[..], &sig[..]].concat();
	let mut keys = Vec::new();
	assert_eq!(extract_keyid(&mut cb, b"p", &two, &mut keys), Ok(()));
	assert_eq!(keys.len(), 2);
	assert!(cb.lines.is_empty());
}

#[test]
fn keyid_errors_are_logged() {
	let mut cb = Log::default();
	let mut keys = Vec::new();
	let r = extract_keyid(&mut cb, b"p", &[0x08], &mut keys);
	assert_eq!(r, Err(KeyidError::Format));
	let r = extract_keyid(&mut cb, b"p", &[0x8b, 0, 4], &mut keys);
	assert_eq!(r, Err(KeyidError::Unsupported));
	// the hashed area runs to one byte before the end
	let mut cut = packet(&[2, 2, 0], &[]);
	cut.truncate(cut.len() - 3);
	let r = extract_keyid(&mut cb, b"p", &cut, &mut keys);
	assert_eq!(r, Err(KeyidError::Format));
	let lines: Vec<&str> = cb.lines.iter().map(|(_, l)| &l[..]).collect();
	assert_eq!(
		lines,
		[
			"p: signature format error\n",
			"p: unsupported signature format\n",
			"p: signature format error\n"
		]
	);
}

#[test]
fn checks_before_gpg() {
	let d = Dir::new("before");
	let mut kr = d.keyring();
	let mut cb = Log::default();
	let f = d.path("f");
	assert_eq!(sigpath(b"a.db"), b"a.db.sig");
	let missing = d.path("missing");
	let r = gpgme_checksig(&mut kr, &mut cb, Some(&missing), None);
	assert_eq!(r, Err(Errno::NotAFile));
	let r = gpgme_checksig(&mut kr, &mut cb, None, None);
	assert_eq!(r, Err(Errno::NotAFile));
	let r = gpgme_checksig(&mut kr, &mut cb, Some(&f), None);
	assert_eq!(r, Err(Errno::SigMissing));
	assert!(cb.lines.is_empty());
	// the keyring check comes first, once, then the base64
	for _ in 0..2 {
		let r = gpgme_checksig(&mut kr, &mut cb, Some(&f), Some(b"Zg"));
		assert_eq!(r, Err(Errno::SigInvalid));
	}
	assert_eq!(cb.lines.len(), 1);
	assert_eq!(cb.lines[0].0, LogLevel::Warning);
	assert!(cb.lines[0].1.contains("pacman-key --init"));
}

#[test]
fn helper_missing_signature() {
	let d = Dir::new("helper");
	let (mut kr, mut cb) = (d.keyring(), Log::default());
	let f = d.path("f");
	let r = check_pgp_helper(
		&mut kr,
		&mut cb,
		Some(&f),
		None,
		true,
		false,
		false,
	);
	assert_eq!(r, (Ok(()), Vec::new()));
	let r = check_pgp_helper(
		&mut kr,
		&mut cb,
		Some(&f),
		None,
		false,
		true,
		true,
	);
	assert_eq!(r, (Err(Some(Errno::SigMissing)), Vec::new()));
}

fn result(status: SigStatus, validity: SigValidity) -> SigResult {
	SigResult {
		key: PgpKey {
			fingerprint: Some(b"F00F".to_vec()),
			uid: (status != SigStatus::KeyUnknown)
				.then(|| b"A <a@b>".to_vec()),
			..PgpKey::default()
		},
		status,
		validity,
	}
}

#[test]
fn process_siglist_messages() {
	let d = Dir::new("process");
	let (mut kr, mut cb) = (d.keyring(), Log::default());
	use SigStatus::*;
	use SigValidity::*;
	let list = [
		result(Valid, Full),
		result(Valid, Marginal),
		result(Valid, Unknown),
		result(Valid, Never),
		result(SigExpired, Full),
		result(KeyDisabled, Full),
		result(Invalid, Unknown),
		result(KeyUnknown, Unknown),
		result(KeyExpired, Unknown),
	];
	let kr = &mut kr;
	assert!(!process_siglist(
		kr, &mut cb, b"core", &list, false, false, true
	));
	assert!(!process_siglist(
		kr,
		&mut cb,
		b"core",
		&[],
		false,
		true,
		true
	));
	assert!(!process_siglist(
		kr,
		&mut cb,
		b"core",
		&[],
		true,
		true,
		true
	));
	let lines: Vec<&str> = cb.lines.iter().map(|(_, l)| &l[..]).collect();
	assert_eq!(
		lines,
		[
			"core: signature from \"A <a@b>\" is marginal trust\n",
			"core: signature from \"A <a@b>\" should never be trusted\n",
			"core: signature from \"A <a@b>\" is expired\n",
			"core: key \"A <a@b>\" is disabled\n",
			"core: signature from \"A <a@b>\" is invalid\n",
			// the first keyring use
			"Public keyring not found; have you run 'pacman-key --init'?\n",
			// no uid: the fingerprint; gpg is not there, no keyring
			"core: key \"F00F\" is unknown\n",
			"keyring is not writable\n",
			"core: signature from \"A <a@b>\" is expired\n",
			"keyring is not writable\n",
			"core: missing required signature\n",
		]
	);
	// an unwritable keyring asks nothing
	assert!(cb.questions.is_empty());
	assert_eq!(key_in_keychain(kr, &mut cb, b"F00F0000"), None);
}
