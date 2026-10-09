// init_gpgme's lines (signing.c) against the C: the C runs it once per
// process (static init), so this binary holds a single test, on a
// gpgdir without a keyring. gpgme's library version has no port
// counterpart (PORTING.md): the value after "GPGME version: " is masked
use std::fs;

use alpm_core::internals::signing::{Keyring, key_in_keychain};
use difftest::{CSigHandle, RecordingCallbacks, TempRoot};

const FPR: &[u8] = b"0123456789ABCDEF0123456789ABCDEF01234567";

fn masked(logs: &[(i32, Vec<u8>)]) -> Vec<(i32, String)> {
	let version = "GPGME version: ";
	let text = |m: &[u8]| String::from_utf8_lossy(m).into_owned();
	let mask = |m: String| match m.starts_with(version) {
		true => format!("{version}<v>\n"),
		false => m,
	};
	logs.iter().map(|(l, m)| (*l, mask(text(m)))).collect()
}

#[test]
fn init_lines_against_c() {
	let tmp = TempRoot::new("signing-init");
	for d in ["root", "db", "gnupg"] {
		fs::create_dir_all(tmp.dir().join(d)).unwrap();
	}
	let gpgdir = [&tmp.path("gnupg")[..], b"/"].concat();
	let (root, db) = (tmp.dir().join("root"), tmp.dir().join("db"));
	let c = CSigHandle::uninit(&root, &db, &gpgdir);
	let c = c.in_keychain(FPR);
	let mut kr = Keyring::new(&gpgdir);
	let mut cb = RecordingCallbacks::default();
	let r = key_in_keychain(&mut kr, &mut cb, FPR);
	assert_eq!(c.rc, 0, "an unknown key on the C side");
	assert_eq!(r, Some(false));
	let (c, r) = (masked(&c.events.logs), masked(&cb.events.logs));
	assert!(c.iter().any(|(_, m)| m.starts_with("GPGME engine")));
	assert_eq!(c, r);
}
