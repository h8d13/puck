// alpm_core::backup against the C in backup.c
use alpm_core::backup::{Backup, split_backup};
use difftest::{Rng, c_backup_dup, c_split_backup, iters};

const ALPHABET: &[u8] = b"ab/.\t\t \xc3";

fn show(s: &[u8]) -> String {
	String::from_utf8_lossy(s).into_owned()
}

fn assert_same(s: &[u8]) {
	let r = split_backup(s);
	assert_eq!(
		c_split_backup(Some(s)),
		(0, Some(r.name), r.hash),
		"{:?}",
		show(s)
	);
}

#[test]
fn split_backup_edge_cases() {
	for s in [&b""[..], b"\t", b"a\tb", b"a\t\tb", b"\ta", b"a\t", b"\t\t"]
	{
		assert_same(s);
	}
}

#[test]
fn split_backup_fuzz() {
	let mut rng = Rng::new(0xbac0);
	for _ in 0..iters() {
		assert_same(&rng.bytes(ALPHABET, 12));
	}
}

#[test]
fn backup_dup_fuzz() {
	let mut rng = Rng::new(0xd0b);
	for _ in 0..iters() / 10 {
		let b = Backup {
			name: rng.bytes(ALPHABET, 8),
			hash: (rng.below(2) == 0)
				.then(|| rng.bytes(ALPHABET, 8)),
		};
		assert_eq!(c_backup_dup(&b), b);
	}
}

// contract the future C ABI shim has to keep
#[test]
fn c_null_contract() {
	assert_eq!(c_split_backup(None), (0, None, None));
}
