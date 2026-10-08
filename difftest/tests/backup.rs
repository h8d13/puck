// alpm_core::backup against the C in backup.c
use alpm_core::backup::{Backup, needbackup};
use alpm_core::package::Package;
use difftest::{Rng, c_backup_dup, c_needbackup, c_needbackup_null, iters};

const ALPHABET: &[u8] = b"ab/.\t\t \xc3";

fn show(s: &[u8]) -> String {
	String::from_utf8_lossy(s).into_owned()
}

#[test]
fn backup_dup_fuzz() {
	let mut rng = Rng::new(0xd0b);
	for _ in 0..iters() / 10 {
		let b = Backup {
			name: rng.bytes(ALPHABET, 8).into(),
			hash: (rng.below(2) == 0)
				.then(|| rng.bytes(ALPHABET, 8).into()),
		};
		assert_eq!(c_backup_dup(&b), b);
	}
}

// short names from a small alphabet: repeated names (the first entry
// wins) and misses. the hash is irrelevant to the lookup
#[test]
fn needbackup_fuzz() {
	let mut rng = Rng::new(0x2eed);
	let n = iters() / 4;
	let (mut found, mut dup) = (0usize, 0usize);
	for _ in 0..n {
		let backup: Vec<Backup> = (0..rng.below(6))
			.map(|_| Backup {
				name: rng.bytes(b"ab/", 3).into(),
				hash: (rng.below(2) == 0)
					.then(|| rng.bytes(b"ab", 3).into()),
			})
			.collect();
		let pkg = Package {
			backup: backup.into(),
			..Package::default()
		};
		let file = rng.bytes(b"ab/", 3);
		let r = needbackup(&file, &pkg);
		let r = r.map(|b| {
			pkg.backup
				.iter()
				.position(|x| std::ptr::eq(x, b))
				.unwrap()
		});
		let c = c_needbackup(&file, &pkg);
		assert_eq!(c, r, "{:?} in {:?}", show(&file), pkg.backup);
		found += usize::from(c.is_some());
		let same = |b: &&Backup| *b.name == file[..];
		dup += usize::from(pkg.backup.iter().filter(same).count() > 1);
	}
	assert!(found >= n / 10 && dup >= n / 50, "{found} {dup}/{n}");
}

// contract the future C ABI shim has to keep
#[test]
fn c_null_contract() {
	assert_eq!(c_needbackup_null(), (true, true));
}
