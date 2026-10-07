// unit tests for alpm_core::backup
use alpm_core::backup::*;

fn backup(name: &[u8], hash: Option<&[u8]>) -> Backup {
	Backup {
		name: name.to_vec(),
		hash: hash.map(<[u8]>::to_vec),
	}
}

#[test]
fn split_backup_cases() {
	assert_eq!(
		split_backup(b"etc/pacman.conf\tabc123"),
		backup(b"etc/pacman.conf", Some(b"abc123"))
	);
	assert_eq!(split_backup(b"etc/fstab"), backup(b"etc/fstab", None));
	assert_eq!(split_backup(b"a\tb\tc"), backup(b"a", Some(b"b\tc")));
	assert_eq!(split_backup(b"\t"), backup(b"", Some(b"")));
	assert_eq!(split_backup(b""), backup(b"", None));
	assert_eq!(split_backup(b"a\0\tb"), backup(b"a", None));
}
