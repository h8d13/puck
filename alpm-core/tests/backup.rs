// unit tests for alpm_core::backup
use alpm_core::backup::*;

fn backup(name: &[u8], hash: Option<&[u8]>) -> Backup {
	Backup {
		name: name.into(),
		hash: hash.map(Box::from),
	}
}

#[test]
fn needbackup_cases() {
	let pkg = alpm_core::package::Package {
		backup: vec![
			backup(b"etc/a", Some(b"1")),
			backup(b"etc/b", None),
			backup(b"etc/a", Some(b"2")),
		]
		.into(),
		..Default::default()
	};
	let found = needbackup(b"etc/a", &pkg).unwrap();
	assert!(std::ptr::eq(found, &pkg.backup[0]));
	assert_eq!(needbackup(b"etc/b\0x", &pkg), Some(&pkg.backup[1]));
	assert_eq!(needbackup(b"etc/c", &pkg), None);
	assert_eq!(needbackup(b"etc", &pkg), None);
}
