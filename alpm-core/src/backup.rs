// port of lib/libalpm/backup.c
//
// _alpm_needbackup searches alpm_pkg_t, waits for package.c.
// _alpm_backup_dup and _alpm_backup_free are Clone and Drop.

use crate::util::until_nul;

// alpm_backup_t
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Backup {
	// file name, without .pacsave
	pub name: Vec<u8>,
	// None when the entry has no tab
	pub hash: Option<Vec<u8>>,
}

// _alpm_split_backup: "file\thash" split at the first tab, later tabs stay
// in the hash. allocation is the only way the C fails, so no Result
pub fn split_backup(s: &[u8]) -> Backup {
	let s = until_nul(s);
	match s.iter().position(|&c| c == b'\t') {
		Some(i) => Backup {
			name: s[..i].to_vec(),
			hash: Some(s[i + 1..].to_vec()),
		},
		None => Backup {
			name: s.to_vec(),
			hash: None,
		},
	}
}
