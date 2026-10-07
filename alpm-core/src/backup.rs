// port of lib/libalpm/backup.c
//
// _alpm_backup_dup and _alpm_backup_free are Clone and Drop.

use crate::package::Package;
use crate::util::until_nul;

// alpm_backup_t
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Backup {
	// file name, without .pacsave
	pub name: Vec<u8>,
	// None when the entry has no tab
	pub hash: Option<Vec<u8>>,
}

// _alpm_needbackup: first backup entry of pkg named file (strcmp). the
// C's NULL checks belong to the C ABI layer
pub fn needbackup<'a>(file: &[u8], pkg: &'a Package) -> Option<&'a Backup> {
	let file = until_nul(file);
	pkg.backup.iter().find(|b| until_nul(&b.name) == file)
}
