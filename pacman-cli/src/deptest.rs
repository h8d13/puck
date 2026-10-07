// port of src/pacman/deptest.c: -T, the dependency strings the local db
// does not satisfy
use alpm_core::handle::Handle;
use alpm_core::util::until_nul;

use crate::check::Output;

// pacman_deptest: targets that are neither a local package name nor
// satisfied by one, one per line on stdout. 127 when any is missing,
// else 0
pub fn pacman_deptest(
	handle: &mut Handle,
	targets: &[Vec<u8>],
	o: &mut Output,
) -> i32 {
	let dbext = handle.dbext().to_vec();
	let mut deps: Vec<&[u8]> = Vec::new();
	for target in targets {
		let target = until_nul(target);
		let found = handle.localdb_mut().is_some_and(|db| {
			db.get_pkg(&dbext, target).is_ok()
				|| db.find_satisfier(&dbext, target).is_some()
		});
		if !found {
			deps.push(target);
		}
	}
	if deps.is_empty() {
		return 0;
	}
	for dep in deps {
		o.stdout.extend_from_slice(dep);
		o.stdout.push(b'\n');
	}
	127
}
