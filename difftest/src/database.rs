// C side of src/pacman/database.c (frontend objects, see build.rs): runs
// pacman_database on a FrontHandle like sync_ro runs pacman_sync, with
// op_q_check, quiet and flags (--asdeps/--asexplicit) from the Config.
// -D writes desc files through _alpm_local_db_write, which sets the
// umask: callers hold difftest::umask_lock() first
use std::ffi::c_int;

use pacman_cli::conf::Config;

use crate::CList;
use crate::sync_ro::{CRun, FrontHandle, run_op};

unsafe extern "C" {
	fn pacman_database(targets: *mut CList) -> c_int;
}

// pacman_database(targets) on fh
pub fn c_pacman_database<S: AsRef<[u8]>>(
	fh: &FrontHandle,
	cfg: &Config,
	targets: &[S],
) -> CRun {
	run_op(fh, cfg, 0, targets, pacman_database)
}
