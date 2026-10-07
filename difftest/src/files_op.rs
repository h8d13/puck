// C side of src/pacman/files.c (frontend objects, see build.rs): runs
// pacman_files on a FrontHandle like sync_ro runs pacman_sync. the handle
// should carry dbext ".files", as setup_libalpm sets it for -F
use std::ffi::c_int;

use pacman_cli::conf::Config;

use crate::CList;
use crate::sync_ro::{CRun, FrontHandle, run_op};

unsafe extern "C" {
	fn pacman_files(targets: *mut CList) -> c_int;
}

// pacman_files(targets) on fh. C precondition: no -Fy (downloads)
pub fn c_pacman_files<S: AsRef<[u8]>>(
	fh: &FrontHandle,
	cfg: &Config,
	targets: &[S],
) -> CRun {
	assert_eq!(cfg.op_s_sync, 0, "-Fy downloads");
	run_op(fh, cfg, 0, targets, pacman_files)
}
