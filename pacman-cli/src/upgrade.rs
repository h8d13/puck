// port of src/pacman/upgrade.c: pacman_upgrade up to the commit
//
// URL targets go through alpm_fetch_pkgurl, every file is loaded with
// the local (fetched: remote) file siglevel and added, then the sync
// code prepares (sync_prepare_execute, Prepared::Commit where the C
// commits).

use std::ffi::c_int;
use std::io::BufRead;

use alpm_core::add::add_pkg;
use alpm_core::be_package::pkg_load_level;
use alpm_core::handle::Handle;
use alpm_core::util::until_nul;

use crate::sync::{error, sync_prepare_execute};
use crate::util::{Prepared, Ui, trans_init, trans_release};

fn failed<R>(ui: &mut Ui<R>, targ: &[u8], e: &[u8]) {
	error(ui.out, ui.config, &[b"'", targ, b"': ", e, b"\n"]);
}

// load_packages: each file loaded at siglevel and added as an explicit
// target, 1 when any failed (the others still load)
fn load_packages<R, S: AsRef<[u8]>>(
	ui: &mut Ui<R>,
	h: &mut Handle,
	targets: &[S],
	siglevel: c_int,
) -> i32 {
	let mut retval = 0;
	for t in targets {
		let targ = until_nul(t.as_ref());
		let loaded = h.with_callbacks(|h, cb| {
			pkg_load_level(
				h.keyring_mut(),
				cb,
				targ,
				true,
				siglevel,
			)
		});
		let pkg = match loaded {
			Ok(pkg) => pkg,
			Err(e) => {
				failed(
					ui,
					targ,
					e.errno().strerror().as_bytes(),
				);
				retval = 1;
				continue;
			}
		};
		if let Err(e) = add_pkg(h, pkg.clone(), None) {
			failed(ui, targ, e.strerror().as_bytes());
			retval = 1;
			continue;
		}
		ui.explicit_adds.push(pkg);
	}
	retval
}

// pacman_upgrade: a failed fetch returns the C's -1 before any
// transaction
pub fn pacman_upgrade<R: BufRead, S: AsRef<[u8]>>(
	ui: &mut Ui<R>,
	h: &mut Handle,
	targets: &[S],
) -> Prepared {
	let config = ui.config;
	if targets.is_empty() {
		let msg: &[u8] = b"no targets specified (use -h for help)\n";
		error(ui.out, config, &[msg]);
		return Prepared::Done(1);
	}
	let is_url = |t: &&[u8]| t.windows(3).any(|w| w == b"://");
	let targets: Vec<&[u8]> =
		targets.iter().map(|t| until_nul(t.as_ref())).collect();
	let (remote, local): (Vec<&[u8]>, Vec<&[u8]>) =
		targets.into_iter().partition(is_url);
	let mut fetched = Vec::new();
	if !remote.is_empty() {
		match h.fetch_pkgurl(&remote) {
			Ok(files) => fetched = files,
			Err(_) => return Prepared::Done(-1),
		}
	}
	if !trans_init(ui.out, config, h, config.flags, true) {
		return Prepared::Done(1);
	}
	if config.print == 0 {
		ui.out.stdout.extend_from_slice(b"loading packages...\n");
	}
	let mut retval = load_packages(ui, h, &local, h.local_file_siglevel());
	retval |= load_packages(ui, h, &fetched, h.remote_file_siglevel());
	if retval != 0 {
		trans_release(ui.out, config, h);
		return Prepared::Done(retval);
	}
	sync_prepare_execute(ui, h)
}
