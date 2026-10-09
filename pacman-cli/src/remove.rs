// port of src/pacman/remove.c: pacman_remove
//
// the C prints to stdout and through pm_printf to stderr, both go into
// ui.out. a yes to the last question commits.

use std::io::BufRead;

use alpm_core::Handle;
use alpm_core::Package;
use alpm_core::dep_compute_string;
use alpm_core::fnmatch;
use alpm_core::remove_pkg;
use alpm_core::{PrepareData, trans_commit, trans_get_remove, trans_prepare};
use pacman_common::util_common::until_nul;

use crate::conf::cat;
use crate::sync::{error, local_list, warning};
use crate::util::{
	DbPkg, TransTargets, Ui, colon_printf, display_targets, noyes,
	print_packages, trans_init, trans_release, yesno,
};

fn removal_failed<R>(ui: &mut Ui<R>, target: &[u8], e: &[u8]) {
	error(ui.out, ui.config, &[b"'", target, b"': ", e, b"\n"]);
}

// remove_target: the installed package of that name, else every member
// of the local group of that name. false is the C's -1
fn remove_target<R>(ui: &mut Ui<R>, h: &mut Handle, target: &[u8]) -> bool {
	let dbs = h.dbs_mut();
	let (dbext, cb) = (dbs.dbext, dbs.cb);
	let Some(db) = dbs.local else {
		return false;
	};
	if let Ok(pkg) = db.get_pkg(dbext, cb, target) {
		let pkg = pkg.clone();
		if let Err(e) = remove_pkg(h, &pkg) {
			removal_failed(ui, target, e.strerror().as_bytes());
			return false;
		}
		ui.explicit_removes.push(pkg);
		return true;
	}
	let dbs = h.dbs_mut();
	let Some(db) = dbs.local else {
		return false;
	};
	let members: Vec<Package> = match db
		.get_group(dbs.dbext, dbs.cb, target)
	{
		Ok(Some(grp)) => grp.packages.into_iter().cloned().collect(),
		_ => {
			let msg: [&[u8]; 3] =
				[b"target not found: ", target, b"\n"];
			error(ui.out, ui.config, &msg);
			return false;
		}
	};
	for pkg in members {
		if let Err(e) = remove_pkg(h, &pkg) {
			removal_failed(ui, target, e.strerror().as_bytes());
			return false;
		}
		ui.explicit_removes.push(pkg);
	}
	true
}

// pacman_remove: targets ("local/" stripped) into a transaction, prepare,
// the HoldPkg question, then nothing to do, --print, or the target list
// and the remove question; a yes commits
pub fn pacman_remove<R: BufRead, S: AsRef<[u8]>>(
	ui: &mut Ui<R>,
	h: &mut Handle,
	targets: &[S],
) -> i32 {
	let config = ui.config;
	if targets.is_empty() {
		let msg: &[u8] = b"no targets specified (use -h for help)\n";
		error(ui.out, config, &[msg]);
		return 1;
	}
	if !trans_init(ui.out, config, h, config.flags, false) {
		return 1;
	}
	let mut retval = 0;
	for t in targets {
		let t = until_nul(t.as_ref());
		let t = t.strip_prefix(b"local/").unwrap_or(t);
		if !remove_target(ui, h, t) {
			retval = 1;
		}
	}
	if retval == 0 {
		retval = match prepare(ui, h) {
			Some(r) => r,
			None => commit(ui, h),
		};
	}
	if !trans_release(ui.out, config, h) {
		retval = 1;
	}
	retval
}

// alpm_trans_commit, what came before it printed first
fn commit<R>(ui: &mut Ui<R>, h: &mut Handle) -> i32 {
	ui.out.flush();
	let Err(e) = trans_commit(h) else {
		return 0;
	};
	let msg = [
		b"failed to commit transaction (",
		e.errno.strerror().as_bytes(),
		b")\n",
	];
	error(ui.out, ui.config, &msg);
	1
}

// the steps from alpm_trans_prepare on, None for a yes to remove
fn prepare<R: BufRead>(ui: &mut Ui<R>, h: &mut Handle) -> Option<i32> {
	let config = ui.config;
	if let Err(e) = trans_prepare(h) {
		let msg = [
			b"failed to prepare transaction (",
			e.errno.strerror().as_bytes(),
			b")\n",
		];
		error(ui.out, config, &msg);
		if let PrepareData::Missing(misses) = &e.data {
			for m in misses {
				let dep = dep_compute_string(&m.depend);
				let causing = m.causingpkg.as_deref();
				let msg = cat(&[
					b"removing ",
					causing.unwrap_or(b"(null)"),
					b" breaks dependency '",
					&dep,
					b"' required by ",
					&m.target,
					b"\n",
				]);
				colon_printf(
					&mut ui.out.stdout,
					&config.colstr,
					&msg,
				);
			}
		}
		return Some(1);
	}

	let remove = trans_get_remove(h).unwrap_or_default();
	let mut holdpkg = false;
	for pkg in remove {
		let name = pkg.name_bytes();
		if config.holdpkg.iter().any(|p| fnmatch(p, name)) {
			let msg: [&[u8]; 2] =
				[name, b" is designated as a HoldPkg.\n"];
			warning(ui.out, config, &msg);
			holdpkg = true;
		}
	}
	let msg = b"HoldPkg was found in target list. Do you want to continue?";
	if holdpkg && !noyes(ui.out, config, ui.term, msg) {
		return Some(1);
	}

	if remove.is_empty() {
		ui.out.stdout
			.extend_from_slice(b" there is nothing to do\n");
		return Some(0);
	}
	let local = h.localdb();
	let pkgs: Vec<DbPkg> =
		remove.iter().map(|pkg| DbPkg { pkg, db: local }).collect();
	if config.print != 0 {
		let out = &mut ui.out.stdout;
		print_packages(
			out,
			config,
			&pkgs,
			h.cachedirs(),
			ui.format_date,
		);
		return Some(0);
	}
	let remove: Vec<&Package> = remove.iter().collect();
	let explicit_removes: Vec<&Package> =
		ui.explicit_removes.iter().collect();
	let targets = TransTargets {
		add: &[],
		remove: &remove,
		explicit_adds: &[],
		explicit_removes: &explicit_removes,
	};
	display_targets(ui.out, config, &targets, &local_list(h), ui.cols);
	ui.out.stdout.push(b'\n');
	let msg = b"Do you want to remove these packages?";
	match yesno(ui.out, config, ui.term, msg) {
		true => None,
		false => Some(1),
	}
}
