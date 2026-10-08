// port of the planning part of lib/libalpm/remove.c: alpm_remove_pkg and
// _alpm_remove_prepare (cascade, keep needed, optdepend notices).
//
// not here: _alpm_remove_packages and the file removal it runs (the
// commit port). trans->remove holds dups of local packages; the C dups
// force-load every section, trans.rs reloads them fully after prepare.

use crate::callbacks::{Callbacks, Event, LogLevel};
use crate::deps::{
	DepMissing, checkdeps, dep_compute_string, find_satisfier, recursedeps,
};
use crate::error::Errno;
use crate::handle::Handle;
use crate::package::{Package, PkgFrom, pkg_cmp, pkg_find};
use crate::trans::{
	PrepareData, PrepareError, TRANS_FLAG_CASCADE, TRANS_FLAG_NODEPS,
	TRANS_FLAG_NODEPVERSION, TRANS_FLAG_RECURSE, TRANS_FLAG_RECURSEALL,
	TRANS_FLAG_UNNEEDED, Trans, TransState, View, log, opt_str, trans_in,
};

use LogLevel::{Debug, Error, Warning};

// alpm_remove_pkg: a local package joins the removals once, as a dup of
// its fully loaded cache entry. other origins are WrongArgs
pub fn remove_pkg(h: &mut Handle, pkg: &Package) -> Result<(), Errno> {
	if pkg.origin != Some(PkgFrom::LocalDb) {
		return Err(Errno::WrongArgs);
	}
	let trans = trans_in(h, TransState::Initialized)?;
	let name = opt_str(&pkg.name).to_vec();
	if pkg_find(&trans.remove, pkg.name_bytes()).is_some() {
		let msg = [b"skipping duplicate target: ", &name[..], b"\n"];
		log(h.callbacks(), Debug, &msg);
		return Ok(());
	}
	let msg = [
		b"adding package ",
		&name[..],
		b" to the transaction remove list\n",
	];
	log(h.callbacks(), Debug, &msg);
	let dbs = h.dbs_mut();
	let (dbext, cb) = (dbs.dbext, dbs.cb);
	let full = dbs
		.local
		.and_then(|db| {
			db.force_load_pkg(dbext, cb, pkg.name_bytes()).ok()
		})
		.map(Package::dup);
	let copy = full.unwrap_or_else(|| pkg.dup());
	let trans = h.trans_mut().expect("checked above");
	trans.remove.push(copy);
	Ok(())
}

fn checkdeps_rev(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &Trans,
) -> Vec<DepMissing> {
	let nodepversion = trans.flags & TRANS_FLAG_NODEPVERSION != 0;
	let env = view.env(nodepversion);
	let rem: Vec<&Package> = trans.remove.iter().collect();
	checkdeps(&env, &view.local_list(), &rem, &[], true, cb)
}

// remove_prepare_cascade (static in C): the local packages whose
// dependencies break join the removals, until nothing breaks
fn cascade(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
	mut lp: Vec<DepMissing>,
) {
	while !lp.is_empty() {
		for miss in &lp {
			let Some(info) = view.local.find(&miss.target) else {
				let msg = [
					b"could not find ",
					&miss.target[..],
					b" in database -- skipping\n",
				];
				log(cb, Error, &msg);
				continue;
			};
			if pkg_find(&trans.remove, info.name_bytes()).is_some()
			{
				continue;
			}
			let msg = [
				b"pulling ",
				opt_str(&info.name),
				b" in target list\n",
			];
			log(cb, Debug, &msg);
			trans.remove.push(info.dup());
		}
		lp = checkdeps_rev(view, cb, trans);
	}
}

// remove_prepare_keep_needed (static in C): removals that break a
// dependency leave the target list, until nothing breaks
fn keep_needed(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
	mut lp: Vec<DepMissing>,
) {
	while !lp.is_empty() {
		for miss in &lp {
			let causing =
				miss.causingpkg.as_deref().unwrap_or_default();
			let Some(pkg) = pkg_find(&trans.remove, causing) else {
				continue;
			};
			// alpm_list_remove with _alpm_pkg_cmp: the first of that
			// name
			let i = trans
				.remove
				.iter()
				.position(|p| pkg_cmp(p, pkg).is_eq())
				.expect("found above");
			let gone = trans.remove.remove(i);
			let msg = [
				b"removing ",
				opt_str(&gone.name),
				b" from target list\n",
			];
			log(cb, Warning, &msg);
		}
		lp = checkdeps_rev(view, cb, trans);
	}
}

// remove_notify_needed_optdepends (static in C): an OPTDEP_REMOVAL event
// per optdepend of a remaining local package a removal satisfies
fn notify_optdepends(view: &View, cb: &mut dyn Callbacks, trans: &Trans) {
	for pkg in view.local.iter() {
		if pkg.optdepends.is_empty()
			|| pkg_find(&trans.remove, pkg.name_bytes()).is_some()
		{
			continue;
		}
		for optdep in &pkg.optdepends {
			let optstring = dep_compute_string(optdep);
			if find_satisfier(&trans.remove, &optstring).is_some() {
				cb.event(&Event::OptdepRemoval { pkg, optdep });
			}
		}
	}
}

// _alpm_remove_prepare: -Rs adds what only the targets need (after the
// cascade with -Rcs), a broken dependency pulls its package in (-Rc),
// drops the removal that breaks it (-Ru) or fails with the missing
// dependencies
pub(crate) fn remove_prepare(
	view: &View,
	cb: &mut dyn Callbacks,
	trans: &mut Trans,
) -> Result<(), PrepareError> {
	let flags = trans.flags;
	let recurse = flags & TRANS_FLAG_RECURSE != 0;
	let cascading = flags & TRANS_FLAG_CASCADE != 0;
	let nodeps = flags & TRANS_FLAG_NODEPS != 0;
	let explicit = flags & TRANS_FLAG_RECURSEALL != 0;
	if recurse && !cascading {
		log(cb, Debug, &[b"finding removable dependencies\n"]);
		recursedeps(view.local, &mut trans.remove, explicit, cb);
	}

	if !nodeps {
		cb.event(&Event::CheckdepsStart);
		log(cb, Debug, &[b"looking for unsatisfied dependencies\n"]);
		let lp = checkdeps_rev(view, cb, trans);
		if !lp.is_empty() {
			if cascading {
				cascade(view, cb, trans, lp);
			} else if flags & TRANS_FLAG_UNNEEDED != 0 {
				keep_needed(view, cb, trans, lp);
			} else {
				let data = PrepareData::Missing(lp);
				let e = Errno::UnsatisfiedDeps;
				return Err(PrepareError::new(e, data));
			}
		}
	}

	if cascading && recurse {
		log(cb, Debug, &[b"finding removable dependencies\n"]);
		recursedeps(view.local, &mut trans.remove, explicit, cb);
	}

	if !nodeps {
		notify_optdepends(view, cb, trans);
		cb.event(&Event::CheckdepsDone);
	}
	Ok(())
}
