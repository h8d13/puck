// port of alpm_add_pkg of lib/libalpm/add.c, the target side of -S/-U.
//
// not here: the extraction, backup handling and local db writes of
// _alpm_upgrade_packages (the commit port).

use crate::callbacks::LogLevel;
use crate::error::Errno;
use crate::handle::Handle;
use crate::package::{
	Package, PkgFrom, PkgReason, pkg_compare_versions, pkg_find,
};
use crate::trans::{
	TRANS_FLAG_DOWNLOADONLY, TRANS_FLAG_NEEDED, TransPkg, TransState,
	load_caches, log, opt_str, trans_in,
};

use LogLevel::{Debug, Warning};

// alpm_add_pkg: a sync (db is its position in Handle::syncdbs()) or
// file package becomes an explicit target. the same sync package again
// is skipped, another of that name is TransDupTarget (a file package is
// never the same: the C compares addresses, pacman loads each file
// once). an installed package of that name only brings warnings, or
// with NEEDED skips an up to date one
pub fn add_pkg(
	h: &mut Handle,
	pkg: Package,
	db: Option<usize>,
) -> Result<(), Errno> {
	if pkg.origin == Some(PkgFrom::LocalDb) {
		return Err(Errno::WrongArgs);
	}
	trans_in(h, TransState::Initialized)?;
	let (name, ver) = (opt_str(&pkg.name).to_vec(), opt_str(&pkg.version));
	let ver = ver.to_vec();
	log(h.callbacks(), Debug, &[b"adding package '", &name, b"'\n"]);

	let trans = h.trans().expect("checked above");
	let add = trans.add.iter().map(|t| &t.pkg);
	if let Some(dup) = pkg_find(add, pkg.name_bytes()) {
		let same = trans.add.iter().any(|t| {
			std::ptr::eq(&t.pkg, dup)
				&& t.db.is_some() && t.db == db
		});
		if !same {
			return Err(Errno::TransDupTarget);
		}
		let msg = [b"skipping duplicate target: ", &name[..], b"\n"];
		log(h.callbacks(), Debug, &msg);
		return Ok(());
	}
	let flags = trans.flags;

	load_caches(h, false);
	let local = h
		.localdb()
		.and_then(|db| db.loaded_pkgcache())
		.and_then(|c| c.find(pkg.name_bytes()))
		.map(|l| (l.clone(), pkg_compare_versions(&pkg, l)));
	if let Some((local, cmp)) = local {
		let (lname, lver) =
			(opt_str(&local.name), opt_str(&local.version));
		let downloadonly = flags & TRANS_FLAG_DOWNLOADONLY != 0;
		let cb = h.callbacks();
		if cmp.is_eq() {
			if flags & TRANS_FLAG_NEEDED != 0 {
				let msg = [
					lname,
					b"-",
					lver,
					b" is up to date -- skipping\n",
				];
				log(cb, Warning, &msg);
				return Ok(());
			}
			if !downloadonly {
				let msg = [
					lname,
					b"-",
					lver,
					b" is up to date -- reinstalling\n",
				];
				log(cb, Warning, &msg);
			}
		} else if cmp.is_lt() && !downloadonly {
			let msg = [
				b"downgrading package ",
				lname,
				b" (",
				lver,
				b" => ",
				&ver[..],
				b")\n",
			];
			log(cb, Warning, &msg);
		}
	}

	let msg = [
		b"adding package ",
		&name[..],
		b"-",
		&ver[..],
		b" to the transaction add list\n",
	];
	log(h.callbacks(), Debug, &msg);
	let trans = h.trans_mut().expect("checked above");
	// the C target is the cache entry itself: one a prepare dropped to
	// unresolvable comes back with its removes and oldpkg
	let dropped = trans.unresolvable.iter().find(|t| {
		t.db.is_some() && t.db == db && t.pkg.name == pkg.name
	});
	let mut t = match dropped {
		Some(t) => t.clone(),
		None => TransPkg::new(pkg, db),
	};
	t.pkg.reason = PkgReason::Explicit;
	trans.add.push(t);
	Ok(())
}
