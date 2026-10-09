//! puck-mini: a small example front end on alpm-core's public API.
//!
//! it opens a [`Handle`], installs [`Callbacks`], and runs three
//! operations through the same calls pacman-cli uses: list installed
//! packages (`-Q`), search the sync dbs (`-Ss`) and a one-package sync
//! install (`-S`: resolve, prepare, commit). the point is to prove the
//! crate's default public surface is enough for a Rust front end: this
//! crate depends on `alpm-core` with default features and never touches
//! `alpm_core::internals::*`.

use std::io::{self, Write};

use alpm_core::{
	Callbacks, Errno, Handle, LogLevel, Package, add_pkg, trans_commit,
	trans_init, trans_prepare, trans_release,
};

/// stderr logger for a non-interactive front end. debug/function lines
/// are dropped (pacman's default logmask); questions are left at their
/// default answer, the C's zeroed answer, so the run never blocks.
pub struct Cli;

impl Callbacks for Cli {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		if matches!(level, LogLevel::Debug | LogLevel::Function) {
			return;
		}
		let _ = io::stderr().write_all(msg);
	}
	// question() left at its default: the answer stays the C's zeroed
	// default, i.e. no/decline, which is what a non-interactive front
	// end wants.
}

// a package's version as bytes, the pub `version` field of the C struct
fn version(pkg: &Package) -> &[u8] {
	pkg.version.as_deref().unwrap_or_default()
}

// Errno -> io::Error carrying the C's strerror text
fn as_io(e: Errno) -> io::Error {
	io::Error::other(e.strerror())
}

fn msg_io(s: String) -> io::Error {
	io::Error::other(s)
}

/// list installed packages as "name version", like `pacman -Q`.
pub fn query_installed(h: &mut Handle, out: &mut dyn Write) -> io::Result<()> {
	// DbsMut lends the local db next to dbext and the callbacks, the
	// shape alpm-core gives for a db read that logs through the handle
	let dbs = h.dbs_mut();
	let local = dbs.local.expect("local db registered by initialize");
	let cache = local.pkgcache(dbs.dbext, dbs.cb).map_err(as_io)?;
	for pkg in cache.iter() {
		out.write_all(pkg.name_bytes())?;
		out.write_all(b" ")?;
		out.write_all(version(pkg))?;
		out.write_all(b"\n")?;
	}
	Ok(())
}

/// search every sync db for `needle` (a regex, so a plain substring
/// matches like `pacman -Ss`), printing "repo/name version" and the
/// description. returns the number of hits.
pub fn search(
	h: &mut Handle,
	needle: &[u8],
	out: &mut dyn Write,
) -> io::Result<usize> {
	let dbs = h.dbs_mut();
	let (dbext, cb) = (dbs.dbext, dbs.cb);
	let mut shown = 0;
	for db in dbs.sync.iter_mut() {
		// the search borrows db mutably and the hits reborrow it, so
		// take the repo name first
		let repo = db.name().to_vec();
		let hits = db.search(dbext, cb, &[needle]).map_err(as_io)?;
		for pkg in hits {
			out.write_all(&repo)?;
			out.write_all(b"/")?;
			out.write_all(pkg.name_bytes())?;
			out.write_all(b" ")?;
			out.write_all(version(pkg))?;
			out.write_all(b"\n")?;
			if let Some(desc) = pkg.desc.as_deref() {
				out.write_all(b"    ")?;
				out.write_all(desc)?;
				out.write_all(b"\n")?;
			}
			shown += 1;
		}
	}
	Ok(shown)
}

// the transaction body between trans_init and trans_release: resolve a
// named package from the sync db at `idx`, add it, prepare and commit.
fn install_inner(
	h: &mut Handle,
	idx: usize,
	name: &[u8],
	out: &mut dyn Write,
) -> io::Result<()> {
	// dup_pkg returns an owned Package, so the DbsMut borrow can end
	// before add_pkg takes the handle again
	let pkg = {
		let dbs = h.dbs_mut();
		let db = &mut dbs.sync[idx];
		db.dup_pkg(dbs.dbext, dbs.cb, name).map_err(as_io)?.0
	};
	writeln!(out, "resolved {}", String::from_utf8_lossy(name))?;

	add_pkg(h, pkg, Some(idx)).map_err(as_io)?;
	trans_prepare(h).map_err(|e| {
		msg_io(format!(
			"prepare failed: {} ({:?})",
			e.errno.strerror(),
			e.data
		))
	})?;
	writeln!(out, "prepared")?;

	trans_commit(h).map_err(|e| {
		msg_io(format!(
			"commit failed: {} ({:?})",
			e.errno.strerror(),
			e.data
		))
	})?;
	writeln!(out, "committed")?;
	Ok(())
}

/// install one named package from the sync db `repo`, like `pacman -S`:
/// resolve, prepare, commit. the transaction is always released, even on
/// failure.
pub fn install(
	h: &mut Handle,
	repo: &[u8],
	name: &[u8],
	out: &mut dyn Write,
) -> io::Result<()> {
	let idx = h
		.syncdbs()
		.iter()
		.position(|d| d.name() == repo)
		.ok_or_else(|| {
			msg_io(format!(
				"no sync db '{}'",
				String::from_utf8_lossy(repo)
			))
		})?;

	trans_init(h, 0).map_err(|e| msg_io(format!("trans_init: {e:?}")))?;
	let res = install_inner(h, idx, name, out);
	let rel = trans_release(h).map_err(as_io);
	res?;
	rel?;
	Ok(())
}
