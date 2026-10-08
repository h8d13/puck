// port of src/util/testpkg.c: alpm_pkg_load with full checks at the
// testpkg siglevel, its messages and exit status
//
// main()'s compile-time paths and siglevel are `Setup` fields, so the
// equivalence tests can point them at fixture roots and keyrings; the
// binary passes `Setup::DEFAULT`. stdout and stderr are collected in buffers,
// messages are the untranslated msgids.
use std::ffi::c_int;

use alpm_core::PACKAGE_VERSION;
use alpm_core::be_package::pkg_load_level;
use alpm_core::callbacks::{Callbacks, LogLevel};
use alpm_core::error::Errno;
use alpm_core::handle::Handle;
use alpm_core::signing::{SIG_PACKAGE, SIG_PACKAGE_OPTIONAL};

// ROOTDIR, DBPATH, GPGDIR of the reference build's config.h, the siglevel
// main() loads with
#[derive(Clone, Copy, Debug)]
pub struct Setup<'a> {
	pub root: &'a [u8],
	pub dbpath: &'a [u8],
	pub gpgdir: &'a [u8],
	pub siglevel: c_int,
}

impl Setup<'static> {
	pub const DEFAULT: Setup<'static> = Setup {
		root: b"/",
		dbpath: b"/var/lib/pacman/",
		gpgdir: b"/etc/pacman.d/gnupg/",
		siglevel: SIG_PACKAGE | SIG_PACKAGE_OPTIONAL,
	};
}

#[derive(Debug, Default)]
pub struct Output {
	pub out: Vec<u8>,
	pub err: Vec<u8>,
}

// output_cb: errors and warnings to stdout with their prefix. the C
// skips an empty format string; messages arrive formatted here, so an
// empty message is skipped instead
struct Printer<'a>(&'a mut Vec<u8>);

impl Callbacks for Printer<'_> {
	fn log(&mut self, level: LogLevel, msg: &[u8]) {
		if msg.is_empty() {
			return;
		}
		let prefix: &[u8] = match level {
			LogLevel::Error => b"error: ",
			LogLevel::Warning => b"warning: ",
			_ => return,
		};
		self.0.extend_from_slice(prefix);
		self.0.extend_from_slice(msg);
	}
}

// what main() prints for a failed load
fn failure(err: Errno) -> Vec<u8> {
	match err {
		Errno::PkgNotFound => b"Cannot find the given file.\n".to_vec(),
		Errno::PkgOpen => b"Cannot open the given file.\n".to_vec(),
		Errno::Libarchive | Errno::PkgInvalid => {
			b"Package is invalid.\n".to_vec()
		}
		e => format!("libalpm error: {}\n", e.strerror()).into_bytes(),
	}
}

// main() on argv minus argv[0]: the exit status
pub fn run(args: &[Vec<u8>], setup: &Setup<'_>, o: &mut Output) -> i32 {
	let [file] = args else {
		let usage = format!("testpkg (pacman) v{PACKAGE_VERSION}\n\n\
			Test a pacman package for validity.\n\n\
			Usage: testpkg <package file>\n");
		o.err.extend_from_slice(usage.as_bytes());
		return 1;
	};
	let mut handle = match Handle::initialize(setup.root, setup.dbpath) {
		Ok(h) => h,
		Err(e) => {
			let msg = format!(
				"cannot initialize alpm: {}\n",
				e.strerror()
			);
			o.err.extend_from_slice(msg.as_bytes());
			return 1;
		}
	};
	handle.set_gpgdir(setup.gpgdir);
	let mut cb = Printer(&mut o.out);
	let kr = handle.keyring_mut();
	let loaded = pkg_load_level(kr, &mut cb, file, true, setup.siglevel);
	// alpm_release only fails on a NULL handle or a live transaction,
	// neither exists here
	match loaded {
		Ok(_) => {
			o.out.extend_from_slice(b"Package is valid.\n");
			0
		}
		Err(e) => {
			o.out.extend_from_slice(&failure(e.errno()));
			1
		}
	}
}
