// puck-mini: tiny CLI over the puck_mini library, itself over
// alpm-core's public API only. usage:
//
//   puck-mini [--root R] [--dbpath D] [--cachedir C]
//             [--repo NAME --server URL] <query|search|install> [ARG]
//
// query               list installed packages (-Q)
// search <needle>     search the sync db --repo names (-Ss)
// install <pkgname>   sync-install one package from --repo (-S)

use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

use alpm_core::Handle;
use puck_mini::{Cli, install, query_installed, search};

struct Args {
	root: Vec<u8>,
	dbpath: Vec<u8>,
	cachedir: Option<Vec<u8>>,
	repo: Option<Vec<u8>>,
	server: Option<Vec<u8>>,
	cmd: Option<Vec<u8>>,
	arg: Option<Vec<u8>>,
}

// a flag's value, or an error naming the flag
fn value(it: &mut impl Iterator<Item = Vec<u8>>, flag: &str) -> Vec<u8> {
	it.next().unwrap_or_else(|| {
		eprintln!("missing value for {flag}");
		std::process::exit(2);
	})
}

fn parse(argv: Vec<Vec<u8>>) -> Args {
	let mut a = Args {
		root: b"/".to_vec(),
		dbpath: b"/var/lib/pacman/".to_vec(),
		cachedir: None,
		repo: None,
		server: None,
		cmd: None,
		arg: None,
	};
	let mut it = argv.into_iter();
	while let Some(tok) = it.next() {
		match &tok[..] {
			b"--root" => a.root = value(&mut it, "--root"),
			b"--dbpath" => a.dbpath = value(&mut it, "--dbpath"),
			b"--cachedir" => {
				a.cachedir = Some(value(&mut it, "--cachedir"))
			}
			b"--repo" => a.repo = Some(value(&mut it, "--repo")),
			b"--server" => {
				a.server = Some(value(&mut it, "--server"))
			}
			_ if a.cmd.is_none() => a.cmd = Some(tok),
			_ => a.arg = Some(tok),
		}
	}
	a
}

fn run(a: &Args) -> io::Result<()> {
	let mut h = Handle::initialize(&a.root, &a.dbpath)
		.map_err(|e| io::Error::other(e.strerror()))?;
	h.set_callbacks(Box::new(Cli));
	if let Some(dir) = &a.cachedir {
		h.add_cachedir(dir);
	}
	if let Some(repo) = &a.repo {
		h.register_syncdb(repo, 0)
			.map_err(|e| io::Error::other(e.strerror()))?;
		if let Some(server) = &a.server {
			// dbs_mut lends the db next to the callbacks add_server
			// logs through
			let dbs = h.dbs_mut();
			let db = dbs.sync.last_mut().expect("just registered");
			db.add_server(dbs.cb, server)
				.map_err(|e| io::Error::other(e.strerror()))?;
		}
	}

	let out = &mut io::stdout();
	match a.cmd.as_deref() {
		Some(b"query") => query_installed(&mut h, out),
		Some(b"search") => {
			let needle = a.arg.as_deref().unwrap_or_default();
			search(&mut h, needle, out).map(|_| ())
		}
		Some(b"install") => {
			let repo = a.repo.as_deref().unwrap_or_default();
			let name = a.arg.as_deref().unwrap_or_default();
			install(&mut h, repo, name, out)
		}
		other => {
			let name = String::from_utf8_lossy(
				other.unwrap_or(b"(none)"),
			);
			Err(io::Error::other(format!(
				"unknown command: {name}"
			)))
		}
	}
}

fn main() -> ExitCode {
	let argv: Vec<Vec<u8>> = std::env::args_os()
		.skip(1)
		.map(|a| a.as_bytes().to_vec())
		.collect();
	let a = parse(argv);
	match run(&a) {
		Ok(()) => ExitCode::SUCCESS,
		Err(e) => {
			let _ = writeln!(io::stderr(), "error: {e}");
			ExitCode::FAILURE
		}
	}
}
