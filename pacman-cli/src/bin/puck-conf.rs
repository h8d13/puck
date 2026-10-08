// the pacman-conf binary: pacman-conf.c main() on the process
// (pacman_cli::pacman_conf::run)
use std::io::{self, IsTerminal, Write};
use std::os::unix::ffi::OsStringExt;

use pacman_cli::pacman::Io;
use pacman_cli::pacman_conf::run;

fn main() {
	let mut argv: Vec<Vec<u8>> =
		std::env::args_os().map(OsStringExt::into_vec).collect();
	let mut io = Io {
		stdout_tty: io::stdout().is_terminal(),
		posixly_correct: std::env::var_os("POSIXLY_CORRECT").is_some(),
		..Io::default()
	};
	let ret = run(&mut argv, &mut io);
	// stderr is unbuffered in the C, its lines come before the
	// buffered stdout flushed at exit. write errors are dropped like
	// the unchecked stdio calls
	let _ = io::stderr().write_all(&io.err);
	let _ = io::stdout().write_all(&io.out);
	std::process::exit(ret);
}
