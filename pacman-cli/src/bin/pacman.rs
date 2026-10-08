// the pacman binary: pacman.c main() on the process (pacman_cli::pacman::run)
use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::os::unix::ffi::OsStringExt;

use pacman_cli::pacman::{Io, Process, run, std_sink, std_term};

// freopen(ctermid(NULL), "r", stdin): only the open is checked, std
// cannot put the terminal in place of fd 0; later prompts read the
// (exhausted) stdin
fn reopen_tty() -> Result<(), i32> {
	match File::open("/dev/tty") {
		Ok(_) => Ok(()),
		Err(e) => Err(e.raw_os_error().unwrap_or(0)),
	}
}

fn main() {
	// the download helper child of the sandbox runs this binary
	if let Some(c) = alpm_core::sandbox::helper_entry() {
		std::process::exit(c)
	}
	let mut argv: Vec<Vec<u8>> =
		std::env::args_os().map(OsStringExt::into_vec).collect();
	// stdin is read only for a "-" target, prompts need it otherwise
	let dash = argv.iter().skip(1).any(|a| a == b"-");
	let mut input = Vec::new();
	let piped = !io::stdin().is_terminal();
	if dash && piped {
		let _ = io::stdin().read_to_end(&mut input);
	}
	let process = Process {
		uid: alpm_core::util::getuid(),
		stdin: piped.then_some(&input[..]),
		reopen_tty,
	};
	let mut io = Io {
		stdout_tty: io::stdout().is_terminal(),
		posixly_correct: std::env::var_os("POSIXLY_CORRECT").is_some(),
		debug_stamps: true,
		..Io::default()
	};
	let ret = run(&mut argv, process, &mut io, std_term, Some(std_sink));
	std::process::exit(ret);
}
