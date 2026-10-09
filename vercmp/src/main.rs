// port of src/util/vercmp.c, same output and exit codes
use std::env;
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

use alpm_core::PACKAGE_VERSION;
use alpm_core::vercmp;

fn usage() {
	eprint!("vercmp (pacman) v{PACKAGE_VERSION}\n\n\
		Compare package version numbers using pacman's version \
		comparison logic.\n\n\
		Usage: vercmp <ver1> <ver2>\n\n\
		Output values:\n  \
		< 0 : if ver1 < ver2\n    \
		0 : if ver1 == ver2\n  \
		> 0 : if ver1 > ver2\n");
}

fn main() -> ExitCode {
	let args: Vec<_> = env::args_os().skip(1).collect();

	if args.is_empty() {
		usage();
		return ExitCode::from(2);
	}
	if args[0] == "-h" || args[0] == "--help" {
		usage();
		return ExitCode::SUCCESS;
	}
	if args.len() != 2 {
		eprint!(
			"error: {} argument(s) specified\n\n\
			Usage: vercmp <ver1> <ver2>\n",
			args.len()
		);
		return ExitCode::FAILURE;
	}

	let ret = vercmp(args[0].as_bytes(), args[1].as_bytes());
	println!("{}", ret as i8);
	ExitCode::SUCCESS
}
