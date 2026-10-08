// the testpkg binary: testpkg.c main() on the process
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt;

use testpkg::{Output, Setup, run};

fn main() {
	let args: Vec<Vec<u8>> = std::env::args_os()
		.skip(1)
		.map(OsStringExt::into_vec)
		.collect();
	let mut o = Output::default();
	let ret = run(&args, &Setup::DEFAULT, &mut o);
	// stderr unbuffered, stdout flushed at exit like the C's stdio.
	// write errors are dropped like the unchecked printf calls
	let _ = io::stderr().write_all(&o.err);
	let _ = io::stdout().write_all(&o.out);
	std::process::exit(ret);
}
