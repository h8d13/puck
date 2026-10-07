// C side of the getopt_long port: glibc's own getopt_long, the parser
// pacman.c calls
//
// getopt keeps its state in libc globals (optind, optarg, optopt, opterr
// and a static struct) and prints to the C `stderr`: GETOPT serializes
// every run, stderr points at an open_memstream for its duration. each
// run starts with optind = 0, the glibc full reinitialization.
use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr;
use std::sync::Mutex;

use pacman_cli::getopt::{HasArg, LongOpt};

use crate::{c_free, fclose, fflush, open_memstream, stderr};

// getopt.h struct option
#[repr(C)]
struct COption {
	name: *const c_char,
	has_arg: c_int,
	flag: *mut c_int,
	val: c_int,
}

unsafe extern "C" {
	static mut optind: c_int;
	static mut opterr: c_int;
	static mut optopt: c_int;
	static mut optarg: *mut c_char;
	fn getopt_long(
		argc: c_int,
		argv: *const *mut c_char,
		shortopts: *const c_char,
		longopts: *const COption,
		longind: *mut c_int,
	) -> c_int;
}

static GETOPT: Mutex<()> = Mutex::new(());

// one getopt_long call: return value and the globals after it
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetoptStep {
	pub ret: i32,
	pub optind: usize,
	pub optopt: i32,
	pub optarg: Option<Vec<u8>>,
	pub longind: usize,
	// lossy UTF-8, readable in assert messages
	pub stderr: String,
}

// a whole run: every pass until -1, then argv as permuted
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetoptRun {
	pub steps: Vec<GetoptStep>,
	pub argv: Vec<Vec<u8>>,
}

// runs `passes` scans over argv like parseargs: the first from a full
// reinit, the next ones with optind = 1. longind starts at `longind`
pub fn c_getopt_run(
	argv: &[Vec<u8>],
	optstring: &[u8],
	longopts: &[LongOpt],
	print_errors: bool,
	passes: usize,
	longind: usize,
) -> GetoptRun {
	let _guard = GETOPT.lock().unwrap_or_else(|e| e.into_inner());
	let strs: Vec<CString> = argv
		.iter()
		.map(|a| CString::new(a.clone()).unwrap())
		.collect();
	let mut ptrs: Vec<*mut c_char> =
		strs.iter().map(|s| s.as_ptr().cast_mut()).collect();
	ptrs.push(ptr::null_mut());
	let names: Vec<CString> = longopts
		.iter()
		.map(|o| CString::new(o.name).unwrap())
		.collect();
	let mut table: Vec<COption> = longopts
		.iter()
		.zip(&names)
		.map(|(o, n)| COption {
			name: n.as_ptr(),
			has_arg: match o.has_arg {
				HasArg::No => 0,
				HasArg::Required => 1,
				HasArg::Optional => 2,
			},
			flag: ptr::null_mut(),
			val: o.val,
		})
		.collect();
	table.push(COption {
		name: ptr::null(),
		has_arg: 0,
		flag: ptr::null_mut(),
		val: 0,
	});
	let optstring = CString::new(optstring).unwrap();
	let argc = c_int::try_from(argv.len()).unwrap();
	let mut ind = c_int::try_from(longind).unwrap();
	let mut steps = Vec::new();
	let mut seen = 0usize;

	// SAFETY: GETOPT serializes the getopt globals and the stderr swap.
	// argv pointers, names and optstring outlive the run; getopt only
	// permutes the pointer array, never writes the strings. optarg points
	// into one of those strings and is copied right away. the memstream
	// buffer is malloc'd, valid for size bytes after fclose
	unsafe {
		let (mut buf, mut size) = (ptr::null_mut(), 0usize);
		let mem = open_memstream(&mut buf, &mut size);
		assert!(!mem.is_null());
		let real = stderr;
		fflush(real);
		stderr = mem;
		// the internal optopt survives the reinit: an unrecognized
		// long option zeroes it, like a fresh process
		opterr = 0;
		optind = 0;
		let reset = [
			c"x".as_ptr().cast_mut(),
			c"--\x01".as_ptr().cast_mut(),
		];
		let mut unused = 0;
		getopt_long(
			2,
			reset.as_ptr(),
			c"".as_ptr(),
			table.as_ptr(),
			&mut unused,
		);
		let zeroed = optopt;
		assert_eq!(zeroed, 0);
		opterr = c_int::from(print_errors);
		for pass in 0..passes {
			optind = if pass == 0 { 0 } else { 1 };
			loop {
				let ret = getopt_long(
					argc,
					ptrs.as_ptr(),
					optstring.as_ptr(),
					table.as_ptr(),
					&mut ind,
				);
				fflush(mem);
				// the bytes written by this call
				let all = std::slice::from_raw_parts(
					buf.cast::<u8>(),
					size,
				);
				let text = &all[seen..];
				seen = size;
				let arg = (!optarg.is_null()).then(|| {
					CStr::from_ptr(optarg)
						.to_bytes()
						.to_vec()
				});
				steps.push(GetoptStep {
					ret,
					optind: usize::try_from(optind)
						.unwrap(),
					optopt,
					optarg: arg,
					longind: usize::try_from(ind).unwrap(),
					stderr: String::from_utf8_lossy(text)
						.into_owned(),
				});
				if ret == -1 {
					break;
				}
			}
		}
		stderr = real;
		fclose(mem);
		c_free(buf.cast());
		let argv = ptrs[..argv.len()]
			.iter()
			.map(|&p| CStr::from_ptr(p).to_bytes().to_vec())
			.collect();
		GetoptRun { steps, argv }
	}
}
