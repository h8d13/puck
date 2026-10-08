// C side of src/pacman/util.c, from the frontend objects (see build.rs)
//
// the displays print to the C `stdout` and read the global `config`,
// both process wide: every such call holds FRONTEND and points `stdout`
// at an open_memstream for its duration. only C stdio is redirected, the
// test harness writing to fd 1 from other threads is not captured, which
// a dup2 on fd 1 would do. LC_ALL is C.UTF-8, set once before any call.
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::ptr;
use std::sync::{Mutex, Once};

use crate::conf::{ColStrC, ConfigC};
use crate::{CList, c_free, cstr, fclose, opt_ptr, take};
use crate::{fflush, open_memstream, stdout};

use pacman_cli::util::{ColStr, SigResult, SigStatus, SigValidity};

// glibc locale.h
const LC_ALL: c_int = 6;

#[repr(C)]
struct PgpKey {
	data: *mut c_void,
	fingerprint: *const c_char,
	uid: *const c_char,
	name: *const c_char,
	email: *const c_char,
	created: i64,
	expires: i64,
	length: c_uint,
	revoked: c_uint,
}

#[repr(C)]
struct SigResultC {
	key: PgpKey,
	status: c_int,
	validity: c_int,
}

#[repr(C)]
struct SigList {
	count: usize,
	results: *mut SigResultC,
}

unsafe extern "C" {
	pub(crate) static mut config: *mut ConfigC;
	pub(crate) fn config_new() -> *mut ConfigC;
	pub(crate) fn setlocale(
		category: c_int,
		locale: *const c_char,
	) -> *mut c_char;
	// wchar_t is a 32-bit int, passed and stored as u32 here
	fn wcwidth(c: u32) -> c_int;
	fn mbstowcs(dst: *mut u32, src: *const c_char, n: usize) -> usize;

	fn indentprint(s: *const c_char, indent: u16, cols: u16);
	fn getcols() -> u16;
	fn strreplace(
		s: *const c_char,
		needle: *const c_char,
		replace: *const c_char,
	) -> *mut c_char;
	fn string_display(title: *const c_char, s: *const c_char, cols: u16);
	fn humanize_size(
		bytes: i64,
		target_unit: c_char,
		precision: c_int,
		label: *mut *const c_char,
	) -> f64;
	fn list_display(title: *const c_char, list: *const CList, maxcols: u16);
	fn list_display_linebreak(
		title: *const c_char,
		list: *const CList,
		maxcols: u16,
	);
	fn signature_display(
		title: *const c_char,
		siglist: *mut SigList,
		maxcols: u16,
	);
	fn arg_to_string(argc: c_int, argv: *mut *mut c_char) -> *mut c_char;
	fn console_cursor_move_up(lines: c_uint);
	fn console_cursor_move_down(lines: c_uint);
	fn console_erase_line();
}

pub(crate) static FRONTEND: Mutex<()> = Mutex::new(());

pub(crate) fn init() {
	static ONCE: Once = Once::new();
	ONCE.call_once(|| {
		// SAFETY: runs once, before any other C call of this module,
		// config_new returns a calloc'd config_t or NULL
		unsafe {
			let l = setlocale(LC_ALL, c"C.UTF-8".as_ptr());
			assert!(!l.is_null(), "C.UTF-8 locale missing");
			let c = config_new();
			assert!(!c.is_null());
			// guards the Config mirror: config_new sets these
			let colon = CStr::from_ptr((*c).colstr.colon);
			assert_eq!(colon, c":: ", "config_t layout drifted");
			assert_eq!(CStr::from_ptr((*c).colstr.nocolor), c"");
			config = c;
		}
	});
}

// runs f with config->colstr from colstr and C stdout captured
pub(crate) fn capture(colstr: &ColStr, f: impl FnOnce()) -> Vec<u8> {
	init();
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	let c = [
		colstr.colon,
		colstr.title,
		colstr.repo,
		colstr.version,
		colstr.groups,
		colstr.meta,
		colstr.warn,
		colstr.err,
		colstr.faint,
		colstr.nocolor,
	]
	.map(cstr);
	let colstr_c = |c: &[CString; 10]| ColStrC {
		colon: c[0].as_ptr(),
		title: c[1].as_ptr(),
		repo: c[2].as_ptr(),
		version: c[3].as_ptr(),
		groups: c[4].as_ptr(),
		meta: c[5].as_ptr(),
		warn: c[6].as_ptr(),
		err: c[7].as_ptr(),
		faint: c[8].as_ptr(),
		nocolor: c[9].as_ptr(),
	};
	let (mut buf, mut size) = (std::ptr::null_mut(), 0usize);
	// SAFETY: FRONTEND serializes every access to config and stdout.
	// config is valid after init; the colstr strings outlive the call and
	// are swapped back for static ones before they drop. the memstream
	// replaces stdout only while f runs, its buffer is malloc'd, valid
	// for size bytes after fclose
	unsafe {
		(*config).colstr = colstr_c(&c);
		let mem = open_memstream(&mut buf, &mut size);
		assert!(!mem.is_null());
		let real = stdout;
		fflush(real);
		stdout = mem;
		f();
		fflush(mem);
		stdout = real;
		fclose(mem);
		let empty = c"".as_ptr();
		(*config).colstr = ColStrC {
			colon: c":: ".as_ptr(),
			title: empty,
			repo: empty,
			version: empty,
			groups: empty,
			meta: empty,
			warn: empty,
			err: empty,
			faint: empty,
			nocolor: empty,
		};
		let out = std::slice::from_raw_parts(buf.cast::<u8>(), size)
			.to_vec();
		c_free(buf.cast());
		out
	}
}

// string_length copies s minus colour sequences into malloc(strlen(s))
// and nul terminates it: one byte out of bounds unless a sequence was
// dropped. true where the C may be fed s
pub fn string_length_in_bounds(s: &[u8]) -> bool {
	if !s.contains(&0x1b) {
		return true;
	}
	(0..s.len()).any(|i| {
		let digit = |j: usize| s.get(j).is_some_and(u8::is_ascii_digit);
		if s[i] != 0x1b || s.get(i + 1) != Some(&b'[') || !digit(i + 2)
		{
			return false;
		}
		let mut t = i + 3;
		while digit(t) || s.get(t) == Some(&b';') {
			t += 1;
		}
		s.get(t) == Some(&b'm')
	})
}

fn assert_in_bounds(s: &[u8]) {
	assert!(
		string_length_in_bounds(s),
		"unsafe input for C string_length: {s:?}"
	);
}

// alpm_list_t, alpm_list.h
// Rust-owned alpm_list_t over borrowed C strings, the C only walks
// ->next. the nodes must stay alive while the C runs, moving the Vec
// keeps its buffer in place
fn c_list(items: &[CString]) -> Vec<CList> {
	let mut nodes: Vec<CList> = items
		.iter()
		.map(|s| CList {
			data: s.as_ptr().cast_mut().cast(),
			prev: ptr::null_mut(),
			next: ptr::null_mut(),
		})
		.collect();
	let base = nodes.as_mut_ptr();
	let n = nodes.len();
	for i in 0..n {
		// SAFETY: i < n nodes behind base, no reference into nodes is
		// live; head->prev is the tail in alpm_list
		unsafe {
			let node = base.add(i);
			(*node).prev = base.add((i + n - 1) % n);
			if i + 1 < n {
				(*node).next = base.add(i + 1);
			}
		}
	}
	nodes
}

fn head(nodes: &[CList]) -> *const CList {
	if nodes.is_empty() {
		ptr::null()
	} else {
		nodes.as_ptr()
	}
}

pub fn c_wcwidth(c: u32) -> i32 {
	init();
	// SAFETY: plain value, locale set by init
	unsafe { wcwidth(c) }
}

// true where glibc and the port (unicode-width) give every character of
// s the same wcwidth. the lossy decode holds every char mbstowcs can
// return; its U+FFFD and the 5/6 byte forms (-1) agree
pub fn widths_agree(s: &[u8]) -> bool {
	String::from_utf8_lossy(s).chars().all(|c| {
		c_wcwidth(c as u32) == pacman_cli::util::wcwidth(c as u32)
	})
}

// decoded prefix and whether all of s decoded
pub fn c_mbstowcs(s: &[u8]) -> (Vec<u32>, bool) {
	init();
	let src = cstr(s);
	let mut dst = vec![0u32; s.len() + 1];
	// SAFETY: dst holds strlen + 1 wide chars, enough for any result
	let n = unsafe { mbstowcs(dst.as_mut_ptr(), src.as_ptr(), dst.len()) };
	if n == usize::MAX {
		// glibc wrote the prefix before the invalid sequence
		let k = dst.iter().position(|&c| c == 0).unwrap();
		dst.truncate(k);
		return (dst, false);
	}
	dst.truncate(n);
	(dst, true)
}

pub fn c_indentprint(s: &[u8], indent: u16, cols: u16) -> Vec<u8> {
	let s = cstr(s);
	// SAFETY: valid C string
	capture(&ColStr::default(), || unsafe {
		indentprint(s.as_ptr(), indent, cols)
	})
}

// C precondition: needle not empty, the C loops forever on ""
pub fn c_strreplace(
	s: Option<&[u8]>,
	needle: &[u8],
	replace: Option<&[u8]>,
) -> Option<Vec<u8>> {
	assert!(!needle.is_empty(), "C strreplace hangs on an empty needle");
	let (s, n) = (s.map(cstr), cstr(needle));
	let r = replace.map(cstr);
	// SAFETY: needle valid, s and replace valid or NULL, result is
	// malloc'd or NULL
	let p = unsafe { strreplace(opt_ptr(&s), n.as_ptr(), opt_ptr(&r)) };
	take(p)
}

pub fn c_string_display(
	title: Option<&[u8]>,
	s: Option<&[u8]>,
	cols: u16,
	colstr: &ColStr,
) -> Vec<u8> {
	if let Some(t) = title {
		assert_in_bounds(t);
	}
	let (t, s) = (title.map(cstr), s.map(cstr));
	// SAFETY: title and s valid or NULL
	capture(colstr, || unsafe {
		string_display(opt_ptr(&t), opt_ptr(&s), cols)
	})
}

pub fn c_list_display<S: AsRef<[u8]>>(
	title: Option<&[u8]>,
	list: &[S],
	maxcols: u16,
	colstr: &ColStr,
) -> Vec<u8> {
	title.into_iter().for_each(assert_in_bounds);
	list.iter().for_each(|s| assert_in_bounds(s.as_ref()));
	let t = title.map(cstr);
	let items: Vec<CString> =
		list.iter().map(|s| cstr(s.as_ref())).collect();
	let nodes = c_list(&items);
	// SAFETY: title valid or NULL, nodes a list of valid C strings, all
	// alive for the call
	capture(colstr, || unsafe {
		list_display(opt_ptr(&t), head(&nodes), maxcols)
	})
}

pub fn c_list_display_linebreak<S: AsRef<[u8]>>(
	title: Option<&[u8]>,
	list: &[S],
	maxcols: u16,
	colstr: &ColStr,
) -> Vec<u8> {
	title.into_iter().for_each(assert_in_bounds);
	let t = title.map(cstr);
	let items: Vec<CString> =
		list.iter().map(|s| cstr(s.as_ref())).collect();
	let nodes = c_list(&items);
	// SAFETY: title valid or NULL, nodes a list of valid C strings, all
	// alive for the call
	capture(colstr, || unsafe {
		list_display_linebreak(opt_ptr(&t), head(&nodes), maxcols)
	})
}

fn status_c(s: SigStatus) -> c_int {
	match s {
		SigStatus::Valid => 0,
		SigStatus::KeyExpired => 1,
		SigStatus::SigExpired => 2,
		SigStatus::KeyUnknown => 3,
		SigStatus::KeyDisabled => 4,
		SigStatus::Invalid => 5,
	}
}

fn validity_c(v: SigValidity) -> c_int {
	match v {
		SigValidity::Full => 0,
		SigValidity::Marginal => 1,
		SigValidity::Never => 2,
		SigValidity::Unknown => 3,
	}
}

pub fn c_signature_display(
	title: Option<&[u8]>,
	sigs: &[SigResult],
	maxcols: u16,
	colstr: &ColStr,
) -> Vec<u8> {
	title.into_iter().for_each(assert_in_bounds);
	let t = title.map(cstr);
	let uids: Vec<Option<CString>> =
		sigs.iter().map(|r| r.uid.as_deref().map(cstr)).collect();
	let fprs: Vec<CString> =
		sigs.iter().map(|r| cstr(&r.fingerprint)).collect();
	let mut results: Vec<SigResultC> = sigs
		.iter()
		.zip(uids.iter().zip(&fprs))
		.map(|(r, (uid, fpr))| SigResultC {
			key: PgpKey {
				data: std::ptr::null_mut(),
				fingerprint: fpr.as_ptr(),
				uid: opt_ptr(uid),
				name: std::ptr::null(),
				email: std::ptr::null(),
				created: 0,
				expires: 0,
				length: 0,
				revoked: 0,
			},
			status: status_c(r.status),
			validity: validity_c(r.validity),
		})
		.collect();
	let mut list = SigList {
		count: results.len(),
		results: results.as_mut_ptr(),
	};
	// SAFETY: title valid or NULL, list points at count results whose
	// strings outlive the call, fingerprint never NULL
	capture(colstr, || unsafe {
		signature_display(opt_ptr(&t), &mut list, maxcols)
	})
}

pub fn c_humanize_size(
	bytes: i64,
	target_unit: u8,
	precision: i32,
) -> (f64, Vec<u8>) {
	let mut label = std::ptr::null();
	// SAFETY: label is a valid out pointer, set to a static string
	let v = unsafe {
		humanize_size(
			bytes,
			target_unit as c_char,
			precision,
			&mut label,
		)
	};
	// SAFETY: label points at one of the static unit labels
	(v, unsafe { CStr::from_ptr(label) }.to_bytes().to_vec())
}

pub fn c_arg_to_string<S: AsRef<[u8]>>(args: &[S]) -> Option<Vec<u8>> {
	let args: Vec<CString> =
		args.iter().map(|a| cstr(a.as_ref())).collect();
	let mut argv: Vec<*mut c_char> =
		args.iter().map(|a| a.as_ptr().cast_mut()).collect();
	// SAFETY: argv holds argc valid C strings, the C only reads them;
	// result is malloc'd or NULL
	let p = unsafe {
		arg_to_string(argv.len() as c_int, argv.as_mut_ptr())
	};
	take(p)
}

// C precondition: lines <= i32::MAX, printed with %d
pub fn c_console_cursor_move_up(lines: u32) -> Vec<u8> {
	assert!(lines <= i32::MAX as u32, "%d of {lines}");
	// SAFETY: prints only
	capture(&ColStr::default(), || unsafe {
		console_cursor_move_up(lines)
	})
}

// C precondition: lines <= i32::MAX, printed with %d
pub fn c_console_cursor_move_down(lines: u32) -> Vec<u8> {
	assert!(lines <= i32::MAX as u32, "%d of {lines}");
	// SAFETY: prints only
	capture(&ColStr::default(), || unsafe {
		console_cursor_move_down(lines)
	})
}

pub fn c_console_erase_line() -> Vec<u8> {
	// SAFETY: prints only
	capture(&ColStr::default(), || unsafe { console_erase_line() })
}

// getcols with COLUMNS set to columns (None: unset), its cache reset,
// next to what f (the Rust side) returns under the same environment.
// COLUMNS is process wide: FRONTEND holds it for the call
pub fn getcols_both(
	columns: Option<&[u8]>,
	f: impl FnOnce() -> u16,
) -> (u16, u16) {
	use std::ffi::OsStr;
	use std::os::unix::ffi::OsStrExt;
	let _guard = FRONTEND.lock().unwrap_or_else(|e| e.into_inner());
	// SAFETY: FRONTEND serializes the env writers and readers of this
	// crate's frontend calls; getcols reads COLUMNS once, the cache is
	// reset first so it does
	unsafe {
		match columns {
			Some(v) => std::env::set_var(
				"COLUMNS",
				OsStr::from_bytes(v),
			),
			None => std::env::remove_var("COLUMNS"),
		}
		crate::pkg_show::columns_cache_reset();
		let c = getcols();
		(c, f())
	}
}
