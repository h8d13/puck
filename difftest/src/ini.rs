// C side of src/common/ini.c, from libcommon.a
use std::ffi::{CStr, c_char, c_int, c_void};

use crate::cstr;
use crate::util_common::errno;

type IniParserFn = unsafe extern "C" fn(
	file: *const c_char,
	line: c_int,
	section: *const c_char,
	key: *mut c_char,
	value: *mut c_char,
	data: *mut c_void,
) -> c_int;

unsafe extern "C" {
	fn parse_ini(
		file: *const c_char,
		cb: IniParserFn,
		data: *mut c_void,
	) -> c_int;
}

// one callback invocation, NULL pointers as None. errno only kept for
// the fopen failure call (line 0, all NULL), 0 otherwise
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IniCall {
	pub line: i32,
	pub section: Option<Vec<u8>>,
	pub key: Option<Vec<u8>>,
	pub value: Option<Vec<u8>>,
	pub errno: i32,
}

struct Recorder {
	file: Vec<u8>,
	calls: Vec<IniCall>,
	stop_at: Option<usize>,
}

fn opt_bytes(p: *const c_char) -> Option<Vec<u8>> {
	// SAFETY: parse_ini passes NULL or nul-terminated strings valid for
	// the duration of the callback
	(!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

// returns 100 + call index for the call at stop_at, else 0
unsafe extern "C" fn record(
	file: *const c_char,
	line: c_int,
	section: *const c_char,
	key: *mut c_char,
	value: *mut c_char,
	data: *mut c_void,
) -> c_int {
	let err = errno();
	// SAFETY: data is the &mut Recorder handed to parse_ini below
	let rec = unsafe { &mut *data.cast::<Recorder>() };
	let all_null = section.is_null() && key.is_null() && value.is_null();
	let call = IniCall {
		line,
		section: opt_bytes(section),
		key: opt_bytes(key),
		value: opt_bytes(value),
		errno: if line == 0 && all_null { err } else { 0 },
	};
	// file is passed through unchanged, a mismatch shows as a bogus call
	let file_ok = opt_bytes(file).as_deref() == Some(&rec.file[..]);
	let idx = rec.calls.len();
	rec.calls.push(call);
	if !file_ok {
		rec.calls.push(IniCall {
			line: -1,
			section: None,
			key: None,
			value: None,
			errno: 0,
		});
	}
	if rec.stop_at == Some(idx) {
		return 100 + idx as c_int;
	}
	0
}

// parse_ini on a file path, the callback returns non-zero at stop_at
pub fn c_parse_ini(path: &[u8], stop_at: Option<usize>) -> (i32, Vec<IniCall>) {
	let p = cstr(path);
	let mut rec = Recorder {
		file: path.to_vec(),
		calls: Vec::new(),
		stop_at,
	};
	// SAFETY: p is a valid C string, record matches ini_parser_fn and
	// rec outlives the call, the C does not keep data
	let rc =
		unsafe { parse_ini(p.as_ptr(), record, (&raw mut rec).cast()) };
	(rc, rec.calls)
}
