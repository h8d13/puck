// C side of src/util/testpkg.c. its main() is not linkable: main's body
// after alpm_initialize runs on a CSigHandle (the fixture root, dbpath
// and gpgdir in place of config.h's), the load at a chosen siglevel.
// output_cb's lines come from the handle's log recorder (its errors
// and warnings, like output_cb), the failure texts from the C alpm_strerror
use std::ffi::c_int;

use alpm_core::error::Errno;

use crate::{CSigHandle, c_strerror};

// stdout of testpkg after alpm_initialize and its exit status
pub fn c_testpkg(
	h: &CSigHandle,
	path: &[u8],
	siglevel: c_int,
) -> (i32, Vec<u8>) {
	let call = h.pkg_load(path, true, siglevel);
	let mut out = Vec::new();
	for (level, msg) in &call.events.logs {
		// output_cb prints errors and warnings only
		let prefix: &[u8] = match level {
			1 => b"error: ",
			2 => b"warning: ",
			_ => continue,
		};
		out.extend_from_slice(prefix);
		out.extend_from_slice(msg);
	}
	if call.rc == 0 && call.value.is_some() {
		out.extend_from_slice(b"Package is valid.\n");
		return (0, out);
	}
	let e = call.errno;
	let text: Vec<u8> = if e == Errno::PkgNotFound as c_int {
		b"Cannot find the given file.\n".to_vec()
	} else if e == Errno::PkgOpen as c_int {
		b"Cannot open the given file.\n".to_vec()
	} else if e == Errno::Libarchive as c_int
		|| e == Errno::PkgInvalid as c_int
	{
		b"Package is invalid.\n".to_vec()
	} else {
		[&b"libalpm error: "[..], &c_strerror(e), b"\n"].concat()
	};
	out.extend_from_slice(&text);
	(1, out)
}
