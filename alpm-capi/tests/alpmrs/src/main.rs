// read-path probe over the alpm.rs consumer's raw bindings (alpm-sys).
// identical output whether linked against puck's libalpm.so.16 or the
// real one proves the C ABI. args: <root> <dbpath>
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
#[allow(unused_imports)]
use std::os::raw::c_long;

use alpm_sys::*;

fn s(p: *const c_char) -> String {
	if p.is_null() {
		"None".into()
	} else {
		unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
	}
}

fn pkgs(cache: *mut alpm_list_t) -> Vec<(*mut alpm_pkg_t, String)> {
	let mut out = Vec::new();
	let mut node = cache;
	while !node.is_null() {
		let p = unsafe { (*node).data } as *mut alpm_pkg_t;
		let name = s(unsafe { alpm_pkg_get_name(p) });
		out.push((p, name));
		node = unsafe { alpm_list_next(node) };
	}
	out.sort_by(|a, b| a.1.cmp(&b.1));
	out
}

fn dump(label: &str, cache: *mut alpm_list_t) {
	for (p, name) in pkgs(cache) {
		let ver = s(unsafe { alpm_pkg_get_version(p) });
		let desc = s(unsafe { alpm_pkg_get_desc(p) });
		let isize = unsafe { alpm_pkg_get_isize(p) };
		let reason = unsafe { alpm_pkg_get_reason(p) } as c_int;
		println!("  {label} {name}|{ver}|{desc}|{isize}|{reason}");
	}
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let root = CString::new(args[1].clone()).unwrap();
	let dbpath = CString::new(args[2].clone()).unwrap();

	let mut err: alpm_errno_t = alpm_errno_t::ALPM_ERR_OK;
	let h = unsafe { alpm_initialize(root.as_ptr(), dbpath.as_ptr(), &mut err) };
	assert!(!h.is_null(), "alpm_initialize failed: {err:?}");

	println!("root {}", s(unsafe { alpm_option_get_root(h) }));
	println!("dbpath {}", s(unsafe { alpm_option_get_dbpath(h) }));

	let local = unsafe { alpm_get_localdb(h) };
	println!("localdb {}", s(unsafe { alpm_db_get_name(local) }));
	dump("local", unsafe { alpm_db_get_pkgcache(local) });

	let name = CString::new("testrepo").unwrap();
	let sync = unsafe { alpm_register_syncdb(h, name.as_ptr(), 0) };
	println!("syncdb {}", s(unsafe { alpm_db_get_name(sync) }));
	dump("sync", unsafe { alpm_db_get_pkgcache(sync) });

	for (a, b) in [("1.0", "1.0"), ("1.0", "2.0"), ("2.0-1", "2.0-2"),
			("1:1.0", "2.0")] {
		let ca = CString::new(a).unwrap();
		let cb = CString::new(b).unwrap();
		let r = unsafe { alpm_pkg_vercmp(ca.as_ptr(), cb.as_ptr()) };
		println!("vercmp {a} {b} {r}");
	}

	unsafe { alpm_release(h) };
}
