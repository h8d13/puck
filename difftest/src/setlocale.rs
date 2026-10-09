// C side of alpm_core::setlocale, strftime and tzfile: glibc's
// setlocale(LC_ALL, ""), nl_langinfo, toupper/tolower, localtime_r and
// strftime. the locale is process wide: the locale-probe binary runs
// one environment per process
use std::ffi::{CStr, c_char, c_int};
use std::path::Path;
use std::process::Command;

use alpm_core::strftime::Tm as PortTm;

use crate::cli_util::setlocale;
use crate::handle_opts::localtime;
use crate::pkg_show::strftime;

const LC_ALL: c_int = 6;

unsafe extern "C" {
	fn nl_langinfo(item: c_int) -> *const c_char;
	fn toupper(c: c_int) -> c_int;
	fn tolower(c: c_int) -> c_int;
}

// setlocale(LC_ALL, ""): whether glibc installed the environment's
// locale
pub fn c_setlocale_env() -> bool {
	// SAFETY: "" is a valid C string, the result is only tested
	unsafe { !setlocale(LC_ALL, c"".as_ptr()).is_null() }
}

// nl_langinfo(_NL_ITEM(category, index))
pub fn c_langinfo(category: usize, index: usize) -> Vec<u8> {
	let item = ((category << 16) | index) as c_int;
	// SAFETY: nl_langinfo returns a string valid until the next
	// setlocale, copied at once
	unsafe { CStr::from_ptr(nl_langinfo(item)).to_bytes().to_vec() }
}

pub fn c_toupper(c: u8) -> u8 {
	// SAFETY: c is an unsigned char value
	unsafe { toupper(c_int::from(c)) as u8 }
}

pub fn c_tolower(c: u8) -> u8 {
	// SAFETY: c is an unsigned char value
	unsafe { tolower(c_int::from(c)) as u8 }
}

// localtime(&t) as the port's Tm, None where it fails. localtime, not
// localtime_r, like pacman: it rereads TZ, which matters for a DST name
// without rules. its static buffer: callers keep to one
// thread (the probe binaries)
pub fn c_localtime_tm(t: i64) -> Option<PortTm> {
	// SAFETY: localtime's result is copied before the next call, its
	// tm_zone points into glibc's string pool
	unsafe {
		let p = localtime(&t);
		if p.is_null() {
			return None;
		}
		let tm = &*p;
		let zone = match tm.tm_zone.is_null() {
			true => Vec::new(),
			false => CStr::from_ptr(tm.tm_zone).to_bytes().to_vec(),
		};
		Some(PortTm {
			sec: tm.tm_sec,
			min: tm.tm_min,
			hour: tm.tm_hour,
			mday: tm.tm_mday,
			mon: tm.tm_mon,
			year: tm.tm_year,
			wday: tm.tm_wday,
			yday: tm.tm_yday,
			isdst: tm.tm_isdst,
			gmtoff: tm.tm_gmtoff,
			zone,
			t,
		})
	}
}

// strftime(buf, max, fmt, localtime(&t)) into a zeroed buffer like
// pacman's: the return value and the buffer up to its first nul. one
// thread, like c_localtime_tm
pub fn c_strftime_local(
	t: i64,
	max: usize,
	fmt: &[u8],
) -> Option<(usize, Vec<u8>)> {
	let fmt = crate::cstr(fmt);
	let mut buf = vec![0 as c_char; max.max(1)];
	// SAFETY: tm from localtime, buf holds max bytes and strftime
	// writes at most max
	unsafe {
		let tm = localtime(&t);
		if tm.is_null() {
			return None;
		}
		let n = strftime(buf.as_mut_ptr(), max, fmt.as_ptr(), tm);
		let s = CStr::from_ptr(buf.as_ptr()).to_bytes().to_vec();
		Some((n, s))
	}
}

// the first second of every offset change from 1890 to 2100, found by
// bisection on localtime's tm_gmtoff
pub fn zone_transitions() -> Vec<i64> {
	const DAY: i64 = 86_400;
	let gmtoff = |t| c_localtime_tm(t).map(|tm| tm.gmtoff);
	let mut out = Vec::new();
	let (mut t, end) = (-2_524_521_600, 4_102_444_800);
	let mut prev = gmtoff(t);
	while t < end {
		let next = t + DAY;
		let off = gmtoff(next);
		if off != prev {
			let (mut lo, mut hi) = (t, next);
			while hi - lo > 1 {
				let mid = lo + (hi - lo) / 2;
				match gmtoff(mid) == off {
					true => hi = mid,
					false => lo = mid,
				}
			}
			out.push(hi);
			prev = off;
		}
		t = next;
	}
	out
}

// localedef -i input -f charmap dir/name: a locale for LOCPATH=dir, no
// root needed. localedef exits 1 on warnings with the locale written
pub fn localedef(dir: &Path, name: &str, input: &str, charmap: &str) {
	let mut cmd = Command::new("localedef");
	cmd.args(["-i", input, "-f", charmap]).arg(dir.join(name));
	let o = crate::output_capped(&mut cmd, 300);
	let ok = dir.join(name).join("LC_TIME").is_file();
	let err = String::from_utf8_lossy(&o.stderr);
	assert!(ok, "localedef {name}: {err}");
}
