// run by difftest/tests/handle_opts.rs, one process per TZ (glibc reads
// it once there): the port's local time against localtime(3), the call
// log.c, util.c (PACMAN_DEBUG) and package.c make. compared at every
// offset change from 1890 to 2100 (found by bisection on the C) and
// the seconds around it, then at random seconds: the offset, the log
// leader, the syslog header, the debug stamp and the %c date. prints
// each difference and "compared <n> transitions <m>", exits 1 on any
use std::ffi::CStr;

use alpm_core::log::{LogTime, leader, local_offset, syslog_message};
use difftest::{Rng, c_localtime};
use pacman_cli::package::format_date;
use pacman_cli::util::debug_stamp;

const DAY: i64 = 86_400;
// 1890-01-01 and 2100-01-01
const SCAN: (i64, i64) = (-2_524_521_600, 4_102_444_800);

fn gmtoff(t: i64) -> i64 {
	c_localtime(t, c"")
		.expect("localtime in the scanned years")
		.1
}

// the first second of [lo, hi] with hi's offset, lo's differing
fn bisect(mut lo: i64, mut hi: i64) -> i64 {
	let want = gmtoff(hi);
	while hi - lo > 1 {
		let mid = lo + (hi - lo) / 2;
		match gmtoff(mid) == want {
			true => hi = mid,
			false => lo = mid,
		}
	}
	hi
}

fn transitions() -> Vec<i64> {
	let mut out = Vec::new();
	let mut t = SCAN.0;
	let mut prev = gmtoff(t);
	while t < SCAN.1 {
		let next = t + DAY;
		let off = gmtoff(next);
		if off != prev {
			out.push(bisect(t, next));
			prev = off;
		}
		t = next;
	}
	out
}

fn c_fmt(t: i64, fmt: &CStr) -> Option<Vec<u8>> {
	c_localtime(t, fmt).map(|(s, _)| s)
}

// what differs at t, one line each
fn compare(t: i64) -> Vec<String> {
	let mut diffs = Vec::new();
	let mut check = |what: &str, c: Option<Vec<u8>>, r: Option<Vec<u8>>| {
		if c != r {
			let show = |s: &Option<Vec<u8>>| {
				s.as_deref().map(|b| {
					String::from_utf8_lossy(b).into_owned()
				})
			};
			diffs.push(format!(
				"DIFF {what} t={t} C={:?} rust={:?}",
				show(&c),
				show(&r)
			));
		}
	};
	let off = local_offset(t);
	let c_off = c_localtime(t, c"").map(|(_, o)| o);
	let show = |o: Option<i64>| o.map(|o| o.to_string().into_bytes());
	check("offset", show(c_off), show(off.map(i64::from)));
	let lt = off.map(|utcoff| LogTime { secs: t, utcoff });
	let c = c_fmt(t, c"[%FT%T%z] [").map(|s| [&s[..], b"ALPM] "].concat());
	check("leader", c, lt.map(|lt| leader(lt, b"ALPM")));
	let c = c_fmt(t, c"%h %e %T ")
		.map(|s| [b"<12>", &s[..], b"p: m"].concat());
	check("syslog", c, lt.map(|lt| syslog_message(lt, b"p", b"m")));
	check("debug", c_fmt(t, c"[%H:%M:%S] "), Some(debug_stamp(t)));
	check("date", c_fmt(t, c"%c"), format_date(t));
	diffs
}

fn main() {
	let mut instants = Vec::new();
	let edges = transitions();
	for &t in &edges {
		instants.extend([t - 1, t, t + 1]);
	}
	let mut rng = Rng::new(0x7a);
	for _ in 0..5000 {
		// years 881 to 3058
		instants.push((rng.next_u64() % (1 << 36)) as i64 - (1 << 35));
	}
	let mut failed = false;
	for &t in &instants {
		for d in compare(t) {
			println!("{d}");
			failed = true;
		}
	}
	println!("compared {} transitions {}", instants.len(), edges.len());
	std::process::exit(i32::from(failed));
}
