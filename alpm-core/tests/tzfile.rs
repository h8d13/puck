// unit tests for alpm_core::tzfile: POSIX rule strings and a TZif file
// written here, TZDIR pointing into the test's directory
use std::fs;
use std::path::PathBuf;

use alpm_core::tzfile::{Local, Zone};

fn dir(name: &str) -> PathBuf {
	let d = std::env::temp_dir()
		.join(format!("tzfile-{name}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&d);
	fs::create_dir_all(&d).unwrap();
	d
}

fn zone(tz: Option<&str>, tzdir: &PathBuf) -> Zone {
	let tzdir = tzdir.display().to_string();
	Zone::from_env(&|name: &str| match name {
		"TZ" => tz.map(|t| t.as_bytes().to_vec()),
		"TZDIR" => Some(tzdir.as_bytes().to_vec()),
		_ => None,
	})
}

fn local(isdst: bool, zone: &str, gmtoff: i64) -> Option<Local> {
	Some(Local {
		isdst,
		zone: zone.as_bytes().to_vec(),
		gmtoff,
		leap_correct: 0,
		leap_hit: 0,
	})
}

// 2026-03-08 and 2026-11-01, 00:00 UTC
const MAR8: i64 = 1_772_928_000;
const NOV1: i64 = 1_793_491_200;

#[test]
fn posix_rules() {
	let d = dir("posix");
	let z = zone(Some("EST5EDT,M3.2.0,M11.1.0"), &d);
	// DST from 2:00 EST (07:00 UTC) to 2:00 EDT (06:00 UTC)
	assert_eq!(z.local(MAR8 + 7 * 3600 - 1), local(false, "EST", -18000));
	assert_eq!(z.local(MAR8 + 7 * 3600), local(true, "EDT", -14400));
	assert_eq!(z.local(NOV1 + 6 * 3600 - 1), local(true, "EDT", -14400));
	assert_eq!(z.local(NOV1 + 6 * 3600), local(false, "EST", -18000));
	// southern: DST across the new year
	let s = "<+1345>-13:45<+1245>-12:45,M9.5.0/2:45,M4.1.0/3:45";
	assert_eq!(
		zone(Some(s), &d).local(1_767_225_600),
		local(true, "+1245", 45900)
	);
	// glibc computes rules of years before 1971 from 1970-01-01: no
	// DST in summer 1960
	let z = zone(Some("EST5EDT,M3.2.0,M11.1.0"), &d);
	assert_eq!(z.local(-300_000_000), local(false, "EST", -18000));
	fs::remove_dir_all(d).unwrap();
}

#[test]
fn odd_strings() {
	let d = dir("odd");
	let z = |tz| zone(Some(tz), &d).local(0).unwrap();
	// no file: a name of 3+ letters stays even without an offset
	assert_eq!(z("garbage"), local(false, "garbage", 0).unwrap());
	assert_eq!(z("ab"), local(false, "", 0).unwrap());
	// empty is "Universal", parsed as a name when no file has it
	assert_eq!(z(""), local(false, "Universal", 0).unwrap());
	// ':' alone: UTC
	assert_eq!(z(":"), local(false, "UTC", 0).unwrap());
	assert_eq!(z("<+0330>-3:30"), local(false, "+0330", 12600).unwrap());
	// hours capped at 24, minutes at 59
	assert_eq!(z("AAA99:99").gmtoff, -(24 * 3600 + 59 * 60));
	// a DST name without rules and no posixrules: the US rules
	let z = zone(Some("AAA3BBB"), &d);
	assert_eq!(z.local(MAR8 + 5 * 3600), local(true, "BBB", -7200));
	fs::remove_dir_all(d).unwrap();
}

// a version 2 TZif: the 32-bit block (empty), the 64-bit data, a footer
fn tzif(
	transitions: &[(i64, u8)],
	types: &[(i32, u8, u8)],
	names: &[u8],
	footer: &str,
) -> Vec<u8> {
	let head = |cnt: [u32; 6]| {
		let mut h = b"TZif2".to_vec();
		h.extend([0; 15]);
		for c in cnt {
			h.extend(c.to_be_bytes());
		}
		h
	};
	let mut v = head([0, 0, 0, 0, 1, 1]);
	v.extend([0, 0, 0, 0, 0, 0, 0]);
	let cnt = [
		0,
		0,
		0,
		transitions.len() as u32,
		types.len() as u32,
		names.len() as u32,
	];
	v.extend(head(cnt));
	for (t, _) in transitions {
		v.extend(t.to_be_bytes());
	}
	v.extend(transitions.iter().map(|(_, i)| i));
	for &(off, isdst, idx) in types {
		v.extend(off.to_be_bytes());
		v.extend([isdst, idx]);
	}
	v.extend(names);
	v.extend(format!("\n{footer}\n").bytes());
	v
}

#[test]
fn file() {
	let d = dir("file");
	let data = tzif(
		&[(0, 1), (1000, 2)],
		&[(3600, 0, 0), (7200, 1, 4), (3600, 0, 0)],
		b"AAA\0BBB\0",
		"CCC-3DDD,M3.5.0,M10.5.0/3",
	);
	fs::create_dir_all(d.join("Test")).unwrap();
	fs::write(d.join("Test/Zone"), &data).unwrap();
	for tz in ["Test/Zone", ":Test/Zone"] {
		let z = zone(Some(tz), &d);
		assert_eq!(z.local(-1), local(false, "AAA", 3600));
		assert_eq!(z.local(0), local(true, "BBB", 7200));
		assert_eq!(z.local(999), local(true, "BBB", 7200));
		// after the last transition the footer, its own names
		assert_eq!(z.local(1000), local(false, "CCC", 10800));
		assert_eq!(
			z.local(MAR8 + 120 * 86400),
			local(true, "DDD", 14400)
		);
	}
	let abs = d.join("Test/Zone").display().to_string();
	assert_eq!(zone(Some(&abs), &d).local(0), local(true, "BBB", 7200));
	// a bad type index is not a TZif: parsed as a POSIX name then
	let bad = tzif(&[(0, 5)], &[(3600, 0, 0)], b"AAA\0", "AAA-1");
	fs::write(d.join("Bad"), bad).unwrap();
	assert_eq!(zone(Some("Bad"), &d).local(0), local(false, "Bad", 0));
	// posixrules for a DST name without rules: its transitions with the
	// user's names, moved by the C's (sign-swapped) correction
	let rules = tzif(
		&[(MAR8 + 7 * 3600, 1), (NOV1 + 6 * 3600, 0)],
		&[(-18000, 0, 0), (-14400, 1, 4)],
		b"EST\0EDT\0",
		"EST5EDT,M3.2.0,M11.1.0",
	);
	fs::write(d.join("posixrules"), rules).unwrap();
	let z = zone(Some("AAA3BBB"), &d);
	assert_eq!(z.local(MAR8 + 9 * 3600 - 1), local(false, "AAA", -10800));
	assert_eq!(z.local(MAR8 + 9 * 3600), local(true, "BBB", -7200));
	assert_eq!(z.local(NOV1 + 4 * 3600 - 1), local(true, "BBB", -7200));
	// from the last transition on posixrules' footer, its names and
	// offsets: still EDT until 06:00 UTC
	assert_eq!(z.local(NOV1 + 4 * 3600), local(true, "EDT", -14400));
	assert_eq!(z.local(NOV1 + 86400 * 400).unwrap().zone, b"EST");
	fs::remove_dir_all(d).unwrap();
}
