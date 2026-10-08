// unit tests for alpm_core::strftime, expected values from glibc 2.44
use alpm_core::setlocale::{Era, Locale};
use alpm_core::strftime::{Tm, strftime};

// 2026-08-10 15:17:10 UTC, a Monday, at +02:00 CEST
const T: i64 = 1_786_375_030;

fn tm() -> Tm {
	Tm::at(T, 7200, true, b"CEST").unwrap()
}

fn f(fmt: &str) -> String {
	let out = strftime(256, fmt.as_bytes(), &tm(), &Locale::c()).unwrap();
	String::from_utf8(out).unwrap()
}

#[test]
fn broken_down() {
	let t = tm();
	let fields = (t.year, t.mon, t.mday, t.hour, t.min, t.sec);
	assert_eq!(fields, (126, 7, 10, 17, 17, 10));
	assert_eq!((t.wday, t.yday), (1, 221));
	// leap day and the day before the epoch
	let t = Tm::at(951_782_400, 0, false, b"").unwrap();
	assert_eq!((t.year, t.mon, t.mday, t.yday), (100, 1, 29, 59));
	let t = Tm::at(-1, 0, false, b"").unwrap();
	assert_eq!((t.year, t.mon, t.mday, t.wday), (69, 11, 31, 3));
	assert_eq!((t.hour, t.min, t.sec), (23, 59, 59));
	assert_eq!(Tm::at(i64::MAX, 0, false, b""), None);
}

#[test]
fn c_locale() {
	assert_eq!(f("%c"), "Mon Aug 10 17:17:10 2026");
	assert_eq!(
		f("%x %X %r %R %T %D %F"),
		"08/10/26 17:17:10 05:17:10 PM 17:17 17:17:10 08/10/26 2026-08-10"
	);
	assert_eq!(
		f("%a %A %b %h %B %p %P"),
		"Mon Monday Aug Aug August PM pm"
	);
	assert_eq!(f("%Z %z %s"), "CEST +0200 1786375030");
	assert_eq!(
		f("%C %y %Y %G %g %V %U %W %u %w %j"),
		"20 26 2026 2026 26 33 32 32 1 1 222"
	);
	assert_eq!(
		f("%e %d %k %l %I %H %M %S %m"),
		"10 10 17  5 05 17 17 10 08"
	);
	assert_eq!(f("%n%t%%"), "\n\t%");
}

#[test]
fn flags_and_widths() {
	// glibc's add() pads every piece to the width, '-' included
	assert_eq!(f("%-5e|%_5e|%05e|%-e"), "   10|   10|00010|10");
	assert_eq!(
		f("%10z|%_z|%-z|%Oz"),
		"         +0000000200|+ 200|+200|+0200"
	);
	assert_eq!(
		f("%010a|%^a|%#a|%^B|%#Z"),
		"0000000Mon|MON|MON|AUGUST|cest"
	);
	assert_eq!(f("%^P|%#p|%^p|%^c"), "pm|pm|PM|MON AUG 10 17:17:10 2026");
	assert_eq!(
		f("%_10c|%30c|"),
		"Mon Aug 10 17:17:10 2026|      Mon Aug 10 17:17:10 2026|"
	);
	assert_eq!(f("%3j|%_3d|%-H|%_H"), "222| 10|17|17");
}

#[test]
fn bad_formats() {
	assert_eq!(f("%"), "%");
	assert_eq!(f("%5"), "   %5");
	assert_eq!(f("%E"), "%E");
	assert_eq!(
		f("%Ov|%EV|%q|%N|%:z|%Oc|%Ea|%OY"),
		"%Ov|%EV|%q|%N|%:z|%Oc|%Ea|%OY"
	);
	assert_eq!(f("%^5Q"), " %^5Q");
	// no era: %E falls back, O without alternative digits too
	assert_eq!(f("%Ey|%EY|%EC|%Ex|%Ou|%OH"), "26|2026|20|08/10/26|1|17");
}

#[test]
fn room() {
	let c = Locale::c();
	// 24 bytes and the nul
	assert!(strftime(25, b"%c", &tm(), &c).is_some());
	assert_eq!(strftime(24, b"%c", &tm(), &c), None);
	assert_eq!(strftime(0, b"", &tm(), &c), Some(Vec::new()));
	// a huge width is checked before anything is written
	assert_eq!(strftime(50, b"%2147483647c", &tm(), &c), None);
	assert_eq!(strftime(50, b"%99999999999d", &tm(), &c), None);
}

#[test]
fn era_and_alt_digits() {
	let mut l = Locale::c();
	l.time.eras = vec![Era {
		direction: u32::from(b'+'),
		offset: 1,
		start: [119, 4, 1],
		stop: [i32::MAX, 11, 31],
		name: "令和".into(),
		format: b"%EC%Ey".to_vec(),
		absolute_direction: 1,
	}];
	l.time.alt_digits =
		(0..100).map(|i| format!("<{i}>").into_bytes()).collect();
	let g = |fmt: &str| {
		let out = strftime(256, fmt.as_bytes(), &tm(), &l).unwrap();
		String::from_utf8(out).unwrap()
	};
	assert_eq!(g("%EC|%Ey|%EY|%_EY"), "令和|08|令和08|令和 8");
	assert_eq!(g("%Od|%OH|%Oe|%Oy"), "<10>|<17>|<10>|<26>");
	// before the era
	let old = Tm::at(0, 0, false, b"").unwrap();
	let out = strftime(256, b"%EC|%Ey", &old, &l).unwrap();
	assert_eq!(out, b"19|70");
}
