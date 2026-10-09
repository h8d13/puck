// alpm_core::setlocale, strftime and tzfile against glibc: locale-probe
// runs once per environment (setlocale is process wide). the locales
// are built with localedef into the test's directory and selected with
// LOCPATH, which glibc honours for programs that are not setuid; the
// host's en_US comes from the locale archive (no LOCPATH).
// DIFFTEST_LOCALES=all adds every UTF-8 locale of
// /usr/share/i18n/SUPPORTED to the fixed set
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use difftest::{localedef, output_capped};

// 12- and 24-hour clocks, names in many scripts, eras (ja_JP, th_TH,
// zh_TW), alternative digits (fa_IR), a %c past pacman's 50 bytes
// (ta_IN), %:z (en_SE), a two-byte decimal point (ps_AF), Turkish case
// maps, a Latin-1 charset
const LOCALES: [(&str, &str, &str); 17] = [
	("de_DE.UTF-8", "de_DE", "UTF-8"),
	("fr_FR.UTF-8", "fr_FR", "UTF-8"),
	("ja_JP.UTF-8", "ja_JP", "UTF-8"),
	("pl_PL.UTF-8", "pl_PL", "UTF-8"),
	("en_GB.UTF-8", "en_GB", "UTF-8"),
	("en_US.UTF-8", "en_US", "UTF-8"),
	("ko_KR.UTF-8", "ko_KR", "UTF-8"),
	("th_TH.UTF-8", "th_TH", "UTF-8"),
	("zh_TW.UTF-8", "zh_TW", "UTF-8"),
	("fa_IR.UTF-8", "fa_IR", "UTF-8"),
	("ta_IN.UTF-8", "ta_IN", "UTF-8"),
	("en_SE.UTF-8", "en_SE", "UTF-8"),
	("ps_AF.UTF-8", "ps_AF", "UTF-8"),
	("tr_TR.UTF-8", "tr_TR", "UTF-8"),
	("ru_RU.UTF-8", "ru_RU", "UTF-8"),
	("ar_SA.UTF-8", "ar_SA", "UTF-8"),
	("de_DE.ISO-8859-1", "de_DE", "ISO-8859-1"),
];

// every UTF-8 locale glibc lists, "name.UTF-8 UTF-8" lines
fn supported() -> Vec<(String, String)> {
	let text = fs::read_to_string("/usr/share/i18n/SUPPORTED").unwrap();
	text.lines()
		.filter_map(|l| l.split_once(' '))
		.filter(|(_, cs)| *cs == "UTF-8")
		.map(|(n, _)| {
			// the source is the name without its codeset
			let input = match n.split_once('.') {
				Some((l, rest)) => match rest.split_once('@') {
					Some((_, m)) => format!("{l}@{m}"),
					None => l.to_string(),
				},
				None => n.to_string(),
			};
			(n.to_string(), input)
		})
		.collect()
}

// the locale directory, built once per test binary
fn locales() -> &'static (PathBuf, Vec<String>) {
	static DIR: OnceLock<(PathBuf, Vec<String>)> = OnceLock::new();
	DIR.get_or_init(|| {
		let dir = std::env::temp_dir()
			.join(format!("locales-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		let mut names = Vec::new();
		for (name, input, charmap) in LOCALES {
			localedef(&dir, name, input, charmap);
			names.push(name.to_string());
		}
		if std::env::var("DIFFTEST_LOCALES").as_deref() == Ok("all") {
			for (name, input) in supported() {
				if !names.contains(&name) {
					localedef(&dir, &name, &input, "UTF-8");
					names.push(name);
				}
			}
		}
		// broken copies: a cut LC_TIME, a bad LC_NUMERIC magic, a name
		// saying ISO-8859-1 over UTF-8 data
		let de = dir.join("de_DE.UTF-8");
		for (name, file, f) in [
			(
				"cut_CUT.UTF-8",
				"LC_TIME",
				cut as fn(&[u8]) -> Vec<u8>,
			),
			("bad_BAD.UTF-8", "LC_NUMERIC", flip),
			("mis_MIS.ISO-8859-1", "LC_PAPER", keep),
		] {
			let d = dir.join(name);
			fs::create_dir_all(d.join("LC_MESSAGES")).unwrap();
			for e in fs::read_dir(&de).unwrap() {
				let e = e.unwrap().path();
				if e.is_file() {
					fs::copy(
						&e,
						d.join(e.file_name().unwrap()),
					)
					.unwrap();
				}
			}
			let msg = de.join("LC_MESSAGES/SYS_LC_MESSAGES");
			fs::copy(msg, d.join("LC_MESSAGES/SYS_LC_MESSAGES"))
				.unwrap();
			let b = fs::read(d.join(file)).unwrap();
			fs::write(d.join(file), f(&b)).unwrap();
		}
		(dir, names)
	})
}

fn cut(b: &[u8]) -> Vec<u8> {
	b[..b.len() / 2].to_vec()
}

fn flip(b: &[u8]) -> Vec<u8> {
	[&[b[0] ^ 1][..], &b[1..]].concat()
}

fn keep(b: &[u8]) -> Vec<u8> {
	b.to_vec()
}

// locale-probe under env (plus LOCPATH unless archive): the last line,
// all compares equal
#[track_caller]
fn probe(env: &[(&str, &str)], archive: bool) -> String {
	let (dir, _) = locales();
	let mut cmd = Command::new(env!("CARGO_BIN_EXE_locale-probe"));
	cmd.env_clear().env("PATH", "/usr/bin");
	if !archive {
		cmd.env("LOCPATH", dir);
	}
	for (k, v) in env {
		cmd.env(k, v);
	}
	if let Ok(n) = std::env::var("DIFFTEST_ITERS") {
		cmd.env("DIFFTEST_ITERS", n);
	}
	let o = output_capped(&mut cmd, 1200);
	let out = String::from_utf8_lossy(&o.stdout);
	let err = String::from_utf8_lossy(&o.stderr);
	assert!(o.status.success(), "{env:?}\n{out}{err}");
	let last = out.lines().last().unwrap_or_default().to_string();
	println!("{env:?} archive={archive}: {last}");
	last
}

// "locale true" or "locale false": whether setlocale took the locale
#[track_caller]
fn installed(env: &[(&str, &str)], archive: bool) -> bool {
	probe(env, archive).ends_with("locale true")
}

fn each_locale() {
	let (_, names) = locales();
	let zones = [
		"Europe/Brussels",
		"America/New_York",
		"Asia/Tokyo",
		"Australia/Lord_Howe",
	];
	for (i, name) in names.iter().enumerate() {
		let tz = zones[i % zones.len()];
		assert!(
			installed(&[("LANG", name), ("TZ", tz)], false),
			"{name}"
		);
	}
}

// the archive, the built-in names and failures: the C locale stays
fn archive_and_fallbacks() {
	assert!(installed(&[("LANG", "en_US.UTF-8")], true));
	assert!(installed(&[("LANG", "en_US.utf8"), ("TZ", "UTC")], true));
	assert!(installed(&[("LC_ALL", "C.UTF-8")], true));
	for (env, want) in [
		(&[][..], true),
		(&[("LANG", "C")], true),
		(&[("LANG", "POSIX")], true),
		(&[("LANG", "en_US")], false),
		(&[("LANG", "english")], false),
		(&[("LANG", "xx_YY.UTF-8")], false),
		(&[("LANG", "en_US.UTF-8"), ("LC_TIME", "xx_YY")], false),
		(&[("LANG", "../en_US.UTF-8")], false),
	] {
		assert_eq!(installed(env, true), want, "{env:?}");
	}
	// LOCPATH set: the archive is not read
	assert!(!installed(&[("LANG", "en_US.utf8")], false));
}

fn names_and_categories() {
	for (env, want) in [
		(&[("LANG", "de_DE.UTF-8@euro")][..], true),
		(&[("LANG", "de_DE.utf8")], false),
		(&[("LANG", "german"), ("TZ", "CET-1CEST")], true),
		(
			&[
				("LANG", "C"),
				("LC_TIME", "ja_JP.UTF-8"),
				("LC_NUMERIC", "ps_AF.UTF-8"),
				("LC_CTYPE", "tr_TR.UTF-8"),
			],
			true,
		),
		(
			&[
				("LC_ALL", "fr_FR.UTF-8"),
				("LANG", "de_DE.UTF-8"),
				("LC_TIME", "C"),
			],
			true,
		),
		(
			&[("LANG", "de_DE.UTF-8"), ("LC_PAPER", "xx_XX.UTF-8")],
			false,
		),
		(&[("LANG", "cut_CUT.UTF-8")], false),
		(&[("LANG", "bad_BAD.UTF-8")], false),
		(&[("LANG", "mis_MIS.ISO-8859-1")], false),
		(
			&[
				("LANG", "de_DE.ISO-8859-1"),
				("LC_TIME", "ko_KR.UTF-8"),
			],
			true,
		),
	] {
		assert_eq!(installed(env, false), want, "{env:?}");
	}
}

// zones: rule strings, posixrules defaults, leap seconds, odd values
fn zones() {
	for tz in [
		"",
		":",
		"garbage",
		"ab",
		"AAA3BBB",
		"CET-1CEST",
		"EST5EDT,M3.2.0,M11.1.0",
		"<+1345>-13:45<+1245>-12:45,M9.5.0/2:45,M4.1.0/3:45",
		"right/Europe/Paris",
		"right/UTC",
		"Africa/Casablanca",
		"Pacific/Chatham",
		"Europe/Dublin",
	] {
		assert!(
			installed(
				&[("LANG", "en_GB.UTF-8"), ("TZ", tz)],
				false
			),
			"{tz}"
		);
	}
}

// one test: the locales are built once and removed after the last group
#[test]
fn against_glibc() {
	each_locale();
	archive_and_fallbacks();
	names_and_categories();
	zones();
	fs::remove_dir_all(&locales().0).unwrap();
}
