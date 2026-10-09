// unit tests for alpm_core::setlocale on locale directories written
// here in glibc 2.44's compiled format (LOCPATH, so the archive is not
// read). the equivalence tests compare against glibc on localedef's
// output
use std::fs;
use std::path::{Path, PathBuf};

use alpm_core::setlocale::{D_T_FMT, Locale};

const CATEGORIES: [(&str, u32, u32); 12] = [
	// name, item count, codeset item
	("LC_CTYPE", 86, 14),
	("LC_NUMERIC", 6, 5),
	("LC_TIME", 159, 110),
	("LC_COLLATE", 19, 18),
	("LC_MONETARY", 46, 45),
	("LC_MESSAGES", 5, 4),
	("LC_PAPER", 3, 2),
	("LC_NAME", 7, 6),
	("LC_ADDRESS", 13, 12),
	("LC_TELEPHONE", 5, 4),
	("LC_MEASUREMENT", 2, 1),
	("LC_IDENTIFICATION", 16, 15),
];

// glibc's category number of each entry above
const NUMBERS: [u32; 12] = [0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12];

fn magic(cat: u32) -> u32 {
	let base = match cat {
		3 => 0x2005_1014,
		0 => 0x2009_0720,
		_ => 0x2003_1115,
	};
	base ^ cat
}

// header, index, an aligned zero word every item points to unless set,
// then the set items (4-byte aligned)
fn category(cat: u32, n: u32, items: &[(u32, Vec<u8>)]) -> Vec<u8> {
	let data_at = 8 + 4 * n;
	let mut data = vec![0u8; 4];
	let mut idx = vec![data_at; n as usize];
	for (i, v) in items {
		while !data.len().is_multiple_of(4) {
			data.push(0);
		}
		idx[*i as usize] = data_at + data.len() as u32;
		data.extend_from_slice(v);
		data.push(0);
	}
	let mut out = Vec::new();
	out.extend(magic(cat).to_ne_bytes());
	out.extend(n.to_ne_bytes());
	for i in idx {
		out.extend(i.to_ne_bytes());
	}
	out.extend(data);
	out
}

// toupper as an int32 table for -128..255, 'a' -> 'Q' to tell it apart
fn upper_table() -> Vec<u8> {
	let mut v = Vec::new();
	for c in -128i32..256 {
		let u = match c {
			0x61 => i32::from(b'Q'),
			0x62..=0x7a => c - 32,
			_ => c,
		};
		v.extend(u.to_ne_bytes());
	}
	v
}

struct Fx {
	dir: PathBuf,
}

impl Fx {
	fn new(name: &str) -> Fx {
		let dir = std::env::temp_dir().join(format!(
			"setlocale-{name}-{}",
			std::process::id()
		));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		Fx { dir }
	}

	// a whole locale: codeset in every category, %c "<%d.%m.%Y>",
	// decimal ','
	fn locale(&self, name: &str, codeset: &str) -> PathBuf {
		let d = self.dir.join(name);
		fs::create_dir_all(&d).unwrap();
		for (k, (cname, n, cs)) in CATEGORIES.iter().enumerate() {
			let cat = NUMBERS[k];
			let mut items =
				vec![(*cs, codeset.as_bytes().to_vec())];
			match cat {
				0 => {
					items.push((1, upper_table()));
					items.push((3, upper_table()));
				}
				1 => items.push((0, b",".to_vec())),
				2 => items.push((
					D_T_FMT as u32,
					b"<%d.%m.%Y>".to_vec(),
				)),
				_ => {}
			}
			let data = category(cat, *n, &items);
			if *cname == "LC_MESSAGES" {
				fs::create_dir_all(d.join(cname)).unwrap();
				fs::write(
					d.join(cname).join("SYS_LC_MESSAGES"),
					data,
				)
				.unwrap();
			} else {
				fs::write(d.join(cname), data).unwrap();
			}
		}
		d
	}

	fn env<'a>(
		&'a self,
		vars: &'a [(&str, &str)],
	) -> impl Fn(&str) -> Option<Vec<u8>> + 'a {
		move |name: &str| {
			if name == "LOCPATH" {
				return Some(self
					.dir
					.display()
					.to_string()
					.into_bytes());
			}
			vars.iter()
				.find(|(k, _)| *k == name)
				.map(|(_, v)| v.as_bytes().to_vec())
		}
	}

	fn load(&self, vars: &[(&str, &str)]) -> Option<Locale> {
		Locale::from_env(&self.env(vars))
	}
}

impl Drop for Fx {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.dir);
	}
}

fn rewrite(path: &Path, f: impl FnOnce(&mut Vec<u8>)) {
	let mut b = fs::read(path).unwrap();
	f(&mut b);
	fs::write(path, b).unwrap();
}

#[test]
fn c_and_posix() {
	let fx = Fx::new("c");
	assert_eq!(fx.load(&[]), Some(Locale::c()));
	for name in ["C", "POSIX"] {
		assert_eq!(fx.load(&[("LANG", name)]), Some(Locale::c()));
	}
	// LC_ALL wins, empty values do not count
	let l = fx.load(&[("LC_ALL", ""), ("LC_TIME", "C"), ("LANG", "")]);
	assert_eq!(l, Some(Locale::c()));
	assert_eq!(
		fx.load(&[("LC_ALL", "C"), ("LANG", "xx_YY")]),
		Some(Locale::c())
	);
}

#[test]
fn loaded() {
	let fx = Fx::new("loaded");
	fx.locale("xx_XX.UTF-8", "UTF-8");
	let l = fx.load(&[("LANG", "xx_XX.UTF-8")]).unwrap();
	assert_eq!(l.time.item(D_T_FMT), b"<%d.%m.%Y>");
	assert_eq!(l.decimal_point, b",");
	assert_eq!(l.codeset, b"UTF-8");
	assert_eq!(
		(l.toupper(b'a'), l.toupper(b'b'), l.tolower(b'a')),
		(b'Q', b'B', b'Q')
	);
	// per category: LC_TIME from C, the rest loaded
	let l = fx
		.load(&[("LANG", "xx_XX.UTF-8"), ("LC_TIME", "POSIX")])
		.unwrap();
	assert_eq!(l.time.item(D_T_FMT), b"%a %b %e %H:%M:%S %Y");
	assert_eq!(l.decimal_point, b",");
}

#[test]
fn name_fallbacks() {
	let fx = Fx::new("names");
	fx.locale("xx_XX.utf8", "UTF-8");
	fx.locale("yy", "UTF-8");
	// the normalized codeset, then without the territory
	for name in [
		"xx_XX.UTF-8",
		"xx_XX.utf8",
		"yy_ZZ.UTF-8",
		"yy_ZZ",
		"yy.UTF-8@mod",
	] {
		let l = fx.load(&[("LANG", name)]);
		assert_eq!(
			l.map(|l| l.decimal_point),
			Some(b",".to_vec()),
			"{name}"
		);
	}
	// the modifier goes before the codeset
	assert!(fx.load(&[("LANG", "xx_XX.UTF-8@mod")]).is_some());
	// nothing of these exists
	for name in ["xx_XX", "zz_XX.UTF-8", "x"] {
		assert_eq!(fx.load(&[("LANG", name)]), None, "{name}");
	}
	// a name without a language is looked up whole
	fx.locale("_odd", "UTF-8");
	assert!(fx.load(&[("LANG", "_odd")]).is_some());
	// traversal and stray slashes refused, a leading one allowed
	for name in ["../xx_XX.utf8", "a/xx", "xx/..", ".."] {
		assert_eq!(fx.load(&[("LANG", name)]), None, "{name}");
	}
	// joined to the directory: <dir>//yy
	assert!(fx.load(&[("LANG", "/yy")]).is_some());
	fx.locale("lead/yy", "UTF-8");
	assert!(fx.load(&[("LANG", "/lead/yy")]).is_some());
	let long = "y".repeat(256);
	assert_eq!(fx.load(&[("LANG", long.as_str())]), None);
}

#[test]
fn codesets() {
	let fx = Fx::new("codesets");
	fx.locale("aa_AA.utf8", "UTF-8");
	fx.locale("bb_BB.UTF-8", "ISO-8859-1");
	// UTF8 and UTF-8 are one charset to gconv, cache or builtin aliases
	assert!(fx.load(&[("LANG", "aa_AA.utf8")]).is_some());
	let gconv = [("LANG", "aa_AA.utf8"), ("GCONV_PATH", "/nonexistent")];
	assert!(fx.load(&gconv).is_some());
	// the name says UTF-8, the data another charset
	assert_eq!(fx.load(&[("LANG", "bb_BB.UTF-8")]), None);
	// an empty codeset still names one
	fx.locale("cc_CC", "UTF-8");
	assert_eq!(fx.load(&[("LANG", "cc_CC.")]), None);
	assert!(fx.load(&[("LANG", "cc_CC")]).is_some());
}

#[test]
fn broken_data() {
	let fx = Fx::new("broken");
	let set = |name: &str| fx.load(&[("LANG", name)]);
	let d = fx.locale("aa_AA", "UTF-8");
	assert!(set("aa_AA").is_some());
	// one category missing: none installed
	fs::remove_file(d.join("LC_PAPER")).unwrap();
	assert_eq!(set("aa_AA"), None);
	let d = fx.locale("bb_BB", "UTF-8");
	rewrite(&d.join("LC_TIME"), |b| b[0] ^= 1);
	assert_eq!(set("bb_BB"), None);
	// one item too many: refused, except in LC_CTYPE
	let d = fx.locale("cc_CC", "UTF-8");
	fs::write(d.join("LC_TIME"), category(2, 160, &[])).unwrap();
	assert_eq!(set("cc_CC"), None);
	let d = fx.locale("dd_DD", "UTF-8");
	let ctype = category(
		0,
		90,
		&[
			(14, b"UTF-8".to_vec()),
			(1, upper_table()),
			(3, upper_table()),
		],
	);
	fs::write(d.join("LC_CTYPE"), ctype).unwrap();
	assert!(set("dd_DD").is_some());
	// an index past the data, a misaligned word
	let d = fx.locale("ee_EE", "UTF-8");
	rewrite(&d.join("LC_NUMERIC"), |b| {
		b[8..12].copy_from_slice(&9999u32.to_ne_bytes())
	});
	assert_eq!(set("ee_EE"), None);
	let d = fx.locale("ff_FF", "UTF-8");
	rewrite(&d.join("LC_TIME"), |b| {
		let at = 8 + 4 * 50;
		let v = u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
			+ 1;
		b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
	});
	assert_eq!(set("ff_FF"), None);
}
