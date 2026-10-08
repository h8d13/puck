// glibc's setlocale(LC_ALL, "") as pacman's main calls it (localize),
// glibc 2.44: locale/setlocale.c, findlocale.c, loadarchive.c,
// loadlocale.c, intl/explodename.c, l10nflist.c, localealias.c and the
// codeset alias compare of iconv/gconv_cache.c. what pacman's output
// takes from the locale is read: LC_TIME (strftime), LC_NUMERIC's
// decimal point (printf's %f) and LC_CTYPE's codeset and case maps. all
// twelve categories are resolved and checked like glibc's, which
// installs all of them or none: one category that fails to load leaves
// the whole process in "C".
//
// per category the name is LC_ALL, LC_<category> or LANG (the first
// set and non-empty), else "C". "C" and "POSIX" are built in. without
// LOCPATH the locale archive is tried, then the name's locale.alias
// expansion there; with LOCPATH the archive is skipped. then the
// directories (LOCPATH's, then /usr/lib/locale) are searched for
// <name>/LC_<category>, dropping codeset, normalized codeset, territory
// and modifier in glibc's order. a name naming a codeset must match the
// data's codeset through the gconv aliases.
//
// translation:
// - the C maps the files; here they are read with pread, only what is
//   used: each category's header and index (what _nl_intern_locale_data
//   checks), then the items read from it
// - the C caches loaded files and archive entries per process; this
//   resolves once per call
// - with GCONV_PATH set or no gconv-modules.cache, glibc reads the text
//   gconv-modules for aliases; the port knows only glibc's builtin
//   aliases then (UTF-8, ASCII, UCS-2, UCS-4)
// - strings end at their nul or at the end of the category data (the C
//   reads on past the end of corrupt data), a hash chain without an
//   empty slot ends after one round (the C loops)

use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use crate::util::until_nul;

pub const LC_CTYPE: usize = 0;
pub const LC_NUMERIC: usize = 1;
pub const LC_TIME: usize = 2;
pub const LC_ALL: usize = 6;
// __LC_LAST
const LC_LAST: usize = 13;

const NAMES: [&str; LC_LAST] = [
	"LC_CTYPE",
	"LC_NUMERIC",
	"LC_TIME",
	"LC_COLLATE",
	"LC_MONETARY",
	"LC_MESSAGES",
	"LC_ALL",
	"LC_PAPER",
	"LC_NAME",
	"LC_ADDRESS",
	"LC_TELEPHONE",
	"LC_MEASUREMENT",
	"LC_IDENTIFICATION",
];

// _nl_category_num_items (langinfo.h _NL_NUM_LC_*). a file with fewer
// items is refused, with more too except for LC_CTYPE (CATTEST)
const NUM_ITEMS: [u32; LC_LAST] =
	[86, 6, 159, 19, 46, 5, 0, 3, 7, 13, 5, 2, 16];

// findlocale.c's codeset_idx: the item naming each category's codeset
const CODESET_ITEM: [u32; LC_LAST] =
	[14, 5, 110, 18, 45, 4, 0, 2, 6, 12, 4, 1, 15];

// the items of type word (categories.def): their offset must be aligned
const WORDS: [&[u32]; LC_LAST] = [
	&[
		13, 17, 18, 19, 30, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
		66, 68, 70, 71,
	],
	&[3, 4],
	&[50, 102],
	&[0, 13],
	&[38, 39, 40, 41, 43, 44],
	&[],
	&[],
	&[0, 1],
	&[],
	&[6],
	&[],
	&[],
	&[],
];

// LC_CTYPE items
const CTYPE_TOUPPER: u32 = 1;
const CTYPE_TOLOWER: u32 = 3;
const CTYPE_CODESET_NAME: u32 = 14;
// LC_TIME items
pub const ABDAY_1: usize = 0;
pub const DAY_1: usize = 7;
pub const ABMON_1: usize = 14;
pub const MON_1: usize = 26;
pub const AM_STR: usize = 38;
pub const PM_STR: usize = 39;
pub const D_T_FMT: usize = 40;
pub const D_FMT: usize = 41;
pub const T_FMT: usize = 42;
pub const T_FMT_AMPM: usize = 43;
pub const ERA_D_FMT: usize = 46;
const ALT_DIGITS: usize = 47;
pub const ERA_D_T_FMT: usize = 48;
pub const ERA_T_FMT: usize = 49;
const TIME_ERA_NUM_ENTRIES: usize = 50;
const TIME_ERA_ENTRIES: usize = 51;
pub const ALTMON_1: usize = 111;
pub const ABALTMON_1: usize = 135;
const TIME_ITEMS: usize = 159;

// glibc's COMPLOCALEDIR, LOCALE_ALIAS_PATH and GCONV_DIR on Arch
const LOCALE_DIR: &[u8] = b"/usr/lib/locale";
const ARCHIVE: &str = "/usr/lib/locale/locale-archive";
const ALIAS_FILE: &str = "/usr/share/locale/locale.alias";
const GCONV_CACHE: &str = "/usr/lib/gconv/gconv-modules.cache";

// XPG name parts (loadinfo.h)
const XPG_NORM_CODESET: i32 = 1;
const XPG_CODESET: i32 = 2;
const XPG_TERRITORY: i32 = 4;
const XPG_MODIFIER: i32 = 8;

// LIMAGIC
fn magic(cat: usize) -> u32 {
	let base = match cat {
		3 => 0x2005_1014,
		LC_CTYPE => 0x2009_0720,
		_ => 0x2003_1115,
	};
	base ^ cat as u32
}

// a category's data: a file, or a range of the locale archive
#[derive(Clone)]
struct Blob {
	file: Arc<File>,
	base: u64,
	len: u64,
}

impl Blob {
	// n bytes at off, None past the end or on a read error
	fn read(&self, off: u64, n: usize) -> Option<Vec<u8>> {
		if off.checked_add(n as u64)? > self.len {
			return None;
		}
		let mut buf = vec![0; n];
		self.file.read_exact_at(&mut buf, self.base + off).ok()?;
		Some(buf)
	}

	// the string at off, up to its nul or the end of the data
	fn cstr(&self, off: u64) -> Vec<u8> {
		let mut out = Vec::new();
		let mut at = off;
		while at < self.len {
			let n = (self.len - at).min(256) as usize;
			let Some(chunk) = self.read(at, n) else {
				break;
			};
			let s = until_nul(&chunk);
			out.extend_from_slice(s);
			if s.len() < n {
				break;
			}
			at += n as u64;
		}
		out
	}
}

// a category as _nl_intern_locale_data accepted it: the data and the
// offset of each item
struct Data {
	blob: Blob,
	idx: Vec<u32>,
}

impl Data {
	fn string(&self, item: u32) -> Vec<u8> {
		self.blob.cstr(u64::from(self.idx[item as usize]))
	}

	// the whole data, for the small categories read item by item
	fn bytes(&self) -> Option<Vec<u8>> {
		self.blob.read(0, usize::try_from(self.blob.len).ok()?)
	}
}

// _nl_intern_locale_data: magic, item count, index inside the data,
// word items aligned
fn intern(cat: usize, blob: Blob) -> Option<Data> {
	let head = blob.read(0, 8)?;
	let word = |i: usize| {
		u32::from_ne_bytes([
			head[i],
			head[i + 1],
			head[i + 2],
			head[i + 3],
		])
	};
	let (m, n) = (word(0), word(4));
	if m != magic(cat) || n < NUM_ITEMS[cat] {
		return None;
	}
	if 8 + 4 * u64::from(n) >= blob.len {
		return None;
	}
	let raw = blob.read(8, 4 * n as usize)?;
	let mut idx = Vec::with_capacity(n as usize);
	for (i, w) in raw.chunks_exact(4).enumerate() {
		let at = u32::from_ne_bytes([w[0], w[1], w[2], w[3]]);
		if u64::from(at) > blob.len {
			return None;
		}
		// more items than the category has: CATTEST
		if cat != LC_CTYPE && i >= NUM_ITEMS[cat] as usize {
			return None;
		}
		if WORDS[cat].contains(&(i as u32)) && at % 4 != 0 {
			return None;
		}
		idx.push(at);
	}
	Some(Data { blob, idx })
}

// _nl_load_locale: <dir>/<name>/LC_x, or LC_x/SYS_LC_x if that is a
// directory (LC_MESSAGES)
fn load_file(path: &[u8], cat: usize) -> Option<Data> {
	let path = OsStr::from_bytes(path);
	let mut file = File::open(path).ok()?;
	let mut meta = file.metadata().ok()?;
	if meta.is_dir() {
		let mut sys = path.as_bytes().to_vec();
		sys.extend_from_slice(b"/SYS_");
		sys.extend_from_slice(NAMES[cat].as_bytes());
		file = File::open(OsStr::from_bytes(&sys)).ok()?;
		meta = file.metadata().ok()?;
	}
	let blob = Blob {
		file: Arc::new(file),
		base: 0,
		len: meta.len(),
	};
	intern(cat, blob)
}

// compute_hashval of hashval.h, 32 bits (loadarchive.c)
fn archive_hash(key: &[u8]) -> u32 {
	let mut h = key.len() as u32;
	for &c in key {
		h = h.rotate_left(9).wrapping_add(u32::from(c));
	}
	if h != 0 { h } else { !0 }
}

// _nl_normalize_codeset: alphanumerics kept, letters lowered, "iso"
// before an all-digit name
fn normalize_codeset(s: &[u8]) -> Vec<u8> {
	let alnum: Vec<u8> =
		s.iter().filter(|c| c.is_ascii_alphanumeric())
			.map(u8::to_ascii_lowercase)
			.collect();
	if alnum.iter().all(u8::is_ascii_digit) {
		return [b"iso", &alnum[..]].concat();
	}
	alnum
}

// the locale archive: its header fields as u32, struct locarhead order
struct Archive {
	file: Arc<File>,
	len: u64,
	head: [u32; 14],
}

const NAMEHASH_OFFSET: usize = 2;
const NAMEHASH_SIZE: usize = 4;

impl Archive {
	fn open() -> Option<Archive> {
		let file = File::open(ARCHIVE).ok()?;
		let len = file.metadata().ok()?.len();
		let mut b = [0; 56];
		file.read_exact_at(&mut b, 0).ok()?;
		let mut head = [0; 14];
		for (i, w) in b.chunks_exact(4).enumerate() {
			head[i] = u32::from_ne_bytes([w[0], w[1], w[2], w[3]]);
		}
		// calculate_head_size: the tables fit in the file
		let end = |off: usize, used: usize, size: u64| {
			u64::from(head[off]) + u64::from(head[used]) * size
		};
		let headsize =
			end(2, 4, 12).max(end(5, 6, 1)).max(end(8, 9, 108));
		if headsize > len {
			return None;
		}
		Some(Archive {
			file: Arc::new(file),
			len,
			head,
		})
	}

	fn blob(&self, base: u64, len: u64) -> Blob {
		Blob {
			file: self.file.clone(),
			base,
			len,
		}
	}

	// _nl_load_locale_from_archive: the name with its codeset
	// normalized, looked up in the name hash table; the category
	// ranges of its locale record
	fn find(&self, name: &[u8]) -> Option<[(u64, u64); LC_LAST]> {
		let name = archive_name(name);
		let all = self.blob(0, self.len);
		let size = self.head[NAMEHASH_SIZE];
		if size <= 2 {
			return None;
		}
		let hval = archive_hash(&name);
		let mut idx = hval % size;
		let incr = 1 + hval % (size - 2);
		let table = u64::from(self.head[NAMEHASH_OFFSET]);
		let mut locrec = None;
		for _ in 0..size {
			let e = all.read(table + 12 * u64::from(idx), 12)?;
			let w = |i: usize| {
				u32::from_ne_bytes([
					e[i],
					e[i + 1],
					e[i + 2],
					e[i + 3],
				])
			};
			if w(4) == 0 {
				return None;
			}
			if w(0) == hval && all.cstr(u64::from(w(4))) == name {
				locrec = Some(w(8));
				break;
			}
			idx += incr;
			if idx >= size {
				idx -= size;
			}
		}
		let locrec = u64::from(locrec?);
		if locrec == 0 {
			return None;
		}
		let rec = all.read(locrec + 4, 8 * LC_LAST)?;
		let mut out = [(0, 0); LC_LAST];
		for (cat, r) in out.iter_mut().enumerate() {
			if cat == LC_ALL {
				continue;
			}
			let w = |i: usize| {
				u64::from(u32::from_ne_bytes([
					rec[i],
					rec[i + 1],
					rec[i + 2],
					rec[i + 3],
				]))
			};
			let (off, len) = (w(8 * cat), w(8 * cat + 4));
			if off + len > self.len {
				return None;
			}
			*r = (off, len);
		}
		Some(out)
	}
}

// the archive's name for a locale: a codeset (after the first '.', up
// to '@') normalized
fn archive_name(name: &[u8]) -> Vec<u8> {
	let Some(dot) = name.iter().position(|&c| c == b'.') else {
		return name.to_vec();
	};
	let p = &name[dot + 1..];
	if p.is_empty() || p[0] == b'@' {
		return name.to_vec();
	}
	let end = p.iter().position(|&c| c == b'@').unwrap_or(p.len());
	[&name[..=dot], &normalize_codeset(&p[..end])[..], &p[end..]].concat()
}

// read_alias_file: "alias value" lines, '#' comments, fields split at
// C-locale white space; a line past 399 bytes is read up to there
fn read_aliases() -> Vec<(Vec<u8>, Vec<u8>)> {
	let Ok(text) = std::fs::read(ALIAS_FILE) else {
		return Vec::new();
	};
	let space = |c: &u8| {
		matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
	};
	let mut out = Vec::new();
	for line in text.split_inclusive(|&c| c == b'\n') {
		// fgets into 400 bytes, the rest of a longer line skipped
		let line = until_nul(&line[..line.len().min(399)]);
		let mut words = line.split(space).filter(|w| !w.is_empty());
		let Some(alias) = words.next() else {
			continue;
		};
		if alias[0] == b'#' {
			continue;
		}
		if let Some(value) = words.next() {
			out.push((alias.to_vec(), value.to_vec()));
		}
	}
	out
}

// _nl_expand_alias: strcasecmp (C locale) on the alias. glibc bsearches
// the sorted table, which of several equal aliases it finds is
// unspecified; the first one here
fn expand_alias(
	aliases: &[(Vec<u8>, Vec<u8>)],
	name: &[u8],
) -> Option<Vec<u8>> {
	aliases.iter()
		.find(|(a, _)| a.eq_ignore_ascii_case(name))
		.map(|(_, v)| v.clone())
}

// valid_locale_name: at most 255 bytes, no "..", a '/' only at the start
fn valid_locale_name(name: &[u8]) -> bool {
	let n = name.len();
	if n > 255 || name.windows(4).any(|w| w == b"/../") || name == b".." {
		return false;
	}
	if n >= 3 && (name.starts_with(b"../") || name.ends_with(b"/..")) {
		return false;
	}
	!name.contains(&b'/') || name[0] == b'/'
}

// _nl_explode_name: language[_territory][.codeset][@modifier]
struct Parts {
	mask: i32,
	language: Vec<u8>,
	territory: Vec<u8>,
	// set whenever the name has a '.', even an empty codeset
	codeset: Option<Vec<u8>>,
	normalized: Vec<u8>,
	modifier: Vec<u8>,
}

fn explode(name: &[u8]) -> Parts {
	let stop = |c: &u8| matches!(c, b'_' | b'@' | b'.');
	let lang_end = name.iter().position(stop).unwrap_or(name.len());
	let mut p = Parts {
		mask: 0,
		language: name.to_vec(),
		territory: Vec::new(),
		codeset: None,
		normalized: Vec::new(),
		modifier: Vec::new(),
	};
	// no language: the name as it is (perhaps an alias)
	if lang_end == 0 {
		return p;
	}
	p.language = name[..lang_end].to_vec();
	let mut cp = lang_end;
	if name.get(cp) == Some(&b'_') {
		let start = cp + 1;
		cp = start;
		while cp < name.len() && name[cp] != b'.' && name[cp] != b'@' {
			cp += 1;
		}
		p.territory = name[start..cp].to_vec();
		p.mask |= XPG_TERRITORY;
	}
	if name.get(cp) == Some(&b'.') {
		let start = cp + 1;
		cp = start;
		while cp < name.len() && name[cp] != b'@' {
			cp += 1;
		}
		let codeset = &name[start..cp];
		p.mask |= XPG_CODESET;
		if !codeset.is_empty() {
			p.normalized = normalize_codeset(codeset);
			// the C compares before the '@' is cut, so a modifier
			// always makes the normalized name differ
			if p.normalized[..] != name[start..] {
				p.mask |= XPG_NORM_CODESET;
			}
		}
		p.codeset = Some(codeset.to_vec());
	}
	if name.get(cp) == Some(&b'@') {
		p.modifier = name[cp + 1..].to_vec();
		if !p.modifier.is_empty() {
			p.mask |= XPG_MODIFIER;
		}
	}
	if p.mask & XPG_TERRITORY != 0 && p.territory.is_empty() {
		p.mask &= !XPG_TERRITORY;
	}
	if p.codeset.as_ref().is_some_and(Vec::is_empty) {
		p.mask &= !XPG_CODESET;
	}
	p
}

// _nl_make_l10nflist's file name for the parts in mask
fn l10n_path(dir: &[u8], mask: i32, p: &Parts, cat: usize) -> Vec<u8> {
	let mut s = dir.to_vec();
	s.push(b'/');
	s.extend_from_slice(&p.language);
	if mask & XPG_TERRITORY != 0 {
		s.push(b'_');
		s.extend_from_slice(&p.territory);
	}
	if mask & XPG_CODESET != 0 {
		s.push(b'.');
		s.extend_from_slice(p.codeset.as_deref().unwrap_or_default());
	}
	if mask & XPG_NORM_CODESET != 0 {
		s.push(b'.');
		s.extend_from_slice(&p.normalized);
	}
	if mask & XPG_MODIFIER != 0 {
		s.push(b'@');
		s.extend_from_slice(&p.modifier);
	}
	s.push(b'/');
	s.extend_from_slice(NAMES[cat].as_bytes());
	s
}

// the files _nl_find_locale tries, in order: the full name first (one
// directory only), then each subset of the parts from the most specific
// down, each in every directory. a mask with both codeset forms names
// no real file, glibc never loads it
fn candidates(dirs: &[Vec<u8>], p: &Parts, cat: usize) -> Vec<Vec<u8>> {
	let both = |m: i32| m & XPG_CODESET != 0 && m & XPG_NORM_CODESET != 0;
	let mut out = Vec::new();
	let start = if dirs.len() == 1 {
		if !both(p.mask) {
			out.push(l10n_path(&dirs[0], p.mask, p, cat));
		}
		p.mask - 1
	} else {
		p.mask
	};
	for cnt in (0..=start).rev() {
		if cnt & !p.mask != 0 || both(cnt) {
			continue;
		}
		for dir in dirs {
			out.push(l10n_path(dir, cnt, p, cat));
		}
	}
	out
}

// gconv_charset.h strip: alphanumerics and "_-.,:" upper-cased, at
// most two '/', padded to two
fn strip(s: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	let mut slashes = 0;
	for &c in s {
		if c.is_ascii_alphanumeric() || b"_-.,:".contains(&c) {
			out.push(c.to_ascii_uppercase());
		} else if c == b'/' {
			slashes += 1;
			if slashes == 3 {
				break;
			}
			out.push(b'/');
		}
	}
	while slashes < 2 {
		out.push(b'/');
		slashes += 1;
	}
	out
}

// gconv_builtin.h's aliases, what glibc knows without a configuration
const BUILTIN_ALIASES: &[(&[u8], &[u8])] = &[
	(b"UCS4//", b"ISO-10646/UCS4/"),
	(b"UCS-4//", b"ISO-10646/UCS4/"),
	(b"UCS-4BE//", b"ISO-10646/UCS4/"),
	(b"CSUCS4//", b"ISO-10646/UCS4/"),
	(b"ISO-10646//", b"ISO-10646/UCS4/"),
	(b"10646-1:1993//", b"ISO-10646/UCS4/"),
	(b"10646-1:1993/UCS4/", b"ISO-10646/UCS4/"),
	(b"OSF00010104//", b"ISO-10646/UCS4/"),
	(b"OSF00010105//", b"ISO-10646/UCS4/"),
	(b"OSF00010106//", b"ISO-10646/UCS4/"),
	(b"WCHAR_T//", b"INTERNAL"),
	(b"UTF8//", b"ISO-10646/UTF8/"),
	(b"UTF-8//", b"ISO-10646/UTF8/"),
	(b"ISO-IR-193//", b"ISO-10646/UTF8/"),
	(b"OSF05010001//", b"ISO-10646/UTF8/"),
	(b"ISO-10646/UTF-8/", b"ISO-10646/UTF8/"),
	(b"UCS2//", b"ISO-10646/UCS2/"),
	(b"UCS-2//", b"ISO-10646/UCS2/"),
	(b"OSF00010100//", b"ISO-10646/UCS2/"),
	(b"OSF00010101//", b"ISO-10646/UCS2/"),
	(b"OSF00010102//", b"ISO-10646/UCS2/"),
	(b"ANSI_X3.4//", b"ANSI_X3.4-1968//"),
	(b"ISO-IR-6//", b"ANSI_X3.4-1968//"),
	(b"ANSI_X3.4-1986//", b"ANSI_X3.4-1968//"),
	(b"ISO_646.IRV:1991//", b"ANSI_X3.4-1968//"),
	(b"ASCII//", b"ANSI_X3.4-1968//"),
	(b"ISO646-US//", b"ANSI_X3.4-1968//"),
	(b"US-ASCII//", b"ANSI_X3.4-1968//"),
	(b"US//", b"ANSI_X3.4-1968//"),
	(b"IBM367//", b"ANSI_X3.4-1968//"),
	(b"CP367//", b"ANSI_X3.4-1968//"),
	(b"CSASCII//", b"ANSI_X3.4-1968//"),
	(b"OSF00010020//", b"ANSI_X3.4-1968//"),
	(b"UNICODEBIG//", b"ISO-10646/UCS2/"),
	(b"UCS-2BE//", b"ISO-10646/UCS2/"),
	(b"UNICODELITTLE//", b"ISO-10646/UCS2/"),
	(b"UCS-2LE//", b"ISO-10646/UCS2/"),
];

// gconv-modules.cache (iconvconfig.h): u16 offsets, the name hash
// table maps every name and alias to its module
struct GconvCache {
	data: Vec<u8>,
}

impl GconvCache {
	// __gconv_load_cache: not with GCONV_PATH set, header checked
	fn load(getenv: &dyn Fn(&str) -> Option<Vec<u8>>) -> Option<Self> {
		if getenv("GCONV_PATH").is_some() {
			return None;
		}
		let data = std::fs::read(GCONV_CACHE).ok()?;
		let c = GconvCache { data };
		let len = c.data.len();
		if len < 14 || c.u32_at(0) != 0x2001_0324 {
			return None;
		}
		let (strings, hash) = (c.u16_at(4), c.u16_at(6));
		let (size, module) = (c.u16_at(8), c.u16_at(10));
		let other = c.u16_at(12);
		if strings >= len || hash >= len || size == 0 {
			return None;
		}
		if hash + size * 4 > len || module >= len || other > len {
			return None;
		}
		Some(c)
	}

	fn u16_at(&self, i: usize) -> usize {
		usize::from(u16::from_ne_bytes([
			self.data[i],
			self.data[i + 1],
		]))
	}

	fn u32_at(&self, i: usize) -> u32 {
		let d = &self.data;
		u32::from_ne_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]])
	}

	// find_module_idx
	fn module(&self, name: &[u8]) -> Option<usize> {
		let strtab = self.u16_at(4);
		let (hash, size) = (self.u16_at(6), self.u16_at(8));
		let hval = hash_string(name);
		let mut idx = hval as usize % size;
		let step = 1 + hval as usize % size.saturating_sub(2).max(1);
		let limit = self.data.len() - strtab;
		for _ in 0..size {
			let e = hash + 4 * idx;
			let off = self.u16_at(e);
			if off == 0 {
				return None;
			}
			if off < limit {
				let s = until_nul(&self.data[strtab + off..]);
				if s == name {
					return Some(self.u16_at(e + 2));
				}
			}
			idx += step;
			if idx >= size {
				idx -= size;
			}
		}
		None
	}
}

// __hash_string (intl/hash-string.c), hashpjw on an unsigned long; the
// cache lookup keeps the low 32 bits
fn hash_string(s: &[u8]) -> u32 {
	let mut h: u64 = 0;
	for &c in s {
		h = (h << 4).wrapping_add(u64::from(c));
		let g = h & (0xf << 28);
		if g != 0 {
			h ^= g >> 24;
			h ^= g;
		}
	}
	h as u32
}

// __gconv_compare_alias on two stripped names: equal when they name
// the same module, else byte equal
fn same_codeset(cache: Option<&GconvCache>, a: &[u8], b: &[u8]) -> bool {
	match cache {
		Some(c) => match (c.module(a), c.module(b)) {
			(Some(x), Some(y)) => x == y,
			_ => a == b,
		},
		None => {
			let canon = |n: &[u8]| -> Vec<u8> {
				BUILTIN_ALIASES
					.iter()
					.find(|(f, _)| *f == n)
					.map_or(n.to_vec(), |(_, t)| t.to_vec())
			};
			canon(a) == canon(b)
		}
	}
}

// one category found: built in "C", or data from a file or the archive
enum Found {
	C,
	Data(Data),
}

// the lookups shared by the twelve categories, made once
struct Resolver<'a> {
	getenv: &'a dyn Fn(&str) -> Option<Vec<u8>>,
	locpath: Option<Vec<Vec<u8>>>,
	archive: Option<Option<Archive>>,
	aliases: Option<Vec<(Vec<u8>, Vec<u8>)>>,
	gconv: Option<Option<GconvCache>>,
}

impl Resolver<'_> {
	fn env(&self, name: &str) -> Option<Vec<u8>> {
		(self.getenv)(name).filter(|v| !v.is_empty())
	}

	fn alias(&mut self, name: &[u8]) -> Option<Vec<u8>> {
		let aliases = self.aliases.get_or_insert_with(read_aliases);
		expand_alias(aliases, name)
	}

	fn from_archive(&mut self, cat: usize, name: &[u8]) -> Option<Data> {
		let archive = self.archive.get_or_insert_with(Archive::open);
		let a = archive.as_ref()?;
		let (base, len) = a.find(name)?[cat];
		intern(cat, a.blob(base, len))
	}

	// _nl_find_locale for one category of setlocale(LC_ALL, "")
	fn find(&mut self, cat: usize) -> Option<Found> {
		let name = self
			.env("LC_ALL")
			.or_else(|| self.env(NAMES[cat]))
			.or_else(|| self.env("LANG"))
			.unwrap_or_else(|| b"C".to_vec());
		if name == b"C" || name == b"POSIX" {
			return Some(Found::C);
		}
		if !valid_locale_name(&name) {
			return None;
		}
		let (dirs, loc_name) = match self.locpath.clone() {
			None => {
				if let Some(d) = self.from_archive(cat, &name) {
					return Some(Found::Data(d));
				}
				let alias = self.alias(&name);
				if let Some(a) = &alias
					&& let Some(d) =
						self.from_archive(cat, a)
				{
					return Some(Found::Data(d));
				}
				(vec![LOCALE_DIR.to_vec()], alias)
			}
			Some(dirs) => (dirs, self.alias(&name)),
		};
		let parts = explode(&loc_name.unwrap_or(name));
		let data = candidates(&dirs, &parts, cat)
			.iter()
			.find_map(|path| load_file(path, cat))?;
		if let Some(codeset) = &parts.codeset {
			let ours = strip(&data.string(CODESET_ITEM[cat]));
			let getenv = self.getenv;
			let cache = self.gconv.get_or_insert_with(|| {
				GconvCache::load(getenv)
			});
			if !same_codeset(cache.as_ref(), &strip(codeset), &ours)
			{
				return None;
			}
		}
		Some(Found::Data(data))
	}
}

// what the port takes from a category of the C locale or a loaded one
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Era {
	// '+' or '-'
	pub direction: u32,
	pub offset: i32,
	// tm_year, tm_mon, tm_mday
	pub start: [i32; 3],
	pub stop: [i32; 3],
	pub name: Vec<u8>,
	pub format: Vec<u8>,
	// +1: the era's years count up with time
	pub absolute_direction: i32,
}

// LC_TIME: every item as a string (word items read as such are unused),
// the 100 alternative digits and the eras
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LcTime {
	items: Vec<Vec<u8>>,
	pub alt_digits: Vec<Vec<u8>>,
	pub eras: Vec<Era>,
}

// _nl_C_LC_TIME (C-time.c)
const C_DAYS: [&str; 7] = [
	"Sunday",
	"Monday",
	"Tuesday",
	"Wednesday",
	"Thursday",
	"Friday",
	"Saturday",
];
const C_MONTHS: [&str; 12] = [
	"January",
	"February",
	"March",
	"April",
	"May",
	"June",
	"July",
	"August",
	"September",
	"October",
	"November",
	"December",
];

impl LcTime {
	pub fn c() -> LcTime {
		let mut items = vec![Vec::new(); TIME_ITEMS];
		for (i, d) in C_DAYS.iter().enumerate() {
			items[ABDAY_1 + i] = d.as_bytes()[..3].to_vec();
			items[DAY_1 + i] = d.as_bytes().to_vec();
		}
		for (i, m) in C_MONTHS.iter().enumerate() {
			let ab = m.as_bytes()[..3].to_vec();
			items[ABMON_1 + i] = ab.clone();
			items[ABALTMON_1 + i] = ab;
			items[MON_1 + i] = m.as_bytes().to_vec();
			items[ALTMON_1 + i] = m.as_bytes().to_vec();
		}
		items[AM_STR] = b"AM".to_vec();
		items[PM_STR] = b"PM".to_vec();
		items[D_T_FMT] = b"%a %b %e %H:%M:%S %Y".to_vec();
		items[D_FMT] = b"%m/%d/%y".to_vec();
		items[T_FMT] = b"%H:%M:%S".to_vec();
		items[T_FMT_AMPM] = b"%I:%M:%S %p".to_vec();
		LcTime {
			items,
			alt_digits: Vec::new(),
			eras: Vec::new(),
		}
	}

	fn from_data(d: &Data) -> Option<LcTime> {
		let bytes = d.bytes()?;
		let at = |off: usize| {
			until_nul(bytes.get(off..).unwrap_or_default())
		};
		let items: Vec<Vec<u8>> = d.idx[..TIME_ITEMS]
			.iter()
			.map(|&i| at(i as usize).to_vec())
			.collect();
		// _nl_init_alt_digit: 100 strings from ALT_DIGITS on, read
		// past the item into what follows like the C
		let mut alt_digits = Vec::new();
		if !items[ALT_DIGITS].is_empty() {
			let mut off = d.idx[ALT_DIGITS] as usize;
			for _ in 0..100 {
				let s = at(off);
				alt_digits.push(s.to_vec());
				off += s.len() + 1;
			}
		}
		let word = |i: usize| -> Option<u32> {
			let o = d.idx[i] as usize;
			let b = bytes.get(o..o + 4)?;
			Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
		};
		// eras cut short by corrupt data are dropped (the C reads on)
		let n = word(TIME_ERA_NUM_ENTRIES).unwrap_or(0);
		let at = d.idx[TIME_ERA_ENTRIES] as usize;
		let eras = eras(&bytes, at, n).unwrap_or_default();
		Some(LcTime {
			items,
			alt_digits,
			eras,
		})
	}

	// nl_langinfo of an LC_TIME string item
	pub fn item(&self, i: usize) -> &[u8] {
		&self.items[i]
	}
}

// _nl_init_era_entries: per era 8 int32 (direction, offset, start and
// stop date), the name and format, then the same two as wide strings
fn eras(bytes: &[u8], mut ptr: usize, n: u32) -> Option<Vec<Era>> {
	let int = |o: usize| -> Option<i32> {
		let b = bytes.get(o..o + 4)?;
		Some(i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
	};
	let cstr = |o: usize| until_nul(bytes.get(o..).unwrap_or_default());
	let mut out = Vec::new();
	for _ in 0..n {
		let base = ptr;
		let v: Vec<i32> = (0..8)
			.map(|i| int(ptr + 4 * i))
			.collect::<Option<_>>()?;
		ptr += 32;
		let name = cstr(ptr).to_vec();
		ptr += name.len() + 1;
		let format = cstr(ptr).to_vec();
		ptr += format.len() + 1;
		ptr += 3 - ((ptr - base + 3) & 3);
		// two wide strings, each up to a zero wchar_t
		for _ in 0..2 {
			while int(ptr)? != 0 {
				ptr += 4;
			}
			ptr += 4;
		}
		let start = [v[2], v[3], v[4]];
		let stop = [v[5], v[6], v[7]];
		let plus = v[0] as u32 == u32::from(b'+');
		let ascending = era_date_le(start, stop);
		let absolute_direction = if ascending == plus { 1 } else { -1 };
		out.push(Era {
			direction: v[0] as u32,
			offset: v[1],
			start,
			stop,
			name,
			format,
			absolute_direction,
		});
	}
	Some(out)
}

// ERA_DATE_CMP: a <= b
pub fn era_date_le(a: [i32; 3], b: [i32; 3]) -> bool {
	a[0] < b[0]
		|| (a[0] == b[0]
			&& (a[1] < b[1] || (a[1] == b[1] && a[2] <= b[2])))
}

// the global locale as far as the port reads it
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locale {
	pub time: LcTime,
	// LC_NUMERIC's decimal_point, what printf's %f puts for '.'
	pub decimal_point: Vec<u8>,
	// LC_CTYPE's codeset name, nl_langinfo(CODESET)
	pub codeset: Vec<u8>,
	// toupper/tolower for -128..255, None in "C" (ASCII)
	case: Option<(Vec<i32>, Vec<i32>)>,
}

impl Locale {
	// the "C" locale (and "POSIX")
	pub fn c() -> Locale {
		Locale {
			time: LcTime::c(),
			decimal_point: b".".to_vec(),
			codeset: b"ANSI_X3.4-1968".to_vec(),
			case: None,
		}
	}

	// setlocale(LC_ALL, "") with this environment: None where glibc
	// fails and the process stays in "C"
	pub fn from_env(
		getenv: &dyn Fn(&str) -> Option<Vec<u8>>,
	) -> Option<Locale> {
		let locpath =
			getenv("LOCPATH").filter(|v| !v.is_empty()).map(|v| {
				let mut dirs: Vec<Vec<u8>> = v
					.split(|&c| c == b':')
					.filter(|d| !d.is_empty())
					.map(<[u8]>::to_vec)
					.collect();
				dirs.push(LOCALE_DIR.to_vec());
				dirs
			});
		let mut r = Resolver {
			getenv,
			locpath,
			archive: None,
			aliases: None,
			gconv: None,
		};
		// glibc goes from the last category down, all must load
		let mut found: Vec<Option<Found>> =
			(0..LC_LAST).map(|_| None).collect();
		for cat in (0..LC_LAST).rev() {
			if cat != LC_ALL {
				found[cat] = Some(r.find(cat)?);
			}
		}
		let mut l = Locale::c();
		if let Some(Found::Data(d)) = &found[LC_TIME] {
			l.time = LcTime::from_data(d)?;
		}
		if let Some(Found::Data(d)) = &found[LC_NUMERIC] {
			l.decimal_point = d.string(0);
		}
		if let Some(Found::Data(d)) = &found[LC_CTYPE] {
			l.codeset = d.string(CTYPE_CODESET_NAME);
			let table = |item: u32| -> Option<Vec<i32>> {
				let off = u64::from(d.idx[item as usize]);
				let b = d.blob.read(off, 384 * 4)?;
				Some(b.chunks_exact(4)
					.map(|w| {
						i32::from_ne_bytes([
							w[0], w[1], w[2], w[3],
						])
					})
					.collect())
			};
			l.case = Some((
				table(CTYPE_TOUPPER)?,
				table(CTYPE_TOLOWER)?,
			));
		}
		Some(l)
	}

	// toupper/tolower of a byte, through the LC_CTYPE tables. a result
	// that is no byte is cut to one like the C's store into a char
	pub fn toupper(&self, c: u8) -> u8 {
		match &self.case {
			Some((up, _)) => up[usize::from(c) + 128] as u8,
			None => c.to_ascii_uppercase(),
		}
	}

	pub fn tolower(&self, c: u8) -> u8 {
		match &self.case {
			Some((_, low)) => low[usize::from(c) + 128] as u8,
			None => c.to_ascii_lowercase(),
		}
	}
}

static LOCALIZED: AtomicBool = AtomicBool::new(false);
static CURRENT: OnceLock<Locale> = OnceLock::new();

// pacman's localize(): setlocale(LC_ALL, "") from the process
// environment. resolved on first use, the port never changes the
// environment in between
pub fn localize() {
	LOCALIZED.store(true, Ordering::Relaxed);
}

fn process_env(name: &str) -> Option<Vec<u8>> {
	std::env::var_os(name).map(|v| v.into_encoded_bytes())
}

// the global locale: "C" until localize, like a process before
// setlocale
pub fn current() -> &'static Locale {
	CURRENT.get_or_init(|| {
		if !LOCALIZED.load(Ordering::Relaxed) {
			return Locale::c();
		}
		Locale::from_env(&process_env).unwrap_or_else(Locale::c)
	})
}
