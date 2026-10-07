// pacman_common::util_common against src/common/util-common.c
use std::io::BufReader;
use std::os::unix::fs::{MetadataExt, symlink};

use difftest::{
	CStat, Rng, c_fgets_file, c_fgets_mem, c_hex_representation, c_llstat,
	c_mbasename, c_mdirname, c_strtrim, c_strtrim_null, c_wordsplit, iters,
};
use pacman_common::util_common::{
	hex_representation, llstat, mbasename, mdirname, safe_fgets, strtrim,
	wordsplit,
};

// C-locale space, bytes that are space elsewhere (\x85, \xa0), plus filler
const SPACES: &[u8] = b"  \t\n\x0b\x0c\r\x85\xa0a";

fn show(s: &[u8]) -> String {
	format!("{:?}", String::from_utf8_lossy(s))
}

#[test]
fn hex() {
	let mut rng = Rng::new(0x4e8);
	assert_eq!(c_hex_representation(b""), hex_representation(b""));
	for _ in 0..iters() {
		let b: Vec<u8> = (0..rng.below(24))
			.map(|_| rng.next_u64() as u8)
			.collect();
		assert_eq!(c_hex_representation(&b), hex_representation(&b));
	}
}

#[test]
fn basename_dirname() {
	assert_eq!(c_mdirname(None), b".");
	for p in [&b""[..], b"/", b"//", b"a", b"a/", b"/a", b"a//b", b"/a/b/"]
	{
		assert_eq!(c_mbasename(p), mbasename(p), "{}", show(p));
		assert_eq!(c_mdirname(Some(p)), mdirname(p), "{}", show(p));
	}
	let mut rng = Rng::new(0xd1e);
	for _ in 0..iters() {
		let p = rng.bytes(b"ab//.\x80 ", 12);
		assert_eq!(c_mbasename(&p), mbasename(&p), "{}", show(&p));
		assert_eq!(c_mdirname(Some(&p)), mdirname(&p), "{}", show(&p));
	}
}

#[test]
fn trim() {
	assert_eq!(c_strtrim_null(), 0);
	let mut rng = Rng::new(0x7e1);
	for _ in 0..iters() {
		let s = rng.bytes(SPACES, 12);
		let r = strtrim(&s);
		assert_eq!(
			c_strtrim(&s),
			(r.len(), r.to_vec()),
			"{}",
			show(&s)
		);
	}
}

#[test]
fn wordsplit_fuzz() {
	assert_eq!(c_wordsplit(None), None);
	for s in [
		&b""[..],
		b"   ",
		b"a b",
		b"''",
		b"'a b'c\"d e\"",
		b"\\'a",
		b"\\\"",
		b"'\\''",
		b"\"\\\"\"",
		b"'\\\"'",
		b"\"a\\",
		b"\\",
		b"a\\ b",
		b"'",
		b"x'",
		b"\x0ba\x0cb\x85",
	] {
		assert_eq!(c_wordsplit(Some(s)), wordsplit(s), "{}", show(s));
	}
	let alphabet = b"ab  '\"\"''\\\\\t\n\x0b\x0c\r\x80\xff";
	let mut rng = Rng::new(0x3051);
	for _ in 0..iters() {
		let s = rng.bytes(alphabet, 18);
		assert_eq!(
			c_wordsplit(Some(&s)),
			wordsplit(&s),
			"{}",
			show(&s)
		);
	}
}

// the rust reader driven like the C loop, over a BufReader whose
// capacity forces chunks to span refills
fn rust_chunks(
	data: &[u8],
	size: usize,
	cap: usize,
	max_calls: usize,
) -> Vec<Vec<u8>> {
	let mut r = BufReader::with_capacity(cap, data);
	let mut out = Vec::new();
	for _ in 0..max_calls {
		match safe_fgets(&mut r, size).unwrap() {
			Some(c) => out.push(c),
			None => break,
		}
	}
	out
}

#[test]
fn fgets_chunking() {
	let mut rng = Rng::new(0xf6e7);
	for _ in 0..iters() {
		let data = rng.bytes(b"ab\n\n\0\r", 40);
		let size = match rng.below(20) {
			0 => 1024,
			n => n - 1,
		};
		let cap = 1 + rng.below(8);
		let calls = data.len() + 3;
		assert_eq!(
			c_fgets_mem(&data, size as i32, calls),
			rust_chunks(&data, size, cap, calls),
			"size {size} cap {cap} {}",
			show(&data)
		);
	}
}

// libalpm's be_local reads with a 1024 buffer, ini.c with PATH_MAX
#[test]
fn fgets_real_file_long_lines() {
	let path = format!("/tmp/difftest-fgets-{}", std::process::id());
	let mut data = Vec::new();
	for n in [0, 1, 1022, 1023, 1024, 1025, 2047, 2048, 4095, 4096, 5000] {
		data.extend(std::iter::repeat_n(b'x', n));
		data.push(b'\n');
	}
	data.extend(b"nul\0inside\nno newline at end");
	std::fs::write(&path, &data).unwrap();
	for size in [2, 3, 1023, 1024, 1025, 4096] {
		let calls = data.len() + 3;
		let c = c_fgets_file(path.as_bytes(), &data, size, calls);
		let r = rust_chunks(&data, size as usize, 8192, calls);
		assert_eq!(c, r, "size {size}");
		let r = rust_chunks(&data, size as usize, 7, calls);
		assert_eq!(c, r, "size {size}, small buffer");
	}
	std::fs::remove_file(&path).unwrap();
}

fn rust_llstat(p: &[u8]) -> Result<CStat, i32> {
	llstat(p)
		.map(|m| CStat {
			dev: m.dev(),
			ino: m.ino(),
			mode: m.mode(),
			nlink: m.nlink(),
			size: m.size() as i64,
		})
		.map_err(|e| e.raw_os_error().unwrap())
}

#[test]
fn llstat_temp_tree() {
	let base = format!("/tmp/difftest-llstat-{}", std::process::id());
	let _ = std::fs::remove_dir_all(&base);
	std::fs::create_dir(&base).unwrap();
	std::fs::create_dir(format!("{base}/d")).unwrap();
	std::fs::write(format!("{base}/f"), b"12345").unwrap();
	symlink("d", format!("{base}/ld")).unwrap();
	symlink("f", format!("{base}/lf")).unwrap();
	symlink("nope", format!("{base}/dang")).unwrap();

	let check = |p: &[u8]| {
		assert_eq!(c_llstat(p), rust_llstat(p), "{}", show(p));
	};
	for p in [&b""[..], b"/", b"//", b"///", b".", b"./", b"/tmp//"] {
		check(p);
	}
	let names: &[&[u8]] =
		&[b"f", b"d", b"ld", b"lf", b"dang", b"nope", b"", b".", b".."];
	let mut rng = Rng::new(0x115a);
	let mut seen_ok = 0;
	for _ in 0..iters() / 20 {
		let mut p = base.as_bytes().to_vec();
		for _ in 0..1 + rng.below(3) {
			p.extend(std::iter::repeat_n(b'/', 1 + rng.below(2)));
			p.extend_from_slice(names[rng.below(names.len())]);
		}
		p.extend(std::iter::repeat_n(b'/', rng.below(3)));
		seen_ok += usize::from(c_llstat(&p).is_ok());
		check(&p);
	}
	std::fs::remove_dir_all(&base).unwrap();
	assert!(seen_ok > iters() / 200, "only {seen_ok} paths existed");
}
