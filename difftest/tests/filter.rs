// alpm_core::internals::filter against libarchive's read filters as pacman sets them
// up (archive_read_support_filter_all), read through the raw format: the
// bytes delivered, whether and where the open or a read fails, libarchive's
// text where the port has it (compress, lzma, lzip, lz4, programs,
// stacking; alpm-compress's decoders have their own), and the top filter
use std::io::Write;

use difftest::{
	Rng, c_filter_write, filter_compare as compare,
	filter_compare_file as compare_file, filter_slowest, iters,
};

// payload: text and random bytes, compressible and not
fn payload(rng: &mut Rng, len: usize) -> Vec<u8> {
	let mut v = Vec::with_capacity(len);
	while v.len() < len {
		if rng.below(2) == 0 {
			let word =
				format!("line {} of {}\n", rng.below(500), len);
			v.extend_from_slice(word.as_bytes());
		} else {
			let n = rng.below(300);
			v.extend((0..n).map(|_| rng.next_u64() as u8));
		}
	}
	v.truncate(len);
	v
}

// the streams to check: (what, stream)
fn streams(data: &[u8]) -> Vec<(String, Vec<u8>)> {
	let mut v = Vec::new();
	let w = |name: &str, opts: &str| write(name, opts, data);
	for name in ["gzip", "bzip2", "xz", "zstd", "compress", "lzma", "lzip"]
	{
		v.push((name.to_string(), w(name, "")));
	}
	for opts in [
		"",
		"lz4:block-size=4",
		"lz4:block-size=5,lz4:block-dependence",
		"lz4:block-size=4,lz4:block-dependence,lz4:block-checksum",
		"lz4:block-size=6,lz4:!stream-checksum",
		"lz4:block-size=7,lz4:block-checksum,lz4:!stream-checksum",
	] {
		v.push((format!("lz4 {opts}"), w("lz4", opts)));
	}
	v.push(("lz4 legacy".into(), lz4_legacy(data)));
	// stacked: libarchive decodes the outer stream, then bids again
	let gz = w("gzip", "");
	v.push(("gzip-in-gzip".into(), c_filter_write("gzip", "", &gz)));
	let xz = w("xz", "");
	v.push(("xz-in-lz4".into(), c_filter_write("lz4", "", &xz)));
	let z = w("compress", "");
	v.push(("compress-in-lzip".into(), c_filter_write("lzip", "", &z)));
	v
}

// libarchive's write filter; an empty lz4 stream from lz4_flex: the lz4
// writer crashes closing a stream with no data
fn write(name: &str, opts: &str, data: &[u8]) -> Vec<u8> {
	if name != "lz4" || !data.is_empty() {
		return c_filter_write(name, opts, data);
	}
	let enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
	enc.finish().unwrap()
}

// lz4 -l: legacy frames
fn lz4_legacy(data: &[u8]) -> Vec<u8> {
	let info = lz4_flex::frame::FrameInfo::new().legacy_frame(true);
	let mut enc = lz4_flex::frame::FrameEncoder::with_frame_info(
		info,
		Vec::new(),
	);
	enc.write_all(data).unwrap();
	enc.finish().unwrap()
}

#[test]
fn whole_streams() {
	let mut rng = Rng::new(0x0f11_7e75);
	for len in [0, 1, 100, 70_000, 300_000] {
		let data = payload(&mut rng, len);
		for (what, s) in streams(&data) {
			let what = format!("{what} of {len}");
			let c = compare(&what, &s);
			// libarchive's compress writer puts out one code for no
			// data: a nul byte
			if !(what.starts_with("compress") && len == 0) {
				assert_eq!(c.data, data, "{what}: decoded");
			}
			compare_file(&what, &s);
		}
	}
}

// cut points: every byte of the head and tail, spread and random ones
fn cuts(len: usize, rng: &mut Rng) -> Vec<usize> {
	let mut v: Vec<usize> = (0..len.min(40)).collect();
	v.extend((len.saturating_sub(40))..len);
	v.extend((1..64).map(|i| len * i / 64));
	v.extend((0..16).map(|_| rng.below(len.max(1))));
	v
}

#[test]
fn cut_streams() {
	let mut rng = Rng::new(0x0c07_5eed);
	let data = payload(&mut rng, 200_000);
	let mut kinds = std::collections::BTreeSet::new();
	for (what, s) in streams(&data) {
		for n in cuts(s.len(), &mut rng) {
			let c = compare(&format!("{what} cut at {n}"), &s[..n]);
			kinds.insert((
				c.open_error.is_some(),
				c.read_error.is_some(),
			));
		}
	}
	eprintln!("slowest:\n{}", filter_slowest().join("\n"));
	// open failures, read failures and clean shorter streams all seen
	assert_eq!(kinds.len(), 3, "{kinds:?}");
}

// bytes changed after the magic: the decoders' corrupt-data paths. lz4
// blocks without a checksum are left alone (liblz4 and lz4_flex differ on
// invalid blocks)
#[test]
fn corrupt_streams() {
	let mut rng = Rng::new(0x0bad_da7a);
	let data = payload(&mut rng, 40_000);
	let lz4_safe =
		"lz4:block-size=4,lz4:block-dependence,lz4:block-checksum";
	let mut sets = Vec::new();
	for name in ["gzip", "bzip2", "xz", "zstd", "compress", "lzma", "lzip"]
	{
		sets.push((name.to_string(), c_filter_write(name, "", &data)));
	}
	sets.push((
		"lz4 checked".into(),
		c_filter_write("lz4", lz4_safe, &data),
	));
	let mut compared = 0;
	for (what, s) in &sets {
		for _ in 0..(iters() / 100).max(100) {
			let mut m = s.clone();
			for _ in 0..1 + rng.below(3) {
				// the header region or anywhere
				let at = match rng.below(2) {
					0 => 3 + rng.below(20.min(m.len() - 3)),
					_ => 3 + rng.below(m.len() - 3),
				};
				m[at] = rng.next_u64() as u8;
			}
			compare(&format!("{what} corrupt"), &m);
			compared += 1;
		}
	}
	eprintln!("slowest:\n{}", filter_slowest().join("\n"));
	assert!(compared >= 800);
}

// garbage after a magic, magics alone, several members and frames,
// trailing data, skippable frames
#[test]
fn odd_streams() {
	let mut rng = Rng::new(0x00dd_57e4);
	let data = payload(&mut rng, 5000);
	let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
	let magics: [&[u8]; 14] = [
		b"\x1f\x9d\x90",
		b"\x1f\x9d\x10",
		b"\x1f\x9d\x9f",
		b"\x5d\x00\x00\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff",
		b"LZIP\x01\x0c",
		b"LZIP\x00\x7d",
		b"\x04\x22\x4d\x18\x64\x40\xa7",
		b"\x04\x22\x4d\x18\x44\x70\x1d",
		b"\x02\x21\x4c\x18",
		b"\x50\x2a\x4d\x18\x04\x00\x00\x00abcd\x02\x21\x4c\x18",
		b"\x89LZO\x00\r\n\x1a\n",
		b"LRZI\x00\x06",
		b"GRZipII\x00\x02\x04:)",
		b"\x50\x2a\x4d\x18\x00\x00\x00\x00\x28\xb5\x2f\xfd",
	];
	for m in magics {
		cases.push((format!("magic {m:02x?}"), m.to_vec()));
		for k in [1, 8, 40, 300] {
			let mut v = m.to_vec();
			v.extend((0..k).map(|_| rng.next_u64() as u8));
			cases.push((
				format!("magic {m:02x?} + {k}"),
				v.clone(),
			));
			v.resize(v.len() + 20, 0);
			cases.push((format!("magic {m:02x?} + {k} + nuls"), v));
		}
	}
	for name in [
		"gzip", "bzip2", "xz", "zstd", "compress", "lzma", "lzip",
		"lz4",
	] {
		let s = c_filter_write(name, "", &data);
		let mut two = s.clone();
		two.extend_from_slice(&s);
		cases.push((format!("{name} twice"), two));
		for tail in [
			&b"x"[..],
			b"LZIP",
			b"LZIP\x02\x0c",
			b"LZIP\x01\x0cjunk",
			&[0; 64],
		] {
			let mut t = s.clone();
			t.extend_from_slice(tail);
			cases.push((format!("{name} + {tail:02x?}"), t));
		}
	}
	let lz4 = c_filter_write("lz4", "", &data);
	let mut skip = b"\x5a\x2a\x4d\x18\x03\x00\x00\x00abc".to_vec();
	skip.extend_from_slice(&lz4);
	cases.push(("lz4 after a skippable frame".into(), skip.clone()));
	let mut mid = lz4.clone();
	mid.extend_from_slice(&skip);
	cases.push(("lz4, skippable, lz4".into(), mid));
	let mut far = lz4.clone();
	far.extend_from_slice(b"\x50\x2a\x4d\x18\xff\xff\x00\x00");
	cases.push(("lz4 + skippable past the end".into(), far));
	let legacy = lz4_legacy(&data);
	let mut both = legacy.clone();
	both.extend_from_slice(&lz4);
	cases.push(("lz4 legacy then frame".into(), both));
	// an empty frame first ends the stream (lz4_filter_read)
	let empty = write("lz4", "", b"");
	let mut e = empty.clone();
	e.extend_from_slice(&lz4);
	cases.push(("lz4 empty frame then data".into(), e));
	// layers around MAX_NUMBER_FILTERS: its rounds end with 25 filters
	// even when no bidder would take the 25th's output
	let mut deep = data.clone();
	for n in 1..=27 {
		deep = c_filter_write("gzip", "", &deep);
		if n >= 24 {
			cases.push((format!("{n} gzip layers"), deep.clone()));
		}
	}
	// trailers changed byte by byte: lzip's crc32 and sizes, gzip's
	// unchecked crc32 and size, xz's index and footer
	for name in ["gzip", "xz", "lzip", "lzma", "bzip2", "zstd", "lz4"] {
		let s = c_filter_write(name, "", &data);
		for back in 1..=24.min(s.len()) {
			let mut m = s.clone();
			let at = m.len() - back;
			m[at] ^= 0x41;
			cases.push((format!("{name} trailer byte -{back}"), m));
		}
	}
	for (what, input) in &cases {
		compare(what, input);
	}
}

// the program filters need their program: none of lzop, lrzip, grzip is
// installed here, libarchive's child fails to exec it
#[test]
fn missing_programs() {
	for (what, m) in [
		("lzop", &b"\x89LZO\x00\r\n\x1a\n\x10\x30"[..]),
		("lrzip", b"LRZI\x00\x06\x00\x00\x00\x00"),
		("grzip", b"GRZipII\x00\x02\x04:)\x00"),
	] {
		let c = compare(what, m);
		assert_eq!(
			c.open_error.as_deref(),
			Some(&b"Child process exited with status 254"[..]),
			"{what}"
		);
	}
}
