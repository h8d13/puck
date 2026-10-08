// libarchive's program filters (lrzip, lzop, grzip) with their programs
// present: stand-ins on PATH that check libarchive's arguments, drop the
// format's magic and gunzip the rest, or fail in the ways a program can
// (exit status, a signal, exiting without reading). one test in its own
// binary: PATH is changed for the whole process, the C's execvp and the
// port's Command both look it up
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use difftest::{Comp, Rng, TempRoot, compress_bytes, filter_compare};

// (program, its arguments, the magic the bidder takes)
const PROGRAMS: [(&str, &str, &[u8]); 3] = [
	("lzop", "-d", b"\x89LZO\x00\r\n\x1a\n"),
	("lrzip", "-d -q", b"LRZI\x00\x06"),
	("grzip", "-d", b"GRZipII\x00\x02\x04:)"),
];

// a stand-in: behaviour by the byte after the magic
fn script(args: &str, magic: usize) -> String {
	format!("#!/bin/sh\n\
		[ \"$*\" = \"{args}\" ] || exit 64\n\
		head -c {magic} > /dev/null\n\
		mode=$(head -c 1)\n\
		case $mode in\n\
		g) exec gzip -dc ;;\n\
		e) exit 3 ;;\n\
		t) kill -TERM $$ ;;\n\
		p) kill -PIPE $$ ;;\n\
		*) cat > /dev/null; exit 0 ;;\n\
		esac\n")
}

#[test]
fn programs() {
	let t = TempRoot::new("filter-programs");
	let bin = std::path::PathBuf::from(std::ffi::OsString::from(
		String::from_utf8(t.path("bin")).unwrap(),
	));
	fs::create_dir(&bin).unwrap();
	for (name, args, magic) in PROGRAMS {
		let p = bin.join(name);
		let mut f = fs::File::create(&p).unwrap();
		f.write_all(script(args, magic.len()).as_bytes()).unwrap();
		fs::set_permissions(&p, fs::Permissions::from_mode(0o755))
			.unwrap();
	}
	let path =
		format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
	// SAFETY: the only test of this binary, set before anything else
	// reads the environment or spawns
	unsafe { std::env::set_var("PATH", path) };

	let mut rng = Rng::new(0x9e0_9a4);
	let data: Vec<u8> = (0..300_000)
		.map(|i| {
			if i % 7 == 0 {
				rng.next_u64() as u8
			} else {
				b'a'
			}
		})
		.collect();
	let gz = compress_bytes(Comp::Gzip, &data, false);
	let mut kinds = std::collections::BTreeSet::new();
	for (name, _, magic) in PROGRAMS {
		let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
		let good = [magic, b"g", &gz].concat();
		cases.push(("gunzipped".into(), good.clone()));
		for n in [
			magic.len() + 1,
			magic.len() + 30,
			good.len() / 3,
			good.len() - 4,
		] {
			cases.push((format!("cut at {n}"), good[..n].to_vec()));
		}
		let mut bad = good.clone();
		bad[magic.len() + 40] ^= 0x55;
		cases.push(("corrupt".into(), bad));
		let big = vec![b'x'; 1 << 20];
		for (mode, what) in [
			(b'e', "exits 3"),
			(b't', "SIGTERM"),
			(b'p', "SIGPIPE"),
			(b'z', "no output"),
		] {
			cases.push((
				what.into(),
				[magic, &[mode], &big].concat(),
			));
		}
		for (what, input) in cases {
			let c = filter_compare(
				&format!("{name} {what}"),
				&input,
			);
			kinds.insert((
				c.open_error.is_some(),
				c.read_error.is_some(),
			));
		}
	}
	assert!(kinds.len() >= 2, "{kinds:?}");
}
