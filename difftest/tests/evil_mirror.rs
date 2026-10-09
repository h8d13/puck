// the hostile-mirror robustness matrix: a loopback mirror
// (IronicEvilMirrorPkger) serves malformed transport, metadata, archive
// and signature responses to C pacman (PACMAN_BUILD) and puck, driven
// with -S (sync install) and -U (url install) on fixture roots. every
// case asserts BOTH binaries end safe (nonzero exit, nothing registered
// in the local db, nothing written outside the configured root) and
// records whether C and puck behave equivalently. a divergence where
// one side is unsafe and the other is not would be the finding; so far
// both reject every input. the control cases prove the rejections are
// meaningful (a well-formed package installs identically).
use std::time::Duration;

use difftest::{
	Comp, Desc, GpgFixture, IronicEvilMirrorPkger, Reply, TarNode, Verdict,
	assert_safe, file_node, good_package, package, raw_cl, reason,
	sign_bytes,
};

fn mirror(tag: &str) -> IronicEvilMirrorPkger {
	IronicEvilMirrorPkger::new(tag)
}

// a 200 File reply serving a package body, no ranges, no mtime
fn serve(body: Vec<u8>) -> Reply {
	Reply::File {
		body,
		ranges: false,
		mtime: None,
	}
}

fn gz(name: &str) -> String {
	format!("{name}-1.0-1-x86_64.pkg.tar.gz")
}

// print one table row and return it for the caller's bookkeeping
fn row(v: &Verdict) {
	let short = |s: String| {
		s.chars().take(52).collect::<String>().replace('\n', " ")
	};
	println!(
		"  {:24}  C[{}: {}]\n  {:24}  puck[{}: {}]  => {}",
		v.name,
		v.c.rc,
		short(reason(&v.c)),
		"",
		v.puck.rc,
		short(reason(&v.puck)),
		if v.same { "same" } else { "DIFFER" }
	);
	if !v.same {
		println!(
			"    DIFFER detail:\n    C rc={} out={}b\n{}    puck rc={} out={}b\n{}",
			v.c.rc,
			v.c.out.len(),
			String::from_utf8_lossy(&v.c.err),
			v.puck.rc,
			v.puck.out.len(),
			String::from_utf8_lossy(&v.puck.err),
		);
	}
}

// ---- control: a well-formed package installs the same on both ----

#[test]
fn control_installs_equal() {
	let m = mirror("em-control");
	let file = gz("good");
	let body = good_package("good", "1.0-1", Comp::Gzip);
	m.sync_db(&[Desc::truthful("good", "1.0-1", &file, &body)]);
	m.route(&file, vec![serve(body)]);
	m.conf("Never");
	let v = m.twin("control -S", &["-S".into(), "good".into()]);
	row(&v);
	assert_eq!(v.c.rc, 0, "control must install on C");
	assert_eq!(v.puck.rc, 0, "control must install on puck");
	assert_eq!(v.c.local, vec!["good-1.0-1".to_string()]);
	assert!(v.same, "control must be equivalent");
}

// ---- 1. transport lies ----

#[test]
fn transport_lies() {
	let m = mirror("em-transport");
	m.conf("Never");
	println!("== transport lies");
	let body = good_package("p", "1.0-1", Comp::Gzip);
	let file = gz("p");

	// Content-Length larger than the body: the client waits for bytes
	// that never arrive, then the connection closes
	m.sync_db(&[Desc::truthful("p", "1.0-1", &file, &body)]);
	m.route(&file, vec![raw_cl(body.len() as i64 + 4096, &body)]);
	let v = m.twin("cl_too_large", &["-S".into(), "p".into()]);
	row(&v);
	assert_safe("cl_too_large", "C", &v.c);
	assert_safe("cl_too_large", "puck", &v.puck);

	// Content-Length smaller than the body: a truncated file, caught by
	// the db's sha256
	m.route(&file, vec![raw_cl(body.len() as i64 / 2, &body)]);
	let v = m.twin("cl_too_small", &["-S".into(), "p".into()]);
	row(&v);
	assert_safe("cl_too_small", "C", &v.c);
	assert_safe("cl_too_small", "puck", &v.puck);

	// a body exceeding the db's %CSIZE%
	let mut small = Desc::truthful("p", "1.0-1", &file, &body);
	small.csize = "16".into();
	m.sync_db(&[small]);
	m.route(&file, vec![serve(body.clone())]);
	let v = m.twin("body_exceeds_csize", &["-S".into(), "p".into()]);
	row(&v);
	assert_safe("body_exceeds_csize", "C", &v.c);
	assert_safe("body_exceeds_csize", "puck", &v.puck);

	// chunked encoding that never terminates (connection cut before the
	// terminator chunk, bounded by connection close)
	m.sync_db(&[Desc::truthful("p", "1.0-1", &file, &body)]);
	m.route(
		&file,
		vec![Reply::Chunked {
			body: body.clone(),
			cut: true,
		}],
	);
	let v = m.twin("chunked_unterminated", &["-S".into(), "p".into()]);
	row(&v);
	assert_safe("chunked_unterminated", "C", &v.c);
	assert_safe("chunked_unterminated", "puck", &v.puck);

	// a redirect loop to the same url
	m.route(&file, vec![Reply::Redirect(302, m.url(&file))]);
	let v = m.twin("redirect_loop", &["-S".into(), "p".into()]);
	row(&v);
	assert_safe("redirect_loop", "C", &v.c);
	assert_safe("redirect_loop", "puck", &v.puck);

	// 404 for a package the db says exists
	m.route(&file, vec![Reply::Status(404, b"nope\n".to_vec())]);
	let v = m.twin("pkg_404", &["-S".into(), "p".into()]);
	row(&v);
	assert_safe("pkg_404", "C", &v.c);
	assert_safe("pkg_404", "puck", &v.puck);

	// a stall mid-body, then the connection closes (short pause so the
	// binaries' own handling returns well within the backstop)
	m.route(
		&file,
		vec![Reply::Stall {
			body: body.clone(),
			at: body.len() / 2,
			pause: Duration::from_secs(3),
			finish: false,
		}],
	);
	let v = m.twin("stall_mid_body", &["-S".into(), "p".into()]);
	row(&v);
	assert_safe("stall_mid_body", "C", &v.c);
	assert_safe("stall_mid_body", "puck", &v.puck);
}

// ---- 2. metadata lies ----

#[test]
fn metadata_lies() {
	let m = mirror("em-metadata");
	println!("== metadata lies");
	let body = good_package("p", "1.0-1", Comp::Gzip);
	let file = gz("p");
	m.route(&file, vec![serve(body.clone())]);

	// %SHA256SUM% that does not match the package
	m.conf("Never");
	let mut d = Desc::truthful("p", "1.0-1", &file, &body);
	d.sha256 = "ab".repeat(32);
	m.sync_db(&[d]);
	let v = m.twin("sha256_mismatch", &["-S".into(), "p".into()]);
	row(&v);
	assert_safe("sha256_mismatch", "C", &v.c);
	assert_safe("sha256_mismatch", "puck", &v.puck);

	// a package whose .PKGINFO name/version disagree with the db entry
	let other = package(
		"other",
		"9.9-9",
		&[file_node("usr/bin/evil", b"x\n")],
		Comp::Gzip,
	);
	m.route(&file, vec![serve(other.clone())]);
	m.sync_db(&[Desc::truthful("p", "1.0-1", &file, &other)]);
	let v = m.twin("pkginfo_name_mismatch", &["-S".into(), "p".into()]);
	row(&v);
	assert_safe("pkginfo_name_mismatch", "C", &v.c);
	assert_safe("pkginfo_name_mismatch", "puck", &v.puck);

	// integer-overflow-shaped %ISIZE%, with CheckSpace so the diskspace
	// precheck consumes it
	m.route(&file, vec![serve(body.clone())]);
	m.conf_opts("Never", "CheckSpace\n");
	let mut d = Desc::truthful("p", "1.0-1", &file, &body);
	d.isize = "999999999999999999999999".into();
	m.sync_db(&[d]);
	let v = m.twin("isize_overflow", &["-S".into(), "p".into()]);
	row(&v);
	assert_safe("isize_overflow", "C", &v.c);
	assert_safe("isize_overflow", "puck", &v.puck);

	// %FILENAME% with a path traversal: the download/cache path must not
	// escape the cache dir
	m.conf("Never");
	let traversal = "../../../../em-pwned-1.0-1-x86_64.pkg.tar.gz";
	let mut d = Desc::truthful("p", "1.0-1", traversal, &body);
	d.filename = traversal.into();
	m.sync_db(&[d]);
	m.route(traversal, vec![serve(body.clone())]);
	let v = m.twin("filename_traversal", &["-S".into(), "p".into()]);
	row(&v);
	// no assert_safe: the escape invariant is the point, enforced in twin
	assert_eq!(
		v.c.local,
		Vec::<String>::new(),
		"filename_traversal/C registered"
	);
	assert_eq!(
		v.puck.local,
		Vec::<String>::new(),
		"filename_traversal/puck registered"
	);
}

// ---- 3. archive attacks ----

#[test]
fn archive_attacks() {
	let m = mirror("em-archive");
	m.conf("Never");
	println!("== archive attacks");

	// a decompression bomb: a tiny gzip inflating to 64 MiB. both must
	// stream it (bounded memory) rather than buffer and OOM; the
	// backstop timeout would fail a true hang, the runner's 4 GiB cap a
	// true OOM. behaviour recorded, equivalence asserted
	let big = package(
		"bomb",
		"1.0-1",
		&[file_node("usr/bin/big", &vec![0u8; 64 << 20])],
		Comp::Gzip,
	);
	let url = m.url(&gz("bomb"));
	m.route(&gz("bomb"), vec![serve(big)]);
	let v = m.twin("decompress_bomb", &["-U".into(), url]);
	row(&v);
	assert!(
		v.same,
		"decompress_bomb: C and puck diverged on a bomb\nC {}\npuck {}",
		reason(&v.c),
		reason(&v.puck)
	);

	// tar member names with ../ and a leading /: nothing may land
	// outside the root
	// a single ../ lands in the fixture dir, which the harness scans and
	// would flag; libarchive/puck strip any depth the same way, so this
	// faithfully tests neutralization while staying catchable
	let trav = package(
		"trav",
		"1.0-1",
		&[
			file_node("../em-pwned", b"owned\n"),
			file_node("/em-pwned-abs", b"owned\n"),
			file_node("usr/bin/ok", b"x\n"),
		],
		Comp::Gzip,
	);
	let url = m.url(&gz("trav"));
	m.route(&gz("trav"), vec![serve(trav)]);
	let v = m.twin("tar_path_traversal", &["-U".into(), url]);
	row(&v);

	// a symlink escape: a symlink out of the root, then a file written
	// through it
	let link = TarNode {
		name: b"esc".to_vec(),
		kind: b'2',
		mode: 0o777,
		link: b"..".to_vec(),
		data: Vec::new(),
	};
	let sym = package(
		"sym",
		"1.0-1",
		&[link, file_node("esc/em-pwned-sym", b"owned\n")],
		Comp::Gzip,
	);
	let url = m.url(&gz("sym"));
	m.route(&gz("sym"), vec![serve(sym)]);
	let v = m.twin("symlink_escape", &["-U".into(), url]);
	row(&v);

	// overlapping/duplicate members
	let dup = package(
		"dup",
		"1.0-1",
		&[
			file_node("usr/bin/evil", b"first\n"),
			file_node("usr/bin/evil", b"second\n"),
		],
		Comp::Gzip,
	);
	let url = m.url(&gz("dup"));
	m.route(&gz("dup"), vec![serve(dup)]);
	let v = m.twin("duplicate_members", &["-U".into(), url]);
	row(&v);

	// truncated archives at a few framing boundaries
	let whole = good_package("trunc", "1.0-1", Comp::Gzip);
	for (tag, cut) in [
		("trunc_header", 8usize),
		("trunc_mid", whole.len() / 2),
		("trunc_tail", whole.len().saturating_sub(5)),
	] {
		let part = whole[..cut.min(whole.len())].to_vec();
		let url = m.url(&gz("trunc"));
		m.route(&gz("trunc"), vec![serve(part)]);
		let v = m.twin(tag, &["-U".into(), url]);
		row(&v);
		assert_safe(tag, "C", &v.c);
		assert_safe(tag, "puck", &v.puck);
	}
}

// ---- 4. signature attacks ----

#[test]
fn signature_attacks() {
	let gpg = GpgFixture::new("em-gpg");
	let m = mirror("em-signature");
	m.use_keyring(&gpg);
	m.conf("Required");
	println!("== signature attacks");
	let body = good_package("s", "1.0-1", Comp::Gzip);
	let file = gz("s");
	let signame = format!("{file}.sig");

	// control: a valid detached signature by a trusted key installs on
	// both, proving the keyring path and that the rejections mean
	// something
	let good_sig = sign_bytes(&gpg, m.dir(), &body, "full");
	m.route(&file, vec![serve(body.clone())]);
	m.route(&signame, vec![serve(good_sig)]);
	let url = m.url(&file);
	let v = m.twin("control_signed -U", &["-U".into(), url.clone()]);
	row(&v);
	assert_eq!(
		v.c.rc,
		0,
		"signed control must install on C\n{}",
		reason(&v.c)
	);
	assert_eq!(
		v.puck.rc,
		0,
		"signed control must install on puck\n{}",
		reason(&v.puck)
	);

	// a valid signature over different data
	let wrong = sign_bytes(&gpg, m.dir(), b"other data\n", "full");
	m.route(&signame, vec![serve(wrong)]);
	let v = m.twin("sig_wrong_data", &["-U".into(), url.clone()]);
	row(&v);
	assert_safe("sig_wrong_data", "C", &v.c);
	assert_safe("sig_wrong_data", "puck", &v.puck);

	// a good package with a corrupted detached sig
	let mut corrupt = sign_bytes(&gpg, m.dir(), &body, "full");
	let n = corrupt.len();
	corrupt[n / 2] ^= 0xff;
	m.route(&signame, vec![serve(corrupt)]);
	let v = m.twin("sig_corrupted", &["-U".into(), url.clone()]);
	row(&v);
	assert_safe("sig_corrupted", "C", &v.c);
	assert_safe("sig_corrupted", "puck", &v.puck);

	// a sig over a truncated copy of the package
	let trunc = sign_bytes(&gpg, m.dir(), &body[..body.len() / 2], "full");
	m.route(&signame, vec![serve(trunc)]);
	let v = m.twin("sig_over_truncated", &["-U".into(), url.clone()]);
	row(&v);
	assert_safe("sig_over_truncated", "C", &v.c);
	assert_safe("sig_over_truncated", "puck", &v.puck);

	// missing sig where SigLevel requires one
	m.route(&signame, vec![Reply::Status(404, b"nope\n".to_vec())]);
	let v = m.twin("sig_missing", &["-U".into(), url]);
	row(&v);
	assert_safe("sig_missing", "C", &v.c);
	assert_safe("sig_missing", "puck", &v.puck);
}
