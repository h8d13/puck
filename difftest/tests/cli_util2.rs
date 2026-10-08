// pacman_cli::util (transaction summary, --print-format, optdepends,
// select_display, prompts, rmrf) against src/pacman/util.c, both sides in
// C.UTF-8 with TZ=UTC. the C runs on a real handle (UtilWorld) whose
// local cache, dbs, server and cache dirs the Rust handle mirrors
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use alpm_core::be_local::INFRQ_DSIZE;
use alpm_core::deps::{Depend, dep_from_string};
use alpm_core::handle::Handle;
use alpm_core::package::{Package, PkgFrom};
use alpm_core::util::hash_sdbm;
use difftest::{
	CACHED, CIo, CORE_SERVER, Pty, Rng, UtilWorld, c_colon_printf,
	c_multiselect_question, c_question, c_rmrf, c_select_question, iters,
	run_tty_probe, utc_date, widths_agree,
};
use pacman_cli::conf::Config;
use pacman_cli::pacman::{
	PM_OP_QUERY, PM_OP_REMOVE, PM_OP_SYNC, PM_OP_UPGRADE,
};
use pacman_cli::util::{
	ColStr, DbPkg, Output, Term, TransTargets, colon_printf,
	display_new_optdepends, display_optdepends, display_targets,
	multiselect_question, noyes, print_packages, rmrf, select_display,
	select_question, yesno,
};

fn show(s: &[u8]) -> String {
	format!("{:?}", String::from_utf8_lossy(s))
}

fn pick<'a>(rng: &mut Rng, from: &[&'a [u8]]) -> &'a [u8] {
	from[rng.below(from.len())]
}

fn text(rng: &mut Rng, tokens: &[&[u8]], max: usize) -> Vec<u8> {
	(0..rng.below(max))
		.flat_map(|_| pick(rng, tokens))
		.copied()
		.collect()
}

const COLORS: ColStr<'static> = ColStr {
	colon: b"\x1b[1;34m::\x1b[0;1m ",
	title: b"\x1b[1m",
	repo: b"\x1b[1;35m",
	version: b"\x1b[1;32m",
	groups: b"\x1b[1;34m",
	meta: b"\x1b[1;36m",
	warn: b"\x1b[1;33m",
	err: b"\x1b[1;31m",
	faint: b"\x1b[2m",
	nocolor: b"\x1b[0m",
};

fn config(rng: &mut Rng) -> Config {
	let mut c = Config::new();
	c.colstr = match rng.below(2) {
		0 => ColStr {
			colon: b":: ",
			..ColStr::default()
		},
		_ => COLORS,
	};
	if rng.below(8) == 0 {
		c.logmask = 0;
	}
	c
}

// stdin as a pipe, stdout no terminal: what the C sees under difftest
fn term(input: &[u8]) -> Term<&[u8]> {
	Term::new(input, false, false)
}

fn check_io(what: &str, c: (i32, CIo), r: (i32, Output, usize)) {
	assert_eq!(
		(
			c.0,
			show(&c.1.out.stdout),
			show(&c.1.out.stderr),
			c.1.consumed
		),
		(r.0, show(&r.1.stdout), show(&r.1.stderr), r.2),
		"{what}"
	);
}

// answers: the words in several cases, near misses, whitespace the trim
// takes, invalid and non-ASCII UTF-8 (U+0130 lowers to i), nul, and
// runs that push a line past the 31 bytes of the buffer
const ANSWERS: &[&[u8]] = &[
	b"y",
	b"Y",
	b"yes",
	b"YES",
	b"yEs",
	b"n",
	b"N",
	b"no",
	b"nO",
	b"ye",
	b"yess",
	b" ",
	b"\t",
	b"\n",
	b"\n",
	b"\r",
	b"\x0b",
	b"x",
	"\u{e9}".as_bytes(),
	"Y\u{301}".as_bytes(),
	"\u{130}".as_bytes(),
	"\u{ff39}".as_bytes(),
	b"\xff",
	b"\xc3",
	b"\0",
	b"abcdefghijklmnopqrstuvwxyz",
];

#[test]
fn question_answers() {
	let mut rng = Rng::new(0x9e5);
	let fixed: &[&[u8]] = &[
		b"",
		b"\n",
		b"y\n",
		b"YES\n",
		b"no\n",
		b" y \n",
		b"y",
		b"yes please\n",
		b"\xc3\n",
		b"Y\xc3\n",
		b"y\0es\n",
		b"0123456789012345678901234567890y\n",
	];
	let mut inputs: Vec<Vec<u8>> =
		fixed.iter().map(|s| s.to_vec()).collect();
	for _ in 0..iters() {
		inputs.push(text(&mut rng, ANSWERS, 6));
	}
	for (i, input) in inputs.iter().enumerate() {
		let mut cfg = config(&mut rng);
		cfg.noconfirm = u16::from(rng.below(6) == 0);
		let preset = i % 2 == 0;
		let msg = text(
			&mut rng,
			&[b"Proceed", b" ", b"%", "\u{e9}".as_bytes()],
			4,
		);
		let c = c_question(&cfg, preset, &msg, input);
		let mut out = Output::default();
		let mut t = term(input);
		let r = match preset {
			true => yesno(&mut out, &cfg, &mut t, &msg),
			false => noyes(&mut out, &cfg, &mut t, &msg),
		};
		let consumed = input.len() - t.stdin.len();
		check_io(
			&format!(
				"{} preset {preset} noconfirm {}",
				show(input),
				cfg.noconfirm
			),
			c,
			(i32::from(r), out, consumed),
		);
	}
}

const NUMBERS: &[&[u8]] = &[
	b"1",
	b"2",
	b"3",
	b"7",
	b"12",
	b"0",
	b"-",
	b"+",
	b" ",
	b"\t",
	b"\n",
	b"\n",
	b"x",
	b"^",
	b",",
	b"2147483648",
	b"4294967297",
	b"99999999999999999999",
	b"\0",
];

#[test]
fn select_question_answers() {
	let mut rng = Rng::new(0x5e1);
	for _ in 0..iters() {
		let mut cfg = config(&mut rng);
		cfg.noconfirm = u16::from(rng.below(8) == 0);
		let count = rng.below(10) as i32;
		let input = text(&mut rng, NUMBERS, 8);
		let c = c_select_question(&cfg, count, &input);
		let mut out = Output::default();
		let mut t = term(&input);
		let r = select_question(&mut out, &cfg, &mut t, count);
		let consumed = input.len() - t.stdin.len();
		check_io(
			&format!("{} count {count}", show(&input)),
			c,
			(r, out, consumed),
		);
	}
}

const SELECTIONS: &[&[u8]] = &[
	b"1",
	b"2",
	b"3",
	b"5",
	b"12",
	b"0",
	b"1-3",
	b"2-1",
	b"3-",
	b"-2",
	b"^",
	b"^2",
	b"^1-4",
	b"-",
	b",",
	b",",
	b" ",
	b" ",
	b"\t",
	b"\n",
	b"x",
	b"+3",
	b"99999999999",
	b"\0",
];

// a selection line, sometimes padded around the buffer sizes (63, 127)
fn selection(rng: &mut Rng) -> Vec<u8> {
	let mut s = text(rng, SELECTIONS, 8);
	if rng.below(4) == 0 {
		let fill = b" ,1"[rng.below(3)];
		let n = [62, 63, 64, 126, 127, 128, 200][rng.below(7)];
		let at = rng.below(s.len() + 1);
		s.splice(at..at, std::iter::repeat_n(fill, n - s.len().min(n)));
	}
	if rng.below(2) == 0 {
		s.push(b'\n');
		s.extend(text(rng, SELECTIONS, 4));
	}
	s
}

fn check_multiselect(cfg: &Config, count: usize, input: &[u8]) {
	let (cret, carray, cio) = c_multiselect_question(cfg, count, input);
	let mut out = Output::default();
	let mut t = term(input);
	let mut array = vec![false; count];
	let r = multiselect_question(&mut out, cfg, &mut t, &mut array);
	let consumed = input.len() - t.stdin.len();
	let what = format!("{} count {count}", show(input));
	assert_eq!(carray, array, "{what}");
	check_io(&what, (cret, cio), (r, out, consumed));
}

#[test]
fn multiselect_question_answers() {
	let mut rng = Rng::new(0x3a5);
	let cfg = Config::new();
	// end of input right after a chunk that filled the buffer
	for n in [62, 63, 64, 126, 127, 128] {
		let line = vec![b','; n];
		check_multiselect(&cfg, 4, &line);
		let mut nl = line.clone();
		nl.push(b'\n');
		check_multiselect(&cfg, 4, &nl);
	}
	// an all-whitespace first token keeps the selection
	check_multiselect(&cfg, 4, b",\t,3\n");
	check_multiselect(&cfg, 4, b"3\n");
	for _ in 0..iters() {
		let mut cfg = config(&mut rng);
		cfg.noconfirm = u16::from(rng.below(10) == 0);
		let count = rng.below(14);
		let input = selection(&mut rng);
		check_multiselect(&cfg, count, &input);
	}
}

#[test]
fn colon_printf_message() {
	let mut rng = Rng::new(0xc01);
	for _ in 0..iters() / 100 {
		let cfg = config(&mut rng);
		let msg =
			text(&mut rng, &[b"Repository ", b"x", b"\n", b"%"], 4);
		let mut out = Vec::new();
		colon_printf(&mut out, &cfg.colstr, &msg);
		assert_eq!(c_colon_printf(&cfg, &msg), out, "{}", show(&msg));
	}
}

fn tmp(name: &str) -> PathBuf {
	static N: AtomicUsize = AtomicUsize::new(0);
	let n = N.fetch_add(1, Ordering::Relaxed);
	std::env::temp_dir().join(format!(
		"difftest-cli-util2-{name}-{}-{n}",
		std::process::id()
	))
}

// rm -rf through directories left without permissions
fn force_remove(path: &Path) {
	let Ok(meta) = fs::symlink_metadata(path) else {
		return;
	};
	if !meta.is_dir() {
		fs::remove_file(path).unwrap();
		return;
	}
	fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
	for e in fs::read_dir(path).unwrap() {
		force_remove(&e.unwrap().path());
	}
	fs::remove_dir(path).unwrap();
}

#[derive(Debug, PartialEq)]
enum Node {
	File(Vec<u8>),
	// mode, None when the listing failed
	Dir(u32, Option<Vec<(Vec<u8>, Node)>>),
	Link(Vec<u8>),
}

fn snapshot(path: &Path) -> Node {
	let meta = fs::symlink_metadata(path).unwrap();
	if meta.file_type().is_symlink() {
		let t = fs::read_link(path).unwrap();
		return Node::Link(t.as_os_str().as_bytes().to_vec());
	}
	if meta.is_file() {
		return Node::File(fs::read(path).unwrap_or_default());
	}
	let mode = meta.permissions().mode() & 0o7777;
	let Ok(rd) = fs::read_dir(path) else {
		return Node::Dir(mode, None);
	};
	let mut entries: Vec<_> = rd
		.map(|e| {
			let e = e.unwrap();
			(e.file_name().as_bytes().to_vec(), snapshot(&e.path()))
		})
		.collect();
	entries.sort_by(|a, b| a.0.cmp(&b.0));
	Node::Dir(mode, Some(entries))
}

// a random tree: files, links (to a file, a dir, nowhere) and dirs, some
// without write (children stay), read (no listing) or any permission
#[derive(Clone)]
enum Spec {
	File,
	Link(&'static str),
	Dir(u32, Vec<(String, Spec)>),
}

fn spec(rng: &mut Rng, depth: usize) -> Spec {
	match rng.below(if depth > 2 { 2 } else { 4 }) {
		0 => Spec::File,
		1 => Spec::Link(["f0", "..", "missing"][rng.below(3)]),
		_ => {
			let mode = [0o755, 0o755, 0o700, 0o500, 0o300, 0o000]
				[rng.below(6)];
			let kids = (0..rng.below(4))
				.map(|i| {
					(format!("f{i}"), spec(rng, depth + 1))
				})
				.collect();
			Spec::Dir(mode, kids)
		}
	}
}

fn build(path: &Path, s: &Spec) {
	match s {
		Spec::File => fs::write(path, b"x").unwrap(),
		Spec::Link(t) => symlink(t, path).unwrap(),
		Spec::Dir(mode, kids) => {
			fs::create_dir(path).unwrap();
			for (name, k) in kids {
				build(&path.join(name), k);
			}
			fs::set_permissions(
				path,
				fs::Permissions::from_mode(*mode),
			)
			.unwrap();
		}
	}
}

#[test]
fn rmrf_trees() {
	let mut rng = Rng::new(0x4f4);
	let base = tmp("rmrf");
	fs::create_dir(&base).unwrap();
	for _ in 0..(iters() / 100).max(200) {
		let tree =
			Spec::Dir(0o755, vec![("t".into(), spec(&mut rng, 0))]);
		let target = ["t", "t/f0", "t/f1/f0", "t/", "missing", "t/f0/"]
			[rng.below(6)];
		let mut snaps = Vec::new();
		let mut rets = Vec::new();
		for side in ["c", "r"] {
			let root = base.join(side);
			build(&root, &tree);
			let p = [
				root.as_os_str().as_bytes(),
				b"/",
				target.as_bytes(),
			]
			.concat();
			rets.push(match side {
				"c" => c_rmrf(&p),
				_ => rmrf(&p),
			});
			snaps.push(snapshot(&root));
			force_remove(&root);
		}
		assert_eq!(rets[0], rets[1], "{target}");
		assert_eq!(snaps[0], snaps[1], "{target}");
	}
	fs::remove_dir(&base).unwrap();
}

// names, versions: ASCII, one wide and one combining character (widths
// agree with glibc), a tab (width -1) and the C's '-'
const NAME_TOKENS: &[&[u8]] = &[
	b"a",
	b"lib",
	b"-",
	b"x",
	b"2",
	"\u{3042}".as_bytes(),
	"e\u{301}".as_bytes(),
];
const VERSION_TOKENS: &[&[u8]] = &[
	b"1",
	b".",
	b"2",
	b"-",
	b"10",
	b"r",
	b":",
	"\u{e9}".as_bytes(),
	b"\t",
];

fn pkg(name: &[u8], version: &[u8]) -> Package {
	Package {
		name_hash: hash_sdbm(name),
		name: Some(name.into()),
		version: Some(version.into()),
		infolevel: INFRQ_DSIZE,
		builddate: -1,
		..Package::default()
	}
}

fn name(rng: &mut Rng) -> Vec<u8> {
	let mut n = text(rng, NAME_TOKENS, 4);
	if n.is_empty() && rng.below(4) != 0 {
		n.push(b'p');
	}
	n
}

fn version(rng: &mut Rng) -> Vec<u8> {
	text(rng, VERSION_TOKENS, 5)
}

fn size(rng: &mut Rng) -> i64 {
	match rng.below(6) {
		0 => 0,
		1 => rng.below(4096) as i64,
		2 => -(rng.below(1 << 30) as i64),
		3 => (rng.next_u64() >> 14) as i64,
		_ => rng.below(1 << 32) as i64,
	}
}

// fresh world dir, removed on drop with the world
struct Fx {
	world: UtilWorld,
	h: Handle,
}

impl Fx {
	fn new(name: &str) -> Self {
		let world = UtilWorld::new(&tmp(name));
		let h = world.rust_handle();
		Fx { world, h }
	}

	// the db a package of origin and sync index gets
	fn db(&self, p: &Package, idx: usize) -> Option<&alpm_core::db::Db> {
		match p.origin {
			Some(PkgFrom::SyncDb) => Some(&self.h.syncdbs()[idx]),
			Some(PkgFrom::LocalDb) => self.h.localdb(),
			_ => None,
		}
	}

	fn db_pkgs<'a>(
		&'a self,
		pkgs: &'a [(Package, usize)],
	) -> Vec<DbPkg<'a>> {
		pkgs.iter()
			.map(|(p, i)| DbPkg {
				pkg: p,
				db: self.db(p, *i),
			})
			.collect()
	}
}

fn cols(rng: &mut Rng) -> u16 {
	match rng.below(6) {
		0 => 0,
		1 => 65535,
		2 => 80,
		_ => 10 + rng.below(120) as u16,
	}
}

#[test]
fn display_targets_tables() {
	// display text is compared where glibc and the port agree on widths
	for t in NAME_TOKENS.iter().chain(VERSION_TOKENS) {
		assert!(widths_agree(t), "{}", show(t));
	}
	let mut fx = Fx::new("targets");
	let mut rng = Rng::new(0x7a6);
	let mut seen = Seen::new(&["table", "list", "too narrow", "sizes"]);
	for _ in 0..iters() / 20 {
		let mut local: Vec<Package> = Vec::new();
		for _ in 0..rng.below(5) {
			let n = name(&mut rng);
			if !n.is_empty()
				&& !local
					.iter()
					.any(|p| p.name.as_deref() == Some(&n))
			{
				let mut p = pkg(&n, &version(&mut rng));
				p.origin = Some(PkgFrom::LocalDb);
				p.isize = size(&mut rng);
				local.push(p);
			}
		}
		let add: Vec<(Package, usize)> = (0..rng.below(5))
			.map(|_| {
				let mut p = pkg(
					&name(&mut rng),
					&version(&mut rng),
				);
				p.origin = match rng.below(5) {
					0 => Some(PkgFrom::File(
						b"/x.pkg"[..].into(),
					)),
					_ => Some(PkgFrom::SyncDb),
				};
				p.isize = size(&mut rng);
				p.download_size = size(&mut rng);
				(p, rng.below(2))
			})
			.collect();
		let remove: Vec<Package> = (0..rng.below(4))
			.map(|_| {
				let mut p = pkg(
					&name(&mut rng),
					&version(&mut rng),
				);
				p.origin = Some(PkgFrom::LocalDb);
				p.isize = size(&mut rng);
				p
			})
			.collect();
		let explicit = |rng: &mut Rng,
		                from: &[&Package]|
		 -> Vec<Package> {
			from.iter()
				.filter(|_| rng.below(2) == 0)
				.map(|p| pkg(p.name.as_deref().unwrap(), b""))
				.collect()
		};
		let ea = explicit(
			&mut rng,
			&add.iter().map(|(p, _)| p).collect::<Vec<_>>(),
		);
		let er = explicit(&mut rng, &remove.iter().collect::<Vec<_>>());
		let mut cfg = config(&mut rng);
		cfg.verbosepkglists = u16::from(rng.below(3) != 0);
		cfg.op_s_downloadonly = u16::from(rng.below(5) == 0);
		let cols = cols(&mut rng);
		fx.world.set_caches(&local, [&[], &[]]);
		let c = fx.world.display_targets(
			&cfg,
			&add,
			&remove,
			(&ea, &er),
			cols,
		);
		let add_r = fx.db_pkgs(&add);
		let remove_r: Vec<&Package> = remove.iter().collect();
		let (ea_r, er_r): (Vec<&Package>, Vec<&Package>) =
			(ea.iter().collect(), er.iter().collect());
		let trans = TransTargets {
			add: &add_r,
			remove: &remove_r,
			explicit_adds: &ea_r,
			explicit_removes: &er_r,
		};
		let local_r: Vec<&Package> = local.iter().collect();
		let mut out = Output::default();
		display_targets(&mut out, &cfg, &trans, &local_r, cols);
		assert_eq!(
			(show(&c.stdout), show(&c.stderr)),
			(show(&out.stdout), show(&out.stderr)),
			"add {add:?} remove {remove:?} local {local:?} cols {cols}"
		);
		let has =
			|s: &[u8], w: &[u8]| s.windows(w.len()).any(|x| x == w);
		seen.count([
			has(&out.stdout, b"Net Change"),
			has(&out.stdout, b"Packages ("),
			has(&out.stderr, b"insufficient"),
			has(&out.stdout, b"Size:"),
		]);
	}
	seen.finish("display_targets");
}

// how often each output feature showed up, every one at least once
struct Seen {
	names: &'static [&'static str],
	hits: Vec<usize>,
	compared: usize,
}

impl Seen {
	fn new(names: &'static [&'static str]) -> Self {
		Seen {
			names,
			hits: vec![0; names.len()],
			compared: 0,
		}
	}

	fn count<const N: usize>(&mut self, features: [bool; N]) {
		self.compared += 1;
		for (h, f) in self.hits.iter_mut().zip(features) {
			*h += usize::from(f);
		}
	}

	fn finish(&self, what: &str) {
		println!("{what}: compared {}", self.compared);
		for (name, h) in self.names.iter().zip(&self.hits) {
			println!("{what}: {name} {h}");
			assert!(*h > 0, "{what}: no {name}");
		}
	}
}

const DEPS: &[&str] = &[
	"a", "b>=1", "c: why", "a: other", "d=2", "e<3: x", "f>1.0", "lib-x",
];

fn deps(rng: &mut Rng, max: usize) -> Vec<Depend> {
	(0..rng.below(max))
		.map(|_| {
			dep_from_string(DEPS[rng.below(DEPS.len())].as_bytes())
		})
		.collect()
}

// field text, sometimes holding a token a later replacement matches
const FIELD_TOKENS: &[&[u8]] = &[
	b"x",
	b"desc",
	b" ",
	b"%n",
	b"%r",
	b"%s",
	b"%",
	b"%%",
	"\u{e9}".as_bytes(),
];

fn field(rng: &mut Rng) -> Option<Vec<u8>> {
	(rng.below(4) != 0).then(|| text(rng, FIELD_TOKENS, 4))
}

const FORMAT_TOKENS: &[&[u8]] = &[
	b"%n", b"%v", b"%l", b"%r", b"%s", b"%b", b"%d", b"%a", b"%e", b"%f",
	b"%g", b"%h", b"%p", b"%u", b"%C", b"%D", b"%G", b"%H", b"%M", b"%O",
	b"%P", b"%R", b"%L", b"%", b"%%", b"x", b" ", b"-",
];

const FILENAMES: &[&[u8]] = &[
	CACHED[0].as_bytes(),
	CACHED[1].as_bytes(),
	CACHED[2].as_bytes(),
	CACHED[3].as_bytes(),
	b"missing-1-1-any.pkg.tar.zst",
	b"",
];

#[test]
fn print_packages_formats() {
	let fx = Fx::new("print");
	let mut rng = Rng::new(0x9f7);
	let mut seen = Seen::new(&["cached", "server", "date", "%b kept"]);
	for _ in 0..iters() / 20 {
		let mut cfg = config(&mut rng);
		cfg.print_format = (rng.below(6) != 0)
			.then(|| text(&mut rng, FORMAT_TOKENS, 8));
		cfg.op = [PM_OP_SYNC, PM_OP_UPGRADE, PM_OP_QUERY, PM_OP_REMOVE]
			[rng.below(4)];
		let pkgs: Vec<(Package, usize)> = (0..1 + rng.below(3))
			.map(|_| {
				let mut p = pkg(
					&name(&mut rng),
					&version(&mut rng),
				);
				p.origin = match rng.below(5) {
					0 => Some(PkgFrom::LocalDb),
					1 => Some(PkgFrom::File(
						b"/srv/x.pkg"[..].into(),
					)),
					2 => None,
					_ => Some(PkgFrom::SyncDb),
				};
				p.filename =
					Some(pick(&mut rng, FILENAMES).into());
				p.desc = field(&mut rng).map(Box::from);
				p.arch = field(&mut rng).map(Box::from);
				p.base = field(&mut rng).map(Box::from);
				p.url = field(&mut rng).map(Box::from);
				p.packager = field(&mut rng).map(Box::from);
				p.sha256sum = field(&mut rng).map(Box::from);
				p.base64_sig = field(&mut rng).map(Box::from);
				p.builddate = [
					-1,
					0,
					1_700_000_000,
					rng.below(1 << 33) as i64,
				][rng.below(4)];
				p.size = size(&mut rng);
				p.isize = size(&mut rng);
				p.download_size =
					[0, 0, size(&mut rng)][rng.below(3)];
				p.depends = deps(&mut rng, 3).into();
				p.optdepends = deps(&mut rng, 3).into();
				p.checkdepends = deps(&mut rng, 2).into();
				p.makedepends = deps(&mut rng, 2).into();
				p.conflicts = deps(&mut rng, 2).into();
				p.provides = deps(&mut rng, 2).into();
				p.replaces = deps(&mut rng, 2).into();
				p.groups = (0..rng.below(3))
					.map(|_| name(&mut rng).into())
					.collect();
				p.licenses = (0..rng.below(3))
					.map(|_| name(&mut rng).into())
					.collect();
				(p, rng.below(2))
			})
			.collect();
		let c = fx.world.print_packages(&cfg, &pkgs);
		let mut out = Vec::new();
		let dirs = fx.h.cachedirs();
		print_packages(
			&mut out,
			&cfg,
			&fx.db_pkgs(&pkgs),
			dirs,
			utc_date,
		);
		assert_eq!(
			(show(&c.stdout), show(&c.stderr)),
			(show(&out), show(b"")),
			"{:?} {pkgs:?}",
			cfg.print_format.as_deref().map(show)
		);
		let has = |w: &[u8]| out.windows(w.len()).any(|x| x == w);
		seen.count([
			has(b"file://"),
			has(CORE_SERVER),
			has(b" 2023"),
			has(b"%b"),
		]);
	}
	seen.finish("print_packages");
}

#[test]
fn optdepends_lists() {
	let mut fx = Fx::new("optdepends");
	let mut rng = Rng::new(0x0d7);
	let mut seen = Seen::new(&["installed", "pending", "new", "none new"]);
	let some = |rng: &mut Rng, origin: PkgFrom| -> Vec<Package> {
		let mut names: Vec<Vec<u8>> = Vec::new();
		for _ in 0..rng.below(4) {
			let n = [b"a", b"b", b"c", b"d", b"e", b"f", b"q"]
				[rng.below(7)]
			.to_vec();
			if !names.contains(&n) {
				names.push(n);
			}
		}
		names.iter()
			.map(|n| {
				let mut p = pkg(
					n,
					pick(rng, &[b"1", b"2", b"0.5", b"3"]),
				);
				p.origin = Some(origin.clone());
				p.provides = deps(rng, 2).into();
				p
			})
			.collect()
	};
	for _ in 0..iters() / 20 {
		let cfg = config(&mut rng);
		let local = some(&mut rng, PkgFrom::LocalDb);
		let pending = some(&mut rng, PkgFrom::SyncDb);
		let mut old = pkg(b"old", b"1");
		old.optdepends = deps(&mut rng, 5).into();
		let mut new = pkg(&name(&mut rng), b"2");
		new.optdepends = deps(&mut rng, 5).into();
		let cols = cols(&mut rng);
		fx.world.set_caches(&local, [&[], &[]]);
		let local_r: Vec<&Package> = local.iter().collect();
		let pending_r: Vec<&Package> = pending.iter().collect();
		let installed = (&local_r[..], &pending_r[..]);
		let c = fx.world.optdepends(&cfg, None, &new, &pending, cols);
		let mut out = Vec::new();
		display_optdepends(
			&mut out,
			&cfg.colstr,
			&new,
			installed,
			cols,
		);
		assert_eq!(
			show(&c.stdout),
			show(&out),
			"{new:?} {local:?} {pending:?}"
		);
		let all = out;
		let c = fx.world.optdepends(
			&cfg,
			Some(&old),
			&new,
			&pending,
			cols,
		);
		let mut out = Vec::new();
		display_new_optdepends(
			&mut out,
			&cfg.colstr,
			(&old, &new),
			installed,
			cols,
		);
		assert_eq!(
			show(&c.stdout),
			show(&out),
			"{old:?} {new:?} {local:?} {pending:?}"
		);
		let has =
			|s: &[u8], w: &[u8]| s.windows(w.len()).any(|x| x == w);
		seen.count([
			has(&all, b"[installed]"),
			has(&all, b"[pending]"),
			!out.is_empty(),
			out.is_empty() && !all.is_empty(),
		]);
	}
	seen.finish("optdepends");
}

#[test]
fn select_display_blocks() {
	let fx = Fx::new("select");
	let mut rng = Rng::new(0x5d1);
	for _ in 0..iters() / 20 {
		let cfg = config(&mut rng);
		let pkgs: Vec<(Package, usize)> = (0..1 + rng.below(8))
			.map(|_| {
				let mut p = pkg(&name(&mut rng), b"1");
				p.origin = match rng.below(4) {
					0 => Some(PkgFrom::LocalDb),
					_ => Some(PkgFrom::SyncDb),
				};
				(p, rng.below(2))
			})
			.collect();
		let cols = cols(&mut rng);
		let c = fx.world.select_display(&cfg, &pkgs, cols);
		let mut out = Vec::new();
		let db_pkgs = fx.db_pkgs(&pkgs);
		let pairs: Vec<(Option<&[u8]>, &Package)> = db_pkgs
			.iter()
			.map(|p| (p.db.map(|d| d.name()), p.pkg))
			.collect();
		select_display(&mut out, &cfg.colstr, &pairs, cols);
		assert_eq!(show(&c.stdout), show(&out), "{pkgs:?} cols {cols}");
	}
}

fn tty_probe() -> PathBuf {
	PathBuf::from(env!("CARGO_BIN_EXE_tty-probe"))
}

fn probe_result(stderr: &[u8]) -> String {
	// the answer's echo goes to the terminal, the result line follows
	// the prompt on stderr
	let s = String::from_utf8_lossy(stderr);
	let r = s.split_once("result ").map(|(_, r)| r.trim_end());
	r.unwrap_or_else(|| panic!("no result in {s:?}"))
		.to_string()
}

// getcols on a terminal stdout without COLUMNS: TIOCGWINSZ's width, 80
// for a width of 0 (the C's -EIO)
#[test]
fn getcols_terminal() {
	for cols in [123, 1, 0, 300] {
		let pty = Pty::open(cols);
		let err = run_tty_probe(&tty_probe(), "cols", &pty, b"", b"");
		let want = if cols == 0 { 80 } else { cols };
		assert_eq!(probe_result(&err), format!("{want} {want}"));
	}
}

// typeahead queued on a terminal stdin before the prompt is dropped
// (flush_term_input), the answer typed after it counts
#[test]
fn prompt_flushes_typeahead() {
	for side in ["c", "rust"] {
		let pty = Pty::open(80);
		let mut m = &pty.master;
		std::io::Write::write_all(&mut m, b"n\n").unwrap();
		let mode = format!("yesno-{side}");
		let err = run_tty_probe(
			&tty_probe(),
			&mode,
			&pty,
			b"[Y/n] ",
			b"y\n",
		);
		assert_eq!(probe_result(&err), "1", "{side}: {err:?}");
		assert!(err.starts_with(b":: go? [Y/n] "), "{side}: {err:?}");
	}
}
