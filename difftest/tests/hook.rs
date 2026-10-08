// alpm_core::hook against the C _alpm_hook_run on root "/" (hooks run on
// the host, as the C does without a chroot). random hook files in three
// hook directories (masking, symlinks to /dev/null, dangling links,
// directories, unreadable files, missing or non-directory hookdirs) are
// parsed and validated through both; then valid hooks are matched
// against random transactions and run, their Exec printing what came on
// stdin. compared: return value, every log line (debug included) and
// event in order, the logfile lines.
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use alpm_core::callbacks::HookWhen;
use alpm_core::filelist::{File, FileList};
use alpm_core::hook::{AddTarget, Targets, hook_run};
use alpm_core::package::Package;
use alpm_core::util::hash_sdbm;
use difftest::{
	CHookHandle, CHookResult, LocalEntry, Rng, RustHookHandle, TempRoot,
	iters,
};

const LOCAL: [(&str, &str, &str); 3] = [
	("a", "1.0-1", "virt=2"),
	("b", "2.0-1", "libb.so=1-64"),
	("foo", "1:0.5-3", "bar"),
];

const DEPENDS: [&str; 9] = [
	"a", "a>=1.0", "a>2", "virt", "virt=2", "virt<2", "missing", "",
	"b=2.0",
];

const NAMES: [&str; 11] = [
	"a.hook",
	"b.hook",
	"10-x.hook",
	"x.hook.bak",
	"README",
	".hook",
	"ab.hook",
	"a.hookx",
	"é.hook",
	"zz.hook",
	"a-b.hook",
];

fn pick<T: Copy>(rng: &mut Rng, items: &[T]) -> T {
	items[rng.below(items.len())]
}

// a fixture tempdir: local db, three hookdir paths, a logfile per side;
// the C and the Rust handle on root "/"
struct Fix {
	tmp: TempRoot,
	dirs: Vec<Vec<u8>>,
}

impl Fix {
	fn new(tag: &str) -> Self {
		let tmp = TempRoot::new(tag);
		tmp.reset_local();
		let entries: Vec<LocalEntry> = LOCAL
			.iter()
			.map(|(n, v, p)| LocalEntry {
				dir: format!("{n}-{v}"),
				desc: Some(format!(
					"%NAME%\n{n}\n\n%VERSION%\n{v}\n\n\
						%BASE%\n{n}\n\n%DESC%\nA package\n\n\
						%URL%\nhttps://example.org/\n\n\
						%ARCH%\nx86_64\n\n\
						%BUILDDATE%\n1700000000\n\n\
						%INSTALLDATE%\n1700000001\n\n\
						%PACKAGER%\nA B <a@b.org>\n\n\
						%SIZE%\n42\n\n%VALIDATION%\npgp\n\n\
						%PROVIDES%\n{p}\n\n"
				)
				.into_bytes()),
				files: Some(Vec::new()),
				install: false,
			})
			.collect();
		tmp.write_local(&entries);
		let dirs = (0..3)
			.map(|i| {
				[&tmp.path(&format!("hooks{i}"))[..], b"/"]
					.concat()
			})
			.collect();
		Fix { tmp, dirs }
	}

	fn c(&self) -> CHookHandle {
		let mut c = CHookHandle::new(
			b"/",
			&self.tmp.dbpath(),
			self.tmp.dir().join("log"),
		);
		c.set_hookdirs(&self.dirs);
		c
	}

	fn r(&self) -> RustHookHandle {
		let mut r = RustHookHandle::new(
			b"/",
			&self.tmp.dbpath(),
			self.tmp.dir().join("log-rs"),
		);
		r.set_hookdirs(&self.dirs);
		r
	}

	fn dir(&self, i: usize) -> std::path::PathBuf {
		self.tmp.dir().join(format!("hooks{i}"))
	}

	fn clear(&self) {
		for i in 0..3 {
			let d = self.dir(i);
			match fs::symlink_metadata(&d) {
				Ok(m) if m.is_dir() => {
					fs::remove_dir_all(&d).unwrap()
				}
				Ok(_) => fs::remove_file(&d).unwrap(),
				Err(_) => {}
			}
		}
	}
}

// a random directive line, value None leaves the '=' out. the C
// dereferences a missing Operation/Type/When value, so those always get
// one
fn directive(rng: &mut Rng) -> String {
	const KEYS: [&str; 11] = [
		"Operation",
		"Type",
		"Target",
		"When",
		"Description",
		"Depends",
		"AbortOnFail",
		"NeedsTargets",
		"Exec",
		"Bogus",
		"operation",
	];
	let key = pick(rng, &KEYS);
	let values: &[&str] = match key {
		"Operation" | "operation" => &[
			"Install", "Upgrade", "Remove", "install", "", "Bogus",
		],
		"Type" => &["Package", "Path", "File", ""],
		"When" => &["PreTransaction", "PostTransaction", "Pre", ""],
		"Exec" => &[
			"/bin/true",
			"/bin/sh -c 'exit 0'",
			"'unbalanced",
			"\"a b\" c\\'d",
			"",
			"  x   y  ",
		],
		"Depends" => &DEPENDS,
		_ => &["x", "", "a b", "*", "!x", "no"],
	};
	let needs_value = matches!(key, "Operation" | "Type" | "When");
	if !needs_value && rng.below(6) == 0 {
		return format!("{key}\n");
	}
	let sp = |rng: &mut Rng| pick(rng, &["", " ", "\t", "  "]);
	let (a, b, c) = (sp(rng), sp(rng), sp(rng));
	format!("{a}{key}{b}={c}{}\n", pick(rng, values))
}

fn hook_text(rng: &mut Rng) -> String {
	const HEADERS: [&str; 6] = [
		"[Trigger]",
		"[Action]",
		"[Trigger]",
		"[Action]",
		"[Bogus]",
		"[trigger]",
	];
	let mut s = String::new();
	for _ in 0..rng.below(14) {
		match rng.below(10) {
			0 | 1 => {
				s += pick(rng, &HEADERS);
				s += "\n";
			}
			2 => s += pick(rng, &["# comment\n", "\n", "  \n"]),
			_ => s += &directive(rng),
		}
	}
	s
}

#[derive(Clone, Copy)]
enum Kind {
	Hook,
	DevNull,
	Dangling,
	Dir,
	Unreadable,
}

fn write_entry(dir: &Path, name: &str, kind: Kind, text: &str) {
	let p = dir.join(name);
	if fs::symlink_metadata(&p).is_ok() {
		return;
	}
	match kind {
		Kind::Hook => fs::write(&p, text).unwrap(),
		Kind::DevNull => symlink("/dev/null", &p).unwrap(),
		Kind::Dangling => symlink(dir.join("nowhere"), &p).unwrap(),
		Kind::Dir => fs::create_dir(&p).unwrap(),
		Kind::Unreadable => {
			fs::write(&p, text).unwrap();
			fs::set_permissions(
				&p,
				fs::Permissions::from_mode(0o000),
			)
			.unwrap();
		}
	}
}

// each hookdir missing, a plain file, or a directory of random entries,
// hooks from gen
// hooks from make. errors adds the entries that fail the scan
fn write_dirs(
	fix: &Fix,
	rng: &mut Rng,
	errors: bool,
	make: &mut impl FnMut(&mut Rng) -> String,
) {
	fix.clear();
	for i in 0..3 {
		let d = fix.dir(i);
		match rng.below(if errors { 8 } else { 16 }) {
			0 => continue,
			1 => {
				fs::write(&d, "x").unwrap();
				continue;
			}
			_ => fs::create_dir(&d).unwrap(),
		}
		for _ in 0..rng.below(5) {
			let kind = match rng.below(if errors { 14 } else { 40 })
			{
				0 => Kind::DevNull,
				1 => Kind::Dir,
				2 => Kind::Dangling,
				3 => Kind::Unreadable,
				_ => Kind::Hook,
			};
			let text = make(rng);
			write_entry(&d, pick(rng, &NAMES), kind, &text);
		}
	}
}

fn rust_run(
	r: &mut RustHookHandle,
	add: &[AddTarget],
	remove: &[&Package],
	when: HookWhen,
) -> CHookResult {
	let ok = hook_run(&mut r.h, &Targets { add, remove }, when);
	r.take(ok, -1)
}

fn show(fix: &Fix) -> String {
	let mut out = String::new();
	for i in 0..3 {
		let d = fix.dir(i);
		out += &format!("{}:\n", d.display());
		let Ok(rd) = fs::read_dir(&d) else { continue };
		for e in rd.map(Result::unwrap) {
			let text = fs::read_to_string(e.path())
				.unwrap_or_default();
			out += &format!("  {:?}:\n{text}\n", e.file_name());
		}
	}
	out
}

fn when_of(rng: &mut Rng) -> HookWhen {
	match rng.below(2) {
		0 => HookWhen::PreTransaction,
		_ => HookWhen::PostTransaction,
	}
}

fn compare(fix: &Fix, c: CHookResult, r: CHookResult) {
	assert_eq!(c, r, "\nC:    {c:?}\nRust: {r:?}\nhooks:\n{}", show(fix));
}

#[test]
fn fixed_masking() {
	let fix = Fix::new("hook-mask");
	let (mut c, mut r) = (fix.c(), fix.r());
	fix.clear();
	for i in 0..3 {
		fs::create_dir(fix.dir(i)).unwrap();
	}
	let hook = "[Trigger]\nOperation = Install\nType = Package\n\
		Target = *\n[Action]\nWhen = PostTransaction\n\
		Exec = /bin/sh -c 'echo HOOK'\n";
	// a.hook masked by /dev/null in the last dir, b.hook by an invalid
	// file (which does not mask), zz.hook only in the first
	write_entry(&fix.dir(0), "a.hook", Kind::Hook, hook);
	write_entry(&fix.dir(2), "a.hook", Kind::DevNull, "");
	write_entry(&fix.dir(0), "b.hook", Kind::Hook, hook);
	write_entry(&fix.dir(1), "b.hook", Kind::Hook, "[Bogus]\n");
	write_entry(&fix.dir(0), "zz.hook", Kind::Hook, hook);
	write_entry(&fix.dir(1), "zz.hook", Kind::Hook, hook);
	let pkg = Package {
		name: Some(b"p".to_vec()),
		..Package::default()
	};
	let when = HookWhen::PostTransaction;
	let cr = c.hook_run(&[(&pkg, None)], &[], when);
	let add = [AddTarget {
		pkg: &pkg,
		oldpkg: None,
	}];
	let rr = rust_run(&mut r, &add, &[], when);
	let ran = |r: &CHookResult| {
		r.1.iter()
			.filter_map(|x| match x {
				difftest::HookRec::RunStart(n, ..) => {
					Some(n.clone())
				}
				_ => None,
			})
			.collect::<Vec<_>>()
	};
	assert_eq!(ran(&cr), [b"b.hook".to_vec(), b"zz.hook".to_vec()]);
	compare(&fix, cr, rr);
}

// parse and validation messages: no transaction packages, so nothing
// triggers and Target without a value is safe for the C
#[test]
fn parse_validate_fuzz() {
	let fix = Fix::new("hook-parse");
	let (mut c, mut r) = (fix.c(), fix.r());
	let mut rng = Rng::new(0x600c);
	let n = (iters() / 5).max(500);
	for _ in 0..n {
		write_dirs(&fix, &mut rng, true, &mut hook_text);
		let when = when_of(&mut rng);
		let cr = c.hook_run(&[], &[], when);
		let rr = rust_run(&mut r, &[], &[], when);
		compare(&fix, cr, rr);
	}
	fix.clear();
}

const PKGS: [&str; 6] = ["a", "b", "foo", "foo-libs", "bar", "é"];
const PATHS: [&str; 10] = [
	"usr/",
	"usr/bin/",
	"usr/bin/x",
	"usr/bin/y",
	"usr/lib/libx.so",
	"usr/lib/liby.so.1",
	"etc/conf",
	"etc/é",
	"opt/x",
	"!x",
];
const PATTERNS: [&str; 16] = [
	"a",
	"foo*",
	"!foo-libs",
	"*",
	"!*",
	"usr/bin/*",
	"!usr/bin/x",
	"etc/*",
	"usr/lib/*.so",
	"\\!x",
	"!x",
	"usr/",
	"*/x",
	"é",
	"b",
	"[ab]",
];

fn files(rng: &mut Rng) -> FileList {
	let mut names: Vec<&str> =
		(0..rng.below(5)).map(|_| pick(rng, &PATHS)).collect();
	names.sort();
	names.dedup();
	FileList {
		files: names
			.iter()
			.map(|n| File::new(n.as_bytes().to_vec(), 0, 0o100644))
			.collect(),
	}
}

fn pkg(rng: &mut Rng) -> Package {
	let name = pick(rng, &PKGS).as_bytes().to_vec();
	Package {
		name_hash: hash_sdbm(&name),
		name: Some(name),
		version: Some(b"1.0-1".to_vec()),
		files: files(rng),
		..Package::default()
	}
}

// valid hooks that print their name, stdin lines and exit 0 or 1
fn valid_hook(rng: &mut Rng) -> String {
	let mut s = String::new();
	for _ in 0..1 + rng.below(2) {
		s += "[Trigger]\n";
		for _ in 0..1 + rng.below(3) {
			let op = pick(rng, &["Install", "Upgrade", "Remove"]);
			s += &format!("Operation = {op}\n");
		}
		s += &format!("Type = {}\n", pick(rng, &["Package", "Path"]));
		for _ in 0..1 + rng.below(3) {
			s += &format!("Target = {}\n", pick(rng, &PATTERNS));
		}
	}
	s += "[Action]\n";
	if rng.below(2) == 0 {
		s += "Description = a hook\n";
	}
	let when = pick(rng, &["PreTransaction", "PostTransaction"]);
	s += &format!("When = {when}\n");
	if rng.below(3) == 0 {
		s += "AbortOnFail\n";
	}
	match rng.below(12) {
		0..3 => s += &format!("Depends = {}\n", pick(rng, &DEPENDS)),
		3 => s += "Depends\n",
		_ => {}
	}
	// an empty Exec: execv(NULL) in the C child. it reads nothing, so
	// no NeedsTargets (the stdin write would race its exit)
	if rng.below(15) == 0 {
		return s + "Exec =\n";
	}
	if rng.below(2) == 0 {
		s += "NeedsTargets\n";
	}
	let code = rng.below(3) / 2;
	s += &format!("Exec = /bin/sh -c 'echo run; while IFS= read -r l; \
		do echo \"t:$l\"; done; echo err >&2; exit {code}'\n");
	s
}

// trigger matching and runs: valid hooks, random transactions
#[test]
fn match_run_fuzz() {
	let fix = Fix::new("hook-match");
	let (mut c, mut r) = (fix.c(), fix.r());
	let mut rng = Rng::new(0x7e57);
	let n = (iters() / 50).max(300);
	let mut ran = 0;
	for _ in 0..n {
		write_dirs(&fix, &mut rng, false, &mut valid_hook);
		let adds: Vec<Package> =
			(0..rng.below(5)).map(|_| pkg(&mut rng)).collect();
		let olds: Vec<Option<Package>> = adds
			.iter()
			.map(|p| {
				(rng.below(2) == 0).then(|| Package {
					files: files(&mut rng),
					..p.clone()
				})
			})
			.collect();
		let removes: Vec<Package> =
			(0..rng.below(3)).map(|_| pkg(&mut rng)).collect();
		let noextract: Vec<Vec<u8>> = (0..rng.below(3))
			.map(|_| pick(&mut rng, &PATTERNS).as_bytes().to_vec())
			.collect();
		let when = when_of(&mut rng);

		let ctargets: Vec<(&Package, Option<&Package>)> = adds
			.iter()
			.zip(&olds)
			.map(|(p, o)| (p, o.as_ref()))
			.collect();
		let rtargets: Vec<AddTarget> = ctargets
			.iter()
			.map(|&(pkg, oldpkg)| AddTarget { pkg, oldpkg })
			.collect();
		let rem: Vec<&Package> = removes.iter().collect();
		c.set_noextracts(&noextract);
		r.set_noextracts(&noextract);
		let cr = c.hook_run(&ctargets, &rem, when);
		let rr = rust_run(&mut r, &rtargets, &rem, when);
		ran += cr
			.1
			.iter()
			.filter(|r| {
				matches!(r, difftest::HookRec::RunStart(..))
			})
			.count();
		let ctx = format!(
			"add {:?}\nold {:?}\nremove {:?}\nnoextract {noextract:?}",
			adds.iter().map(desc).collect::<Vec<_>>(),
			olds.iter()
				.map(|o| o.as_ref().map(desc))
				.collect::<Vec<_>>(),
			removes.iter().map(desc).collect::<Vec<_>>(),
		);
		assert_eq!(cr, rr, "\n{ctx}\nhooks:\n{}", show(&fix));
	}
	fix.clear();
	// hooks did trigger and run
	assert!(ran > n / 3, "only {ran} hooks ran in {n} cases");
}

fn desc(p: &Package) -> String {
	let names: Vec<String> =
		p.files.files
			.iter()
			.map(|f| String::from_utf8_lossy(f.name()).into_owned())
			.collect();
	format!("{} {names:?}", String::from_utf8_lossy(p.name_bytes()))
}
