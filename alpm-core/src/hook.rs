// port of lib/libalpm/hook.c: hook files ([Trigger]/[Action]), the scan
// of the hook directories (a later directory masks a same-named file of
// an earlier one), trigger matching against the transaction, and running
// the triggered hooks through util::run_chroot.
//
// hookdirs, noextract, root, the local db, logcb, eventcb and the
// logfile come from the Handle; the transaction (a separate unit) comes
// in as Targets. where the C dereferences NULL (an Operation, Type or
// When without '='), the port reports an invalid value instead.

use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use pacman_common::ini::{Ini, parse_ini};
use pacman_common::util_common::wordsplit;

use crate::callbacks::{Callbacks, Event, HookRun, HookWhen, LogLevel, logv};
use crate::deps::find_satisfier;
use crate::handle::Handle;
use crate::package::{DbCaches, Package};
use crate::util::{
	CALLER_PREFIX, PATH_MAX, fnmatch_patterns, run_chroot, strerror,
	until_nul,
};

// ALPM_HOOK_SUFFIX
pub const HOOK_SUFFIX: &[u8] = b".hook";

// enum _alpm_hook_op_t bits of Trigger::op
pub const OP_INSTALL: u8 = 1 << 0;
pub const OP_UPGRADE: u8 = 1 << 1;
pub const OP_REMOVE: u8 = 1 << 2;

// enum _alpm_trigger_type_t
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerType {
	Package = 1,
	Path,
}

// struct _alpm_trigger_t. a Target without '=' is the C's NULL entry:
// it counts for validation and never matches (the C would crash on it)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trigger {
	pub op: u8,
	pub ttype: Option<TriggerType>,
	pub targets: Vec<Option<Vec<u8>>>,
}

// struct _alpm_hook_t without matches (Hook::triggered returns them).
// cmd Some(empty) is an empty Exec value, which the C accepts. a Depends
// without '=' never resolves, like alpm_find_satisfier(NULL)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hook {
	pub name: Vec<u8>,
	pub desc: Option<Vec<u8>>,
	pub triggers: Vec<Trigger>,
	pub depends: Vec<Option<Vec<u8>>>,
	pub cmd: Option<Vec<Vec<u8>>>,
	pub when: Option<HookWhen>,
	pub abort_on_fail: bool,
	pub needs_targets: bool,
}

// a transaction target: the new package and the installed one it
// replaces (pkg->oldpkg)
#[derive(Clone, Copy, Debug)]
pub struct AddTarget<'a> {
	pub pkg: &'a Package,
	pub oldpkg: Option<&'a Package>,
}

// handle->trans->add and ->remove. packages need names and file lists
#[derive(Clone, Copy, Debug)]
pub struct Targets<'a> {
	pub add: &'a [AddTarget<'a>],
	pub remove: &'a [&'a Package],
}

// a value through printf %s: glibc prints NULL as "(null)"
fn shown(v: Option<&[u8]>) -> &[u8] {
	v.unwrap_or(b"(null)")
}

// _alpm_hook_parse_cb on one parse_ini callback: 1 stops parsing
fn parse_cb(
	hook: &mut Hook,
	file: &[u8],
	ev: Ini,
	cb: &mut dyn Callbacks,
) -> i32 {
	let (line, section, key, value) = match ev {
		Ini::OpenError(e) => {
			logv(
				cb,
				LogLevel::Error,
				&[
					b"error while reading hook ",
					file,
					b": ",
					&strerror(e),
					b"\n",
				],
			);
			return 1;
		}
		Ini::Section { line, name } => {
			return begin_section(hook, file, line, name, cb);
		}
		Ini::Directive {
			line,
			section,
			key,
			value,
		} => (line, section, key, value),
	};
	let at = format!(" line {line}: ");
	let at = at.as_bytes();
	let error = |cb: &mut dyn Callbacks, what: &[u8], v: &[u8]| {
		logv(
			cb,
			LogLevel::Error,
			&[b"hook ", file, at, what, v, b"\n"],
		);
		1
	};
	let overwrite = |cb: &mut dyn Callbacks, what: &[u8]| {
		logv(
			cb,
			LogLevel::Warning,
			&[
				b"hook ",
				file,
				at,
				b"overwriting previous definition of ",
				what,
				b"\n",
			],
		);
	};
	let invalid = |cb: &mut dyn Callbacks| {
		error(cb, b"invalid value ", shown(value))
	};
	match (section, key) {
		(None, _) => error(cb, b"invalid option ", key),
		(Some(b"Trigger"), _) => {
			// the section header pushed a trigger
			let t = hook.triggers.last_mut().expect("trigger");
			match key {
				b"Operation" => {
					let op = match value {
						Some(b"Install") => OP_INSTALL,
						Some(b"Upgrade") => OP_UPGRADE,
						Some(b"Remove") => OP_REMOVE,
						_ => return invalid(cb),
					};
					t.op |= op;
				}
				b"Type" => {
					if t.ttype.is_some() {
						overwrite(cb, b"Type");
					}
					t.ttype = Some(match value {
						Some(b"Package") => {
							TriggerType::Package
						}
						Some(b"Path") => {
							TriggerType::Path
						}
						_ => return invalid(cb),
					});
				}
				b"Target" => t
					.targets
					.push(value.map(<[u8]>::to_vec)),
				_ => return error(cb, b"invalid option ", key),
			}
			0
		}
		(Some(_), _) => match key {
			b"When" => {
				if hook.when.is_some() {
					overwrite(cb, b"When");
				}
				hook.when = Some(match value {
					Some(b"PreTransaction") => {
						HookWhen::PreTransaction
					}
					Some(b"PostTransaction") => {
						HookWhen::PostTransaction
					}
					_ => return invalid(cb),
				});
				0
			}
			b"Description" => {
				if hook.desc.is_some() {
					overwrite(cb, b"Description");
				}
				hook.desc = value.map(<[u8]>::to_vec);
				0
			}
			b"Depends" => {
				hook.depends.push(value.map(<[u8]>::to_vec));
				0
			}
			// the value is not looked at: "AbortOnFail = no" sets it
			b"AbortOnFail" => {
				hook.abort_on_fail = true;
				0
			}
			b"NeedsTargets" => {
				hook.needs_targets = true;
				0
			}
			b"Exec" => {
				if hook.cmd.is_some() {
					overwrite(cb, b"Exec");
				}
				// wordsplit(NULL) is EINVAL like an open quote
				hook.cmd = value.and_then(wordsplit);
				match hook.cmd {
					Some(_) => 0,
					None => invalid(cb),
				}
			}
			_ => error(cb, b"invalid option ", key),
		},
	}
}

// a "[name]" line: parse_ini only passes directives of sections the
// callback accepted, so every other section is Action
fn begin_section(
	hook: &mut Hook,
	file: &[u8],
	line: usize,
	name: &[u8],
	cb: &mut dyn Callbacks,
) -> i32 {
	match name {
		b"Trigger" => hook.triggers.push(Trigger::default()),
		b"Action" => {}
		_ => {
			let at = format!(" line {line}: invalid section ");
			logv(
				cb,
				LogLevel::Error,
				&[b"hook ", file, at.as_bytes(), name, b"\n"],
			);
			return 1;
		}
	}
	0
}

impl Trigger {
	// _alpm_trigger_validate
	fn validate(&self, file: &[u8], cb: &mut dyn Callbacks) -> bool {
		let missing = [
			(self.targets.is_empty(), &b"targets"[..]),
			(self.ttype.is_none(), b"type"),
			(self.op == 0, b"operation"),
		];
		for (_, what) in missing.iter().filter(|(m, _)| *m) {
			logv(
				cb,
				LogLevel::Error,
				&[
					b"Missing trigger ",
					what,
					b" in hook: ",
					file,
					b"\n",
				],
			);
		}
		!missing.iter().any(|(m, _)| *m)
	}

	fn patterns(&self) -> Vec<&[u8]> {
		self.targets.iter().filter_map(|t| t.as_deref()).collect()
	}

	// _alpm_hook_trigger_match_file: the transaction's paths split
	// into installed (minus NoExtract), removed (upgraded packages' old
	// files and removed packages' files) and those in both (upgraded).
	// returned when one of the trigger's operations has paths
	fn match_file<'a>(
		&self,
		targets: &Targets<'a>,
		noextract: &[Vec<u8>],
	) -> Matches<'a> {
		let pats = self.patterns();
		let hit = |name: &[u8]| {
			fnmatch_patterns(&pats, name) == Some(false)
		};
		let files =
			|p: &'a Package| p.files.files.iter().map(|f| f.name());
		let mut install: Vec<&[u8]> = targets
			.add
			.iter()
			.flat_map(|t| files(t.pkg))
			.filter(|n| {
				fnmatch_patterns(noextract, n) != Some(false)
			})
			.filter(|n| hit(n))
			.collect();
		let old = targets.add.iter().filter_map(|t| t.oldpkg);
		let mut remove: Vec<&[u8]> = old
			.chain(targets.remove.iter().copied())
			.flat_map(files)
			.filter(|n| hit(n))
			.collect();
		install.sort();
		remove.sort();

		// paths in both lists move to upgrade, every copy of them
		let (mut ins, mut rem, mut upgrade) = (vec![], vec![], vec![]);
		let (mut i, mut j) = (0, 0);
		while i < install.len() {
			while j < remove.len() && install[i] > remove[j] {
				rem.push(remove[j]);
				j += 1;
			}
			if j == remove.len() {
				break;
			}
			if install[i] != remove[j] {
				ins.push(install[i]);
				i += 1;
				continue;
			}
			let path = install[i];
			upgrade.push(path);
			while i < install.len() && install[i] == path {
				i += 1;
			}
			while j < remove.len() && remove[j] == path {
				j += 1;
			}
		}
		ins.extend_from_slice(&install[i..]);
		rem.extend_from_slice(&remove[j..]);
		self.select(ins, upgrade, rem)
	}

	// _alpm_hook_trigger_match_pkg: installs and upgrades by the new
	// package's name (an upgrade has an oldpkg), removals of names not
	// also being added
	fn match_pkg<'a>(&self, targets: &Targets<'a>) -> Matches<'a> {
		let pats = self.patterns();
		let hit = |p: &Package| {
			fnmatch_patterns(&pats, p.name_bytes()) == Some(false)
		};
		let (mut ins, mut upgrade, mut rem) = (vec![], vec![], vec![]);
		if self.op & (OP_INSTALL | OP_UPGRADE) != 0 {
			for t in targets.add.iter().filter(|t| hit(t.pkg)) {
				match t.oldpkg {
					Some(_) if self.op & OP_UPGRADE
						!= 0 =>
					{
						upgrade.push(t.pkg.name_bytes())
					}
					None if self.op & OP_INSTALL != 0 => {
						ins.push(t.pkg.name_bytes())
					}
					_ => {}
				}
			}
		}
		if self.op & OP_REMOVE != 0 {
			let added = |p: &Package| {
				targets.add.iter().any(|t| {
					t.pkg.name_bytes() == p.name_bytes()
				})
			};
			for p in targets
				.remove
				.iter()
				.filter(|p| hit(p) && !added(p))
			{
				rem.push(p.name_bytes());
			}
		}
		self.select(ins, upgrade, rem)
	}

	// the lists of the trigger's operations; nothing when all are empty
	fn select<'a>(
		&self,
		ins: Vec<&'a [u8]>,
		upgrade: Vec<&'a [u8]>,
		rem: Vec<&'a [u8]>,
	) -> Matches<'a> {
		let lists = [
			(OP_INSTALL, ins),
			(OP_UPGRADE, upgrade),
			(OP_REMOVE, rem),
		];
		let mut out = Vec::new();
		for (op, list) in lists {
			if self.op & op != 0 {
				out.extend(list);
			}
		}
		Matches(out)
	}
}

// the matched names or paths of one trigger, a match when not empty
struct Matches<'a>(Vec<&'a [u8]>);

impl Hook {
	// _alpm_hook_validate: a hook without triggers is valid (it masks a
	// lower priority one); otherwise every trigger, Exec and When must
	// be set. AbortOnFail outside PreTransaction only warns
	pub fn validate(&self, file: &[u8], cb: &mut dyn Callbacks) -> bool {
		if self.triggers.is_empty() {
			return true;
		}
		let mut ok = true;
		for t in &self.triggers {
			ok &= t.validate(file, cb);
		}
		if self.cmd.is_none() {
			ok = false;
			logv(
				cb,
				LogLevel::Error,
				&[
					b"Missing Exec option in hook: ",
					file,
					b"\n",
				],
			);
		}
		match self.when {
			None => {
				ok = false;
				logv(cb, LogLevel::Error, &[
					b"Missing When option in hook: ",
					file,
					b"\n",
				]);
			}
			Some(HookWhen::PostTransaction)
				if self.abort_on_fail =>
			{
				logv(cb, LogLevel::Warning, &[
					b"AbortOnFail set for PostTransaction hook: ",
					file,
					b"\n",
				]);
			}
			Some(_) => {}
		}
		ok
	}

	// _alpm_hook_triggered: Some(matches) when a trigger matches. the
	// matches (names or paths) are only collected for NeedsTargets,
	// sorted and deduplicated as _alpm_hook_run_hook feeds them
	pub fn triggered<'a>(
		&self,
		targets: &Targets<'a>,
		noextract: &[Vec<u8>],
	) -> Option<Vec<&'a [u8]>> {
		let mut all = Vec::new();
		let mut hit = false;
		for t in &self.triggers {
			let m = match t.ttype {
				Some(TriggerType::Package) => {
					t.match_pkg(targets)
				}
				_ => t.match_file(targets, noextract),
			};
			if m.0.is_empty() {
				continue;
			}
			if !self.needs_targets {
				return Some(Vec::new());
			}
			hit = true;
			all.extend(m.0);
		}
		all.sort();
		all.dedup();
		hit.then_some(all)
	}

	// _alpm_hook_run_hook: Depends against the local db, then Exec with
	// the matches one per line on stdin for NeedsTargets. the local
	// descs load up front where the C lazy-loads them per satisfier
	fn run(&self, h: &mut Handle, matches: &[&[u8]]) -> bool {
		for dep in &self.depends {
			let local = h.local_cache().into_iter();
			if dep.as_ref()
				.and_then(|d| find_satisfier(local, d))
				.is_none()
			{
				logv(h.callbacks(), LogLevel::Error, &[
					b"unable to run hook ",
					&self.name,
					b": could not satisfy dependencies\n",
				]);
				return false;
			}
		}
		let cmd = self.cmd.as_deref().unwrap_or_default();
		let argv: Vec<&[u8]> = cmd.iter().map(|a| &a[..]).collect();
		let stdin = self.needs_targets.then(|| {
			matches.iter()
				.flat_map(|m| [*m, b"\n"])
				.flatten()
				.copied()
		});
		let stdin: Option<Vec<u8>> = stdin.map(Iterator::collect);
		let cmd0 = argv.first().copied();
		run_chroot(h, cmd0, &argv, stdin.as_deref())
	}
}

// _alpm_hook_cmp: names compared without the suffix, a prefix first
fn hook_cmp(a: &Hook, b: &Hook) -> std::cmp::Ordering {
	stem(a).cmp(stem(b))
}

fn stem(h: &Hook) -> &[u8] {
	&h.name[..h.name.len().saturating_sub(HOOK_SUFFIX.len())]
}

// parse_ini + _alpm_hook_parse_cb on path. None when the callback
// stopped parsing (its error is logged). name is left empty
pub fn parse_hook(path: &[u8], cb: &mut dyn Callbacks) -> Option<Hook> {
	let mut hook = Hook::default();
	let path = until_nul(path);
	let os = Path::new(std::ffi::OsStr::from_bytes(path));
	let ret = parse_ini(os, |ev| parse_cb(&mut hook, path, ev, cb));
	(ret == 0).then_some(hook)
}

// one directory of _alpm_hook_run's scan: hooks not yet in hooks
// (masked by name) are parsed and validated. false on any error
fn scan_dir(dir: &[u8], hooks: &mut Vec<Hook>, cb: &mut dyn Callbacks) -> bool {
	let too_long = strerror(&rustix::io::Errno::NAMETOOLONG.into());
	if dir.len() >= PATH_MAX {
		logv(
			cb,
			LogLevel::Error,
			&[
				b"could not open directory: ",
				dir,
				b": ",
				&too_long,
				b"\n",
			],
		);
		return false;
	}
	let entries = match fs::read_dir(std::ffi::OsStr::from_bytes(dir)) {
		Ok(d) => d,
		Err(e) if e.kind() == io::ErrorKind::NotFound => return true,
		Err(e) => {
			logv(
				cb,
				LogLevel::Error,
				&[
					b"could not open directory: ",
					dir,
					b": ",
					&strerror(&e),
					b"\n",
				],
			);
			return false;
		}
	};
	let mut ok = true;
	for entry in entries {
		let entry =
			match entry {
				Ok(e) => e,
				Err(e) => {
					logv(cb, LogLevel::Error, &[
					b"could not read directory: ",
					dir,
					b": ",
					&strerror(&e),
					b"\n",
				]);
					return false;
				}
			};
		let name = entry.file_name();
		let name = name.as_bytes();
		if name.len() >= PATH_MAX - dir.len() {
			logv(
				cb,
				LogLevel::Error,
				&[
					b"could not open file: ",
					dir,
					name,
					b": ",
					&too_long,
					b"\n",
				],
			);
			ok = false;
			continue;
		}
		ok &= scan_entry(dir, name, hooks, cb);
	}
	ok
}

// one directory entry of the scan; false on error
fn scan_entry(
	dir: &[u8],
	name: &[u8],
	hooks: &mut Vec<Hook>,
	cb: &mut dyn Callbacks,
) -> bool {
	let path = [dir, name].concat();
	let debug = |cb: &mut dyn Callbacks, what: &[u8]| {
		logv(cb, LogLevel::Debug, &[what, &path, b"\n"]);
	};
	if !name.ends_with(HOOK_SUFFIX) {
		debug(cb, b"skipping non-hook file ");
		return true;
	}
	if hooks.iter().any(|h| h.name == name) {
		debug(cb, b"skipping overridden hook ");
		return true;
	}
	match fs::metadata(std::ffi::OsStr::from_bytes(&path)) {
		Err(e) => {
			logv(
				cb,
				LogLevel::Error,
				&[
					b"could not stat file ",
					&path,
					b": ",
					&strerror(&e),
					b"\n",
				],
			);
			return false;
		}
		Ok(m) if m.is_dir() => {
			debug(cb, b"skipping directory ");
			return true;
		}
		Ok(_) => {}
	}
	debug(cb, b"parsing hook file ");
	let hook = parse_hook(&path, cb).filter(|h| h.validate(&path, cb));
	let Some(mut hook) = hook else {
		logv(
			cb,
			LogLevel::Debug,
			&[b"parsing hook file ", &path, b" failed\n"],
		);
		return false;
	};
	hook.name = name.to_vec();
	hooks.push(hook);
	true
}

// _alpm_hook_run: the hooks of every hookdir, the last directory first
// so its files mask same-named ones of earlier directories (a symlink to
// /dev/null parses as an empty, triggerless hook). any scan error stops
// PreTransaction before running. the hooks of `when` whose triggers
// match run sorted by name; for PreTransaction a failing AbortOnFail hook
// stops the rest. true when nothing failed (C 0)
pub fn hook_run(h: &mut Handle, targets: &Targets, when: HookWhen) -> bool {
	let mut hooks = Vec::new();
	let mut ok = true;
	// the scan logs through the handle
	let hookdirs = h.hookdirs().to_vec();
	for dir in hookdirs.iter().rev() {
		ok &= scan_dir(until_nul(dir), &mut hooks, h.callbacks());
	}
	if !ok && when == HookWhen::PreTransaction {
		return false;
	}
	hooks.sort_by(hook_cmp);

	let triggered: Vec<(&Hook, Vec<&[u8]>)> = hooks
		.iter()
		.filter(|h| h.when == Some(when))
		.filter_map(|hk| {
			Some((hk, hk.triggered(targets, h.noextracts())?))
		})
		.collect();
	if triggered.is_empty() {
		return ok;
	}
	h.callbacks().event(&Event::HookStart { when });
	let total = triggered.len();
	for (i, (hook, matches)) in triggered.iter().enumerate() {
		let run = HookRun {
			name: &hook.name,
			desc: hook.desc.as_deref(),
			position: i + 1,
			total,
		};
		let msg = [b"running '", run.name, b"'...\n"].concat();
		// alpm_logaction's result is not checked
		let _ = h.logaction(CALLER_PREFIX, &msg);
		h.callbacks().event(&Event::HookRunStart(run));
		if !hook.run(h, matches) && hook.abort_on_fail {
			ok = false;
		}
		h.callbacks().event(&Event::HookRunDone(run));
		if !ok && when == HookWhen::PreTransaction {
			break;
		}
	}
	h.callbacks().event(&Event::HookDone { when });
	ok
}
