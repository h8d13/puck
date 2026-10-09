// port of lib/libalpm/deps.c: dependency strings, version matching,
// satisfiers, checkdeps, sorting by dependencies, the resolver and the
// -Rs cascade.
//
// handle state comes in as a DepsEnv (ignore lists and assumeinstalled,
// the NODEPVERSION trans flag, db caches and usage), borrowed apart from
// the callbacks (Handle::dbs_mut).
// QUESTION and _alpm_log go to the caller's Callbacks, pm_errno comes
// back as Err. alpm_dep_free, depmiss_new/alpm_depmissing_free and
// _alpm_dep_dup are Drop and Clone.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::ffi::{c_int, c_ulong};
use std::ptr;

use crate::callbacks::{Callbacks, LogLevel, Question, logv};
use crate::db::{DB_USAGE_INSTALL, DB_USAGE_UPGRADE};
use crate::error::Errno;
use crate::graph::{Graph, State};
use crate::package::{Package, PkgReason, has_name, pkg_cmp, pkg_find};
use crate::pkghash::PkgHash;
use crate::trans::opt_str;
use crate::util::fnmatch;
use crate::util::{hash_sdbm, until_nul};
use crate::version::vercmp;

/// alpm_depmod_t, discriminants as in alpm.h
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepMod {
	Any = 1,
	Eq,
	Ge,
	Le,
	Gt,
	Lt,
}

/// alpm_depend_t. NULL strings are None, name is never NULL once parsed
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Depend {
	pub name: Box<[u8]>,
	pub version: Option<Box<[u8]>>,
	pub desc: Option<Box<[u8]>>,
	pub name_hash: c_ulong,
	pub depmod: DepMod,
}

impl DepMod {
	// operator text of alpm_dep_compute_string
	fn as_bytes(self) -> &'static [u8] {
		match self {
			DepMod::Any => b"",
			DepMod::Eq => b"=",
			DepMod::Ge => b">=",
			DepMod::Le => b"<=",
			DepMod::Gt => b">",
			DepMod::Lt => b"<",
		}
	}
}

// alpm_pkg_vercmp ordering, NULL sorts before any string
fn vercmp_opt(a: Option<&[u8]>, b: Option<&[u8]>) -> Ordering {
	match (a, b) {
		(Some(a), Some(b)) => vercmp(a, b),
		_ => a.is_some().cmp(&b.is_some()),
	}
}

/// dep_vercmp (static in C): does version1 satisfy "mod version2"
pub fn dep_vercmp(
	version1: Option<&[u8]>,
	depmod: DepMod,
	version2: Option<&[u8]>,
) -> bool {
	if depmod == DepMod::Any {
		return true;
	}
	let cmp = vercmp_opt(version1, version2);
	match depmod {
		DepMod::Any => true,
		DepMod::Eq => cmp.is_eq(),
		DepMod::Ge => cmp.is_ge(),
		DepMod::Le => cmp.is_le(),
		DepMod::Lt => cmp.is_lt(),
		DepMod::Gt => cmp.is_gt(),
	}
}

// the C checks the stored hash before strcmp, kept so hand-built
// structs with a stale hash behave the same
fn same_name(a: &Depend, b: &Depend) -> bool {
	a.name_hash == b.name_hash && until_nul(&a.name) == until_nul(&b.name)
}

/// _alpm_depcmp_provides: only versioned provisions ("name=ver") can
/// satisfy a versioned dep
pub fn depcmp_provides(dep: &Depend, provisions: &[Depend]) -> bool {
	provisions.iter().any(|p| match (dep.depmod, p.depmod) {
		(DepMod::Any, _) => same_name(p, dep),
		(_, DepMod::Eq) => {
			same_name(p, dep)
				&& dep_vercmp(
					p.version.as_deref(),
					dep.depmod,
					dep.version.as_deref(),
				)
		}
		_ => false,
	})
}

/// _alpm_depcmp_literal: pkg is dep by name (hash first, like the C),
/// and its version satisfies dep's
pub fn depcmp_literal(pkg: &Package, dep: &Depend) -> bool {
	// the hash alone first: cutting dep.name at its nul before the
	// mismatch is known cost requiredby a scan per pair
	pkg.name_hash == dep.name_hash
		&& has_name(pkg, until_nul(&dep.name), dep.name_hash)
		&& dep_vercmp(
			pkg.version.as_deref(),
			dep.depmod,
			dep.version.as_deref(),
		)
}

/// _alpm_depcmp: the package itself or one of its provisions
pub fn depcmp(pkg: &Package, dep: &Depend) -> bool {
	depcmp_literal(pkg, dep) || depcmp_provides(dep, &pkg.provides)
}

/// alpm_find_satisfier: first package in list order satisfying depstring
pub fn find_satisfier<'a, I>(pkgs: I, depstring: &[u8]) -> Option<&'a Package>
where
	I: IntoIterator<Item = &'a Package>,
{
	find_dep_satisfier(pkgs, &dep_from_string(depstring))
}

/// find_dep_satisfier (static in C): first package in list order
/// satisfying dep
pub fn find_dep_satisfier<'a, I>(pkgs: I, dep: &Depend) -> Option<&'a Package>
where
	I: IntoIterator<Item = &'a Package>,
{
	pkgs.into_iter().find(|p| depcmp(p, dep))
}

/// alpm_dep_from_string: "name[op version][: desc]". the first ": "
/// starts the description (a bare ':' is an epoch), the operator is
/// searched before it, '<' first, then '>', then '='
pub fn dep_from_string(s: &[u8]) -> Depend {
	let s = until_nul(s);
	let (head, desc) = match s.windows(2).position(|w| w == b": ") {
		Some(i) => (&s[..i], Some(s[i + 2..].into())),
		None => (s, None),
	};

	// ptr[1] in the C may sit just past the head: that byte is ':' or the
	// nul, never '=', so start never passes head.len()
	let op = |c: u8, with_eq: DepMod, bare: DepMod| {
		let i = head.iter().position(|&b| b == c)?;
		Some(match s.get(i + 1) {
			Some(b'=') => (i, i + 2, with_eq),
			_ => (i, i + 1, bare),
		})
	};
	let eq = || {
		let i = head.iter().position(|&b| b == b'=')?;
		Some((i, i + 1, DepMod::Eq))
	};
	let found = op(b'<', DepMod::Le, DepMod::Lt)
		.or_else(|| op(b'>', DepMod::Ge, DepMod::Gt))
		.or_else(eq);

	let (name, version, depmod) = match found {
		Some((i, start, m)) => {
			(&head[..i], Some(head[start..].into()), m)
		}
		None => (head, None, DepMod::Any),
	};
	Depend {
		name: name.into(),
		version,
		desc,
		name_hash: hash_sdbm(name),
		depmod,
	}
}

/// alpm_dep_compute_string: version is dropped for Any, a missing
/// version prints nothing after the operator. fields go through %s, so
/// each is cut at its first nul
pub fn dep_compute_string(dep: &Depend) -> Vec<u8> {
	let ver = match dep.depmod {
		DepMod::Any => &[][..],
		_ => dep.version.as_deref().unwrap_or_default(),
	};
	let (name, op) = (&dep.name[..], dep.depmod.as_bytes());
	let mut out = [name, op, ver].map(until_nul).concat();
	if let Some(desc) = &dep.desc {
		out.extend_from_slice(b": ");
		out.extend_from_slice(until_nul(desc));
	}
	out
}

/// alpm_depmissing_t. causingpkg is set by reverse dependency checks only
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepMissing {
	pub target: Vec<u8>,
	pub depend: Depend,
	pub causingpkg: Option<Vec<u8>>,
}

/// a db as the resolver reads it: alpm_db_t usage, the loaded cache
/// (list order for scans, the hash for lookups by name) and its name, what
/// alpm_pkg_get_db gives a provider in the select question
#[derive(Clone, Copy, Debug)]
pub struct DbPkgs<'a> {
	pub usage: c_int,
	pub cache: &'a PkgHash<Package>,
	pub name: &'a [u8],
}

/// the handle options deps.c reads (Handle::deps_opts)
#[derive(Clone, Copy, Debug)]
pub struct DepsOpts<'a> {
	pub ignorepkg: &'a [Vec<u8>],
	pub ignoregroup: &'a [Vec<u8>],
	pub assumeinstalled: &'a [Depend],
}

impl DepsOpts<'_> {
	/// alpm_pkg_should_ignore: the name or one of the groups matches an
	/// ignorepkg/ignoregroup entry as an fnmatch pattern (alpm_list_find
	/// with _alpm_fnmatch, so no '!' negation). groups as given, the C
	/// getter lazy-loads them for local packages
	pub fn should_ignore(&self, pkg: &Package) -> bool {
		let matches = |pats: &[Vec<u8>], s: &[u8]| {
			pats.iter().any(|p| fnmatch(p, s))
		};
		matches(self.ignorepkg, pkg.name_bytes())
			|| pkg.groups
				.iter()
				.any(|g| matches(self.ignoregroup, g))
	}
}

/// the handle state deps.c reads. packages need depends, provides, groups
/// and reason loaded (the C getters lazy-load local entries)
#[derive(Clone, Copy, Debug)]
pub struct DepsEnv<'a> {
	pub opts: DepsOpts<'a>,
	/// handle->trans->flags & ALPM_TRANS_FLAG_NODEPVERSION, false without
	/// a transaction
	pub nodepversion: bool,
	/// handle->db_local
	pub local: DbPkgs<'a>,
	/// handle->dbs_sync, registration order
	pub sync: &'a [DbPkgs<'a>],
}

fn name_of(pkg: &Package) -> &[u8] {
	opt_str(&pkg.name)
}

// _alpm_pkg_depends_on (static in C): pkg2 satisfies a depend of pkg1
fn depends_on(pkg1: &Package, pkg2: &Package) -> bool {
	pkg1.depends.iter().any(|d| depcmp(pkg2, d))
}

fn satisfied_in(pkgs: &[&Package], dep: &Depend) -> bool {
	find_dep_satisfier(pkgs.iter().copied(), dep).is_some()
}

fn find_name<'a>(pkgs: &[&'a Package], name: &[u8]) -> Option<&'a Package> {
	pkg_find(pkgs.iter().copied(), name)
}

/// alpm_list_diff with _alpm_pkg_cmp: both sides merge sorted by name
/// (stable), an equal name cancels one entry on each side. the result is
/// in name order
pub fn list_diff<'a>(
	lhs: &[&'a Package],
	rhs: &[&Package],
) -> Vec<&'a Package> {
	let mut left = lhs.to_vec();
	left.sort_by(|a, b| pkg_cmp(a, b));
	let mut right = rhs.to_vec();
	right.sort_by(|a, b| pkg_cmp(a, b));
	let (mut l, mut r, mut out) = (0, 0, Vec::new());
	while l < left.len() && r < right.len() {
		match pkg_cmp(left[l], right[r]) {
			Ordering::Less => {
				out.push(left[l]);
				l += 1;
			}
			Ordering::Greater => r += 1,
			Ordering::Equal => (l, r) = (l + 1, r + 1),
		}
	}
	out.extend_from_slice(&left[l..]);
	out
}

// NODEPVERSION: the C sets depend->mod to ANY in place and restores it
// afterwards, so missing entries and log lines carry the ANY copy
fn effective(dep: &Depend, nodepversion: bool) -> Cow<'_, Depend> {
	match nodepversion {
		false => Cow::Borrowed(dep),
		true => Cow::Owned(Depend {
			depmod: DepMod::Any,
			..dep.clone()
		}),
	}
}

/// alpm_checkdeps: pkglist entries named in rem or upgrade are the
/// modified ones, the rest the untouched db. upgrade depends need a
/// satisfier in upgrade, the untouched db or assumeinstalled. with
/// reversedeps, untouched packages whose depend only a modified package
/// satisfied are broken
pub fn checkdeps(
	env: &DepsEnv,
	pkglist: &[&Package],
	rem: &[&Package],
	upgrade: &[&Package],
	reversedeps: bool,
	log: &mut dyn Callbacks,
) -> Vec<DepMissing> {
	let touched = |p: &&Package| {
		let n = p.name_bytes();
		find_name(rem, n).is_some() || find_name(upgrade, n).is_some()
	};
	let (modified, dblist): (Vec<&Package>, Vec<&Package>) =
		pkglist.iter().copied().partition(touched);
	let satisfied = |dep: &Depend| {
		satisfied_in(upgrade, dep)
			|| satisfied_in(&dblist, dep)
			|| depcmp_provides(dep, env.opts.assumeinstalled)
	};
	let mut baddeps = Vec::new();

	for tp in upgrade {
		let (name, ver) = (name_of(tp), opt_str(&tp.version));
		let line: [&[u8]; 5] =
			[b"checkdeps: package ", name, b"-", ver, b"\n"];
		logv(log, LogLevel::Debug, &line);
		for d in &tp.depends {
			let dep = effective(d, env.nodepversion);
			if satisfied(&dep) {
				continue;
			}
			let s = dep_compute_string(&dep);
			let line: [&[u8]; 5] = [
				b"checkdeps: missing dependency '",
				&s,
				b"' for package '",
				name,
				b"'\n",
			];
			logv(log, LogLevel::Debug, &line);
			baddeps.push(DepMissing {
				target: tp.name_bytes().to_vec(),
				depend: dep.into_owned(),
				causingpkg: None,
			});
		}
	}

	if !reversedeps {
		return baddeps;
	}
	for lp in &dblist {
		for d in &lp.depends {
			let dep = effective(d, env.nodepversion);
			let causing = find_dep_satisfier(
				modified.iter().copied(),
				&dep,
			);
			let Some(causing) = causing else { continue };
			if satisfied(&dep) {
				continue;
			}
			let s = dep_compute_string(&dep);
			let line: [&[u8]; 5] = [
				b"checkdeps: transaction would break '",
				&s,
				b"' dependency of '",
				name_of(lp),
				b"'\n",
			];
			logv(log, LogLevel::Debug, &line);
			baddeps.push(DepMissing {
				target: lp.name_bytes().to_vec(),
				depend: dep.into_owned(),
				causingpkg: Some(causing.name_bytes().to_vec()),
			});
		}
	}
	baddeps
}

// dep_graph_init (static in C): a vertex per target, an edge for each
// dependency. local packages not among targets/ignore (by name) join
// lazily when a vertex depends on them, so their own deps are followed
fn dep_graph_init<'a>(
	local: &[&'a Package],
	targets: &[&'a Package],
	ignore: &[&Package],
) -> Vec<Graph<&'a Package>> {
	let mut localpkgs = list_diff(local, targets);
	if !ignore.is_empty() {
		localpkgs = list_diff(&localpkgs, ignore);
	}
	let mut vertices: Vec<_> =
		targets.iter().map(|&p| Graph::new(p)).collect();
	// vertices appended below are visited too
	let mut i = 0;
	while i < vertices.len() {
		let p_i = vertices[i].data;
		for j in 0..vertices.len() {
			if depends_on(p_i, vertices[j].data) {
				vertices[i].children.push(j);
			}
		}
		let mut j = 0;
		while j < localpkgs.len() {
			if !depends_on(p_i, localpkgs[j]) {
				j += 1;
				continue;
			}
			vertices.push(Graph::new(localpkgs.remove(j)));
			let id = vertices.len() - 1;
			vertices[i].children.push(id);
		}
		i += 1;
	}
	vertices
}

// the C's alpm_list_find_ptr on targets
fn is_target(targets: &[&Package], pkg: &Package) -> bool {
	targets.iter().any(|t| ptr::eq(*t, pkg))
}

// _alpm_warn_dep_cycle (static in C): vertex is being processed and a
// child of ancestor. only logged when vertex is a target and a target
// ancestor other than vertex itself exists
fn warn_dep_cycle(
	log: &mut dyn Callbacks,
	vertices: &[Graph<&Package>],
	targets: &[&Package],
	ancestor: usize,
	vertex: usize,
	reverse: bool,
) {
	if !is_target(targets, vertices[vertex].data) {
		return;
	}
	let mut a = Some(ancestor);
	while let Some(x) = a {
		if is_target(targets, vertices[x].data) {
			break;
		}
		a = vertices[x].parent;
	}
	let Some(a) = a.filter(|&a| a != vertex) else {
		return;
	};
	let (anc, child) = (vertices[a].data, vertices[vertex].data);
	logv(log, LogLevel::Debug, &[b"dependency cycle detected:\n"]);
	let what: &[u8] = match reverse {
		true => b" will be removed after its ",
		false => b" will be installed before its ",
	};
	let line: [&[u8]; 4] =
		[name_of(anc), what, name_of(child), b" dependency\n"];
	logv(log, LogLevel::Debug, &line);
}

/// _alpm_sortbydeps: targets reordered so dependencies come first
/// (reverse: last), by an iterative DFS over dep_graph_init's vertices in
/// creation order. local packages only link indirect dependencies, ignore
/// keeps some out. targets are matched by identity like the C pointers
pub fn sortbydeps<'a>(
	env: &DepsEnv<'a>,
	targets: &[&'a Package],
	ignore: &[&Package],
	reverse: bool,
	log: &mut dyn Callbacks,
) -> Vec<&'a Package> {
	if targets.is_empty() {
		return Vec::new();
	}
	logv(log, LogLevel::Debug, &[b"started sorting dependencies\n"]);
	let local: Vec<&Package> = env.local.cache.iter().collect();
	let mut vertices = dep_graph_init(&local, targets, ignore);
	let mut newtargs = Vec::new();

	// i: the top-level vertex, v: the one being visited
	let (mut i, mut v) = (0, 0);
	while i < vertices.len() {
		vertices[v].state = State::Processing;
		let mut switched = false;
		while !switched && let Some(next) = vertices[v].next_child() {
			match vertices[next].state {
				State::Unprocessed => {
					switched = true;
					vertices[next].parent = Some(v);
					v = next;
				}
				State::Processing => warn_dep_cycle(
					log, &vertices, targets, v, next,
					reverse,
				),
				State::Processed => {}
			}
		}
		if switched {
			continue;
		}
		if is_target(targets, vertices[v].data) {
			newtargs.push(vertices[v].data);
		}
		vertices[v].state = State::Processed;
		match vertices[v].parent {
			Some(p) => v = p,
			None => {
				i += 1;
				while i < vertices.len()
					&& vertices[i].state
						!= State::Unprocessed
				{
					i += 1;
				}
				v = i;
			}
		}
	}

	logv(log, LogLevel::Debug, &[b"sorting dependencies finished\n"]);
	if reverse {
		newtargs.reverse();
	}
	newtargs
}

// _alpm_select_depends (static in C): moves the packages of from that
// pkg depends on to the end of to, keeping explicitly installed ones
// unless explicit
fn select_depends<'a>(
	from: &mut Vec<&'a Package>,
	to: &mut Vec<&'a Package>,
	pkg: &Package,
	explicit: bool,
) {
	let mut i = 0;
	while i < from.len() {
		let deppkg = from[i];
		let reason_ok = explicit || deppkg.reason == PkgReason::Depend;
		if reason_ok && depends_on(pkg, deppkg) {
			to.push(from.remove(i));
		} else {
			i += 1;
		}
	}
}

// _alpm_recursedeps' selection: every package of db only needed by
// targs (transitively), in the order the C appends them. packages of db
// with a target's name never count; explicitly installed ones only with
// include_explicit. db is the cache of the db (remove.c passes the local
// one); the caller logs and dups each one into targs, the C's tail loop
pub fn recursedeps<'a>(
	db: &'a PkgHash<Package>,
	targs: &[Package],
	include_explicit: bool,
) -> Vec<&'a Package> {
	let mut keep: Vec<&Package> = db.iter().collect();
	for t in targs.iter() {
		let i = keep.iter().position(|k| pkg_cmp(k, t).is_eq());
		if let Some(i) = i {
			keep.remove(i);
		}
	}

	let mut rem = Vec::new();
	for t in targs.iter() {
		select_depends(&mut keep, &mut rem, t, include_explicit);
	}
	// rem grows while it is walked
	let mut i = 0;
	while i < rem.len() {
		let p = rem[i];
		select_depends(&mut keep, &mut rem, p, include_explicit);
		i += 1;
	}
	// still needed by a kept package: back to keep, walked as well
	let mut i = 0;
	while i < keep.len() && !rem.is_empty() {
		let p = keep[i];
		select_depends(&mut rem, &mut keep, p, true);
		i += 1;
	}
	rem
}

// the ignored-package branch of resolvedep: with prompt the question,
// else a warning and the default (skip). true installs anyway
fn install_ignored(
	cb: &mut dyn Callbacks,
	pkg: &Package,
	prompt: bool,
) -> bool {
	let mut q = Question::InstallIgnorepkg { install: 0, pkg };
	if prompt {
		cb.question(&mut q);
	} else {
		let (name, ver) = (name_of(pkg), opt_str(&pkg.version));
		let line: [&[u8]; 5] =
			[b"ignoring package ", name, b"-", ver, b"\n"];
		logv(cb, LogLevel::Warning, &line);
	}
	q.answer() != 0
}

// resolvedep (static in C): a satisfier of dep in the dbs used for
// install/upgrade, skipping packages named in excluding. first a
// package named dep in db order, then providers over every db in cache
// order: an installed provider wins at once, more than one asks the
// select question. ignored packages are skipped unless installed anyway
fn resolvedep<'a>(
	env: &DepsEnv<'a>,
	dep: &Depend,
	dbs: &[DbPkgs<'a>],
	excluding: &[&Package],
	prompt: bool,
	cb: &mut dyn Callbacks,
) -> Result<&'a Package, Errno> {
	let usable = |db: &&DbPkgs<'a>| {
		db.usage & (DB_USAGE_INSTALL | DB_USAGE_UPGRADE) != 0
	};
	let excluded =
		|p: &Package| find_name(excluding, p.name_bytes()).is_some();
	let mut ignored = false;

	for db in dbs.iter().filter(usable) {
		let Some(pkg) = db.cache.find(&dep.name) else {
			continue;
		};
		if !depcmp_literal(pkg, dep) || excluded(pkg) {
			continue;
		}
		if env.opts.should_ignore(pkg)
			&& !install_ignored(cb, pkg, prompt)
		{
			ignored = true;
			continue;
		}
		return Ok(pkg);
	}

	let name = until_nul(&dep.name);
	let (mut providers, mut provider_dbs) = (Vec::new(), Vec::new());
	for db in dbs.iter().filter(usable) {
		for pkg in db.cache.iter() {
			if has_name(pkg, name, dep.name_hash)
				|| !depcmp_provides(dep, &pkg.provides)
				|| excluded(pkg)
			{
				continue;
			}
			if env.opts.should_ignore(pkg)
				&& !install_ignored(cb, pkg, prompt)
			{
				ignored = true;
				continue;
			}
			let line: [&[u8]; 5] = [
				b"provider found (",
				name_of(pkg),
				b" provides ",
				name,
				b")\n",
			];
			logv(cb, LogLevel::Debug, &line);
			if env.local.cache.find(pkg.name_bytes()).is_some() {
				return Ok(pkg);
			}
			providers.push(pkg);
			provider_dbs.push(db.name);
		}
	}

	if !providers.is_empty() {
		let mut q = Question::SelectProvider {
			use_index: 0,
			providers: &providers,
			dbs: &provider_dbs,
			depend: dep,
		};
		if providers.len() > 1 {
			cb.question(&mut q);
		}
		let chosen = usize::try_from(q.answer()).ok();
		if let Some(&pkg) = chosen.and_then(|i| providers.get(i)) {
			return Ok(pkg);
		}
	}
	Err(match ignored {
		true => Errno::PkgIgnored,
		false => Errno::PkgNotFound,
	})
}

/// alpm_find_dbs_satisfier: resolvedep over dbs, asking about ignored
/// packages. an empty dbs is the C's NULL list (WRONG_ARGS)
pub fn find_dbs_satisfier<'a>(
	env: &DepsEnv<'a>,
	dbs: &[DbPkgs<'a>],
	depstring: &[u8],
	cb: &mut dyn Callbacks,
) -> Result<&'a Package, Errno> {
	if dbs.is_empty() {
		return Err(Errno::WrongArgs);
	}
	let dep = dep_from_string(depstring);
	resolvedep(env, &dep, dbs, &[], true, cb)
}

/// _alpm_resolvedeps: adds pkg and the sync packages resolving its missing
/// dependencies (depth first) to packages. satisfiers already in packages
/// or preferred come first, then the sync dbs; a dependency an installed
/// package (not in rem) satisfies is fine. on failure packages is restored
/// and the unresolvable entries are appended to data (the C appends only
/// with a data list, here the caller drops them). Err is always
/// UNSATISFIED_DEPS: the pm_errno the C leaves behind is overwritten by
/// later lookups and by its caller (sync.c)
#[allow(clippy::too_many_arguments)]
pub fn resolvedeps<'a>(
	env: &DepsEnv<'a>,
	localpkgs: &[&'a Package],
	pkg: &'a Package,
	preferred: &[&'a Package],
	packages: &mut Vec<&'a Package>,
	rem: &[&'a Package],
	data: &mut Vec<DepMissing>,
	cb: &mut dyn Callbacks,
) -> Result<(), Errno> {
	let r = Resolve {
		env,
		localpkgs,
		preferred,
		rem,
	};
	match r.resolve(pkg, packages, data, cb) {
		true => Ok(()),
		false => Err(Errno::UnsatisfiedDeps),
	}
}

// the arguments _alpm_resolvedeps passes down unchanged
struct Resolve<'r, 'a> {
	env: &'r DepsEnv<'a>,
	localpkgs: &'r [&'a Package],
	preferred: &'r [&'a Package],
	rem: &'r [&'a Package],
}

impl<'a> Resolve<'_, 'a> {
	fn lookup(
		&self,
		dep: &Depend,
		dbs: &[DbPkgs<'a>],
		excluding: &[&Package],
		cb: &mut dyn Callbacks,
	) -> Option<&'a Package> {
		resolvedep(self.env, dep, dbs, excluding, false, cb).ok()
	}

	fn resolve(
		&self,
		pkg: &'a Package,
		packages: &mut Vec<&'a Package>,
		data: &mut Vec<DepMissing>,
		cb: &mut dyn Callbacks,
	) -> bool {
		if find_name(packages, pkg.name_bytes()).is_some() {
			return true;
		}
		let copy = packages.clone();
		packages.push(pkg);

		logv(
			cb,
			LogLevel::Debug,
			&[b"started resolving dependencies\n"],
		);
		let deps = checkdeps(
			self.env,
			self.localpkgs,
			self.rem,
			&[pkg],
			false,
			cb,
		);
		let mut ok = true;
		for miss in deps {
			let dep = &miss.depend;
			if find_dep_satisfier(packages.iter().copied(), dep)
				.is_some()
			{
				continue;
			}
			let preferred = self.preferred.iter().copied();
			let spkg = match find_dep_satisfier(preferred, dep) {
				Some(p) => Some(p),
				None => self.lookup(
					dep,
					self.env.sync,
					packages,
					cb,
				),
			};
			if let Some(spkg) = spkg
				&& self.resolve(spkg, packages, data, cb)
			{
				let line: [&[u8]; 5] = [
					b"pulling dependency ",
					name_of(spkg),
					b" (needed by ",
					name_of(pkg),
					b")\n",
				];
				logv(cb, LogLevel::Debug, &line);
				continue;
			}
			let local = std::slice::from_ref(&self.env.local);
			if self.lookup(dep, local, self.rem, cb).is_some() {
				continue;
			}
			let s = dep_compute_string(dep);
			let line: [&[u8]; 5] = [
				b"cannot resolve \"",
				&s,
				b"\", a dependency of \"",
				name_of(pkg),
				b"\"\n",
			];
			logv(cb, LogLevel::Warning, &line);
			data.push(miss);
			ok = false;
		}

		if !ok {
			*packages = copy;
		}
		logv(
			cb,
			LogLevel::Debug,
			&[b"finished resolving dependencies\n"],
		);
		ok
	}
}
