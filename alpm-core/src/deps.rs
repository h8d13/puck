// port of lib/libalpm/deps.c, dependency strings and version matching.
// resolving (needing a handle or packages) is not ported yet.

use std::cmp::Ordering;
use std::ffi::c_ulong;

use crate::util::{hash_sdbm, until_nul};
use crate::version::vercmp;

// alpm_depmod_t, discriminants as in alpm.h
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepMod {
	Any = 1,
	Eq,
	Ge,
	Le,
	Gt,
	Lt,
}

// alpm_depend_t. NULL strings are None, name is never NULL once parsed
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Depend {
	pub name: Vec<u8>,
	pub version: Option<Vec<u8>>,
	pub desc: Option<Vec<u8>>,
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

// dep_vercmp (static in C): does version1 satisfy "mod version2"
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

// _alpm_depcmp_provides: only versioned provisions ("name=ver") can
// satisfy a versioned dep
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

// alpm_dep_from_string: "name[op version][: desc]". the first ": "
// starts the description (a bare ':' is an epoch), the operator is
// searched before it, '<' first, then '>', then '='
pub fn dep_from_string(s: &[u8]) -> Depend {
	let s = until_nul(s);
	let (head, desc) = match s.windows(2).position(|w| w == b": ") {
		Some(i) => (&s[..i], Some(s[i + 2..].to_vec())),
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
			(&head[..i], Some(head[start..].to_vec()), m)
		}
		None => (head, None, DepMod::Any),
	};
	Depend {
		name: name.to_vec(),
		version,
		desc,
		name_hash: hash_sdbm(name),
		depmod,
	}
}

// alpm_dep_compute_string: version is dropped for Any, a missing
// version prints nothing after the operator. fields go through %s, so
// each is cut at its first nul
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
