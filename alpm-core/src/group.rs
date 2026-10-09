// port of lib/libalpm/group.c
//
// _alpm_group_free is Drop: the C frees the list nodes only, the packages
// belong to the db cache. P is the handle to a member, as in PkgHash

use crate::package::Package;
use crate::util::until_nul;

/// alpm_group_t
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group<P = Package> {
	pub name: Vec<u8>,
	pub packages: Vec<P>,
}

impl<P> Group<P> {
	/// _alpm_group_new: copy of name, no members yet
	pub fn new(name: &[u8]) -> Self {
		Group {
			name: until_nul(name).to_vec(),
			packages: Vec::new(),
		}
	}
}
