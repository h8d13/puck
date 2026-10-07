// unit tests for alpm_core::group
use alpm_core::group::Group;
use alpm_core::package::Package;

#[test]
fn new_copies_name() {
	let g = Group::<Package>::new(b"base-devel");
	assert_eq!(g.name, b"base-devel");
	assert!(g.packages.is_empty());
	assert_eq!(Group::<Package>::new(b"a\0b").name, b"a");
}
