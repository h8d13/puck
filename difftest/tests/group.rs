// alpm_core::internals::group against the C in group.c
use alpm_core::internals::group::Group;
use alpm_core::internals::package::Package;
use difftest::{Rng, c_group_new, iters};

fn assert_same(name: &[u8]) {
	let g = Group::<Package>::new(name);
	assert_eq!(
		c_group_new(Some(name)),
		(Some(g.name), g.packages.is_empty()),
		"{:?}",
		String::from_utf8_lossy(name)
	);
}

#[test]
fn new_edge_cases() {
	for name in [&b""[..], b"base-devel", b"\xc3"] {
		assert_same(name);
	}
}

#[test]
fn new_fuzz() {
	let mut rng = Rng::new(0x6409);
	for _ in 0..iters() {
		assert_same(&rng.bytes(b"ab- \xc3", 10));
	}
}

// contract the future C ABI shim has to keep: NULL name is copied as NULL
#[test]
fn c_null_contract() {
	assert_eq!(c_group_new(None), (None, true));
}
