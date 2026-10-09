// alpm_core::internals::error::strerror against C alpm_strerror
use alpm_core::internals::error::{Errno, strerror};
use difftest::{Rng, c_strerror};

fn check(err: i32) {
	assert_eq!(c_strerror(err), strerror(err).as_bytes(), "err {err}");
}

#[test]
fn every_value_and_out_of_range() {
	for &e in &Errno::ALL {
		assert_eq!(
			c_strerror(e as i32),
			e.strerror().as_bytes(),
			"{e:?}"
		);
	}
	for err in -300..300 {
		check(err);
	}
	for err in [i32::MIN, i32::MIN + 1, i32::MAX - 1, i32::MAX] {
		check(err);
	}
}

#[test]
fn fuzz() {
	let mut rng = Rng::new(0xe770);
	for _ in 0..difftest::iters() {
		check(rng.next_u64() as i32);
	}
}
