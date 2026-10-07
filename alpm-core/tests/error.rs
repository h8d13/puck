// unit tests for alpm_core::error
use alpm_core::error::{Errno, strerror};

#[test]
fn discriminants_follow_alpm_h() {
	for (i, &e) in Errno::ALL.iter().enumerate() {
		assert_eq!(e as i32, i as i32, "{e:?}");
		assert_eq!(Errno::from_raw(i as i32), Some(e));
	}
	assert_eq!(Errno::MissingCapabilitySignatures as i32, 55);
	assert_eq!(Errno::from_raw(56), None);
	assert_eq!(Errno::from_raw(-1), None);
}

#[test]
fn messages() {
	assert_eq!(strerror(0), "unexpected error");
	assert_eq!(strerror(1), "out of memory!");
	assert_eq!(strerror(-1), "unexpected error");
	assert_eq!(strerror(i32::MAX), "unexpected error");
	assert_eq!(
		Errno::TransNotLocked.to_string(),
		"transaction commit attempt when database is not locked"
	);
}
