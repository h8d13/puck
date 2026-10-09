// get_install_time's SOURCE_DATE_EPOCH parse: strtoull base 10 over the
// whole string, no ERANGE
use alpm_core::internals::add::install_time;

#[test]
fn install_time_source_date_epoch() {
	let now = 42;
	assert_eq!(install_time(None, now), now);
	assert_eq!(install_time(Some(b"1234"), now), 1234);
	assert_eq!(install_time(Some(b" \t+77"), now), 77);
	// strtoull negates in unsigned long long, time_t reads it back
	assert_eq!(install_time(Some(b"-1"), now), -1);
	assert_eq!(install_time(Some(b"18446744073709551615"), now), -1);
	for bad in
		[&b""[..], b"12x", b" ", b"+", b"18446744073709551616", b"1 "]
	{
		assert_eq!(install_time(Some(bad), now), now, "{bad:?}");
	}
}
