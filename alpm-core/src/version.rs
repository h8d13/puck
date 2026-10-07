// port of lib/libalpm/version.c (rpmvercmp + parseEVR, from rpm 4.8.1)
//
// works on bytes like the C: ctype calls run in the C locale there, so
// ascii predicates match, and bytes >= 0x80 count as separators.
// the C sees nul-terminated strings, input is cut at the first nul to match.

use std::cmp::Ordering;

use crate::util::until_nul;

// 0 past the end stands in for the C string terminator
fn at(s: &[u8], i: usize) -> u8 {
	s.get(i).copied().unwrap_or(0)
}

// [epoch:]version[-release], missing or empty epoch is "0"
fn parse_evr(evr: &[u8]) -> (&[u8], &[u8], Option<&[u8]>) {
	let s = evr.iter().take_while(|c| c.is_ascii_digit()).count();
	// last '-' after the epoch digits splits off the release
	let se = evr[s..].iter().rposition(|&c| c == b'-').map(|i| s + i);
	let vend = se.unwrap_or(evr.len());
	let release = se.map(|i| &evr[i + 1..]);

	if at(evr, s) != b':' {
		// different from rpm: always assume 0 epoch
		return (b"0", &evr[..vend], release);
	}
	let epoch = if s == 0 { &b"0"[..] } else { &evr[..s] };
	(epoch, &evr[s + 1..vend], release)
}

// compare alternating alpha and numeric segments
fn rpmvercmp(a: &[u8], b: &[u8]) -> Ordering {
	if a == b {
		return Ordering::Equal;
	}

	let (mut one, mut two) = (0, 0);
	let (mut ptr1, mut ptr2) = (0, 0);

	while at(a, one) != 0 && at(b, two) != 0 {
		while one < a.len() && !a[one].is_ascii_alphanumeric() {
			one += 1;
		}
		while two < b.len() && !b[two].is_ascii_alphanumeric() {
			two += 1;
		}
		if one == a.len() || two == b.len() {
			break;
		}

		// different separator lengths decide on their own
		let (sep1, sep2) = (one - ptr1, two - ptr2);
		if sep1 != sep2 {
			return sep1.cmp(&sep2);
		}

		// segment type is picked from a, b gets walked with the same
		// predicate and may come out empty
		let isnum = a[one].is_ascii_digit();
		let is_seg = |c: &u8| {
			if isnum {
				c.is_ascii_digit()
			} else {
				c.is_ascii_alphabetic()
			}
		};
		ptr1 = one + a[one..].iter().take_while(|c| is_seg(c)).count();
		ptr2 = two + b[two..].iter().take_while(|c| is_seg(c)).count();

		let mut seg1 = &a[one..ptr1];
		let mut seg2 = &b[two..ptr2];

		// numeric segments are always newer than alpha segments
		if seg2.is_empty() {
			return if isnum {
				Ordering::Greater
			} else {
				Ordering::Less
			};
		}

		if isnum {
			// strip leading zeros, then more digits wins
			seg1 = trim_zeros(seg1);
			seg2 = trim_zeros(seg2);
			let len = seg1.len().cmp(&seg2.len());
			if len.is_ne() {
				return len;
			}
		}

		// same as strcmp: alpha order, or digit order at equal length
		let rc = seg1.cmp(seg2);
		if rc.is_ne() {
			return rc;
		}

		one = ptr1;
		two = ptr2;
	}

	let (c1, c2) = (at(a, one), at(b, two));
	// all segments equal, only separators differed
	if c1 == 0 && c2 == 0 {
		return Ordering::Equal;
	}

	// a remaining alpha string never beats an empty one
	if (c1 == 0 && !c2.is_ascii_alphabetic()) || c1.is_ascii_alphabetic() {
		Ordering::Less
	} else {
		Ordering::Greater
	}
}

fn trim_zeros(s: &[u8]) -> &[u8] {
	let n = s.iter().take_while(|&&c| c == b'0').count();
	&s[n..]
}

// alpm_pkg_vercmp without the NULL cases, those live in the C ABI layer
pub fn vercmp(a: &[u8], b: &[u8]) -> Ordering {
	let (a, b) = (until_nul(a), until_nul(b));
	if a == b {
		return Ordering::Equal;
	}

	let (epoch1, ver1, rel1) = parse_evr(a);
	let (epoch2, ver2, rel2) = parse_evr(b);

	let ret = rpmvercmp(epoch1, epoch2).then_with(|| rpmvercmp(ver1, ver2));
	match (ret, rel1, rel2) {
		(Ordering::Equal, Some(r1), Some(r2)) => rpmvercmp(r1, r2),
		_ => ret,
	}
}
