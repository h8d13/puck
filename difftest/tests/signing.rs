// alpm_core::internals::signing::decode_signature against C alpm_decode_signature
use alpm_core::internals::signing::{DecodeError, decode_signature};
use difftest::{Rng, c_decode_signature, encode_base64 as encode, iters};

const ENC: &[u8] =
	b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// symbols plus everything the scanner special-cases
const NOISE: &[u8] = b"AZaz09+/====\r\n\n \x7f\xc3-_";

fn random_input(rng: &mut Rng) -> Vec<u8> {
	match rng.below(3) {
		// valid encoding, maybe wrapped, maybe damaged
		0 | 1 => {
			let raw: Vec<u8> = (0..rng.below(40))
				.map(|_| rng.next_u64() as u8)
				.collect();
			let mut s = encode(&raw);
			for _ in 0..rng.below(4) {
				let i = rng.below(s.len() + 1);
				let c = NOISE[rng.below(NOISE.len())];
				if rng.below(2) == 0 || i == s.len() {
					s.insert(i, c);
				} else {
					s[i] = c;
				}
			}
			s
		}
		_ => (0..rng.below(16))
			.map(|_| NOISE[rng.below(NOISE.len())])
			.collect(),
	}
}

// what the C decoder special-cases, by the accepted symbols. the crate
// alone differs on all but Whole: the port's framing keeps them equal
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
	Whole,
	// "\n" or "\r\n" between symbols
	LineBreaks,
	// last whole group padded with nonzero bits after the kept bytes
	TrailingBits,
	// 1-3 symbols after the last whole group, dropped
	DroppedTail,
	// no symbol at all, the C buffer is not initialized
	NoSymbol,
	TooSmall,
	Invalid,
}

fn classes(b64: &[u8], r: &Result<Vec<u8>, DecodeError>) -> Vec<Class> {
	match r {
		Err(DecodeError::BufferTooSmall) => {
			return vec![Class::TooSmall];
		}
		Err(DecodeError::InvalidCharacter) => {
			return vec![Class::Invalid];
		}
		Ok(_) => {}
	}
	let sym: Vec<u8> = b64
		.iter()
		.copied()
		.filter(|&c| c != b'\n' && c != b'\r')
		.collect();
	if sym.is_empty() {
		return vec![Class::NoSymbol];
	}
	let mut out = Vec::new();
	if sym.len() != b64.len() {
		out.push(Class::LineBreaks);
	}
	if !sym.len().is_multiple_of(4) {
		out.push(Class::DroppedTail);
	}
	let whole = &sym[..sym.len() - sym.len() % 4];
	let val = |c: u8| ENC.iter().position(|&e| e == c).unwrap_or(0);
	let low = match whole {
		[.., c, b'=', b'='] => val(*c) & 0xf,
		[.., c, b'='] => val(*c) & 0x3,
		_ => 0,
	};
	if low != 0 {
		out.push(Class::TrailingBits);
	}
	if out.is_empty() {
		out.push(Class::Whole);
	}
	out
}

fn assert_same(b64: &[u8]) -> Vec<Class> {
	let c = c_decode_signature(b64);
	let r = decode_signature(b64);
	let show = String::from_utf8_lossy(b64);
	assert_eq!(c.rc == 0, r.is_ok(), "{show:?} c={} rust={r:?}", c.rc);
	match (c.data, &r) {
		(Some(cd), Ok(rd)) => assert_eq!(&cd, rd, "{show:?}"),
		// C divergence, see UPSTREAM.md
		(None, Ok(rd)) => {
			assert!(rd.is_empty(), "{show:?}");
			assert_eq!(c.len, b64.len() * 3 / 4, "{show:?}");
		}
		_ => {}
	}
	classes(b64, &r)
}

#[test]
fn fuzz_against_c() {
	let n = iters();
	let mut rng = Rng::new(0xb64);
	let mut seen = std::collections::BTreeMap::new();
	for _ in 0..n {
		for k in assert_same(&random_input(&mut rng)) {
			*seen.entry(k).or_insert(0usize) += 1;
		}
	}
	println!("{seen:?}");
	// every class compared: per 1000 inputs, about 3/4 of the rates
	// measured with 200000 iterations
	let min = [
		(Class::Whole, 150),
		(Class::LineBreaks, 40),
		(Class::TrailingBits, 3),
		(Class::DroppedTail, 20),
		(Class::NoSymbol, 20),
		(Class::TooSmall, 70),
		(Class::Invalid, 500),
	];
	for (k, per_1000) in min {
		let got = seen.get(&k).copied().unwrap_or(0);
		assert!(got * 1000 >= n * per_1000, "{k:?}: {got} of {n}");
	}
}

#[test]
fn edge_cases_against_c() {
	let cases: &[(&[u8], &[Class])] = &[
		(b"", &[Class::NoSymbol]),
		(b"\n", &[Class::NoSymbol]),
		(b"\n\n\n\n", &[Class::NoSymbol]),
		(b"\r\n\r\n", &[Class::NoSymbol]),
		(b"\r", &[Class::Invalid]),
		(b"Zg", &[Class::TooSmall]),
		(b"Zg\n\n", &[Class::LineBreaks, Class::DroppedTail]),
		(b"Zg==", &[Class::Whole]),
		(b"Zh==", &[Class::TrailingBits]),
		(b"Zm9=", &[Class::TrailingBits]),
		(b"Zg===", &[Class::Invalid]),
		// enough room that only the pad limit rejects it
		(b"Zg===\n\n\n\n", &[Class::Invalid]),
		(b"Zg=\n=", &[Class::LineBreaks]),
		(b"Zm9v\r\nYmFy", &[Class::LineBreaks]),
		(b"Zm9v\rYmFy", &[Class::Invalid]),
		(b"=Zm9", &[Class::Invalid]),
		(b"Zg==Zg==", &[Class::Invalid]),
		(b"Zm9v-_", &[Class::Invalid]),
		(b"Zm9vYg\n\n\n", &[Class::LineBreaks, Class::DroppedTail]),
		(b"Zm9vZ\n\n\n\n", &[Class::LineBreaks, Class::DroppedTail]),
		(b"Zm9v=\n\n\n", &[Class::LineBreaks, Class::DroppedTail]),
		(b"Zm9vZg=\n\n", &[Class::LineBreaks, Class::DroppedTail]),
	];
	for &(b64, want) in cases {
		let show = String::from_utf8_lossy(b64);
		assert_eq!(assert_same(b64), want, "{show:?}");
	}
}
