// alpm_core::signing::decode_signature against C alpm_decode_signature
use alpm_core::signing::decode_signature;
use difftest::{Rng, c_decode_signature};

const ENC: &[u8] =
	b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// symbols plus everything the scanner special-cases
const NOISE: &[u8] = b"AZaz09+/====\r\n\n \x7f\xc3-_";

// standard padded encoding, the C has none to compare against
fn encode(raw: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	for chunk in raw.chunks(3) {
		let mut b = [0u8; 3];
		b[..chunk.len()].copy_from_slice(chunk);
		let x = u32::from(b[0]) << 16
			| u32::from(b[1]) << 8
			| u32::from(b[2]);
		for k in 0..4 {
			if k <= chunk.len() {
				out.push(ENC
					[(x >> (18 - 6 * k)) as usize & 0x3f]);
			} else {
				out.push(b'=');
			}
		}
	}
	out
}

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

fn assert_same(b64: &[u8]) {
	let c = c_decode_signature(b64);
	let r = decode_signature(b64);
	let show = String::from_utf8_lossy(b64);
	assert_eq!(c.rc == 0, r.is_ok(), "{show:?} c={} rust={r:?}", c.rc);
	match (c.data, r) {
		(Some(cd), Ok(rd)) => assert_eq!(cd, rd, "{show:?}"),
		// C divergence, see UPSTREAM.md
		(None, Ok(rd)) => {
			assert!(rd.is_empty(), "{show:?}");
			assert_eq!(c.len, b64.len() * 3 / 4, "{show:?}");
		}
		_ => {}
	}
}

#[test]
fn fuzz_against_c() {
	let iters = std::env::var("DIFFTEST_ITERS")
		.map_or(200_000, |s| s.parse().unwrap());
	let mut rng = Rng::new(0xb64);
	for _ in 0..iters {
		assert_same(&random_input(&mut rng));
	}
}

#[test]
fn edge_cases_against_c() {
	let cases: &[&[u8]] = &[
		b"",
		b"\n",
		b"\n\n\n\n",
		b"\r\n\r\n",
		b"\r",
		b"Zg",
		b"Zg\n\n",
		b"Zg==",
		b"Zg===",
		// enough room that only the pad limit rejects it
		b"Zg===\n\n\n\n",
		b"Zg=\n=",
		b"Zm9v\r\nYmFy",
		b"=Zm9",
		b"Zm9vYg\n\n\n",
	];
	for &b64 in cases {
		assert_same(b64);
	}
}
