// port of lib/libalpm/base64.c (PolarSSL 0.14.2, decode only like upstream)
//
// accepts "\n" and "\r\n" anywhere, up to two trailing '=', nothing after
// padding. an incomplete trailing group is dropped without error.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
	InvalidCharacter,
}

const INVALID: u8 = 127;
const PAD: u8 = 64;

// 6-bit value per ascii byte, PAD for '=', INVALID otherwise
const DEC_MAP: [u8; 128] = {
	let mut map = [INVALID; 128];
	let enc = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\
		0123456789+/";
	let mut i = 0;
	while i < enc.len() {
		map[enc[i] as usize] = i as u8;
		i += 1;
	}
	map[b'=' as usize] = PAD;
	map
};

fn dec(c: u8) -> u8 {
	DEC_MAP.get(c as usize).copied().unwrap_or(INVALID)
}

// number of base64 symbols, padding included, after validation
fn count_symbols(src: &[u8]) -> Result<usize, Error> {
	let (mut n, mut pads) = (0, 0);
	for (i, &c) in src.iter().enumerate() {
		// lone '\r' is rejected below, only "\r\n" is a line break
		if c == b'\n' || (c == b'\r' && src.get(i + 1) == Some(&b'\n'))
		{
			continue;
		}
		let v = dec(c);
		if v == INVALID {
			return Err(Error::InvalidCharacter);
		}
		if v == PAD {
			pads += 1;
			if pads > 2 {
				return Err(Error::InvalidCharacter);
			}
		} else if pads != 0 {
			// data after padding
			return Err(Error::InvalidCharacter);
		}
		n += 1;
	}
	Ok(n)
}

// required output buffer size
pub fn decoded_len(src: &[u8]) -> Result<usize, Error> {
	let n = count_symbols(src)?;
	Ok((n * 6).div_ceil(8))
}

pub fn decode(src: &[u8]) -> Result<Vec<u8>, Error> {
	let mut out = Vec::with_capacity(decoded_len(src)?);
	let (mut x, mut n, mut keep) = (0u32, 0, 3);

	for &c in src {
		if c == b'\r' || c == b'\n' {
			continue;
		}
		let v = dec(c);
		if v == PAD {
			keep -= 1;
		}
		x = (x << 6) | u32::from(v & 0x3f);
		n += 1;
		if n == 4 {
			n = 0;
			let group = [(x >> 16) as u8, (x >> 8) as u8, x as u8];
			out.extend_from_slice(&group[..keep]);
		}
	}
	Ok(out)
}
