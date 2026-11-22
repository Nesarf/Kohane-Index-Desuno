// A dependency-free zlib reader and writer, enough for the KBA lossless tier.
//
// RFC 1950 (zlib wrapper) + RFC 1951 (deflate). The reader supports all three block types
// (stored, fixed Huffman, dynamic Huffman) so it can decode any stream Node's zlib writes;
// the writer emits stored blocks only, which is a legal deflate stream and round-trips through
// both readers - it makes no attempt to compress, because byte-exact compression would mean
// reimplementing a specific zlib library's matching strategy, and that is not the contract
// the KBA tier needs (see tools/selfcheck.mjs, the lossless tier judge).

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
    13, 13,
];

// LSB-first bit reader over a byte slice, the deflate bit order.
struct BitReader<'a> {
    bytes: &'a [u8],
    bit: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        BitReader { bytes, bit: 0 }
    }
    fn read(&mut self, n: u8) -> Result<u32, String> {
        if n == 0 {
            return Ok(0);
        }
        let mut v: u32 = 0;
        for i in 0..n {
            let byte = self.bytes.get(self.bit / 8).copied().ok_or_else(|| "unexpected end of stream".to_string())?;
            v |= (((byte >> (self.bit % 8)) & 1) as u32) << i;
            self.bit += 1;
        }
        Ok(v)
    }
    fn align_byte(&mut self) {
        self.bit = (self.bit + 7) / 8 * 8;
    }
    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, String> {
        let start = self.bit / 8;
        let end = start + n;
        if end > self.bytes.len() {
            return Err("unexpected end of stream".into());
        }
        self.bit = end * 8;
        Ok(self.bytes[start..end].to_vec())
    }
}

// Huffman decoding by walking the code tree one bit at a time. Codes are at most 15 bits,
// so the walk is bounded and dependency-free.
struct Huffman {
    // tree[node] = (zero_child, one_child); a child of 0xFFFF means "no edge here".
    tree: Vec<(u16, u16)>,
    // leaf[node] = Some(symbol) when the node is a symbol.
    leaf: Vec<Option<u16>>,
}

impl Huffman {
    fn from_lengths(lengths: &[u8]) -> Result<Huffman, String> {
        // Count codes per length, then assign canonical codes (RFC 1951 3.2.2).
        let max_bits = 15usize;
        let mut count = [0u16; 16];
        for &l in lengths {
            if l as usize > max_bits {
                return Err("a code length exceeds 15 bits".into());
            }
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut next_code = [0u16; 16];
        let mut code = 0u16;
        for bits in 1..=max_bits {
            code = (code + count[bits - 1]) << 1;
            next_code[bits] = code;
        }
        let mut h = Huffman {
            tree: vec![(0xFFFF, 0xFFFF); 1],
            leaf: vec![None; 1],
        };
        for (symbol, &l) in lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let c = next_code[l as usize];
            next_code[l as usize] += 1;
            let mut node = 0usize;
            for b in (0..l).rev() {
                let bit = (c >> b) & 1;
                let child = if bit == 0 {
                    if h.tree[node].0 == 0xFFFF {
                        h.tree[node].0 = h.tree.len() as u16;
                        h.tree.push((0xFFFF, 0xFFFF));
                        h.leaf.push(None);
                    }
                    h.tree[node].0 as usize
                } else {
                    if h.tree[node].1 == 0xFFFF {
                        h.tree[node].1 = h.tree.len() as u16;
                        h.tree.push((0xFFFF, 0xFFFF));
                        h.leaf.push(None);
                    }
                    h.tree[node].1 as usize
                };
                node = child;
            }
            h.leaf[node] = Some(symbol as u16);
        }
        Ok(h)
    }
    fn decode(&self, r: &mut BitReader) -> Result<u16, String> {
        let mut node = 0usize;
        for _ in 0..15 {
            let bit = r.read(1)?;
            node = if bit == 0 {
                self.tree[node].0 as usize
            } else {
                self.tree[node].1 as usize
            };
            if node == 0xFFFF {
                return Err("an invalid huffman code was read".into());
            }
            if let Some(sym) = self.leaf[node] {
                return Ok(sym);
            }
        }
        Err("a huffman code did not terminate in 15 bits".into())
    }
}

// Fixed Huffman code lengths (RFC 1951 3.2.6): literals 0-143 get 8 bits, 144-255 get 9,
// 256-279 get 7, 280-287 get 8; the 30 distance codes all get 5.
fn fixed_lit_lengths() -> Vec<u8> {
    let mut v = vec![0u8; 288];
    for i in 0..144 {
        v[i] = 8;
    }
    for i in 144..256 {
        v[i] = 9;
    }
    for i in 256..280 {
        v[i] = 7;
    }
    for i in 280..288 {
        v[i] = 8;
    }
    v
}
fn fixed_dist_lengths() -> Vec<u8> {
    vec![5u8; 30]
}

// The length code 285 is 258 with no extra bits; codes 286-287 never appear.
fn decode_length(r: &mut BitReader, code: u16) -> Result<u16, String> {
    if code == 285 {
        return Ok(258);
    }
    let idx = (code - 257) as usize;
    let extra = LENGTH_EXTRA[idx];
    let add = r.read(extra)?;
    Ok(LENGTH_BASE[idx] + add as u16)
}

fn decode_dist(r: &mut BitReader, code: u16) -> Result<u16, String> {
    let idx = code as usize;
    let extra = DIST_EXTRA[idx];
    let add = r.read(extra)?;
    Ok(DIST_BASE[idx] + add as u16)
}

/// Inflate a full RFC 1950 zlib stream back to bytes. Errors name the RFC clause that failed.
pub fn inflate_zlib(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 6 {
        return Err("the zlib stream is too short for its header and checksum".into());
    }
    let cmf = input[0];
    let flg = input[1];
    if (cmf & 0x0F) != 8 {
        return Err("the zlib stream uses an unknown compression method".into());
    }
    if ((cmf as u16) << 8 | flg as u16) % 31 != 0 {
        return Err("the zlib header checksum does not hold".into());
    }
    let mut r = BitReader::new(&input[2..input.len() - 4]);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let bfinal = r.read(1)?;
        let btype = r.read(2)?;
        match btype {
            0 => {
                r.align_byte();
                let len = r.read(16)? as usize;
                let nlen = r.read(16)? as usize;
                if len ^ nlen != 0xFFFF {
                    return Err("the stored block length complement does not hold".into());
                }
                out.extend(r.read_bytes(len)?);
            }
            1 => {
                let lit = Huffman::from_lengths(&fixed_lit_lengths())?;
                let dist = Huffman::from_lengths(&fixed_dist_lengths())?;
                loop {
                    let sym = lit.decode(&mut r)?;
                    if sym < 256 {
                        out.push(sym as u8);
                    } else if sym == 256 {
                        break;
                    } else if sym <= 285 {
                        let len = decode_length(&mut r, sym)? as usize;
                        let dcode = dist.decode(&mut r)?;
                        if dcode > 29 {
                            return Err("the fixed distance code is out of range".into());
                        }
                        let d = decode_dist(&mut r, dcode)? as usize;
                        if d > out.len() {
                            return Err("a match distance points before the start of the output".into());
                        }
                        for _ in 0..len {
                            let b = out[out.len() - d];
                            out.push(b);
                        }
                    } else {
                        return Err("a literal code beyond 285 was read".into());
                    }
                }
            }
            2 => {
                let hlit = r.read(5)? as usize + 257;
                let hdist = r.read(5)? as usize + 1;
                let hclen = r.read(4)? as usize + 4;
                const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
                let mut clen = [0u8; 19];
                for i in 0..hclen {
                    clen[ORDER[i]] = r.read(3)? as u8;
                }
                let clen_h = Huffman::from_lengths(&clen)?;
                let mut lengths = Vec::with_capacity(hlit + hdist);
                while lengths.len() < hlit + hdist {
                    let sym = clen_h.decode(&mut r)?;
                    match sym {
                        0..=15 => lengths.push(sym as u8),
                        16 => {
                            if lengths.is_empty() {
                                return Err("a repeat code appears before any length".into());
                            }
                            let prev = *lengths.last().unwrap();
                            let n = r.read(2)? as usize + 3;
                            for _ in 0..n {
                                lengths.push(prev);
                            }
                        }
                        17 => {
                            let n = r.read(3)? as usize + 3;
                            for _ in 0..n {
                                lengths.push(0);
                            }
                        }
                        18 => {
                            let n = r.read(7)? as usize + 11;
                            for _ in 0..n {
                                lengths.push(0);
                            }
                        }
                        _ => return Err("a code-length symbol beyond 18 was read".into()),
                    }
                    if lengths.len() > hlit + hdist {
                        return Err("the declared literal table overflowed".into());
                    }
                }
                let lit = Huffman::from_lengths(&lengths[..hlit])?;
                let dist = Huffman::from_lengths(&lengths[hlit..])?;
                loop {
                    let sym = lit.decode(&mut r)?;
                    if sym < 256 {
                        out.push(sym as u8);
                    } else if sym == 256 {
                        break;
                    } else if sym <= 285 {
                        let len = decode_length(&mut r, sym)? as usize;
                        let dcode = dist.decode(&mut r)?;
                        if dcode > 29 {
                            return Err("the distance code is out of range".into());
                        }
                        let d = decode_dist(&mut r, dcode)? as usize;
                        if d > out.len() {
                            return Err("a match distance points before the start of the output".into());
                        }
                        for _ in 0..len {
                            let b = out[out.len() - d];
                            out.push(b);
                        }
                    } else {
                        return Err("a literal code beyond 285 was read".into());
                    }
                }
            }
            _ => return Err("the deflate stream uses a reserved block type".into()),
        }
        if bfinal == 1 {
            break;
        }
    }
    // The trailing adler32 is big-endian in the zlib wrapper.
    let expected = ((input[input.len() - 4] as u32) << 24)
        | ((input[input.len() - 3] as u32) << 16)
        | ((input[input.len() - 2] as u32) << 8)
        | (input[input.len() - 1] as u32);
    let actual = adler32(&out);
    if expected != actual {
        return Err(format!(
            "the zlib checksum does not hold (stream says {expected:#010x}, data says {actual:#010x})"
        ));
    }
    Ok(out)
}

/// Adler-32 (RFC 1950 8.2): A = 1 + sum(bytes), B = sum of A after each byte, both mod 65521.
pub fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Deflate the input as a zlib stream made of stored blocks only: legal, dependency-free, and
/// round-trip identical through every inflate. Stored blocks carry at most 65535 bytes each.
pub fn deflate_zlib_stored(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 65535 * 5 + 11);
    out.push(0x78); // CMF: deflate, 32K window
    out.push(0x01); // FLG: check bits that make (CMF<<8|FLG) % 31 == 0
    let mut at = 0;
    while at < input.len() || (input.is_empty() && at == 0) {
        let take = std::cmp::min(65535, input.len() - at);
        let last = at + take >= input.len();
        out.push(if last { 1 } else { 0 });
        out.extend_from_slice(&(take as u16).to_le_bytes());
        out.extend_from_slice(&(!(take as u16)).to_le_bytes());
        out.extend_from_slice(&input[at..at + take]);
        at += take;
        if input.is_empty() {
            break;
        }
    }
    out.extend_from_slice(&adler32(input).to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_matches_rfc_example() {
        // The RFC 1950 appendix example: "Wikipedia" gives adler32 0x11E60398.
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
    }

    #[test]
    fn stored_round_trip() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let stream = deflate_zlib_stored(&data);
        assert_eq!(inflate_zlib(&stream).unwrap(), data);
    }

    #[test]
    fn empty_round_trip() {
        let stream = deflate_zlib_stored(b"");
        assert_eq!(inflate_zlib(&stream).unwrap(), b"");
    }

    #[test]
    fn rejects_a_bad_checksum() {
        let mut stream = deflate_zlib_stored(b"hello");
        let n = stream.len();
        stream[n - 1] ^= 0xFF;
        assert!(inflate_zlib(&stream).is_err());
    }

    #[test]
    fn rejects_a_truncated_stream() {
        let stream = deflate_zlib_stored(b"hello world");
        assert!(inflate_zlib(&stream[..stream.len() - 3]).is_err());
    }
}
