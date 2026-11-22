// IMA ADPCM, byte-exact with the JS original (deps/decoders/kba.mjs, tier 2).
//
// The JS side uses the standard IMA bit-by-bit form; this port must produce identical bytes, so
// the cross-check in selfcheck can compare outputs directly. Blocks of 1024 frames, each opening
// with pred (i16 LE) and the step index (u8), then packed 4-bit nibbles (low nibble first).
pub const ADPCM_BLOCK: usize = 1024;

pub const STEP_TABLE: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408,
    449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
    2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630,
    9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794,
    32767,
];

pub const INDEX_TABLE: [i32; 16] = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8];

/// Encode 16-bit PCM into the IMA ADPCM body (blocks only - the KBA1 header is separate).
pub fn adpcm_encode(pcm: &[i16]) -> Vec<u8> {
    let frames = pcm.len();
    let blocks = frames.div_ceil(ADPCM_BLOCK);
    let mut body = vec![0u8; blocks * (2 + 1 + ADPCM_BLOCK / 2)];
    let mut out = 0usize;
    for b in 0..blocks {
        let start = b * ADPCM_BLOCK;
        let count = (frames - start).min(ADPCM_BLOCK);
        let mut pred: i32 = 0;
        let mut index: i32 = 0;
        body[out..out + 2].copy_from_slice(&(pred as i16).to_le_bytes());
        out += 2;
        body[out] = index as u8;
        out += 1;
        let mut lo: Option<u8> = None;
        for i in 0..count {
            let x = pcm[start + i] as i32;
            let mut diff = x - pred;
            let mut code: u8 = 0;
            if diff < 0 {
                code = 8;
                diff = -diff;
            }
            let mut step = STEP_TABLE[index as usize];
            let mut delta = step >> 3;
            if diff >= step {
                code |= 4;
                diff -= step;
                delta += step;
            }
            step >>= 1;
            if diff >= step {
                code |= 2;
                diff -= step;
                delta += step;
            }
            step >>= 1;
            if diff >= step {
                code |= 1;
                delta += step;
            }
            pred += if code & 8 != 0 { -delta } else { delta };
            pred = pred.clamp(-32768, 32767);
            index = (index + INDEX_TABLE[(code & 7) as usize]).clamp(0, 88);
            match lo {
                None => {
                    body[out] = code;
                    lo = Some(code);
                }
                Some(first) => {
                    body[out] = first | (code << 4);
                    out += 1;
                    lo = None;
                }
            }
        }
        if lo.is_some() {
            out += 1;
        }
    }
    body.truncate(out);
    body
}
