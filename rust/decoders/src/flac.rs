// FLAC encoding, order-identical with the JS original (deps/decoders/flac-encoder.mjs).
//
// The port is a verification brick: every branch decision (subframe type, Rice parameters, LPC
// quantisation) must land on the same bytes as JS, so the search logic and all float arithmetic
// are copied operation-for-operation - IEEE f64 order matters for the LPC coefficients. The input
// here is raw 16-bit PCM (the JS side converts the same bytes from floats before encoding), the
// STREAMINFO MD5 describes exactly those bytes, and the independent JS walk (tools/flac-walk.mjs)
// decodes the result sample-exact in the cross-check.
use crate::bitwriter::BitWriter;
use crate::md5::Md5;

const BLOCK: usize = 4096;
const BLOCK_CODE: u32 = 12;

fn crc8(buf: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &b in buf {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 { (crc << 1) ^ 0x07 } else { crc << 1 };
        }
    }
    crc
}

fn crc16(buf: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in buf {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x8005 } else { crc << 1 };
        }
    }
    crc
}

fn utf8_number(value: u64) -> Vec<u8> {
    if value < 0x80 {
        return vec![value as u8];
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut v = value;
    while v > 0 {
        bytes.insert(0, (v & 0x3f) as u8);
        v >>= 6;
    }
    let lead = (0xffu32 << (8 - bytes.len())) & 0xff;
    bytes[0] |= lead as u8;
    bytes
}

/// Levinson-Durbin over the signal's autocorrelation - the same normalisation, the same clamp,
/// the same recursion order as JS, because byte-exactness means float-exactness.
fn lpc_coeffs(s: &[i32], order: usize) -> Vec<f64> {
    let mut r = vec![0f64; order + 1];
    for lag in 0..=order {
        let mut acc = 0f64;
        for i in 0..s.len() - lag {
            acc += (s[i] as f64) * (s[i + lag] as f64);
        }
        r[lag] = acc;
    }
    let r0 = if r[0] != 0.0 { r[0] } else { 1.0 };
    for lag in 0..=order {
        r[lag] /= r0;
    }
    let mut a = vec![0f64; order + 1];
    a[0] = 1.0;
    let mut err = r[0];
    for k in 1..=order {
        let mut delta = r[k];
        for j in 1..k {
            delta -= a[j] * r[k - j];
        }
        let mut refl = delta / err;
        if refl > 0.9999 {
            refl = 0.9999;
        } else if refl < -0.9999 {
            refl = -0.9999;
        }
        let prev = a[..k].to_vec();
        for j in 1..k {
            a[j] = prev[j] - refl * prev[k - j];
        }
        a[k] = refl;
        err *= 1.0 - refl * refl;
        if err < 1e-9 {
            err = 1e-9;
        }
    }
    a
}

struct ResidualPlan {
    p: u32,
    params: Vec<u32>,
    bits: usize,
    per: usize,
}

fn plan_residual(res: &[i32], order: usize, count: usize) -> Option<ResidualPlan> {
    let mut best: Option<ResidualPlan> = None;
    for p in 0..=2u32 {
        if count % (1usize << p) != 0 {
            continue;
        }
        let per = count >> p;
        if per <= order || per == 0 {
            continue;
        }
        let mut params = Vec::new();
        let mut bits = 0usize;
        let mut ok = true;
        for part in 0..(1u32 << p) {
            let from = if part == 0 { 0 } else { per - order + ((part - 1) as usize) * per };
            let to = if part == 0 { per - order } else { per - order + (part as usize) * per };
            if to > res.len() {
                ok = false;
                break;
            }
            let mut best_k = 0u32;
            let mut best_part_bits = usize::MAX;
            for k in 0..=15u32 {
                let b: usize = if k == 15 {
                    5 + (to - from) * 16
                } else {
                    let mut sum = 0usize;
                    for i in from..to {
                        let u = ((res[i] << 1) ^ (res[i] >> 31)) as u32;
                        sum += (u >> k) as usize + 1 + k as usize;
                    }
                    sum
                };
                if b < best_part_bits {
                    best_part_bits = b;
                    best_k = k;
                }
            }
            params.push(best_k);
            bits += best_part_bits;
        }
        if !ok {
            continue;
        }
        let total = bits + 2 + 4 + params.len() * 4;
        if best.as_ref().map(|b| total < b.bits).unwrap_or(true) {
            best = Some(ResidualPlan { p, params, bits: total, per });
        }
    }
    best
}

/// Encode raw 16-bit PCM into a FLAC stream, byte-identical with the JS encoder.
pub fn encode_flac(pcm: &[i16], sample_rate: u32, channels: u16, vendor: &str) -> Vec<u8> {
    let frames = pcm.len() / channels as usize;
    let pcm_bytes: Vec<u8> = pcm
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let md5 = Md5::digest(&pcm_bytes);

    let mut stream_info = vec![0u8; 34];
    stream_info[0..2].copy_from_slice(&(BLOCK as u16).to_be_bytes());
    stream_info[2..4].copy_from_slice(&(BLOCK as u16).to_be_bytes());
    // min/max frame size unknown: already zero
    stream_info[10..14].copy_from_slice(
        &(((sample_rate << 12) | (((channels - 1) as u32) << 9) | ((16 - 1) << 4)) as u32).to_be_bytes(),
    );
    let total = frames as u64;
    stream_info[14..18].copy_from_slice(&((total & 0xffffffff) as u32).to_be_bytes());
    stream_info[18..34].copy_from_slice(&md5);

    let v = vendor.as_bytes();
    let mut comment = Vec::new();
    comment.extend_from_slice(&(v.len() as u32).to_le_bytes());
    comment.extend_from_slice(v);
    comment.extend_from_slice(&0u32.to_le_bytes());

    let mut parts: Vec<u8> = Vec::new();
    parts.extend_from_slice(b"fLaC");
    // metadata block header: not last, type 0 (STREAMINFO), length 34
    parts.push(0x00);
    parts.extend_from_slice(&34u32.to_be_bytes()[1..]);
    parts.extend_from_slice(&stream_info);
    // last block, type 4 (vorbis comment)
    parts.push(0x84);
    parts.extend_from_slice(&(comment.len() as u32).to_be_bytes()[1..]);
    parts.extend_from_slice(&comment);

    let mut frame_number = 0u64;
    let mut frame_start = 0usize;
    while frame_start < frames {
        let count = BLOCK.min(frames - frame_start);
        let partial = count != BLOCK;

        let mut header = BitWriter::new();
        header.write(0x3ffe, 14);
        header.write(0, 1);
        header.write(0, 1);
        header.write(if partial { 7 } else { BLOCK_CODE }, 4);
        header.write(0, 4);
        header.write(if channels == 1 { 0 } else { 1 }, 4);
        header.write(4, 3);
        header.write(0, 1);
        let number_bytes = utf8_number(frame_number);
        let size_field: Vec<u8> = if partial {
            vec![((count - 1) >> 8) as u8, (count - 1) as u8]
        } else {
            Vec::new()
        };
        let mut header_bytes = header.into_bytes();
        header_bytes.extend_from_slice(&number_bytes);
        header_bytes.extend_from_slice(&size_field);
        let mut with_crc = header_bytes.clone();
        with_crc.push(crc8(&header_bytes));

        let mut body = BitWriter::new();
        for c in 0..channels as usize {
            let mut s = vec![0i32; count];
            for i in 0..count {
                s[i] = pcm[(frame_start + i) * channels as usize + c] as i32;
            }

            let mut constant = true;
            for i in 1..count {
                if s[i] != s[0] {
                    constant = false;
                    break;
                }
            }

            body.write(0, 1);
            if constant {
                body.write(0, 6);
                body.write(0, 1);
                body.write_signed(s[0], 16);
                continue;
            }

            struct Candidate {
                kind_lpc: bool,
                order: usize,
                precision: usize,
                shift: i32,
                q: Vec<i32>,
                p: u32,
                params: Vec<u32>,
                bits: usize,
                res: Vec<i32>,
                per: usize,
            }

            let mut best: Option<Candidate> = None;
            let try_fixed = |best: &mut Option<Candidate>, order: usize, res: &[i32], plan: &ResidualPlan| {
                let total = plan.bits + order * 16;
                if best.as_ref().map(|b| total < b.bits).unwrap_or(true) {
                    *best = Some(Candidate {
                        kind_lpc: false,
                        order,
                        precision: 0,
                        shift: 0,
                        q: Vec::new(),
                        p: plan.p,
                        params: plan.params.clone(),
                        bits: total,
                        res: res.to_vec(),
                        per: plan.per,
                    });
                }
            };

            for order in 0..=4usize {
                if count <= order {
                    continue;
                }
                let mut res = vec![0i32; count - order];
                let mut res_ok = true;
                for i in order..count {
                    let predicted = match order {
                        1 => s[i - 1],
                        2 => 2 * s[i - 1] - s[i - 2],
                        3 => 3 * s[i - 1] - 3 * s[i - 2] + s[i - 3],
                        4 => 4 * s[i - 1] - 6 * s[i - 2] + 4 * s[i - 3] - s[i - 4],
                        _ => 0,
                    };
                    res[i - order] = s[i] - predicted;
                    if res[i - order] > 32767 || res[i - order] < -32768 {
                        res_ok = false;
                    }
                }
                if !res_ok {
                    continue;
                }
                if let Some(plan) = plan_residual(&res, order, count) {
                    try_fixed(&mut best, order, &res, &plan);
                }
            }

            for order in 1..=8usize {
                if count <= order {
                    continue;
                }
                let coeffs = lpc_coeffs(&s, order);
                for precision in 12..=16usize {
                    let max_q = (1i32 << (precision - 1)) - 1;
                    for shift in -6..=6i32 {
                        let mut q = vec![0i32; order];
                        let mut q_ok = true;
                        for j in 1..=order {
                            let v = (coeffs[j] * 2f64.powi(shift)).round();
                            if v > max_q as f64 || v < -(max_q as f64) - 1.0 {
                                q_ok = false;
                                break;
                            }
                            q[j - 1] = v as i32;
                        }
                        if !q_ok {
                            continue;
                        }
                        let mut res = vec![0i32; count - order];
                        let mut res_ok = true;
                        for i in order..count {
                            let mut sum = 0f64;
                            for j in 0..order {
                                sum += (q[j] as f64) * (s[i - 1 - j] as f64);
                            }
                            let pred = (sum / 2f64.powi(shift)).floor() as i32;
                            res[i - order] = s[i] - pred;
                            if res[i - order] > 32767 || res[i - order] < -32768 {
                                res_ok = false;
                                break;
                            }
                        }
                        if !res_ok {
                            continue;
                        }
                        let Some(plan) = plan_residual(&res, order, count) else {
                            continue;
                        };
                        let total = plan.bits + order * 16 + 4 + 5 + order * precision;
                        if best.as_ref().map(|b| total < b.bits).unwrap_or(true) {
                            best = Some(Candidate {
                                kind_lpc: true,
                                order,
                                precision,
                                shift,
                                q,
                                p: plan.p,
                                params: plan.params.clone(),
                                bits: total,
                                res,
                                per: plan.per,
                            });
                        }
                    }
                }
            }

            let Some(best) = best else {
                body.write(1, 6);
                body.write(0, 1);
                for i in 0..count {
                    body.write_signed(s[i], 16);
                }
                continue;
            };
            if best.bits >= count * 16 + 8 {
                body.write(1, 6);
                body.write(0, 1);
                for i in 0..count {
                    body.write_signed(s[i], 16);
                }
                continue;
            }

            let write_residual = |body: &mut BitWriter, best: &Candidate| {
                body.write(0, 2);
                body.write(best.p, 4);
                for (part, &k) in best.params.iter().enumerate() {
                    let from = if part == 0 {
                        0
                    } else {
                        best.per - best.order + (part - 1) * best.per
                    };
                    let to = if part == 0 {
                        best.per - best.order
                    } else {
                        best.per - best.order + part * best.per
                    };
                    body.write(k, 4);
                    for i in from..to.min(best.res.len()) {
                        if k == 15 {
                            if i == from {
                                body.write(16, 5);
                            }
                            body.write_signed(best.res[i], 16);
                            continue;
                        }
                        let v = best.res[i];
                        let u = ((v << 1) ^ (v >> 31)) as u32;
                        let q = u >> k;
                        for _ in 0..q {
                            body.write(0, 1);
                        }
                        body.write(1, 1);
                        if k > 0 {
                            body.write(u & ((1u32 << k) - 1), k);
                        }
                    }
                }
            };

            if best.kind_lpc {
                body.write(32 + best.order as u32 - 1, 6);
                body.write(0, 1);
                for i in 0..best.order {
                    body.write_signed(s[i], 16);
                }
                body.write(best.precision as u32 - 1, 4);
                body.write_signed(best.shift, 5);
                for j in 0..best.order {
                    body.write_signed(best.q[j], best.precision as u32);
                }
                write_residual(&mut body, &best);
            } else {
                body.write(8 + best.order as u32, 6);
                body.write(0, 1);
                for i in 0..best.order {
                    body.write_signed(s[i], 16);
                }
                write_residual(&mut body, &best);
            }
        }

        let frame_bytes = body.into_bytes();
        let mut whole = with_crc.clone();
        whole.extend_from_slice(&frame_bytes);
        let crc = crc16(&whole);
        parts.extend_from_slice(&whole);
        parts.extend_from_slice(&crc.to_be_bytes());

        frame_start += BLOCK;
        frame_number += 1;
    }

    parts
}
