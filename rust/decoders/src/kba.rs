// The KBA audio container (deps/decoders/kba.mjs), ported tier by tier.
//
// Tiers 0 (raw) and 2 (IMA ADPCM) are byte-exact with the JS encoder, so the cross-check can
// compare files directly. Tier 1 (lossless) writes a stored-block zlib stream: legal deflate,
// decodable by Node's inflateSync, but deliberately not byte-exact with a specific zlib library's
// matching strategy. The lossless judge in tools/selfcheck.mjs states that contract: the JS side
// decodes what this side wrote and gets the original samples back (round-trip, not byte equality),
// while the decode direction stays byte-exact (this reader restores every sample a JS-written
// stream encodes).
use crate::adpcm;
use crate::json::Json;
use crate::md5;
use crate::zlib;

const TIER_NAMES: [&str; 3] = ["raw", "lossless", "adpcm"];

fn hex16(d: [u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn pcm_le_bytes(pcm: &[i16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(pcm.len() * 2);
    for x in pcm {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

/// Encode int16 PCM into a KBA container. `frames` in the header is the PCM length, exactly like
/// the JS side: one frame is one sample in the interleaved stream.
pub fn encode_kba(pcm: &[i16], tier: u8, sample_rate: u32, channels: u16) -> Result<Vec<u8>, String> {
    if tier > 2 {
        return Err(format!("unknown tier {tier}"));
    }
    let mut out = Vec::with_capacity(16 + pcm.len() * 2);
    out.extend_from_slice(b"KBA1");
    out.push(1); // version
    out.push(tier);
    out.extend_from_slice(&sample_rate.to_le_bytes());
    out.extend_from_slice(&channels.to_le_bytes());
    out.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
    match tier {
        0 => out.extend_from_slice(&pcm_le_bytes(pcm)),
        1 => {
            let mut delta = Vec::with_capacity(pcm.len() * 2);
            let mut prev: i16 = 0;
            for &x in pcm {
                delta.extend_from_slice(&x.wrapping_sub(prev).to_le_bytes());
                prev = x;
            }
            out.extend_from_slice(&zlib::deflate_zlib_stored(&delta));
        }
        _ => out.extend_from_slice(&adpcm::adpcm_encode(pcm)),
    }
    Ok(out)
}

#[derive(Debug)]
pub struct KbaReceipt {
    pub tier: String,
    pub sample_rate: u32,
    pub channels: u16,
    pub frames: u32,
    pub pcm_frames: usize,
    pub pcm_md5: String,
}

impl KbaReceipt {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("tier", Json::str(&self.tier)),
            ("sampleRate", Json::int(self.sample_rate as i64)),
            ("channels", Json::int(self.channels as i64)),
            ("frames", Json::int(self.frames as i64)),
            ("pcmFrames", Json::int(self.pcm_frames as i64)),
            ("pcmMd5", Json::str(&self.pcm_md5)),
        ])
    }
}

fn adpcm_decode(body: &[u8], frames: usize) -> Result<Vec<i16>, String> {
    let mut pcm = vec![0i16; frames];
    let mut at = 0usize;
    let mut written = 0usize;
    while written < frames {
        let count = (frames - written).min(adpcm::ADPCM_BLOCK);
        if at + 2 > body.len() {
            return Err("the adpcm body ends inside a block header".into());
        }
        let mut pred = i32::from(i16::from_le_bytes([body[at], body[at + 1]]));
        at += 2;
        if at >= body.len() {
            return Err("the adpcm body ends inside a block header".into());
        }
        let mut index = body[at] as i32;
        at += 1;
        let mut hi: Option<u8> = None;
        for _ in 0..count {
            let nibble;
            match hi {
                None => {
                    let b = *body.get(at).ok_or("the adpcm body ends inside a nibble pair")?;
                    at += 1;
                    hi = Some(b);
                    nibble = b & 0x0f;
                }
                Some(b) => {
                    nibble = b >> 4;
                    hi = None;
                }
            }
            let code = (nibble & 7) as usize;
            let step = adpcm::STEP_TABLE[index as usize];
            let mut delta = step >> 3;
            if nibble & 4 != 0 {
                delta += step;
            }
            if nibble & 2 != 0 {
                delta += step >> 1;
            }
            if nibble & 1 != 0 {
                delta += step >> 2;
            }
            pred += if nibble & 8 != 0 { -delta } else { delta };
            pred = pred.clamp(-32768, 32767);
            index = (index + adpcm::INDEX_TABLE[code]).clamp(0, 88);
            pcm[written] = pred as i16;
            written += 1;
        }
    }
    Ok(pcm)
}

/// Decode a KBA container back to int16 PCM. The receipt carries the PCM digest instead of the
/// sample array, so the cross-check compares digests of the two decoded streams (the same bytes
/// both sides recover) rather than shipping megabytes of samples through JSON.
pub fn decode_kba(buf: &[u8]) -> Result<KbaReceipt, String> {
    if buf.len() < 16 || &buf[..4] != b"KBA1" {
        return Err("not a kohane audio container (no KBA1 marker)".into());
    }
    if buf[4] != 1 {
        return Err(format!("not a kohane audio container (unknown version {})", buf[4]));
    }
    let tier = buf[5];
    if tier > 2 {
        return Err(format!("not a kohane audio container (unknown tier {tier})"));
    }
    let sample_rate = u32::from_le_bytes(buf[6..10].try_into().unwrap());
    let channels = u16::from_le_bytes(buf[10..12].try_into().unwrap());
    let frames = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let body = &buf[16..];
    let pcm: Vec<i16> = match tier {
        0 => {
            let n = body.len() / 2;
            let mut v = Vec::with_capacity(n);
            for c in body.chunks_exact(2) {
                v.push(i16::from_le_bytes([c[0], c[1]]));
            }
            v
        }
        1 => {
            let delta = zlib::inflate_zlib(body)?;
            let mut v = Vec::with_capacity(delta.len() / 2);
            let mut acc: i32 = 0;
            for c in delta.chunks_exact(2) {
                acc += i16::from_le_bytes([c[0], c[1]]) as i32;
                v.push(acc as i16);
            }
            v
        }
        _ => adpcm_decode(body, frames as usize)?,
    };
    Ok(KbaReceipt {
        tier: TIER_NAMES[tier as usize].to_string(),
        sample_rate,
        channels,
        frames,
        pcm_frames: pcm.len(),
        pcm_md5: hex16(md5::Md5::digest(&pcm_le_bytes(&pcm))),
    })
}

#[derive(Debug)]
pub struct KbaStats {
    pub tier: String,
    pub sample_rate: u32,
    pub channels: u16,
    pub frames: u32,
    pub bytes: usize,
    pub pcm_bytes: u32,
}

impl KbaStats {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("tier", Json::str(&self.tier)),
            ("sampleRate", Json::int(self.sample_rate as i64)),
            ("channels", Json::int(self.channels as i64)),
            ("frames", Json::int(self.frames as i64)),
            ("bytes", Json::int(self.bytes as i64)),
            ("pcmBytes", Json::int(self.pcm_bytes as i64)),
        ])
    }
}

pub fn kba_stats(buf: &[u8]) -> Result<KbaStats, String> {
    if buf.len() < 16 || &buf[..4] != b"KBA1" {
        return Err("not a kohane audio container (no KBA1 marker)".into());
    }
    let tier = buf[5];
    let tier_name = TIER_NAMES
        .get(tier as usize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("tier{tier}"));
    let sample_rate = u32::from_le_bytes(buf[6..10].try_into().unwrap());
    let channels = u16::from_le_bytes(buf[10..12].try_into().unwrap());
    let frames = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    Ok(KbaStats {
        tier: tier_name,
        sample_rate,
        channels,
        frames,
        bytes: buf.len(),
        pcm_bytes: frames * 2 * u32::from(channels.max(1)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(frames: usize) -> Vec<i16> {
        (0..frames)
            .map(|i| ((i as f64 * 0.13).sin() * 12000.0) as i16)
            .collect()
    }

    #[test]
    fn raw_round_trip() {
        let pcm = tone(2048);
        let buf = encode_kba(&pcm, 0, 44100, 1).unwrap();
        let r = decode_kba(&buf).unwrap();
        assert_eq!(r.tier, "raw");
        assert_eq!(r.pcm_frames, pcm.len());
        assert_eq!(r.frames, 2048);
        let again = encode_kba(&pcm, 0, 44100, 1).unwrap();
        assert_eq!(buf, again);
    }

    #[test]
    fn adpcm_round_trip_decodes_back() {
        let pcm = tone(4096);
        let buf = encode_kba(&pcm, 2, 44100, 1).unwrap();
        let r = decode_kba(&buf).unwrap();
        assert_eq!(r.tier, "adpcm");
        assert_eq!(r.pcm_frames, pcm.len());
    }

    #[test]
    fn lossless_round_trip() {
        let pcm = tone(3000);
        let buf = encode_kba(&pcm, 1, 48000, 2).unwrap();
        let r = decode_kba(&buf).unwrap();
        assert_eq!(r.tier, "lossless");
        assert_eq!(r.pcm_frames, pcm.len());
        assert_eq!(r.pcm_md5, hex16(md5::Md5::digest(&pcm_le_bytes(&pcm))));
    }

    #[test]
    fn refuses_with_the_js_sentences() {
        let e = decode_kba(b"nope").unwrap_err();
        assert_eq!(e, "not a kohane audio container (no KBA1 marker)");
        let mut v = vec![0u8; 16];
        v[..4].copy_from_slice(b"KBA1");
        v[4] = 9;
        let e = decode_kba(&v).unwrap_err();
        assert_eq!(e, "not a kohane audio container (unknown version 9)");
        v[4] = 1;
        v[5] = 7;
        let e = decode_kba(&v).unwrap_err();
        assert_eq!(e, "not a kohane audio container (unknown tier 7)");
    }

    #[test]
    fn stats_match_the_header() {
        let pcm = tone(100);
        let buf = encode_kba(&pcm, 2, 22050, 2).unwrap();
        let s = kba_stats(&buf).unwrap();
        assert_eq!(s.tier, "adpcm");
        assert_eq!(s.sample_rate, 22050);
        assert_eq!(s.channels, 2);
        assert_eq!(s.frames, 100);
        assert_eq!(s.pcm_bytes, 400);
        assert_eq!(s.bytes, buf.len());
    }
}
