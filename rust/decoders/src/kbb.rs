// The KBB instrument bank (deps/decoders/kbb.mjs): a SoundFont converted into kohane's own
// containers. The kbb document this side writes must be byte-identical with the JS side's
// JSON.stringify output - key order, number formatting and all - because the cross-check compares
// documents directly. Every third-party byte disappears in the conversion; what survives is the
// enumerated zones, the deduplicated sample payloads (kba, base64 inside the document), and the
// report.
use crate::json::Json;
use crate::kba::{downsample2, encode_kba};
use crate::parsers::sf2::{read_sf2, Bag, Gen, Sf2};
use crate::sha256;
use std::collections::HashMap;
use std::fs;

const GEN_INSTRUMENT: u16 = 41;
const GEN_KEY_RANGE: u16 = 43;
const GEN_VEL_RANGE: u16 = 44;
const GEN_START_LOOP: u16 = 45;
const GEN_END_LOOP: u16 = 46;
const GEN_SAMPLE_ID: u16 = 53;
const GEN_SAMPLE_MODES: u16 = 54;

const REFUSE_NO_SAMPLES: &str = "the SoundFont declares no samples";
const REFUSE_NO_SMPL: &str = "the SoundFont carries no sample data (no smpl chunk)";

fn range_of(amount: u16) -> (u16, u16) {
    (amount & 0xff, (amount >> 8) & 0xff)
}

fn gens_of(gens: &[Gen], bag: usize, count: usize) -> HashMap<u16, u16> {
    let mut out = HashMap::new();
    for i in 0..count {
        let Some(g) = gens.get(bag + i) else { break };
        if g.oper != 0 {
            out.insert(g.oper, g.amount);
        }
    }
    out
}

// JS: (amount << 16 >> 16) - the 32-bit signed spread of the stored u16.
fn signed_amount(amount: u16) -> i32 {
    amount as i16 as i32
}

fn bag_count(bags: &[Bag], gen_table_len: usize, b: usize) -> usize {
    let gap = (if b + 1 < bags.len() { bags[b + 1].gen_index as usize } else { gen_table_len })
        .saturating_sub(bags[b].gen_index as usize);
    if bags[b].gen_count != 0 {
        bags[b].gen_count as usize
    } else {
        gap
    }
}

fn num_of(j: &Json, key: &str) -> f64 {
    match j.get(key) {
        Some(Json::Num(n)) => *n,
        _ => 0.0,
    }
}

fn str_of(j: &Json, key: &str) -> String {
    match j.get(key) {
        Some(Json::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

struct Zone {
    preset: usize,
    instrument: String,
    sample: usize,
    lo_key: u16,
    hi_key: u16,
    vel_lo: u16,
    vel_hi: u16,
    root_key: i64,
    loop_start: i64,
    loop_end: i64,
    loop_mode: u16,
}

fn collect_zones(font: &Sf2) -> Vec<Zone> {
    let mut zones = Vec::new();
    let pcount = font.presets.len();
    for pi in 0..pcount {
        let next = if pi + 1 < pcount {
            num_of(&font.presets[pi + 1], "bagIndex") as usize
        } else {
            font.pbags.len()
        };
        let mut b = num_of(&font.presets[pi], "bagIndex") as usize;
        while b < next && b < font.pbags.len() {
            let gen_count = bag_count(&font.pbags, font.pgens.len(), b);
            if gen_count == 0 {
                b += 1;
                continue;
            }
            let pg = gens_of(&font.pgens, font.pbags[b].gen_index as usize, gen_count);
            let key_range = match pg.get(&GEN_KEY_RANGE) {
                Some(&v) => range_of(v),
                None => (0, 127),
            };
            let vel_range = match pg.get(&GEN_VEL_RANGE) {
                Some(&v) => range_of(v),
                None => (0, 127),
            };
            let Some(&inst_idx) = pg.get(&GEN_INSTRUMENT) else {
                b += 1;
                continue;
            };
            let inst_idx = inst_idx as usize;
            let Some(inst) = font.instruments.get(inst_idx) else {
                b += 1;
                continue;
            };
            let inext = if inst_idx + 1 < font.instruments.len() {
                num_of(&font.instruments[inst_idx + 1], "bagIndex") as usize
            } else {
                font.ibags.len()
            };
            let mut ib = num_of(inst, "bagIndex") as usize;
            while ib < inext && ib < font.ibags.len() {
                let igen_count = bag_count(&font.ibags, font.igens.len(), ib);
                if igen_count == 0 {
                    ib += 1;
                    continue;
                }
                let ig = gens_of(&font.igens, font.ibags[ib].gen_index as usize, igen_count);
                let sample_idx = ig.get(&GEN_SAMPLE_ID).copied().unwrap_or(0) as usize;
                let Some(s) = font.samples.get(sample_idx) else {
                    ib += 1;
                    continue;
                };
                let k = match ig.get(&GEN_KEY_RANGE) {
                    Some(&v) => range_of(v),
                    None => key_range,
                };
                let v = match ig.get(&GEN_VEL_RANGE) {
                    Some(&v) => range_of(v),
                    None => vel_range,
                };
                let loop_mode = ig.get(&GEN_SAMPLE_MODES).copied().unwrap_or(0);
                let start_loop = s.start_loop as i64
                    + match ig.get(&GEN_START_LOOP) {
                        Some(&amt) => signed_amount(amt) as i64 * 2,
                        None => 0,
                    };
                let end_loop = s.end_loop as i64
                    + match ig.get(&GEN_END_LOOP) {
                        Some(&amt) => signed_amount(amt) as i64 * 2,
                        None => 0,
                    };
                zones.push(Zone {
                    preset: pi,
                    instrument: str_of(inst, "name"),
                    sample: sample_idx,
                    lo_key: k.0,
                    hi_key: k.1,
                    vel_lo: v.0,
                    vel_hi: v.1,
                    root_key: s.original_pitch as i64 + s.pitch_correction as i64,
                    loop_start: (((start_loop - s.start as i64) as f64) / 2.0).floor().max(0.0) as i64,
                    loop_end: (((end_loop - s.start as i64) as f64) / 2.0)
                        .floor()
                        .min(((s.end as i64 - s.start as i64) as f64 / 2.0).floor()) as i64,
                    loop_mode,
                });
                ib += 1;
            }
            b += 1;
        }
    }
    zones
}

fn base64(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[(n >> 18) as usize & 63] as char);
        out.push(ALPHA[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHA[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHA[n as usize & 63] as char } else { '=' });
    }
    out
}

pub struct KbbOut {
    pub kbb: Json,
    pub report: Json,
}

impl KbbOut {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![("kbb", self.kbb.clone()), ("report", self.report.clone())])
    }
}

pub fn convert_sf2_to_kbb(file: &str, name: Option<String>, target_rate: u32, tier: &str) -> Result<KbbOut, String> {
    let font = read_sf2(file)?;
    if font.samples.is_empty() {
        return Err(REFUSE_NO_SAMPLES.into());
    }
    let Some(smpl_at) = font.smpl_at else {
        return Err(REFUSE_NO_SMPL.into());
    };
    let target_rate = if target_rate > 0 { target_rate } else { 22050 };
    let tier_num = match tier {
        "raw" => 0,
        "lossless" => 1,
        _ => 2,
    };
    let buf = fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;

    let zones = collect_zones(&font);

    let mut unique: HashMap<String, usize> = HashMap::new();
    let mut samples: Vec<Json> = Vec::new();
    for (i, s) in font.samples.iter().enumerate() {
        let byte_len = ((s.end as i64 - s.start as i64).max(0) as usize).min(buf.len().saturating_sub(smpl_at));
        let raw = &buf[smpl_at + s.start as usize..smpl_at + s.start as usize + byte_len];
        let digest = sha256::digest_hex(raw);
        let rec_idx = match unique.get(&digest) {
            Some(&idx) => idx,
            None => {
                let frames = raw.len() / 2;
                let mut pcm = Vec::with_capacity(frames);
                for c in raw.chunks_exact(2) {
                    pcm.push(i16::from_le_bytes([c[0], c[1]]));
                }
                let mut rate = s.sample_rate;
                if rate >= target_rate * 2 {
                    pcm = downsample2(&pcm);
                    rate = (rate as f64 / 2.0).round() as u32;
                }
                let kba = encode_kba(&pcm, tier_num, rate, 1)?;
                let rec = Json::obj(vec![
                    ("name", Json::str(&s.name)),
                    ("rate", Json::int(rate as i64)),
                    ("frames", Json::int(pcm.len() as i64)),
                    ("sha256", Json::str(&digest)),
                    ("kba", Json::str(&base64(&kba))),
                    ("refs", Json::arr(Vec::new())),
                ]);
                let idx = samples.len();
                samples.push(rec);
                unique.insert(digest, idx);
                idx
            }
        };
        match &mut samples[rec_idx] {
            Json::Obj(fields) => {
                for (k, v) in fields.iter_mut() {
                    if k == "refs" {
                        if let Json::Arr(items) = v {
                            items.push(Json::int(i as i64));
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    let presets: Vec<Json> = font
        .presets
        .iter()
        .enumerate()
        .map(|(pi, p)| {
            let zone_items: Vec<Json> = zones
                .iter()
                .filter(|z| z.preset == pi)
                .map(|z| {
                    Json::obj(vec![
                        ("instrument", Json::str(&z.instrument)),
                        ("loKey", Json::int(z.lo_key as i64)),
                        ("hiKey", Json::int(z.hi_key as i64)),
                        ("velLo", Json::int(z.vel_lo as i64)),
                        ("velHi", Json::int(z.vel_hi as i64)),
                        ("sample", Json::int(z.sample as i64)),
                        ("rootKey", Json::int(z.root_key)),
                        ("loopStart", Json::int(z.loop_start)),
                        ("loopEnd", Json::int(z.loop_end)),
                        ("loopMode", Json::int(z.loop_mode as i64)),
                    ])
                })
                .collect();
            Json::obj(vec![
                ("name", Json::str(&str_of(p, "name"))),
                ("bank", Json::int(num_of(p, "bank") as i64)),
                ("preset", Json::int(num_of(p, "preset") as i64)),
                ("zones", Json::arr(zone_items)),
            ])
        })
        .collect();

    let bank_name = name
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| match font.presets.first() {
            Some(p) => str_of(p, "name"),
            None => "converted bank".to_string(),
        });

    let kbb = Json::obj(vec![
        ("format", Json::str("kohane-bank")),
        ("version", Json::int(1)),
        ("name", Json::str(&bank_name)),
        ("sampleRate", Json::int(target_rate as i64)),
        ("tier", Json::str(tier)),
        ("presets", Json::arr(presets)),
        ("samples", Json::arr(samples)),
    ]);
    let kbb_bytes = kbb.render().len();
    let report = Json::obj(vec![
        ("sourceBytes", Json::int(font.size as i64)),
        ("kbbBytes", Json::int(kbb_bytes as i64)),
        ("ratio", Json::num((kbb_bytes as f64 / font.size.max(1) as f64 * 1000.0).round() / 1000.0)),
        ("presets", Json::int(font.presets.len() as i64)),
        ("zones", Json::int(zones.len() as i64)),
        ("samples", Json::int(font.samples.len() as i64)),
        ("uniqueSamples", Json::int(unique.len() as i64)),
        ("deduped", Json::int(font.samples.len() as i64 - unique.len() as i64)),
    ]);
    Ok(KbbOut { kbb, report })
}

/// Validate and open a .kbb document; the kba payloads stay base64 (decoding is the audio tier's job).
pub fn read_kbb(buf: &[u8]) -> Result<Json, String> {
    let text = match std::str::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => return Err("not a kohane bank (the bytes are not the container's JSON envelope)".into()),
    };
    let doc = match crate::json::parse(text) {
        Ok(v) => v,
        Err(_) => return Err("not a kohane bank (the bytes are not the container's JSON envelope)".into()),
    };
    match doc.get("format") {
        Some(Json::Str(f)) if f == "kohane-bank" => {}
        _ => return Err("not a kohane bank (missing the kohane-bank marker)".into()),
    }
    match doc.get("version") {
        Some(Json::Num(v)) if *v == 1.0 => {}
        _ => {
            return Err(format!(
                "not a kohane bank (unknown version {})",
                doc.get("version").map(|v| v.render()).unwrap_or_else(|| "undefined".into())
            ))
        }
    }
    if !matches!(doc.get("presets"), Some(Json::Arr(_))) {
        return Err("not a kohane bank (presets is not a list)".into());
    }
    let samples = match doc.get("samples") {
        Some(Json::Arr(items)) if !items.is_empty() => items.clone(),
        _ => return Err("not a kohane bank (no samples)".into()),
    };
    for (i, s) in samples.iter().enumerate() {
        match s.get("kba") {
            Some(Json::Str(k)) if !k.is_empty() => {}
            _ => return Err(format!("not a kohane bank (sample {i} carries no kba payload)")),
        }
    }
    Ok(doc)
}

/// The design's acceptance question: can the bank alone enumerate instruments, key ranges and loops?
pub fn kbb_summary(doc: &Json) -> Json {
    let presets = match doc.get("presets") {
        Some(Json::Arr(items)) => items.clone(),
        _ => Vec::new(),
    };
    let mut zones = 0usize;
    let mut key_ranges = true;
    let mut loops = true;
    for p in &presets {
        let Some(Json::Arr(pz)) = p.get("zones") else {
            key_ranges = false;
            loops = false;
            continue;
        };
        zones += pz.len();
        for z in pz {
            let is_int = |k: &str| matches!(z.get(k), Some(Json::Num(n)) if n.fract() == 0.0);
            if !is_int("loKey") || !is_int("hiKey") {
                key_ranges = false;
            }
            if !is_int("loopStart") || !is_int("loopEnd") {
                loops = false;
            }
        }
    }
    let sample_count = match doc.get("samples") {
        Some(Json::Arr(items)) => items.len(),
        _ => 0,
    };
    Json::obj(vec![
        ("presets", Json::int(presets.len() as i64)),
        ("zones", Json::int(zones as i64)),
        ("samples", Json::int(sample_count as i64)),
        ("tier", Json::str(match doc.get("tier") {
            Some(Json::Str(s)) => s.clone(),
            _ => String::new(),
        })),
        ("enumerable", Json::obj(vec![
            ("keyRanges", Json::Bool(key_ranges && zones > 0)),
            ("loops", Json::Bool(loops && zones > 0)),
            ("samples", Json::Bool(sample_count > 0)),
        ])),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_alphabet() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn read_rejects_with_the_js_sentences() {
        let e = read_kbb(b"nope").unwrap_err();
        assert_eq!(e, "not a kohane bank (the bytes are not the container's JSON envelope)");
        let e = read_kbb(br#"{"format":"nope"}"#).unwrap_err();
        assert_eq!(e, "not a kohane bank (missing the kohane-bank marker)");
        let e = read_kbb(br#"{"format":"kohane-bank","version":2}"#).unwrap_err();
        assert_eq!(e, "not a kohane bank (unknown version 2)");
        let e = read_kbb(br#"{"format":"kohane-bank","version":1,"presets":{}}"#).unwrap_err();
        assert_eq!(e, "not a kohane bank (presets is not a list)");
        let e = read_kbb(br#"{"format":"kohane-bank","version":1,"presets":[]}"#).unwrap_err();
        assert_eq!(e, "not a kohane bank (no samples)");
        let e = read_kbb(br#"{"format":"kohane-bank","version":1,"presets":[],"samples":[{"name":"x","kba":""}]}"#).unwrap_err();
        assert_eq!(e, "not a kohane bank (sample 0 carries no kba payload)");
    }

    #[test]
    fn summary_answers_the_acceptance_question() {
        let doc = crate::json::parse(
            r#"{"format":"kohane-bank","version":1,"tier":"adpcm","presets":[{"zones":[{"loKey":0,"hiKey":127,"loopStart":0,"loopEnd":5}]}],"samples":[{"kba":"AAAA"}]}"#,
        )
        .unwrap();
        let s = kbb_summary(&doc);
        assert_eq!(s.get("presets").unwrap().render(), "1");
        assert_eq!(s.get("zones").unwrap().render(), "1");
        assert_eq!(s.get("enumerable").unwrap().render(), "{\"keyRanges\":true,\"loops\":true,\"samples\":true}");
    }
}
