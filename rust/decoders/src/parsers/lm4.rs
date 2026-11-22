// LM4 Mark II drumkit lists, order-identical with the JS original (deps/decoders/lm4.mjs):
// a four-line header ("vst samples," / kit name / sample folder / vendor), one line per velocity
// layer (pad, MIDI note, sample name, file, velocity range, mute group, play mode), closed by -1.
use crate::json::Json;
use std::fs;

pub struct Pad {
    pub pad: u32,
    pub midi: u32,
    pub name: String,
    pub sample: String,
    pub vel_lo: u32,
    pub vel_hi: u32,
    pub group: u32,
    pub mode: u32,
}

pub struct Kit {
    pub name: String,
    pub folder: String,
    pub vendor: String,
    pub pads: Vec<Pad>,
}

impl Kit {
    pub fn to_json(&self) -> Json {
        let mut midi_map: Vec<(String, Json)> = Vec::new();
        for pad in &self.pads {
            let key = pad.midi.to_string();
            if !midi_map.iter().any(|(k, _)| k == &key) {
                midi_map.push((key, Json::str(pad.name.clone())));
            }
        }
        let mut midi_notes: Vec<u32> = self.pads.iter().map(|p| p.midi).collect();
        midi_notes.sort_unstable();
        midi_notes.dedup();
        let unique: Vec<String> = {
            let mut v: Vec<String> = self.pads.iter().map(|p| p.sample.clone()).collect();
            v.sort();
            v.dedup();
            v
        };
        Json::obj(vec![
            ("container", Json::str("lm4-drumkit")),
            ("format", Json::str("lm4-drumkit")),
            ("name", Json::str(self.name.clone())),
            ("folder", Json::str(self.folder.clone())),
            ("vendor", Json::str(self.vendor.clone())),
            (
                "pads",
                Json::arr(
                    self.pads
                        .iter()
                        .map(|p| {
                            Json::obj(vec![
                                ("pad", Json::int(p.pad as i64)),
                                ("midi", Json::int(p.midi as i64)),
                                ("name", Json::str(p.name.clone())),
                                ("sample", Json::str(p.sample.clone())),
                                ("velLo", Json::int(p.vel_lo as i64)),
                                ("velHi", Json::int(p.vel_hi as i64)),
                                ("group", Json::int(p.group as i64)),
                                ("mode", Json::int(p.mode as i64)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("padCount", Json::int(self.pads.len() as i64)),
            ("samples", Json::int(unique.len() as i64)),
            ("midiMap", Json::Obj(midi_map)),
            (
                "midiNotes",
                Json::arr(midi_notes.iter().map(|n| Json::int(*n as i64)).collect()),
            ),
        ])
    }
}

pub fn parse_lm4_kit(text: &str) -> Result<Kit, String> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.first().map(|l| l.trim()) != Some("vst samples,") {
        return Err("not an LM4 drumkit list (missing the 'vst samples,' header)".into());
    }
    let name = lines.get(1).map(|l| l.trim().to_string()).unwrap_or_default();
    let folder = lines.get(2).map(|l| l.trim().to_string()).unwrap_or_default();
    let vendor = lines.get(3).map(|l| l.trim().to_string()).unwrap_or_default();
    let mut pads = Vec::new();
    for line in lines.iter().skip(4) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "-1" {
            break;
        }
        let f: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if f.len() < 6 || !f[0].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let num = |i: usize| -> u32 { f.get(i).and_then(|s| s.parse().ok()).unwrap_or(0) };
        pads.push(Pad {
            pad: num(0),
            midi: num(3),
            name: f[4].to_string(),
            sample: f[5].to_string(),
            vel_lo: num(6),
            vel_hi: num(7),
            group: if f.len() > 12 { num(12) } else { 0 },
            mode: if f.len() > 13 { num(13) } else { 0 },
        });
    }
    if name.is_empty() {
        return Err("not an LM4 drumkit list (no kit name)".into());
    }
    Ok(Kit { name, folder, vendor, pads })
}

pub fn read_lm4_kit(file: &str) -> Result<Kit, String> {
    let text = fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    parse_lm4_kit(&text)
}
