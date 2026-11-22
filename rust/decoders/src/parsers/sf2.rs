// SoundFont 2 reading, order-identical with the JS original (deps/decoders/sf2.mjs): the sfbk
// form, the sdta smpl region, and the pdta tables - phdr presets, inst instruments, shdr samples
// with name/rate/pitch/loop, and the bag/generator chains.
use crate::json::Json;
use std::fs;

fn fourcc(buf: &[u8], at: usize) -> String {
    String::from_utf8_lossy(&buf[at..(at + 4).min(buf.len())]).to_string()
}

fn cstr(buf: &[u8], at: usize, len: usize) -> String {
    let end = (at..(at + len).min(buf.len())).find(|&i| buf[i] == 0).unwrap_or((at + len).min(buf.len()));
    String::from_utf8_lossy(&buf[at..end]).to_string()
}

struct Bag {
    gen_index: u16,
    gen_count: u16,
}

struct Gen {
    oper: u16,
    amount: u16,
}

struct Sample {
    name: String,
    start: u32,
    end: u32,
    start_loop: u32,
    end_loop: u32,
    sample_rate: u32,
    original_pitch: u8,
    pitch_correction: i8,
    sample_type: u16,
}

pub struct Sf2 {
    pub size: usize,
    pub presets: Vec<Json>,
    pub instruments: Vec<Json>,
    pub samples: Vec<Sample>,
    pub pbags: Vec<Bag>,
    pub ibags: Vec<Bag>,
    pub pgens: Vec<Gen>,
    pub igens: Vec<Gen>,
    pub smpl_bytes: usize,
    pub smpl_at: Option<usize>,
}

impl Sf2 {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("container", Json::str("sf2")),
            ("size", Json::int(self.size as i64)),
            ("presets", Json::arr(self.presets.clone())),
            ("instruments", Json::arr(self.instruments.clone())),
            (
                "samples",
                Json::arr(
                    self.samples
                        .iter()
                        .map(|s| {
                            Json::obj(vec![
                                ("name", Json::str(s.name.clone())),
                                ("start", Json::int(s.start as i64)),
                                ("end", Json::int(s.end as i64)),
                                ("startLoop", Json::int(s.start_loop as i64)),
                                ("endLoop", Json::int(s.end_loop as i64)),
                                ("sampleRate", Json::int(s.sample_rate as i64)),
                                ("originalPitch", Json::int(s.original_pitch as i64)),
                                ("pitchCorrection", Json::int(s.pitch_correction as i64)),
                                ("sampleType", Json::int(s.sample_type as i64)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("smplBytes", Json::int(self.smpl_bytes as i64)),
            ("smplAt", self.smpl_at.map(|v| Json::int(v as i64)).unwrap_or(Json::Null)),
            (
                "summary",
                Json::obj(vec![
                    ("presets", Json::int(self.presets.len() as i64)),
                    ("instruments", Json::int(self.instruments.len() as i64)),
                    ("samples", Json::int(self.samples.len() as i64)),
                    (
                        "sampleRateHint",
                        if self.samples.is_empty() {
                            Json::Null
                        } else {
                            Json::int(self.samples[0].sample_rate as i64)
                        },
                    ),
                ]),
            ),
        ])
    }
}

fn walk_list<F: FnMut(&str, usize, usize)>(buf: &[u8], from: usize, to: usize, mut visit: F) {
    let mut at = from;
    while at + 8 <= to {
        let id = fourcc(buf, at);
        let size = u32::from_le_bytes([buf[at + 4], buf[at + 5], buf[at + 6], buf[at + 7]]) as usize;
        let body = at + 8;
        if body + size > to {
            break;
        }
        visit(&id, body, body + size);
        at = body + size + (size % 2);
    }
}

pub fn read_sf2(file: &str) -> Result<Sf2, String> {
    let buf = fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    if buf.len() < 12 || fourcc(&buf, 0) != "RIFF" || fourcc(&buf, 8) != "sfbk" {
        return Err("not a SoundFont (no RIFF/sfbk marker)".into());
    }
    let mut out = Sf2 {
        size: buf.len(),
        presets: Vec::new(),
        instruments: Vec::new(),
        samples: Vec::new(),
        pbags: Vec::new(),
        ibags: Vec::new(),
        pgens: Vec::new(),
        igens: Vec::new(),
        smpl_bytes: 0,
        smpl_at: None,
    };
    let limit = buf.len();
    let mut at = 12usize;
    while at + 8 <= limit {
        let id = fourcc(&buf, at);
        let size = u32::from_le_bytes([buf[at + 4], buf[at + 5], buf[at + 6], buf[at + 7]]) as usize;
        let body = at + 8;
        if body + size > limit {
            break;
        }
        let end = body + size;
        if id == "LIST" {
            let list_type = fourcc(&buf, body);
            if list_type == "sdta" || list_type == "pdta" {
                walk_list(&buf, body + 4, end, |cid, cbody, cend| {
                    match cid {
                        "smpl" => {
                            out.smpl_bytes += cend - cbody;
                            if out.smpl_at.is_none() {
                                out.smpl_at = Some(cbody);
                            }
                        }
                        "phdr" if cend - cbody >= 38 => {
                            let mut p = cbody;
                            while p + 38 <= cend {
                                let name = cstr(&buf, p, 20);
                                if name == "EOP" || name == "eop" {
                                    break;
                                }
                                out.presets.push(Json::obj(vec![
                                    ("name", Json::str(name)),
                                    ("preset", Json::int(u16::from_le_bytes([buf[p + 20], buf[p + 21]]) as i64)),
                                    ("bank", Json::int(u16::from_le_bytes([buf[p + 22], buf[p + 23]]) as i64)),
                                    ("bagIndex", Json::int(u16::from_le_bytes([buf[p + 24], buf[p + 25]]) as i64)),
                                ]));
                                p += 38;
                            }
                        }
                        "inst" if cend - cbody >= 22 => {
                            let mut p = cbody;
                            while p + 22 <= cend {
                                let name = cstr(&buf, p, 20);
                                if name == "EOI" || name == "eoi" {
                                    break;
                                }
                                out.instruments.push(Json::obj(vec![
                                    ("name", Json::str(name)),
                                    ("bagIndex", Json::int(u16::from_le_bytes([buf[p + 20], buf[p + 21]]) as i64)),
                                ]));
                                p += 22;
                            }
                        }
                        "shdr" if cend - cbody >= 46 => {
                            let mut p = cbody;
                            while p + 46 <= cend {
                                let name = cstr(&buf, p, 20);
                                if name == "EOS" || name == "eos" {
                                    break;
                                }
                                let u32at = |o: usize| {
                                    u32::from_le_bytes([buf[p + o], buf[p + o + 1], buf[p + o + 2], buf[p + o + 3]])
                                };
                                out.samples.push(Sample {
                                    name,
                                    start: u32at(20),
                                    end: u32at(24),
                                    start_loop: u32at(28),
                                    end_loop: u32at(32),
                                    sample_rate: u32at(36),
                                    original_pitch: buf[p + 40],
                                    pitch_correction: buf[p + 41] as i8,
                                    sample_type: u16::from_le_bytes([buf[p + 44], buf[p + 45]]),
                                });
                                p += 46;
                            }
                        }
                        "pbag" | "ibag" if cend - cbody >= 4 => {
                            let mut p = cbody;
                            while p + 4 <= cend {
                                let bag = Bag {
                                    gen_index: u16::from_le_bytes([buf[p], buf[p + 1]]),
                                    gen_count: u16::from_le_bytes([buf[p + 2], buf[p + 3]]),
                                };
                                if cid == "pbag" {
                                    out.pbags.push(bag);
                                } else {
                                    out.ibags.push(bag);
                                }
                                p += 4;
                            }
                        }
                        "pgen" | "igen" if cend - cbody >= 4 => {
                            let mut p = cbody;
                            while p + 4 <= cend {
                                let gen = Gen {
                                    oper: u16::from_le_bytes([buf[p], buf[p + 1]]),
                                    amount: u16::from_le_bytes([buf[p + 2], buf[p + 3]]),
                                };
                                if cid == "pgen" {
                                    out.pgens.push(gen);
                                } else {
                                    out.igens.push(gen);
                                }
                                p += 4;
                            }
                        }
                        _ => {}
                    }
                });
            }
        }
        at = end + (size % 2);
    }
    Ok(out)
}
