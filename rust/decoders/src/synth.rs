// Keygen-music synthesis, ported from deps/decoders/synth.mjs. The score is data, the sound is
// generated on demand: oscillators (sine / square / saw / triangle / noise) with a per-note ADSR
// envelope, summed into one mono float stream and hard-clamped at the unit range. The float
// semantics mirror the JS side exactly - samples accumulate in f64, the noise is one xorshift32
// per note seeded from the pitch, and the envelope gates and releases at the same boundaries - so
// the non-sine waves render bit-identical and the sine wave differs only by libm's last digit.
use crate::json::Json;
use crate::md5;

const MIDDLE_A: f64 = 440.0;

pub fn pitch_hz(pitch: f64) -> f64 {
    MIDDLE_A * 2f64.powf((pitch - 69.0) / 12.0)
}

fn wave_sine(phase: f64) -> f64 {
    (2.0 * std::f64::consts::PI * phase).sin()
}
fn wave_square(phase: f64) -> f64 {
    if phase < 0.5 {
        1.0
    } else {
        -1.0
    }
}
fn wave_saw(phase: f64) -> f64 {
    1.0 - 2.0 * phase
}
fn wave_triangle(phase: f64) -> f64 {
    4.0 * (phase - 0.5).abs() - 1.0
}

fn noise_seed(pitch: f64, index: usize) -> u32 {
    // JS: (((pitch * 2654435761) ^ (index * 40503)) >>> 0) || 1 - f64 products that are exact
    // integers, ToInt32 on both sides, zero replaced by one.
    let a = (pitch * 2654435761.0) as i64;
    let b = (index as f64 * 40503.0) as i64;
    let x = ((a as u32) ^ (b as u32)) as u32;
    if x == 0 {
        1
    } else {
        x
    }
}

fn next_noise(state: &mut u32) -> f64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x as f64 / 0xffffffffu32 as f64
}

fn envelope_at(env: &(f64, f64, f64, f64), t: f64, dur: f64) -> f64 {
    let (a, d, s, r) = *env;
    let gate = t.min(dur);
    let mut level = if gate <= a {
        if a > 0.0 {
            gate / a
        } else {
            1.0
        }
    } else if gate <= a + d {
        if d > 0.0 {
            1.0 - ((gate - a) / d) * (1.0 - s)
        } else {
            s
        }
    } else {
        s
    };
    if t > dur {
        let mut rel = (t - dur) / r;
        if rel > 1.0 - 1e-9 {
            rel = 1.0;
        }
        level *= 1.0 - rel;
    }
    level
}

fn num_of(j: &Json, key: &str) -> Option<f64> {
    match j.get(key) {
        Some(Json::Num(n)) => Some(*n),
        _ => None,
    }
}

fn str_of(j: &Json, key: &str) -> String {
    match j.get(key) {
        Some(Json::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

#[derive(Debug)]
pub struct SynthOut {
    pub samples: Vec<f64>,
    pub frames: usize,
    pub sample_rate: u32,
    pub notes: usize,
    pub last_end_sec: f64,
    pub peak_min: f64,
    pub peak_max: f64,
}

impl SynthOut {
    pub fn to_json(&self) -> Json {
        let mut bytes = Vec::with_capacity(self.samples.len() * 8);
        for s in &self.samples {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        let digest = md5::Md5::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
        Json::obj(vec![
            ("samplesMd5", Json::str(&digest)),
            ("frames", Json::int(self.frames as i64)),
            ("sampleRate", Json::int(self.sample_rate as i64)),
            ("notes", Json::int(self.notes as i64)),
            ("lastEndSec", Json::num(self.last_end_sec)),
            ("peaks", Json::obj(vec![
                ("min", Json::num(self.peak_min)),
                ("max", Json::num(self.peak_max)),
            ])),
        ])
    }
}

pub fn synthesize(score: &Json) -> Result<SynthOut, String> {
    let sample_rate = num_of(score, "sampleRate").unwrap_or(0.0);
    let sample_rate = if sample_rate > 0.0 { sample_rate as u32 } else { 44100 };
    let default_wave = str_of(score, "wave");
    let default_wave = if default_wave.is_empty() { "square".to_string() } else { default_wave };
    let adsr = match score.get("adsr") {
        Some(Json::Obj(fields)) => {
            let mut env = (0.005f64, 0.08f64, 0.7f64, 0.05f64);
            for (k, v) in fields {
                if let Json::Num(n) = v {
                    match k.as_str() {
                        "a" => env.0 = *n,
                        "d" => env.1 = *n,
                        "s" => env.2 = *n,
                        "r" => env.3 = *n,
                        _ => {}
                    }
                }
            }
            env
        }
        _ => (0.005, 0.08, 0.7, 0.05),
    };
    let notes: Vec<&Json> = match score.get("notes") {
        Some(Json::Arr(items)) => items.iter().collect(),
        _ => Vec::new(),
    };
    if notes.is_empty() {
        return Err("a score needs at least one note".into());
    }

    struct Prepared {
        t: f64,
        dur: f64,
        vel: f64,
        step: f64,
        wave: u8, // 0 sine, 1 square, 2 saw, 3 triangle, 4 noise
        noise_state: Option<u32>,
        phase: f64,
    }
    let mut end = 0.0f64;
    let mut prepared: Vec<Prepared> = Vec::with_capacity(notes.len());
    for (ni, n) in notes.iter().enumerate() {
        let t = num_of(n, "t").unwrap_or(0.0).max(0.0);
        let dur = num_of(n, "dur").unwrap_or(0.0).max(0.0);
        let pitch = match num_of(n, "pitch") {
            Some(p) if p.is_finite() => p,
            _ => return Err("every note needs a pitch".into()),
        };
        let vel = match num_of(n, "vel") {
            None => 1.0,
            Some(v) => v.max(0.0).min(1.0),
        };
        let wave_name = str_of(n, "wave");
        let wave_name = if wave_name.is_empty() { default_wave.clone() } else { wave_name };
        let wave = match wave_name.as_str() {
            "sine" => 0u8,
            "square" => 1u8,
            "saw" => 2u8,
            "triangle" => 3u8,
            "noise" => 4u8,
            _ => {
                let shown = if wave_name.is_empty() { default_wave.clone() } else { wave_name.clone() };
                return Err(format!("unknown wave \"{shown}\" (sine, square, saw, triangle, noise)"));
            }
        };
        let note_end = t + dur + adsr.3;
        if note_end > end {
            end = note_end;
        }
        prepared.push(Prepared {
            t,
            dur,
            vel,
            step: pitch_hz(pitch) / sample_rate as f64,
            wave,
            noise_state: if wave == 4 { Some(noise_seed(pitch, ni)) } else { None },
            phase: 0.0,
        });
    }

    let frames = (end * sample_rate as f64).ceil() as usize;
    let mut samples = vec![0.0f64; frames];
    for n in prepared.iter_mut() {
        let start = (n.t * sample_rate as f64).floor() as usize;
        for i in start..frames {
            let t = i as f64 / sample_rate as f64;
            if t > n.t + n.dur + adsr.3 {
                break;
            }
            let level = envelope_at(&adsr, t - n.t, n.dur) * n.vel;
            if level == 0.0 && t > n.t + n.dur {
                continue;
            }
            let wv = match n.wave {
                0 => wave_sine(n.phase),
                1 => wave_square(n.phase),
                2 => wave_saw(n.phase),
                3 => wave_triangle(n.phase),
                _ => next_noise(n.noise_state.as_mut().unwrap()) * 2.0 - 1.0,
            };
            samples[i] += wv * level;
            n.phase += n.step;
            if n.phase >= 1.0 {
                n.phase -= n.phase.floor();
            }
        }
    }

    let mut peak_min = 0.0f64;
    let mut peak_max = 0.0f64;
    for s in samples.iter_mut() {
        if *s > 1.0 {
            *s = 1.0;
        } else if *s < -1.0 {
            *s = -1.0;
        }
        if *s < peak_min {
            peak_min = *s;
        }
        if *s > peak_max {
            peak_max = *s;
        }
    }

    Ok(SynthOut {
        samples,
        frames,
        sample_rate,
        notes: prepared.len(),
        last_end_sec: end,
        peak_min,
        peak_max,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Json {
        crate::json::parse(s).unwrap()
    }

    #[test]
    fn pitch_hz_matches_the_midi_anchor() {
        assert!((pitch_hz(69.0) - 440.0).abs() < 1e-12);
        assert!((pitch_hz(81.0) - 880.0).abs() < 1e-12);
    }

    #[test]
    fn envelope_segments_are_linear() {
        let env = (0.1, 0.2, 0.7, 0.1);
        assert!((envelope_at(&env, 0.0, 10.0) - 0.0).abs() < 1e-12);
        assert!((envelope_at(&env, 0.05, 10.0) - 0.5).abs() < 1e-12);
        assert!((envelope_at(&env, 0.1, 10.0) - 1.0).abs() < 1e-12);
        assert!((envelope_at(&env, 0.5, 10.0) - 0.7).abs() < 1e-12);
    }

    #[test]
    fn an_empty_score_refuses() {
        let e = synthesize(&parse(r#"{"notes":[]}"#)).unwrap_err();
        assert_eq!(e, "a score needs at least one note");
    }

    #[test]
    fn an_unknown_wave_refuses() {
        let e = synthesize(&parse(r#"{"notes":[{"t":0,"dur":0.1,"pitch":60,"wave":"warp"}]}"#)).unwrap_err();
        assert_eq!(e, "unknown wave \"warp\" (sine, square, saw, triangle, noise)");
    }

    #[test]
    fn a_square_note_renders_within_the_unit_range() {
        let out = synthesize(&parse(r#"{"sampleRate":8000,"notes":[{"t":0,"dur":0.05,"pitch":69,"wave":"square"}],"adsr":{"a":0.001,"d":0.01,"s":0.7,"r":0.02}}"#)).unwrap();
        assert!(out.frames > 0);
        assert!(out.peak_max <= 1.0);
        assert!(out.peak_min >= -1.0);
        assert_eq!(out.notes, 1);
    }

    #[test]
    fn noise_is_seeded_per_note() {
        let a = noise_seed(60.0, 0);
        let b = noise_seed(60.0, 0);
        let c = noise_seed(61.0, 0);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
