// Kohane's mixer (deps/decoders/mix.mjs): gain, pan and bus routing over rendered stems. The
// float semantics mirror the JS side exactly - Float32Array elements are read as f32, widened to
// f64 for the arithmetic, and written back as f32 with round-to-nearest - and the accumulation
// order is the JS loop order, so the rendered samples are bit-identical, not just close.
use crate::json::Json;
use crate::md5;

pub fn pan_coeffs(pan: f64) -> (f64, f64) {
    let p = if pan.is_finite() { pan } else { 0.0 };
    let p = p.clamp(-1.0, 1.0);
    (
        ((p + 1.0) * std::f64::consts::PI / 4.0).cos(),
        ((p + 1.0) * std::f64::consts::PI / 4.0).sin(),
    )
}

fn str_of(j: &Json, key: &str) -> String {
    match j.get(key) {
        Some(Json::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

fn num_of(j: &Json, key: &str) -> Option<f64> {
    match j.get(key) {
        Some(Json::Num(n)) => Some(*n),
        _ => None,
    }
}

/// Throw unless every declared effect is one this build executes. Empty today, exactly like the
/// JS side: gain and pan are track fields, and every effect entry in a mix document is refused.
pub fn assert_renderable(mix: &Json) -> Result<(), String> {
    let walk = |label: &str, holder: Option<&Json>| -> Result<(), String> {
        let effects: Vec<&Json> = match holder.and_then(|h| h.get("effects")) {
            Some(Json::Arr(items)) => items.iter().collect(),
            _ => Vec::new(),
        };
        for fx in effects {
            let kind = match fx.get("kind") {
                Some(Json::Str(s)) if !s.is_empty() => s.clone(),
                _ => "?".to_string(),
            };
            let note = match fx.get("note") {
                Some(Json::Str(s)) if !s.is_empty() => format!(" ({s})"),
                _ => String::new(),
            };
            return Err(format!(
                "{label} declares effect \"{kind}\"{note}, which this build does not execute - refusing rather than rendering something the mix does not say"
            ));
        }
        Ok(())
    };
    if let Some(Json::Arr(tracks)) = mix.get("tracks") {
        for t in tracks {
            let name = str_of(t, "name");
            walk(&format!("track \"{name}\""), Some(t))?;
        }
    }
    if let Some(Json::Arr(buses)) = mix.get("buses") {
        for b in buses {
            let name = str_of(b, "name");
            walk(&format!("bus \"{name}\""), Some(b))?;
        }
    }
    walk("master", mix.get("master"))
}

/// Mix rendered stems into one interleaved stereo buffer. stems: [{frames, l, r, route}];
/// mix: {buses: [{name, gain}], master: {gain}}. The receipt carries the sample digest instead of
/// the sample array, like the kba receipt.
pub fn mix_stems(stems: &Json, mix: &Json, sample_rate: u32) -> Result<Json, String> {
    let stems = match stems {
        Json::Arr(items) => items,
        _ => return Err("stems must be a list".into()),
    };
    let mut frames = 0usize;
    for s in stems {
        let n = num_of(s, "frames").unwrap_or(0.0) as usize;
        if n > frames {
            frames = n;
        }
    }
    let mut bus_names: Vec<String> = Vec::new();
    let mut bus_gain: Vec<f64> = Vec::new();
    if let Some(Json::Arr(buses)) = mix.get("buses") {
        for b in buses {
            let name = str_of(b, "name");
            let gain = match num_of(b, "gain") {
                Some(g) if g.is_finite() => g,
                _ => 1.0,
            };
            bus_names.push(name);
            bus_gain.push(gain);
        }
    }
    let master_gain = match mix.get("master").and_then(|m| num_of(m, "gain")) {
        Some(g) if g.is_finite() => g,
        _ => 1.0,
    };

    let mut out_l = vec![0f32; frames];
    let mut out_r = vec![0f32; frames];
    let mut bus_l: Vec<Vec<f32>> = (0..bus_names.len()).map(|_| vec![0f32; frames]).collect();
    let mut bus_r: Vec<Vec<f32>> = (0..bus_names.len()).map(|_| vec![0f32; frames]).collect();

    for s in stems {
        let n = (num_of(s, "frames").unwrap_or(0.0) as usize).min(frames);
        let route = str_of(s, "route");
        let route = if route.is_empty() { "master".to_string() } else { route };
        let (target_l, target_r): (Option<&mut Vec<f32>>, Option<&mut Vec<f32>>) = if route == "master" {
            (Some(&mut out_l), Some(&mut out_r))
        } else {
            match bus_names.iter().position(|b| *b == route) {
                Some(i) => (Some(&mut bus_l[i]), Some(&mut bus_r[i])),
                None => {
                    let declared = if bus_names.is_empty() { "none".to_string() } else { bus_names.join(", ") };
                    return Err(format!("track routed to unknown bus \"{route}\" (declared buses: {declared})"));
                }
            }
        };
        let target_l = target_l.unwrap();
        let target_r = target_r.unwrap();
        let l_items = match s.get("l") {
            Some(Json::Arr(items)) => items,
            _ => return Err("a stem carries no l channel".into()),
        };
        let r_items = match s.get("r") {
            Some(Json::Arr(items)) => items,
            _ => return Err("a stem carries no r channel".into()),
        };
        for i in 0..n {
            let lv = match l_items.get(i) {
                Some(Json::Num(v)) => *v as f32,
                _ => 0.0,
            };
            let rv = match r_items.get(i) {
                Some(Json::Num(v)) => *v as f32,
                _ => 0.0,
            };
            target_l[i] = (target_l[i] as f64 + lv as f64) as f32;
            target_r[i] = (target_r[i] as f64 + rv as f64) as f32;
        }
    }
    for (bi, name) in bus_names.iter().enumerate() {
        let g = bus_gain[bi];
        for i in 0..frames {
            out_l[i] = (out_l[i] as f64 + bus_l[bi][i] as f64 * g) as f32;
            out_r[i] = (out_r[i] as f64 + bus_r[bi][i] as f64 * g) as f32;
        }
        let _ = name;
    }
    let mut samples = Vec::with_capacity(frames * 2);
    for i in 0..frames {
        samples.push((out_l[i] as f64 * master_gain) as f32);
        samples.push((out_r[i] as f64 * master_gain) as f32);
    }
    let mut bytes = Vec::with_capacity(samples.len() * 4);
    for s in &samples {
        bytes.extend_from_slice(&s.to_le_bytes());
    }
    let digest = md5::Md5::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(Json::obj(vec![
        ("frames", Json::int(frames as i64)),
        ("sampleRate", Json::int(sample_rate as i64)),
        ("channels", Json::int(2)),
        ("samplesMd5", Json::str(&digest)),
        ("samplesCount", Json::int(samples.len() as i64)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pan_extremes_isolate_channels() {
        let (l, r) = pan_coeffs(-1.0);
        assert!((l - 1.0).abs() < 1e-12);
        assert!(r.abs() < 1e-12);
        let (l, r) = pan_coeffs(1.0);
        assert!(l.abs() < 1e-12);
        assert!((r - 1.0).abs() < 1e-12);
        let (l, r) = pan_coeffs(0.0);
        assert!((l - r).abs() < 1e-12);
    }

    #[test]
    fn unknown_bus_refuses() {
        let stems = crate::json::parse(
            r#"[{"frames":2,"l":[0.5,0.5],"r":[0.5,0.5],"route":"ghost"}]"#,
        )
        .unwrap();
        let mix = crate::json::parse(r#"{"buses":[{"name":"reverb","gain":0.5}],"master":{"gain":1}}"#).unwrap();
        let e = mix_stems(&stems, &mix, 44100).unwrap_err();
        assert_eq!(e, "track routed to unknown bus \"ghost\" (declared buses: reverb)");
    }

    #[test]
    fn undeclared_effect_refuses() {
        let mix = crate::json::parse(
            r#"{"tracks":[{"name":"drums","effects":[{"kind":"eq","note":"low shelf"}]}]}"#,
        )
        .unwrap();
        let e = assert_renderable(&mix).unwrap_err();
        assert_eq!(
            e,
            "track \"drums\" declares effect \"eq\" (low shelf), which this build does not execute - refusing rather than rendering something the mix does not say"
        );
    }

    #[test]
    fn stems_sum_to_the_master() {
        let stems = crate::json::parse(
            r#"[{"frames":2,"l":[0.25,0.25],"r":[0.25,0.25],"route":"master"},{"frames":2,"l":[0.25,0.25],"r":[0.25,0.25],"route":"master"}]"#,
        )
        .unwrap();
        let mix = crate::json::parse(r#"{"master":{"gain":1}}"#).unwrap();
        let r = mix_stems(&stems, &mix, 44100).unwrap();
        assert_eq!(r.get("frames").unwrap().render(), "2");
        assert_eq!(r.get("channels").unwrap().render(), "2");
    }
}
