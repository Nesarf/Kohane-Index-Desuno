// The kb family's JSON containers - .kbs score, .kbw wave envelope, .kbv view layout, .kbm mix.
//
// These four are the "作编混" side of the .kb family: documents Kohane stores itself in. They
// share one envelope - { format, version } with a per-family marker - and are JSON documents. The
// readers are strict about what they accept: a file that is not the container fails with the
// container's own name ("not a kohane score"), never a vague "unknown format", and a note list
// that fails shape checks is refused instead of being handed downstream.
//
// The Rust port is judged byte-exact against deps/decoders/kb-media.mjs: write output must be the
// same JSON envelope bytes, read receipts must agree field for field, and every refusal must carry
// the same sentence the JS reader raises.
use crate::json::Json;

const WAVES: [&str; 5] = ["sine", "square", "saw", "triangle", "noise"];

fn marker(kind: &str) -> &'static str {
    match kind {
        "kbs" => "kohane-score",
        "kbw" => "kohane-wave",
        "kbv" => "kohane-view",
        _ => "kohane-mix",
    }
}

fn what(kind: &str) -> &'static str {
    match kind {
        "kbs" => "kohane score",
        "kbw" => "kohane wave envelope",
        "kbv" => "kohane view layout",
        _ => "kohane mix",
    }
}

// ---------------------------------------------------------------- shared helpers

fn is_num(j: &Json) -> bool {
    matches!(j, Json::Num(n) if n.is_finite())
}

fn num_or(j: Option<&Json>, default: f64) -> f64 {
    match j {
        Some(Json::Num(n)) if n.is_finite() => *n,
        _ => default,
    }
}

// JS String() semantics for a primitive JSON value; arrays join their elements, objects are the
// generic tag - the same shapes String() produces.
fn js_stringify(j: &Json) -> String {
    match j {
        Json::Null => "null".into(),
        Json::Bool(true) => "true".into(),
        Json::Bool(false) => "false".into(),
        Json::Num(n) => Json::Num(*n).render(),
        Json::Str(s) => s.clone(),
        Json::Arr(items) => items.iter().map(js_stringify).collect::<Vec<_>>().join(","),
        Json::Obj(_) => "[object Object]".into(),
    }
}

// Math.round(x) is round-half-up toward +infinity; the [-0.5, 0) band rounds to -0, which JSON
// then renders as 0. f64::round() is round-half-away, so the band must be handled explicitly.
fn js_round(x: f64) -> f64 {
    if (-0.5..0.0).contains(&x) {
        -0.0
    } else {
        (x + 0.5).floor()
    }
}

fn is_wave(s: &str) -> bool {
    WAVES.contains(&s)
}

// JS open(): parse the envelope, then check the marker and the version, with the container's own
// name on every failure.
fn open<'a>(kind: &str, text: &'a str) -> Result<Json, String> {
    let w = what(kind);
    let doc = crate::json::parse(text)
        .map_err(|_| format!("not a {w} (the bytes are not the container's JSON envelope)"))?;
    let m = marker(kind);
    match &doc {
        Json::Obj(_) => {}
        _ => return Err(format!("not a {w} (missing the {m} marker)")),
    }
    match doc.get("format") {
        Some(Json::Str(f)) if f == m => {}
        _ => return Err(format!("not a {w} (missing the {m} marker)")),
    }
    match doc.get("version") {
        Some(Json::Num(v)) if *v == 1.0 => {}
        other => {
            let shown = match other {
                Some(v) => v.render(),
                None => "undefined".into(),
            };
            return Err(format!("not a {w} (unknown version {shown})"));
        }
    }
    Ok(doc)
}

fn seal(kind: &str, body: Vec<(&str, Json)>) -> Vec<u8> {
    let mut pairs = vec![("format", Json::str(marker(kind))), ("version", Json::int(1))];
    pairs.extend(body);
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
        .render()
        .into_bytes()
}

// The input of a write is the score/wave/view/mix object as parsed JSON; array members that are
// not the right type are dropped or defaulted exactly where the JS writer drops them.
fn clean_effect(f: &Json) -> Vec<(&'static str, Json)> {
    let kind = match f.get("kind") {
        None => "?".to_string(),
        Some(Json::Null) | Some(Json::Bool(false)) => "?".to_string(),
        Some(Json::Num(n)) if *n == 0.0 => "?".to_string(),
        Some(Json::Str(s)) if s.is_empty() => "?".to_string(),
        Some(v) => js_stringify(v),
    };
    let mut pairs = vec![("kind", Json::str(kind))];
    if let Some(Json::Str(note)) = f.get("note") {
        pairs.push(("note", Json::str(note.clone())));
    }
    pairs
}

// ---------------------------------------------------------------- .kbs score

pub fn write_kbs(input: &Json) -> Vec<u8> {
    let notes = match input.get("notes") {
        Some(Json::Arr(a)) => a.clone(),
        _ => vec![],
    };
    let parts: Vec<Json> = match input.get("parts") {
        Some(Json::Arr(a)) => a.iter().map(|e| Json::str(js_stringify(e))).collect(),
        _ => vec![],
    };
    let instruments = match input.get("instruments") {
        Some(v @ (Json::Obj(_) | Json::Arr(_))) if !matches!(v, Json::Null) => v.clone(),
        _ => Json::Obj(vec![]),
    };
    let title = match input.get("title") {
        Some(Json::Str(s)) if !s.is_empty() => s.clone(),
        _ => "untitled score".into(),
    };
    let bpm = match input.get("bpm") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => *n,
        _ => 120.0,
    };
    let key = match input.get("key") {
        Some(Json::Str(s)) if !s.is_empty() => s.clone(),
        _ => "C".into(),
    };
    let sample_rate = match input.get("sampleRate") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => *n,
        _ => 44100.0,
    };
    let wave = match input.get("wave") {
        Some(Json::Str(s)) if is_wave(s) => s.clone(),
        _ => "square".into(),
    };
    let mut body = vec![
        ("title", Json::str(title)),
        ("bpm", Json::num(bpm)),
        ("key", Json::str(key)),
        ("sampleRate", Json::num(sample_rate)),
        ("wave", Json::str(wave)),
    ];
    match input.get("adsr") {
        Some(v @ (Json::Obj(_) | Json::Arr(_))) if !matches!(v, Json::Null) => {
            body.push(("adsr", v.clone()));
        }
        _ => {}
    }
    body.push(("parts", Json::arr(parts)));
    body.push(("instruments", instruments));
    body.push(("notes", Json::arr(notes)));
    seal("kbs", body)
}

pub fn read_kbs(buf: &[u8]) -> Result<Json, String> {
    let text = std::str::from_utf8(buf)
        .map_err(|_| "not a kohane score (the bytes are not the container's JSON envelope)".to_string())?;
    let doc = open("kbs", text)?;
    let notes = match doc.get("notes") {
        Some(Json::Arr(a)) => a.clone(),
        _ => return Err("not a kohane score (notes is not a list)".into()),
    };
    for (i, n) in notes.iter().enumerate() {
        let Json::Obj(_) = n else {
            return Err(format!("not a kohane score (note {i} is not a {{t, dur, pitch}} event)"));
        };
        let t = n.get("t");
        let dur = n.get("dur");
        let pitch = n.get("pitch");
        let bad_note = !is_num(t.unwrap_or(&Json::Null))
            || !is_num(dur.unwrap_or(&Json::Null))
            || num_or(t, 0.0) < 0.0
            || num_or(dur, 0.0) < 0.0
            || !matches!(pitch, Some(Json::Num(p)) if p.fract() == 0.0 && *p >= 0.0 && *p <= 127.0);
        if bad_note {
            return Err(format!(
                "not a kohane score (note {i} is not a {{t, dur, pitch}} event)"
            ));
        }
        if let Some(vel) = n.get("vel") {
            if !matches!(vel, Json::Num(v) if v.is_finite() && *v >= 0.0 && *v <= 1.0) {
                return Err(format!("not a kohane score (note {i} velocity is not a 0..1 level)"));
            }
        }
        if let Some(w) = n.get("wave") {
            let ok = matches!(w, Json::Str(s) if is_wave(s));
            if !ok {
                return Err(format!(
                    "not a kohane score (note {i} wave \"{}\" is not a kohane oscillator)",
                    js_stringify(w)
                ));
            }
        }
    }
    let mut receipt = vec![
        ("format", Json::str(marker("kbs"))),
        ("version", Json::int(1)),
        ("title", Json::str(match doc.get("title") {
            Some(Json::Str(s)) => s.clone(),
            _ => "untitled score".into(),
        })),
        ("bpm", Json::num(match doc.get("bpm") {
            Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => *n,
            _ => 120.0,
        })),
        ("key", Json::str(match doc.get("key") {
            Some(Json::Str(s)) => s.clone(),
            _ => "C".into(),
        })),
        ("sampleRate", Json::num(match doc.get("sampleRate") {
            Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => *n,
            _ => 44100.0,
        })),
        ("wave", Json::str(match doc.get("wave") {
            Some(Json::Str(s)) if is_wave(s) => s.clone(),
            _ => "square".into(),
        })),
    ];
    match doc.get("adsr") {
        Some(v @ (Json::Obj(_) | Json::Arr(_))) if !matches!(v, Json::Null) => {
            receipt.push(("adsr", v.clone()));
        }
        _ => {}
    }
    let parts: Vec<Json> = match doc.get("parts") {
        Some(Json::Arr(a)) => a.iter().map(|e| Json::str(js_stringify(e))).collect(),
        _ => vec![],
    };
    let instruments = match doc.get("instruments") {
        Some(v @ (Json::Obj(_) | Json::Arr(_))) if !matches!(v, Json::Null) => v.clone(),
        _ => Json::Obj(vec![]),
    };
    receipt.push(("parts", Json::arr(parts)));
    receipt.push(("instruments", instruments));
    receipt.push(("notes", Json::arr(notes)));
    Ok(Json::Obj(
        receipt.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
    ))
}

// ---------------------------------------------------------------- .kbw wave envelope

pub fn write_kbw(input: &Json) -> Vec<u8> {
    let buckets = match input.get("buckets") {
        Some(Json::Arr(a)) => a.clone(),
        _ => vec![],
    };
    let sample_rate = match input.get("sampleRate") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => *n,
        _ => 44100.0,
    };
    let frames = match input.get("frames") {
        Some(Json::Num(n)) if n.is_finite() && *n >= 0.0 => js_round(*n),
        _ => 0.0,
    };
    let channel_count = match input.get("channelCount") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => js_round(*n),
        _ => 1.0,
    };
    let bucket_size = match input.get("bucketSize") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => js_round(*n),
        _ => 512.0,
    };
    seal(
        "kbw",
        vec![
            ("sampleRate", Json::num(sample_rate)),
            ("frames", Json::num(frames)),
            ("channelCount", Json::num(channel_count)),
            ("bucketSize", Json::num(bucket_size)),
            ("buckets", Json::arr(buckets)),
        ],
    )
}

pub fn read_kbw(buf: &[u8]) -> Result<Json, String> {
    let text = std::str::from_utf8(buf).map_err(|_| {
        "not a kohane wave envelope (the bytes are not the container's JSON envelope)".to_string()
    })?;
    let doc = open("kbw", text)?;
    let buckets = match doc.get("buckets") {
        Some(Json::Arr(a)) if !a.is_empty() => a.clone(),
        _ => return Err("not a kohane wave envelope (buckets is empty)".into()),
    };
    let sample_rate = match doc.get("sampleRate") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => *n,
        _ => return Err("not a kohane wave envelope (bad sample rate)".into()),
    };
    let frames = match doc.get("frames") {
        Some(Json::Num(n)) if n.is_finite() && *n >= 0.0 => *n,
        _ => return Err("not a kohane wave envelope (bad frame count)".into()),
    };
    let bucket_size = match doc.get("bucketSize") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => *n,
        _ => return Err("not a kohane wave envelope (bad bucket size)".into()),
    };
    for (i, b) in buckets.iter().enumerate() {
        let Json::Arr(pair) = b else {
            return Err(format!(
                "not a kohane wave envelope (bucket {i} is not a [min, max] pair in -1..1)"
            ));
        };
        let (Some(lo), Some(hi)) = (pair.first(), pair.get(1)) else {
            return Err(format!(
                "not a kohane wave envelope (bucket {i} is not a [min, max] pair in -1..1)"
            ));
        };
        if pair.len() != 2
            || !is_num(lo)
            || !is_num(hi)
            || num_or(Some(lo), 0.0) > num_or(Some(hi), 0.0)
            || num_or(Some(lo), 0.0) < -1.0
            || num_or(Some(hi), 0.0) > 1.0
        {
            return Err(format!(
                "not a kohane wave envelope (bucket {i} is not a [min, max] pair in -1..1)"
            ));
        }
    }
    let channel_count = match doc.get("channelCount") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => js_round(*n),
        _ => 1.0,
    };
    let coverage = buckets.len() as f64 * bucket_size;
    let covers_all = coverage >= frames;
    let duration_sec = frames / sample_rate;
    Ok(Json::Obj(vec![
        ("format".into(), Json::str(marker("kbw"))),
        ("version".into(), Json::int(1)),
        ("sampleRate".into(), Json::num(sample_rate)),
        ("frames".into(), Json::num(frames)),
        ("channelCount".into(), Json::num(channel_count)),
        ("bucketSize".into(), Json::num(bucket_size)),
        ("buckets".into(), Json::arr(buckets)),
        ("coverage".into(), Json::num(coverage)),
        ("coversAll".into(), Json::Bool(covers_all)),
        ("durationSec".into(), Json::num(duration_sec)),
    ]))
}

// ---------------------------------------------------------------- .kbv view layout

pub fn write_kbv(input: &Json) -> Vec<u8> {
    let lanes = match input.get("lanes") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => js_round(*n),
        _ => 1.0,
    };
    let octave_lines: Vec<Json> = match input.get("octaveLines") {
        Some(Json::Arr(a)) => a
            .iter()
            .filter(|e| is_num(e))
            .map(|e| Json::num(js_round(num_or(Some(e), 0.0))))
            .collect(),
        _ => vec![],
    };
    let palette: Vec<Json> = match input.get("palette") {
        Some(Json::Arr(a)) => a
            .iter()
            .filter(|e| matches!(e, Json::Str(_)))
            .map(|e| match e {
                Json::Str(s) => Json::str(s.clone()),
                _ => unreachable!(),
            })
            .collect(),
        _ => vec![],
    };
    seal(
        "kbv",
        vec![
            ("title", Json::str(match input.get("title") {
                Some(Json::Str(s)) if !s.is_empty() => s.clone(),
                _ => "untitled view".into(),
            })),
            ("lanes", Json::num(lanes)),
            ("octaveLines", Json::arr(octave_lines)),
            ("palette", Json::arr(palette)),
        ],
    )
}

pub fn read_kbv(buf: &[u8]) -> Result<Json, String> {
    let text = std::str::from_utf8(buf).map_err(|_| {
        "not a kohane view layout (the bytes are not the container's JSON envelope)".to_string()
    })?;
    let doc = open("kbv", text)?;
    let lanes = match doc.get("lanes") {
        Some(Json::Num(n)) if n.is_finite() && *n >= 1.0 => js_round(*n),
        _ => return Err("not a kohane view layout (lanes is not a positive count)".into()),
    };
    let palette = match doc.get("palette") {
        Some(Json::Arr(a)) => a.clone(),
        _ => return Err("not a kohane view layout (palette is not a list)".into()),
    };
    let octave_lines: Vec<Json> = match doc.get("octaveLines") {
        Some(Json::Arr(a)) => a
            .iter()
            .filter(|e| is_num(e))
            .map(|e| Json::num(js_round(num_or(Some(e), 0.0))))
            .collect(),
        _ => vec![],
    };
    Ok(Json::Obj(vec![
        ("format".into(), Json::str(marker("kbv"))),
        ("version".into(), Json::int(1)),
        ("title".into(), Json::str(match doc.get("title") {
            Some(Json::Str(s)) => s.clone(),
            _ => "untitled view".into(),
        })),
        ("lanes".into(), Json::num(lanes)),
        ("octaveLines".into(), Json::arr(octave_lines)),
        ("palette".into(), Json::arr(palette.iter().map(|e| Json::str(js_stringify(e))).collect())),
    ]))
}

// ---------------------------------------------------------------- .kbm mix

pub fn write_kbm(input: &Json) -> Vec<u8> {
    let clean_track = |t: &Json| -> Vec<(&'static str, Json)> {
        let effects: Vec<Json> = match t.get("effects") {
            Some(Json::Arr(a)) => a
                .iter()
                .map(|f| {
                    Json::Obj(
                        clean_effect(f)
                            .into_iter()
                            .map(|(k, v)| (k.to_string(), v))
                            .collect(),
                    )
                })
                .collect(),
            _ => vec![],
        };
        vec![
            ("name", Json::str(match t.get("name") {
                Some(Json::Str(s)) if !s.is_empty() => s.clone(),
                _ => "track".into(),
            })),
            ("gain", Json::num(match t.get("gain") {
                Some(Json::Num(n)) if n.is_finite() => *n,
                _ => 1.0,
            })),
            ("pan", Json::num(match t.get("pan") {
                Some(Json::Num(n)) if n.is_finite() => n.max(-1.0).min(1.0),
                _ => 0.0,
            })),
            ("route", Json::str(match t.get("route") {
                Some(Json::Str(s)) if !s.is_empty() => s.clone(),
                _ => "master".into(),
            })),
            ("effects", Json::arr(effects)),
        ]
    };
    let clean_bus = |b: &Json| -> Vec<(&'static str, Json)> {
        let effects: Vec<Json> = match b.get("effects") {
            Some(Json::Arr(a)) => a
                .iter()
                .map(|f| {
                    Json::Obj(
                        clean_effect(f)
                            .into_iter()
                            .map(|(k, v)| (k.to_string(), v))
                            .collect(),
                    )
                })
                .collect(),
            _ => vec![],
        };
        vec![
            ("name", Json::str(match b.get("name") {
                Some(Json::Str(s)) if !s.is_empty() => s.clone(),
                _ => "bus".into(),
            })),
            ("gain", Json::num(match b.get("gain") {
                Some(Json::Num(n)) if n.is_finite() => *n,
                _ => 1.0,
            })),
            ("effects", Json::arr(effects)),
        ]
    };
    let tracks: Vec<Json> = match input.get("tracks") {
        Some(Json::Arr(a)) => a
            .iter()
            .map(|t| Json::Obj(clean_track(t).into_iter().map(|(k, v)| (k.to_string(), v)).collect()))
            .collect(),
        _ => vec![],
    };
    let buses: Vec<Json> = match input.get("buses") {
        Some(Json::Arr(a)) => a
            .iter()
            .map(|b| Json::Obj(clean_bus(b).into_iter().map(|(k, v)| (k.to_string(), v)).collect()))
            .collect(),
        _ => vec![],
    };
    let master = input.get("master");
    let master_effects: Vec<Json> = match master.and_then(|m| m.get("effects")) {
        Some(Json::Arr(a)) => a
            .iter()
            .map(|f| {
                Json::Obj(
                    clean_effect(f)
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                )
            })
            .collect(),
        _ => vec![],
    };
    let title = match input.get("title") {
        Some(Json::Str(s)) if !s.is_empty() => s.clone(),
        _ => "untitled mix".into(),
    };
    let sample_rate = match input.get("sampleRate") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => *n,
        _ => 44100.0,
    };
    seal(
        "kbm",
        vec![
            ("title", Json::str(title)),
            ("sampleRate", Json::num(sample_rate)),
            ("tracks", Json::arr(tracks)),
            ("buses", Json::arr(buses)),
            ("master", Json::Obj(vec![
                ("gain".to_string(), Json::num(match master.and_then(|m| m.get("gain")) {
                    Some(Json::Num(n)) if n.is_finite() => *n,
                    _ => 1.0,
                })),
                ("effects".to_string(), Json::arr(master_effects)),
            ])),
        ],
    )
}

pub fn read_kbm(buf: &[u8]) -> Result<Json, String> {
    let text = std::str::from_utf8(buf).map_err(|_| {
        "not a kohane mix (the bytes are not the container's JSON envelope)".to_string()
    })?;
    let doc = open("kbm", text)?;
    let tracks = match doc.get("tracks") {
        Some(Json::Arr(a)) => a.clone(),
        _ => return Err("not a kohane mix (tracks is not a list)".into()),
    };
    let buses = match doc.get("buses") {
        Some(Json::Arr(a)) => a.clone(),
        _ => return Err("not a kohane mix (buses is not a list)".into()),
    };
    if !matches!(doc.get("master"), Some(Json::Obj(_))) {
        return Err("not a kohane mix (master is not an object)".into());
    }
    let bus_name = |b: &Json| -> String {
        match b.get("name") {
            Some(Json::Str(s)) if !s.is_empty() => s.clone(),
            Some(Json::Bool(true)) => "true".into(),
            Some(Json::Num(n)) if *n != 0.0 => Json::Num(*n).render(),
            Some(Json::Obj(_)) => "[object Object]".into(),
            Some(Json::Arr(a)) if !a.is_empty() => a.iter().map(js_stringify).collect::<Vec<_>>().join(","),
            _ => String::new(),
        }
    };
    let bus_names: Vec<String> = buses.iter().map(bus_name).collect();
    let read_gain = |v: Option<&Json>, i: usize, who: &str| -> Result<f64, String> {
        match v {
            None => Ok(1.0),
            Some(Json::Num(n)) if n.is_finite() && *n >= 0.0 => Ok(*n),
            _ => Err(format!("not a kohane mix ({who} {i} gain is not a level)")),
        }
    };
    let mut out_tracks: Vec<Json> = Vec::new();
    for (i, t) in tracks.iter().enumerate() {
        let Json::Obj(_) = t else {
            return Err(format!("not a kohane mix (track {i} is not an object)"));
        };
        let gain = read_gain(t.get("gain"), i, "track")?;
        let pan = match t.get("pan") {
            None => 0.0,
            Some(Json::Num(n)) if n.is_finite() && *n >= -1.0 && *n <= 1.0 => *n,
            _ => return Err(format!("not a kohane mix (track {i} pan is outside -1..1)")),
        };
        let route = match t.get("route") {
            Some(Json::Str(s)) if !s.is_empty() => s.clone(),
            _ => "master".into(),
        };
        if route != "master" && !bus_names.contains(&route) {
            return Err(format!(
                "not a kohane mix (track {i} routes to unknown bus \"{route}\")"
            ));
        }
        let effects = match t.get("effects") {
            Some(Json::Arr(a)) => a.clone(),
            _ => vec![],
        };
        out_tracks.push(Json::Obj(vec![
            ("name".into(), Json::str(match t.get("name") {
                Some(Json::Str(s)) => s.clone(),
                _ => "track".into(),
            })),
            ("gain".into(), Json::num(gain)),
            ("pan".into(), Json::num(pan)),
            ("route".into(), Json::str(route)),
            ("effects".into(), Json::arr(effects)),
        ]));
    }
    let mut out_buses: Vec<Json> = Vec::new();
    for (i, b) in buses.iter().enumerate() {
        let Json::Obj(_) = b else {
            return Err(format!("not a kohane mix (bus {i} is not an object)"));
        };
        let gain = read_gain(b.get("gain"), i, "bus")?;
        let effects = match b.get("effects") {
            Some(Json::Arr(a)) => a.clone(),
            _ => vec![],
        };
        out_buses.push(Json::Obj(vec![
            ("name".into(), Json::str(match b.get("name") {
                Some(Json::Str(s)) => s.clone(),
                _ => "bus".into(),
            })),
            ("gain".into(), Json::num(gain)),
            ("effects".into(), Json::arr(effects)),
        ]));
    }
    let master = doc.get("master").unwrap();
    let master_gain = match master.get("gain") {
        None => 1.0,
        Some(Json::Num(n)) if n.is_finite() && *n >= 0.0 => *n,
        _ => return Err("not a kohane mix (master gain is not a level)".into()),
    };
    let master_effects = match master.get("effects") {
        Some(Json::Arr(a)) => a.clone(),
        _ => vec![],
    };
    Ok(Json::Obj(vec![
        ("format".into(), Json::str(marker("kbm"))),
        ("version".into(), Json::int(1)),
        ("title".into(), Json::str(match doc.get("title") {
            Some(Json::Str(s)) => s.clone(),
            _ => "untitled mix".into(),
        })),
        ("sampleRate".into(), Json::num(match doc.get("sampleRate") {
            Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => *n,
            _ => 44100.0,
        })),
        ("tracks".into(), Json::arr(out_tracks)),
        ("buses".into(), Json::arr(out_buses)),
        ("master".into(), Json::Obj(vec![
            ("gain".to_string(), Json::num(master_gain)),
            ("effects".to_string(), Json::arr(master_effects)),
        ])),
    ]))
}

// ---------------------------------------------------------------- registry face

fn capability(id: &str, kohane_name: &str, container: &str, read: &str, decode: &str, encode: &str, verified: &str) -> Json {
    Json::Obj(vec![
        ("id".into(), Json::str(id)),
        ("kohaneName".into(), Json::str(kohane_name)),
        ("container".into(), Json::str(container)),
        ("read".into(), Json::Obj(vec![("level".into(), Json::str("full")), ("detail".into(), Json::str(read))])),
        ("decode".into(), Json::Obj(vec![("level".into(), Json::str("none")), ("detail".into(), Json::str(decode))])),
        ("encode".into(), Json::Obj(vec![("level".into(), Json::str("full")), ("detail".into(), Json::str(encode))])),
        ("verifiedAgainst".into(), Json::str(verified)),
    ])
}

pub fn capabilities() -> Json {
    Json::arr(vec![
        capability(
            "kbs",
            "Kohane Bassline Score",
            "kbs",
            "the score document: title, tempo, key, parts, instruments and the note list - note events in the synth's second space, so a read score replays directly",
            "a score is data, not audio: the sound is generated by the synth, and the .kbw envelope describes any rendered waveform",
            "writes the .kbs score document",
            "the selfcheck kpb media section: write/read round trip, replay frame counts, tampered-score refusal, and the bundle self-proof",
        ),
        capability(
            "kbw",
            "Kohane Bassline Wave",
            "kbw",
            "the waveform envelope document: sample rate, frame count, bucket size and the min/max bucket pairs - enough to draw the waveform",
            "the envelope describes audio, it does not carry samples",
            "writes the .kbw envelope document from min/max buckets",
            "the selfcheck kpb media section: write/read round trip, bucket coverage against the declared frame count",
        ),
        capability(
            "kbv",
            "Kohane Bassline View",
            "kbv",
            "the waterfall layout document: title, lane count, octave lines and the palette",
            "a layout has no samples",
            "writes the .kbv layout document",
            "the selfcheck kpb media section: write/read round trip, lane and palette checks",
        ),
        capability(
            "kbm",
            "Kohane Bassline Mix",
            "kbm",
            "the mix document: tracks with gain/pan/route, buses with gain, master gain, and the declared effect chains",
            "a mix is instructions, not audio: the mixer renders stems through it (deps/decoders/mix.mjs)",
            "writes the .kbm mix document",
            "the selfcheck kpb mix (stage 4) section: write/read round trip, route validation against declared buses, and the mixer's own verified judges",
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(items: Vec<(&str, Json)>) -> Json {
        Json::Obj(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    #[test]
    fn kbs_round_trip_and_refusals() {
        let score = obj(vec![
            ("title", Json::str("test")),
            ("bpm", Json::num(150.0)),
            ("notes", Json::arr(vec![
                obj(vec![("t", Json::num(0.0)), ("dur", Json::num(0.5)), ("pitch", Json::int(60))]),
                obj(vec![("t", Json::num(0.5)), ("dur", Json::num(0.25)), ("pitch", Json::int(64)), ("vel", Json::num(0.8)), ("wave", Json::str("saw"))]),
            ])),
            ("adsr", obj(vec![("a", Json::num(0.01)), ("r", Json::num(0.2))])),
            ("parts", Json::arr(vec![Json::str("lead"), Json::str("bass")])),
        ]);
        let bytes = write_kbs(&score);
        let back = read_kbs(&bytes).unwrap();
        assert_eq!(back.get("title").unwrap().render(), "\"test\"");
        assert_eq!(back.get("bpm").unwrap().render(), "150");
        assert_eq!(back.get("notes").unwrap().render(), "[{\"t\":0,\"dur\":0.5,\"pitch\":60},{\"t\":0.5,\"dur\":0.25,\"pitch\":64,\"vel\":0.8,\"wave\":\"saw\"}]");
        assert_eq!(back.get("adsr").unwrap().render(), "{\"a\":0.01,\"r\":0.2}");
        assert_eq!(back.get("parts").unwrap().render(), "[\"lead\",\"bass\"]");

        // a note with pitch out of range is refused with the container's own name
        let bad = obj(vec![("notes", Json::arr(vec![
            obj(vec![("t", Json::num(0.0)), ("dur", Json::num(0.5)), ("pitch", Json::int(200))]),
        ]))]);
        let err = read_kbs(&write_kbs(&bad)).unwrap_err();
        assert_eq!(err, "not a kohane score (note 0 is not a {t, dur, pitch} event)");

        // a non-container fails with the marker sentence, not a parse error
        let err2 = read_kbs(br#"{"format":"other","version":1,"notes":[]}"#).unwrap_err();
        assert_eq!(err2, "not a kohane score (missing the kohane-score marker)");
        let err3 = read_kbs(b"not json at all").unwrap_err();
        assert_eq!(err3, "not a kohane score (the bytes are not the container's JSON envelope)");
    }

    #[test]
    fn kbw_coverage_and_refusals() {
        let wave = obj(vec![
            ("sampleRate", Json::int(44100)),
            ("frames", Json::int(1024)),
            ("bucketSize", Json::int(512)),
            ("buckets", Json::arr(vec![
                Json::arr(vec![Json::num(-0.5), Json::num(0.5)]),
                Json::arr(vec![Json::num(0.0), Json::num(1.0)]),
            ])),
        ]);
        let bytes = write_kbw(&wave);
        let back = read_kbw(&bytes).unwrap();
        assert_eq!(back.get("coverage").unwrap().render(), "1024");
        assert_eq!(back.get("coversAll").unwrap().render(), "true");
        assert_eq!(back.get("durationSec").unwrap().render(), "0.023219954648526078");

        let empty = obj(vec![]);
        let err = read_kbw(&write_kbw(&empty)).unwrap_err();
        assert_eq!(err, "not a kohane wave envelope (buckets is empty)");
    }

    #[test]
    fn kbv_defaults() {
        let view = obj(vec![
            ("lanes", Json::num(3.5)),
            ("palette", Json::arr(vec![Json::str("#fff"), Json::str("#000")])),
            ("octaveLines", Json::arr(vec![Json::int(0), Json::int(12), Json::num(-0.25)])),
        ]);
        let back = read_kbv(&write_kbv(&view)).unwrap();
        assert_eq!(back.get("lanes").unwrap().render(), "4");
        assert_eq!(back.get("octaveLines").unwrap().render(), "[0,12,0]");
    }

    #[test]
    fn kbm_route_validation() {
        let mix = obj(vec![
            ("title", Json::str("song mix")),
            ("buses", Json::arr(vec![obj(vec![("name", Json::str("reverb"))])])),
            ("tracks", Json::arr(vec![
                obj(vec![("name", Json::str("drums")), ("gain", Json::num(0.8)), ("pan", Json::num(2.0)), ("route", Json::str("reverb")), ("effects", Json::arr(vec![obj(vec![("kind", Json::str("eq")), ("note", Json::str("low shelf"))])]))]),
            ])),
        ]);
        let bytes = write_kbm(&mix);
        let back = read_kbm(&bytes).unwrap();
        let tracks = back.get("tracks").unwrap().render();
        assert_eq!(tracks, "[{\"name\":\"drums\",\"gain\":0.8,\"pan\":1,\"route\":\"reverb\",\"effects\":[{\"kind\":\"eq\",\"note\":\"low shelf\"}]}]");

        // a route to an undeclared bus is refused with the bus's name in the sentence
        let bad = obj(vec![("tracks", Json::arr(vec![
            obj(vec![("route", Json::str("missing"))]),
        ]))]);
        let err = read_kbm(&write_kbm(&bad)).unwrap_err();
        assert_eq!(err, "not a kohane mix (track 0 routes to unknown bus \"missing\")");

        let err2 = read_kbm(br#"{"format":"kohane-mix","version":2,"tracks":[],"buses":[],"master":{}}"#).unwrap_err();
        assert_eq!(err2, "not a kohane mix (unknown version 2)");
    }

    #[test]
    fn capabilities_report_four_containers() {
        let caps = capabilities();
        let Json::Arr(items) = caps else { panic!("not an array") };
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].get("id").unwrap().render(), "\"kbs\"");
        assert_eq!(items[3].get("id").unwrap().render(), "\"kbm\"");
    }
}
