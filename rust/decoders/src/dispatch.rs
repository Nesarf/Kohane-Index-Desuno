// The exec dispatch: `kohane-decoder op <tool> <op> [args.json]` turns a model-facing op id into
// a Rust answer. A wired op returns the same shape the JS tool returns, so the thin shell can
// trust it in place of the JS original; an unwired op answers handled:false with the engine
// named, so the shell routes it back to JS instead of guessing. The absorbed-but-unwired ops
// (ztdw, mix, kbi and the rest) stay honest in the registry's second list.
use crate::json::Json;
use crate::{kba, kbb, ztdw};
use std::fs;

fn str_arg(params: &Json, key: &str) -> String {
    match params.get(key) {
        Some(Json::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

fn num_arg(params: &Json, key: &str) -> Option<f64> {
    match params.get(key) {
        Some(Json::Num(n)) => Some(*n),
        _ => None,
    }
}

pub fn dispatch(tool: &str, op: &str, params: &Json) -> Json {
    match (tool, op) {
        ("library_audio", "kba") => dispatch_kba(params),
        ("library_audio", "kbb") => dispatch_kbb(params),
        ("library_audio", "ztdw") => dispatch_ztdw(params),
        ("library_audio", "mix") => Json::obj(vec![
            ("handled", Json::Bool(false)),
            ("engine", Json::str("js")),
            ("reason", Json::str("op=mix renders stems through the synth, which the rust side has not absorbed yet")),
        ]),
        ("library_audio", "kbi") => Json::obj(vec![
            ("handled", Json::Bool(false)),
            ("engine", Json::str("js")),
            ("reason", Json::str("op=kbi classifies preset roles through the JS plugin table, which the rust side has not absorbed yet")),
        ]),
        _ => Json::obj(vec![
            ("handled", Json::Bool(false)),
            ("engine", Json::str("js")),
            ("reason", Json::str("this op is not wired into the rust dispatch yet")),
        ]),
    }
}

// op=kba read: the same shape the JS tool returns - {ok, op, path, ...stats, decodedFrames,
// decodedPeak, note}. Writing a container from a WAV/AIFF source needs the JS decoder, which the
// rust side has not absorbed, so that path stays on JS and says so.
fn dispatch_kba(params: &Json) -> Json {
    let path = str_arg(params, "path");
    if !path.is_empty() {
        return match fs::read(&path) {
            Ok(buf) => match (kba::kba_stats(&buf), kba::decode_kba(&buf)) {
                (Ok(stats), Ok(dec)) => Json::obj(vec![
                    ("ok", Json::Bool(true)),
                    ("op", Json::str("kba")),
                    ("path", Json::str(&path)),
                    ("tier", Json::str(&stats.tier)),
                    ("sampleRate", Json::int(stats.sample_rate as i64)),
                    ("channels", Json::int(stats.channels as i64)),
                    ("frames", Json::int(stats.frames as i64)),
                    ("bytes", Json::int(stats.bytes as i64)),
                    ("pcmBytes", Json::int(stats.pcm_bytes as i64)),
                    ("decodedFrames", Json::int(dec.frames as i64)),
                    ("decodedPeak", Json::int(dec.decoded_peak)),
                    ("note", Json::str("read: the tier was declared in the header, never guessed")),
                ]),
                (Err(e), _) | (_, Err(e)) => Json::obj(vec![
                    ("ok", Json::Bool(false)),
                    ("op", Json::str("kba")),
                    ("note", Json::str(&e)),
                ]),
            },
            Err(e) => Json::obj(vec![
                ("ok", Json::Bool(false)),
                ("op", Json::str("kba")),
                ("note", Json::str(&format!("cannot read {path}: {e}"))),
            ]),
        };
    }
    let out = str_arg(params, "out");
    if !out.is_empty() {
        return Json::obj(vec![
            ("handled", Json::Bool(false)),
            ("engine", Json::str("js")),
            ("reason", Json::str("writing a kba container from a WAV/AIFF source still needs the JS decoder")),
        ]);
    }
    Json::obj(vec![
        ("ok", Json::Bool(false)),
        ("op", Json::str("kba")),
        ("note", Json::str("kba needs a .kba path to read, or --out with --source to write one")),
    ])
}

// op=kbb read and convert: read returns {ok, op, path, name, tier, ...summary}; convert writes
// the bank document and returns the report with the JS wording.
fn dispatch_kbb(params: &Json) -> Json {
    let path = str_arg(params, "path");
    if !path.is_empty() {
        return match fs::read(&path) {
            Ok(buf) => match kbb::read_kbb(&buf) {
                Ok(doc) => {
                    let summary = kbb::kbb_summary(&doc);
                    let name = match doc.get("name") {
                        Some(Json::Str(s)) => s.clone(),
                        _ => String::new(),
                    };
                    let tier = match doc.get("tier") {
                        Some(Json::Str(s)) => s.clone(),
                        _ => String::new(),
                    };
                    let pick = |k: &str| summary.get(k).cloned().unwrap_or(Json::Null);
                    Json::obj(vec![
                        ("ok", Json::Bool(true)),
                        ("op", Json::str("kbb")),
                        ("path", Json::str(&path)),
                        ("name", Json::str(&name)),
                        ("tier", Json::str(&tier)),
                        ("presets", pick("presets")),
                        ("zones", pick("zones")),
                        ("samples", pick("samples")),
                        ("enumerable", pick("enumerable")),
                    ])
                }
                Err(e) => Json::obj(vec![
                    ("ok", Json::Bool(false)),
                    ("op", Json::str("kbb")),
                    ("note", Json::str(&e)),
                ]),
            },
            Err(e) => Json::obj(vec![
                ("ok", Json::Bool(false)),
                ("op", Json::str("kbb")),
                ("note", Json::str(&format!("cannot read {path}: {e}"))),
            ]),
        };
    }
    let out = str_arg(params, "out");
    if !out.is_empty() {
        let source = str_arg(params, "source");
        if source.is_empty() {
            return Json::obj(vec![
                ("ok", Json::Bool(false)),
                ("op", Json::str("kbb")),
                ("note", Json::str("kbb needs --source (a .sf2 file) to convert")),
            ]);
        }
        let name = str_arg(params, "title");
        let name_opt = if name.is_empty() { None } else { Some(name) };
        let rate = num_arg(params, "targetRate").map(|n| n as u32).unwrap_or(22050);
        let tier = str_arg(params, "tier");
        let tier = if tier.is_empty() { "adpcm".to_string() } else { tier };
        return match kbb::convert_sf2_to_kbb(&source, name_opt, rate, &tier) {
            Ok(out_doc) => {
                let report = out_doc.report.clone();
                let r = |k: &str| -> i64 {
                    match report.get(k) {
                        Some(Json::Num(n)) => *n as i64,
                        _ => 0,
                    }
                };
                let bytes = out_doc.kbb.render().len();
                if params.get("dryRun").is_some() {
                    Json::obj(vec![
                        ("ok", Json::Bool(true)),
                        ("op", Json::str("kbb")),
                        ("out", Json::str(&out)),
                        ("bytes", Json::int(bytes as i64)),
                        ("written", Json::Bool(false)),
                        ("report", report),
                        ("note", Json::str("dryRun: the .kbb bank was not written")),
                    ])
                } else {
                    match fs::write(&out, out_doc.kbb.render()) {
                        Ok(()) => Json::obj(vec![
                            ("ok", Json::Bool(true)),
                            ("op", Json::str("kbb")),
                            ("out", Json::str(&out)),
                            ("source", Json::str(&source)),
                            ("bytes", Json::int(bytes as i64)),
                            ("written", Json::Bool(true)),
                            ("report", report.clone()),
                            ("note", Json::str(&format!(
                                "converted: {} preset(s), {} zone(s), {} unique sample payload(s) ({} deduplicated) - nothing third-party survives the conversion",
                                r("presets"), r("zones"), r("uniqueSamples"), r("deduped")
                            ))),
                        ]),
                        Err(e) => Json::obj(vec![
                            ("ok", Json::Bool(false)),
                            ("op", Json::str("kbb")),
                            ("note", Json::str(&format!("cannot write {out}: {e}"))),
                        ]),
                    }
                }
            }
            Err(e) => Json::obj(vec![
                ("ok", Json::Bool(false)),
                ("op", Json::str("kbb")),
                ("note", Json::str(&e)),
            ]),
        };
    }
    Json::obj(vec![
        ("ok", Json::Bool(false)),
        ("op", Json::str("kbb")),
        ("note", Json::str("kbb needs a .kbb path to read, or --out with --source to convert a SoundFont")),
    ])
}

// op=ztdw: the config directory report and the sample extraction, both read paths the rust side
// has absorbed. Staging the extracted samples as WAV needs the JS wav encoder, so --out stays on JS.
fn dispatch_ztdw(params: &Json) -> Json {
    let path = str_arg(params, "path");
    let source = str_arg(params, "source");
    if source.is_empty() {
        if path.is_empty() {
            return Json::obj(vec![
                ("ok", Json::Bool(false)),
                ("op", Json::str("ztdw")),
                ("note", Json::str("ztdw needs the --path config to report the directory, or --path config + --source merge + --index/--sample to extract")),
            ]);
        }
        return match ztdw::read_ztdw_config(&path) {
            Ok(config) => {
                let pick = |k: &str| config.get(k).cloned().unwrap_or(Json::Null);
                Json::obj(vec![
                    ("ok", Json::Bool(true)),
                    ("op", Json::str("ztdw")),
                    ("path", Json::str(&path)),
                    ("container", pick("container")),
                    ("rawSourceDir", pick("rawSourceDir")),
                    ("pad", pick("pad")),
                    ("mergeFiles", pick("mergeFiles")),
                    ("sources", pick("sources")),
                    ("pitches", pick("pitches")),
                    ("summary", pick("summary")),
                ])
            }
            Err(e) => Json::obj(vec![
                ("ok", Json::Bool(false)),
                ("op", Json::str("ztdw")),
                ("note", Json::str(&e)),
            ]),
        };
    }
    if path.is_empty() {
        return Json::obj(vec![
            ("ok", Json::Bool(false)),
            ("op", Json::str("ztdw")),
            ("note", Json::str("ztdw extraction needs the --path config plus --index or --sample")),
        ]);
    }
    let config = match ztdw::read_ztdw_config(&path) {
        Ok(c) => c,
        Err(e) => return Json::obj(vec![
            ("ok", Json::Bool(false)),
            ("op", Json::str("ztdw")),
            ("note", Json::str(&e)),
        ]),
    };
    // Flat view: every source with its merge file name, in directory order.
    let mut flat: Vec<Json> = Vec::new();
    if let Some(Json::Arr(merge_files)) = config.get("mergeFiles") {
        for m in merge_files {
            let merge_name = match m.get("name") {
                Some(Json::Str(s)) => s.clone(),
                _ => String::new(),
            };
            if let Some(Json::Arr(sources)) = m.get("sources") {
                for s in sources {
                    let mut fields: Vec<(String, Json)> = vec![("mergeFile".to_string(), Json::str(&merge_name))];
                    if let Json::Obj(items) = s {
                        fields.extend(items.iter().map(|(k, v)| (k.clone(), v.clone())));
                    }
                    flat.push(Json::Obj(fields));
                }
            }
        }
    }
    let mut entry: Option<Json> = None;
    if let Some(Json::Num(idx)) = params.get("index") {
        let idx = *idx as i64;
        if idx >= 0 && (idx as usize) < flat.len() {
            entry = Some(flat[idx as usize].clone());
        }
    }
    if entry.is_none() {
        let sample = str_arg(params, "sample");
        if !sample.is_empty() {
            for e in &flat {
                if let Some(Json::Str(name)) = e.get("name") {
                    if *name == sample {
                        entry = Some(e.clone());
                        break;
                    }
                }
            }
        }
    }
    let Some(entry) = entry else {
        return Json::obj(vec![
            ("ok", Json::Bool(false)),
            ("op", Json::str("ztdw")),
            ("note", Json::str(&format!("no sample entry selected (config holds {}; pass --index or --sample)", flat.len()))),
        ]);
    };
    if !str_arg(params, "out").is_empty() {
        return Json::obj(vec![
            ("handled", Json::Bool(false)),
            ("engine", Json::str("js")),
            ("reason", Json::str("staging the extracted samples as WAV needs the JS wav encoder")),
        ]);
    }
    match ztdw::read_ztdw_sample(&source, &entry, None) {
        Ok(got) => {
            let pick = |k: &str| got.get(k).cloned().unwrap_or(Json::Null);
            let num = |k: &str| -> f64 {
                match got.get(k) {
                    Some(Json::Num(n)) => *n,
                    _ => 0.0,
                }
            };
            let observed_peak = num("observedPeak");
            let merge = match entry.get("mergeFile") {
                Some(Json::Str(s)) => s.clone(),
                _ => String::new(),
            };
            Json::obj(vec![
                ("ok", Json::Bool(true)),
                ("op", Json::str("ztdw")),
                ("merge", Json::str(&merge)),
                ("source", pick("source")),
                ("start", entry.get("start").cloned().unwrap_or(Json::Null)),
                ("base", pick("base")),
                ("frames", pick("frames")),
                ("channels", pick("channels")),
                ("bitDepth", pick("bitDepth")),
                ("pitch", entry.get("pitch").cloned().unwrap_or(Json::Null)),
                ("rr", entry.get("rr").cloned().unwrap_or(Json::Null)),
                ("declaredPeak", entry.get("maxPeakLin").cloned().unwrap_or(Json::Null)),
                ("observedPeak", Json::num((observed_peak * 1e6).round() / 1e6)),
                ("gainRatio", pick("gainRatio")),
                ("note", Json::str("the sample region was read as int32 PCM (24-bit values); give --out to stage it as WAV")),
            ])
        }
        Err(e) => Json::obj(vec![
            ("ok", Json::Bool(false)),
            ("op", Json::str("ztdw")),
            ("note", Json::str(&e)),
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Json {
        crate::json::parse(s).unwrap()
    }

    #[test]
    fn unwired_ops_answer_handled_false() {
        let r = dispatch("library_audio", "peaks", &parse("{}"));
        assert_eq!(r.get("handled").unwrap().render(), "false");
        assert_eq!(r.get("engine").unwrap().render(), "\"js\"");
    }

    #[test]
    fn kba_read_refuses_a_missing_path() {
        let r = dispatch("library_audio", "kba", &parse(r#"{"path":"Z:/no/such/file.kba"}"#));
        assert_eq!(r.get("ok").unwrap().render(), "false");
    }

    #[test]
    fn kba_write_path_stays_on_js() {
        let r = dispatch("library_audio", "kba", &parse(r#"{"out":"x.kba","source":"x.wav"}"#));
        assert_eq!(r.get("handled").unwrap().render(), "false");
        assert_eq!(r.get("engine").unwrap().render(), "\"js\"");
    }

    #[test]
    fn kbb_refuses_without_a_target() {
        let r = dispatch("library_audio", "kbb", &parse("{}"));
        assert_eq!(r.get("ok").unwrap().render(), "false");
        assert_eq!(r.get("note").unwrap().render(), "\"kbb needs a .kbb path to read, or --out with --source to convert a SoundFont\"");
    }
}
