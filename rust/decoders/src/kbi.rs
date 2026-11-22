// The KBI single-instrument container (deps/decoders/kbi.mjs): one patch, kohane's own words.
// What a patch IS is carried here; whose patch it was is not, so no product name survives the
// conversion. Two preset shapes convert in: the FL FPCh preset (CcnK envelope) and the plain
// four-char plugin id plus binary body (the FabFilter .ffp shape).
use crate::json::Json;
use crate::kbb::base64;
use crate::parsers::fxp::parse_fpch;

fn str_field(j: &Json, key: &str) -> String {
    match j.get(key) {
        Some(Json::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

fn js_round(x: f64) -> i64 {
    (x + 0.5).floor() as i64
}

/// Write the .kbi document. The recipe key is present only when the caller supplies an object,
/// exactly like the JS side's spread of a body whose recipe is undefined.
pub fn write_kbi(instrument: &Json) -> Vec<u8> {
    let name = str_field(instrument, "name");
    let name = if name.is_empty() { "untitled instrument" } else { &name };
    let role = str_field(instrument, "role");
    let role = if role.is_empty() { "unknown" } else { &role };
    let kind = if matches!(instrument.get("kind"), Some(Json::Str(s)) if s == "bank") {
        "bank"
    } else {
        "preset"
    };
    let source = str_field(instrument, "source");
    let source = if source.is_empty() { "preset" } else { &source };
    let params = match instrument.get("params") {
        Some(Json::Str(s)) => s.clone(),
        _ => String::new(),
    };
    let param_bytes = match instrument.get("paramBytes") {
        Some(Json::Num(n)) if n.is_finite() && *n > 0.0 => js_round(*n),
        _ => 0,
    };
    let mut fields: Vec<(&str, Json)> = vec![
        ("format", Json::str("kohane-instrument")),
        ("version", Json::int(1)),
        ("name", Json::str(name)),
        ("kind", Json::str(kind)),
        ("role", Json::str(role)),
        ("source", Json::str(source)),
        ("params", Json::str(&params)),
        ("paramBytes", Json::int(param_bytes)),
    ];
    if matches!(instrument.get("recipe"), Some(Json::Obj(_))) {
        fields.push(("recipe", instrument.get("recipe").unwrap().clone()));
    }
    Json::obj(fields).render().into_bytes()
}

pub fn read_kbi(buf: &[u8]) -> Result<Json, String> {
    let text = match std::str::from_utf8(buf) {
        Ok(s) => s,
        Err(_) => return Err("not a kohane instrument (the bytes are not the container's JSON envelope)".into()),
    };
    let doc = match crate::json::parse(text) {
        Ok(v) => v,
        Err(_) => return Err("not a kohane instrument (the bytes are not the container's JSON envelope)".into()),
    };
    match doc.get("format") {
        Some(Json::Str(f)) if f == "kohane-instrument" => {}
        _ => return Err("not a kohane instrument (missing the kohane-instrument marker)".into()),
    }
    match doc.get("version") {
        Some(Json::Num(v)) if *v == 1.0 => {}
        _ => {
            return Err(format!(
                "not a kohane instrument (unknown version {})",
                doc.get("version").map(|v| v.render()).unwrap_or_else(|| "undefined".into())
            ))
        }
    }
    let name = match doc.get("name") {
        Some(Json::Str(s)) if !s.is_empty() => s.clone(),
        _ => return Err("not a kohane instrument (no name)".into()),
    };
    let params = match doc.get("params") {
        Some(Json::Str(s)) => s.clone(),
        _ => return Err("not a kohane instrument (params is not a payload)".into()),
    };
    let kind = if matches!(doc.get("kind"), Some(Json::Str(s)) if s == "bank") { "bank" } else { "preset" };
    let role = str_field(&doc, "role");
    let role = if role.is_empty() { "unknown" } else { &role };
    let source = str_field(&doc, "source");
    let source = if source.is_empty() { "preset" } else { &source };
    let param_bytes = match doc.get("paramBytes") {
        Some(Json::Num(n)) if n.is_finite() => *n,
        _ => 0.0,
    };
    let mut fields: Vec<(&str, Json)> = vec![
        ("format", Json::str("kohane-instrument")),
        ("version", Json::int(1)),
        ("name", Json::str(&name)),
        ("kind", Json::str(kind)),
        ("role", Json::str(role)),
        ("source", Json::str(source)),
        ("params", Json::str(&params)),
        ("paramBytes", Json::num(param_bytes)),
    ];
    if matches!(doc.get("recipe"), Some(Json::Obj(_))) {
        fields.push(("recipe", doc.get("recipe").unwrap().clone()));
    }
    Ok(Json::obj(fields))
}

/// Convert one preset file's bytes into a .kbi document. `name` overrides the file's own.
pub fn convert_preset_to_kbi(bytes: &[u8], name: Option<&str>, role: &str) -> Result<Json, String> {
    if bytes.len() >= 4 && &bytes[0..4] == b"CcnK" {
        let p = parse_fpch(bytes)?;
        let params = base64(&bytes[p.body_at..p.body_at + p.body_bytes]);
        let fallback = "untitled instrument";
        let doc_name = match name {
            Some(n) if !n.is_empty() => n,
            _ => {
                if p.name.is_empty() {
                    fallback
                } else {
                    &p.name
                }
            }
        };
        return Ok(Json::obj(vec![
            ("format", Json::str("kohane-instrument")),
            ("version", Json::int(1)),
            ("name", Json::str(doc_name)),
            ("kind", Json::str(p.kind)),
            ("role", Json::str(role)),
            ("source", Json::str(if p.kind == "bank" { "fxb" } else { "fxp" })),
            ("params", Json::str(&params)),
            ("paramBytes", Json::int(p.body_bytes as i64)),
        ]));
    }
    if bytes.len() < 5 {
        return Err("not a preset file (too short)".into());
    }
    let id = std::str::from_utf8(&bytes[0..4]).map_err(|_| "not a preset file (no four-character id)".to_string())?;
    let printable = id.chars().all(|c| ('\x20'..='\x7e').contains(&c));
    if !printable {
        return Err("not a preset file (no four-character id)".into());
    }
    let fallback = "untitled instrument";
    let doc_name = match name {
        Some(n) if !n.is_empty() => n,
        _ => fallback,
    };
    Ok(Json::obj(vec![
        ("format", Json::str("kohane-instrument")),
        ("version", Json::int(1)),
        ("name", Json::str(doc_name)),
        ("kind", Json::str("preset")),
        ("role", Json::str(role)),
        ("source", Json::str("ffp")),
        ("params", Json::str(&base64(&bytes[4..]))),
        ("paramBytes", Json::int((bytes.len() - 4) as i64)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Json {
        crate::json::parse(s).unwrap()
    }

    #[test]
    fn write_round_trips_through_read() {
        let doc = parse(r#"{"name":"saw lead","kind":"preset","role":"lead","params":"AAAA","paramBytes":3}"#);
        let bytes = write_kbi(&doc);
        let back = read_kbi(&bytes).unwrap();
        assert_eq!(back.get("name").unwrap().render(), "\"saw lead\"");
        assert_eq!(back.get("role").unwrap().render(), "\"lead\"");
        assert_eq!(back.get("paramBytes").unwrap().render(), "3");
    }

    #[test]
    fn recipe_appears_only_when_given() {
        let no_recipe = parse(r#"{"name":"x","params":""}"#);
        let bytes = write_kbi(&no_recipe);
        assert!(!String::from_utf8_lossy(&bytes).contains("recipe"));
        let with_recipe = parse(r#"{"name":"x","params":"","recipe":{"a":1}}"#);
        let bytes = write_kbi(&with_recipe);
        assert!(String::from_utf8_lossy(&bytes).contains("\"recipe\":{\"a\":1}"));
    }

    #[test]
    fn read_refuses_with_the_js_sentences() {
        let e = read_kbi(b"nope").unwrap_err();
        assert_eq!(e, "not a kohane instrument (the bytes are not the container's JSON envelope)");
        let e = read_kbi(br#"{"format":"nope"}"#).unwrap_err();
        assert_eq!(e, "not a kohane instrument (missing the kohane-instrument marker)");
        let e = read_kbi(br#"{"format":"kohane-instrument","version":9}"#).unwrap_err();
        assert_eq!(e, "not a kohane instrument (unknown version 9)");
        let e = read_kbi(br#"{"format":"kohane-instrument","version":1}"#).unwrap_err();
        assert_eq!(e, "not a kohane instrument (no name)");
        let e = read_kbi(br#"{"format":"kohane-instrument","version":1,"name":"x"}"#).unwrap_err();
        assert_eq!(e, "not a kohane instrument (params is not a payload)");
    }

    #[test]
    fn four_char_shape_converts_with_the_ffp_source() {
        let mut bytes = b"FfFp".to_vec();
        bytes.extend_from_slice(&[1, 2, 3, 4, 5]);
        let doc = convert_preset_to_kbi(&bytes, Some("my patch"), "fx").unwrap();
        assert_eq!(doc.get("name").unwrap().render(), "\"my patch\"");
        assert_eq!(doc.get("source").unwrap().render(), "\"ffp\"");
        assert_eq!(doc.get("paramBytes").unwrap().render(), "5");
        assert_eq!(doc.get("params").unwrap().render(), "\"AQIDBAU=\"");
    }

    #[test]
    fn bad_shapes_refuse() {
        let e = convert_preset_to_kbi(b"abc", None, "unknown").unwrap_err();
        assert_eq!(e, "not a preset file (too short)");
        let e = convert_preset_to_kbi(b"\x00\x01\x02\x03\x04", None, "unknown").unwrap_err();
        assert_eq!(e, "not a preset file (no four-character id)");
    }
}
