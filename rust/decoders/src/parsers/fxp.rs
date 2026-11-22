// FL preset chunks (.fxp/.fxb), order-identical with the JS original (deps/decoders/fxp.mjs):
// the CcnK envelope, the FPCh/FBCh chunk, the plugin id, the NUL-terminated preset name and the
// parameter body's offset and size.
use crate::json::Json;
use std::fs;

pub struct Fpch {
    pub kind: &'static str,
    pub plugin: String,
    pub name: String,
    pub body_at: usize,
    pub body_bytes: usize,
    pub file_bytes: usize,
}

impl Fpch {
    pub fn to_json(&self) -> Json {
        Json::obj(vec![
            ("container", Json::str("fxp")),
            ("kind", Json::str(self.kind)),
            ("plugin", Json::str(self.plugin.clone())),
            ("name", Json::str(self.name.clone())),
            ("bodyAt", Json::int(self.body_at as i64)),
            ("bodyBytes", Json::int(self.body_bytes as i64)),
            ("fileBytes", Json::int(self.file_bytes as i64)),
        ])
    }
}

pub fn parse_fpch(buf: &[u8]) -> Result<Fpch, String> {
    if buf.len() < 28 || &buf[0..4] != b"CcnK" {
        return Err("not a FL preset (no CcnK envelope)".into());
    }
    let kind = String::from_utf8_lossy(&buf[8..12]).to_string();
    if kind != "FPCh" && kind != "FBCh" {
        return Err(format!("not a FL preset (no FPCh/FBCh chunk, saw {kind})"));
    }
    let envelope_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let plugin = String::from_utf8_lossy(&buf[16..20]).to_string();
    let mut name_end = 28usize;
    while name_end < buf.len() && name_end < 28 + 512 && buf[name_end] != 0 {
        name_end += 1;
    }
    let name = String::from_utf8_lossy(&buf[28..name_end]).to_string();
    let body_at = name_end + 1;
    let body_end = (envelope_size + 8).min(buf.len());
    let body_bytes = body_end.saturating_sub(body_at);
    Ok(Fpch {
        kind: if kind == "FBCh" { "bank" } else { "preset" },
        plugin,
        name,
        body_at,
        body_bytes,
        file_bytes: buf.len(),
    })
}

pub fn read_fxp(file: &str) -> Result<Fpch, String> {
    let buf = fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    parse_fpch(&buf)
}
