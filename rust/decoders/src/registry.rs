// The tool-surface registry: which of KID's model-facing tools exist, and which of their ops the
// Rust core has already absorbed. The JS thin shell reads this to route an op either to the Rust
// binary or back to the JS original - the registry is a map, not a claim of completeness: ops the
// Rust side does not list stay on the JS side by default.
//
// The tool list mirrors lib/core.mjs TOOLS (16 entries as of this port); the rust_ops lists name
// only what this crate really implements, each verified by the selfcheck cross-check section.
use crate::json::Json;

pub struct ToolSurface {
    pub name: &'static str,
    pub rust_ops: &'static [&'static str],
}

pub fn tools() -> Vec<ToolSurface> {
    vec![
        ToolSurface { name: "library_record", rust_ops: &[] },
        ToolSurface { name: "library_index", rust_ops: &[] },
        ToolSurface { name: "library_query", rust_ops: &[] },
        ToolSurface { name: "library_detect", rust_ops: &[] },
        ToolSurface { name: "library_sniff", rust_ops: &[] },
        ToolSurface { name: "library_vcs", rust_ops: &[] },
        ToolSurface {
            name: "library_audio",
            rust_ops: &["kbs", "kbw", "kbv", "kbm", "adpcm-encode", "flac-encode"],
        },
        ToolSurface { name: "library_format", rust_ops: &["sf2", "fxp", "lm4"] },
        ToolSurface { name: "library_plugin", rust_ops: &[] },
        ToolSurface { name: "library_sessions", rust_ops: &[] },
        ToolSurface { name: "library_decrypt", rust_ops: &[] },
        ToolSurface { name: "library_export", rust_ops: &[] },
        ToolSurface { name: "library_encoding", rust_ops: &[] },
        ToolSurface { name: "library_adb", rust_ops: &[] },
        ToolSurface { name: "analyze_object", rust_ops: &[] },
        ToolSurface { name: "library_environment", rust_ops: &[] },
    ]
}

pub fn render() -> String {
    let items: Vec<Json> = tools()
        .into_iter()
        .map(|t| {
            let ops: Vec<Json> = t
                .rust_ops
                .iter()
                .map(|op| Json::Obj(vec![("id".into(), Json::str(*op)), ("surface".into(), Json::str("rust"))]))
                .collect();
            Json::Obj(vec![
                ("name".into(), Json::str(t.name)),
                ("rustOps".into(), Json::arr(ops)),
            ])
        })
        .collect();
    Json::Obj(vec![
        ("engine".into(), Json::str("rust-core")),
        ("tools".into(), Json::arr(items)),
    ])
    .render()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lists_all_sixteen_tools() {
        let all = tools();
        assert_eq!(all.len(), 16);
        assert!(all.iter().any(|t| t.name == "library_audio"));
        assert!(all.iter().any(|t| t.name == "library_format"));
        assert!(all.iter().any(|t| t.name == "analyze_object"));
        let audio = all.iter().find(|t| t.name == "library_audio").unwrap();
        assert_eq!(audio.rust_ops.len(), 6);
        let fmt = all.iter().find(|t| t.name == "library_format").unwrap();
        assert_eq!(fmt.rust_ops.len(), 3);
    }
}
