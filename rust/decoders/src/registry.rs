// The tool-surface registry: which of KID's model-facing tools exist, which ops the Rust core has
// absorbed, and which of those the exec dispatch has actually wired. The JS thin shell reads this
// to route an op: a wired op runs in Rust, an absorbed-but-unwired op can run in Rust through the
// subcommands, and everything else stays on the JS side by default. The registry is a map, not a
// claim of completeness.
//
// The tool list mirrors lib/core.mjs TOOLS (16 entries as of this port); the rust_ops lists name
// only what this crate really implements, each verified by the selfcheck cross-check section; the
// dispatched lists name what `kohane-decoder op <tool> <op>` answers in place of the JS original.
use crate::json::Json;

pub struct ToolSurface {
    pub name: &'static str,
    pub rust_ops: &'static [&'static str],
    pub dispatched: &'static [&'static str],
}

pub fn tools() -> Vec<ToolSurface> {
    vec![
        ToolSurface { name: "library_record", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_index", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_query", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_detect", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_sniff", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_vcs", rust_ops: &[], dispatched: &[] },
        ToolSurface {
            name: "library_audio",
            rust_ops: &["kbs", "kbw", "kbv", "kbm", "adpcm-encode", "flac-encode", "kba", "kbb", "kbi", "ztdw", "mix"],
            dispatched: &["kba", "kbb", "ztdw"],
        },
        ToolSurface { name: "library_format", rust_ops: &["sf2", "fxp", "lm4"], dispatched: &[] },
        ToolSurface { name: "library_plugin", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_sessions", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_decrypt", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_export", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_encoding", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_adb", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "analyze_object", rust_ops: &[], dispatched: &[] },
        ToolSurface { name: "library_environment", rust_ops: &[], dispatched: &[] },
    ]
}

pub fn render() -> String {
    let items: Vec<Json> = tools()
        .into_iter()
        .map(|t| {
            let ops: Vec<Json> = t
                .rust_ops
                .iter()
                .map(|op| {
                    Json::Obj(vec![
                        ("id".into(), Json::str(*op)),
                        ("surface".into(), Json::str(if t.dispatched.contains(op) { "rust" } else { "rust-subcommand" })),
                    ])
                })
                .collect();
            Json::Obj(vec![
                ("name".into(), Json::str(t.name)),
                ("rustOps".into(), Json::arr(ops)),
                ("dispatched".into(), Json::arr(t.dispatched.iter().map(|op| Json::str(*op)).collect())),
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
        assert_eq!(audio.rust_ops.len(), 11);
        assert_eq!(audio.dispatched.len(), 3);
        let fmt = all.iter().find(|t| t.name == "library_format").unwrap();
        assert_eq!(fmt.rust_ops.len(), 3);
    }

    #[test]
    fn dispatched_ops_are_absorbed_ops() {
        for t in tools() {
            for op in t.dispatched {
                assert!(t.rust_ops.contains(op), "{} dispatches {} but has not absorbed it", t.name, op);
            }
        }
    }
}
