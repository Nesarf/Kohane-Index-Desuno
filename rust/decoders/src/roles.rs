// The plugin role classifier, ported from lib/core.mjs (classifyPluginRole and its two hint
// tables). The JS side runs regexes over the lowercased source name, then over the host's own
// category; this side uses a small hand-written matcher for the subset those tables actually use -
// literal alternation, word boundaries, start and end anchors, and one optional space - which is
// the honest scope: the hints are data, not a general regex engine.
//
// The first match wins, the name table before the category table, and the fallback is "unknown".

const ROLE_HINTS: &[(&str, &str)] = &[
    ("automation", "control"),
    ("compress|limit|maxim|dynamics|transient|rebalance", "effect.dynamics"),
    ("delay|echo|gross ?beat|glitch|stutter", "effect.delay"),
    ("reverb|reeverb|convol", "effect.reverb"),
    ("equal|\\beq\\b|equo|parametric|tonal", "effect.eq"),
    ("filter|philter|formant|wah|low ?end", "effect.filter"),
    ("vocod|pitch|autotune|breath|spectral", "effect.spectral"),
    ("chorus|flang|phas|tremol|vibrato", "effect.modulation"),
    ("dist|overdrive|drive|saturat|crush|soft ?clip|clipper|waveshap|squeeze|hardcore|exciter", "effect.distortion"),
    ("patcher|modular|wrapper|^layer$", "modular"),
    ("meter|loudness|analy|scope|spectrum|spectrogram|stereometer|\\bvu\\b|waveform|visual|dance|video|chroma", "meter"),
    ("^audio clip", "generator.sampler"),
    ("drum|kick|perc|tom\\b|snare|^fpc\\b", "generator.drum"),
    ("sampl|granul|directwave|slice|sfz|soundfont|wavetable", "generator.sampler"),
    ("synth|osc|additive|subtra|\\bfm\\b|organ|piano|keys|bass", "generator.synth"),
    ("editor|record|render|newtone|newtime", "editor"),
    ("control|envelope|formula|\\blfo\\b|surface|mapper|splitter|voltage", "control"),
    ("midi|send|routing|route|\\bbus\\b|\\bout\\b|rewire|server", "utility.routing"),
    ("browser|notebook|utility|tool|manager|scratch|mobile", "utility"),
];

const CATEGORY_HINTS: &[(&str, &str)] = &[
    ("synth", "generator.synth"),
    ("^generators/drum|^drum", "generator.drum"),
    ("sampler", "generator.sampler"),
    ("distortion", "effect.distortion"),
    ("dynamics", "effect.dynamics"),
    ("flanger", "effect.modulation"),
    ("delay", "effect.delay"),
    ("filter", "effect.filter"),
    ("gain", "effect.gain"),
    ("patcher", "modular"),
    ("visual", "meter"),
    ("controller", "control"),
    ("midi", "utility.routing"),
    ("^generators/", "generator.synth"),
];

#[derive(Clone)]
enum Tok {
    Lit(String),
    Boundary,
}

#[derive(Clone)]
struct Alt {
    start_anchor: bool,
    end_anchor: bool,
    tokens: Vec<Tok>,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_boundary(s: &str, pos: usize) -> bool {
    if pos == 0 || pos == s.len() {
        return true;
    }
    let prev = s[..pos].chars().next_back().unwrap();
    let next = s[pos..].chars().next().unwrap();
    is_word_char(prev) != is_word_char(next)
}

/// Compile one alternative. The only meta-syntax is what the tables use: `\b` boundaries, `^` and
/// `$` anchors, and ` ?` for one optional space.
fn compile_alt(raw: &str) -> Alt {
    let mut a = raw;
    let start_anchor = a.starts_with('^');
    if start_anchor {
        a = &a[1..];
    }
    let end_anchor = a.ends_with('$');
    if end_anchor {
        a = &a[..a.len() - 1];
    }
    let mut tokens = Vec::new();
    let mut lit = String::new();
    let chars: Vec<char> = a.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1] == 'b' {
            if !lit.is_empty() {
                tokens.push(Tok::Lit(std::mem::take(&mut lit)));
            }
            tokens.push(Tok::Boundary);
            i += 2;
            continue;
        }
        if chars[i] == '?' {
            // The only use is " ?": the preceding literal space becomes optional by splitting the
            // alternative at compile time, handled by the caller - a bare ? is never emitted.
            i += 1;
            continue;
        }
        lit.push(chars[i]);
        i += 1;
    }
    if !lit.is_empty() {
        tokens.push(Tok::Lit(lit));
    }
    Alt { start_anchor, end_anchor, tokens }
}

/// A hint pattern may contain " ?" alternatives; each expands to two compiled variants.
fn compile_variants(raw: &str) -> Vec<Alt> {
    let mut out = vec![compile_alt(raw)];
    let mut queue = vec![raw.to_string()];
    while let Some(cur) = queue.pop() {
        if let Some(at) = cur.find(" ?") {
            let without = format!("{}{}", &cur[..at], &cur[at + 2..]);
            let with = format!("{}{}", &cur[..at], &cur[at + 1..]);
            out.push(compile_alt(&without));
            out.push(compile_alt(&with));
            queue.push(without);
            queue.push(with);
        }
    }
    out.dedup_by(|a, b| {
        a.start_anchor == b.start_anchor
            && a.end_anchor == b.end_anchor
            && a.tokens.len() == b.tokens.len()
            && a.tokens
                .iter()
                .zip(b.tokens.iter())
                .all(|(x, y)| match (x, y) {
                    (Tok::Lit(l1), Tok::Lit(l2)) => l1 == l2,
                    (Tok::Boundary, Tok::Boundary) => true,
                    _ => false,
                })
    });
    out
}

fn alt_matches(alt: &Alt, s: &str) -> bool {
    let starts: Vec<usize> = if alt.start_anchor { vec![0] } else { (0..=s.len()).collect() };
    for start in starts {
        if start > s.len() {
            break;
        }
        let mut pos = start;
        let mut ok = true;
        for tok in &alt.tokens {
            match tok {
                Tok::Lit(l) => {
                    if s[pos..].starts_with(l) {
                        pos += l.len();
                    } else {
                        ok = false;
                        break;
                    }
                }
                Tok::Boundary => {
                    if !is_boundary(s, pos) {
                        ok = false;
                        break;
                    }
                }
            }
        }
        if ok && (!alt.end_anchor || pos == s.len()) {
            return true;
        }
    }
    false
}

fn hint_matches(pattern: &str, s: &str) -> bool {
    for alt_raw in pattern.split('|') {
        for alt in compile_variants(alt_raw) {
            if alt_matches(&alt, s) {
                return true;
            }
        }
    }
    false
}

pub fn classify_plugin_role(source_name: &str, category: &str) -> String {
    let s = source_name.to_lowercase();
    for (pat, role) in ROLE_HINTS {
        if hint_matches(pat, &s) {
            return (*role).to_string();
        }
    }
    let c = category.to_lowercase();
    for (pat, role) in CATEGORY_HINTS {
        if hint_matches(pat, &c) {
            return (*role).to_string();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_boundaries_keep_parts_apart() {
        assert!(hint_matches("\\beq\\b", "the eq sits here"));
        assert!(!hint_matches("\\beq\\b", "equal power"));
        assert!(hint_matches("\\bfm\\b", "fm synth"));
        assert!(!hint_matches("\\bfm\\b", "fm8 synth"));
        assert!(hint_matches("\\bvu\\b", "a vu meter"));
        assert!(!hint_matches("\\bvu\\b", "vulcan"));
    }

    #[test]
    fn anchors_and_optional_spaces_hold() {
        assert!(hint_matches("^layer$", "layer"));
        assert!(!hint_matches("^layer$", "layer one"));
        assert!(hint_matches("gross ?beat", "gross beat"));
        assert!(hint_matches("gross ?beat", "grossbeat"));
        assert!(hint_matches("low ?end", "lowend theory"));
        assert!(hint_matches("^audio clip", "audio clip x"));
        assert!(!hint_matches("^audio clip", "the audio clip"));
        assert!(hint_matches("^fpc\\b", "fpc drums"));
        assert!(!hint_matches("^fpc\\b", "xfpc"));
    }

    #[test]
    fn the_first_match_wins() {
        assert_eq!(classify_plugin_role("synth1 automation", ""), "control");
        assert_eq!(classify_plugin_role("great compressor", ""), "effect.dynamics");
        assert_eq!(classify_plugin_role("syl1", ""), "unknown");
        assert_eq!(classify_plugin_role("", "generators/synth/engine"), "generator.synth");
        assert_eq!(classify_plugin_role("", "drum"), "generator.drum");
        assert_eq!(classify_plugin_role("anything", ""), "unknown");
    }
}
