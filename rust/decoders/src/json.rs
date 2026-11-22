// A minimal JSON writer and reader, so the parsers' receipts stay dependency-free.
//
// The Rust side answers in JSON for the cross-check to read; only output is needed (the CLI takes
// plain argv), and the vocabulary is small - numbers, strings, bools, arrays, objects. Floats are
// written with JS's NumberToString semantics so a receipt and a container byte-match what the JS
// side's JSON.stringify produces (the kb family is JSON documents, so byte-exactness is judged on
// the serialisation, not only on parsed values).
//
// The reader exists because the kb containers (kbs/kbw/kbv/kbm) are themselves JSON envelopes:
// reading them in Rust needs a strict parser, and a container that is not the container must fail
// with the container's own name, never a vague parse error.
#[derive(Clone, Debug)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }
    pub fn num(n: f64) -> Json {
        Json::Num(n)
    }
    pub fn int(n: i64) -> Json {
        Json::Num(n as f64)
    }
    pub fn arr(items: Vec<Json>) -> Json {
        Json::Arr(items)
    }
    pub fn obj(items: Vec<(&str, Json)>) -> Json {
        Json::Obj(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn opt_str(s: Option<String>) -> Json {
        match s {
            Some(v) => Json::Str(v),
            None => Json::Null,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(&js_number(*n)),
            Json::Str(s) => write_string(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Obj(pairs) => {
                out.push('{');
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// JS NumberToString (the shortest round-tripping decimal, then ECMA-262 7.1.12.1 formatting):
// exponential notation when the decimal exponent is >= 21 or <= -7, plain notation otherwise,
// "-0" renders as "0" and NaN/Infinity render as null (JSON.stringify semantics).
fn js_number(n: f64) -> String {
    if n == 0.0 {
        return "0".into();
    }
    if !n.is_finite() {
        return "null".into();
    }
    // Rust's {:e} on a float with no precision is the shortest round-trip mantissa (same goal as
    // JS), e.g. 44100 -> "4.41e4", 1.5 -> "1.5e0". Normalise from that.
    let s = format!("{:e}", n);
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.as_str()),
    };
    let (m, e) = rest.split_once('e').expect("float exponent form");
    let exp: i64 = e.parse().expect("float exponent");
    let (ip, frac) = match m.split_once('.') {
        Some((a, b)) => (a, b),
        None => (m, ""),
    };
    let digits = format!("{ip}{frac}");
    let sign = if neg { "-" } else { "" };
    let frac_len = frac.len() as i64;
    if exp >= 21 || exp <= -7 {
        // JS exponential notation always carries the exponent sign ("1e+21", "1.5e-7").
        if exp >= 0 {
            format!("{sign}{m}e+{exp}")
        } else {
            format!("{sign}{m}e{exp}")
        }
    } else {
        // Plain notation: digits * 10^(exp - frac_len) written positionally.
        let decimal_places = frac_len - exp;
        if decimal_places > 0 {
            let dp = decimal_places as usize;
            if dp >= digits.len() {
                format!("{sign}0.{}{}", "0".repeat(dp - digits.len()), digits)
            } else {
                let split = digits.len() - dp;
                format!("{sign}{}.{}", &digits[..split], &digits[split..])
            }
        } else {
            format!("{sign}{}{}", digits, "0".repeat((-decimal_places) as usize))
        }
    }
}

// ---------------------------------------------------------------- reader

pub fn parse(text: &str) -> Result<Json, String> {
    let b = text.as_bytes();
    let mut i = 0usize;
    skip_ws(b, &mut i);
    let v = parse_value(text, b, &mut i)?;
    skip_ws(b, &mut i);
    if i != b.len() {
        return Err(format!("json parse error at byte {i}: trailing content"));
    }
    Ok(v)
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n' | b'\r') {
        *i += 1;
    }
}

fn parse_value(text: &str, b: &[u8], i: &mut usize) -> Result<Json, String> {
    skip_ws(b, i);
    match b.get(*i) {
        Some(b'{') => parse_object(text, b, i),
        Some(b'[') => parse_array(text, b, i),
        Some(b'"') => Ok(Json::Str(parse_string(text, b, i)?)),
        Some(b't') => {
            expect_word(b, i, "true")?;
            Ok(Json::Bool(true))
        }
        Some(b'f') => {
            expect_word(b, i, "false")?;
            Ok(Json::Bool(false))
        }
        Some(b'n') => {
            expect_word(b, i, "null")?;
            Ok(Json::Null)
        }
        Some(c) if *c == b'-' || c.is_ascii_digit() => parse_number(text, b, i),
        _ => Err(format!("json parse error at byte {}: expected a value", *i)),
    }
}

fn expect_word(b: &[u8], i: &mut usize, word: &str) -> Result<(), String> {
    if b.len() >= *i + word.len() && &b[*i..*i + word.len()] == word.as_bytes() {
        *i += word.len();
        Ok(())
    } else {
        Err(format!("json parse error at byte {}: expected {word}", *i))
    }
}

fn parse_object(text: &str, b: &[u8], i: &mut usize) -> Result<Json, String> {
    *i += 1; // {
    let mut pairs: Vec<(String, Json)> = Vec::new();
    skip_ws(b, i);
    if b.get(*i) == Some(&b'}') {
        *i += 1;
        return Ok(Json::Obj(pairs));
    }
    loop {
        skip_ws(b, i);
        if b.get(*i) != Some(&b'"') {
            return Err(format!("json parse error at byte {}: expected a string key", *i));
        }
        let key = parse_string(text, b, i)?;
        skip_ws(b, i);
        if b.get(*i) != Some(&b':') {
            return Err(format!("json parse error at byte {}: expected ':'", *i));
        }
        *i += 1;
        let value = parse_value(text, b, i)?;
        // JSON.parse keeps the last of duplicate keys; drop the earlier one.
        if let Some(pos) = pairs.iter().position(|(k, _)| k == &key) {
            pairs.remove(pos);
        }
        pairs.push((key, value));
        skip_ws(b, i);
        match b.get(*i) {
            Some(b',') => {
                *i += 1;
            }
            Some(b'}') => {
                *i += 1;
                return Ok(Json::Obj(pairs));
            }
            _ => return Err(format!("json parse error at byte {}: expected ',' or '}}'", *i)),
        }
    }
}

fn parse_array(text: &str, b: &[u8], i: &mut usize) -> Result<Json, String> {
    *i += 1; // [
    let mut items: Vec<Json> = Vec::new();
    skip_ws(b, i);
    if b.get(*i) == Some(&b']') {
        *i += 1;
        return Ok(Json::Arr(items));
    }
    loop {
        let value = parse_value(text, b, i)?;
        items.push(value);
        skip_ws(b, i);
        match b.get(*i) {
            Some(b',') => {
                *i += 1;
            }
            Some(b']') => {
                *i += 1;
                return Ok(Json::Arr(items));
            }
            _ => return Err(format!("json parse error at byte {}: expected ',' or ']'", *i)),
        }
    }
}

fn parse_string(text: &str, b: &[u8], i: &mut usize) -> Result<String, String> {
    *i += 1; // "
    let mut out = String::new();
    loop {
        match b.get(*i) {
            None => return Err(format!("json parse error at byte {}: unterminated string", *i)),
            Some(b'"') => {
                *i += 1;
                return Ok(out);
            }
            Some(b'\\') => {
                *i += 1;
                match b.get(*i) {
                    Some(b'"') => {
                        out.push('"');
                        *i += 1;
                    }
                    Some(b'\\') => {
                        out.push('\\');
                        *i += 1;
                    }
                    Some(b'/') => {
                        out.push('/');
                        *i += 1;
                    }
                    Some(b'b') => {
                        out.push('\u{0008}');
                        *i += 1;
                    }
                    Some(b'f') => {
                        out.push('\u{000c}');
                        *i += 1;
                    }
                    Some(b'n') => {
                        out.push('\n');
                        *i += 1;
                    }
                    Some(b'r') => {
                        out.push('\r');
                        *i += 1;
                    }
                    Some(b't') => {
                        out.push('\t');
                        *i += 1;
                    }
                    Some(b'u') => {
                        *i += 1;
                        let hi = hex4(b, i)?;
                        if (0xd800..=0xdbff).contains(&hi) {
                            // surrogate pair: must be followed by \uDC00-\uDFFF
                            if b.get(*i) == Some(&b'\\') && b.get(*i + 1) == Some(&b'u') {
                                *i += 2;
                                let lo = hex4(b, i)?;
                                if !(0xdc00..=0xdfff).contains(&lo) {
                                    return Err(format!(
                                        "json parse error at byte {}: bad surrogate pair",
                                        *i
                                    ));
                                }
                                let cp = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
                                out.push(char::from_u32(cp).unwrap());
                            } else {
                                return Err(format!(
                                    "json parse error at byte {}: lone high surrogate",
                                    *i
                                ));
                            }
                        } else if let Some(c) = char::from_u32(hi) {
                            out.push(c);
                        } else {
                            return Err(format!(
                                "json parse error at byte {}: bad escape",
                                *i
                            ));
                        }
                    }
                    _ => return Err(format!("json parse error at byte {}: bad escape", *i)),
                }
            }
            Some(_) => {
                // copy one UTF-8 char; the bytes slice is known-UTF-8 because text is a &str
                let ch = text[*i..].chars().next().unwrap();
                out.push(ch);
                *i += ch.len_utf8();
            }
        }
    }
}

fn hex4(b: &[u8], i: &mut usize) -> Result<u32, String> {
    if *i + 4 > b.len() {
        return Err(format!("json parse error at byte {}: bad \\u escape", *i));
    }
    let mut v = 0u32;
    for k in 0..4 {
        let c = b[*i + k];
        let d = match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'a'..=b'f' => (c - b'a' + 10) as u32,
            b'A'..=b'F' => (c - b'A' + 10) as u32,
            _ => return Err(format!("json parse error at byte {}: bad \\u escape", *i)),
        };
        v = v * 16 + d;
    }
    *i += 4;
    Ok(v)
}

fn parse_number(text: &str, b: &[u8], i: &mut usize) -> Result<Json, String> {
    let start = *i;
    if b.get(*i) == Some(&b'-') {
        *i += 1;
    }
    match b.get(*i) {
        Some(b'0') => *i += 1,
        Some(c) if c.is_ascii_digit() => {
            while b.get(*i).is_some_and(|c| c.is_ascii_digit()) {
                *i += 1;
            }
        }
        _ => return Err(format!("json parse error at byte {}: bad number", start)),
    }
    if b.get(*i) == Some(&b'.') {
        *i += 1;
        if !b.get(*i).is_some_and(|c| c.is_ascii_digit()) {
            return Err(format!("json parse error at byte {}: bad number", start));
        }
        while b.get(*i).is_some_and(|c| c.is_ascii_digit()) {
            *i += 1;
        }
    }
    if matches!(b.get(*i), Some(b'e') | Some(b'E')) {
        *i += 1;
        if matches!(b.get(*i), Some(b'+') | Some(b'-')) {
            *i += 1;
        }
        if !b.get(*i).is_some_and(|c| c.is_ascii_digit()) {
            return Err(format!("json parse error at byte {}: bad number", start));
        }
        while b.get(*i).is_some_and(|c| c.is_ascii_digit()) {
            *i += 1;
        }
    }
    let slice = &text[start..*i];
    match slice.parse::<f64>() {
        Ok(n) => Ok(Json::Num(n)),
        Err(_) => Err(format!("json parse error at byte {start}: bad number")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Json {
        parse(s).unwrap()
    }

    #[test]
    fn parses_scalars_and_nesting() {
        assert!(matches!(p("null"), Json::Null));
        assert!(matches!(p("true"), Json::Bool(true)));
        assert!(matches!(p("false"), Json::Bool(false)));
        assert!(matches!(p("12"), Json::Num(n) if n == 12.0));
        assert!(matches!(p("-0.5"), Json::Num(n) if n == -0.5));
        assert!(matches!(p("1.5e3"), Json::Num(n) if n == 1500.0));
        assert!(matches!(p("2E-2"), Json::Num(n) if n == 0.02));
        assert!(matches!(p("\"a\\nb\""), Json::Str(s) if s == "a\nb"));
        let v = p("{\"a\":[1,{\"b\":\"x\"}]}");
        assert_eq!(v.get("a").unwrap().render(), "[1,{\"b\":\"x\"}]");
        assert!(parse("1 2").is_err());
        assert!(parse("{").is_err());
        assert!(parse("{\"a\":}").is_err());
        assert!(parse("\"unterminated").is_err());
        assert!(parse("01").is_err());
        assert!(parse("{\"a\":1,\"a\":2}").unwrap().get("a").unwrap().render() == "2");
        assert!(parse("\"\\ud83d\\ude00\"").unwrap().render() == "\"\u{1f600}\"");
    }

    #[test]
    fn numbers_serialize_like_js() {
        let js = |n: f64| js_number(n);
        assert_eq!(js(0.0), "0");
        assert_eq!(js(-0.0), "0");
        assert_eq!(js(1.0), "1");
        assert_eq!(js(44100.0), "44100");
        assert_eq!(js(120.5), "120.5");
        assert_eq!(js(0.5), "0.5");
        assert_eq!(js(-1.25), "-1.25");
        assert_eq!(js(0.1), "0.1");
        assert_eq!(js(1e-6), "0.000001");
        assert_eq!(js(1e-7), "1e-7");
        assert_eq!(js(1.5e-7), "1.5e-7");
        assert_eq!(js(1e16), "10000000000000000");
        assert_eq!(js(1.5e16), "15000000000000000");
        assert_eq!(js(1e21), "1e+21");
        assert_eq!(js(-2.5e21), "-2.5e+21");
        assert_eq!(js(f64::NAN), "null");
        assert_eq!(js(f64::INFINITY), "null");
        assert_eq!(js(3.141592653589793), "3.141592653589793");
    }
}
