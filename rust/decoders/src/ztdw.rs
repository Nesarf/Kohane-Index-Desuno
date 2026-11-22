// The .ztdw sample container, read natively (deps/decoders/ztdw.mjs). The config is a note, one
// padding byte of slack, a zlib stream and an XML directory; the reader probes the two neighbour
// offsets instead of guessing the pad. The merge file's data base is probed the same honest way:
// walk 4 KB blocks from the smallest recorded start until one is genuinely dense. PCM is read at
// the declared bit depth with 24-bit values sign-extended, and the receipt reports the observed
// peak, the declared peak and the gain ratio between them.
use crate::json::Json;
use crate::md5;
use crate::zlib;
use std::fs;

const NOTE: &str = "do not crack pls.";

fn find_attr<'a>(line: &'a str, attr: &str) -> Option<&'a str> {
    let pat = format!("{attr}=\"");
    let at = line.find(&pat)? + pat.len();
    let rest = &line[at..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn parse_attr_num(line: &str, attr: &str) -> Option<f64> {
    find_attr(line, attr).and_then(|v| v.parse().ok())
}

pub fn read_ztdw_config(file: &str) -> Result<Json, String> {
    let buf = fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    read_ztdw_config_bytes(&buf)
}

pub fn read_ztdw_config_bytes(buf: &[u8]) -> Result<Json, String> {
    let note_bytes = NOTE.as_bytes();
    let mut base = None;
    for i in 0..buf.len().saturating_sub(note_bytes.len() - 1) {
        if buf[i..].starts_with(note_bytes) {
            base = Some(i);
            break;
        }
    }
    let Some(base) = base else {
        return Err("not a ztdw config (the container's note is missing)".into());
    };
    let at = base + note_bytes.len();
    let mut xml: Option<String> = None;
    let mut pad = -1i64;
    for start in [at, at + 1, at + 2] {
        if start >= buf.len() {
            break;
        }
        if let Ok(text) = zlib::inflate_zlib(&buf[start..]) {
            if let Ok(s) = String::from_utf8(text) {
                xml = Some(s);
                pad = (start - at) as i64;
                break;
            }
        }
    }
    let Some(xml) = xml else {
        return Err("the ztdw directory does not inflate at any expected start".into());
    };

    let mut raw_source_dir: Option<String> = None;
    if let Some(at) = xml.find("raw_source_dir_name=\"") {
        let rest = &xml[at + "raw_source_dir_name=\"".len()..];
        if let Some(end) = rest.find('"') {
            raw_source_dir = Some(rest[..end].to_string());
        }
    }
    let mut merge_files: Vec<Json> = Vec::new();
    let mut current: Option<usize> = None;
    for line in xml.split(['\r', '\n']) {
        if let Some(name) = find_attr(line, "<merge_file name") {
            let idx = merge_files.len();
            merge_files.push(Json::obj(vec![
                ("name", Json::str(name)),
                ("sources", Json::arr(Vec::new())),
            ]));
            current = Some(idx);
            continue;
        }
        let Some(name) = find_attr(line, "<src_file name") else {
            continue;
        };
        let Some(idx) = current else { continue };
        let start = parse_attr_num(line, "startInBigFile");
        let length = parse_attr_num(line, "length");
        let channels = parse_attr_num(line, "channelNum");
        let bit_depth = parse_attr_num(line, "bitDepth");
        let peak = parse_attr_num(line, "maxPeakLin");
        let (Some(start), Some(length), Some(channels), Some(bit_depth), Some(peak)) =
            (start, length, channels, bit_depth, peak)
        else {
            continue;
        };
        let pitch = find_pitch(name).map(|v| v as f64);
        let rr = find_rr(name).map(|v| v as f64);
        let source = Json::obj(vec![
            ("name", Json::str(name)),
            ("start", Json::int(start as i64)),
            ("length", Json::int(length as i64)),
            ("channels", Json::int(channels as i64)),
            ("bitDepth", Json::int(bit_depth as i64)),
            ("maxPeakLin", Json::num(peak)),
            ("pitch", pitch.map(Json::num).unwrap_or(Json::Null)),
            ("rr", rr.map(Json::num).unwrap_or(Json::Null)),
        ]);
        match &mut merge_files[idx] {
            Json::Obj(fields) => {
                for (k, v) in fields.iter_mut() {
                    if k == "sources" {
                        if let Json::Arr(items) = v {
                            items.push(source.clone());
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    let mut sources = 0usize;
    let mut pitch_set: Vec<Option<f64>> = Vec::new();
    for m in &merge_files {
        if let Some(Json::Arr(items)) = m.get("sources") {
            sources += items.len();
            for s in items {
                let p = match s.get("pitch") {
                    Some(Json::Num(n)) => Some(*n),
                    _ => None,
                };
                if !pitch_set.contains(&p) {
                    pitch_set.push(p);
                }
            }
        }
    }
    // The JS side keeps null in the set and sorts numerically, null comparing as zero.
    pitch_set.sort_by(|a, b| a.unwrap_or(0.0).partial_cmp(&b.unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal));

    let merge_count = merge_files.len();
    Ok(Json::obj(vec![
        ("container", Json::str("ztdw-config")),
        ("rawSourceDir", raw_source_dir.map(Json::str).unwrap_or(Json::Null)),
        ("pad", Json::int(pad)),
        ("mergeFiles", Json::arr(merge_files)),
        ("sources", Json::int(sources as i64)),
        ("pitches", Json::arr(pitch_set.into_iter().map(|p| p.map(Json::num).unwrap_or(Json::Null)).collect())),
        ("summary", Json::obj(vec![
            ("mergeFiles", Json::int(merge_count as i64)),
            ("sources", Json::int(sources as i64)),
            ("note", Json::str("the directory carries each sample's start, length, channels, bit depth, peak, pitch offset and round-robin number")),
        ])),
    ]))
}

fn find_pitch(name: &str) -> Option<i64> {
    let at = name.find("pitch_")? + "pitch_".len();
    let rest = &name[at..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.len() == 3 {
        digits.parse().ok()
    } else {
        None
    }
}

fn find_rr(name: &str) -> Option<i64> {
    let at = name.find("rr_")? + "rr_".len();
    let rest = &name[at..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// Walk 4 KB blocks from the smallest recorded start until one is genuinely dense (more than half
/// its bytes non-zero); that block's start is the data base. The JS side caches per merge file;
/// a single call probes once, so the two agree.
fn locate_base(handle: &mut fs::File, min_start: usize, file_size: u64) -> usize {
    let chunk = 4096usize;
    let mut buf = vec![0u8; chunk];
    use std::io::{Read, Seek, SeekFrom};
    let mut off = min_start;
    while (off as u64) + (chunk as u64) <= file_size {
        if handle.seek(SeekFrom::Start(off as u64)).is_err() {
            break;
        }
        let n = handle.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        let nz = buf[..n].iter().filter(|&&b| b != 0).count();
        if nz > n / 2 {
            return off;
        }
        off += chunk;
    }
    0
}

pub fn read_ztdw_sample(merge_file: &str, source: &Json, base_override: Option<usize>) -> Result<Json, String> {
    let name = match source.get("name") {
        Some(Json::Str(s)) => s.clone(),
        _ => return Err("a ztdw source needs a name".into()),
    };
    let start = num_of(source, "start") as usize;
    let length = num_of(source, "length") as usize;
    let channels = num_of(source, "channels") as usize;
    let bit_depth = num_of(source, "bitDepth") as usize;
    let declared_peak = match source.get("maxPeakLin") {
        Some(Json::Num(n)) => *n,
        _ => 0.0,
    };
    let bytes_per_sample = bit_depth.div_ceil(8);
    let bytes = length;
    let fd = fs::File::open(merge_file).map_err(|e| format!("cannot read {merge_file}: {e}"))?;
    let file_size = fd.metadata().map_err(|e| format!("cannot stat {merge_file}: {e}"))?.len();
    use std::io::{Read, Seek, SeekFrom};
    let mut handle = fd;
    let base = match base_override {
        Some(b) => b,
        None => locate_base(&mut handle, start.min(1 << 20), file_size),
    };
    let mut buf = vec![0u8; bytes];
    let mut read = 0usize;
    while read < bytes {
        if handle.seek(SeekFrom::Start((start + base + read) as u64)).is_err() {
            break;
        }
        let n = handle.read(&mut buf[read..]).unwrap_or(0);
        if n == 0 {
            break;
        }
        read += n;
    }
    let samples_count = read / bytes_per_sample;
    let mut samples: Vec<i32> = Vec::with_capacity(samples_count);
    for i in 0..samples_count {
        let at = i * bytes_per_sample;
        let v = if bytes_per_sample == 3 {
            let mut v = buf[at] as u32 | ((buf[at + 1] as u32) << 8) | ((buf[at + 2] as u32) << 16);
            if v & 0x800000 != 0 {
                v = v.wrapping_sub(0x1000000);
            }
            v as i32
        } else if bytes_per_sample == 2 {
            i16::from_le_bytes([buf[at], buf[at + 1]]) as i32
        } else {
            i32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
        };
        samples.push(v);
    }
    let observed_peak = if samples.is_empty() {
        0.0
    } else {
        samples.iter().map(|x| x.unsigned_abs() as f64).fold(0.0f64, f64::max) / (2f64.powi(bit_depth as i32 - 1))
    };
    let gain_ratio = if observed_peak > 0.0 {
        Some(((declared_peak / observed_peak) * 1e6 + 0.5).floor() / 1e6)
    } else {
        None
    };
    let mut pcm_bytes = Vec::with_capacity(samples.len() * 4);
    for s in &samples {
        pcm_bytes.extend_from_slice(&s.to_le_bytes());
    }
    let digest = {
        let d = md5::Md5::digest(&pcm_bytes);
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    Ok(Json::obj(vec![
        ("container", Json::str("ztdw-merge")),
        ("source", Json::str(&name)),
        ("frames", Json::int((samples_count / channels.max(1)) as i64)),
        ("channels", Json::int(channels as i64)),
        ("bitDepth", Json::int(bit_depth as i64)),
        ("samplesMd5", Json::str(&digest)),
        ("samplesCount", Json::int(samples_count as i64)),
        ("base", Json::int(base as i64)),
        ("observedPeak", Json::num(observed_peak)),
        ("declaredPeak", Json::num(declared_peak)),
        ("gainRatio", gain_ratio.map(Json::num).unwrap_or(Json::Null)),
        ("note", Json::str("PCM at the declared bit depth, read at the probed data base; the stored samples are normalised, and the declared peak is the pre-normalisation gain")),
    ]))
}

fn num_of(j: &Json, key: &str) -> f64 {
    match j.get(key) {
        Some(Json::Num(n)) => *n,
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pitch_and_rr_parse_from_names() {
        assert_eq!(find_pitch("some_pitch_012_thing"), Some(12));
        assert_eq!(find_pitch("no_pitch_here"), None);
        assert_eq!(find_pitch("pitch_12"), None);
        assert_eq!(find_rr("blah_rr_3.wav"), Some(3));
        assert_eq!(find_rr("blah_rr_.wav"), None);
    }

    #[test]
    fn config_refuses_without_the_note() {
        let e = read_ztdw_config_bytes(b"nothing here").unwrap_err();
        assert_eq!(e, "not a ztdw config (the container's note is missing)");
    }

    #[test]
    fn config_refuses_when_nothing_inflates() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"do not crack pls.");
        buf.extend_from_slice(b"not a zlib stream at all");
        let e = read_ztdw_config_bytes(&buf).unwrap_err();
        assert_eq!(e, "the ztdw directory does not inflate at any expected start");
    }
}
