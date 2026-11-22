// The byte-exact cross-check against the JS original: the fixture was produced by
// deps/decoders/kba.mjs from the same PCM, so a differing byte here means the port drifted.
use std::fs;

fn kba_header(tier: u8, sample_rate: u32, channels: u16, frames: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(16);
    h.extend_from_slice(b"KBA1");
    h.push(1);
    h.push(tier);
    h.extend_from_slice(&sample_rate.to_le_bytes());
    h.extend_from_slice(&channels.to_le_bytes());
    h.extend_from_slice(&frames.to_le_bytes());
    h
}

#[test]
fn adpcm_matches_the_js_reference_byte_for_byte() {
    let raw = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/adpcm-pcm.raw"
    ))
    .unwrap();
    let pcm: Vec<i16> = raw
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();
    let frames = pcm.len() as u32;
    let body = kohane_decoder::adpcm::adpcm_encode(&pcm);
    let mut out = kba_header(2, 44100, 1, frames);
    out.extend_from_slice(&body);

    let reference = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/adpcm-js.kba"
    ))
    .unwrap();
    assert_eq!(out.len(), reference.len(), "length differs");
    assert_eq!(out, reference, "the ADPCM port drifted from the JS reference");
}
