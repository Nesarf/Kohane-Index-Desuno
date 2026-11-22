// The FLAC cross-check, same discipline as the ADPCM one: the fixture was produced by
// deps/decoders/flac-encoder.mjs from the same PCM, so a differing byte means the port drifted.
use std::fs;

#[test]
fn flac_matches_the_js_reference_byte_for_byte() {
    let raw = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/flac-pcm.raw"
    ))
    .unwrap();
    let pcm: Vec<i16> = raw
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();
    let out = kohane_decoder::flac::encode_flac(&pcm, 44100, 1, "kohane-index-desuno");
    let reference = fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/flac-js.flac"
    ))
    .unwrap();
    assert_eq!(out.len(), reference.len(), "length differs");
    assert_eq!(out, reference, "the FLAC port drifted from the JS reference");
}
