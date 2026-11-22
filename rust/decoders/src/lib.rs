// The library half of the verification brick: encoders as reusable modules, so both the CLI and
// the tests exercise the same code the JS side is cross-checked against.
pub mod adpcm;
pub mod bitwriter;
pub mod flac;
pub mod json;
pub mod kba;
pub mod kbb;
pub mod kbi;
pub mod md5;
pub mod parsers;
pub mod registry;
pub mod sha256;
pub mod zlib;
