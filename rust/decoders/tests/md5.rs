// MD5 against the RFC 1321 test vectors - the FLAC encoder records this digest in STREAMINFO,
// so a wrong MD5 would corrupt every stream silently.
use kohane_decoder::md5::Md5;

fn hex(d: [u8; 16]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn rfc1321_vectors() {
    assert_eq!(hex(Md5::digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hex(Md5::digest(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        hex(Md5::digest(b"message digest")),
        "f96b697d7cb7938d525a2f31aaf161d0"
    );
    assert_eq!(
        hex(Md5::digest(b"abcdefghijklmnopqrstuvwxyz")),
        "c3fcd3d76192e4007dfb496cca67e13b"
    );
    // a payload crossing several 64-byte blocks
    let long: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
    let mut h = Md5::new();
    h.update(&long);
    let one = h.finalize();
    let mut h2 = Md5::new();
    for chunk in long.chunks(64) {
        h2.update(chunk);
    }
    assert_eq!(hex(one), hex(h2.finalize()), "chunked update must equal one-shot");
}
