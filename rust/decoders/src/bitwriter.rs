// The bit writer, order-identical with the JS original (flac-encoder.mjs): values go out
// most-significant bit first, signed values as two's complement, and a trailing align pads
// with zeros. Byte-exactness with JS depends on keeping this order exactly.
pub struct BitWriter {
    bytes: Vec<u8>,
    partial: u32,
    bits: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        BitWriter { bytes: Vec::new(), partial: 0, bits: 0 }
    }

    pub fn write(&mut self, value: u32, width: u32) {
        for i in (0..width).rev() {
            self.partial = (self.partial << 1) | ((value >> i) & 1);
            self.bits += 1;
            if self.bits == 8 {
                self.bytes.push((self.partial & 0xff) as u8);
                self.partial = 0;
                self.bits = 0;
            }
        }
    }

    pub fn write_signed(&mut self, value: i32, width: u32) {
        let v = if value < 0 { value + (1i32 << width) } else { value };
        self.write(v as u32, width);
    }

    pub fn align(&mut self) {
        if self.bits != 0 {
            self.partial <<= 8 - self.bits;
            self.bytes.push((self.partial & 0xff) as u8);
            self.partial = 0;
            self.bits = 0;
        }
    }

    pub fn into_bytes(mut self) -> Vec<u8> {
        self.align();
        self.bytes
    }
}
