// FLAC, written natively.
//
// KID's own encoder, registered in deps/manifest.json as a separate module from the reader - encoders
// and decoders are different claims, and keeping them apart is what lets "can read" and "can write" be
// answered honestly. This stage writes a **legal but uncompressed** stream: constant subframes for
// silence and verbatim subframes for everything else, with correct CRCs and a correct MD5 of the raw
// PCM. Prediction (fixed/LPC) and Rice coding come next; until then the file is larger than it needs
// to be, and the module says so rather than pretending.
import fs from "node:fs";
import crypto from "node:crypto";

export const capabilities = {
  id: "flac-encoder",
  kohaneName: "Kohane Bassline Stream Writer (FLAC)",
  container: "flac",
  read: { level: "none", detail: "this module writes; reading is the reader module's job" },
  decode: { level: "none", detail: "not applicable" },
  encode: { level: "partial", detail: "stream marker, STREAMINFO, a Vorbis comment with the kohane vendor string, and frames using constant and verbatim subframes (no prediction or Rice coding yet)" },
  verifiedAgainst: "round trip against the project's own reader plus the MD5 of the source PCM recorded in STREAMINFO",
};

const BLOCK = 4096;
const BLOCK_CODE = 12;                     // 4096 samples per frame, fixed blocking

class BitWriter {
  constructor() {
    this.bytes = [];
    this.partial = 0;
    this.bits = 0;
  }

  write(value, width) {
    for (let i = width - 1; i >= 0; i--) {
      this.partial = (this.partial << 1) | ((value >>> i) & 1);
      this.bits++;
      if (this.bits === 8) { this.bytes.push(this.partial & 0xff); this.partial = 0; this.bits = 0; }
    }
  }

  /** Signed values are written as two's complement, which is what the format expects. */
  writeSigned(value, width) {
    this.write(value < 0 ? value + (1 << width) : value, width);
  }

  align() {
    if (this.bits) { this.partial <<= 8 - this.bits; this.bytes.push(this.partial & 0xff); this.partial = 0; this.bits = 0; }
  }

  toBuffer() { this.align(); return Buffer.from(this.bytes); }
}

const crc8 = (buf) => {
  let crc = 0;
  for (const b of buf) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = crc & 0x80 ? ((crc << 1) ^ 0x07) & 0xff : (crc << 1) & 0xff;
  }
  return crc;
};

const crc16 = (buf) => {
  let crc = 0;
  for (const b of buf) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x8005) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
};

/** The frame/sample number is coded as UTF-8 would code it, which is the format's own convention. */
const utf8Number = (value) => {
  if (value < 0x80) return Buffer.from([value]);
  const bytes = [];
  let v = value;
  while (v > 0) { bytes.unshift(v & 0x3f); v >>>= 6; }
  const lead = (0xff << (8 - bytes.length)) & 0xff;
  bytes[0] |= lead;
  return Buffer.from(bytes);
};

const LE = (value, width) => {
  const b = Buffer.alloc(width);
  if (width === 3) { b.writeUIntBE(value, 0, 3); return Buffer.from([b[2], b[1], b[0]]); }
  if (width === 8) b.writeBigUInt64BE(BigInt(value));
  else b.writeUIntBE(value, 0, width);
  if (width === 8) return Buffer.from(b).reverse();
  return Buffer.from(b).reverse();
};

const chunkHeader = (last, type, length) => Buffer.from([
  (last ? 0x80 : 0x00) | type,
  (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff,
]);

/**
 * Encodes interleaved samples (floats in -1..1, like the decoders produce) into a FLAC stream.
 * The MD5 recorded in STREAMINFO is of the raw PCM as written, so a reader can prove the samples.
 */
export function encodeFlac(samples, { sampleRate, channels, bitsPerSample = 16, vendor = "kohane-index-desuno" }) {
  if (![16].includes(bitsPerSample)) throw new Error("this stage writes 16-bit streams only");
  const frames = Math.floor(samples.length / channels);
  const max = (1 << (bitsPerSample - 1)) - 1;

  // the raw PCM, little-endian, interleaved: what STREAMINFO's MD5 must describe
  const pcm = Buffer.alloc(frames * channels * 2);
  for (let i = 0; i < frames * channels; i++) {
    const v = Math.max(-1, Math.min(1, samples[i] || 0));
    pcm.writeInt16LE(Math.round(v * max), i * 2);
  }
  const md5 = crypto.createHash("md5").update(pcm).digest();

  const writer = new BitWriter();
  // "fLaC" marker, then STREAMINFO as the first metadata block
  const streamInfo = Buffer.alloc(34);
  streamInfo.writeUInt16BE(BLOCK, 0);
  streamInfo.writeUInt16BE(BLOCK, 2);
  streamInfo.writeUIntBE(0, 4, 3);                      // minimum frame size: unknown
  streamInfo.writeUIntBE(0, 7, 3);                      // maximum frame size: unknown
  streamInfo.writeUInt32BE((sampleRate << 12) | ((channels - 1) << 9) | ((bitsPerSample - 1) << 4) | 0, 10);
  // bytes 10..17 hold 64 bits: sample rate (20), channels-1 (3), bits-1 (5), total samples (36).
  // The first word covers the rate/channels/bits plus the top four bits of the count; the second word
  // carries the low 32 bits. Writing a 64-bit value at offset 14 would run into the MD5 field at 18.
  const total = BigInt(frames);
  streamInfo.writeUInt32BE(((sampleRate & 0xfffff) << 12) | ((channels - 1) << 9) | ((bitsPerSample - 1) << 4) | Number((total >> 32n) & 0xfn), 10);
  streamInfo.writeUInt32BE(Number(total & 0xffffffffn), 14);
  md5.copy(streamInfo, 18);

  const comment = (() => {
    const v = Buffer.from(vendor, "utf8");
    const parts = [Buffer.alloc(4), Buffer.alloc(4)];
    parts[0].writeUInt32LE(v.length);
    parts[1].writeUInt32LE(0);
    return Buffer.concat([parts[0], v, parts[1]]);
  })();

  const parts = [Buffer.from("fLaC", "latin1"), chunkHeader(false, 0, 34), streamInfo, chunkHeader(true, 4, comment.length), comment];

  for (let frame = 0, frameNumber = 0; frame < frames; frame += BLOCK, frameNumber++) {
    const count = Math.min(BLOCK, frames - frame);
    const header = new BitWriter();
    header.write(0x3ffe, 14);                          // sync
    header.write(0, 1);                                // reserved
    header.write(0, 1);                                // fixed blocking
    // A final frame holding fewer samples than the block size must say so: code 12 claims a full
    // 4096 and a real decoder would read past the data. Code 7 means "the count follows, minus one".
    const partial = count !== BLOCK;
    header.write(partial ? 7 : BLOCK_CODE, 4);
    header.write(0, 4);                                // sample rate: as in STREAMINFO
    header.write(channels === 1 ? 0 : 1, 4);           // channel assignment: independent
    header.write(4, 3);                                // sample size: 16 bit
    header.write(0, 1);                                // reserved
    const numberBytes = utf8Number(frameNumber);
    const sizeField = partial ? Buffer.from([((count - 1) >> 8) & 0xff, (count - 1) & 0xff]) : Buffer.alloc(0);
    const headerBytes = Buffer.concat([header.toBuffer(), numberBytes, sizeField]);
    const withCrc = Buffer.concat([headerBytes, Buffer.from([crc8(headerBytes)])]);

    const body = new BitWriter();
    for (let c = 0; c < channels; c++) {
      const s = new Int32Array(count);
      for (let i = 0; i < count; i++) s[i] = pcm.readInt16LE(((frame + i) * channels + c) * 2);

      let constant = true;
      for (let i = 1; i < count; i++) if (s[i] !== s[0]) { constant = false; break; }

      body.write(0, 1);                              // zero padding bit
      if (constant) {
        body.write(0, 6);                            // subframe type 0 = constant
        body.write(0, 1);                            // no wasted bits
        body.writeSigned(s[0], 16);
        continue;
      }

      // Fixed predictors, orders 0 to 2: residual = sample minus the predictor of that order. For
      // each order the cheapest Rice parameter is found by counting the bits it would take, and the
      // order that costs least wins - unless none of them beats writing the samples as they are.
      // Fixed predictors of orders 0 to 4, each tried against every partition order from 0 to 2.
      // A partition is a stretch of residuals that gets its own Rice parameter, which is what makes a
      // signal with a quiet half and a busy half compress well: one parameter for the whole subframe
      // would be a compromise neither half wants.
      let best = null;
      for (let order = 0; order <= 4; order++) {
        if (count <= order) continue;
        const res = new Int32Array(count - order);
        for (let i = order; i < count; i++) {
          let predicted = 0;
          if (order === 1) predicted = s[i - 1];
          else if (order === 2) predicted = 2 * s[i - 1] - s[i - 2];
          else if (order === 3) predicted = 3 * s[i - 1] - 3 * s[i - 2] + s[i - 3];
          else if (order === 4) predicted = 4 * s[i - 1] - 6 * s[i - 2] + 4 * s[i - 3] - s[i - 4];
          res[i - order] = s[i] - predicted;
        }
        for (let p = 0; p <= 2; p++) {
          const per = count >> p;
          if (per <= order || per === 0) continue;
          const params = [];
          let bits = 0;
          let ok = true;
          for (let part = 0; part < (1 << p); part++) {
            const from = part === 0 ? 0 : per - order + (part - 1) * per;
            const to = part === 0 ? per - order : per - order + part * per;
            if (to > res.length) { ok = false; break; }
            let bestK = 0;
            let bestPartBits = Infinity;
            for (let k = 0; k <= 14; k++) {
              let b = 0;
              for (let i = from; i < to; i++) {
                const u = (res[i] << 1) ^ (res[i] >> 31);   // zigzag: small negatives stay small
                b += (u >>> k) + 1 + k;
              }
              if (b < bestPartBits) { bestPartBits = b; bestK = k; }
            }
            params.push(bestK);
            bits += bestPartBits;
          }
          if (!ok) continue;
          const total = bits + 2 + 4 + params.length * 4 + order * 16;
          if (!best || total < best.bits) best = { order, p, params, bits: total, res, per };
        }
      }

      if (!best || best.bits >= count * 16 + 8) {
        body.write(1, 6);                            // subframe type 1 = verbatim
        body.write(0, 1);
        for (let i = 0; i < count; i++) body.writeSigned(s[i], 16);
        continue;
      }

      body.write(8 + best.order, 6);                 // subframe type 001xxx: fixed predictor of that order
      body.write(0, 1);
      for (let i = 0; i < best.order; i++) body.writeSigned(s[i], 16);   // warm-up samples
      body.write(0, 2);                              // residual method 00: Rice with 4-bit parameters
      body.write(best.p, 4);                         // partition order
      for (let part = 0; part < best.params.length; part++) {
        const k = best.params[part];
        const from = part === 0 ? 0 : best.per - best.order + (part - 1) * best.per;
        const to = part === 0 ? best.per - best.order : best.per - best.order + part * best.per;
        body.write(k, 4);
        for (let i = from; i < to && i < best.res.length; i++) {
          const v = best.res[i];
          const u = (v << 1) ^ (v >> 31);
          const q = u >>> k;
          for (let j = 0; j < q; j++) body.write(0, 1);   // unary quotient: q zero bits
          body.write(1, 1);                              // ...then the terminating one
          if (k > 0) body.write(u & ((1 << k) - 1), k);
        }
      }
    }
    const frameBytes = body.toBuffer();
    const whole = Buffer.concat([withCrc, frameBytes]);
    const footer = Buffer.alloc(2);
    footer.writeUInt16BE(crc16(whole));
    parts.push(whole, footer);
  }

  void writer;
  return Buffer.concat(parts);
}

export function encodeWav16(samples, { sampleRate, channels }) {
  const frames = Math.floor(samples.length / channels);
  const pcm = Buffer.alloc(frames * channels * 2);
  for (let i = 0; i < frames * channels; i++) {
    const v = Math.max(-1, Math.min(1, samples[i] || 0));
    pcm.writeInt16LE(Math.round(v * 32767), i * 2);
  }
  const head = Buffer.alloc(44);
  head.write("RIFF", 0, "latin1");
  head.writeUInt32LE(36 + pcm.length, 4);
  head.write("WAVEfmt ", 8, "latin1");
  head.writeUInt32LE(16, 16);
  head.writeUInt16LE(1, 20);
  head.writeUInt16LE(channels, 22);
  head.writeUInt32LE(sampleRate, 24);
  head.writeUInt32LE(sampleRate * channels * 2, 28);
  head.writeUInt16LE(channels * 2, 32);
  head.writeUInt16LE(16, 34);
  head.write("data", 36, "latin1");
  head.writeUInt32LE(pcm.length, 40);
  return Buffer.concat([head, pcm]);
}

export function writeFlac(file, samples, options) {
  const buf = encodeFlac(samples, options);
  fs.writeFileSync(file, buf);
  return { path: file, bytes: buf.length, frames: Math.floor(samples.length / options.channels) };
}
