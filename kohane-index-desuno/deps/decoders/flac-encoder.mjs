// FLAC, written natively.
//
// KID's own encoder, registered in deps/manifest.json as a separate module from the reader - encoders
// and decoders are different claims, and keeping them apart is what lets "can read" and "can write" be
// answered honestly. This stage writes a legal compressed stream: constant subframes for silence,
// verbatim subframes where prediction loses, and fixed predictors of orders 0-4 with partitioned Rice
// coding (partition orders 0-2, 4-bit parameters) for everything else, with correct CRCs and a correct
// MD5 of the raw PCM. Constant, verbatim, fixed-predictor (orders 0-4) and LPC (orders 1-8,
// Levinson-Durbin plus quantisation search) subframes are all written, with partitioned Rice
// coding including escaped partitions.
import fs from "node:fs";
import crypto from "node:crypto";

export const capabilities = {
  id: "flac-encoder",
  kohaneName: "Kohane Bassline Stream Writer (FLAC)",
  container: "flac",
  read: { level: "none", detail: "this module writes; reading is the reader module's job" },
  decode: { level: "none", detail: "not applicable" },
  encode: { level: "partial", detail: "stream marker, STREAMINFO, a Vorbis comment with the kohane vendor string, and frames using constant, verbatim, fixed-predictor (orders 0-4) and LPC (orders 1-8, Levinson-Durbin with quantisation search) subframes with partitioned Rice coding (partition orders 0-2, 4-bit parameters) including escaped partitions (k=15, 5-bit width + raw residuals)" },
  verifiedAgainst: "round trip against the project's own reader plus the MD5 of the source PCM recorded in STREAMINFO, the independent bit-stream walk in tools/flac-walk.mjs (sample-exact), and ffmpeg where present",
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

/**
 * Levinson-Durbin over the signal's autocorrelation, returning the prediction coefficients
 * a[1..order] such that s[i] ~ sum a[j] * s[i-j]. The window is the whole subframe.
 */
function lpcCoeffs(s, order) {
  const r = new Float64Array(order + 1);
  for (let lag = 0; lag <= order; lag++) {
    let acc = 0;
    for (let i = 0; i < s.length - lag; i++) acc += s[i] * s[i + lag];
    r[lag] = acc;
  }
  // Normalise by r[0]: the raw autocorrelation of a full-scale int16 subframe is ~1e13, and a
  // narrow-band signal pushes the residual energy down hard. In the normalised space the
  // reflection coefficients stay near [-1, 1] and the energy cannot underflow.
  const r0 = r[0] || 1;
  for (let lag = 0; lag <= order; lag++) r[lag] /= r0;
  const a = new Float64Array(order + 1);
  a[0] = 1;
  let err = r[0];
  for (let k = 1; k <= order; k++) {
    // Prediction-coefficient form of the Levinson recursion: the coefficients answer
    // x[n] ~ sum a[j] x[n-j], which is exactly what a FLAC LPC subframe stores. The error-filter
    // form carries the opposite signs, and mixing the two yields coefficients that look right
    // in shape but predict the wrong signal.
    let delta = r[k];
    for (let j = 1; j < k; j++) delta -= a[j] * r[k - j];
    let ref = delta / err;
    // An ill-conditioned correlation matrix can push a reflection coefficient a hair past one;
    // without the clamp the energy turns negative and the next step divides into absurdity.
    if (ref > 0.9999) ref = 0.9999;
    else if (ref < -0.9999) ref = -0.9999;
    // The recursion reads the previous order's coefficients; updating in place in ascending order
    // would let a[j] see values this very step has already overwritten.
    const prev = a.slice(0, k);
    for (let j = 1; j < k; j++) a[j] = prev[j] - ref * prev[k - j];
    a[k] = ref;
    err *= 1 - ref * ref;
    if (err < 1e-9) err = 1e-9;
  }
  return a;
}

/**
 * Plan the residual coding shared by fixed and LPC subframes: for each partition order 0..2 pick
 * the cheapest Rice parameter per partition (escape included). Returns { p, params, bits } where
 * bits covers method + partition order + parameters + residuals - the parts both subframe kinds
 * share. Returns null when no partition order divides the block size legally.
 */
function planResidual(res, order, count) {
  let bestPlan = null;
  for (let p = 0; p <= 2; p++) {
    // RFC 9639 9.2.7: the partition order must divide the block size evenly, so a tail frame
    // whose block size is not a multiple of 4 may not use partition order 2.
    if (count % (1 << p) !== 0) continue;
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
      for (let k = 0; k <= 15; k++) {
        let b;
        if (k === 15) {
          // Escape code: 5 bits of per-sample width, then the residuals as signed two's
          // complement. It wins exactly when even the coarsest Rice parameter cannot beat
          // plain writing.
          b = 5 + (to - from) * 16;
        } else {
          b = 0;
          for (let i = from; i < to; i++) {
            const u = (res[i] << 1) ^ (res[i] >> 31);   // zigzag: small negatives stay small
            b += (u >>> k) + 1 + k;
          }
        }
        if (b < bestPartBits) { bestPartBits = b; bestK = k; }
      }
      params.push(bestK);
      bits += bestPartBits;
    }
    if (!ok) continue;
    const total = bits + 2 + 4 + params.length * 4;
    if (!bestPlan || total < bestPlan.bits) bestPlan = { p, params, bits: total, per };
  }
  return bestPlan;
}

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

      // Fixed predictors of orders 0 to 4, then LPC predictors of orders 1 to 8: for each
      // candidate the residual is planned into Rice-coded partitions (escape included) and the
      // cheapest one wins - unless none of them beats writing the samples as they are. The total
      // compared here covers the residual plan plus the warm-up samples; the constant 6+1 subframe
      // header bits are the same for every candidate, so they cancel out of the comparison.
      let best = null;
      const tryCandidate = (order, res, plan, extraBits) => {
        if (!plan) return;
        const total = plan.bits + order * 16 + extraBits;
        if (!best || total < best.bits) best = { kind: "fixed", order, p: plan.p, params: plan.params, bits: total, res, per: plan.per };
      };      for (let order = 0; order <= 4; order++) {
        if (count <= order) continue;
        const res = new Int32Array(count - order);
        let resOk = true;
        for (let i = order; i < count; i++) {
          let predicted = 0;
          if (order === 1) predicted = s[i - 1];
          else if (order === 2) predicted = 2 * s[i - 1] - s[i - 2];
          else if (order === 3) predicted = 3 * s[i - 1] - 3 * s[i - 2] + s[i - 3];
          else if (order === 4) predicted = 4 * s[i - 1] - 6 * s[i - 2] + 4 * s[i - 3] - s[i - 4];
          res[i - order] = s[i] - predicted;
          // Residuals are written with bps bits (16) in every branch - including the escape - so a
          // predictor whose residual leaves that range cannot be written losslessly and is out.
          if (res[i - order] > 32767 || res[i - order] < -32768) resOk = false;
        }
        if (!resOk) continue;
        tryCandidate(order, res, planResidual(res, order, count), 0);
      }

      // LPC: solve the prediction coefficients with Levinson-Durbin, then quantise them - the
      // coefficients are stored signed with `precision` bits and used shifted by `shift` (RFC 9639
      // 9.2.3). Every (precision, shift) pair is judged by re-computing the residuals with the
      // quantised coefficients, so the search sees the error quantisation introduced, not the
      // float coefficients.
      for (let order = 1; order <= 8; order++) {
        if (count <= order) continue;
        const coeffs = lpcCoeffs(s, order);
        for (let precision = 12; precision <= 16; precision++) {
          const maxQ = (1 << (precision - 1)) - 1;
          for (let shift = -6; shift <= 6; shift++) {
            const q = new Int32Array(order);
            let qOk = true;
            for (let j = 1; j <= order; j++) {
              const v = Math.round(coeffs[j] * 2 ** shift);
              if (v > maxQ || v < -maxQ - 1) { qOk = false; break; }
              q[j - 1] = v;
            }
            if (!qOk) continue;
            const res = new Int32Array(count - order);
            let resOk = true;
            for (let i = order; i < count; i++) {
              let sum = 0;
              for (let j = 0; j < order; j++) sum += q[j] * s[i - 1 - j];
              // Arithmetic right shift by `shift`; Math.floor keeps negative sums exact where a
              // 32-bit >> would truncate.
              const pred = Math.floor(sum / 2 ** shift);
              res[i - order] = s[i] - pred;
              if (res[i - order] > 32767 || res[i - order] < -32768) { resOk = false; break; }
            }
            if (!resOk) continue;
            const plan = planResidual(res, order, count);
            if (!plan) continue;
            const total = plan.bits + order * 16 + 4 + 5 + order * precision;
            if (!best || total < best.bits) {
              best = { kind: "lpc", order, precision, shift, q, p: plan.p, params: plan.params, bits: total, res, per: plan.per };
            }
          }
        }
      }

      if (!best || best.bits >= count * 16 + 8) {
        body.write(1, 6);                            // subframe type 1 = verbatim
        body.write(0, 1);
        for (let i = 0; i < count; i++) body.writeSigned(s[i], 16);
        continue;
      }

      // The residual partitions are written identically for fixed and LPC subframes.
      const writeResidualPartitions = () => {
        body.write(0, 2);                            // residual method 00: Rice with 4-bit parameters
        body.write(best.p, 4);                       // partition order
        for (let part = 0; part < best.params.length; part++) {
          const k = best.params[part];
          const from = part === 0 ? 0 : best.per - best.order + (part - 1) * best.per;
          const to = part === 0 ? best.per - best.order : best.per - best.order + part * best.per;
          body.write(k, 4);
          for (let i = from; i < to && i < best.res.length; i++) {
            if (k === 15) {
              if (i === from) body.write(16, 5);           // escaped partition: 5-bit sample width
              body.writeSigned(best.res[i], 16);           // then raw signed residuals
              continue;
            }
            const v = best.res[i];
            const u = (v << 1) ^ (v >> 31);
            const q = u >>> k;
            for (let j = 0; j < q; j++) body.write(0, 1);   // unary quotient: q zero bits
            body.write(1, 1);                              // ...then the terminating one
            if (k > 0) body.write(u & ((1 << k) - 1), k);
          }
        }
      };

      if (best.kind === "lpc") {
        body.write(32 + best.order - 1, 6);         // subframe type 10xxxxx: LPC of order x+1
        body.write(0, 1);
        for (let i = 0; i < best.order; i++) body.writeSigned(s[i], 16);   // warm-up samples
        body.write(best.precision - 1, 4);           // QLP precision: bits per coefficient minus one
        body.writeSigned(best.shift, 5);             // QLP shift: signed
        for (let j = 0; j < best.order; j++) body.writeSigned(best.q[j], best.precision);
        writeResidualPartitions();
        continue;
      }

      body.write(8 + best.order, 6);                 // subframe type 001xxx: fixed predictor of that order
      body.write(0, 1);
      for (let i = 0; i < best.order; i++) body.writeSigned(s[i], 16);   // warm-up samples
      writeResidualPartitions();
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
