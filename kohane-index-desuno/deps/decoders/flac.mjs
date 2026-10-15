// FLAC, read natively.
//
// KID's own decoder, written here rather than borrowed, and registered in deps/manifest.json as a
// decoder with origin "built here". Stage one covers what a file *is* - the stream marker, the
// metadata blocks and STREAMINFO's sample rate, channel count, bit depth, total samples and the MD5
// of the original PCM - plus the first frame header, which is where bit-exactness will have to start.
//
// Two habits are deliberate. Every field is reported in the unit the format states it in (a sample
// rate, not a code), because a caller should not have to know the format's tables. And anything not
// yet implemented says so: a decoder that returns silence for an unsupported feature is worse than one
// that refuses, because the silence looks like a decoded file.
import fs from "node:fs";
import { pathToFileURL } from "node:url";

const MARKER = "fLaC";

/** A reader over a Buffer that hands out MSB-first bit fields, which is how the format is written. */
class BitReader {
  constructor(buf, offset = 0) {
    this.buf = buf;
    this.byte = offset;
    this.bit = 0;
  }

  u(n) {
    let value = 0;
    for (let i = 0; i < n; i++) {
      const b = this.buf[this.byte];
      if (b === undefined) throw new Error("ran off the end of the file");
      value = (value << 1) | ((b >> (7 - this.bit)) & 1);
      this.bit++;
      if (this.bit === 8) { this.bit = 0; this.byte++; }
    }
    return value >>> 0;
  }

  get position() { return this.byte * 8 + this.bit; }
}

/**
 * What this module can and cannot do, stated where the code lives so the registry never has to
 * guess or keep a parallel list.
 */
export const capabilities = {
  id: "flac",
  container: "flac",
  read: { level: "metadata", detail: "stream marker, metadata blocks, STREAMINFO, Vorbis comments, first frame header" },
  decode: { level: "none", detail: "subframe decoding (constant/verbatim/fixed/LPC, Rice coding, channel decorrelation) is not implemented" },
  encode: { level: "none", detail: "a FLAC encoder is planned; it will be a separate module, matching the split decode/encode rule" },
  verifiedAgainst: "a real 150 MB master (48 kHz, stereo, 24 bit, 30,543,355 samples, 636.32 s) and a synthesised stream",
};

export function readFlac(file) {
  const buf = fs.readFileSync(file);
  if (buf.length < 8 || buf.toString("latin1", 0, 4) !== MARKER) {
    throw new Error("not a FLAC stream (no fLaC marker)");
  }

  const blocks = [];
  let streamInfo = null;
  let at = 4;

  while (at + 4 <= buf.length) {
    const header = buf[at];
    const last = (header & 0x80) !== 0;
    const type = header & 0x7f;
    const length = (buf[at + 1] << 16) | (buf[at + 2] << 8) | buf[at + 3];
    const body = at + 4;
    if (body + length > buf.length) throw new Error("a metadata block runs past the end of the file");

    const names = {
      0: "STREAMINFO", 1: "PADDING", 2: "APPLICATION", 3: "SEEKTABLE", 4: "VORBIS_COMMENT",
      5: "CUESHEET", 6: "PICTURE", 127: "INVALID",
    };
    const entry = { type, name: names[type] || `RESERVED(${type})`, length, last };
    blocks.push(entry);

    if (type === 0) {
      const r = new BitReader(buf, body);
      const minBlockSize = r.u(16);
      const maxBlockSize = r.u(16);
      const minFrameSize = r.u(24);
      const maxFrameSize = r.u(24);
      const sampleRate = r.u(20);
      const channelsMinusOne = r.u(3);
      const bitsMinusOne = r.u(5);
      const totalSamples = (r.u(4) * 4294967296) + r.u(32);
      const md5 = buf.subarray(r.byte, r.byte + 16).toString("hex");
      streamInfo = {
        minBlockSize,
        maxBlockSize,
        minFrameSize,
        maxFrameSize,
        sampleRate,
        channels: channelsMinusOne + 1,
        bitsPerSample: bitsMinusOne + 1,
        totalSamples,
        durationSec: sampleRate ? Math.round((totalSamples / sampleRate) * 1000) / 1000 : null,
        md5,
      };
      entry.detail = `${sampleRate} Hz, ${channelsMinusOne + 1} channel(s), ${bitsMinusOne + 1} bit, ${totalSamples} samples`;
    } else if (type === 4) {
      // Vorbis comment: length-prefixed little-endian strings. The vendor string alone usually says
      // which encoder wrote the file, which is useful evidence when a stream looks unusual.
      const view = buf.subarray(body, body + length);
      try {
        const vendorLength = view.readUInt32LE(0);
        const vendor = view.subarray(4, 4 + vendorLength).toString("utf8");
        const count = view.readUInt32LE(4 + vendorLength);
        const tags = [];
        let p = 8 + vendorLength;
        for (let i = 0; i < count && p + 4 <= view.length; i++) {
          const n = view.readUInt32LE(p);
          tags.push(view.subarray(p + 4, p + 4 + n).toString("utf8"));
          p += 4 + n;
        }
        entry.detail = `vendor="${vendor}", ${tags.length} tag(s)`;
        entry.tags = tags.slice(0, 12);
      } catch {
        entry.detail = "comment block present but not parsable";
      }
    }

    at = body + length;
    if (last) break;
  }

  // The first frame header, to prove where the metadata ends. Its fields are codes, so they are
  // translated here rather than left for the caller.
  let firstFrame = null;
  if (at + 4 <= buf.length) {
    const r = new BitReader(buf, at);
    const sync = r.u(14);
    if (sync === 0x3ffe) {
      const reserved = r.u(1);
      const blocking = r.u(1);
      const blockSizeCode = r.u(4);
      const sampleRateCode = r.u(4);
      const channelCode = r.u(4);
      const sampleSizeCode = r.u(3);
      r.u(1);
      const BLOCK_SIZES = { 1: 192, 2: 576, 3: 1152, 4: 2304, 5: 4608, 8: 256, 9: 512, 10: 1024, 11: 2048, 12: 4096, 13: 8192, 14: 16384, 15: 32768 };
      const SAMPLE_RATES = { 1: 88200, 2: 176400, 3: 192000, 4: 8000, 5: 16000, 6: 22050, 7: 24000, 8: 32000, 9: 44100, 10: 48000, 11: 96000 };
      const SAMPLE_SIZES = { 1: 8, 2: 12, 4: 16, 5: 20, 6: 24 };
      const CHANNELS = { 0: 1, 1: 2, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 8: 2, 9: 2, 10: 2 };
      firstFrame = {
        offset: at,
        blocking: blocking ? "variable" : "fixed",
        blockSize: blockSizeCode === 0 || blockSizeCode === 6 || blockSizeCode === 7 ? "from the end of the header" : BLOCK_SIZES[blockSizeCode] ?? null,
        sampleRate: sampleRateCode === 0 ? "from STREAMINFO" : sampleRateCode === 12 ? "from the end of the header" : SAMPLE_RATES[sampleRateCode] ?? null,
        channels: CHANNELS[channelCode] ?? null,
        channelAssignment: channelCode <= 7 ? "independent" : channelCode === 8 ? "left/side" : channelCode === 9 ? "right/side" : channelCode === 10 ? "mid/side" : "reserved",
        bitsPerSample: sampleSizeCode === 0 ? "from STREAMINFO" : SAMPLE_SIZES[sampleSizeCode] ?? null,
        reservedBitSet: reserved === 1,
      };
    }
  }

  return {
    container: "flac",
    blocks,
    streamInfo,
    firstFrame,
    /** Where the frame decoder will begin, and what it still owes. */
    framesAt: at,
    decoded: false,
    pending: "frame decoding (subframes, Rice coding, channel decorrelation) is not implemented yet; this reports what the file is",
  };
}

// The self-run guard compares the resolved path with this module's own path. A name-suffix test is
// not enough: a caller called "test-flac.mjs" ends with "flac.mjs" and would trigger the CLI block on
// import, which is exactly what happened the first time this was run.
const isMain = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  const file = process.argv[2];
  if (!file) {
    console.log("usage: node flac.mjs <file.flac>");
    process.exit(1);
  }
  const info = readFlac(file);
  console.log(`${file}`);
  console.log(`  metadata: ${info.blocks.map((b) => `${b.name}(${b.length})`).join(" ")}`);
  const s = info.streamInfo;
  if (s) {
    console.log(`  streaminfo: ${s.sampleRate} Hz, ${s.channels} ch, ${s.bitsPerSample} bit, ${s.totalSamples} samples, ${s.durationSec}s, md5 ${s.md5.slice(0, 12)}...`);
    console.log(`  frame size limits: ${s.minFrameSize}..${s.maxFrameSize} bytes, block ${s.minBlockSize}..${s.maxBlockSize}`);
  }
  console.log(`  first frame at byte ${info.framesAt}: ${info.firstFrame ? JSON.stringify(info.firstFrame) : "no frame header found"}`);
  console.log(`  ${info.pending}`);
}
