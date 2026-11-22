// Kohane's audio container (.kba): PCM in three tiers, with ADPCM as the default.
//
// The KPB volume policy (research/notes/2026-10-15-kpb-design.md section 5) makes the tier the
// main knob: adpcm is the default (16-bit PCM to 4-bit, about a quarter of the size), lossless is
// the optional exact tier (delta encoding through the built-in deflate), and raw is the fallback
// that stores the samples untouched. The container itself is plain and honest about which tier a
// file carries, so a reader never guesses.
//
// Layout: "KBA1" | version(1) | tier(1) | sampleRate(u32 LE) | channels(u16 LE) | frames(u32 LE)
//         | body. tier 0 = raw int16 interleaved; tier 1 = deflate(delta(int16)); tier 2 = IMA
//         ADPCM, one 4-bit nibble per sample, blocks of 1024 frames each opening with pred(i16) and
//         step index(u8).
import zlib from "node:zlib";

const MAGIC = "KBA1";
const TIERS = { raw: 0, lossless: 1, adpcm: 2 };
const TIER_NAMES = ["raw", "lossless", "adpcm"];
const ADPCM_BLOCK = 1024;

// IMA ADPCM step table and index adjustment, the standard tables every encoder and decoder shares.
const STEP_TABLE = [7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767];
const INDEX_TABLE = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8];

function adpcmEncode(pcm) {
  const frames = pcm.length;
  const blocks = Math.ceil(frames / ADPCM_BLOCK);
  const body = Buffer.alloc(blocks * (2 + 1 + Math.ceil(Math.min(frames, ADPCM_BLOCK) / 2)));
  let out = 0;
  for (let b = 0; b < blocks; b++) {
    const start = b * ADPCM_BLOCK;
    const count = Math.min(ADPCM_BLOCK, frames - start);
    let pred = 0;
    let index = 0;
    body.writeInt16LE(pred, out); out += 2;
    body[out++] = index;
    let lo = null;
    for (let i = 0; i < count; i++) {
      const x = pcm[start + i];
      // the standard IMA bit-by-bit encoder: the code is found by successive halving so the
      // decoder's delta reconstruction (step/8, +step, +step/2, +step/4 per bit) matches exactly.
      let diff = x - pred;
      let code = 0;
      if (diff < 0) { code = 8; diff = -diff; }
      let step = STEP_TABLE[index];
      let delta = step >> 3;
      if (diff >= step) { code |= 4; diff -= step; delta += step; }
      step >>= 1;
      if (diff >= step) { code |= 2; diff -= step; delta += step; }
      step >>= 1;
      if (diff >= step) { code |= 1; delta += step; }
      pred += (code & 8) ? -delta : delta;
      pred = Math.max(-32768, Math.min(32767, pred));
      index = Math.max(0, Math.min(88, index + INDEX_TABLE[code & 7]));
      if (lo === null) { body[out] = code; lo = body[out]; }
      else { body[out++] = lo | (code << 4); lo = null; }
    }
    if (lo !== null) out++;
  }
  return body.subarray(0, out);
}

function adpcmDecode(body, frames) {
  const pcm = new Int16Array(frames);
  let at = 0;
  let written = 0;
  while (written < frames) {
    const count = Math.min(ADPCM_BLOCK, frames - written);
    let pred = body.readInt16LE(at); at += 2;
    let index = body[at++];
    let hi = null;
    for (let i = 0; i < count; i++) {
      let nibble;
      if (hi === null) { hi = body[at++]; nibble = hi & 0x0f; }
      else { nibble = hi >> 4; hi = null; }
      const code = nibble & 7;
      const step = STEP_TABLE[index];
      let delta = step >> 3;
      if (nibble & 4) delta += step;
      if (nibble & 2) delta += step >> 1;
      if (nibble & 1) delta += step >> 2;
      pred += (nibble & 8) ? -delta : delta;
      pred = Math.max(-32768, Math.min(32767, pred));
      index = Math.max(0, Math.min(88, index + INDEX_TABLE[code]));
      pcm[written++] = pred;
    }
  }
  return pcm;
}

/** One-pole low-pass then every-other-sample decimation: the honest 2:1 downsampling. */
export function downsample2(pcm) {
  const out = new Int16Array(Math.floor(pcm.length / 2));
  let y = 0;
  let o = 0;
  for (let i = 0; i < pcm.length; i++) {
    y += 0.25 * (pcm[i] - y);
    if (i % 2 === 1) out[o++] = Math.round(y);
  }
  return out;
}

export function encodeKba(pcm, options = {}) {
  if (!(pcm instanceof Int16Array)) throw new Error("encodeKba needs an Int16Array");
  const sampleRate = Number(options.sampleRate) || 44100;
  const channels = Number(options.channels) || 1;
  const tier = TIERS[String(options.tier || "adpcm").toLowerCase()] ?? 2;
  const frames = pcm.length;
  const head = Buffer.alloc(16);
  head.write(MAGIC, 0, "latin1");
  head[4] = 1;
  head[5] = tier;
  head.writeUInt32LE(sampleRate, 6);
  head.writeUInt16LE(channels, 10);
  head.writeUInt32LE(frames, 12);
  let body;
  if (tier === 0) {
    body = Buffer.from(pcm.buffer, pcm.byteOffset, pcm.byteLength);
  } else if (tier === 1) {
    const delta = Buffer.alloc(frames * 2);
    let prev = 0;
    for (let i = 0; i < frames; i++) {
      delta.writeInt16LE(pcm[i] - prev, i * 2);
      prev = pcm[i];
    }
    body = zlib.deflateSync(delta);
  } else {
    body = adpcmEncode(pcm);
  }
  return Buffer.concat([head, body]);
}

export function decodeKba(buf) {
  if (buf.length < 16 || buf.toString("latin1", 0, 4) !== MAGIC) throw new Error("not a kohane audio container (no KBA1 marker)");
  if (buf[4] !== 1) throw new Error(`not a kohane audio container (unknown version ${buf[4]})`);
  const tier = buf[5];
  if (tier > 2) throw new Error(`not a kohane audio container (unknown tier ${tier})`);
  const sampleRate = buf.readUInt32LE(6);
  const channels = buf.readUInt16LE(10);
  const frames = buf.readUInt32LE(12);
  const body = buf.subarray(16);
  let pcm;
  if (tier === 0) {
    // Read through the Buffer API: the file Buffer may sit at an odd offset in Node's pool, and a
    // typed-array view over it would refuse to start.
    const n = Math.floor(body.length / 2);
    pcm = new Int16Array(n);
    for (let i = 0; i < n; i++) pcm[i] = body.readInt16LE(i * 2);
  } else if (tier === 1) {
    const delta = zlib.inflateSync(body);
    pcm = new Int16Array(delta.length / 2);
    let prev = 0;
    for (let i = 0; i < pcm.length; i++) {
      prev += delta.readInt16LE(i * 2);
      pcm[i] = prev;
    }
  } else {
    pcm = adpcmDecode(body, frames);
  }
  return { tier: TIER_NAMES[tier], sampleRate, channels, frames, pcm };
}

export function kbaStats(buf) {
  if (buf.length < 16 || buf.toString("latin1", 0, 4) !== MAGIC) throw new Error("not a kohane audio container (no KBA1 marker)");
  return {
    tier: TIER_NAMES[buf[5]] || `tier${buf[5]}`,
    sampleRate: buf.readUInt32LE(6),
    channels: buf.readUInt16LE(10),
    frames: buf.readUInt32LE(12),
    bytes: buf.length,
    pcmBytes: buf.readUInt32LE(12) * 2 * Math.max(1, buf.readUInt16LE(10)),
  };
}

export const capabilities = {
  id: "kba",
  kohaneName: "Kohane Bassline Audio",
  container: "kba",
  read: { level: "full", detail: "the container header: tier, sample rate, channels, frame count" },
  decode: { level: "full", detail: "all three tiers back to int16 PCM: raw verbatim, lossless through delta+deflate, adpcm through IMA 4-bit" },
  encode: { level: "full", detail: "writes any tier from int16 PCM; adpcm is the default, the tier is the volume knob" },
  verifiedAgainst: "the selfcheck kpb assets (stage 5) section: adpcm round-trip peak error, block-spanning encodes, lossless and raw round-trips sample for sample, and the real SoundFont converted through it inside the volume window",
};
