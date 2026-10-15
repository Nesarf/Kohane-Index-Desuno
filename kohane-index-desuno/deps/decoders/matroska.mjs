// Matroska / WebM, read natively.
//
// KID's own decoder, registered in deps/manifest.json. The engine could already say "mkv/webm" from
// the EBML marker; this looks inside: how long the file is, and what tracks it carries (video size,
// audio rate and channels, codec identifiers) - which is the part an index actually wants.
//
// Two rules carried over from the FLAC reader. Values are reported in the unit the format means (a
// duration in seconds, not in timecode units, and a resolution in pixels), and every unrecognised
// element is stepped over by its own declared size rather than guessed at - an EBML reader that
// guesses desynchronises and then reports invented tracks.
import fs from "node:fs";
import { pathToFileURL } from "node:url";

// Element IDs are written as variable-length integers; these are the ones this reader understands,
// kept as the raw byte sequences so a lookup is exact.
const ID = {
  EBML: [0x1a, 0x45, 0xdf, 0xa3],
  DOC_TYPE: [0x42, 0x82],
  DOC_TYPE_VERSION: [0x42, 0x87],
  SEGMENT: [0x18, 0x53, 0x80, 0x67],
  INFO: [0x15, 0x49, 0xa9, 0x66],
  TIMECODE_SCALE: [0x2a, 0xd7, 0xb1],
  DURATION: [0x44, 0x89],
  MUXING_APP: [0x4d, 0x80],
  WRITING_APP: [0x57, 0x41],
  TITLE: [0x7b, 0xa9],
  TRACKS: [0x16, 0x54, 0xae, 0x6b],
  TRACK_ENTRY: [0xae],
  TRACK_NUMBER: [0xd7],
  TRACK_TYPE: [0x83],
  CODEC_ID: [0x86],
  CODEC_NAME: [0x25, 0x86, 0x88],
  DEFAULT_DURATION: [0x23, 0xe3, 0x83],
  VIDEO: [0xe0],
  PIXEL_WIDTH: [0xb0],
  PIXEL_HEIGHT: [0xba],
  AUDIO: [0xe1],
  SAMPLING_FREQUENCY: [0xb5],
  CHANNELS: [0x9f],
  BIT_DEPTH: [0x62, 0x64],
  LANGUAGE: [0x22, 0xb5, 0x9c],
  NAME: [0x53, 0x6e],
};

// Array.from, not map: on a Buffer (a Uint8Array) map returns another Uint8Array, so mapping bytes
// to hex strings coerces them straight back to numbers and every key comes out mangled - which is
// how this reader first managed to walk a file and match nothing at all.
const key = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/** Read a variable-length integer: the length is coded in the leading zero bits of the first byte. */
function vint(buf, at, keepMarker) {
  if (at >= buf.length) throw new Error("ran off the end while reading a variable-length integer");
  const first = buf[at];
  if (first === 0) throw new Error("a variable-length integer of length zero is not valid here");
  let length = 1;
  for (let mask = 0x80; mask && !(first & mask); mask >>= 1) length++;
  if (at + length > buf.length) throw new Error("a variable-length integer runs past the end of the file");
  let value = keepMarker ? first : first & (0xff >> length);
  for (let i = 1; i < length; i++) value = value * 256 + buf[at + i];
  return { value, length, unknown: !keepMarker && value === Math.pow(2, 7 * length) - 1 };
}

function uint(buf, at, length) {
  let value = 0;
  for (let i = 0; i < length; i++) value = value * 256 + buf[at + i];
  return value;
}

function float64(buf, at, length) {
  if (length === 4) return buf.readFloatBE(at);
  if (length === 8) return buf.readDoubleBE(at);
  return NaN;
}

function text(buf, at, length) {
  return buf.subarray(at, at + length).toString("utf8").replace(/\0+$/, "");
}

/**
 * What this module can and cannot do. Container knowledge is separate from codec knowledge: this
 * reader knows where the tracks and their stated properties are, not how their frames are coded.
 */
export const capabilities = {
  id: "matroska",
  container: "matroska/webm",
  read: { level: "metadata", detail: "EBML walk (recursive through master elements), Info (duration, timecode scale, muxing app, title), Tracks (number, type, codec id, video size, audio rate/channels/bit depth)" },
  decode: { level: "none", detail: "elementary streams are not decoded: this reads the container's own description of its tracks" },
  encode: { level: "none", detail: "no muxer yet" },
  verifiedAgainst: "a synthesised stream with chosen values (matroska, 2500 ms, V_VP8 1280x720, A_OPUS 48 kHz stereo)",
};

export function readMatroska(file, options = {}) {
  const buf = fs.readFileSync(file);
  const limit = options.limit || 4 * 1024 * 1024;   // headers live at the front; probing stays bounded

  const first = vint(buf, 0, true);
  if (first.value !== 0x1a45dfa3) throw new Error("not an EBML stream (no EBML header)");

  const out = { container: "matroska", docType: null, docTypeVersion: null, info: {}, tracks: [], decoded: false, seen: [] };
  // Master elements contain other elements; leaves contain data. A reader that visits only the top
  // level sees "Info" and "Tracks" and nothing inside them - which is exactly what happened before
  // this recursion was added, and it looks like an empty file rather than a bug.
  const MASTERS = new Set([key(ID.EBML), key(ID.SEGMENT), key(ID.INFO), key(ID.TRACKS), key(ID.TRACK_ENTRY), key(ID.VIDEO), key(ID.AUDIO)]);
  const walk = (from, to, visit) => {
    let at = from;
    while (at < to) {
      let id;
      let size;
      try {
        id = vint(buf, at, true);
        size = vint(buf, at + id.length, false);
      } catch {
        return at;
      }
      const idKey = key(buf.subarray(at, at + id.length));
      const body = at + id.length + size.length;
      const end = size.unknown ? to : Math.min(body + size.value, to, buf.length);
      visit(idKey, body, end);
      if (MASTERS.has(idKey) && body < end) walk(body, end, visit);
      at = size.unknown ? to : end;
    }
    return at;
  };

  let current = null;
  walk(0, Math.min(buf.length, limit), (id, body, end) => {
    // What the reader actually walked: an empty result and a reader that never entered anything look
    // identical from the outside, and this is the difference.
    if (out.seen.length < 60) out.seen.push(id + "@" + body + "+" + (end - body));
    switch (id) {
      case key(ID.DOC_TYPE): out.docType = text(buf, body, end - body); break;
      case key(ID.DOC_TYPE_VERSION): out.docTypeVersion = uint(buf, body, end - body); break;
      case key(ID.TIMECODE_SCALE): out.info.timecodeScaleNs = uint(buf, body, end - body); break;
      case key(ID.DURATION): out.info.durationRaw = float64(buf, body, end - body); break;
      case key(ID.MUXING_APP): out.info.muxingApp = text(buf, body, end - body); break;
      case key(ID.WRITING_APP): out.info.writingApp = text(buf, body, end - body); break;
      case key(ID.TITLE): out.info.title = text(buf, body, end - body); break;
      case key(ID.TRACK_ENTRY):
        current = { number: null, typeCode: null, codec: null, video: {}, audio: {} };
        out.tracks.push(current);
        break;
      case key(ID.TRACK_NUMBER): if (current) current.number = uint(buf, body, end - body); break;
      case key(ID.TRACK_TYPE): if (current) current.typeCode = uint(buf, body, end - body); break;
      case key(ID.CODEC_ID): if (current) current.codec = text(buf, body, end - body); break;
      case key(ID.CODEC_NAME): if (current && !current.codecName) current.codecName = text(buf, body, end - body); break;
      case key(ID.PIXEL_WIDTH): if (current) current.video.width = uint(buf, body, end - body); break;
      case key(ID.PIXEL_HEIGHT): if (current) current.video.height = uint(buf, body, end - body); break;
      case key(ID.SAMPLING_FREQUENCY): if (current) current.audio.sampleRate = float64(buf, body, end - body); break;
      case key(ID.CHANNELS): if (current) current.audio.channels = uint(buf, body, end - body); break;
      case key(ID.BIT_DEPTH): if (current) current.audio.bits = uint(buf, body, end - body); break;
      case key(ID.NAME): if (current && !current.name) current.name = text(buf, body, end - body); break;
      default: break;
    }
  });

  const scale = out.info.timecodeScaleNs || 1000000;
  if (typeof out.info.durationRaw === "number" && Number.isFinite(out.info.durationRaw)) {
    out.info.durationSec = Math.round((out.info.durationRaw * scale / 1e9) * 1000) / 1000;
  }
  const TYPES = { 1: "video", 2: "audio", 3: "complex", 16: "logo", 17: "subtitle", 18: "buttons", 32: "control" };
  out.tracks = out.tracks.map((t) => ({
    number: t.number,
    type: TYPES[t.typeCode] || `unknown(${t.typeCode})`,
    codec: t.codec,
    codecName: t.codecName,
    name: t.name,
    ...(t.video.width || t.video.height ? { width: t.video.width, height: t.video.height } : {}),
    ...(t.audio.sampleRate || t.audio.channels ? { sampleRate: t.audio.sampleRate, channels: t.audio.channels, bits: t.audio.bits } : {}),
  }));
  out.readBytes = Math.min(buf.length, limit);
  out.pending = "frames are not decoded: this reports the container's own description of its tracks";
  return out;
}

const isMain = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  const file = process.argv[2];
  if (!file) { console.log("usage: node matroska.mjs <file.mkv>"); process.exit(1); }
  const r = readMatroska(file);
  console.log(file);
  console.log(`  docType ${r.docType} v${r.docTypeVersion}, muxed by "${r.info.muxingApp || "?"}"`);
  console.log(`  duration ${r.info.durationSec ?? "?"}s (timecode scale ${r.info.timecodeScaleNs} ns)`);
  for (const t of r.tracks) console.log(`  track ${t.number} ${t.type} ${t.codec || "?"} ${t.width ? t.width + "x" + t.height : ""} ${t.sampleRate ? t.sampleRate + " Hz " + t.channels + " ch" : ""}`);
}
