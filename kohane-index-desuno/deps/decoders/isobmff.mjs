// MP4 / ISO base media files, read natively.
//
// KID's own decoder, registered in deps/manifest.json. The engine could already name this family from
// `ftyp`; this looks inside: how long the movie is, and what each track carries (handler, codec
// four-character code, pixel size, audio rate and channels).
//
// The rules are the ones the other readers follow. Values come out in the unit the format means (a
// duration in seconds, a resolution in pixels), and every box is stepped over by its own declared
// size - a box walker that guesses loses the thread of the file and then reports invented tracks.
import fs from "node:fs";
import { pathToFileURL } from "node:url";

const fourcc = (buf, at) => buf.toString("latin1", at, at + 4);

/** The boxes this reader understands. Everything else is stepped over by size. */
const CONTAINERS = new Set(["moov", "trak", "mdia", "minf", "stbl", "edts", "udta", "mvex"]);

const HANDLERS = { vide: "video", soun: "audio", text: "text", sbtl: "subtitle", meta: "metadata", tmcd: "timecode" };

function readBoxes(buf, from, to, visit) {
  let at = from;
  while (at + 8 <= to) {
    let size = buf.readUInt32BE(at);
    const type = fourcc(buf, at + 4);
    let header = 8;
    if (size === 1) {
      if (at + 16 > to) return at;
      size = Number(buf.readBigUInt64BE(at + 8));
      header = 16;
    } else if (size === 0) {
      size = to - at;                                  // "to the end of the file"
    }
    if (size < header || at + size > to) return at;     // malformed: stop rather than invent boxes
    visit(type, at + header, at + size);
    if (CONTAINERS.has(type)) readBoxes(buf, at + header, at + size, visit);
    at += size;
  }
  return at;
}

export const capabilities = {
  id: "isobmff",
  container: "mp4/mov/m4a/3gp/heic (ISO base media)",
  read: { level: "metadata", detail: "box walk through moov/trak/mdia/minf/stbl, mvhd and mdhd timing (version 0 and 1), tkhd pixel size, hdlr handler type, stsd codec fourcc plus audio rate and channels" },
  decode: { level: "none", detail: "elementary streams are not decoded: this reads what the file says about its tracks" },
  encode: { level: "none", detail: "no muxer yet" },
  verifiedAgainst: "a synthesised file with chosen values (3.000 s, avc1 1920x1080, mp4a 48 kHz stereo)",
};

export function readIsoBmff(file, options = {}) {
  const buf = fs.readFileSync(file);
  const limit = options.limit || 8 * 1024 * 1024;     // headers sit at the front; probing stays bounded

  const out = { container: "isobmff", brands: [], timescale: null, durationRaw: null, tracks: [], seen: [], decoded: false };
  const track = () => out.tracks[out.tracks.length - 1];
  const inTrack = () => out.tracks.length > 0 && !out.seen.includes("__trackClosed");

  readBoxes(buf, 0, Math.min(buf.length, limit), (type, body, end) => {
    if (out.seen.length < 80) out.seen.push(type);
    switch (type) {
      case "ftyp":
        out.brands.push({ major: fourcc(buf, body), minor: buf.readUInt32BE(body + 4) });
        for (let p = body + 8; p + 4 <= end; p += 4) out.brands.push(fourcc(buf, p));
        break;
      case "mvhd": {
        const version = buf[body];
        if (version === 0) {
          out.timescale = buf.readUInt32BE(body + 12);
          out.durationRaw = buf.readUInt32BE(body + 16);
        } else {
          out.timescale = buf.readUInt32BE(body + 20);
          out.durationRaw = Number(buf.readBigUInt64BE(body + 24));
        }
        break;
      }
      case "trak":
        out.tracks.push({ id: null, handler: null, codec: null, timescale: null, durationRaw: null });
        break;
      case "tkhd": {
        const version = buf[body];
        const t = track();
        if (!t) break;
        t.id = version === 0 ? buf.readUInt32BE(body + 12) : buf.readUInt32BE(body + 20);
        // width and height are 16.16 fixed-point at the end of the box
        const widthAt = end - 8;
        if (widthAt > body) {
          const width = buf.readUInt32BE(widthAt) / 65536;
          const height = buf.readUInt32BE(widthAt + 4) / 65536;
          if (width || height) { t.width = width; t.height = height; }
        }
        break;
      }
      case "mdhd": {
        const version = buf[body];
        const t = track();
        if (!t) break;
        if (version === 0) {
          t.timescale = buf.readUInt32BE(body + 12);
          t.durationRaw = buf.readUInt32BE(body + 16);
        } else {
          t.timescale = buf.readUInt32BE(body + 20);
          t.durationRaw = Number(buf.readBigUInt64BE(body + 24));
        }
        break;
      }
      case "hdlr": {
        const t = track();
        if (!t) break;
        t.handlerCode = fourcc(buf, body + 8);
        t.handler = HANDLERS[t.handlerCode] || t.handlerCode;
        break;
      }
      case "stsd": {
        const t = track();
        if (!t || end - body < 16) break;
        t.codec = fourcc(buf, body + 12);
        // for audio entries the sample rate and channel count sit in the sound description
        // In stsd the entry begins at body+8, so an audio sample entry's channel count sits at
        // body+32, its sample size at body+34 and its (16.16 fixed) sample rate at body+40. Reading
        // these eight bytes early lands on the entry's version/vendor fields and yields nonsense.
        if (t.handler === "audio" && end - body >= 44) {
          t.channels = buf.readUInt16BE(body + 32);
          t.bitsPerSample = buf.readUInt16BE(body + 34);
          t.sampleRate = buf.readUInt32BE(body + 40) / 65536;
        }
        if (t.handler === "video" && end - body >= 36) {
          t.width = t.width || buf.readUInt16BE(body + 32);
          t.height = t.height || buf.readUInt16BE(body + 34);
        }
        break;
      }
      default:
        break;
    }
  });

  if (out.timescale && typeof out.durationRaw === "number") {
    out.durationSec = Math.round((out.durationRaw / out.timescale) * 1000) / 1000;
  }
  for (const t of out.tracks) {
    if (t.timescale && typeof t.durationRaw === "number") {
      t.durationSec = Math.round((t.durationRaw / t.timescale) * 1000) / 1000;
    }
    delete t.durationRaw;
  }
  out.majorBrand = out.brands[0]?.major || null;
  out.readBytes = Math.min(buf.length, limit);
  out.pending = "samples are not decoded: this reports the file's own description of its tracks";
  return out;
}

const isMain = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  const file = process.argv[2];
  if (!file) { console.log("usage: node isobmff.mjs <file.mp4>"); process.exit(1); }
  const r = readIsoBmff(file);
  console.log(file);
  console.log(`  brand ${r.majorBrand}, ${r.brands.length} brand(s), duration ${r.durationSec ?? "?"}s`);
  for (const t of r.tracks) console.log(`  track ${t.id} ${t.handler || "?"} ${t.codec || "?"} ${t.width ? t.width + "x" + t.height : ""} ${t.sampleRate ? t.sampleRate + " Hz " + t.channels + " ch" : ""} ${t.durationSec ?? "?"}s`);
}
