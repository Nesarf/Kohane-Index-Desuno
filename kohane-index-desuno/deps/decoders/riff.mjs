// RIFF containers, read natively: AVI video and WAVE audio live in the same chunked layout.
//
// KID's own decoder, registered in deps/manifest.json. RIFF is deliberately simple - a form type and
// a chain of chunks, each with its own size, padded to an even boundary - and the reader follows
// exactly that, stepping over anything it does not know by the size the chunk declares.
//
// The engine already decodes WAVE samples for envelopes; this reports the container's description
// (rate, channels, duration) for the same files, so the two views agree instead of competing.
import fs from "node:fs";
import { pathToFileURL } from "node:url";

export const capabilities = {
  id: "riff",
  kohaneName: "Kohane Bassline Wave/Movie Reader (RIFF)",
  container: "riff (avi / wav / webp)",
  read: { level: "metadata", detail: "form type, chunk chain with even-boundary padding, AVI main header (frame timing, stream count, size) and per-stream headers (type, handler, scale/rate, video size, audio channels and bit depth), WAVE format and data sizes" },
  decode: { level: "partial", detail: "PCM WAVE samples are decoded by the engine's own readers (op=peaks, op=pcm, op=play); AVI elementary streams are not decoded" },
  encode: { level: "partial", detail: "a canonical WAVE can be staged for the system player; AVI writing does not exist" },
  verifiedAgainst: "synthesised AVI and WAVE files whose values were chosen in advance",
};

const fourcc = (buf, at) => buf.toString("latin1", at, at + 4);

function walkChunks(buf, from, to, visit) {
  let at = from;
  while (at + 8 <= to) {
    const id = fourcc(buf, at);
    const size = buf.readUInt32LE(at + 4);
    const body = at + 8;
    if (size < 0 || body + size > to) break;     // malformed: stop rather than invent chunks
    visit(id, body, body + size);
    at = body + size + (size % 2);               // chunks are padded to an even boundary
  }
  return at;
}

const LIST_FORMS = new Set(["hdrl", "strl", "movi", "INFO", "odml", "strd"]);

export function readRiff(file, options = {}) {
  const buf = fs.readFileSync(file);
  if (buf.length < 12 || fourcc(buf, 0) !== "RIFF") throw new Error("not a RIFF file");
  const form = fourcc(buf, 8);
  const limit = Math.min(buf.length, options.limit || 8 * 1024 * 1024);

  const out = { container: "riff", form: form.trim(), size: buf.readUInt32LE(4) + 8, chunks: [], seen: [], tracks: [] };
  const walk = (from, to) => walkChunks(buf, from, to, (id, body, end) => {
    if (out.seen.length < 60) out.seen.push(id);
    if (id === "LIST") {
      const listType = fourcc(buf, body);
      out.chunks.push(`LIST:${listType}`);
      if (LIST_FORMS.has(listType)) walk(body + 4, end);
      return;
    }
    out.chunks.push(id);

    if (id === "avih") {
      const microSecPerFrame = buf.readUInt32LE(body);
      const totalFrames = buf.readUInt32LE(body + 16);
      const streams = buf.readUInt32LE(body + 24);
      out.avi = {
        microSecPerFrame,
        totalFrames,
        streams,
        width: buf.readUInt32LE(body + 32),
        height: buf.readUInt32LE(body + 36),
        frameRate: microSecPerFrame ? Math.round((1e6 / microSecPerFrame) * 1000) / 1000 : null,
        durationSec: microSecPerFrame && totalFrames ? Math.round((totalFrames * microSecPerFrame / 1e6) * 1000) / 1000 : null,
      };
    } else if (id === "strh") {
      out.tracks.push({
        type: fourcc(buf, body).trim(),
        handler: fourcc(buf, body + 4).trim(),
        scale: buf.readUInt32LE(body + 20),
        rate: buf.readUInt32LE(body + 24),
        length: buf.readUInt32LE(body + 32),
      });
      const t = out.tracks[out.tracks.length - 1];
      t.durationSec = t.scale && t.rate ? Math.round((t.length * t.scale / t.rate) * 1000) / 1000 : null;
    } else if (id === "strf") {
      const t = out.tracks[out.tracks.length - 1];
      if (!t) return;
      if (t.type === "vids") {
        t.width = buf.readInt32LE(body + 4);
        t.height = buf.readInt32LE(body + 8);
        t.bitsPerPixel = buf.readUInt16LE(body + 14);
      } else if (t.type === "auds") {
        t.formatTag = buf.readUInt16LE(body);
        t.channels = buf.readUInt16LE(body + 2);
        t.sampleRate = buf.readUInt32LE(body + 4);
        t.bitsPerSample = buf.readUInt16LE(body + 14);
      }
    } else if (id === "fmt ") {
      out.wave = {
        formatTag: buf.readUInt16LE(body),
        channels: buf.readUInt16LE(body + 2),
        sampleRate: buf.readUInt32LE(body + 4),
        bitsPerSample: buf.readUInt16LE(body + 14),
      };
    } else if (id === "data" && out.wave) {
      const bytes = end - body;
      const frameBytes = (out.wave.channels * out.wave.bitsPerSample) / 8;
      out.wave.dataBytes = bytes;
      out.wave.frames = frameBytes ? Math.floor(bytes / frameBytes) : null;
      out.wave.durationSec = frameBytes && out.wave.sampleRate
        ? Math.round((bytes / frameBytes / out.wave.sampleRate) * 1000) / 1000
        : null;
    }
  });

  walk(12, limit);
  out.readBytes = Math.min(buf.length, limit);
  out.pending = "AVI elementary streams are not decoded: this reports the headers' own description; WAVE samples go through the engine's PCM readers";
  return out;
}

const isMain = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  const file = process.argv[2];
  if (!file) { console.log("usage: node riff.mjs <file.avi|file.wav>"); process.exit(1); }
  const r = readRiff(file);
  console.log(file);
  console.log(`  form ${r.form}, chunks ${r.chunks.join(" ")}`);
  if (r.avi) console.log(`  avi: ${r.avi.width}x${r.avi.height}, ${r.avi.frameRate} fps, ${r.avi.totalFrames} frames, ${r.avi.durationSec}s`);
  for (const t of r.tracks) console.log(`  track ${t.type} ${t.handler} ${t.width ? t.width + "x" + t.height : ""} ${t.sampleRate ? t.sampleRate + " Hz " + t.channels + " ch" : ""} ${t.durationSec ?? "?"}s`);
  if (r.wave) console.log(`  wave: ${r.wave.sampleRate} Hz ${r.wave.channels} ch ${r.wave.bitsPerSample} bit, ${r.wave.durationSec}s`);
}
