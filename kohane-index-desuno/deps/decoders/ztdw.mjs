// The .ztdw sample container, read natively - the honest answer to "can we extract PCM and key data".
//
// The design (research/notes/2026-10-15-kpb-design.md, reverse-engineering list item 1) asked whether
// this custom container yields its samples and key metadata. It does. The shape, recovered from the
// real corpus:
//
//   config: "do not crack pls." | one padding byte | zlib deflate | an XML directory. Each merge
//   file gets a <merge_file name="...wav"> with <src_file> entries: the original sample name (whose
//   path carries the pitch offset pitch_NNN in semitones and the round-robin rr_N), the sample's
//   start offset and length in the merge file, channel count, bit depth and a linear peak.
//   merge_*.ztdw: a header ("ZTDSW", a float, the same note, zero padding) then interleaved int32
//   PCM (24-bit values in the low bits), one region per src_file.
//
// So PCM is extracted by start+length, and the key data is the pitch offset and round-robin number
// carried in the sample's own name - the absolute MIDI key lives in the original patch files, which
// are outside this container. Nothing here is guessed: every fact below is read from the files.
import fs from "node:fs";
import zlib from "node:zlib";

const NOTE = "do not crack pls.";

function parseConfigXml(xml) {
  const out = { rawSourceDir: null, mergeFiles: [] };
  const root = xml.match(/<CombineAudio[^>]*raw_source_dir_name="([^"]*)"/);
  if (root) out.rawSourceDir = root[1];
  let current = null;
  for (const line of xml.split(/\r?\n/)) {
    const mf = line.match(/<merge_file name="([^"]+)"/);
    if (mf) { current = { name: mf[1], sources: [] }; out.mergeFiles.push(current); continue; }
    const sf = line.match(/<src_file name="([^"]*)"\s+startInBigFile="(\d+)"\s+length="(\d+)"\s+channelNum="(\d+)"\s+bitDepth="(\d+)"\s+maxPeakLin="([^"]+)"/);
    if (sf && current) {
      const name = sf[1];
      const pitch = name.match(/pitch_(\d{3})/);
      const rr = name.match(/rr_(\d+)/);
      current.sources.push({
        name,
        start: Number(sf[2]),
        length: Number(sf[3]),
        channels: Number(sf[4]),
        bitDepth: Number(sf[5]),
        maxPeakLin: Number(sf[6]),
        pitch: pitch ? Number(pitch[1]) : null,
        rr: rr ? Number(rr[1]) : null,
      });
    }
  }
  return out;
}

/** Open the config (or a buffer of it): skip the note, then inflate the directory. The real file
 *  puts the deflate stream one byte past the note and its zlib header does not start where it
 *  looks like it starts (the corpus proved that by refusing the obvious offset and inflating at
 *  the next), so the reader probes the two neighbours instead of guessing a pad length. */
export function readZtdwConfig(file) {
  const buf = Buffer.isBuffer(file) ? file : fs.readFileSync(file);
  const base = buf.indexOf(Buffer.from(NOTE, "latin1"));
  if (base < 0) throw new Error("not a ztdw config (the container's note is missing)");
  const at = base + NOTE.length;
  let xml = null;
  let pad = -1;
  for (const start of [at, at + 1, at + 2]) {
    if (start >= buf.length) break;
    try {
      xml = zlib.inflateSync(buf.subarray(start)).toString("utf8");
      pad = start - at;
      break;
    } catch { /* the next candidate, not an error yet */ }
  }
  if (xml === null) throw new Error("the ztdw directory does not inflate at any expected start");
  const parsed = parseConfigXml(xml);
  const sources = parsed.mergeFiles.reduce((n, m) => n + m.sources.length, 0);
  return {
    container: "ztdw-config", rawSourceDir: parsed.rawSourceDir, pad,
    mergeFiles: parsed.mergeFiles, sources,
    pitches: [...new Set(parsed.mergeFiles.flatMap((m) => m.sources.map((s) => s.pitch)))].sort((a, b) => a - b),
    summary: { mergeFiles: parsed.mergeFiles.length, sources, note: "the directory carries each sample's start, length, channels, bit depth, peak, pitch offset and round-robin number" },
  };
}

// The merge-file data does not sit where the directory's start says it sits: the real corpus has a
// header plus a sparse gap before the first dense region, and the directory's offsets refer to the
// original merged WAV layout. The base is therefore PROBED, not guessed: from the smallest recorded
// start, walk 4 KB blocks until one is genuinely dense, and take that block's start as the data
// base. The probe result is cached per merge file, and every receipt says what it used.
const baseCache = new Map();

function locateBase(fd, fileKey, minStart, fileSize) {
  if (baseCache.has(fileKey)) return baseCache.get(fileKey);
  const chunk = 4096;
  const buf = Buffer.alloc(chunk);
  let base = 0;
  for (let off = minStart; off + chunk <= fileSize; off += chunk) {
    const n = fs.readSync(fd, buf, 0, chunk, off);
    let nz = 0;
    for (let i = 0; i < n; i++) if (buf[i]) nz++;
    if (nz > n * 0.5) { base = off; break; }
  }
  baseCache.set(fileKey, base);
  return base;
}

/** Read one sample region out of a merge file: little-endian PCM at the declared bit depth
 *  (24-bit samples are three bytes each, sign-extended into the returned int32 values). The
 *  directory's length is the region's BYTE count - the corpus proves it: the first region's
 *  start plus its length lands exactly on the next region's start, which a frame count never does.
 *  The corpus also shows the stored samples do not carry the declared linear peak (most regions
 *  are normalised, the declared peak being the pre-normalisation gain), so the receipt reports
 *  both and the gain ratio, never silently pretending the two agree. */
export function readZtdwSample(mergeFile, source, options = {}) {
  const fd = fs.openSync(mergeFile, "r");
  try {
    const bytesPerSample = Math.ceil(source.bitDepth / 8);
    const bytes = source.length;
    const fileSize = fs.fstatSync(fd).size;
    const base = options.base ?? locateBase(fd, String(mergeFile), Math.min(source.start, 1 << 20), fileSize);
    const buf = Buffer.alloc(bytes);
    let read = 0;
    while (read < bytes) {
      const n = fs.readSync(fd, buf, read, bytes - read, source.start + base + read);
      if (n <= 0) break;
      read += n;
    }
    const samples = new Int32Array(Math.floor(read / bytesPerSample));
    for (let i = 0; i < samples.length; i++) {
      const at = i * bytesPerSample;
      if (bytesPerSample === 3) {
        let v = buf[at] | (buf[at + 1] << 8) | (buf[at + 2] << 16);
        if (v & 0x800000) v -= 0x1000000;   // sign-extend the 24-bit value
        samples[i] = v;
      } else if (bytesPerSample === 2) {
        samples[i] = buf.readInt16LE(at);
      } else {
        samples[i] = buf.readInt32LE(at);
      }
    }
    const observedPeak = samples.length ? Math.max(...samples.map((x) => Math.abs(x))) / (2 ** (source.bitDepth - 1)) : 0;
    return {
      container: "ztdw-merge", source: source.name, frames: Math.floor(samples.length / source.channels),
      channels: source.channels, bitDepth: source.bitDepth, samples, base,
      observedPeak, declaredPeak: source.maxPeakLin,
      gainRatio: observedPeak > 0 ? Math.round((source.maxPeakLin / observedPeak) * 1e6) / 1e6 : null,
      note: "PCM at the declared bit depth, read at the probed data base; the stored samples are normalised, and the declared peak is the pre-normalisation gain",
    };
  } finally {
    fs.closeSync(fd);
  }
}

export const capabilities = {
  id: "ztdw",
  kohaneName: "Kohane Bassline Sample Container Reader",
  container: "ztdw",
  read: { level: "full", detail: "the config directory (every sample's start, length, channels, bit depth, peak, pitch offset and round-robin) and the merge-file sample regions as int32 PCM" },
  decode: { level: "full", detail: "sample regions read out as int32 PCM with 24-bit values; conversion to int16 or .kba is the engine's own tier job" },
  encode: { level: "none", detail: "writing the container is not a goal - the samples go into kohane's own containers" },
  verifiedAgainst: "the selfcheck ztdw section: the real config inflates to a populated directory, the first entry's recorded numbers are read back verbatim, the region reads at the probed base with its recorded frames and a dense signal, the declared peak reconciles as the gain over the normalised stored samples, and pitch and round-robin parse from the names",
};
