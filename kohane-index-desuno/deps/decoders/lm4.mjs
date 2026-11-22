// The LM4 Mark II drumkit list (.txt), read natively.
//
// LM4's drumkits are plain text: a four-line header ("vst samples," / kit name / sample folder /
// vendor), then one line per velocity layer - pad number, MIDI note, sample name, file, velocity
// range, mute group and play mode - closed by a lone "-1". The samples are referenced by file name
// inside the named folder, so a kit is fully enumerable from the text alone, which is exactly what
// KID needs to index the content: every pad, its MIDI note, its sample and its velocity layers.
import fs from "node:fs";

const HEADER = "vst samples,";

export function parseLm4Kit(text) {
  const lines = String(text).split(/\r?\n/);
  if (lines[0].trim() !== HEADER) throw new Error("not an LM4 drumkit list (missing the 'vst samples,' header)");
  const name = (lines[1] || "").trim();
  const folder = (lines[2] || "").trim();
  const vendor = (lines[3] || "").trim();
  const pads = [];
  for (let i = 4; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    if (line === "-1") break;
    const f = line.split(",").map((s) => s.trim());
    if (f.length < 6 || !/^\d+$/.test(f[0])) continue;
    pads.push({
      pad: Number(f[0]),
      midi: Number(f[3]),
      name: f[4],
      sample: f[5],
      velLo: Number(f[6]),
      velHi: Number(f[7]),
      group: f.length > 12 ? Number(f[12]) || 0 : 0,
      mode: f.length > 13 ? Number(f[13]) || 0 : 0,
    });
  }
  if (!name) throw new Error("not an LM4 drumkit list (no kit name)");
  const midiMap = {};
  for (const p of pads) if (!(p.midi in midiMap)) midiMap[p.midi] = p.name;
  return {
    format: "lm4-drumkit", name, folder, vendor,
    pads, padCount: pads.length, samples: [...new Set(pads.map((p) => p.sample))].length,
    midiMap, midiNotes: Object.keys(midiMap).map(Number).sort((a, b) => a - b),
  };
}

export function readLm4Kit(file) {
  return Object.assign({ container: "lm4-drumkit", path: file }, parseLm4Kit(fs.readFileSync(file, "utf8")));
}

/** Walk a LM4 content directory: every drumkit list (plain and the wav-flavoured copies) with its
 *  kit name, and the sample totals underneath. Facts only - nothing is written. */
export function scanLm4Content(dir) {
  const kits = [];
  const samples = new Map();
  const walk = (d) => {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = d + "/" + e.name;
      if (e.isDirectory()) { walk(p); continue; }
      if (/\.(wav|aif)$/i.test(e.name)) samples.set(e.name.toLowerCase(), p);
      else if (/\.txt$/i.test(e.name)) {
        try {
          const kit = parseLm4Kit(fs.readFileSync(p, "utf8"));
          kits.push({ path: p, name: kit.name, folder: kit.folder, pads: kit.padCount, midiNotes: kit.midiNotes.length });
        } catch { /* not a drumkit list */ }
      }
    }
  };
  walk(dir);
  kits.sort((a, b) => a.name.localeCompare(b.name));
  return { dir, kits, kitCount: kits.length, sampleFiles: samples.size };
}

export const capabilities = {
  id: "lm4",
  kohaneName: "Kohane Bassline Drumkit List Reader",
  container: "lm4-drumkit",
  read: { level: "full", detail: "the drumkit list: kit name, sample folder, vendor, and every pad with its MIDI note, sample, velocity layers, mute group and play mode" },
  decode: { level: "none", detail: "the list references samples by name; the samples are plain WAV/AIFF read by the engine's own readers" },
  encode: { level: "none", detail: "writing kits is not a goal" },
  verifiedAgainst: "the selfcheck lm4 section: a synthesised kit parses pad for pad, foreign text is refused, and the real D:/LM4Mark2 content scans into kits and sample totals where present",
};
