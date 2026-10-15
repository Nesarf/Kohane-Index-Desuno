// Adopted-plugin inventory scanner (read-only, static).
//
// Purpose: build ONE kohane-owned catalogue of the plugin binaries this machine carries, so the
// adoption step does not depend on any vendor tool. Nothing is loaded, linked or executed - the
// scanner only reads file headers, the export-name region and the version strings.
//
//   node analyze-binaries.mjs [--json out.json] [--md out.md]
//
// Output per binary: container kind (vst3/clap/vst2/standalone), PE arch, exported ABI entry
// points, version strings, and the functional words found in its own name. The functional words
// are what the kohane plugin directory is built from; vendor strings stay inside this research
// catalogue and never reach the product.
import fs from "node:fs";
import path from "node:path";

const ROOTS = [
  { id: "vst3-a", kind: "vst3", dir: "C:/Program Files/Common Files/VST3/iZotope" },
  { id: "vst3-m", kind: "vst3", dir: "C:/Program Files/Common Files/VST3/MiniMeters" },
  { id: "clap-m", kind: "clap", dir: "C:/Program Files/Common Files/CLAP/MiniMeters" },
  { id: "vst2-a", kind: "vst2", dir: "C:/Program Files/Steinberg/VstPlugins/iZotope" },
];
const STANDALONE = [
  "C:/Program Files/MinimMeters/MiniMeters.exe",
  "C:/Program Files/MiniMeters/MiniMeters.exe",
  "C:/Program Files/iZotope/Ozone 9/win64/iZotope Ozone 9.exe",
];

// Export names that identify a plugin ABI. Checked as ASCII in the export-name region.
const ABI_MARKERS = ["VSTPluginMain", "GetPluginFactory", "clap_entry", "main", "GetPluginFactory2"];
// Generic function words: an adopted capability is named for what it DOES. Ordered longest-first
// so "Dynamic EQ" wins over "EQ".
const FUNCTION_VOCAB = [
  "Dynamic EQ", "Master Rebalance", "Low End Focus", "Spectral Shaper", "Breath Control", "Match EQ",
  "Vintage Tape", "Vintage Compressor", "Vintage Limiter", "Vintage EQ", "Vocal Synth",
  "Equalizer", "Maximizer", "Compressor", "Limiter", "Exciter", "Imager", "Dynamics", "De-esser",
  "Transient", "Saturator", "Oscilloscope", "Spectrogram", "Stereometer", "Loudness", "Spectrum",
  "Waveform", "Rebalance", "Vocoder", "Granular", "Sampler", "Reverb", "Delay", "Chorus",
  "Flanger", "Phaser", "Filter", "Gate", "Expander", "Meter", "Analyzer", "VU", "EQ", "Tape",
  "Vinyl", "Pitch", "Width", "Synth", "Server", "Control", "Relay", "Insight", "Nectar",
];

const KNOWN_EXT = new Set([".vst3", ".clap", ".dll", ".exe", ".component"]);

function walk(dir, out = []) {
  let ents;
  try {
    ents = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of ents) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      // A .vst3 bundle is a directory: descend, but keep the bundle name as the plugin name.
      walk(full, out);
    } else if (e.isFile() && KNOWN_EXT.has(path.extname(e.name).toLowerCase())) {
      out.push(full);
    }
  }
  return out;
}

// Minimal PE reader: arch + whether the export name table mentions a plugin ABI entry point.
function readPe(file) {
  const out = { pe: false, arch: null, exports: [], strings: {} };
  let fd;
  try {
    fd = fs.openSync(file, "r");
    const head = Buffer.alloc(4096);
    const n = fs.readSync(fd, head, 0, head.length, 0);
    if (n < 64 || head.readUInt16LE(0) !== 0x5a4d) return out; // 'MZ'
    const peOff = head.readUInt32LE(0x3c);
    if (head.toString("latin1", peOff, peOff + 4) !== "PE\0\0") return out;
    out.pe = true;
    const machine = head.readUInt16LE(peOff + 4);
    out.arch = machine === 0x8664 ? "x64" : machine === 0x14c ? "x86" : `0x${machine.toString(16)}`;

    // Export names live in a region described by the data directory; instead of mapping sections
    // the whole file is scanned for the ABI entry names (they are plain ASCII in that table).
    const buf = fs.readFileSync(file);
    for (const m of ABI_MARKERS) {
      if (buf.includes(Buffer.from(m, "latin1"))) out.exports.push(m);
    }
    // Version resource: keys and values are UTF-16LE. Read the value that follows each key.
    const utf16 = buf.toString("utf16le");
    for (const key of ["ProductName", "FileDescription", "FileVersion", "ProductVersion", "CompanyName", "OriginalFilename"]) {
      const at = utf16.indexOf(key);
      if (at < 0) continue;
      const after = utf16.slice(at + key.length, at + key.length + 160).replace(/^\u0000+/, "");
      const value = after.split("\u0000").find((s) => /[\x20-\x7e]/.test(s || "")) || "";
      if (value) out.strings[key] = value.trim().slice(0, 80);
    }
  } catch {
    return out;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
  }
  return out;
}

function functionalWords(name) {
  const clean = name.replace(/\.(vst3|clap|dll|exe|component)$/i, "");
  const hits = [];
  for (const w of FUNCTION_VOCAB) {
    const re = new RegExp(`(^|[^A-Za-z])${w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^A-Za-z]|$)`, "i");
    if (re.test(clean) && !hits.some((h) => h.toLowerCase().includes(w.toLowerCase()))) hits.push(w);
  }
  return hits;
}

const rows = [];
for (const r of ROOTS) {
  for (const f of walk(r.dir)) {
    const st = fs.statSync(f);
    const pe = readPe(f);
    const base = path.basename(f);
    rows.push({
      root: r.id,
      kind: r.kind,
      file: f.replace(/\\/g, "/"),
      name: base,
      mb: +(st.size / 1048576).toFixed(2),
      arch: pe.arch,
      abi: pe.exports,
      version: pe.strings.FileVersion || null,
      product: pe.strings.ProductName || pe.strings.FileDescription || null,
      words: functionalWords(base),
    });
  }
}
for (const f of STANDALONE) {
  if (!fs.existsSync(f)) continue;
  const st = fs.statSync(f);
  const pe = readPe(f);
  rows.push({
    root: "standalone", kind: "standalone", file: f.replace(/\\/g, "/"), name: path.basename(f),
    mb: +(st.size / 1048576).toFixed(2), arch: pe.arch, abi: pe.exports,
    version: pe.strings.FileVersion || null, product: pe.strings.ProductName || pe.strings.FileDescription || null,
    words: functionalWords(path.basename(f)),
  });
}

rows.sort((a, b) => a.root.localeCompare(b.root) || a.name.localeCompare(b.name));
const out = {
  scannedAt: new Date().toISOString(),
  roots: ROOTS.map((r) => r.id),
  total: rows.length,
  byKind: rows.reduce((a, r) => ((a[r.kind] = (a[r.kind] || 0) + 1), a), {}),
  rows,
};
const jsonOut = process.argv.includes("--json") ? process.argv[process.argv.indexOf("--json") + 1] : "catalog.json";
fs.writeFileSync(jsonOut, JSON.stringify(out, null, 2), "utf8");

const md = [
  "# Adopted-plugin catalogue (static, read-only)",
  "",
  `Scanned: ${out.scannedAt} - ${out.total} binaries (${Object.entries(out.byKind).map(([k, v]) => `${k} ${v}`).join(", ")})`,
  "",
  "| kind | binary | MB | arch | ABI entries | version | functional words |",
  "|---|---|---:|---|---|---|---|",
  ...rows.map((r) => `| ${r.kind} | ${r.name} | ${r.mb} | ${r.arch || "-"} | ${(r.abi || []).join(", ") || "-"} | ${r.version || "-"} | ${(r.words || []).join(", ") || "-"} |`),
  "",
].join("\n");
const mdOut = process.argv.includes("--md") ? process.argv[process.argv.indexOf("--md") + 1] : "catalog.md";
fs.writeFileSync(mdOut, md, "utf8");

console.log(`binaries: ${out.total}  ${JSON.stringify(out.byKind)}`);
for (const r of rows) console.log(`${r.kind.padEnd(11)} ${r.name.padEnd(38)} ${String(r.mb).padStart(6)}MB ${String(r.arch).padEnd(4)} [${(r.abi || []).join(",")}] v=${r.version || "-"} words=[${(r.words || []).join(",")}]`);
console.log(`\nwrote ${jsonOut} and ${mdOut}`);
