// kohane-index-desuno - Cross-harness shared core (harness-independent).
//
// This module is the pure-Node core of kohane-index-desuno. It contains the
// library storage/retrieval logic, a 108-entry file-signature table with declared-vs-actual
// forgery checks, per-install format personalisation (library_format), AES-256-GCM payload
// encryption, ADB device management (legitimate developer subset), system encoding detection,
// media fingerprints, and a `TOOLS` registry of the 12 model-facing tools as plain async
// functions.
//
// It is consumed by two entry points, both of which share one implementation:
//   - mcp/index.mjs  : an MCP stdio server (@modelcontextprotocol/sdk).
//   - cli/index.mjs  : a command-line driver (node cli/index.mjs <tool> [args]).
//
// A narrower DSH-only edition of this core exists as a separate package and is used as a READ-ONLY
// reference for this build: this tree never imports from it, never writes to it, and is never
// overwritten by it. The read-only cross-check lives in tools/reference-check.mjs.
//
// There is NO @deepseek-ai/dsh-tools import here: this file must stay pure Node so it can
// be reused outside a DSH host. Register the media providers once per process by calling
// `registerDefaultMediaProvider()` when you bootstrap an entry point.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes, createHash, createCipheriv, createDecipheriv, hkdfSync } from "node:crypto";
import nodeZlib from "node:zlib";
import { fileURLToPath } from "node:url";
import { readFlac } from "../deps/decoders/flac.mjs";
import { readMatroska } from "../deps/decoders/matroska.mjs";
import { readIsoBmff } from "../deps/decoders/isobmff.mjs";
import { readOgg } from "../deps/decoders/ogg.mjs";
import { readRiff } from "../deps/decoders/riff.mjs";
import { encodeFlac, encodeWav16 } from "../deps/decoders/flac-encoder.mjs";
import { decodeExternally, resolveExternalDecoder } from "../deps/external.mjs";
import { readUnityAsset } from "../deps/decoders/unity-asset.mjs";
import { mediaCapabilities } from "../deps/media-registry.mjs";
// Runtime portability: worker threads are the one thing a runtime may not provide, so they are resolved
// here instead of imported outright. A runtime without them loads this module and takes the
// single-threaded path; nothing else in the core depends on a specific runtime.
const { isMainThread, parentPort, workerData, Worker: WorkerCtor } = await (async () => {
  try {
    return await import("node:worker_threads");
  } catch {
    return { isMainThread: true, parentPort: null, workerData: undefined, Worker: null };
  }
})();
const WORKERS_AVAILABLE = typeof WorkerCtor === "function";

// Field length caps: guard against overlong/malformed input polluting the library
// (applies to name/description/summary/source/path).
const MAX_LEN = { name: 200, source: 300, path: 500, description: 1000, summary: 4000 };

function clampField(v, key) {
  if (typeof v !== "string") return "";
  const max = MAX_LEN[key] || 500;
  return v.length > max ? v.slice(0, max) : v;
}

// DSH home: library storage root. node_modules may be read-only or cleaned on update,
// so the library always lives under DSH_HOME.
function dshHome() {
  return process.env.DSH_HOME || path.join(os.homedir(), ".dsh");
}

function libraryDir() {
  return path.join(dshHome(), "library");
}

// Index file: a JSON manifest + objects array.
function indexFile() {
  return path.join(libraryDir(), "index.json");
}

// Directory for raw object payloads (optional; keeps index.json lean).
function payloadDir() {
  return path.join(libraryDir(), "objects");
}

// Allowed object types (enum-like set, prevents arbitrary strings polluting schema).
const OBJ_TYPES = new Set([
  "tool",          // executable tool / script / program
  "plugin",        // DSH plugin / extension
  "env",           // environment fact (path, variable, service, port)
  "file",          // file / folder (artifact, output dir)
  "product",       // product / deliverable (build, release)
  "knowledge",     // knowledge (doc, note, conclusion)
  "persona",       // persona / character card (immutable file)
  "image",         // image (immutable file)
  "document",      // document (immutable file)
  "table",         // table (immutable file)
  "audio",         // audio (immutable file)
  "work_record",   // work record (session, log, daily report, runtime state)
  "log",           // log (immutable file)
  "workspace",     // a workspace itself
  "reference",     // external reference / dependency (cross-directory external object)
  "other",         // fallback
]);

// Type -> change-disposition policy:
//   "verify"  : auto-verifiable (tool/plugin/env). On content change, record it and
//               notify DSH to check, outputting the result to the user.
//   "confirm" : immutable-file class (persona/image/document/table/audio/work_record/
//               log/file). On content change, do NOT auto-overwrite; force the user to
//               confirm the change or explain it.
const DISPOSITION = {
  tool: "verify",
  plugin: "verify",
  env: "verify",
  persona: "confirm",
  image: "confirm",
  document: "confirm",
  table: "confirm",
  audio: "confirm",
  work_record: "confirm",
  log: "confirm",
  file: "confirm",
  product: "confirm",
  knowledge: "confirm",
  workspace: "confirm",
  reference: "confirm",
  other: "confirm",
};

function dispositionFor(type) {
  return DISPOSITION[type] || "confirm";
}

// Change detection: fingerprint the substantive fields (everything except type/name/source).
function fingerprint(o) {
  return JSON.stringify([o.path || "", o.description || "", o.summary || "", (o.tags || []).slice().sort(), (o.related || []).slice().sort()]);
}

// Fingerprint that handles sensitive objects (stored as an encrypted __content meta, whose
// public fields carry no path/description/summary/tags). Decrypt before fingerprinting so a
// sensitive object is compared by its real content rather than an always-equal empty string.
function fingerprintObject(o) {
  if (o && o.__content && o.__content.sens === 1) {
    const plain = decryptSensitive(o.__content);
    if (plain && !plain.__decryptError) return fingerprint(plain);
    return "";
  }
  return fingerprint(o);
}

// ---------- [1] Media evidence: pluggable media providers (inspired by FreeMote Plugins) ----------
// Each media type can go through a dedicated analyzer (provider); adding a new format only
// requires registering a new provider without touching core logic.
// Provider shape: { match(ext) -> bool, async analyze(filePath) -> {ok, detail} }
const MEDIA_PROVIDERS = [];

// Register built-in media analysis engines: ffprobe (same ffmpeg family used by
// (a media player's own recognition tables, present locally) + a media metadata tool.
// Both are generic fallback providers (match always true); mediaFingerprint tries each
// in order and returns on the first success.
function registerDefaultMediaProvider() {
  // 1) ffprobe engine (codecs/duration/streams) - resolve across platforms.
  const ffprobe = resolveTool(
    "FFPROBE_PATH",
    [
      "D:\\ffmpeg-8.1.1-essentials_build\\bin\\ffprobe.exe",           // Windows (this machine)
      "/usr/bin/ffprobe", "/usr/local/bin/ffprobe", "/opt/homebrew/bin/ffprobe", "/opt/local/bin/ffprobe", "/snap/bin/ffprobe", // macOS/Linux
    ],
    "ffprobe"
  );
  MEDIA_PROVIDERS.push({
    name: "ffprobe",
    match: () => true,
    async analyze(filePath) {
      if (!ffprobe) return { ok: false, detail: "ffprobe not available" };
      const r = await runSilent(ffprobe, ["-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", filePath], { timeoutMs: 20000 });
      if (!r.ok || !r.out) return { ok: false, detail: r.err.slice(0, 120) || "ffprobe produced no output" };
      try {
        const j = JSON.parse(r.out);
        const fmt = j.format || {};
        const streams = j.streams || [];
        const v = streams.filter((s) => s.codec_type === "video");
        const a = streams.filter((s) => s.codec_type === "audio");
        const format = fmt.format_name || "";
        const duration = fmt.duration ? ` ${Math.round(parseFloat(fmt.duration))}s` : "";
        return { ok: true, detail: `[ffprobe] ${format} ${v.length}V/${a.length}A${duration}` };
      } catch (e) {
        return { ok: false, detail: String(e && e.message || e).slice(0, 120) };
      }
    },
  });
  // 2) MediaInfo engine (detailed General metadata) - resolve across platforms.
  const exe = resolveTool(
    "MEDIAINFO_PATH",
    [
      "E:\\DaShaoHuo\\downloads\\mediainfo-cli\\MediaInfo.exe",        // Windows (this machine)
      "/usr/bin/mediainfo", "/usr/local/bin/mediainfo", "/opt/homebrew/bin/mediainfo", "/opt/local/bin/mediainfo", "/snap/bin/mediainfo", // macOS/Linux
    ],
    "mediainfo"
  );
  MEDIA_PROVIDERS.push({
    name: "mediainfo",
    match: () => true,
    async analyze(filePath) {
      if (!exe) return { ok: false, detail: "MediaInfo CLI not available" };
      if (!fs.existsSync(filePath)) return { ok: false, detail: "path does not exist, skipping media evidence" };
      const r = await runSilent(exe, ["--Output=JSON", filePath], { timeoutMs: 20000 });
      if (!r.ok || !r.out) return { ok: false, detail: r.err.slice(0, 120) || "analysis produced no output" };
      try {
        const j = JSON.parse(r.out);
        const media = j && j.media;
        const tracks = (media && media.track) || [];
        const gen = tracks.find((t) => t["@type"] === "General") || {};
        const format = gen.Format || "?";
        const profile = gen.Format_Profile || "";
        const video = gen.VideoCount || "0";
        const audio = gen.AudioCount || "0";
        const ext = gen.FileExtension || "";
        return { ok: true, detail: `[MediaInfo] ${format}${profile ? `(${profile})` : ""} ${video}V/${audio}A ${ext ? `[${ext}]` : ""}${gen.Duration ? ` ${gen.Duration}` : ""}` };
      } catch (e) {
        return { ok: false, detail: String(e && e.message || e).slice(0, 120) };
      }
    },
  });
}

// Media analysis entry: try extension-specific provider, then all generic providers,
// then fall back to file-header signature sniffing. Returns { ok, detail }.
async function mediaFingerprint(filePath) {
  if (!filePath) return { ok: false, detail: "no path" };
  if (!fs.existsSync(filePath)) return { ok: false, detail: "path does not exist, skipping media evidence" };
  const ext = path.extname(filePath).toLowerCase().replace(".", "");
  // 1) extension-specific provider
  const specific = MEDIA_PROVIDERS.find((p) => p.match(ext));
  if (specific) {
    const r = await specific.analyze(filePath);
    if (r.ok) return r;
  }
  // 2) generic providers (ffprobe, mediainfo) in order
  for (const p of MEDIA_PROVIDERS.filter((x) => x.match(true))) {
    const r = await p.analyze(filePath);
    if (r.ok) return r;
  }
  // 3) file-header signature fallback (7-Zip/Bandizip approach)
  const sniff = (typeof sniffFileType === "function") ? sniffFileType(filePath) : null;
  if (sniff) return { ok: true, detail: `[signature] ${sniff.format} (${sniff.note})` };
  return { ok: false, detail: "unrecognized (no ffprobe/MediaInfo output and unknown signature)" };
}

// ---------- [1b] Unified external analyzer invocation (Unity / Blender / ...) ----------
// The media providers above proved the pattern: a provider declares what it handles and how to
// invoke its tool, while the core owns invocation, timeouts and result normalisation. This
// section generalises that into one ANALYZER registry so heavier project-level analyzers (Unity
// projects, Blender scenes, and later user-registered extractors) plug into a single entry
// point: analyzeObject(). Providers never open a desktop session and never write to the target.
//
// Provider shape:
//   { name, kind, match(target) -> bool, async analyze(target, opts) -> {ok, kind, fields, detail} }
// `target` is a file or directory path. `opts.deep` opts into heavyweight analysis (e.g. running
// the Blender CLI); light providers ignore it.
const ANALYZER_PROVIDERS = [];
let analyzersRegistered = false;

// Blender .blend header: "BLENDER" (7 bytes) + pointer size ('_' = 32-bit, '-' = 64-bit)
// + endianness ('v' = little, 'V' = big) + three ASCII digits of the version ("404" -> 4.04).
function readBlendHeader(filePath) {
  const head = readHeader(filePath, 16);
  if (!head || head.length < 12) return null;
  if (head.slice(0, 7).toString("latin1") !== "BLENDER") return null;
  const ptr = String.fromCharCode(head[7]);
  const endian = String.fromCharCode(head[8]);
  const raw = head.slice(9, 12).toString("latin1");
  if (!/^\d{3}$/.test(raw)) return null;
  return {
    version: `${parseInt(raw[0], 10)}.${raw.slice(1)}`,
    pointerSize: ptr === "-" ? 64 : 32,
    endian: endian === "V" ? "big" : "little",
  };
}

// Find a Unity project root at or above a path (a Unity project has Assets/ plus either
// ProjectSettings/ProjectVersion.txt or Packages/manifest.json). Returns the root or null.
function findUnityProjectRoot(startPath) {
  let dir = startPath;
  try {
    if (fs.existsSync(dir) && fs.statSync(dir).isFile()) dir = path.dirname(dir);
  } catch { return null; }
  for (let i = 0; i < 4 && dir; i++) {
    const hasAssets = fs.existsSync(path.join(dir, "Assets"));
    const hasVersion = fs.existsSync(path.join(dir, "ProjectSettings", "ProjectVersion.txt"));
    const hasManifest = fs.existsSync(path.join(dir, "Packages", "manifest.json"));
    if (hasAssets && (hasVersion || hasManifest)) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

// Count files by extension under a directory (entry-bounded so a huge project cannot stall).
function countByExtension(root, exts, { maxEntries = 200000 } = {}) {
  const counts = Object.fromEntries(exts.map((e) => [e, 0]));
  let seen = 0;
  const stack = [root];
  while (stack.length && seen < maxEntries) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      seen++;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { stack.push(full); continue; }
      const ext = path.extname(e.name).toLowerCase().replace(".", "");
      if (ext in counts) counts[ext]++;
    }
  }
  return { counts, scanned: seen };
}

// Unity project fields: structure + metadata only; the editor is never launched.
function unityProjectFields(root) {
  const fields = { kind: "unity-project", root };

  try {
    const vf = path.join(root, "ProjectSettings", "ProjectVersion.txt");
    if (fs.existsSync(vf)) {
      const txt = fs.readFileSync(vf, "utf8");
      const m = txt.match(/m_EditorVersion:\s*(\S+)/);
      const r = txt.match(/m_EditorVersionWithRevision:\s*(\S+)/);
      if (m) fields.unityVersion = m[1];
      if (r) fields.editorRevision = r[1];
    }
  } catch {}

  try {
    const mf = path.join(root, "Packages", "manifest.json");
    if (fs.existsSync(mf)) {
      // Unity files edited on Windows can carry a UTF-8 BOM, which JSON.parse rejects.
      const j = JSON.parse(fs.readFileSync(mf, "utf8").replace(/^\uFEFF/, ""));
      const deps = j.dependencies || {};
      fields.packageCount = Object.keys(deps).length;
      fields.packages = Object.keys(deps).slice(0, 40);
    }
  } catch {}

  const exts = ["unity", "prefab", "cs", "mat", "shader", "asmdef", "asset", "anim", "controller", "png", "jpg", "fbx", "wav", "mp3", "mp4"];
  const { counts, scanned } = countByExtension(path.join(root, "Assets"), exts);
  fields.scenes = counts.unity;
  fields.prefabs = counts.prefab;
  fields.scripts = counts.cs;
  fields.materials = counts.mat;
  fields.shaders = counts.shader;
  fields.assemblies = counts.asmdef;
  fields.animations = counts.anim + counts.controller;
  fields.models = counts.fbx;
  fields.textures = counts.png + counts.jpg;
  fields.audio = counts.wav + counts.mp3;
  fields.scannedEntries = scanned;
  return fields;
}

// Python expression run inside Blender (headless) that dumps scene statistics as one JSON line.
const BLENDER_STATS_EXPR = [
  "import bpy, json",
  "def _c(t):",
  "    return len([o for o in bpy.data.objects if o.type == t])",
  "print('KOHANE_JSON=' + json.dumps({",
  "    'blenderVersion': bpy.app.version_string,",
  "    'scenes': len(bpy.data.scenes),",
  "    'collections': len(bpy.data.collections),",
  "    'objects': len(bpy.data.objects),",
  "    'meshes': len(bpy.data.meshes),",
  "    'materials': len(bpy.data.materials),",
  "    'cameras': _c('CAMERA'),",
  "    'lights': _c('LIGHT'),",
  "    'armatures': _c('ARMATURE'),",
  "    'curves': len(bpy.data.curves),",
  "    'images': len(bpy.data.images),",
  "    'actions': len(bpy.data.actions),",
  "    'engines': sorted({s.render.engine for s in bpy.data.scenes}),",
  "}))",
].join("\n");

// ---- a music host's native project container --------------------------------
// kohane-native: pure Node, no FL installation required. Layout:
//   header chunk | u32 headerSize | header bytes | data chunk | u32 dataSize | event stream
// The event stream is a sequence of `[id u8][len u8][payload]` records. The full record walk is not
// decoded yet (unknown ids can desync it), so metadata is collected by matching the two events that
// actually carry it - robust to unknown ids, and checked against a real file written by 20.7.2 samples:
//   C7 = the writing FL version, ASCII, e.g. C7 08 "11.5.13\0"
//   C9 = an embedded object/plugin NAME, UTF-16LE (a 0xC9 id, a length, then the name)ruity dB Meter"
// Some files also carry a four-byte marker near the end of the data chunkata block.
// The layout was established from samples on this machine; the notes stay outside the published tree.1), decode-flhd.mjs.
// A container layout is machine-local knowledge: it lives in the machine's own library directory and
// is loaded from there. With no local module this reports that it has no decoder, and the provider
// that asks for one stays silent rather than guessing.
let _localContainerDecoder = null;
function decodeNativeContainer(buf) {
  const empty = { container: false, writerVersion: null, names: [], headerBytes: 0, dataBytes: 0, trailer: null };
  if (_localContainerDecoder === null) {
    _localContainerDecoder = false;
    try {
      const rel = LOCAL_NATIVE_FORMATS.containerDecoder;
      if (rel) {
        // Synchronous on purpose: one caller walks containers inside a synchronous loop, and an
        // async loader would quietly give that caller nothing at all.
        const requireLocal = createRequire(import.meta.url);
        const mod = requireLocal(path.join(libraryDir(), rel));
        if (mod && typeof mod.decodeNativeContainer === "function") _localContainerDecoder = mod.decodeNativeContainer;
      }
    } catch {
      _localContainerDecoder = false;
    }
  }
  if (!_localContainerDecoder) return empty;
  return _localContainerDecoder(buf) || empty;
}

// ---- Kohane plugin directory (adopted capabilities, kohane-owned vocabulary) ----
// kohane-index-desuno adopts plugin *capabilities*, never plugin *code*: nothing here loads, links
// or executes a third-party binary, and the directory stands on its own even on a machine where
// none of those plugins is installed.
//
// Two layers, deliberately separated:
//   1. The CAPABILITY layer (this file, and everything the tools print) is kohane's own: one brand
//      plus a functional word, e.g. "Kohane Bassline Maximizer". It names what a capability DOES,
//      so no third-party product name ever reaches a result, a directory listing or an export.
//   2. The LOCAL ADOPTION layer ($DSH_HOME/library/plugins.local.json) records which plugin on
//      THIS machine provides which capability. That is local bookkeeping, needed to recognise the
//      plugin again on a later scan, and it is only ever shown by an explicit op=provenance call.
// Evidence and method: research/adopted-plugins (static, read-only) + research/fl-studio.
const KOHANE_PLUGIN_BRAND = "Kohane Bassline";

// Role taxonomy. Roles are kohane's own vocabulary - what a capability DOES - so capabilities
// coming from different hosts land on the same shelf.
const KOHANE_PLUGIN_ROLES = {
  "generator.synth": "sound generator that synthesises notes from oscillators",
  "generator.sampler": "sound generator that plays sampled material",
  "generator.drum": "percussion generator",
  "effect.dynamics": "level control (compression, limiting, maximising)",
  "effect.filter": "frequency-axis shaping",
  "effect.eq": "multi-band tonal shaping",
  "effect.delay": "time-based echo",
  "effect.reverb": "space simulation / convolution",
  "effect.modulation": "chorus, flanger, phaser family",
  "effect.distortion": "non-linear saturation",
  "effect.spectral": "spectral processing (vocoding, pitch, breath)",
  "effect.gain": "gain, pan, stereo placement",
  "effect.multi": "several effects inside one slot",
  "meter": "measurement and visualisation",
  "control": "parameter generation and automation",
  "utility": "session housekeeping",
  "utility.routing": "signal / MIDI routing",
  "modular": "container that hosts other plugins",
  "editor": "audio editing and rendering",
  "unknown": "not classified yet (give it a functional word)",
};

// Default functional word per role, used when a capability brings no word of its own.
const ROLE_FUNCTION_WORD = {
  "generator.synth": "Synth",
  "generator.sampler": "Sampler",
  "generator.drum": "Drum",
  "effect.dynamics": "Dynamics",
  "effect.filter": "Filter",
  "effect.eq": "Equalizer",
  "effect.delay": "Delay",
  "effect.reverb": "Reverb",
  "effect.modulation": "Modulation",
  "effect.distortion": "Distortion",
  "effect.spectral": "Spectral",
  "effect.gain": "Gain",
  "effect.multi": "Multifx",
  "meter": "Meter",
  "control": "Control",
  "utility": "Utility",
  "utility.routing": "Routing",
  "modular": "Modular",
  "editor": "Editor",
  "unknown": "Capability",
};

// Generic function words: the vocabulary an adopted capability is named from. Longest first, so a
// compound ("Dynamic EQ") beats its parts. These are craft nouns, not product names.
const PLUGIN_FUNCTION_VOCAB = [
  "Vintage Compressor", "Vintage Limiter", "Vintage Tape", "Vintage EQ", "Dynamic EQ",
  "Band Compressor", "Match EQ", "Stereo Enhancer", "Stereo Shaper", "Vocal Synth", "Audio Server",
  "Multiband Compressor", "Parametric EQ", "Movement Filter", "Wide Flanger", "Image Synth",
  "Transient", "Saturator", "Oscilloscope", "Spectrogram", "Stereometer", "Equalizer", "Maximizer",
  "Compressor", "Convolver", "Multifx", "Granular", "Overdrive", "Distortion", "Modular", "Low End",
  "Envelope", "Notebook", "Limiter", "Chorus", "Flanger", "Balance", "Formula", "Sampler",
  "Loudness", "Spectrum", "Waveform", "Exciter", "Imager", "Dynamics", "Spectral", "Rebalance",
  "Vocoder", "Reverb", "Delay", "Filter", "Engine", "Random", "Surface", "Dashboard", "Editor",
  "Midi Out", "Midi Synth", "Clock", "Peak", "Send", "Color", "Kick", "Drum", "Pad", "Bank",
  "Wave", "VU", "Synth", "Tape", "Gate", "Analyzer", "Width", "Pitch", "Control",
];

// Keyword hints placing a discovered plugin on the taxonomy shelf. The first match wins.
const PLUGIN_ROLE_HINTS = [
  [/automation/, "control"],
  [/compress|limit|maxim|dynamics|transient|rebalance/, "effect.dynamics"],
  [/delay|echo|gross ?beat|glitch|stutter/, "effect.delay"],
  [/reverb|reeverb|convol/, "effect.reverb"],
  [/equal|\beq\b|equo|parametric|tonal/, "effect.eq"],
  [/filter|philter|formant|wah|low ?end/, "effect.filter"],
  [/vocod|pitch|autotune|breath|spectral/, "effect.spectral"],
  [/chorus|flang|phas|tremol|vibrato/, "effect.modulation"],
  [/dist|overdrive|drive|saturat|crush|soft ?clip|clipper|waveshap|squeeze|hardcore|exciter/, "effect.distortion"],
  [/patcher|modular|wrapper|^layer$/, "modular"],
  [/meter|loudness|analy|scope|spectrum|spectrogram|stereometer|\bvu\b|waveform|visual|dance|video|chroma/, "meter"],
  [/^audio clip/, "generator.sampler"],
  [/drum|kick|perc|tom\b|snare|^fpc\b/, "generator.drum"],
  [/sampl|granul|directwave|slice|sfz|soundfont|wavetable/, "generator.sampler"],
  [/synth|osc|additive|subtra|\bfm\b|organ|piano|keys|bass/, "generator.synth"],
  [/editor|record|render|newtone|newtime/, "editor"],
  [/control|envelope|formula|\blfo\b|surface|mapper|splitter|voltage/, "control"],
  [/midi|send|routing|route|\bbus\b|\bout\b|rewire|server/, "utility.routing"],
  [/browser|notebook|utility|tool|manager|scratch|mobile/, "utility"],
];

// Second pass, used only when the name says nothing: the host's own folder filing is evidence too.
const PLUGIN_CATEGORY_HINTS = [
  [/synth/, "generator.synth"],
  [/^generators\/drum|^drum/, "generator.drum"],
  [/sampler/, "generator.sampler"],
  [/distortion/, "effect.distortion"],
  [/dynamics/, "effect.dynamics"],
  [/flanger/, "effect.modulation"],
  [/delay/, "effect.delay"],
  [/filter/, "effect.filter"],
  [/gain/, "effect.gain"],
  [/patcher/, "modular"],
  [/visual/, "meter"],
  [/controller/, "control"],
  [/midi/, "utility.routing"],
  [/^generators\//, "generator.synth"],
];

// The curated capability slots: kohane's own directory, correct on any machine, installed or not.
// [functional word, role, note?]
const KOHANE_CAPABILITIES = [
  ["Engine", "generator.synth", "flagship slot: the bass engine itself"],
  ["Additive", "generator.synth", "additive / resynthesis engine"],
  ["FM", "generator.synth", "FM synthesis"],
  ["Random", "generator.synth", "randomised patch explorer"],
  ["Bank", "generator.synth", "preset-bank synth"],
  ["Midi Synth", "generator.synth", "renders notes through the system MIDI synth"],
  ["Vocal Synth", "generator.synth", "voice-oriented synthesis"],
  ["Sampler", "generator.sampler", ""],
  ["Wave", "generator.sampler", "sample player with layer mapping"],
  ["Granular", "generator.sampler", "granular playback"],
  ["Image Synth", "generator.sampler", "turns an image into a wavetable"],
  ["Drum", "generator.drum", "modelling percussion synth"],
  ["Kick", "generator.drum", ""],
  ["Kick Drum", "generator.drum", "low-percussion generator"],
  ["Compressor", "effect.dynamics", ""],
  ["Vintage Compressor", "effect.dynamics", "character compression"],
  ["Multiband Compressor", "effect.dynamics", ""],
  ["Band Compressor", "effect.dynamics", ""],
  ["Limiter", "effect.dynamics", ""],
  ["Vintage Limiter", "effect.dynamics", "character limiting"],
  ["Maximizer", "effect.dynamics", "loudness maximiser"],
  ["Dynamics", "effect.dynamics", "multipurpose dynamics stage"],
  ["Transient", "effect.dynamics", "transient shaping"],
  ["Rebalance", "effect.dynamics", "source/balance rebalancing"],
  ["Equalizer", "effect.eq", ""],
  ["Vintage EQ", "effect.eq", "character equaliser"],
  ["Dynamic EQ", "effect.eq", "level-dependent equaliser"],
  ["Match EQ", "effect.eq", "reference-matching equaliser"],
  ["Tone Reference", "effect.eq", "target-curve tone control"],
  ["Filter", "effect.filter", ""],
  ["Movement Filter", "effect.filter", "multi-band movement filter"],
  ["Low End", "effect.filter", "low-band focus"],
  ["Spectral Shaping", "effect.filter", "shaping the spectrum over time"],
  ["Delay", "effect.delay", ""],
  ["Delay 2", "effect.delay", ""],
  ["Delay 3", "effect.delay", ""],
  ["Convolver", "effect.reverb", ""],
  ["Reverb", "effect.reverb", ""],
  ["Chorus", "effect.modulation", ""],
  ["Flanger", "effect.modulation", ""],
  ["Wide Flanger", "effect.modulation", "wide stereo flanger"],
  ["Phaser", "effect.modulation", ""],
  ["Distortion", "effect.distortion", ""],
  ["Overdrive", "effect.distortion", ""],
  ["Destroyer", "effect.distortion", "destructive multi-stage mangler"],
  ["Exciter", "effect.distortion", "harmonic exciter"],
  ["Saturator", "effect.distortion", ""],
  ["Vintage Tape", "effect.distortion", "tape character"],
  ["Spectral", "effect.spectral", "spectral processing"],
  ["Vocoder", "effect.spectral", ""],
  ["Breath Control", "effect.spectral", "breath and plosive removal"],
  ["Balance", "effect.gain", ""],
  ["Pan", "effect.gain", "pan and modulation"],
  ["Stereo Enhancer", "effect.gain", "stereo widening"],
  ["Stereo Shaper", "effect.gain", "stereo field shaping"],
  ["Imager", "effect.gain", "stereo imaging"],
  ["Multifx", "effect.multi", "x/y performance multi-effect"],
  ["Meter", "meter", ""],
  ["Loudness", "meter", "loudness measurement"],
  ["VU", "meter", "analogue-style level metering"],
  ["Spectrum", "meter", "spectrum analyser"],
  ["Spectrogram", "meter", "spectrogram display"],
  ["Oscilloscope", "meter", "waveform display over time"],
  ["Waveform", "meter", "waveform display"],
  ["Stereometer", "meter", "stereo field display"],
  ["Dashboard", "meter", "multi-meter panel"],
  ["Clock", "meter", "time display"],
  ["Envelope", "control", "multi-point envelope generator"],
  ["Formula", "control", "expression-driven parameter control"],
  ["Peak", "control", "envelope follower used as a control source"],
  ["Surface", "control", "hardware / MIDI control-surface binding"],
  ["Pad", "control", "pad-style note entry"],
  ["Color", "control", "maps colour onto note properties"],
  ["Modular", "modular", "hosts other plugins inside one slot"],
  ["Editor", "editor", "audio editing and rendering (kohane-native, no host script engine)"],
  ["Send", "utility.routing", ""],
  ["Midi Out", "utility.routing", ""],
  ["Audio Server", "utility.routing", "shared audio server for other instances"],
  ["Notebook", "utility", "in-project notes"],
];

// The bare brand name is reserved for the flagship capability: the engine every producer reaches
// for when a track needs a bassline, so "Kohane Bassline" reads as the engine itself.
const KOHANE_PLUGIN_FLAGSHIP = "Engine";

const PLUGIN_STATE_MAX_BYTES = 16 * 1024 * 1024;
const PLUGIN_BINARY_SCAN_BYTES = 32 * 1024 * 1024;

// Comparison key: case- and punctuation-insensitive.
function pluginKey(name) {
  return String(name || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function pluginSlug(text) {
  return String(text || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
}

// Uniform naming: one brand, then the functional word for what the capability does.
function kohanePluginName(fn, brand) {
  const b = String(brand || KOHANE_PLUGIN_BRAND).trim() || KOHANE_PLUGIN_BRAND;
  const f = String(fn || "").trim();
  return (f ? `${b} ${f}` : b).slice(0, 80);
}

function isKohaneFlagship(capabilityWord) {
  return pluginKey(capabilityWord) === pluginKey(KOHANE_PLUGIN_FLAGSHIP);
}

function classifyPluginRole(sourceName, category) {
  const s = String(sourceName || "").toLowerCase();
  for (const [re, role] of PLUGIN_ROLE_HINTS) if (re.test(s)) return role;
  const c = String(category || "").toLowerCase();
  for (const [re, role] of PLUGIN_CATEGORY_HINTS) if (re.test(c)) return role;
  return "unknown";
}

function roleFunctionWord(role) {
  return ROLE_FUNCTION_WORD[role] || ROLE_FUNCTION_WORD.unknown;
}

// Pull a functional word out of an observed binary name. Only craft nouns are kept, so the result
// carries no product name; a name that says nothing leaves this empty and the role word is used.
const VENDOR_NOISE = /(^|[^a-z])(vst|vst3|clap|au|x64|x86|64|32|win|win64|mac|demo|trial|beta|version)([^a-z]|$)/gi;

function extractFunctionWord(localName) {
  let s = String(localName || "").replace(/\.(vst3|clap|dll|exe|component|so)$/i, "");
  s = s.replace(VENDOR_NOISE, " ").replace(/[_\-.]+/g, " ").replace(/\s+/g, " ").trim();
  for (const w of PLUGIN_FUNCTION_VOCAB) {
    const re = new RegExp(`(^|[^A-Za-z0-9])${w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^A-Za-z0-9]|$)`, "i");
    if (re.test(s)) return w;
  }
  return "";
}

// ---------- Local adoption pack: which plugin on THIS machine provides which capability -------
// The pack never restates the capability directory - it only links observations to it, so there is
// one source of truth for names and no drift. Its contents are local bookkeeping and are not part
// of any normal result.
function pluginPackFile() {
  return path.join(libraryDir(), "plugins.local.json");
}

function emptyPluginPack() {
  return { version: 2, brand: KOHANE_PLUGIN_BRAND, updatedAt: null, entries: [] };
}

function normalizePluginPack(raw) {
  const d = emptyPluginPack();
  if (!raw || typeof raw !== "object") return d;
  const brand = String(raw.brand || "").trim().slice(0, 60);
  d.brand = brand || KOHANE_PLUGIN_BRAND;
  d.updatedAt = raw.updatedAt || null;
  for (const e of Array.isArray(raw.entries) ? raw.entries : []) {
    if (!e || typeof e !== "object") continue;
    // v1 packs used `sourceName`; accept it so an existing install keeps its links.
    const localName = String(e.localName || e.sourceName || "").trim().slice(0, 120);
    if (!localName) continue;
    d.entries.push({
      localName,
      capability: String(e.capability || e.function || "").trim().slice(0, 40),
      name: String(e.name || "").trim().slice(0, 80),
      role: KOHANE_PLUGIN_ROLES[e.role] ? e.role : "",
      kind: String(e.kind || e.sourceFormat || "plugin").slice(0, 24),
      localCategory: String(e.localCategory || e.sourceCategory || "").slice(0, 80),
      localVersion: String(e.localVersion || e.sourceVersion || "").slice(0, 40),
      localFile: String(e.localFile || e.sourceFile || "").slice(0, 260),
      origin: ["discovered", "manual"].includes(e.origin) ? e.origin : "manual",
      note: String(e.note || "").slice(0, 200),
      updatedAt: e.updatedAt || null,
    });
  }
  return d;
}

function loadPluginPack() {
  try {
    return normalizePluginPack(JSON.parse(fs.readFileSync(pluginPackFile(), "utf8")));
  } catch {
    return emptyPluginPack();
  }
}

function savePluginPack(pack) {
  const p = normalizePluginPack(pack);
  p.updatedAt = new Date().toISOString();
  fs.mkdirSync(libraryDir(), { recursive: true });
  fs.writeFileSync(pluginPackFile(), JSON.stringify(p, null, 2), "utf8");
  return p;
}

// The word a local observation contributes, and the name it would publish.
function derivedFunctionWord(p) {
  if (p.name) return "";
  if (p.capability) return p.capability;
  const observed = extractFunctionWord(p.localName);
  if (observed) return observed;
  return roleFunctionWord(p.role || classifyPluginRole(p.localName, p.localCategory));
}

function derivedKohaneName(p, brand) {
  const b = String(brand || KOHANE_PLUGIN_BRAND).trim() || KOHANE_PLUGIN_BRAND;
  if (p.name) return p.name;
  if (isKohaneFlagship(derivedFunctionWord(p)) && !p.capability) return kohanePluginName("", b);
  return kohanePluginName(derivedFunctionWord(p), b);
}

// Is a name already published by a DIFFERENT capability? (An entry may reuse its own name.)
function kohaneNameTaken(entries, name, localName) {
  const n = String(name || "").toLowerCase();
  const key = pluginKey(localName);
  return entries.some((e) => e.name.toLowerCase() === n && pluginKey(e.sourceKey) !== key);
}

function duplicateKohaneNames(entries) {
  const seenName = new Set(), seenId = new Set(), dupes = new Set();
  for (const e of entries) {
    const n = String(e.name).toLowerCase(), i = String(e.id).toLowerCase();
    if (seenName.has(n) || seenId.has(i)) dupes.add(e.name);
    seenName.add(n);
    seenId.add(i);
  }
  return [...dupes];
}

function dedupeKohaneNames(entries) {
  const used = new Set();
  for (const e of entries) {
    const base = e.name;
    let name = base, n = 2;
    while (used.has(name.toLowerCase())) name = `${base} ${n++}`;
    if (name !== base) {
      e.name = name;
      e.id = pluginSlug(name);
      e.numbered = true;
    }
    used.add(name.toLowerCase());
  }
  return entries;
}

// The public directory: curated capability slots first, then one entry per adopted capability.
// Nothing in the returned objects carries a third-party name - the local link is kept in
// `sourceKey`, which maps back to the pack for op=provenance, and is never printed.
function resolveKohanePlugins(pack) {
  const brand = (pack && pack.brand) || KOHANE_PLUGIN_BRAND;
  const entries = [];
  const byWord = new Map();
  for (const [fn, role, note] of KOHANE_CAPABILITIES) {
    const name = isKohaneFlagship(fn) ? kohanePluginName("", brand) : kohanePluginName(fn, brand);
    const e = {
      id: pluginSlug(name),
      name,
      function: fn,
      role,
      origin: "capability",
      sourceKey: null,
      linked: 0,
      renamed: false,
      note: note || "",
    };
    entries.push(e);
    byWord.set(pluginKey(fn), e);
  }

  for (const p of (pack && pack.entries) || []) {
    const word = p.name ? "" : p.capability || extractFunctionWord(p.localName);
    const slot = word ? byWord.get(pluginKey(word)) : null;
    if (slot) {
      slot.linked++;
      slot.sourceKey = slot.sourceKey || pluginKey(p.localName);
      if (!slot.note && p.note) slot.note = p.note;
      if (p.name) { slot.name = p.name; slot.id = pluginSlug(p.name); slot.renamed = true; }
      continue;
    }
    entries.push({
      id: pluginSlug(derivedKohaneName(p, brand)),
      name: derivedKohaneName(p, brand),
      function: derivedFunctionWord(p),
      role: p.role || classifyPluginRole(p.localName, p.localCategory),
      origin: p.origin || "discovered",
      sourceKey: pluginKey(p.localName),
      linked: 1,
      renamed: !!p.name,
      note: p.note || "",
    });
  }
  return dedupeKohaneNames(entries);
}

// Local adoption detail for one entry: the plugin(s) on this machine that provide it. This is the
// ONLY path that shows third-party names, and it exists so the user can audit the links.
function pluginProvenance(pack, key) {
  const k = pluginKey(key);
  return (pack.entries || [])
    .filter((e) => pluginKey(e.localName) === pluginKey(key) || (key && pluginKey(e.localName).includes(k)))
    .map((e) => ({ localName: e.localName, kind: e.kind, category: e.localCategory || null, version: e.localVersion || null, file: e.localFile || null, capability: e.capability || extractFunctionWord(e.localName), role: e.role, origin: e.origin }));
}

// ---------- Discovery: read binaries and state files, never load a plugin ----------
// A plugin binary's own name is the honest source of its capability word; the ABI entry points and
// the version strings are read from the file header region only. Read-only, no registration.
function pluginRoots() {
  const env = String(process.env.KOHANE_PLUGIN_ROOTS || "").split(path.delimiter).map((s) => s.trim()).filter(Boolean);
  const pf = process.env.ProgramFiles || "C:\\Program Files";
  const cf = process.env.CommonProgramFiles || "C:\\Program Files\\Common Files";
  const bases = [
    path.join(cf, "VST3"), path.join(cf, "VST2"), path.join(cf, "CLAP"),
    path.join(pf, "VSTPlugins"), path.join(pf, "Steinberg", "VstPlugins"),
    "/Library/Audio/Plug-Ins/VST3", "/Library/Audio/Plug-Ins/Components", "/Library/Audio/Plug-Ins/CLAP",
    path.join(os.homedir(), "Library/Audio/Plug-Ins/VST3"),
    "/usr/lib/vst3", "/usr/lib/clap", path.join(os.homedir(), ".vst3"),
  ];
  return [...new Set([...env, ...bases])].filter((d) => {
    try { return fs.statSync(d).isDirectory(); } catch { return false; }
  });
}

const PLUGIN_BINARY_EXT = { ".vst3": "vst3", ".clap": "clap", ".dll": "vst2", ".so": "vst3", ".component": "vst2" };
const PLUGIN_ABI_MARKERS = {
  vst3: ["GetPluginFactory"],
  clap: ["clap_entry"],
  vst2: ["VSTPluginMain"],
};

// A .vst3 may be a single file or a macOS-style bundle directory; both are handled.
function collectPluginBinaries(dir, out = [], depth = 0) {
  let ents;
  try {
    ents = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of ents) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (depth < 6) collectPluginBinaries(full, out, depth + 1);
      continue;
    }
    if (!e.isFile()) continue;
    const ext = path.extname(e.name).toLowerCase();
    if (PLUGIN_BINARY_EXT[ext]) out.push({ file: full, kind: PLUGIN_BINARY_EXT[ext] });
  }
  return out;
}

// Read arch + ABI entry points + version strings from the file header region (bounded, read-only).
function readPluginBinary(file, kind) {
  const out = { kind, arch: null, abi: [], version: null, product: null };
  let buf;
  try {
    const fd = fs.openSync(file, "r");
    const size = fs.statSync(file).size;
    buf = Buffer.alloc(Math.min(size, PLUGIN_BINARY_SCAN_BYTES));
    fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
  } catch {
    return out;
  }
  if (buf.length >= 64 && buf.readUInt16LE(0) === 0x5a4d) {
    const peOff = buf.readUInt32LE(0x3c);
    if (peOff + 6 < buf.length && buf.toString("latin1", peOff, peOff + 4) === "PE\0\0") {
      const machine = buf.readUInt16LE(peOff + 4);
      out.arch = machine === 0x8664 ? "x64" : machine === 0x14c ? "x86" : `0x${machine.toString(16)}`;
    }
  }
  for (const m of PLUGIN_ABI_MARKERS[kind] || []) {
    if (buf.includes(Buffer.from(m, "latin1"))) out.abi.push(m);
  }
  const utf16 = buf.toString("utf16le");
  for (const key of ["ProductName", "FileDescription", "FileVersion"]) {
    const at = utf16.indexOf(key);
    if (at < 0) continue;
    const value = utf16.slice(at + key.length, at + key.length + 160).replace(/^\u0000+/, "").split("\u0000").find((s) => /[\x20-\x7e]/.test(s || "")) || "";
    if (!value) continue;
    if (key === "FileVersion") out.version = out.version || value.trim().slice(0, 40);
    else out.product = out.product || value.trim().slice(0, 80);
  }
  return out;
}

// Walk every plugin root and report what this machine carries, described by CAPABILITY only.
function scanPluginInstallations(opts = {}) {
  const maxFiles = Math.min(Math.max(Number(opts.maxFiles) || 800, 1), 5000);
  const roots = (opts.roots && opts.roots.length ? opts.roots : pluginRoots()).filter((d) => {
    try { return fs.statSync(d).isDirectory(); } catch { return false; }
  });
  const out = { roots, scanned: 0, skipped: 0, truncated: false, plugins: [] };
  for (const root of roots) {
    if (out.truncated) break;
    for (const b of collectPluginBinaries(root)) {
      if (out.scanned >= maxFiles) { out.truncated = true; break; }
      out.scanned++;
      let st;
      try { st = fs.statSync(b.file); } catch { out.skipped++; continue; }
      const info = readPluginBinary(b.file, b.kind);
      const base = path.basename(b.file).replace(/\.(vst3|clap|dll|so|component)$/i, "");
      out.plugins.push({
        localName: base,
        kind: b.kind,
        file: b.file,
        mb: +(st.size / 1048576).toFixed(2),
        arch: info.arch,
        abi: info.abi,
        version: info.version,
        product: info.product,
        word: extractFunctionWord(base),
        role: classifyPluginRole(base, ""),
      });
    }
  }
  out.plugins.sort((a, b) => pluginKey(a.localName).localeCompare(pluginKey(b.localName)) || a.file.localeCompare(b.file));
  return out;
}

// A plugin database may keep its state files directly below it, or one or two category levels
// down, so the whole (bounded) tree is checked before a directory is treated as one.
function looksLikePluginDatabase(dir, maxDepth = 3) {
  const stack = [[dir, 0]];
  let seen = 0;
  while (stack.length && seen < 400) {
    const [cur, depth] = stack.pop();
    let ents;
    try {
      ents = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of ents) {
      if (seen++ >= 400) break;
      if (e.isFile() && e.name.toLowerCase().endsWith(".fst")) return true;
      if (e.isDirectory() && depth < maxDepth) stack.push([path.join(cur, e.name), depth + 1]);
    }
  }
  return false;
}

// Native plugin state files embed the writing plugin's own name (UTF-16LE) and a writer version,
// so an installation's own plugin database can be enumerated from headers alone.
function scanPluginDatabase(dir, maxFiles = 600) {
  const out = { dir, scanned: 0, states: 0, skipped: 0, truncated: false, plugins: [] };
  const stack = [dir];
  while (stack.length && !out.truncated) {
    const cur = stack.pop();
    let ents;
    try {
      ents = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      out.skipped++;
      continue;
    }
    for (const ent of ents) {
      const full = path.join(cur, ent.name);
      if (ent.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!ent.isFile()) continue;
      if (out.scanned >= maxFiles) {
        out.truncated = true;
        break;
      }
      out.scanned++;
      let size = 0;
      try {
        size = fs.statSync(full).size;
      } catch {
        continue;
      }
      if (size > PLUGIN_STATE_MAX_BYTES) {
        out.skipped++;
        continue;
      }
      const head = readHeader(full, 4);
      if (!head || head.length < 4 || head.toString("latin1") !== "FLhd") {
        out.skipped++;
        continue;
      }
      let d;
      try {
        d = decodeNativeContainer(fs.readFileSync(full));
      } catch {
        out.skipped++;
        continue;
      }
      if (!d.container) {
        out.skipped++;
        continue;
      }
      out.states++;
      const rel = path.relative(dir, path.dirname(full));
      out.plugins.push({
        file: full,
        localName: (d.names[0] || path.basename(full, path.extname(full))).slice(0, 120),
        nameFromState: d.names.length > 0,
        kind: "native-state",
        localCategory: rel && rel !== "." ? rel.split(path.sep).slice(-2).join("/") : "",
        version: d.writerVersion,
      });
    }
  }
  out.plugins.sort((a, b) => pluginKey(a.localName).localeCompare(pluginKey(b.localName)) || a.file.localeCompare(b.file));
  return out;
}

// One plugin can own several state files, so callers group by plugin rather than by file.
function distinctPlugins(plugins) {
  const byKey = new Map();
  for (const p of plugins) {
    const key = pluginKey(p.localName);
    if (!key) continue;
    const hit = byKey.get(key);
    if (hit) {
      hit.states = (hit.states || 1) + 1;
      if (!hit.localCategory && p.localCategory) hit.localCategory = p.localCategory;
      if (!hit.version && p.version) hit.version = p.version;
      continue;
    }
    byKey.set(key, { ...p, states: 1 });
  }
  return [...byKey.values()];
}

function findPluginDatabase() {
  const candidates = [];
  const env = String(process.env.KOHANE_FL_DIR || "").trim();
  if (env) candidates.push(env, path.join(env, "Data", "Patches", "Plugin database"));
  const drives = [];
  for (const letter of "CDEFGH") {
    try {
      fs.accessSync(`${letter}:\\`);
      drives.push(`${letter}:\\`);
    } catch {}
  }
  for (const d of drives) {
    try {
      for (const name of fs.readdirSync(d)) if (/^FL ?Studio/i.test(name)) candidates.push(path.join(d, name, "Data", "Patches", "Plugin database"));
    } catch {}
    for (const pf of ["Program Files", "Program Files (x86)"]) {

      const il = path.join(d, pf, "Image-Line");
      try {
        for (const name of fs.readdirSync(il)) if (/^FL ?Studio/i.test(name)) candidates.push(path.join(il, name, "Data", "Patches", "Plugin database"));
      } catch {}
    }
  }
  for (const c of [...new Set(candidates)]) {
    try {
      if (!fs.statSync(c).isDirectory()) continue;
    } catch {
      continue;
    }
    if (looksLikePluginDatabase(c)) return c;
  }
  return null;
}

// Register the built-in analyzers (idempotent). Called lazily by analyzeObject() so every
// entry point (DSH / MCP / CLI) gets them without extra bootstrapping.
function registerDefaultAnalyzer() {
  if (analyzersRegistered) return;
  analyzersRegistered = true;

  ANALYZER_PROVIDERS.push({
    name: "unity-project",
    kind: "unity-project",
    match(target) {
      try { return fs.existsSync(target) && fs.statSync(target).isDirectory() && !!findUnityProjectRoot(target); }
      catch { return false; }
    },
    async analyze(target) {
      const root = findUnityProjectRoot(target);
      if (!root) return { ok: false, kind: "unity-project", detail: "not a Unity project (needs Assets/ + ProjectSettings/)" };
      const fields = unityProjectFields(root);
      const detail = `[Unity] ${fields.unityVersion || "version unknown"} - ${fields.scenes || 0} scene(s), ${fields.prefabs || 0} prefab(s), ${fields.scripts || 0} script(s), ${fields.packageCount || 0} package(s)`;
      return { ok: true, kind: "unity-project", fields, detail };
    },
  });

  ANALYZER_PROVIDERS.push({
    name: "blender",
    kind: "blender",
    match(target) {
      try {
        if (!fs.existsSync(target) || fs.statSync(target).isDirectory()) return false;
      } catch { return false; }
      if (path.extname(target).toLowerCase() === ".blend") return true;
      return !!readBlendHeader(target);
    },
    async analyze(target, opts = {}) {
      const header = readBlendHeader(target);
      if (!header) return { ok: false, kind: "blender", detail: "not a .blend file (missing BLENDER header)" };
      const fields = { kind: "blender", version: header.version, pointerSize: header.pointerSize, endian: header.endian };
      try { fields.bytes = fs.statSync(target).size; } catch {}
      let detail = `[Blender] .blend v${header.version} (${header.pointerSize}-bit, ${header.endian}-endian)`;

      if (opts.deep) {
        const exe = resolveTool("BLENDER_PATH", [
          "E:\\Blender Foundation\\Blender 4.4\\blender.exe", // Windows (this machine)
          "/usr/bin/blender", "/usr/local/bin/blender", "/Applications/Blender.app/Contents/MacOS/Blender",
        ], "blender");
        if (exe) {
          fields.blenderExe = exe;
          // -b = background (no window); --factory-startup keeps user prefs/addons out.
          const r = await runSilent(exe, ["-b", "--factory-startup", target, "--python-expr", BLENDER_STATS_EXPR], { timeoutMs: 120000, maxOut: 4 * 1024 * 1024 });
          const line = String(r.out || "").split(/\r?\n/).find((l) => l.startsWith("KOHANE_JSON="));
          if (line) {
            try {
              const stats = JSON.parse(line.slice("KOHANE_JSON=".length));
              fields.scene = stats;
              detail += ` - ${stats.objects} object(s), ${stats.meshes} mesh(es), ${stats.materials} material(s), ${stats.cameras} camera(s), ${stats.lights} light(s)`;
            } catch (e) {
              detail += ` - deep stats unparsable (${String(e && e.message || e).slice(0, 80)})`;
            }
          } else {
            detail += ` - deep analysis produced no stats (${String(r.err || "").trim().slice(0, 100) || "blender produced no output"})`;
          }
        } else {
          detail += " - deep analysis skipped (blender CLI not found; set BLENDER_PATH)";
        }
      }
      return { ok: true, kind: "blender", fields, detail };
    },
  });

  ANALYZER_PROVIDERS.push({
    // A Unity scene, prefab, asset or .meta file: text, so it is read whole and reported as a
    // document stream. Nothing here needs the editor.
    name: "unity-asset",
    kind: "unity-asset",
    match(target) {
      try {
        if (!fs.existsSync(target) || fs.statSync(target).isDirectory()) return false;
        if (!/\.(unity|prefab|asset|mat|anim|controller|meta)$/i.test(target)) return false;
        const head = readHeader(target, 64);
        if (!head) return false;
        const text = head.toString("utf8").replace(/^\uFEFF/, "");
        return /^%YAML/.test(text) || /^fileFormatVersion:/.test(text) || /^--- !u!/.test(text);
      } catch { return false; }
    },
    async analyze(target) {
      const r = readUnityAsset(target);
      const bits = [`${r.documents} document(s)`];
      const top = Object.entries(r.classes).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([id, n]) => `${r.classNames[id]} ${n}`);
      if (top.length) bits.push(top.join(", "));
      if (r.guidCount) bits.push(`${r.guidCount} guid reference(s)`);
      if (r.hasPrefabInstance) bits.push("contains a prefab instance");
      if (r.metaGuid) bits.push(`meta guid ${r.metaGuid.slice(0, 8)}`);
      return {
        ok: true,
        kind: "unity-asset",
        fields: {
          documents: r.documents,
          classes: r.names.length ? r.classNames : r.classNames,
          classCounts: r.classes,
          names: r.names.slice(0, 12),
          guidCount: r.guidCount,
          scriptGuids: r.scriptGuids.length,
          hasPrefabInstance: r.hasPrefabInstance,
          metaGuid: r.metaGuid,
          importer: r.importer,
        },
        detail: bits.join(" - "),
      };
    },
  });

  ANALYZER_PROVIDERS.push({
    name: "kb-container",
    kind: "kb-container",
    match(target) {
      try {
        if (!fs.existsSync(target) || fs.statSync(target).isDirectory()) return false;
        const magic = LOCAL_NATIVE_FORMATS.containerMagic;
        if (!magic) return false;                       // no local table: this machine claims nothing
        const head = readHeader(target, 4);
        return !!head && head.length === 4 && head.toString("latin1") === magic;
      } catch { return false; }
    },
    async analyze(target, opts = {}) {
      let buf;
      try { buf = fs.readFileSync(target); } catch (e) {
        return { ok: false, kind: "kb-container", detail: `unreadable: ${String(e && e.message || e)}` };
      }
      const d = decodeNativeContainer(buf);
      if (!d.container) return { ok: false, kind: "kb-container", detail: "not a native plugin container" };
      const fields = {
        kind: "kb-container",
        writerVersion: d.writerVersion,
        pluginCount: d.names.length,
        // The container's own object names are third-party strings, so they are reported only when
        // deep analysis is explicitly requested; the default view speaks kohane's vocabulary.
        ...(opts.deep ? { names: d.names } : {}),
        headerBytes: d.headerBytes,
        dataBytes: d.dataBytes,
        trailer: d.trailer,
      };
      // Every plugin a project references is reported under its kohane name: the file says what it
      // used, the directory says what kohane calls that capability. The local link table resolves
      // the container's own object name to a capability word; an unknown name is reported without
      // a capability rather than with the raw string.
      let mapped = 0;
      if (d.names.length) {
        try {
          const pack = loadPluginPack();
          const links = new Map((pack.entries || []).map((e) => [pluginKey(e.localName), e.capability || extractFunctionWord(e.localName)]));
          const dir = resolveKohanePlugins(pack);
          fields.kohane = d.names.map((n) => {
            const word = links.get(pluginKey(n)) || extractFunctionWord(n);
            const hit = word ? dir.find((e) => pluginKey(e.function) === pluginKey(word)) : null;
            if (hit) mapped++;
            return { kohaneName: hit ? hit.name : null, role: hit ? hit.role : null };
          });
        } catch {
          fields.kohane = [];
        }
      }
      const bits = ["native plugin container", `header ${d.headerBytes}B`, `data ${d.dataBytes}B`];
      if (d.writerVersion) bits.push(`written by version ${d.writerVersion}`);
      if (d.names.length) bits.push(`${d.names.length} plugin(s)`);
      if (d.names.length) bits.push(`kohane: ${mapped}/${d.names.length} mapped`);
      return { ok: true, kind: "kb-container", fields, detail: `[kb] ${bits.join(" - ")}` };
    },
  });
}

// ---- User-registered (DIY) analyzers -------------------------------------
// Registered through `library_format op=analyzer-add` and stored in the same local pack as the
// format signatures. Data-driven on purpose: an entry declares an external command plus an argv
// template, so a user plugs in their own tool without writing code. Built-in analyzers always run
// first (see analyzeObject), so a local entry can never shadow Unity/Blender/media handling.

// Does a DIY analyzer claim this target? True on any matching extension or name pattern.
function localAnalyzerMatches(def, target) {
  try {
    if (Array.isArray(def.exts) && def.exts.length) {
      const ext = path.extname(target).toLowerCase().replace(".", "");
      if (ext && def.exts.includes(ext)) return true;
    }
    if (def.matchName) {
      if (new RegExp(def.matchName, "i").test(path.basename(target))) return true;
    }
  } catch {}
  return false;
}

// Run one DIY analyzer: substitute {path} into the argv template, invoke it silently (timeout
// capped, no console window), then turn stdout into fields according to `parse`.
async function runLocalAnalyzer(def, target) {
  if (!def || !def.exe) return { ok: false, kind: (def && def.kind) || null, detail: "incomplete analyzer definition" };
  const argv = (def.args || []).map((a) => String(a).replace(/\{path\}/g, target));
  const r = await runSilent(def.exe, argv, { timeoutMs: def.timeoutMs || 30000, maxOut: 2 * 1024 * 1024 });
  if (!r.ok) {
    const why = String(r.err || "").trim().slice(0, 160) || `exit ${r.code}`;
    return { ok: false, kind: def.kind, detail: `[${def.name}] command failed: ${why}` };
  }
  const out = String(r.out || "").trim();
  if (!out) return { ok: false, kind: def.kind, detail: `[${def.name}] produced no output` };
  if (def.parse === "text") {
    return { ok: true, kind: def.kind, fields: { kind: def.kind, analyzer: def.name, local: true, text: out.slice(0, 4000) }, detail: `[${def.name}] local analyzer ok${def.note ? ` - ${def.note}` : ""}` };
  }
  try {
    return { ok: true, kind: def.kind, fields: { kind: def.kind, analyzer: def.name, local: true, data: JSON.parse(out) }, detail: `[${def.name}] local analyzer ok${def.note ? ` - ${def.note}` : ""}` };
  } catch (e) {
    return { ok: false, kind: def.kind, detail: `[${def.name}] output is not JSON (${String(e && e.message || e).slice(0, 100)}); re-register with parse:"text" if that is expected` };
  }
}

// Unified analysis entry: run every matching analyzer provider (built-ins first, then the user's
// DIY analyzers), then fall back to media fingerprinting and magic-byte sniffing.
// Returns { ok, kind, fields?, detail }.
async function analyzeObject(target, opts = {}) {
  if (!target) return { ok: false, kind: null, detail: "no path" };
  let exists = false, isDir = false;
  try { exists = fs.existsSync(target); isDir = exists && fs.statSync(target).isDirectory(); } catch {}
  if (!exists) return { ok: false, kind: null, detail: "path does not exist" };

  registerDefaultAnalyzer();
  for (const p of ANALYZER_PROVIDERS) {
    let matched = false;
    try { matched = p.match(target); } catch { matched = false; }
    if (!matched) continue;
    const r = await p.analyze(target, opts);
    if (r && r.ok) return r;
  }

  // Built-in generic fallback: media fingerprint (ffprobe/MediaInfo) plus magic-byte signature.
  let fallback = null;
  if (!isDir) {
    const sniff = sniffFileType(target);
    const fields = sniff ? { kind: "file", type: sniff.type, format: sniff.format, note: sniff.note } : { kind: "file" };
    const mf = await mediaFingerprint(target);
    if (mf && mf.ok) { fields.media = mf.detail; fallback = { ok: true, kind: "file", fields, detail: mf.detail }; }
    else if (sniff) fallback = { ok: true, kind: "file", fields, detail: `[signature] ${sniff.format} (${sniff.note})` };
    else fallback = { ok: false, kind: "file", fields, detail: "no analyzer matched and no known signature" };
  }

  // The installation's own (DIY) analyzers run only when nothing built-in identified the target,
  // so a local entry extends coverage and can never shadow Unity/Blender/media handling.
  if (!fallback || !fallback.ok) {
    try {
      for (const def of loadLocalFormats().analyzers) {
        if (!localAnalyzerMatches(def, target)) continue;
        const r = await runLocalAnalyzer(def, target);
        if (r && r.ok) return r;
      }
    } catch {}
  }

  if (fallback) return fallback;
  return { ok: false, kind: "directory", detail: "no analyzer matched this directory" };
}

// JSONL append log (generic, greppable, non-growing). Line shape: {ts, op, type, name, source, disposition, detail}
function appendLog(entry) {
  try {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
    fs.appendFileSync(path.join(libraryDir(), "log.jsonl"), line, "utf8");
  } catch {}
}

// ---------- [2] No popup: silent external tool invocation ----------
// Unified child_process.spawn wrapper with windowsHide:true to hide console windows
// (especially uv/CLI tools), preventing the plugin from popping unwanted windows.
// Has timeout protection; on failure returns {ok:false, err}.
function runSilent(exe, args, { timeoutMs = 30000, maxOut = 2 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(exe, args, { windowsHide: true });
    } catch (e) {
      resolve({ ok: false, err: String(e && e.message || e), out: "" });
      return;
    }
    let out = "", err = "", done = false;
    const finish = (rc) => {
      if (done) return;
      done = true;
      resolve({ ok: rc === 0, code: rc, out, err });
    };
    child.stdout.on("data", (d) => { if (out.length < maxOut) out += d; });
    child.stderr.on("data", (d) => { if (err.length < maxOut) err += d; });
    child.on("close", finish);
    child.on("error", (e) => { err = String(e && e.message || e); finish(-1); });
    setTimeout(() => { if (!done) { try { child.kill(); } catch {} finish(-2); } }, timeoutMs);
  });
}

// ---------- Cross-platform tool resolution ----------
// Resolve an external tool's executable path across platforms. Priority:
//   1) explicit env var (e.g. FFPROBE_PATH / MEDIAINFO_PATH)
//   2) a per-platform list of common absolute paths (if file exists)
//   3) plain command name (relies on PATH via spawn; ffprobe/mediainfo are on PATH on most Unix systems)
// Returns the best candidate string, or null if nothing looks usable.
function resolveTool(envName, candidates, commandName) {
  if (process.env[envName]) return process.env[envName];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  // Last resort: bare command name - spawn will resolve it from PATH.
  return commandName || null;
}

// ---------- [5] ADB device management (legitimate Android-developer subset) ----------
// ADB-Toolkit (github.com/ASHWIN990/ADB-Toolkit) is a penetration-testing Bash script.
// This plugin integrates ONLY its legitimate Android-developer operations (device listing,
// install/uninstall, launch, shell, logcat, screenshot/screenrecord, root-check, reboot,
// pull/push, wireless connect). Its offensive sections (Metasploit payload, hang-the-phone
// DoS, send SMS, bulk-copy camera/downloads/WhatsApp/full storage) are deliberately NOT
// implemented here.
function adbPath() {
  return resolveTool(
    "ADB_PATH",
    ["D:\\platform-tools\\adb.exe", "/usr/bin/adb", "/usr/local/bin/adb", "/opt/homebrew/bin/adb", "/opt/local/bin/adb", "/snap/bin/adb"],
    "adb"
  );
}

// Run adb with an optional device serial (-s). Silent (windowsHide), timeout-capped.
async function runAdb(args, { timeoutMs = 30000, device = "" } = {}) {
  const adb = adbPath();
  if (!adb) return { ok: false, code: -1, out: "", err: "adb not found (set ADB_PATH or install Android platform-tools)" };
  const full = device ? ["-s", device, ...args] : args;
  return runSilent(adb, full, { timeoutMs, maxOut: 512 * 1024 });
}

// Legitimate ADB action catalogue (one tool, action-keyed). `need` = required tool args;
// `args(a)` maps tool args -> adb argv; special actions are handled inline in execute.
const ADB_ACTIONS = {
  devices: { args: () => ["devices", "-l"] },
  "restart-server": { restart: true },
  reboot: { args: () => ["reboot"] },
  "reboot-recovery": { args: () => ["reboot", "recovery"] },
  "reboot-bootloader": { args: () => ["reboot", "bootloader"] },
  shell: { args: (a) => ["shell", a.command], need: ["command"] },
  "info-system": { args: () => ["shell", "getprop"] },
  "info-cpu": { args: () => ["shell", "cat", "/proc/cpuinfo"] },
  "info-memory": { args: () => ["shell", "cat", "/proc/meminfo"] },
  "device-details": { details: true },
  bugreport: { args: () => ["bugreport"], timeoutMs: 60000 },
  install: { args: (a) => ["install", "-r", a.apk], need: ["apk"], timeoutMs: 120000 },
  uninstall: { args: (a) => ["uninstall", a.package], need: ["package"] },
  "list-packages": { args: () => ["shell", "pm", "list", "packages"] },
  logcat: { args: (a) => ["logcat", "-d", "-t", String(a.lines || 100)] },
  push: { args: (a) => ["push", a.local, a.remote], need: ["local", "remote"] },
  pull: { args: (a) => ["pull", a.remote, a.local], need: ["remote", "local"] },
  launch: { args: (a) => ["shell", "monkey", "-p", a.package, "-c", "android.intent.category.LAUNCHER", "1"], need: ["package"] },
  screenshot: { screenshot: true },
  screenrecord: { screenrecord: true },
  "root-check": { args: () => ["shell", "which", "su"] },
  "remote-connect": { args: (a) => ["connect", a.target], need: ["target"] },
};

// ---------- Encoding detection + indicative adaptation ----------
// The library always persists as UTF-8 (the most stable choice). But if the host's
// system default encoding is NOT UTF-8 (common across East Asia / some EU / LATAM
// locales), external-tool output and file reads can mojibake. This module detects the
// system default encoding and issues indicative guidance so the plugin lands without
// mojibake. It never rewrites the library; it only reports and advises.

// Region -> common legacy encodings -> indicative guidance (for future DSH regional builds
// or hosts whose system default encoding is not UTF-8).
const INDICATIVE_ENCODING_HINTS = [
  { region: "Japan (Japanese)", codepages: [932, 51932, 50220, 50221], labels: ["Shift-JIS", "EUC-JP", "ISO-2022-JP"], hint: "Set the terminal/system to UTF-8 (chcp 65001 on Windows; LANG=en_US.UTF-8 or ja_JP.UTF-8 on Unix)." },
  { region: "Korea (Korean)", codepages: [949, 51949], labels: ["EUC-KR", "CP949"], hint: "Set the system to UTF-8 (chcp 65001 on Windows; LANG=ko_KR.UTF-8 on Unix)." },
  { region: "Southeast Asia (Thai/Vietnamese/Indonesian)", codepages: [874], labels: ["Windows-874 (Thai)"], hint: "Set the system to UTF-8 (chcp 65001 on Windows; LANG=th_TH.UTF-8 / vi_VN.UTF-8 / id_ID.UTF-8 on Unix)." },
  { region: "China / Taiwan / Hong Kong (Chinese)", codepages: [936, 950], labels: ["GBK/GB2312", "Big5"], hint: "Set the system to UTF-8 (chcp 65001 on Windows; LANG=zh_CN.UTF-8 / zh_TW.UTF-8 on Unix)." },
  { region: "Europe (Western/Central/Eastern)", codepages: [1250, 1251, 1252, 1253, 1254, 1257], labels: ["Windows-1250/1251/1252/1253/1254/1257", "ISO-8859-x"], hint: "Set the system to UTF-8 (chcp 65001 on Windows; LANG=en_US.UTF-8 / de_DE.UTF-8 / fr_FR.UTF-8 / ru_RU.UTF-8 on Unix)." },
  { region: "Latin America (Spanish/Portuguese)", codepages: [1252, 28591], labels: ["Windows-1252", "ISO-8859-1 (Latin-1)"], hint: "Set the system to UTF-8 (chcp 65001 on Windows; LANG=es_ES.UTF-8 / pt_BR.UTF-8 on Unix)." },
];

// Detect the current system default encoding (best effort).
// Returns { codepage, label, utf8 } - codepage/label may be null if unknown.
function detectSystemEncoding() {
  if (process.platform === "win32") {
    // Windows: chcp reports the active console code page (65001 = UTF-8).
    return detectSystemEncodingSync();
  }
  // Unix: derive from the locale. POSIX precedence is LC_ALL, then LC_CTYPE, then LANG.
  const lang = process.env.LC_ALL || process.env.LC_CTYPE || process.env.LANG || "";
  if (/utf-?8/i.test(lang)) return { codepage: null, label: "UTF-8", utf8: true };
  if (/shift.?jis|ja/i.test(lang)) return { codepage: 932, label: "Shift-JIS", utf8: false };
  if (/euc.?kr|ko/i.test(lang)) return { codepage: 949, label: "EUC-KR/CP949", utf8: false };
  // Traditional Chinese locales are Big5, not GBK: check them before the generic zh/gb rule.
  if (/big5|zh[_-]?(tw|hk)/i.test(lang)) return { codepage: 950, label: "Big5", utf8: false };
  if (/gb|zh/i.test(lang)) return { codepage: 936, label: "GBK/GB2312", utf8: false };
  if (/8859-1|latin-?1/i.test(lang)) return { codepage: 28591, label: "ISO-8859-1 (Latin-1)", utf8: false };
  if (/1252|cp1252/i.test(lang)) return { codepage: 1252, label: "Windows-1252", utf8: false };
  return { codepage: null, label: lang || "unknown", utf8: false };
}

// Sync fallback for Windows code page detection (avoids making detectSystemEncoding async).
function detectSystemEncodingSync() {
  try {
    const r = spawnSync("cmd", ["/c", "chcp"], { encoding: "utf8", windowsHide: true, timeout: 5000 });
    const out = (r.stdout || "") + (r.stderr || "");
    const m = out.match(/(\d+)/);
    const cp = m ? parseInt(m[1], 10) : null;
    if (cp === 65001) return { codepage: 65001, label: "UTF-8", utf8: true };
    if (cp === 936) return { codepage: 936, label: "GBK/GB2312", utf8: false };
    if (cp === 932) return { codepage: 932, label: "Shift-JIS", utf8: false };
    if (cp === 949) return { codepage: 949, label: "EUC-KR/CP949", utf8: false };
    if (cp === 950) return { codepage: 950, label: "Big5", utf8: false };
    if (cp === 874) return { codepage: 874, label: "Windows-874 (Thai)", utf8: false };
    if (cp === 1252) return { codepage: 1252, label: "Windows-1252", utf8: false };
    return { codepage: cp, label: `CP${cp}`, utf8: false };
  } catch {
    return { codepage: null, label: "unknown", utf8: false };
  }
}

// ---------- [1]+ File signature recognition library (magic bytes, 7-Zip/Bandizip approach) ----------
// Identify a file's true type from its header bytes rather than a spoofable/changeable
// extension. Coverage: archives / common images / audio / video / executables / documents.
// Extend by appending entries to FILE_SIGNATURES.
// Note: signature table is compiled from public format specs and open-source recognition
// approaches (e.g. 7-Zip's 7zHeader.h); licenses are independent (see README).
const FILE_SIGNATURES = [
  // A container and a preset family whose layout was established from samples on this machine. These
  // return to the local format table once the format layer has a first-class place for them; keeping
  // them here for now keeps the reader working, which comes first.
  { sig: [0x46, 0x4C, 0x68, 0x64], type: "audio", format: "kb-container", note: "native plugin container (FLhd header)" },
  { sig: [0x46, 0x4D, 0x69, 0x63], type: "audio", format: "fabfilter-preset", note: "preset of a mixing suite present on this machine" },
  // Media containers a player would name, recovered while reconciling a media player's own support
  // matrix against this library (research note: 2026-10-15). Only the families the engine could not
  // already place were kept - everything else overlapped what is below.
  { sig: [0x77, 0x76, 0x70, 0x6b], type: "audio", format: "wavpack", note: "WavPack lossless audio (77 76 70 6B)" },
  { sig: [0x54, 0x54, 0x41, 0x31], type: "audio", format: "tta", note: "True Audio lossless stream (54 54 41 31)" },
  { sig: [0x46, 0x52, 0x4d, 0x38], type: "audio", format: "dsdiff", note: "DSDIFF / DSD stream (46 52 4D 38, FRM8)" },
  { sig: [0x63, 0x61, 0x66, 0x66], type: "audio", format: "caf", note: "Core Audio Format (63 61 66 66, caff)" },
  // Archives / containers
  { sig: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], type: "archive", format: "7z", note: "7-Zip archive (37 7A BC AF 27 1C)" },
  { sig: [0x50, 0x4B, 0x03, 0x04], type: "archive", format: "zip", note: "ZIP / ZIP-based format (incl. docx/xlsx - disambiguate by extension)" },
  { sig: [0x50, 0x4B, 0x07, 0x08], type: "archive", format: "zip-spanned", note: "ZIP spanned/empty header" },
  { sig: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], type: "archive", format: "rar", note: "RAR archive" },
  { sig: [0x1F, 0x8B], type: "archive", format: "gzip", note: "GZIP" },
  { sig: [0x42, 0x5A, 0x68], type: "archive", format: "bzip2", note: "BZip2" },
  { sig: [0x28, 0xB5, 0x2F, 0xFD], type: "archive", format: "zstd", note: "Zstandard" },
  { sig: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], type: "archive", format: "xz", note: "XZ compressed stream (FD 37 7A 58 5A 00)" },
  { sig: [0x5D, 0x00, 0x00], type: "archive", format: "lzma", note: "LZMA-Alone stream (5D 00 00 prefix)" },
  { sig: [0x75, 0x73, 0x74, 0x61, 0x72], type: "archive", format: "tar", note: "TAR (ustar header)" },
  { sig: [0x4D, 0x50, 0x51, 0x1A], type: "archive", format: "mpq", note: "Blizzard MPQ archive (StarCraft/Warcraft, MPQ header)" },
  { sig: [0x43, 0x50, 0x4B, 0x20], type: "archive", format: "cri-cpk", note: "CRIWARE CPK container (CPK header)" },
  // Images (incl. game/engine resource formats)
  { sig: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], type: "image", format: "png", note: "PNG (8-byte header)" },
  { sig: [0xFF, 0xD8, 0xFF], type: "image", format: "jpeg", note: "JPEG (FF D8 FF)" },
  { sig: [0x42, 0x4D], type: "image", format: "bmp", note: "BMP (BM)" },
  { sig: [0x47, 0x49, 0x46, 0x38], type: "image", format: "gif", note: "GIF (GIF8)" },
  { sig: [0x49, 0x49, 0x2A, 0x00], type: "image", format: "tiff-le", note: "TIFF (II little-endian)" },
  { sig: [0x4D, 0x4D, 0x00, 0x2A], type: "image", format: "tiff-be", note: "TIFF (MM big-endian)" },
  { sig: [0x54, 0x4C, 0x47, 0x35, 0x2E, 0x30, 0x00, 0x00], type: "image", format: "tlg5", note: "KiriKiri/Emote TLG5 image (TLG5.0)" },
  { sig: [0x54, 0x4C, 0x47, 0x36, 0x2E, 0x30, 0x00, 0x00], type: "image", format: "tlg6", note: "KiriKiri/Emote TLG6 image (TLG6.0)" },
  { sig: [0x32, 0x2E, 0x30, 0x4E], type: "image", format: "aoe-slp", note: "Age of Empires graphics (SLP, 2.0N + ArtDesk header)" },
  { sig: [0x00, 0x00, 0x01, 0x00], type: "image", format: "ico", note: "Windows icon (ICO)" },
  // Audio
  { sig: [0x49, 0x44, 0x33], type: "audio", format: "mp3", note: "MP3 (ID3 tag)" },
  { sig: [0x4F, 0x67, 0x67, 0x53], type: "audio", format: "ogg", note: "OGG (OggS)" },
  { sig: [0x66, 0x4C, 0x61, 0x43], type: "audio", format: "flac", note: "FLAC (fLaC)" },
  { sig: [0x4D, 0x41, 0x43, 0x20], type: "audio", format: "ape", note: "Monkey's Audio APE (MAC )" },
  { sig: [0x44, 0x53, 0x44, 0x20], type: "audio", format: "dsf", note: "Sony DSF (DSD Stream File, 'DSD ' header)" },
  // Wavetable container adopted from the synthesis suites (research/adopted-plugins): a little-endian
  // magic, then version/frame counters, then float32 frames. 1E AB F7 FF is stable across samples.
  { sig: [0x1E, 0xAB, 0xF7, 0xFF], type: "audio", format: "wavetable", note: "wavetable (1E AB F7 FF + frame table)" },
  // VST presets
  { sig: [0x43, 0x63, 0x6E, 0x4B], type: "audio", format: "vst-preset", note: "VST preset (.fxp/.fxb, magic CcnK)" },
  { sig: [0x4D, 0x54, 0x68, 0x64], type: "audio", format: "midi", note: "MIDI (MThd header)" },
  { sig: [0x43, 0x41, 0x54, 0x20], type: "audio", format: "rex2", note: "Propellerhead REX2 sample (CAT  + REX2)" },
  { sig: [0x4E, 0x45, 0x58, 0x55, 0x53], type: "audio", format: "nexus-preset", note: "Nexus preset/arp (NEXUS2 header)" },
  { sig: [0x5A, 0x54, 0x44, 0x53], type: "audio", format: "ztdw-sample", note: "ZTDW compressed sample (ZTDS header)" },
  { sig: [0x32, 0x50, 0x4D, 0x44, 0x43], type: "audio", format: "kb-drum-patch", note: "drum patch (2PMDCrash header)" },
  { sig: [0x32, 0x69, 0x42, 0x54], type: "audio", format: "kb-synth-preset", note: "synth preset (2iBT header)" },
  { sig: [0x42, 0x4B, 0x48, 0x44], type: "audio", format: "wwise-bnk", note: "Wwise sound bank (BKHD header)" },
  { sig: [0x46, 0x52, 0x4D, 0x32], type: "audio", format: "vocaloid-db", note: "Vocaloid voice DB (FRM2 header)" },
  // Game resources
  { sig: [0x55, 0x6E, 0x69, 0x74, 0x79, 0x46, 0x53], type: "game", format: "unity-asset", note: "Unity asset bundle (UnityFS header)" },
  // Video / containers
  { sig: [0x4D, 0x4F, 0x4F, 0x56], type: "video", format: "mov/mp4-qt", note: "QuickTime/MOV (moov)" },
  { sig: [0x1A, 0x45, 0xDF, 0xA3], type: "video", format: "mkv/webm", note: "Matroska/WebM (EBML)" },
  { sig: [0x47, 0x40], type: "video", format: "mpeg-ts", note: "MPEG-2 transport stream (TS/live)" },
  { sig: [0x46, 0x4C, 0x56], type: "video", format: "flv", note: "Flash Video (FLV)" },
  // Executables / system
  { sig: [0x4D, 0x5A], type: "executable", format: "pe", note: "Windows executable (MZ, PE/EXE/DLL)" },
  { sig: [0x7F, 0x45, 0x4C, 0x46], type: "executable", format: "elf", note: "ELF (Linux executable/object/shared lib)" },
  // Documents
  { sig: [0x25, 0x50, 0x44, 0x46], type: "document", format: "pdf", note: "PDF (%PDF)" },
  { sig: [0x7B, 0x5C, 0x72, 0x74, 0x66], type: "document", format: "rtf", note: "Rich Text Format (RTF, 7B 5C 72 74 66)" },
  { sig: [0x49, 0x6E, 0x6E, 0x6F, 0x20, 0x53, 0x65, 0x74, 0x75, 0x70], type: "document", format: "inno-setup", note: "Inno Setup installer/uninstaller data" },
  // Databases
  { sig: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00], type: "database", format: "sqlite", note: "SQLite 3 database (SQLite format 3)" },
  { sig: [0x37, 0x7F, 0x06, 0x82], type: "database", format: "sqlite-wal", note: "SQLite write-ahead log (-wal sidecar)" },
  { sig: [0x37, 0x7F, 0x06, 0x83], type: "database", format: "sqlite-wal", note: "SQLite write-ahead log (-wal sidecar, big-endian checksum)" },
  // Images (additional)
  { sig: [0x38, 0x42, 0x50, 0x53], type: "image", format: "psd", note: "Photoshop PSD (8BPS)" },
  { sig: [0x76, 0x2F, 0x31, 0x01], type: "image", format: "exr", note: "OpenEXR image (magic 0x01312F76)" },
  { sig: [0x50, 0x53, 0x42, 0x00], type: "image", format: "psb", note: "KiriKiri/FreeMote PSB resource (PSB)" },
  // Databases (additional) - placed before TTF because ACE/Jet share the 00 01 00 00 prefix.
  { sig: [0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x41, 0x43, 0x45, 0x20, 0x44, 0x42], type: "database", format: "accdb", note: "Microsoft Access database (Standard ACE DB, ACE 2007+; .accdb/.accde/.accdu/.accda/.acc)" },
  { sig: [0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x4A, 0x65, 0x74, 0x20, 0x44, 0x42], type: "database", format: "mdb", note: "Microsoft Access database (Standard Jet DB, Access 97-2003; .mdb/.mde)" },
  // Fonts
  { sig: [0x00, 0x01, 0x00, 0x00], type: "font", format: "ttf", note: "TrueType font (sfnt 0x00010000)" },
  { sig: [0x4F, 0x54, 0x54, 0x4F], type: "font", format: "otf", note: "OpenType CFF font (OTTO)" },
  { sig: [0x77, 0x4F, 0x46, 0x46], type: "font", format: "woff", note: "Web Open Font Format (wOFF)" },
  { sig: [0x77, 0x4F, 0x46, 0x32], type: "font", format: "woff2", note: "Web Open Font Format 2 (wOF2)" },
  // Archives (additional)
  { sig: [0x58, 0x50, 0x33, 0x0D, 0x0A], type: "archive", format: "xp3", note: "KiriKiri XP3 archive (XP3)" },
  { sig: [0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E, 0x0A], type: "archive", format: "ar", note: "ar/COFF static library (!<arch>; .a and MSVC .lib)" },
  // Video / media
  { sig: [0x43, 0x57, 0x53], type: "video", format: "swf", note: "Flash SWF (CWS, zlib-compressed)" },
  { sig: [0x46, 0x57, 0x53], type: "video", format: "swf", note: "Flash SWF (FWS, uncompressed)" },
  // Models / serialization
  { sig: [0x08, 0x06, 0x12, 0x07], type: "model", format: "onnx", note: "ONNX model (protobuf 08 06 12 07)" },
  { sig: [0x80, 0x05], type: "document", format: "pickle", note: "Python pickle (protocol 5, 80 05)" },
  // Documents / other
  { sig: [0x51, 0x43, 0x34, 0x44, 0x43, 0x34, 0x44], type: "document", format: "c4d", note: "Cinema 4D document (QC4DC4D)" },
  { sig: [0x3C, 0x3C, 0x3C, 0x20, 0x4F, 0x72, 0x61, 0x63, 0x6C, 0x65], type: "document", format: "vdi", note: "Oracle VirtualBox disk image (<<< Oracle VM)" },
  // Images (additional)
  { sig: [0x67, 0x69, 0x6D, 0x70, 0x20, 0x78, 0x63, 0x66, 0x20], type: "image", format: "xcf", note: "GIMP XCF image (gimp xcf)" },
  { sig: [0x41, 0x54, 0x26, 0x54, 0x46, 0x4F, 0x52, 0x4D], type: "image", format: "djvu", note: "DjVu document (AT&TFORM)" },
  // Fonts (additional)
  { sig: [0x74, 0x74, 0x63, 0x66], type: "font", format: "ttc", note: "TrueType Collection font (ttcf)" },
  // Archives (additional)
  { sig: [0x4D, 0x53, 0x43, 0x46], type: "archive", format: "cab", note: "Microsoft Cabinet (MSCF)" },
  { sig: [0xED, 0xAB, 0xEE, 0xDB], type: "archive", format: "rpm", note: "RPM package (ED AB EE DB)" },
  // Audio (additional)
  { sig: [0x2E, 0x73, 0x6E, 0x64], type: "audio", format: "au", note: "Sun/NeXT AU audio (.snd)" },
  // Video (additional)
  { sig: [0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C], type: "video", format: "asf", note: "ASF container (WMA/WMV)" },
  { sig: [0x2E, 0x52, 0x4D, 0x46], type: "video", format: "realmedia", note: "RealMedia (RM/RMVB, .RMF)" },
  // Models (additional)
  { sig: [0x47, 0x47, 0x55, 0x46], type: "model", format: "gguf", note: "GGUF model (llama.cpp)" },
  { sig: [0x67, 0x67, 0x6D, 0x6C], type: "model", format: "ggml", note: "GGML model (llama.cpp legacy)" },
  // Web archive
  { sig: [0x57, 0x41, 0x52, 0x43, 0x2F], type: "document", format: "warc", note: "WARC web archive (WARC/)" },
  // Audio (professional - Dolby/DTS)
  { sig: [0x0B, 0x77], type: "audio", format: "ac3", note: "Dolby Digital AC3/E-AC3 (sync 0B 77)" },
  { sig: [0x7F, 0xFE, 0x80, 0x01], type: "audio", format: "dts", note: "DTS audio (sync 7F FE 80 01)" },
  { sig: [0xF8, 0x72, 0x6F, 0xBA], type: "audio", format: "truehd", note: "Dolby TrueHD / MLP (F8 72 6F BA)" },
  // CAD / 3D engineering
  { sig: [0x41, 0x43, 0x31, 0x30], type: "document", format: "dwg", note: "AutoCAD DWG (AC10xx)" },
  { sig: [0x28, 0x44, 0x57, 0x46], type: "document", format: "dwf", note: "Autodesk DWF ((DWF)" },
  { sig: [0x42, 0x4C, 0x45, 0x4E, 0x44, 0x45, 0x52], type: "document", format: "blend", note: "Blender 3D project (BLENDER)" },
  { sig: [0x67, 0x6C, 0x54, 0x46], type: "model", format: "glb", note: "glTF binary (glTF)" },
  // Documents (OLE2 compound)
  { sig: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], type: "document", format: "ole2", note: "OLE2 compound document (DOC/XLS/PPT/INDD/PUB/MSI)" },
  // Disk images
  { sig: [0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78], type: "document", format: "vhd", note: "Virtual Hard Disk (conectix)" },
  { sig: [0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65], type: "document", format: "vhdx", note: "Virtual Hard Disk v2 (vhdxfile)" },
  { sig: [0x51, 0x46, 0x49, 0xFB], type: "document", format: "qcow2", note: "QEMU QCOW2 disk image (QFI FB)" },
  { sig: [0x4D, 0x53, 0x57, 0x49, 0x4D], type: "archive", format: "wim", note: "Windows Imaging Format (MSWIM)" },
  // Scientific / ML data
  { sig: [0x89, 0x48, 0x44, 0x46, 0x0D, 0x0A, 0x1A, 0x0A], type: "model", format: "hdf5", note: "HDF5 scientific data (89 48 44 46)" },
  { sig: [0x93, 0x4E, 0x55, 0x4D, 0x50, 0x59], type: "document", format: "npy", note: "NumPy array (93 NUMPY)" },
  // Professional video exchange
  { sig: [0x06, 0x0E, 0x2B, 0x34, 0x02, 0x05, 0x01, 0x01, 0x0D, 0x01, 0x02, 0x01, 0x01, 0x02], type: "video", format: "mxf", note: "MXF professional media container (KLV key)" },
  // MikuMikuDance / Vocaloid / 3D model formats
  { sig: [0x50, 0x6D, 0x64, 0x00], type: "model", format: "pmd", note: "MikuMikuDance model (PMD, Pmd)" },
  { sig: [0x50, 0x4D, 0x58, 0x20], type: "model", format: "pmx", note: "MikuMikuDance model (PMX)" },
  { sig: [0x50, 0x6F, 0x6C, 0x79, 0x67, 0x6F, 0x6E], type: "document", format: "pmm", note: "MikuMikuDance project (PMM, Polygon Movie maker)" },
  { sig: [0x78, 0x6F, 0x66, 0x20], type: "model", format: "directx", note: "DirectX .x model (xof)" },
  { sig: [0x56, 0x6F, 0x63, 0x61, 0x6C, 0x6F, 0x69, 0x64], type: "document", format: "vpd", note: "Vocaloid/MMD pose data (Vocaloid Pose Data file)" },
  // Developer toolchains (Visual Studio / MSBuild / SQL Server) - headers verified against
  // files shipped with Visual Studio 2022 & 2026 and SSMS 22.
  { sig: [0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x2F, 0x43, 0x2B, 0x2B, 0x20], type: "executable", format: "pdb", note: "Microsoft program database (debug symbols, 'Microsoft C/C++ ')" },
  { sig: [0x4D, 0x53, 0x46, 0x54, 0x02, 0x00], type: "executable", format: "tlb", note: "COM type library (MSFT 2.0 header; .tlb/.olb)" },
  { sig: [0x56, 0x53, 0x57, 0x49, 0x5A, 0x41, 0x52, 0x44, 0x20], type: "document", format: "vsz", note: "Visual Studio wizard (VSWIZARD)" },
  { sig: [0x64, 0x65, 0x78, 0x0A], type: "executable", format: "dex", note: "Android Dalvik executable (dex\\n)" },
  // Help / graphics resources shipped with developer tools (CUR is handled as a special
  // case: its 00 00 02 00 header collides with TGA image-type 2).
  { sig: [0x49, 0x54, 0x53, 0x46], type: "document", format: "chm", note: "Compiled HTML Help (ITSF)" },
  { sig: [0x3F, 0x5F, 0x03, 0x00], type: "document", format: "hlp", note: "Windows Help (HLP 3.x header)" },
  { sig: [0x44, 0x44, 0x53, 0x20], type: "image", format: "dds", note: "DirectDraw Surface texture (DDS )" },
  // OneNote (Office) revision store - file-type GUID at offset 0.
  { sig: [0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3], type: "document", format: "one", note: "OneNote section/page (.one; .onepkg is CAB)" },
  { sig: [0xA1, 0x2F, 0xFF, 0x43, 0xD9, 0xEF, 0x76, 0x4C, 0x9E, 0xE2, 0x10, 0xEA, 0x57, 0x22, 0x76, 0x5F], type: "document", format: "onetoc2", note: "OneNote 2007+ index (.onetoc2)" },
];

// Read the first N bytes (default 8) of a file; returns a Buffer or null on failure.
function readHeader(filePath, len = 8) {
  try {
    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(len);
    const read = fs.readSync(fd, buf, 0, len, 0);
    fs.closeSync(fd);
    return read > 0 ? buf.subarray(0, read) : null;
  } catch {
    return null;
  }
}

// Extension whitelist used by the plain-text heuristic in sniffFileType.
// ZIP-based (OPC/OOXML) packages share the PK header, so the extension is the only
// discriminator. Verified against Office 2016 / Visual Studio 2022-2026 / SSMS 22 files.
const ZIP_PACKAGE_FORMATS = {
  docx: ["document", "Word document"], docm: ["document", "Word macro-enabled document"],
  dotx: ["document", "Word template"], dotm: ["document", "Word macro-enabled template"],
  xlsx: ["document", "Excel workbook"], xlsm: ["document", "Excel macro-enabled workbook"],
  xlsb: ["document", "Excel binary workbook"], xltx: ["document", "Excel template"],
  xltm: ["document", "Excel macro-enabled template"], xlam: ["document", "Excel add-in"],
  pptx: ["document", "PowerPoint presentation"], pptm: ["document", "PowerPoint macro-enabled presentation"],
  potx: ["document", "PowerPoint template"], potm: ["document", "PowerPoint macro-enabled template"],
  ppsx: ["document", "PowerPoint slide show"], ppsm: ["document", "PowerPoint macro-enabled slide show"],
  thmx: ["document", "Office theme package"],
  accdt: ["document", "Access database template"], accft: ["document", "Access field template"],
  odt: ["document", "ODF text"], ods: ["document", "ODF sheet"], odp: ["document", "ODF presentation"],
  odg: ["document", "ODF graphics"], epub: ["document", "EPUB ebook"],
  dacpac: ["archive", "SQL data-tier application"], vsix: ["archive", "Visual Studio extension"],
  nupkg: ["archive", "NuGet package"], jar: ["archive", "Java archive"],
  appx: ["archive", "Windows app package"], msix: ["archive", "MSIX app package"],
  ilv: ["archive", "impulse-library package (ZIP-based)"],
}

// Machine-local format knowledge. Some file families are recognised through a table that is recorded
// locally rather than shipped, because the table was recovered from this machine's own files. The
// engine carries only the mechanism: it loads deps/local/native-formats.json when that file exists
// and behaves as if the table were empty when it does not, so the published source carries no
// third-party format knowledge and no reference to where any of it came from.
function loadLocalNativeFormats() {
  const empty = { containers: {}, signatures: [], textExtensions: [] };
  try {
    // Deliberately outside the package: a table recovered on this machine belongs with this machine's
    // library, not in the source tree, where it could be published by accident.
    const file = path.join(libraryDir(), "native-formats.json");
    if (!fs.existsSync(file)) return empty;
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    return {
      containers: data.containers && typeof data.containers === "object" ? data.containers : {},
      signatures: Array.isArray(data.signatures) ? data.signatures : [],
      textExtensions: Array.isArray(data.textExtensions) ? data.textExtensions : [],
    };
  } catch {
    return empty;
  }
}

const LOCAL_NATIVE_FORMATS = loadLocalNativeFormats();
const NATIVE_CONTAINER_FORMATS = LOCAL_NATIVE_FORMATS.containers;
const NATIVE_SIGNATURES = LOCAL_NATIVE_FORMATS.signatures;
const NATIVE_TEXT_EXTENSIONS = LOCAL_NATIVE_FORMATS.textExtensions;

// Content probes: a handful of extensions are too generic for a magic (.map is claimed by engine
// maps, symbol maps and colour ramps alike), so those are decided from the leading bytes read as
// text. A probe that does not match falls through to the ordinary text heuristic: none of them
// guesses, and a real signature always wins because this table is consulted after the magic tables.
const CONTENT_PROBES = [
  { ext: "map", test: /^\s*\[rgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+/, type: "other", format: "color-map", note: "colour ramp (rgb/rgba stops)" },
  { ext: "vfpatch", test: /^\s*\{\s*"parameters"/, type: "audio", format: "voice-patch", note: "voice-processing patch (JSON parameter set)" },
  { ext: "mms", test: /^\s*[A-Za-z_][A-Za-z0-9_]*\s*\{/, type: "other", format: "meter-session", note: "meter session (block language)" },
];
const TEXT_EXTENSIONS = [
  // subtitle and playlist formats: their content is text, and the extension is the only
  // discriminator a small or truncated file offers.
  "ass", "ssa", "vtt", "sub", "m3u", "m3u8", "pls", "xspf", "wpl", "dpl", "cue",

  // plain text / scripts / config / dotfiles
  "txt", "md", "log", "csv", "json", "jsonl", "ndjson", "ps1", "sh", "py", "js", "mjs", "cjs", "ts", "bat", "cmd", "yaml", "yml", "ini", "xml", "html", "htm", "css", "toml", "cfg", "conf", "config", "reg", "properties", "plist", "manifest", "nfo", "srt", "vdf", "qml", "mm", "env", "gitignore", "gitattributes", "editorconfig",
  // scratch / temp artifacts (content is whatever the writer put there)
  "tmp", "temp", "part", "partial", "crdownload", "bak", "orig", "swp", "swo", "pid",
  // C family / build systems
  "c", "h", "cpp", "hpp", "cc", "hh", "cs", "cxx", "hxx", "ixx", "inl", "def", "asm", "s", "inc", "cmake", "make", "ninja", "gypi", "m4", "lua", "pl", "awk", "rst", "adoc", "jsx", "tsx", "scss", "less", "vue", "pug", "jade", "coffee", "map", "in",
  // shaders / DCC interchange
  "glsl", "hlsl", "hlsli", "osl", "sl", "cginc", "glslinc", "ocio", "cube", "lut", "look", "itx", "spi1d", "spi3d", "epr", "mtlx", "usda", "svg", "dxf", "step", "stp", "iges", "igs", "obj", "stl", "ply", "gltf", "dae", "x3d", "mtl", "wrl",
  // audio / score / font metadata / app-specific text
  "sfz", "mscx", "afm", "pfm", "inf", "cf", "cfu", "tab", "tsv", "pem", "pth", "mht", "mhtml", "fb2", "vac", "aupreset", "kps", "kpsstats", "effect", "mcfunction", "osu", "osr", "vsclip", "vsstyle", "kys", "ksvlayout",
  // Visual Studio / MSBuild / .NET toolchain (verified against VS 2022-2026 + SSMS 22 files)
  "sln", "vcxproj", "vcxitems", "csproj", "vbproj", "fsproj", "njsproj", "pyproj", "sqlproj", "shproj", "sfproj", "wapproj", "projitems", "props", "targets", "filters", "resx", "resw", "resjson", "xaml", "xamlx", "xsd", "xsl", "xslt", "xlf", "snippet", "vstemplate", "vstemplatex", "vstman", "vsdir", "vstdir", "vsixmanifest", "vsixlangpack", "vsct", "pkgdef", "pkgundef", "ruleset", "natvis", "natjmc", "natstepfilter", "imagemanifest", "tmlanguage", "tmsnippet", "tmtheme", "vssettings", "settings", "myapp", "testsettings", "appinstaller", "appxmanifest", "pubxml", "cscfg", "csdef", "wprp", "webinfo", "package", "spdata", "dgsl", "webpart",
  // SQL Server / data tooling
  "sql", "usql", "dmx", "mdx", "xmla", "mof", "rsp", "tt", "t4", "ttinclude", "rdlc",
  // .NET & web app text
  "vb", "fs", "fsx", "fsi", "aspx", "ascx", "asmx", "ashx", "asax", "cshtml", "vbhtml", "master", "skin", "svc", "sitemap", "psm1", "psd1", "ps1xml", "idl", "odl", "acf", "rc", "rgs",
  // Office text resources
  "xrm-ms", "hxc", "hxt", "hxk",
  // documents / man pages / misc
  "man", "1", "5", "7", "dic", "pyx", "pyi", "f", "f90", "cu", "m",
  // other toolchains
  "go", "lock",
];

// Match header bytes against the signature table; returns { type, format, note } or null.
function sniffFileType(filePath) {
  const head = readHeader(filePath, 128);
  if (!head) return null;
  const ext = path.extname(filePath).toLowerCase().replace(".", "");
  for (const entry of FILE_SIGNATURES) {
    const sigLen = entry.sig.length;
    if (sigLen > head.length) continue;
    let match = true;
    for (let i = 0; i < sigLen; i++) {
      if (head[i] !== entry.sig[i]) { match = false; break; }
    }
    if (!match) continue;
    // ZIP-based (OPC/OOXML) packages: disambiguate by extension (they all start with PK).
    if (entry.format === "zip") {
      const pkg = ZIP_PACKAGE_FORMATS[ext];
      if (pkg) return { type: pkg[0], format: ext, note: `ZIP-based package (${pkg[1]})` };
    }
    // GZIP-based project: Ableton Live Set (.als) is gzip-compressed XML.
    if (entry.format === "gzip" && ext === "als") {
      return { type: "audio", format: "ableton", note: "Ableton Live Set (gzip-compressed XML)" };
    }
    // The native project container: its header chunk is shared by the project, preset andfsc, so the
    // extension is what discriminates (kohane-index-desuno extension; see NATIVE_CONTAINER_FORMATS).
    if (entry.format === "kb-container") {
      const fl = NATIVE_CONTAINER_FORMATS[ext];
      if (fl) return { type: fl[0], format: ext, note: fl[1] };
    }
    return { type: entry.type, format: entry.format, note: entry.note };
  }
  // Native plugin preset/pattern formats (kohane-index-desuno extension; see NATIVE_SIGNATURES).
  // Checked after the built-in table so a built-in signature always wins. Entries may declare an
  // offset (`at`) and a digit-version constraint (`digit0`) because the family varies that byte.
  for (const entry of NATIVE_SIGNATURES) {
    const at = entry.at || 0;
    const sigLen = entry.sig.length;
    if (at + sigLen > head.length) continue;
    if (entry.digit0 && !(head[0] >= 0x30 && head[0] <= 0x39)) continue;
    let match = true;
    for (let i = 0; i < sigLen; i++) {
      if (head[at + i] !== entry.sig[i]) { match = false; break; }
    }
    if (match) return { type: entry.type, format: entry.format, note: entry.note };
  }
  // RIFF special-case: bytes 8-11 WAVE->audio/wav, AVI->video/avi, NIKS->NKS sample.
  if (head.length >= 12 && head[0] === 0x52 && head[1] === 0x49 && head[2] === 0x46 && head[3] === 0x46) {
    const kind = head.slice(8, 12).toString("latin1");
    if (kind === "WAVE") return { type: "audio", format: "wav", note: "RIFF-WAVE audio" };
    if (kind === "AVI ") return { type: "video", format: "avi", note: "RIFF-AVI video" };
    if (kind === "NIKS") return { type: "audio", format: "nks", note: "Native Instruments NKS sample (RIFF NIKS)" };
    if (kind === "WEBP") return { type: "image", format: "webp", note: "WebP (RIFF WEBP)" };
    if (kind === "sfbk") return { type: "audio", format: "sf2", note: "SoundFont 2 (RIFF sfbk)" };
    if (kind.startsWith("CDR")) return { type: "image", format: "cdr", note: `CorelDRAW (RIFF ${kind.trim()})` };
    return { type: "audio", format: "riff", note: "RIFF container (unrecognized sub-type)" };
  }
  // AIFF special-case: FORM + AIFF/AIFC at bytes 8-11.
  if (head.length >= 12 && head[0] === 0x46 && head[1] === 0x4F && head[2] === 0x52 && head[3] === 0x4D) {
    const kind = head.slice(8, 12).toString("latin1");
    if (kind === "AIFF" || kind === "AIFC") return { type: "audio", format: "aiff", note: "AIFF audio (FORM + AIFF/AIFC)" };
  }
  // MP4/QuickTime ftyp special-case: 'ftyp' at offset 4. AVIF (AV1 still image) shares
  // the ftyp box but is an image, not video - disambiguate by the major brand.
  if (head.length >= 8 && head[4] === 0x66 && head[5] === 0x74 && head[6] === 0x79 && head[7] === 0x70) {
    const brand = head.slice(8, 12).toString("latin1");
    if (brand === "avif" || brand === "avis") {
      return { type: "image", format: "avif", note: `AVIF (AV1 image, ftyp ${brand})` };
    }
    if (["heic", "heix", "hevc", "hevx", "mif1", "msf1", "hevm", "heim", "heis"].includes(brand)) {
      return { type: "image", format: "heic", note: `HEIC/HEIF image (ftyp ${brand})` };
    }
    return { type: "video", format: "mp4", note: `MP4 (ftyp${brand ? ` ${brand}` : ""})` };
  }
  // Vocaloid DB index special-case: 'DBSe' at offset 8.
  if (head.length >= 12 && head[8] === 0x44 && head[9] === 0x42 && head[10] === 0x53 && head[11] === 0x65) {
    return { type: "audio", format: "vocaloid-db-index", note: "Vocaloid DB index (DBSe at offset 8)" };
  }
  // MOBI/AZW ebook: "BOOKMOBI" or "TEXtREAd" at offset 60.
  if (head.length >= 68) {
    const mtag = head.slice(60, 68).toString("latin1");
    if (mtag === "BOOKMOBI" || mtag === "TEXtREAd") {
      return { type: "document", format: "mobi", note: "Mobipocket/Kindle ebook (MOBI/AZW)" };
    }
  }
  // zlib deflate stream: CMF=0x78 with valid (CMF<<8 | FLG) checksum.
  if (head.length >= 2 && head[0] === 0x78 && (((head[0] << 8) | head[1]) % 31 === 0)) {
    return { type: "archive", format: "zlib", note: "zlib deflate stream" };
  }
  // Mach-O (macOS/iOS executable/library): four magic variants (32/64-bit x endian).
  if (head.length >= 4) {
    const mh = head.slice(0, 4).toString("hex");
    if (mh === "cffaedfe" || mh === "cefaedfe" || mh === "feedfacf" || mh === "feedface") {
      return { type: "executable", format: "macho", note: "Mach-O (macOS/iOS executable/library)" };
    }
  }
  // 3DS (3D Studio): 'MM' (0x4D4D main chunk) at offset 0 + '==' (0x3D3D version chunk)
  // at offset 6 - avoids matching text files that merely start with "MM".
  if (head.length >= 8 && head[0] === 0x4D && head[1] === 0x4D && head[6] === 0x3D && head[7] === 0x3D) {
    return { type: "document", format: "3ds", note: "3D Studio 3DS (MM + 3D 3D version)" };
  }
  // Cursor (CUR): 00 00 02 00 + a plausible image count (bytes 4-5). Kept out of the
  // signature table because TGA image-type 2 files also begin with 00 00 02 00.
  if (head.length >= 6 && head[0] === 0 && head[1] === 0 && head[2] === 2 && head[3] === 0 && ext !== "tga") {
    const count = head[4] | (head[5] << 8);
    if (count >= 1 && count <= 32) return { type: "image", format: "cur", note: "Windows cursor (CUR)" };
  }
  // TGA (Truevision) image: no leading magic - identify by header fields (image-type
  // at byte 2, pixel-depth at byte 16, color-map-type at byte 1).
  if (head.length >= 18 && [0, 1].includes(head[1]) && [0, 1, 2, 3, 9, 10, 11].includes(head[2]) && [8, 15, 16, 24, 32].includes(head[16])) {
    return { type: "image", format: "tga", note: "Truevision TGA image" };
  }
  // Envelope state (.fnv / .env): carries NO magic - it is a small, 4-byte-aligned float table led
  // by two small counters. Profile of 400+ samples from a real installation: size % 4 === 0 and
  // <= 4 KiB, u32[0] in 1..15, u32[1] in 0..15. Gated on the extension AND those structural bounds,
  // so it cannot mislabel an unrelated file (a dotenv .env is text and is caught later by the text
  // heuristic). kohane-index-desuno extension; see research/fl-studio.
  if ((ext === "fnv" || ext === "env") && head.length >= 12) {
    let fnvSize = 0;
    try { fnvSize = fs.statSync(filePath).size; } catch {}
    const u0 = head.readUInt32LE(0), u1 = head.readUInt32LE(4);
    if (fnvSize > 0 && fnvSize % 4 === 0 && fnvSize <= 4096 && u0 >= 1 && u0 <= 15 && u1 <= 15) {
      return { type: "audio", format: "kb-envelope", note: "envelope state (u32-led float table)" };
    }
  }
  // Visual Studio solution (.sln): plain text that may be preceded by a BOM or a blank
  // line, so locate the format marker instead of matching a fixed offset.
  if (ext === "sln" && head.indexOf("Microsoft Visual Studio Solution File") !== -1) {
    return { type: "document", format: "sln", note: "Visual Studio solution (text)" };
  }
  // Local (per-install) signatures are matched last: a locally learned format may only
  // fill a gap, it can never shadow a built-in format.
  const local = loadLocalFormats();
  for (const lf of local.formats) {
    if (lf.sig.length > head.length) continue;
    if (lf.sig.every((b, i) => head[i] === b)) {
      return { type: lf.type, format: lf.format, note: `${lf.note || "locally learned format"} (local pack)` };
    }
  }
  // Plain-text heuristic. A BOM is a strong text signal independent of extension (it
  // covers JSON stored as .db, UTF-16 Windows/Office/VS resources, extensionless text,
  // etc.) and never misclassifies binary files, so it is checked before the whitelist.
  // Go module metadata: .mod/.sum are ambiguous extensions (ProTracker modules also use
  // .mod), so match the well-known file names instead of the extension.
  const base = path.basename(filePath).toLowerCase();
  if (base === "go.mod" || base === "go.sum") {
    return { type: "document", format: base.replace(".", "-"), note: `Go module metadata (${base}, text)` };
  }
  if (head[0] === 0xEF && head[1] === 0xBB && head[2] === 0xBF) {
    return { type: "document", format: ext || "text", note: `UTF-8 text (BOM${ext ? `, .${ext}` : ", no extension"})` };
  }
  // UTF-16 BOM (FF FE little-endian / FE FF big-endian): common for Windows toolchain
  // resources (.rc/.tt/.psd1/.pkgdef) where every ASCII byte is NUL-padded.
  if (head.length >= 2 && ((head[0] === 0xFF && head[1] === 0xFE) || (head[0] === 0xFE && head[1] === 0xFF))) {
    return { type: "document", format: ext || "text", note: `UTF-16 text (BOM${ext ? `, .${ext}` : ", no extension"})` };
  }
  // Extensionless plain-ASCII metadata (e.g. VRChat __info cache entries, version
  // stamps): every byte is printable ASCII/whitespace - a strong text signal that
  // never matches binary blobs (which contain control bytes).
  if (!ext && head.length > 0 && head.every((b) => b === 0x09 || b === 0x0A || b === 0x0D || (b >= 0x20 && b <= 0x7E))) {
    return { type: "document", format: "text", note: "extensionless plain text" };
  }
  // Content probes run before the generic text verdict, so a generic extension can still say what it
  // holds; a probe that does not match leaves the decision to the heuristic below.
  const probeText = head.toString("utf8", 0, Math.min(head.length, 512));
  for (const probe of CONTENT_PROBES) {
    if (ext !== probe.ext) continue;
    if (!probe.test.test(probeText)) continue;
    return { type: probe.type, format: probe.format, note: probe.note };
  }
  if (TEXT_EXTENSIONS.includes(ext)
 || NATIVE_TEXT_EXTENSIONS.includes(ext) || local.textExtensions.includes(ext)) {
    const looksText = head.every((b, i) => i === 0 ? true : (b === 0x09 || b === 0x0A || b === 0x0D || (b >= 0x20 && b <= 0x7E) || b >= 0x80));
    if (looksText) return { type: "document", format: ext, note: `plain text / script (${ext})` };
  }
  return null;
}

// [3] Known handy tools/environments/toolchains (registered on scan; installing missing
// ones requires an instruction + report). Each tool may carry `alts` - alternative
// paths across platforms - so the same scan works on Windows / macOS / Linux.
const DETECT_CANDIDATES = [
  { type: "tool", name: "MediaInfo", path: "E:\\DaShaoHuo\\downloads\\mediainfo-cli\\MediaInfo.exe", alts: ["/usr/bin/mediainfo", "/usr/local/bin/mediainfo", "/opt/homebrew/bin/mediainfo", "/opt/local/bin/mediainfo", "/snap/bin/mediainfo"], desc: "media metadata analysis" },
  { type: "tool", name: "ffmpeg", path: "D:\\ffmpeg-8.1.1-essentials_build\\bin\\ffmpeg.exe", alts: ["/usr/bin/ffmpeg", "/usr/local/bin/ffmpeg", "/opt/homebrew/bin/ffmpeg", "/opt/local/bin/ffmpeg", "/snap/bin/ffmpeg"], desc: "transcoding / media processing" },
  { type: "tool", name: "ffprobe", path: "D:\\ffmpeg-8.1.1-essentials_build\\bin\\ffprobe.exe", alts: ["/usr/bin/ffprobe", "/usr/local/bin/ffprobe", "/opt/homebrew/bin/ffprobe", "/opt/local/bin/ffprobe", "/snap/bin/ffprobe"], desc: "media probing (alternative fingerprint source)" },
  { type: "tool", name: "uv", path: "E:\\DaShaoHuo\\uv\\uv.exe", alts: ["/usr/local/bin/uv", "/opt/homebrew/bin/uv", "/opt/local/bin/uv", "/snap/bin/uv", "~/.local/bin/uv"], desc: "Python package/interpreter manager" },
  { type: "env", name: "llm_toolkit_api", path: "http://127.0.0.1:8100", desc: "local multimodal/retrieval toolkit (needs startup)" },
  { type: "env", name: "DSH_HOME", path: process.env.DSH_HOME || path.join(os.homedir(), ".dsh"), desc: "DSH home directory (host navigation)" },
  { type: "env", name: "Windows SDK", path: "C:\\Program Files (x86)\\Windows Kits\\10", desc: "Windows development SDK" },
  { type: "env", name: "Visual Studio 2026 Community", path: "E:\\VSPnEBs\\Microsoft Visual Studio\\18\\Community", desc: "Visual Studio Community 2026 (18.10) + MSVC 14.51.36231 (v145) + MSBuild; no vcpkg in this instance (vcpkg lives in the VS 2022 instance)" },
  { type: "env", name: "Visual Studio 2022 Community", path: "E:\\VSPnEBs\\Microsoft Visual Studio\\2022\\Community", alts: ["C:\\Program Files\\Microsoft Visual Studio\\2022\\Community"], desc: "Visual Studio Community 2022 17.14; 16 workloads, MSVC 14.44.35207 (v143), vcpkg, Clang/LLVM, MFC/ATL, WDK driver toolset (~17 GB)" },
  { type: "env", name: "SSMS 22", path: "E:\\VSPnEBs\\Microsoft SQL Server Management Studio 22\\Release", desc: "SQL Server Management Studio 22" },
  { type: "env", name: "Microsoft Office 2016 ProPlus", path: "C:\\Program Files\\Microsoft Office\\root\\Office16", desc: "Office 2016 ProPlus 16.0 ClickToRun: Word/Excel/PowerPoint/Access/Outlook/Publisher/OneNote (COM automation; ACE DB engine for accdb/mdb)" },
  { type: "env", name: "WDK (Windows Driver Kit)", path: "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.26100.0\\km", desc: "WDK 10.0.26100 fully installed (km/wdf headers, wdf libs, Inf2Cat/stampinf); VS integration installed into the VS 2022 instance" },
  { type: "tool", name: "Go", path: "E:\\DaShaoHuo\\go\\bin\\go.exe", alts: ["/usr/local/go/bin/go", "/opt/homebrew/bin/go", "/opt/local/bin/go", "/snap/bin/go"], desc: "Go 1.27.1 toolchain (GOPATH/GOCACHE/GOMODCACHE all on E:)" },
  { type: "tool", name: "Git", path: "C:\\Program Files\\Git\\cmd\\git.exe", alts: ["/usr/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git", "/opt/local/bin/git", "/snap/bin/git"], desc: "Git 2.55.0 for Windows" },
  { type: "env", name: "DSH temp dir", path: process.env.TEMP || process.env.TMP || os.tmpdir(), desc: "DSH/Windows scratch area: per-run .tmpXXXXXX dirs, payload/log/err files (library_sniff dir mode can sweep it)" },
];

// Project-local tool candidates, kept OUTSIDE the DETECT_CANDIDATES array literal.
// kohane-index-desuno is the universal + extended edition, so its own additions live in its own
// tables and are never dropped by a reference build. See tools/reference-check.mjs (read-only
// cross-check; it never writes).
DETECT_CANDIDATES.push(
  { type: "tool", name: "Unity Editor", path: "E:\\Unity\\Editor\\Unity.exe", alts: ["/Applications/Unity/Hub/Editor"], desc: "Unity Editor (project analysis runs without launching it; the editor is only needed for batch builds)" },
  { type: "tool", name: "Blender", path: "E:\\Blender Foundation\\Blender 4.4\\blender.exe", alts: ["/usr/bin/blender", "/usr/local/bin/blender", "/Applications/Blender.app/Contents/MacOS/Blender"], desc: "Blender 4.4 CLI (background scene statistics for analyze_object deep mode)" },
);

// Resolve a DETECT candidate's actual existing path across path + alts.
function resolveCandidatePath(c) {
  const candidates = [c.path, ...(c.alts || [])].filter(Boolean);
  for (const p of candidates) {
    if (p.startsWith("~")) {
      const expanded = path.join(os.homedir(), p.slice(1));
      if (fs.existsSync(expanded)) return expanded;
      continue;
    }
    if (fs.existsSync(p)) return p;
  }
  return null;
}

// ---------- Local tool/env candidate pack: per-install personalisation ----------
// DETECT_CANDIDATES above is a fixed list; every machine has its own toolchains, SDKs,
// runtimes and services (in-house CLIs, private engines, local daemons). The local pack
// records them so library_detect adapts to THIS installation, with the same invariants as the
// format pack: built-ins always win, conflicts are refused unless explicitly confirmed,
// proposing never records anything, and no candidate is ever executed - a path is only
// recorded and checked for existence.
function candidatesFile() {
  return path.join(libraryDir(), "candidates.local.json");
}

function emptyCandidatePack() {
  return { version: 1, updatedAt: null, candidates: [] };
}

function normalizeCandidatePack(raw) {
  const d = emptyCandidatePack();
  if (!raw || typeof raw !== "object") return d;
  d.updatedAt = raw.updatedAt || null;
  for (const c of Array.isArray(raw.candidates) ? raw.candidates : []) {
    const type = c && c.type === "env" ? "env" : c && c.type === "tool" ? "tool" : null;
    const name = String((c && c.name) || "").trim();
    const p = String((c && c.path) || "").trim();
    if (!type || !name || !p) continue;
    d.candidates.push({
      type,
      name: name.slice(0, 120),
      path: p.slice(0, 400),
      alts: (Array.isArray(c.alts) ? c.alts : []).map((a) => String(a).slice(0, 400)).slice(0, 20),
      desc: String((c && c.desc) || "").slice(0, 300),
      createdAt: (c && c.createdAt) || null,
    });
  }
  return d;
}

let _candPack = { key: null, data: null };

function loadLocalCandidates() {
  let key = "absent";
  try {
    const st = fs.statSync(candidatesFile());
    key = `${st.mtimeMs}:${st.size}`;
  } catch {
    key = "absent";
  }
  if (_candPack.data && _candPack.key === key) return _candPack.data;
  let data = emptyCandidatePack();
  if (key !== "absent") {
    try {
      data = normalizeCandidatePack(JSON.parse(fs.readFileSync(candidatesFile(), "utf8")));
    } catch {
      data = emptyCandidatePack();
    }
  }
  _candPack = { key, data };
  return data;
}

function saveLocalCandidates(pack) {
  ensureLibrary();
  pack.version = 1;
  pack.updatedAt = new Date().toISOString();
  fs.writeFileSync(candidatesFile(), JSON.stringify(pack, null, 2), "utf8");
  _candPack = { key: null, data: null };
  return candidatesFile();
}

// Built-in entries a candidate would collide with (same type + name).
function builtinCandidateConflicts(c) {
  return DETECT_CANDIDATES
    .filter((b) => b.type === c.type && b.name.toLowerCase() === String(c.name || "").toLowerCase())
    .map((b) => `${b.type} ${b.name}`);
}

// Built-ins first, then local entries; a local entry with a built-in's key never shadows it.
function allCandidates() {
  const local = loadLocalCandidates().candidates;
  const builtinKeys = new Set(DETECT_CANDIDATES.map((b) => `${b.type}::${b.name.toLowerCase()}`));
  return [
    ...DETECT_CANDIDATES.map((c) => ({ ...c, origin: "builtin" })),
    ...local.map((c) => ({ ...c, origin: "local", shadowed: builtinKeys.has(`${c.type}::${c.name.toLowerCase()}`) })),
  ];
}

// Executables/scripts found in a directory - proposals only, nothing is recorded.
const PROPOSAL_EXTS = new Set(["exe", "bat", "cmd", "ps1", "sh", "mjs", "cjs", "py", "jar"]);
function proposeCandidates(dir, maxFiles = 500) {
  const groups = new Map();
  for (const f of walkFiles(dir, maxFiles)) {
    const ext = path.extname(f).toLowerCase().replace(".", "");
    if (!PROPOSAL_EXTS.has(ext)) {
      const s = sniffFileType(f);
      if (!(s && s.type === "executable")) continue;
    }
    const key = ext || "no-ext";
    const g = groups.get(key) || { ext: key, count: 0, samples: [], dirs: [] };
    g.count++;
    if (g.samples.length < 5) {
      g.samples.push(f);
      const d = sanitizePath(path.dirname(f), "dirs", 3, []);
      if (!g.dirs.includes(d)) g.dirs.push(d);
    }
    groups.set(key, g);
  }
  return [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 40);
}

// Key management (v2): derive an AES-256 key from a master secret + random salt via
// HKDF-SHA256, replacing v1's "raw hex key file". Even if the key file is copied away,
// it cannot be decrypted without the master secret.
// Master secret source priority: env DSH_LIBRARY_MASTER_KEY > .library.master file
// (generated alongside the library; v1 raw files remain readable for compatibility).

// Dangerous/sensitive markers (keywords). Note: CJK terms are kept intentionally - they
// are functional regexes matching Chinese sensitive content, not translatable prose.
const SENSITIVE_PATTERNS = [
  /(勒索|ransom)/i, /(木马|trojan)/i, /(病毒|virus|worm)/i, /(后门|backdoor)/i,
  /(键盘记录|keylog)/i, /(窃取|steal|exfil)/i, /(恶意|malware)/i,
  /(api[_-]?key|secret|token|password|passwd|credential)/i,
  /(银行卡|身份证|passport|ssn|社保)/i,
  /(凭证|私钥|private[_-]?key)/i,
];

function isSensitive(obj) {
  const blob = [obj.name, obj.description, obj.summary, obj.path, (obj.tags || []).join(" ")].join(" ");
  return SENSITIVE_PATTERNS.some((re) => re.test(blob));
}

// v2 key file: {v:2, salt, info}. v1 legacy format is a raw hex string (kept for compat).
function keyFile() {
  return path.join(libraryDir(), ".library.key");
}
function masterFile() {
  return path.join(libraryDir(), ".library.master");
}

function getMasterSecret() {
  // Env var first; otherwise .library.master (generated on first use: random 32 bytes, base64).
  if (process.env.DSH_LIBRARY_MASTER_KEY) return Buffer.from(process.env.DSH_LIBRARY_MASTER_KEY, "utf8");
  const mf = masterFile();
  if (fs.existsSync(mf)) return Buffer.from(fs.readFileSync(mf, "utf8").trim(), "base64");
  const m = randomBytes(32);
  fs.writeFileSync(mf, m.toString("base64"), { encoding: "utf8", mode: 0o600 });
  return m;
}

// HKDF `info` namespaces. NEW data is tagged with kohane-index-desuno; the legacy mega-index-map
// strings survive ONLY as read-side fallbacks, so keys and sealed archives written before the
// rename still open. The legacy constants are load-bearing for old data - do not change them.
const KEY_INFO = "kohane-index-desuno:v2";
const KEY_INFO_LEGACY = "mega-index-map:v2";
const SEAL_INFO = "kohane-index-desuno:seal:v1";
const SEAL_INFO_LEGACY = "mega-index-map:seal:v1";

function getOrCreateKey() {
  const kf = keyFile();
  // v1 compat: a raw 64-hex file is used directly as the key.
  if (fs.existsSync(kf)) {
    const raw = fs.readFileSync(kf, "utf8").trim();
    if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, "hex"); // v1 raw hex
    try {
      const j = JSON.parse(raw);
      if (j && j.v === 2) {
        // v2: derive via HKDF-SHA256 from [master secret + salt]. A key file written before the
        // rename carries no `info`, so fall back to the legacy namespace for it.
        const master = getMasterSecret();
        const salt = Buffer.from(j.salt, "hex");
        const derived = hkdfSync("sha256", master, salt, Buffer.from(j.info || KEY_INFO_LEGACY, "utf8"), 32);
        return Buffer.from(derived); // hkdfSync yields an ArrayBuffer; normalise to Buffer
      }
    } catch {}
  }
  // First run: generate a v2 key file.
  const salt = randomBytes(16);
  const info = Buffer.from(KEY_INFO, "utf8");
  const derived = hkdfSync("sha256", getMasterSecret(), salt, info, 32);
  fs.writeFileSync(kf, JSON.stringify({ v: 2, salt: salt.toString("hex"), info: info.toString("utf8") }), { encoding: "utf8", mode: 0o600 });
  return Buffer.from(derived); // hkdfSync yields an ArrayBuffer; normalise to Buffer
}

// Encrypt-isolate a sensitive object as {sens:1, iv, tag, ct}; plaintext never enters the library.
function encryptSensitive(obj) {
  const key = getOrCreateKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plain = JSON.stringify(obj);
  let ct = cipher.update(plain, "utf8", "hex");
  ct += cipher.final("hex");
  const tag = cipher.getAuthTag();
  return { sens: 1, iv: iv.toString("hex"), tag: tag.toString("hex"), ct };
}

function encryptWithKey(obj, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  let ct = cipher.update(JSON.stringify(obj), "utf8", "hex");
  ct += cipher.final("hex");
  return { sens: 1, iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), ct };
}

function decryptWithKey(record, key) {
  if (!record || record.sens !== 1) return record;
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(record.iv, "hex"));
  decipher.setAuthTag(Buffer.from(record.tag, "hex"));
  let plain = decipher.update(record.ct, "hex", "utf8");
  plain += decipher.final("utf8");
  return JSON.parse(plain);
}

/**
 * Rotates the key material. Two shapes: re-derive from the same master secret with a fresh salt and
 * namespace (the usual case), or replace the master secret as well (when the secret file itself is the
 * thing being retired). Both leave a timestamped backup behind, because a rotation that cannot be
 * undone is not a rotation - it is a deletion.
 */
function rotateLibraryKeys(index, opts) {
  const newMaster = Boolean(opts && opts.newMaster);
  const dir = libraryDir();
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupDir = path.join(dir, "backup-rotate-" + stamp);

  const sealed = index.objects.filter((o) => o && o.__content && o.__content.sens === 1);
  const oldKey = getOrCreateKey();
  const opened = [];
  const refused = [];
  for (const obj of sealed) {
    try {
      opened.push({ obj, plain: decryptWithKey(obj.__content, oldKey) });
    } catch (e) {
      refused.push({ id: obj.id, name: obj.name, note: String((e && e.message) || e) });
    }
  }

  // the backup is taken before any key material changes
  fs.mkdirSync(backupDir, { recursive: true });
  const backedUp = [];
  for (const name of [".library.master", ".library.key", "index.json"]) {
    const from = path.join(dir, name);
    if (!fs.existsSync(from)) continue;
    fs.copyFileSync(from, path.join(backupDir, name));
    backedUp.push(name);
  }
  fs.writeFileSync(path.join(backupDir, "WHY.txt"), [
    "Key rotation backup.",
    "Taken at " + new Date().toISOString() + ".",
    "Sealed objects seen: " + sealed.length + "; reopened with the old key: " + opened.length + "; refused: " + refused.length + ".",
    "The files beside this note are the state BEFORE the rotation. Restore them together to undo it.",
  ].join("\n"), "utf8");

  if (newMaster && !process.env.DSH_LIBRARY_MASTER_KEY) {
    fs.writeFileSync(masterFile(), randomBytes(32).toString("base64"), { encoding: "utf8", mode: 0o600 });
  }
  const salt = randomBytes(16);
  fs.writeFileSync(keyFile(), JSON.stringify({ v: 2, salt: salt.toString("hex"), info: KEY_INFO }), { encoding: "utf8", mode: 0o600 });
  const newKey = getOrCreateKey();

  let resealed = 0;
  for (const entry of opened) {
    entry.obj.__content = encryptWithKey(entry.plain, newKey);
    resealed++;
  }

  // proof, not hope: every re-sealed record must open under the new key
  let reopened = 0;
  const stillClosed = [];
  for (const entry of opened) {
    try {
      decryptWithKey(entry.obj.__content, newKey);
      reopened++;
    } catch (e) {
      stillClosed.push({ id: entry.obj.id, name: entry.obj.name, note: String((e && e.message) || e) });
    }
  }

  return { backupDir, backedUp, sealed: sealed.length, resealed, reopened, refusedBefore: refused, refusedAfter: stillClosed, masterSecretReplaced: newMaster };
}
function decryptSensitive(record) {
  if (!record || record.sens !== 1) return record;
  try {
    const key = getOrCreateKey();
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(record.iv, "hex"));
    decipher.setAuthTag(Buffer.from(record.tag, "hex"));
    let plain = decipher.update(record.ct, "hex", "utf8");
    plain += decipher.final("utf8");
    return JSON.parse(plain);
  } catch {
    return { __decryptError: true };
  }
}

// Store an object: sensitive -> encrypt-isolate (plaintext never stored), else store as-is.
// Sensitive objects expose only {type, name, source, sensitive:true, createdAt, __content}.
function storeObject(index, obj) {
  if (isSensitive(obj)) {
    const cipherObj = encryptSensitive(obj);
    const meta = {
      id: obj.id,
      type: obj.type,
      name: obj.name,
      source: obj.source,
      sensitive: true,
      createdAt: obj.createdAt,
      __content: cipherObj,
    };
    index.objects.push(meta);
    return true;
  }
  index.objects.push(obj);
  return false;
}

// Commit one record: store object + refresh timestamp + persist + append log. Returns sensitivity.
function commitRecord(index, obj, disposition, detail) {
  const sens = storeObject(index, obj);
  index.generatedAt = new Date().toISOString();
  saveIndex(index);
  appendLog({ op: "record", type: obj.type, name: obj.name, source: obj.source, disposition, detail: detail + (sens ? " (sensitive, encrypted)" : "") });
  return sens;
}

function ensureLibrary() {
  const dir = libraryDir();
  fs.mkdirSync(dir, { recursive: true });
  fs.mkdirSync(payloadDir(), { recursive: true });
  return dir;
}

function loadIndex() {
  ensureLibrary();
  const file = indexFile();
  if (!fs.existsSync(file)) {
    return { version: 1, generatedAt: null, objects: [] };
  }
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    // Corrupt library file: back it up before returning empty, so the next record
    // doesn't overwrite-and-lose the salvageable remnants.
    try {
      const bak = path.join(libraryDir(), `index.json.corrupt-${Date.now()}`);
      fs.copyFileSync(file, bak);
    } catch {}
    return { version: 1, generatedAt: null, objects: [] };
  }
}

function saveIndex(index) {
  ensureLibrary();
  const file = indexFile();
  // NOTE: synchronous write keeps the read-modify-write cycle atomic on the single
  // JS thread. Do NOT add awaits into the record/index write path, or concurrent tool
  // calls could interleave and lose updates (DSH runs up to maxParallelToolCalls).
  fs.writeFileSync(file, JSON.stringify(index, null, 2), "utf8");
  return file;
}

// ---------- DSH-produced artifacts + declared-vs-actual (forgery) check ----------
// DSH writes the files below while working: session transcripts, storage state,
// content-addressed attachment blobs, config, temp scratch. Knowing their expected shape
// means a planted file that merely *claims* to be DSH output gets caught - the identity
// implied by its name/extension is compared against the magic-byte truth.
const DSH_ARTIFACTS = [
  { re: /^session\..+\.(zstd|jsonl)$/i, role: "dsh-session", note: "DSH session transcript (JSONL, zstd-compressed)", expect: "archive" },
  { re: /^settings\.ya?ml$/i, role: "dsh-settings", note: "DSH settings", expect: "document" },
  { re: /^cordis\.patch\.ya?ml$/i, role: "dsh-plugin-patch", note: "DSH plugin patch manifest", expect: "document" },
  { re: /^disk-guard\.ya?ml$/i, role: "dsh-disk-guard", note: "DSH disk guard config", expect: "document" },
  { re: /^\.credentials\.ya?ml$/i, role: "dsh-credentials", note: "DSH credentials (sensitive)", expect: "document", sensitive: true },
  { re: /^\.anonymous-user-id$/i, role: "dsh-anonymous-id", note: "DSH anonymous user id", expect: "document" },
  { re: /^\.dshw-(size|usage)\.json$/i, role: "dsh-usage", note: "DSH web usage/size counters", expect: "document" },
  { re: /[\\/]attachments[\\/]v1[\\/]objects[\\/]/i, role: "dsh-attachment", note: "DSH attachment blob (content-addressed sha256 name; type comes from content only)" },
  { re: /[\\/]storages[\\/][^\\/]+\.json$/i, role: "dsh-storage", note: "DSH storage state", expect: "document" },
  { re: /[\\/]library[\\/]index\.json$/i, role: "library-index", note: "Library index", expect: "document" },
  { re: /[\\/]library[\\/][^\\/]+\.ndjson$/i, role: "library-log", note: "Library operation log (NDJSON)", expect: "document" },
];

// Scratch/temp names promise nothing about content, so they are recognised but never
// used as an expectation (a temp file legitimately holds anything).
const TEMP_NAME_RE = /\.(tmp|temp|part|partial|crdownload|download|bak|orig|swp|swo|pid)$/i;
const NO_EXPECT = new Set(["tmp", "temp", "part", "partial", "crdownload", "download", "bak", "orig", "swp", "swo", "pid"]);

// Family the *name* claims, per extension: from the text whitelist and the ZIP package
// table, plus the binary families. Used to decide "does the content contradict the name".
const EXT_FAMILY = (() => {
  const m = {};
  for (const e of TEXT_EXTENSIONS) if (!NO_EXPECT.has(e)) m[e] = "document";
  for (const [e, meta] of Object.entries(ZIP_PACKAGE_FORMATS)) m[e] = meta[0];
  Object.assign(m, {
    png: "image", jpg: "image", jpeg: "image", gif: "image", bmp: "image", webp: "image", tga: "image", tif: "image", tiff: "image", psd: "image", dds: "image", ico: "image", cur: "image", exr: "image", heic: "image", avif: "image", xcf: "image", djvu: "image", wmf: "image", emf: "image",
    mp3: "audio", wav: "audio", flac: "audio", ogg: "audio", m4a: "audio", aac: "audio", ac3: "audio", dts: "audio", dsf: "audio", mid: "audio", midi: "audio", sf2: "audio", ape: "audio", rex2: "audio",
    mp4: "video", mkv: "video", webm: "video", avi: "video", mov: "video", wmv: "video", flv: "video", mxf: "video", asf: "video", rmvb: "video",
    zip: "archive", "7z": "archive", rar: "archive", gz: "archive", tar: "archive", xz: "archive", bz2: "archive", zst: "archive", zstd: "archive", cab: "archive", iso: "archive", rpm: "archive", wim: "archive",
    exe: "executable", dll: "executable", sys: "executable", so: "executable", dylib: "executable", pyd: "executable", ocx: "executable", cpl: "executable", scr: "executable", com: "executable", tlb: "executable", olb: "executable", pdb: "executable", winmd: "executable",
    db: "database", sqlite: "database", sqlite3: "database", accdb: "database", accde: "database", mdb: "database", "db-wal": "database", "db-shm": "database", wal: "database", shm: "database",
    ttf: "font", otf: "font", woff: "font", woff2: "font", ttc: "font",
    doc: "document", xls: "document", ppt: "document", pub: "document", msi: "document", msg: "document", one: "document", onetoc2: "document", chm: "document", pdf: "document", rtf: "document", ole2: "document",
    pmx: "model", pmd: "model", glb: "model", onnx: "model", gguf: "model", ggml: "model", hdf5: "model",
  });
  return m;
})();

function dshArtifactOf(filePath) {
  const base = path.basename(filePath);
  for (const a of DSH_ARTIFACTS) if (a.re.test(base) || a.re.test(filePath)) return a;
  // Locally taught name rules (the user's own artifact roles) come after the built-ins.
  for (const a of loadLocalFormats().nameRules) if (a.re.test(base) || a.re.test(filePath)) return { ...a, local: true };
  return null;
}

// Declared family for an extension: local pack first for locally known formats, then the
// built-in table (built-ins still win inside sniffFileType itself).
function declaredFamily(ext) {
  if (!ext) return null;
  const local = loadLocalFormats();
  for (const lf of local.formats) if (lf.ext.includes(ext)) return lf.type;
  if (local.textExtensions.includes(ext)) return "document";
  return EXT_FAMILY[ext] || null;
}

// Assess one file: what it claims to be (name/extension, DSH artifact role) versus what
// its bytes actually are. Any contradiction becomes a flag -> spoofed: true.
// Byte-level text/binary verdict, independent of the extension. Needed because the
// strongest forgery signal is often "no signature matched at all": a .png whose bytes are
// plain ASCII, or a .json holding raw binary, must still be catchable.
function contentKind(filePath) {
  const h = readHeader(filePath, 128);
  if (!h || h.length === 0) return "empty";
  if (h[0] === 0xEF && h[1] === 0xBB && h[2] === 0xBF) return "text";
  if ((h[0] === 0xFF && h[1] === 0xFE) || (h[0] === 0xFE && h[1] === 0xFF)) return "text";
  const printable = h.every((b, i) => i === 0 ? true : (b === 0x09 || b === 0x0A || b === 0x0D || (b >= 0x20 && b <= 0x7E) || b >= 0x80));
  return printable ? "text" : "binary";
}

// Families whose members are never plain text, and formats that are (in practice) always
// text - used to flag contradictions that carry no magic signature at all. `.log` is
// deliberately NOT in the text set: Office diagnostic logs are binary on this machine.
const BINARY_FAMILIES = new Set(["image", "audio", "video", "archive", "executable", "database", "font", "model"]);
const ALWAYS_TEXT_EXTS = new Set(["json", "jsonl", "ndjson", "yaml", "yml", "txt", "md", "csv", "ini", "env", "sln", "xml", "html", "htm"]);

function assessFile(filePath) {
  const base = path.basename(filePath);
  const ext = path.extname(base).toLowerCase().replace(".", "");
  const sniff = sniffFileType(filePath);
  const declared = declaredFamily(ext);
  const artifact = dshArtifactOf(filePath);
  const kind = contentKind(filePath);
  const flags = [];
  if (sniff && declared && sniff.type !== declared) flags.push(`name claims ${declared} (.${ext}) but content is ${sniff.type}/${sniff.format}`);
  if (sniff && artifact && artifact.expect && sniff.type !== artifact.expect) flags.push(`DSH role "${artifact.role}" expects ${artifact.expect} but content is ${sniff.type}/${sniff.format}`);
  if (sniff && artifact && !artifact.expect && sniff.type === "executable") flags.push(`executable content inside DSH artifact role "${artifact.role}"`);
  // No signature matched: fall back to the raw text/binary verdict.
  if (!sniff && kind === "text" && declared && BINARY_FAMILIES.has(declared)) flags.push(`name claims ${declared} (.${ext}) but content is plain text`);
  if (!sniff && kind === "binary" && ALWAYS_TEXT_EXTS.has(ext)) flags.push(`name claims text (.${ext}) but content is binary and matches no known signature`);
  return {
    path: filePath,
    declared,
    artifact: artifact ? artifact.role : null,
    artifactNote: artifact ? artifact.note : null,
    sensitive: !!(artifact && artifact.sensitive),
    temp: TEMP_NAME_RE.test(base),
    kind,
    detected: !!sniff,
    type: sniff ? sniff.type : null,
    format: sniff ? sniff.format : null,
    note: sniff ? sniff.note : "no known signature matched",
    spoofed: flags.length > 0,
    flags,
  };
}

// ---------- Parallel work across cores ----------
// The complaint this answers: one core sweating while the rest watch. Everything that is a pure map
// over independent items - hashing files, measuring waveforms, rendering stems - goes through this
// pool instead of a for loop. A worker is this same module re-entered with a marker in workerData, so
// the package stays a single file and there is no second entry point to keep in sync.
const KB_WORKER_TASKS = new Set(["peaks", "hash"]);

function availableCores() {
  if (!WORKERS_AVAILABLE) return 1;   // no worker threads here: the inline path
  const override = Number(process.env.KOHANE_THREADS);
  if (Number.isInteger(override) && override >= 0) return Math.max(1, Math.min(override, 64));
  try {
    return Math.max(1, Math.min(os.cpus().length || 1, 32));
  } catch {
    return 1;
  }
}

/** The pool's worker half: a small, explicit task table so a worker never runs arbitrary code. */
function runWorkerTask(name, item) {
  if (name === "peaks") return { path: item.path, ...readAudioPeaks(item.path, item.buckets || 512) };
  if (name === "hash") {
    // Deliberately the same function the inline path uses: two implementations of "what is this
    // file's identity" would eventually disagree, and every file would read as changed.
    return { path: item.path, digest: sha256File(item.path, item.maxBytes || 16 * 1024 * 1024) };
  }
  throw new Error(`unknown worker task: ${name}`);
}

/**
 * Map `items` through `task` on several cores. The first version spawned a worker per call and was
 * measured SLOWER than a plain loop (0.36x on 12 files of 3.7 MB: every worker re-loaded this whole
 * module for a few milliseconds of work). So the pool is resident: workers are started once, kept
 * alive, and handed one chunk per call - start-up is paid a single time per process. Below
 * `minItems` the work stays inline, because a pool that loses to a loop is not worth having.
 */
let kbPool = null;          // { task, workers: [{ worker, busy }] }

async function kbPoolClose() {
  if (!kbPool) return;
  const closing = kbPool.workers.map((entry) => entry.worker.terminate().catch(() => {}));
  kbPool = null;
  await Promise.all(closing);
}

async function kbPoolEnsure(task, width) {
  if (kbPool && kbPool.task !== task) await kbPoolClose();
  if (!kbPool) kbPool = { task, workers: [] };
  if (!WORKERS_AVAILABLE) return null;                 // the caller falls back to the inline path
  const { Worker } = await import("node:worker_threads");
  const self = fileURLToPath(import.meta.url);
  while (kbPool.workers.length < width) {
    const worker = new Worker(self, { workerData: { kbWorker: task } });
    worker.unref();                                  // a resident pool must never hold the process open
    kbPool.workers.push({ worker, busy: false });
  }
  return kbPool;
}

async function poolMap(items, task, { threads = availableCores(), label = task, minItems = 8 } = {}) {
  const started = Date.now();
  if (!KB_WORKER_TASKS.has(task)) throw new Error(`unknown task ${task}`);
  const width = Math.max(1, Math.min(threads, items.length));
  if (width <= 1 || items.length < minItems) {
    const results = items.map((item) => runWorkerTask(task, item));
    return { results, threads: 1, mode: "inline", ms: Date.now() - started, label, note: width <= 1 ? "one core asked for" : "fewer items than the pool threshold" };
  }

  const pool = await kbPoolEnsure(task, width);
  const available = pool.workers.filter((entry) => !entry.busy);
  const lanes = Math.max(1, available.length);
  const chunks = Array.from({ length: lanes }, () => []);
  items.forEach((item, i) => chunks[i % lanes].push(item));

  const parts = await Promise.all(chunks.map((chunk, lane) => new Promise((resolve, reject) => {
    const entry = available[lane];
    entry.busy = true;
    const id = ++kbPoolJobId;
    const onMessage = (message) => {
      if (message && message.id !== id) return;
      entry.worker.off("message", onMessage);
      entry.worker.off("error", onError);
      entry.busy = false;
      resolve(Array.isArray(message.results) ? message.results : []);
    };
    const onError = (error) => {
      entry.worker.off("message", onMessage);
      entry.busy = false;
      reject(error);
    };
    entry.worker.on("message", onMessage);
    entry.worker.on("error", onError);
    entry.worker.postMessage({ id, items: chunk });
  })));

  // chunks are interleaved, so put the answers back in the caller's order
  const merged = [];
  const cursors = new Array(lanes).fill(0);
  for (let i = 0; i < items.length; i++) {
    const lane = i % lanes;
    merged.push(parts[lane][cursors[lane]++]);
  }
  return { results: merged, threads: lanes, mode: "workers", ms: Date.now() - started, label, poolSize: pool.workers.length };
}

let kbPoolJobId = 0;

// ---------- Audio waveforms (WAV / AIFF), for both the mixer and the waterfall ----------
// A peak envelope is what a waveform display actually needs: per bucket, the minimum and maximum
// sample. Compressed formats are not decoded here - that is a job for a media provider - and saying
// so is better than pretending.
const AUDIO_MAX_BUCKETS = 20000;

function decodePcm16(view, count) {
  const out = new Float32Array(count);
  for (let i = 0; i < count; i++) out[i] = view.getInt16(i * 2, true) / 32768;
  return out;
}

function readWavPeaks(buf, buckets) {
  const readU32 = (o) => buf.readUInt32LE(o);
  const readU16 = (o) => buf.readUInt16LE(o);
  let at = 12;
  let fmt = null;
  let dataAt = -1;
  let dataLen = 0;
  while (at + 8 <= buf.length) {
    const id = buf.toString("latin1", at, at + 4);
    const size = readU32(at + 4);
    const body = at + 8;
    if (id === "fmt ") {
      fmt = {
        format: readU16(body), channels: readU16(body + 2), sampleRate: readU32(body + 4),
        bits: readU16(body + 14),
      };
    } else if (id === "data") {
      dataAt = body;
      dataLen = Math.min(size, buf.length - body);
    }
    at = body + size + (size % 2);
    if (dataAt >= 0 && fmt) break;
  }
  if (!fmt || dataAt < 0) return { ok: false, note: "WAV without a fmt/data pair" };
  const channelCount = Math.max(1, fmt.channels);
  const bytesPer = Math.max(1, fmt.bits / 8);
  const frames = Math.floor(dataLen / (bytesPer * channelCount));
  const pcm = buf.subarray(dataAt, dataAt + frames * bytesPer * channelCount);
  const sample = (frame, channel) => {
    const o = (frame * channelCount + channel) * bytesPer;
    if (fmt.format === 3 && fmt.bits === 32) return pcm.readFloatLE(o);
    if (fmt.bits === 16) return pcm.readInt16LE(o) / 32768;
    if (fmt.bits === 24) return ((pcm[o] | (pcm[o + 1] << 8) | (pcm[o + 2] << 24)) >> 8) / 8388608;
    if (fmt.bits === 32) return pcm.readInt32LE(o) / 2147483648;
    if (fmt.bits === 8) return (pcm[o] - 128) / 128;
    return 0;
  };
  return { ok: true, channelCount, sampleRate: fmt.sampleRate, bits: fmt.bits, frames, peaks: envelope(sample, frames, channelCount, buckets) };
}

function readAiffPeaks(buf, buckets) {
  let at = 12;
  let comm = null;
  let ssnd = null;
  while (at + 8 <= buf.length) {
    const id = buf.toString("latin1", at, at + 4);
    const size = buf.readUInt32BE(at + 4);
    const body = at + 8;
    if (id === "COMM") {
      const extended = buf.subarray(body + 8, body + 18);          // 80-bit IEEE extended sample rate
      let rate = 0;
      const exponent = buf.readUInt16BE(body + 8) & 0x7fff;
      if (exponent) {
        let mantissa = 0;
        for (let i = 0; i < 8; i++) mantissa = mantissa * 256 + extended[2 + i];
        rate = Math.round(mantissa * Math.pow(2, exponent - 16383 - 63));
      }
      comm = { channels: buf.readUInt16BE(body), frames: buf.readUInt32BE(body + 2), bits: buf.readUInt16BE(body + 6), sampleRate: rate };
    } else if (id === "SSND") {
      ssnd = body + 8 + buf.readUInt32BE(body);                     // skip offset/blockSize
    }
    at = body + size + (size % 2);
    if (comm && ssnd !== null) break;
  }
  if (!comm || ssnd === null) return { ok: false, note: "AIFF without a COMM/SSND pair" };
  const channelCount = Math.max(1, comm.channels);
  const bytesPer = Math.max(1, comm.bits / 8);
  const frames = Math.min(comm.frames, Math.floor((buf.length - ssnd) / (bytesPer * channelCount)));
  const pcm = buf.subarray(ssnd, ssnd + frames * bytesPer * channelCount);
  const sample = (frame, channel) => {
    const o = (frame * channelCount + channel) * bytesPer;
    if (comm.bits === 16) return pcm.readInt16BE(o) / 32768;
    if (comm.bits === 24) return ((pcm[o] << 16 | pcm[o + 1] << 8 | pcm[o + 2]) << 8 >> 8) / 8388608;
    if (comm.bits === 32) return pcm.readInt32BE(o) / 2147483648;
    if (comm.bits === 8) return (pcm[o] - 128) / 128;
    return 0;
  };
  return { ok: true, channelCount, sampleRate: comm.sampleRate, bits: comm.bits, frames, peaks: envelope(sample, frames, channelCount, buckets) };
}

/** Min/max per bucket over the mixed-down channels - the shape a waveform viewer draws. */
function envelope(sample, frames, channelCount, buckets) {
  const count = Math.max(1, Math.min(buckets, AUDIO_MAX_BUCKETS));
  const out = new Array(count);
  const per = frames / count;
  for (let b = 0; b < count; b++) {
    const from = Math.floor(b * per);
    const to = Math.min(frames, Math.max(from + 1, Math.floor((b + 1) * per)));
    let lo = 0;
    let hi = 0;
    const step = Math.max(1, Math.floor((to - from) / 512));
    for (let f = from; f < to; f += step) {
      let v = 0;
      for (let c = 0; c < channelCount; c++) v += sample(f, c);
      v /= channelCount;
      if (v < lo) lo = v;
      if (v > hi) hi = v;
    }
    out[b] = [Math.round(lo * 1000) / 1000, Math.round(hi * 1000) / 1000];
  }
  return out;
}

function readAudioPeaks(file, buckets = 512) {
  let buf;
  try {
    buf = fs.readFileSync(file);
  } catch (e) {
    return { ok: false, note: `cannot read: ${String((e && e.message) || e)}` };
  }
  if (buf.length < 16) return { ok: false, note: "too short to be audio" };
  const magic = buf.toString("latin1", 0, 4);
  if (magic === "RIFF" && buf.toString("latin1", 8, 12) === "WAVE") return readWavPeaks(buf, buckets);
  if (magic === "FORM" && /AIFF|AIFC/.test(buf.toString("latin1", 8, 12))) return readAiffPeaks(buf, buckets);
  return { ok: false, note: `not a PCM container this reader decodes (${magic.trim() || "unknown"})` };
}

// ---------- Standard MIDI files, read as notes ----------
// The waterfall needs notes, and nothing in the engine could read them back. Two details decide
// whether this reader is honest: a note-off is note-on with velocity 0 (or 0x8n), and a same-pitch
// retrigger while the previous note is still sounding is normal in a sustained part - so every pitch
// keeps a stack of open notes. Overwriting instead of stacking silently loses those notes.
// Sysex and the fixed-width channel messages are skipped by their real sizes, because a reader that
// desyncs does not fail; it reports invented notes.
const MIDI_NOTE_NAMES = ["C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B"];

function midiNoteName(key) {
  return `${MIDI_NOTE_NAMES[((key % 12) + 12) % 12]}${Math.floor(key / 12) - 1}`;
}

function midiVlq(buf, at) {
  let value = 0;
  for (;;) {
    if (at >= buf.length) throw new Error("truncated variable-length quantity");
    const b = buf[at++];
    value = (value << 7) | (b & 0x7f);
    if (!(b & 0x80)) break;
  }
  return { value, at };
}

function readMidiScore(file) {
  const buf = fs.readFileSync(file);
  if (buf.length < 14 || buf.toString("latin1", 0, 4) !== "MThd") throw new Error("not a Standard MIDI File (no MThd header)");
  const headerLength = buf.readUInt32BE(4);
  const format = buf.readUInt16BE(8);
  const declaredTracks = buf.readUInt16BE(10);
  const division = buf.readUInt16BE(12);
  const ppq = division & 0x8000 ? null : division;      // SMPTE division is reported, not guessed at

  const tracks = [];
  let tempo = null;
  let title = "";
  let at = 8 + headerLength;

  while (at + 8 <= buf.length && tracks.length < declaredTracks) {
    if (buf.toString("latin1", at, at + 4) !== "MTrk") break;
    const length = buf.readUInt32BE(at + 4);
    const end = Math.min(at + 8 + length, buf.length);
    let p = at + 8;
    let tick = 0;
    let status = 0;
    let name = "";
    const notes = [];
    const open = new Map();                              // "channel:key" -> stack of { tick, velocity }

    while (p < end) {
      const delta = midiVlq(buf, p);
      p = delta.at;
      tick += delta.value;
      let b = buf[p];
      if (b & 0x80) { status = b; p++; } else { b = status; }

      if (b === 0xff) {
        const meta = buf[p++];
        const size = midiVlq(buf, p);
        p = size.at;
        const data = buf.subarray(p, Math.min(p + size.value, end));
        p += size.value;
        if (meta === 0x51 && data.length >= 3) tempo = Math.round(60000000 / ((data[0] << 16) | (data[1] << 8) | data[2]));
        else if (meta === 0x03 && !name) name = data.toString("latin1");
        else if (meta === 0x2f) break;
        continue;
      }
      if (b === 0xf0 || b === 0xf7) {
        const size = midiVlq(buf, p);
        p = size.at + size.value;
        continue;
      }

      const type = b & 0xf0;
      const channel = b & 0x0f;
      if (type === 0x90 || type === 0x80) {
        const key = buf[p++];
        const velocity = buf[p++];
        const slot = `${channel}:${key}`;
        if (type === 0x90 && velocity > 0) {
          const stack = open.get(slot) || [];
          stack.push({ tick, velocity });
          open.set(slot, stack);
        } else {
          const stack = open.get(slot);
          if (stack && stack.length) {
            const started = stack.pop();
            notes.push({ tick: started.tick, note: key, ticks: Math.max(1, tick - started.tick), velocity: started.velocity, channel, pitch: midiNoteName(key) });
            if (!stack.length) open.delete(slot);
          }
        }
        continue;
      }
      p += type === 0xc0 || type === 0xd0 ? 1 : 2;
    }

    for (const [slot, stack] of open) {                  // a note left hanging still happened
      const key = Number(slot.split(":")[1]);
      const channel = Number(slot.split(":")[0]);
      for (const started of stack) {
        notes.push({ tick: started.tick, note: key, ticks: Math.max(1, tick - started.tick), velocity: started.velocity, channel, pitch: midiNoteName(key) });
      }
    }
    notes.sort((a, z) => a.tick - z.tick || a.note - z.note);

    const keys = notes.map((n) => n.note);
    tracks.push({
      name, notes, noteCount: notes.length,
      lowest: keys.length ? midiNoteName(Math.min(...keys)) : null,
      highest: keys.length ? midiNoteName(Math.max(...keys)) : null,
    });
    if (!title && name) title = name;
    at = end;
  }

  const notes = tracks.reduce((a, t) => a + t.noteCount, 0);
  const lastTick = tracks.reduce((a, t) => t.notes.reduce((m, n) => Math.max(m, n.tick + n.ticks), a), 0);
  return {
    path: file, format, ppq, tempo, title, declaredTracks, tracks: tracks.filter((t) => t.noteCount),
    emptyTracks: tracks.filter((t) => !t.noteCount).map((t) => t.name),
    notes, lastTick, bars: ppq ? Math.round((lastTick / (ppq * 4)) * 100) / 100 : null,
  };
}


// ---------- Decoding to samples, and letting the system make the sound ----------
// Recognition answers what a file is; this answers what it contains. Both readers are kept apart
// from the envelope ones on purpose: an envelope can be computed from any frame order, while
// playback needs the frames themselves, in order, at the right rate.
//
// On formats: the staged file handed to the system player is a plain WAV, which is a third-party
// container. That does not cross the storage rule - nothing kohane keeps is stored this way; the
// file exists only to be played by the operating system and can be deleted afterwards.
function kohaneDecodeRiff(buf) {
  if (buf.length < 12 || buf.toString("latin1", 0, 4) !== "RIFF" || buf.toString("latin1", 8, 12) !== "WAVE") {
    throw new Error("not a RIFF/WAVE file");
  }
  let at = 12;
  let fmt = null;
  let data = null;
  while (at + 8 <= buf.length) {
    const id = buf.toString("latin1", at, at + 4);
    const size = buf.readUInt32LE(at + 4);
    const body = at + 8;
    if (id === "fmt ") {
      fmt = {
        tag: buf.readUInt16LE(body),
        channels: buf.readUInt16LE(body + 2),
        sampleRate: buf.readUInt32LE(body + 4),
        bits: buf.readUInt16LE(body + 14),
      };
    } else if (id === "data") {
      data = buf.subarray(body, Math.min(body + size, buf.length));
      break;
    }
    at = body + size + (size % 2);
  }
  if (!fmt || !data) throw new Error("WAVE without a fmt or data chunk");
  const { tag, channels, sampleRate, bits } = fmt;
  const isFloat = tag === 3;
  const bytes = bits / 8;
  const frames = Math.floor(data.length / (bytes * channels));
  const samples = new Float32Array(frames * channels);
  for (let i = 0; i < samples.length; i++) {
    const o = i * bytes;
    let v = 0;
    if (isFloat && bits === 32) v = data.readFloatLE(o);
    else if (bits === 8) v = (data[o] - 128) / 128;
    else if (bits === 16) v = data.readInt16LE(o) / 32768;
    else if (bits === 24) v = ((data[o] | (data[o + 1] << 8) | (data[o + 2] << 16) << 8) >> 8) / 8388608;
    else if (bits === 32) v = data.readInt32LE(o) / 2147483648;
    samples[i] = v;
  }
  return { format: "wav", sampleRate, channels, bits, isFloat, frames, samples };
}

function kohaneDecodeAiff(buf) {
  if (buf.length < 12 || buf.toString("latin1", 0, 4) !== "FORM") throw new Error("not an IFF/FORM file");
  const kind = buf.toString("latin1", 8, 12);
  if (kind !== "AIFF" && kind !== "AIFC") throw new Error("not an AIFF/AIFC file");
  let at = 12;
  let channels = 0;
  let frames = 0;
  let bits = 0;
  let sampleRate = 0;
  let ssnd = null;
  let offset = 0;
  while (at + 8 <= buf.length) {
    const id = buf.toString("latin1", at, at + 4);
    const size = buf.readUInt32BE(at + 4);
    const body = at + 8;
    if (id === "COMM") {
      channels = buf.readUInt16BE(body);
      frames = buf.readUInt32BE(body + 2);
      bits = buf.readUInt16BE(body + 6);
      // an 80-bit IEEE extended float: sign+exponent in the first two bytes, mantissa after
      const exp = buf.readUInt16BE(body + 8);
      const mant = buf.readUInt32BE(body + 10) * 4294967296 + buf.readUInt32BE(body + 14);
      sampleRate = Math.round(mant * Math.pow(2, (exp & 0x7fff) - 16383 - 63));
    } else if (id === "SSND") {
      offset = buf.readUInt32BE(body);
      ssnd = buf.subarray(body + 8 + offset);
      break;
    }
    at = body + size + (size % 2);
  }
  if (!ssnd || !channels) throw new Error("AIFF without COMM or SSND");
  const bytes = Math.max(1, bits / 8);
  const total = Math.min(frames * channels, Math.floor(ssnd.length / bytes));
  const samples = new Float32Array(total);
  for (let i = 0; i < total; i++) {
    const o = i * bytes;
    if (bits === 16) samples[i] = ssnd.readInt16BE(o) / 32768;
    else if (bits === 8) samples[i] = ssnd.readInt8(o) / 128;
    else if (bits === 24) samples[i] = (((ssnd[o] << 16) | (ssnd[o + 1] << 8) | ssnd[o + 2]) << 8 >> 8) / 8388608;
    else if (bits === 32) samples[i] = ssnd.readInt32BE(o) / 2147483648;
    else samples[i] = 0;
  }
  return { format: kind === "AIFC" ? "aifc" : "aiff", sampleRate, channels, bits, isFloat: false, frames: total / channels, samples };
}

function kohaneDecodeAudio(file) {
  const buf = fs.readFileSync(file);
  const head = buf.toString("latin1", 0, 4);
  if (head === "RIFF") return kohaneDecodeRiff(buf);
  if (head === "FORM") return kohaneDecodeAiff(buf);
  // The long tail is borrowed, never pretended: if a decoder is recorded in the dependency ledger (or
  // pointed at by KOHANE_FFMPEG) it is used and the receipt says so; if none is available the refusal
  // names what is missing, because "no decoder is installed" and "this file is broken" are different
  // statements and only one of them is true.
  if (resolveExternalDecoder()) return decodeExternally(file);
  throw new Error("no decoder for this container: the engine decodes PCM WAV and AIFF itself, and no external decoder is installed or recorded (set KOHANE_FFMPEG, or record one in deps/manifest.json)");
}

// A canonical 16-bit stereo WAV, stage only: this is what the operating system's player accepts.
function kohaneStageWav(decoded) {
  const channels = Math.min(2, Math.max(1, decoded.channels));
  const frames = Math.floor(decoded.samples.length / decoded.channels);
  const pcm = Buffer.alloc(frames * channels * 2);
  for (let f = 0; f < frames; f++) {
    for (let c = 0; c < channels; c++) {
      const value = decoded.samples[f * decoded.channels + c] || 0;
      const clamped = Math.max(-1, Math.min(1, value));
      pcm.writeInt16LE(Math.round(clamped * 32767), (f * channels + c) * 2);
    }
  }
  const header = Buffer.alloc(44);
  header.write("RIFF", 0, "latin1");
  header.writeUInt32LE(36 + pcm.length, 4);
  header.write("WAVEfmt ", 8, "latin1");
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(channels, 22);
  header.writeUInt32LE(decoded.sampleRate, 24);
  header.writeUInt32LE(decoded.sampleRate * channels * 2, 28);
  header.writeUInt16LE(channels * 2, 32);
  header.writeUInt16LE(16, 34);
  header.write("data", 36, "latin1");
  header.writeUInt32LE(pcm.length, 40);
  return Buffer.concat([header, pcm]);
}
// ---------- Working-tree status (Git), read-only ----------
// Approaches what an editor's source-control view reports, and it does it from ONE git call per
// repository: porcelain v2 with NUL separation carries the index AND the worktree state of every
// path in a single record, its branch header carries the name, the upstream and the ahead/behind
// counts, and numstat adds the +N/-M line counts an editor paints beside a file. Nothing is written
// and nothing leaves the machine: git runs with --no-optional-locks, a short timeout, a hidden
// window, no pager and no colour. When git is absent, or the path is not inside a repository, the
// answer is "no repository" rather than an error, and every label here stays English so the engine
// carries no localised text.
const GIT_TIMEOUT_MS = 4000;
const VCS_TTL_MS = 2000;
const VCS_MAX_IGNORED = 2000;
const VCS_MAX_DECORATE = 5000;

let gitVersionProbe;                    // undefined until probed, then a version string or null
const repoRootCache = new Map();        // directory -> repository root or null
const repoStatusCache = new Map();      // repository root -> { at, status }

// The states an editor decorates with, with the colours its default themes use for each. The letter
// and the canonical name are for machines; label is what a person reads.
const VCS_STATES = {
  M: { letter: "M", en: "modified", label: "已修改", light: "#895503", dark: "#E2C08D" },
  A: { letter: "A", en: "added", label: "新增（已暂存）", light: "#587C0C", dark: "#81B88B" },
  D: { letter: "D", en: "deleted", label: "已删除", light: "#AD0707", dark: "#C74E39" },
  R: { letter: "R", en: "renamed", label: "已改名", light: "#007100", dark: "#73C991" },
  C: { letter: "C", en: "copied", label: "已复制", light: "#007100", dark: "#73C991" },
  T: { letter: "T", en: "type changed", label: "类型变更", light: "#895503", dark: "#E2C08D" },
  U: { letter: "U", en: "untracked", label: "未跟踪", light: "#007100", dark: "#73C991" },
  I: { letter: "I", en: "ignored", label: "已忽略", light: "#8E8E90", dark: "#8C8C8C" },
  "!": { letter: "!", en: "conflicted", label: "冲突未解", light: "#AD0707", dark: "#E4676B" },
  S: { letter: "S", en: "submodule", label: "子模块有变", light: "#1258A7", dark: "#8DB9E2" },
  clean: { letter: null, en: "committed", label: "已提交", light: null, dark: null },
  none: { letter: null, en: "not in a repository", label: "不在仓库中", light: null, dark: null },
};

// Which state wins when several files are folded into one answer (a folder's badge, a summary).
const VCS_PRECEDENCE = ["!", "D", "M", "T", "R", "C", "A", "S", "U", "I", "clean"];
const VCS_CONFLICT_CODES = new Set(["DD", "AU", "UD", "UA", "DU", "AA", "UU"]);

function gitVersion() {
  if (gitVersionProbe !== undefined) return gitVersionProbe;
  // KOHANE_NO_GIT=1 makes the absent-git path reachable on purpose: it is what the tests use, and it
  // is also what someone who would rather kohane never started a git process at all can set.
  if (process.env.KOHANE_NO_GIT === "1") {
    gitVersionProbe = null;
    return gitVersionProbe;
  }
  try {
    const r = spawnSync("git", ["--version"], { encoding: "utf8", windowsHide: true, timeout: GIT_TIMEOUT_MS });
    const text = String(r.stdout || "").trim();
    gitVersionProbe = (r.status === 0 && /^git version /i.test(text)) ? text.replace(/^git version /i, "") : null;
  } catch {
    gitVersionProbe = null;
  }
  return gitVersionProbe;
}

function runGit(root, args) {
  try {
    const r = spawnSync("git", ["-C", root, ...args], {
      encoding: "utf8", windowsHide: true, timeout: GIT_TIMEOUT_MS, maxBuffer: 96 * 1024 * 1024,
    });
    return { ok: r.status === 0, status: r.status, out: String(r.stdout || ""), err: String(r.stderr || "").trim() };
  } catch (e) {
    return { ok: false, status: -1, out: "", err: String((e && e.message) || e) };
  }
}

function findRepoRoot(startDir) {
  let dir = path.resolve(startDir);
  const walked = [];
  for (;;) {
    if (repoRootCache.has(dir)) {
      const hit = repoRootCache.get(dir);
      for (const d of walked) repoRootCache.set(d, hit);
      return hit;
    }
    walked.push(dir);
    try {
      if (fs.existsSync(path.join(dir, ".git"))) {
        for (const d of walked) repoRootCache.set(d, dir);
        return dir;
      }
    } catch { /* an unreadable directory simply ends the walk */ }
    const parent = path.dirname(dir);
    if (parent === dir) {
      for (const d of walked) repoRootCache.set(d, null);
      return null;
    }
    dir = parent;
  }
}

function vcsStateOf(x, y, sub) {
  if (sub === "S") return "S";                       // submodule holding new commits
  if (VCS_CONFLICT_CODES.has(`${x}${y}`)) return "!";
  const pick = (c) => (c && c !== "." && c !== " " ? c : null);
  const ch = pick(y) || pick(x);                     // the worktree letter is what an editor badges first
  if (!ch) return "clean";
  if (ch === "?") return "U";
  if (ch === "!") return "I";
  return VCS_STATES[ch] ? ch : "M";
}

function colorsOf(state) {
  const meta = VCS_STATES[state];
  return meta && meta.letter ? { light: meta.light, dark: meta.dark } : null;
}

function numOrNull(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;              // "-" means binary and stays null
}

function parsePorcelainV2(root) {
  const res = runGit(root, ["--no-optional-locks", "status", "--porcelain=v2", "-z", "--untracked-files=all", "--find-renames", "--branch"]);
  const empty = {
    root, ok: false, error: res.err || `git exited with ${res.status}`, branch: null,
    entries: new Map(), counts: {}, ignoredTruncated: false,
  };
  if (!res.ok) return empty;

  const fields = res.out.split("\0").filter((s) => s.length > 0);
  const entries = new Map();
  const branch = { name: null, oid: null, upstream: null, ahead: 0, behind: 0, detached: false };
  let ignoredSeen = 0;
  let ignoredTruncated = false;

  for (let i = 0; i < fields.length; i++) {
    const rec = fields[i];
    const type = rec[0];

    if (type === "#") {
      const parts = rec.slice(2).split(" ");
      const key = parts.shift();
      if (key === "branch.head") {
        branch.name = parts.join(" ");
        branch.detached = branch.name === "(detached)";
      }
      else if (key === "branch.oid") branch.oid = parts.join(" ");
      else if (key === "branch.upstream") branch.upstream = parts.join(" ");
      else if (key === "branch.ab") {
        branch.ahead = Number(String(parts[0] || "+0").replace("+", "")) || 0;
        branch.behind = Number(String(parts[1] || "-0").replace("-", "")) || 0;
      }
      continue;
    }

    if (type === "1" || type === "2") {
      const f = rec.slice(2).split(" ");
      const xy = f[0] || "..";
      const sub = f[1] || "N...";
      let rel, orig = null;
      if (type === "1") {
        rel = f.slice(7).join(" ");
      } else {
        rel = f.slice(8).join(" ");
        orig = fields[++i] || null;                  // a rename record carries the old path next
      }
      const x = xy[0], y = xy[1];
      entries.set(rel, {
        path: rel, origPath: orig, state: vcsStateOf(x, y, sub[0]),
        index: x === "." ? null : x, worktree: y === "." ? null : y,
        staged: x !== ".", unstaged: y !== ".",
        submodule: sub[0] === "S", conflicted: VCS_CONFLICT_CODES.has(`${x}${y}`),
      });
      continue;
    }

    if (type === "u") {
      const f = rec.slice(2).split(" ");
      const rel = f.slice(9).join(" ");
      entries.set(rel, { path: rel, state: "!", index: "U", worktree: "U", staged: true, unstaged: true, conflicted: true });
      continue;
    }

    if (type === "?") {
      const rel = rec.slice(2);
      entries.set(rel, { path: rel, state: "U", index: null, worktree: "?", staged: false, unstaged: true, untracked: true });
      continue;
    }

    if (type === "!") {
      ignoredSeen++;
      if (ignoredSeen <= VCS_MAX_IGNORED) {
        const rel = rec.slice(2);
        entries.set(rel, { path: rel, state: "I", ignored: true, staged: false, unstaged: false });
      } else {
        ignoredTruncated = true;
      }
      continue;
    }
  }

  return { root, ok: true, error: null, branch, entries, counts: {}, ignoredTruncated };
}

// One numstat pass for the worktree and one for the index: together they are the +N/-M an editor
// shows, split the same way its two source-control lists are.
function attachNumstat(root, status) {
  const read = (args, staged) => {
    const r = runGit(root, [...args, "--numstat", "-z"]);
    if (!r.ok) return;
    const chunks = r.out.split("\0");
    for (let k = 0; k < chunks.length; k++) {
      const c = chunks[k];
      if (!c) continue;
      const t1 = c.indexOf("\t");
      if (t1 < 0) continue;
      const t2 = c.indexOf("\t", t1 + 1);
      if (t2 < 0) continue;
      const added = c.slice(0, t1);
      const deleted = c.slice(t1 + 1, t2);
      let rel = c.slice(t2 + 1);
      if (rel === "") { rel = chunks[k + 2] || ""; k += 2; }   // a rename: old then new
      if (!rel) continue;
      const entry = status.entries.get(rel);
      if (!entry) continue;
      if (staged) { entry.stagedAdded = numOrNull(added); entry.stagedDeleted = numOrNull(deleted); }
      else { entry.added = numOrNull(added); entry.deleted = numOrNull(deleted); }
    }
  };
  read(["--no-optional-locks", "diff"], false);
  read(["--no-optional-locks", "diff", "--cached"], true);
}

function countByState(entries) {
  const counts = {};
  for (const e of entries.values()) counts[e.state] = (counts[e.state] || 0) + 1;
  return counts;
}

function readRepoStatus(root, fresh) {
  const cached = repoStatusCache.get(root);
  if (!fresh && cached && Date.now() - cached.at < VCS_TTL_MS) return cached.status;
  const status = parsePorcelainV2(root);
  if (status.ok) {
    attachNumstat(root, status);
    status.counts = countByState(status.entries);
  }
  repoStatusCache.set(root, { at: Date.now(), status });
  return status;
}

function foldUnder(entries, relDir) {
  const prefix = !relDir || relDir === "." ? "" : relDir.replace(/[\\/]+$/, "") + "/";
  const counts = {};
  let best = null;
  for (const e of entries.values()) {
    if (prefix && !e.path.startsWith(prefix)) continue;
    counts[e.state] = (counts[e.state] || 0) + 1;
    if (best === null || VCS_PRECEDENCE.indexOf(e.state) < VCS_PRECEDENCE.indexOf(best)) best = e.state;
  }
  return { state: best || "clean", counts };
}

function describeEntry(root, rel, entry, branch, version) {
  if (!entry) {
    return {
      repo: root, relative: rel, state: "clean", letter: null, label: VCS_STATES.clean.label,
      labelEn: VCS_STATES.clean.en, colors: null, branch, git: version, staged: false, unstaged: false,
    };
  }
  const meta = VCS_STATES[entry.state] || VCS_STATES.M;
  return {
    repo: root, relative: rel, state: entry.state, letter: meta.letter,
    label: meta.label, labelEn: meta.en, colors: colorsOf(entry.state), branch, git: version,
    index: entry.index || null, worktree: entry.worktree || null,
    staged: !!entry.staged, unstaged: !!entry.unstaged,
    conflicted: !!entry.conflicted, submodule: !!entry.submodule, ignored: !!entry.ignored,
    origPath: entry.origPath || null,
    added: entry.added ?? null, deleted: entry.deleted ?? null,
    stagedAdded: entry.stagedAdded ?? null, stagedDeleted: entry.stagedDeleted ?? null,
  };
}

function decoratePath(filePath, fresh) {
  const abs = path.resolve(String(filePath));
  const version = gitVersion();
  if (!version) {
    return { path: abs, repo: null, state: "none", letter: null, label: VCS_STATES.none.label, labelEn: VCS_STATES.none.en, colors: null, git: null, note: "这台机器上没有可用的 git" };
  }
  let isDirectory = false;
  try { isDirectory = fs.statSync(abs).isDirectory(); } catch { /* a path that no longer exists can still be a recorded deletion */ }
  const root = findRepoRoot(isDirectory ? abs : path.dirname(abs));
  if (!root) {
    return { path: abs, repo: null, state: "none", letter: null, label: VCS_STATES.none.label, labelEn: VCS_STATES.none.en, colors: null, git: version, note: "这条路径之上没有仓库" };
  }
  const status = readRepoStatus(root, fresh);
  if (!status.ok) {
    return { path: abs, repo: root, state: "none", letter: null, label: VCS_STATES.none.label, labelEn: VCS_STATES.none.en, colors: null, git: version, note: status.error };
  }
  const rel = path.relative(root, abs).split(path.sep).join("/");
  if (isDirectory) {
    const folded = foldUnder(status.entries, rel);
    const meta = VCS_STATES[folded.state] || VCS_STATES.clean;
    return {
      path: abs, repo: root, relative: rel || ".", state: folded.state,
      letter: meta.letter, label: meta.label, labelEn: meta.en,
      colors: colorsOf(folded.state), branch: status.branch, children: folded.counts, git: version,
    };
  }
  return Object.assign({ path: abs }, describeEntry(root, rel, status.entries.get(rel), status.branch, version));
}

function repoSummary(targetPath, fresh) {
  const abs = path.resolve(String(targetPath));
  const version = gitVersion();
  if (!version) return { ok: false, root: null, note: "这台机器上没有可用的 git", git: null };
  let isDirectory = true;
  try { isDirectory = fs.statSync(abs).isDirectory(); } catch { isDirectory = false; }
  const root = findRepoRoot(isDirectory ? abs : path.dirname(abs));
  if (!root) return { ok: false, root: null, note: "这条路径之上没有仓库", git: version };
  const status = readRepoStatus(root, fresh);
  if (!status.ok) return { ok: false, root, note: status.error, git: version };

  const staged = [], changes = [], untracked = [], conflicts = [], submodules = [], ignored = [];
  for (const e of status.entries.values()) {
    const item = {
      path: e.path, state: e.state, letter: (VCS_STATES[e.state] || {}).letter || null,
      added: e.added ?? null, deleted: e.deleted ?? null,
      stagedAdded: e.stagedAdded ?? null, stagedDeleted: e.stagedDeleted ?? null,
      origPath: e.origPath || null,
    };
    if (e.state === "I") { ignored.push(item); continue; }
    if (e.state === "U") { untracked.push(item); continue; }
    if (e.state === "!") { conflicts.push(item); continue; }
    if (e.staged) staged.push(item);
    if (e.unstaged) changes.push(item);
    if (e.submodule) submodules.push(item);
  }
  const branch = status.branch || {};
  return {
    ok: true, root, git: version,
    branch: {
      name: branch.name || null,
      detached: !!branch.detached || !branch.name,
      oid: branch.oid && branch.oid !== "(initial)" ? String(branch.oid).slice(0, 12) : null,
      upstream: branch.upstream || null,
      ahead: branch.ahead || 0,
      behind: branch.behind || 0,
    },
    counts: status.counts,
    changed: status.entries.size,
    ignoredTruncated: !!status.ignoredTruncated,
    staged, changes, untracked, conflicts, submodules,
    ignored: { count: ignored.length, sample: ignored.slice(0, 40).map((i) => i.path) },
  };
}

// ---------- Local format pack: per-install personalisation of the format library ----------
// Built-in coverage is necessarily finite, while every machine carries its own formats
// (CAD/CAM, DAW, engine, in-house tooling). The local pack lets *this* installation teach
// itself what it actually meets, without patching the plugin: magic signatures, plain-text
// extensions and name rules, kept at $DSH_HOME/library/formats.local.json.
// Safety rules: built-ins are always matched first, so a local entry can never shadow a
// known format; conflicts are refused rather than merged. `library_format scan` only
// *proposes* candidates (with evidence) - nothing is learned without explicit samples,
// because a directory an intruder can write to must not be able to teach a fake format.
function localFormatsFile() {
  return path.join(libraryDir(), "formats.local.json");
}

function emptyLocalPack() {
  return { version: 1, updatedAt: null, formats: [], textExtensions: [], nameRules: [], analyzers: [] };
}

function parseHexSig(v) {
  if (Array.isArray(v)) {
    const out = v.map(Number);
    return out.length && out.length <= 32 && out.every((n) => Number.isInteger(n) && n >= 0 && n <= 255) ? out : null;
  }
  const parts = String(v || "").trim().replace(/0x/gi, "").replace(/[,\s]+/g, " ").split(" ").filter(Boolean);
  if (!parts.length || parts.length > 32) return null;
  const out = [];
  for (const p of parts) {
    if (!/^[0-9a-f]{1,2}$/i.test(p.replace(/^0x/i, "").trim() || p)) return null;
    const n = parseInt(p.replace(/^0x/i, ""), 16);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out.push(n);
  }
  return out;
}

function normalizeLocalPack(raw) {
  const d = emptyLocalPack();
  if (!raw || typeof raw !== "object") return d;
  d.updatedAt = raw.updatedAt || null;
  for (const f of Array.isArray(raw.formats) ? raw.formats : []) {
    const sig = parseHexSig(f && f.sig);
    if (!sig || !f.format) continue;
    d.formats.push({
      format: String(f.format).slice(0, 40),
      type: String(f.type || "document"),
      sig,
      ext: (Array.isArray(f.ext) ? f.ext : []).map((e) => String(e).toLowerCase().replace(/^\./, "")).filter(Boolean),
      note: String(f.note || "").slice(0, 200),
      createdAt: f.createdAt || null,
    });
  }
  for (const e of Array.isArray(raw.textExtensions) ? raw.textExtensions : []) {
    const s = String(e).toLowerCase().replace(/^\./, "");
    if (s) d.textExtensions.push(s);
  }
  for (const r of Array.isArray(raw.nameRules) ? raw.nameRules : []) {
    // A name rule must come from a pattern STRING. A live RegExp serialises to {} and would turn
    // into the wildly permissive /[object Object]/i, so anything unrepresentable is dropped
    // rather than silently matching unrelated files.
    const source = typeof r?.source === "string" ? r.source : typeof r?.re === "string" ? r.re : null;
    if (!source) continue;
    let re;
    try {
      re = new RegExp(source, "i");
    } catch {
      continue; // unrepresentable pattern: skip it instead of matching everything
    }
    d.nameRules.push({ re, source, role: String(r.role || "local"), expect: r.expect || null, note: String(r.note || "").slice(0, 200) });
  }
  // User-registered (DIY) analyzers consumed by analyze_object. Validated strictly: an entry
  // without a name, a command, or any way to match is dropped rather than kept half-usable.
  for (const a of Array.isArray(raw.analyzers) ? raw.analyzers : []) {
    if (!a || typeof a !== "object") continue;
    const name = String(a.name || "").slice(0, 60).trim();
    const exe = String(a.exe || "").trim();
    if (!name || !exe) continue;
    const exts = (Array.isArray(a.exts) ? a.exts : [])
      .map((e) => String(e).toLowerCase().replace(/^\./, "").trim()).filter(Boolean).slice(0, 20);
    let matchName = null;
    if (a.matchName) {
      try { new RegExp(String(a.matchName), "i"); matchName = String(a.matchName); } catch { matchName = null; }
    }
    if (!exts.length && !matchName) continue;
    d.analyzers.push({
      name,
      kind: String(a.kind || name).slice(0, 40),
      exts,
      matchName,
      exe,
      args: (Array.isArray(a.args) ? a.args : []).map((x) => String(x)).slice(0, 40),
      timeoutMs: Math.min(Math.max(Number(a.timeoutMs) || 30000, 1000), 300000),
      parse: a.parse === "text" ? "text" : "json",
      note: String(a.note || "").slice(0, 200),
      createdAt: a.createdAt || null,
    });
  }
  return d;
}

let _localPack = { key: null, data: null };

// Cached by file mtime+size, so a hand-edited pack is picked up without a restart.
function loadLocalFormats() {
  let key = "absent";
  try {
    const st = fs.statSync(localFormatsFile());
    key = `${st.mtimeMs}:${st.size}`;
  } catch {
    key = "absent";
  }
  if (_localPack.data && _localPack.key === key) return _localPack.data;
  let data = emptyLocalPack();
  if (key !== "absent") {
    try {
      data = normalizeLocalPack(JSON.parse(fs.readFileSync(localFormatsFile(), "utf8")));
    } catch {
      data = emptyLocalPack();
      data.__corrupt = true;
    }
  }
  _localPack = { key, data };
  return data;
}

function saveLocalFormats(pack) {
  ensureLibrary();
  pack.version = 1;
  pack.updatedAt = new Date().toISOString();
  // Canonical on-disk shape: name rules keep their pattern SOURCE (plus flags), never a live
  // RegExp - RegExp objects serialise to {} and reload as a match-everything pattern.
  const onDisk = {
    version: pack.version,
    updatedAt: pack.updatedAt,
    formats: pack.formats,
    textExtensions: pack.textExtensions,
    nameRules: pack.nameRules.map((r) => ({ source: String(r.source || r.re?.source || ""), flags: "i", role: r.role, expect: r.expect ?? null, note: r.note ?? "" })),
    analyzers: (pack.analyzers || []).map((a) => ({
      name: a.name, kind: a.kind, exts: a.exts, matchName: a.matchName,
      exe: a.exe, args: a.args, timeoutMs: a.timeoutMs, parse: a.parse,
      note: a.note ?? "", createdAt: a.createdAt ?? null,
    })),
  };
  fs.writeFileSync(localFormatsFile(), JSON.stringify(onDisk, null, 2), "utf8");
  _localPack = { key: null, data: null };
  return localFormatsFile();
}

// Built-in signatures a candidate prefix could collide with (either direction).
function builtinSigConflicts(sig) {
  const hits = [];
  for (const entry of FILE_SIGNATURES) {
    const a = entry.sig;
    const n = Math.min(a.length, sig.length);
    let same = true;
    for (let i = 0; i < n; i++) if (a[i] !== sig[i]) { same = false; break; }
    if (same) hits.push(`${entry.format} (${a.map((b) => b.toString(16).padStart(2, "0")).join(" ")})`);
  }
  return [...new Set(hits)];
}

// Longest common byte prefix across the sample headers (capped at 16 bytes).
function commonPrefix(bufs) {
  const list = bufs.filter((b) => b && b.length);
  if (!list.length) return [];
  const min = Math.min(16, ...list.map((b) => b.length));
  const out = [];
  for (let i = 0; i < min; i++) {
    const b = list[0][i];
    if (list.every((x) => x[i] === b)) out.push(b);
    else break;
  }
  return out;
}

function hexSig(arr) {
  return arr.map((b) => b.toString(16).padStart(2, "0")).join(" ");
}

// ---------- Format report: user-generated, user-delivered contribution ----------
// The goal is to collect the formats real machines have that the library still cannot
// identify. The report is built and written locally; it carries no file names, no paths and
// no file contents; nothing in this path touches the network; and delivery is manual - by
// the user, after inspecting exactly what is inside. Nothing is ever sent automatically.
function reportsDir() {
  return path.join(libraryDir(), "reports");
}

const PLUGIN_VERSION = (() => {
  try {
    return String(JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version || "unknown");
  } catch {
    return "unknown";
  }
})();

// CRC-32 (required by ZIP) - tiny table-driven version, no dependency.
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

// Minimal ZIP writer (deflate, UTF-8 names) so the report opens everywhere, dependency-free.
function zipBuffer(entries) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, "utf8");
    const data = Buffer.from(e.data, "utf8");
    const packed = deflateRawSync(data);
    const useDeflate = packed.length < data.length;
    const body = useDeflate ? packed : data;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0x0800, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    parts.push(lh, name, body);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x0800, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(body.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, name);
    offset += lh.length + name.length + body.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cd, end]);
}

// Shared walker: files whose type the library cannot identify (binary only - plain text is
// already covered by the text path). Used by `scan` (local proposals, may carry sample
// paths) and `report` (contribution archive - never carries paths).
function collectUnidentified(dir, maxFiles, maxSamples = 3, withPaths = true) {
  const max = Math.min(Math.max(maxFiles || 1000, 1), 20000);
  const files = [];
  const walk = (d) => {
    if (files.length >= max) return;
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (files.length >= max) return;
      const p = path.join(d, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (e.isFile()) files.push(p);
    }
  };
  walk(dir);
  const groups = new Map();
  for (const f of files) {
    const base = path.basename(f);
    if (base.startsWith(".")) continue;
    const ext = path.extname(base).toLowerCase().replace(".", "");
    if (!ext) continue;
    if (sniffFileType(f)) continue;
    if (contentKind(f) === "text") continue;
    const g = groups.get(ext) || { ext, count: 0, sampleCount: 0, samples: [], heads: [] };
    g.count++;
    if (g.heads.length < maxSamples) {
      g.sampleCount++;
      if (withPaths) g.samples.push(f);
      const h = readHeader(f, 16);
      if (h) g.heads.push(h);
    }
    groups.set(ext, g);
  }
  return { scanned: files.length, groups };
}

// ---------- Format relationships (deps), user-level sanitising, passphrase sealing ----------
// Dependency collection records which formats reference which other formats. Only format
// names/extensions are kept (never paths or file names), so the result is format knowledge
// rather than user data; DLL names are opt-in. Paths, when a user asks for them, are the
// only user-level fields - they are sanitised by default and can be sealed with a
// passphrase the USER holds (they can open it again any time; nobody else can).

function walkFiles(dir, maxFiles) {
  const max = Math.min(Math.max(maxFiles || 1000, 1), 20000);
  const files = [];
  const walk = (d) => {
    if (files.length >= max) return;
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (files.length >= max) return;
      const p = path.join(d, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (e.isFile()) files.push(p);
    }
  };
  walk(dir);
  return files;
}

function readCapped(filePath, maxBytes) {
  try {
    const fd = fs.openSync(filePath, "r");
    const size = fs.fstatSync(fd).size;
    const n = Math.min(size, maxBytes);
    const b = Buffer.alloc(n);
    fs.readSync(fd, b, 0, n, 0);
    fs.closeSync(fd);
    return b;
  } catch {
    return null;
  }
}

// Entry names inside a ZIP/OPC container (local file headers).
function zipEntryNames(buf, max = 400) {
  const out = [];
  let i = 0;
  while (i + 30 <= buf.length && out.length < max) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x03 && buf[i + 3] === 0x04) {
      const compSize = buf.readUInt32LE(i + 18);
      const nameLen = buf.readUInt16LE(i + 26);
      const extraLen = buf.readUInt16LE(i + 28);
      if (i + 30 + nameLen <= buf.length) {
        const nm = buf.subarray(i + 30, i + 30 + nameLen).toString("utf8");
        if (nm) out.push(nm);
        i += 30 + nameLen + extraLen + compSize;
        continue;
      }
    }
    i++;
  }
  return out;
}

// PE import table: the DLL names an executable/library depends on (Windows side of a
// dependency graph). Bounded and defensive - any malformed header returns null.
function peImports(buf, maxDlls = 64) {
  try {
    if (!buf || buf.length < 0x40 || buf[0] !== 0x4d || buf[1] !== 0x5a) return null;
    const peOff = buf.readUInt32LE(0x3c);
    if (peOff + 24 > buf.length || buf.readUInt32LE(peOff) !== 0x00004550) return null;
    const coff = peOff + 4;
    const numSections = buf.readUInt16LE(coff + 2);
    const optSize = buf.readUInt16LE(coff + 16);
    const opt = coff + 20;
    const ddOff = opt + (buf.readUInt16LE(opt) === 0x20b ? 112 : 96);
    if (ddOff + 16 > buf.length) return null;
    const importRva = buf.readUInt32LE(ddOff + 8);
    if (!importRva) return null;
    const secOff = opt + optSize;
    const sections = [];
    for (let i = 0; i < numSections && i < 96; i++) {
      const s = secOff + i * 40;
      if (s + 40 > buf.length) break;
      sections.push({ va: buf.readUInt32LE(s + 12), vsize: buf.readUInt32LE(s + 8), raw: buf.readUInt32LE(s + 20), rawSize: buf.readUInt32LE(s + 16) });
    }
    const rva2off = (rva) => {
      for (const s of sections) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) return s.raw + (rva - s.va);
      return null;
    };
    const desc = rva2off(importRva);
    if (desc == null) return null;
    const out = [];
    for (let i = 0; i < 256; i++) {
      const d = desc + i * 20;
      if (d + 20 > buf.length) break;
      const nameRva = buf.readUInt32LE(d + 12);
      if (!nameRva) break;
      const no = rva2off(nameRva);
      if (no == null || no >= buf.length) break;
      let end = no;
      while (end < buf.length && buf[end] !== 0 && end - no < 260) end++;
      const nm = buf.subarray(no, end).toString("latin1").trim();
      if (nm) out.push(nm);
      if (out.length >= maxDlls) break;
    }
    return out;
  } catch {
    return null;
  }
}

// Extensions referenced by a text file (project/source/markup) - format->format edges only.
// Single-letter extensions are real (.h/.c/.s/.m), but prose abbreviations ("e.g", "i.e.")
// are not, so those are filtered out.
const SINGLE_LETTER_EXTS = new Set(["h", "c", "s", "m", "f", "r", "o", "a", "d", "i"]);
// Only *known* extensions count as references: source code is full of dotted member access
// (Console.WriteLine, .ActiveCfg, Microsoft.NET.Sdk) that would otherwise look like a
// reference to a "writeline"/"activecfg"/"net" format.
const LINKABLE_EXTS = new Set(["dll", "exe", "lib", "obj", "res", "o", "so", "dylib", "pyd", "map", "il", "class", "pch", "idb", "exp"]);
function refsFromText(text) {
  const out = new Set();
  for (const m of text.matchAll(/[A-Za-z0-9_\-.]{1,120}?\.([A-Za-z][A-Za-z0-9]{0,9})\b/g)) {
    const e = m[1].toLowerCase();
    if (e.length === 1 && !SINGLE_LETTER_EXTS.has(e)) continue;
    if (!EXT_FAMILY[e] && !LINKABLE_EXTS.has(e)) continue;
    out.add(e);
  }
  return out;
}

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Replace user/host/date identifiers with placeholders so a path carries structure but not
// identity. `dirs` keeps only the directory part, `full` keeps the whole sanitised path.
function sanitizePath(p, mode = "full", depth = 3, extra = []) {
  let s = String(p || "").replace(/\\/g, "/");
  s = s.replace(/^[A-Za-z]:/, "<drive>");
  s = s.replace(/\/Users\/[^/]+/gi, "/<user>").replace(/\/home\/[^/]+/gi, "/<user>");
  s = s.replace(/\/(AppData)\/[^/]+\/[^/]+/gi, "/$1/<user>");
  s = s.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "<uuid>");
  s = s.replace(/\b(?:session|tmp|\.tmp)-?[A-Za-z0-9_-]{4,}/gi, "<id>");
  s = s.replace(/\b\d{4}-\d{2}-\d{2}(?:[T_]\d{2}[-:]\d{2}[-:]\d{2})?\b/g, "<date>");
  for (const [needle, tag] of [[os.homedir(), "<home>"], [os.hostname(), "<host>"], [os.userInfo().username, "<user>"], ...extra.map((e) => [e, "<excluded>"])]) {
    if (needle && String(needle).length > 2) s = s.replace(new RegExp(escapeRe(String(needle).replace(/\\/g, "/")), "gi"), tag);
  }
  if (mode === "dirs") {
    const parts = path.posix.dirname(s).split("/").filter(Boolean);
    return "<root>/" + parts.slice(-Math.max(1, depth)).join("/");
  }
  return s;
}

// Passphrase sealing: the user holds the passphrase, so they can always reopen it locally
// (op=unseal) and decide for themselves whether anyone else ever can.
function sealWithPassphrase(passphrase, obj) {
  const salt = randomBytes(16);
  const key = Buffer.from(hkdfSync("sha256", Buffer.from(String(passphrase), "utf8"), salt, Buffer.from(SEAL_INFO, "utf8"), 32));
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  let ct = cipher.update(JSON.stringify(obj), "utf8", "hex");
  ct += cipher.final("hex");
  return { v: 1, kdf: "hkdf-sha256", salt: salt.toString("hex"), iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), ct };
}

// Sealed records store no `info`, so the namespace is fixed by this constant. Try the current
// namespace first, then the legacy one, so an archive sealed before the rename still opens.
function unsealWithPassphrase(passphrase, rec) {
  const pass = Buffer.from(String(passphrase), "utf8");
  const salt = Buffer.from(rec.salt, "hex");
  for (const info of [SEAL_INFO, SEAL_INFO_LEGACY]) {
    try {
      const key = Buffer.from(hkdfSync("sha256", pass, salt, Buffer.from(info, "utf8"), 32));
      const d = createDecipheriv("aes-256-gcm", key, Buffer.from(rec.iv, "hex"));
      d.setAuthTag(Buffer.from(rec.tag, "hex"));
      let plain = d.update(rec.ct, "hex", "utf8");
      plain += d.final("utf8");
      return JSON.parse(plain);
    } catch { /* try the next namespace */ }
  }
  return { __unsealError: true };
}

// Dependency aggregation over a directory: format -> format edges. Paths never enter the
// result; DLL names only when explicitly requested.
function collectDeps(dir, maxFiles, wantNames) {
  const files = walkFiles(dir, maxFiles);
  const edges = new Map();
  const dllNames = new Set();
  let inspected = 0;
  for (const f of files) {
    const head = readHeader(f, 4);
    if (!head || head.length < 4) continue;
    let from = path.extname(f).toLowerCase().replace(".", "");
    if (!from) continue;
    const sn = sniffFileType(f);
    if (sn && sn.format) from = sn.format;
    let refs = [];
    const isZip = head[0] === 0x50 && head[1] === 0x4b;
    const isPE = head[0] === 0x4d && head[1] === 0x5a;
    try {
      if (isZip) {
        const buf = readCapped(f, 4 * 1024 * 1024);
        if (buf) refs = [...new Set(zipEntryNames(buf).map((n) => path.extname(n).toLowerCase().replace(".", "")).filter(Boolean))];
      } else if (isPE) {
        const dlls = peImports(readCapped(f, 16 * 1024 * 1024));
        if (dlls && dlls.length) {
          refs = ["dll"];
          if (wantNames) dlls.forEach((d) => dllNames.add(d));
        }
      } else if (contentKind(f) === "text") {
        const buf = readCapped(f, 512 * 1024);
        if (buf) refs = [...refsFromText(buf.toString("utf8"))];
      }
    } catch {}
    if (!refs.length) continue;
    inspected++;
    for (const to of refs.slice(0, 30)) {
      if (!to || to === from) continue;
      const k = `${from}->${to}`;
      edges.set(k, (edges.get(k) || 0) + 1);
    }
  }
  const list = [...edges.entries()]
    .map(([k, count]) => {
      const idx = k.indexOf("->");
      return { from: k.slice(0, idx), to: k.slice(idx + 2), count };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 300);
  return { scanned: files.length, inspected, edges: list, dllNames: [...dllNames].sort().slice(0, 200) };
}

// Read one entry out of a ZIP built by zipBuffer (used to reopen a sealed layer).
function zipReadEntry(buf, wantName) {
  let i = 0;
  while (i + 30 <= buf.length) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x03 && buf[i + 3] === 0x04) {
      const method = buf.readUInt16LE(i + 8);
      const compSize = buf.readUInt32LE(i + 18);
      const nameLen = buf.readUInt16LE(i + 26);
      const extraLen = buf.readUInt16LE(i + 28);
      if (i + 30 + nameLen <= buf.length) {
        const nm = buf.subarray(i + 30, i + 30 + nameLen).toString("utf8");
        const dataStart = i + 30 + nameLen + extraLen;
        if (nm === wantName) {
          const data = buf.subarray(dataStart, dataStart + compSize);
          try { return method === 8 ? inflateRawSync(data) : data; } catch { return null; }
        }
        i = dataStart + compSize;
        continue;
      }
    }
    i++;
  }
  return null;
}

function draftsDir() {
  return path.join(reportsDir(), "drafts");
}

function resolveDraft(idOrPath) {
  const raw = String(idOrPath || "");
  if (raw && fs.existsSync(raw) && fs.statSync(raw).isFile()) return raw;
  try {
    const hits = fs.readdirSync(draftsDir()).filter((f) => f.includes(raw)).sort();
    if (hits.length) return path.join(draftsDir(), hits[hits.length - 1]);
  } catch {}
  return null;
}

// ---------- Format report delivery: a native window, never a console ----------
// The report is only ever delivered by the user. This opens the platform's own GUI - a Windows
// dialog built with WinForms, zenity/kdialog/osascript on Linux/macOS - so the user can read what
// is inside the archive and then choose: send it with their own mail client, save a copy, open the
// folder, or delete it. Every action is an explicit click, the plugin still performs no network
// I/O, and when no GUI is available the caller gets plain instructions instead.
const REPORT_MAIL_TO = "seimuontei@gmail.com";

function latestReportFile() {
  try {
    const zips = fs.readdirSync(reportsDir()).filter((f) => f.endsWith(".zip"));
    if (!zips.length) return null;
    const withTime = zips.map((f) => {
      const p = path.join(reportsDir(), f);
      return { p, t: fs.statSync(p).mtimeMs };
    });
    withTime.sort((a, b) => b.t - a.t);
    return withTime[0].p;
  } catch {
    return null;
  }
}

// How to hand the archive over, without any GUI (servers, SSH, unsupported platform).
function reportDeliveryInstructions(file) {
  return {
    mail: { to: REPORT_MAIL_TO, subject: `[format report] kohane-index-desuno ${PLUGIN_VERSION}`, attachment: file },
    steps: [
      `1. Review the archive (it holds report.json + manifest.txt):  ${file}`,
      `2. Send it yourself to ${REPORT_MAIL_TO} with subject "[format report] kohane-index-desuno ${PLUGIN_VERSION}"`,
      "   - an e-mail cannot carry the attachment automatically: attach the .zip in your own mail client",
      "   - or upload it yourself (e.g. gigafile.nu) and send the link",
      "3. Prefer to keep it local? Do nothing: nothing has been, or will be, transmitted.",
    ],
    note: "nothing was sent and no network I/O was performed",
  };
}

// Windows: a real dialog (read-only preview + explicit actions), built with WinForms.
function windowsReportDialogScript() {
  return [
    'param([string]$ReportPath, [string]$ManifestPath, [string]$ResultPath, [string]$MailTo, [string]$Subject, [string]$Body, [int]$AutoCloseMs = 0, [switch]$SelfTest)',
    "Add-Type -AssemblyName System.Windows.Forms",
    "Add-Type -AssemblyName System.Drawing",
    "[System.Windows.Forms.Application]::EnableVisualStyles()",
    "$choice = $null",
    "$savedTo = $null",
    "$nl = [Environment]::NewLine",
    "$form = New-Object System.Windows.Forms.Form",
    '$form.Text = "kohane-index-desuno - file format report"',
    "$form.ClientSize = New-Object System.Drawing.Size(700, 528)",
    '$form.StartPosition = "CenterScreen"',
    '$form.FormBorderStyle = "FixedDialog"',
    "$form.MaximizeBox = $false",
    "$form.MinimizeBox = $false",
    "$title = New-Object System.Windows.Forms.Label",
    '$title.Text = "A file format report was prepared on this computer."',
    '$title.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)',
    "$title.SetBounds(16, 14, 668, 22)",
    "$form.Controls.Add($title)",
    "$info = New-Object System.Windows.Forms.Label",
    '$info.Text = ("It lists only file types this plugin could not identify: extensions, magic byte prefixes, counts and format relationships." + $nl + "No file names, no folder paths and no file contents are included. Nothing is sent automatically - the choice is yours.")',
    "$info.SetBounds(16, 42, 668, 46)",
    "$form.Controls.Add($info)",
    "$preview = New-Object System.Windows.Forms.TextBox",
    "$preview.Multiline = $true",
    "$preview.ReadOnly = $true",
    '$preview.ScrollBars = "Vertical"',
    "$preview.WordWrap = $false",
    '$preview.Font = New-Object System.Drawing.Font("Consolas", 8.25)',
    "$preview.SetBounds(16, 94, 668, 330)",
    "if (Test-Path $ManifestPath) { $preview.Text = (Get-Content -Raw -Encoding UTF8 $ManifestPath) }",
    "$preview.SelectionStart = 0",
    "$form.Controls.Add($preview)",
    "$chkFolder = New-Object System.Windows.Forms.CheckBox",
    '$chkFolder.Text = "Also open the folder with this file selected, so I can attach it"',
    "$chkFolder.Checked = $true",
    "$chkFolder.SetBounds(16, 434, 500, 22)",
    "$form.Controls.Add($chkFolder)",
    "$btnEmail = New-Object System.Windows.Forms.Button",
    '$btnEmail.Text = "Send by e-mail..."',
    "$btnEmail.SetBounds(16, 470, 140, 34)",
    "$form.Controls.Add($btnEmail)",
    "$btnSave = New-Object System.Windows.Forms.Button",
    '$btnSave.Text = "Save a copy..."',
    "$btnSave.SetBounds(164, 470, 130, 34)",
    "$form.Controls.Add($btnSave)",
    "$btnFolder = New-Object System.Windows.Forms.Button",
    '$btnFolder.Text = "Open folder"',
    "$btnFolder.SetBounds(302, 470, 110, 34)",
    "$form.Controls.Add($btnFolder)",
    "$btnDelete = New-Object System.Windows.Forms.Button",
    '$btnDelete.Text = "Delete report"',
    "$btnDelete.SetBounds(420, 470, 120, 34)",
    "$form.Controls.Add($btnDelete)",
    "$btnClose = New-Object System.Windows.Forms.Button",
    '$btnClose.Text = "Close"',
    "$btnClose.SetBounds(548, 470, 136, 34)",
    "$form.Controls.Add($btnClose)",
    "$form.CancelButton = $btnClose",
    "$btnFolder.Add_Click({ if (Test-Path $ReportPath) { Start-Process explorer.exe -ArgumentList ('/select,\"' + $ReportPath + '\"') } })",
    '$btnEmail.Add_Click({ if ($chkFolder.Checked -and (Test-Path $ReportPath)) { Start-Process explorer.exe -ArgumentList (\'/select,"\' + $ReportPath + \'"\') }; Start-Process ("mailto:" + $MailTo + "?subject=" + [uri]::EscapeDataString($Subject) + "&body=" + [uri]::EscapeDataString($Body)); $script:choice = "email"; $form.Close() })',
    '$btnSave.Add_Click({ $dlg = New-Object System.Windows.Forms.SaveFileDialog; $dlg.Title = "Save a copy of the format report"; $dlg.Filter = "Zip archive (*.zip)|*.zip"; $dlg.FileName = [System.IO.Path]::GetFileName($ReportPath); if ($dlg.ShowDialog() -eq "OK") { Copy-Item -LiteralPath $ReportPath -Destination $dlg.FileName -Force; $script:savedTo = $dlg.FileName; [System.Windows.Forms.MessageBox]::Show(("Saved to:" + $nl + $script:savedTo), "kohane-index-desuno", "OK", "Information") | Out-Null } })',
    '$btnDelete.Add_Click({ $answer = [System.Windows.Forms.MessageBox]::Show("Delete this report from your computer? Nothing was ever sent, so deleting it withdraws it.", "Delete report", "YesNo", "Warning"); if ($answer -eq "Yes") { Remove-Item -LiteralPath $ReportPath -Force -ErrorAction SilentlyContinue; $script:choice = "delete"; $form.Close() } })',
    '$btnClose.Add_Click({ $script:choice = "close"; $form.Close() })',
    "if ($SelfTest) { $st = New-Object System.Windows.Forms.Timer; $st.Interval = 1500; $st.Add_Tick({ $st.Stop(); if (-not $choice) { $script:choice = \"selftest\" }; $form.Close() }); $st.Start() }",
    "if ($AutoCloseMs -gt 0) { $ac = New-Object System.Windows.Forms.Timer; $ac.Interval = $AutoCloseMs; $ac.Add_Tick({ $ac.Stop(); if (-not $choice) { $script:choice = \"timeout\" }; $form.Close() }); $ac.Start() }",
    "[void]$form.ShowDialog()",
    '$action = "closed"',
    "if ($choice) { $action = $choice }",
    '$result = @{ action = $action; savedTo = $savedTo; at = (Get-Date).ToUniversalTime().ToString("o") }',
    "$json = $result | ConvertTo-Json -Compress",
    "# PowerShell 5.1 adds a BOM with -Encoding UTF8, which breaks JSON.parse on the other side,",
    "[System.IO.File]::WriteAllText($ResultPath, $json, (New-Object System.Text.UTF8Encoding($false)))",
    "$form.Dispose()",
  ].join("\n");
}

// Linux/macOS: zenity, then kdialog, then osascript, each in a loop so the user can read the
// manifest before deciding. The shell performs the redirection, so the result never has to
// travel through a stdout pipe.
function posixReportDialogScript() {
  const info = "A file format report was prepared on this computer. It lists only file types this plugin could not identify: extensions, magic byte prefixes, counts and format relationships. No file names, no folder paths and no file contents are included. Nothing is sent automatically - the choice is yours.";
  return [
    "#!/bin/sh",
    "# Report delivery dialog for Linux and macOS (zenity, kdialog or osascript).",
    'REPORT="$1"; MANIFEST="$2"; RESULT="$3"; MAILTO="$4"; SUBJECT="$5"; SUBJECT_ENC="$6"',
    `TEXT="${info}"`,
    'HEAD="kohane-index-desuno - file format report"',
    'write_result() { printf \'{"action":"%s"}\\n\' "$1" > "$RESULT"; }',
    'open_any() {',
    '  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$1" >/dev/null 2>&1; return 0; fi',
    '  if command -v open >/dev/null 2>&1; then open "$1" >/dev/null 2>&1; return 0; fi',
    '  return 1',
    "}",
    'mail_url() { printf "mailto:%s?subject=%s" "$MAILTO" "$SUBJECT_ENC"; }',
    "if command -v zenity >/dev/null 2>&1; then",
    "  while : ; do",
    '    SEL=$(zenity --radiolist --title="$HEAD" --text="$TEXT" --column=Pick --column=Action TRUE "Send by e-mail" FALSE "View contents" FALSE "Open folder" FALSE "Delete report" FALSE "Close" --height=460 --width=720 2>/dev/null | tail -n 1)',
    '    SEL=${SEL##*|}',
    "    case \"$SEL\" in",
    '      "Send by e-mail") open_any "$(mail_url)"; write_result email; break ;;',
    '      "View contents") zenity --text-info --title="$HEAD" --filename="$MANIFEST" --width=760 --height=520 2>/dev/null ; continue ;;',
    '      "Open folder") open_any "$(dirname "$REPORT")"; write_result folder; break ;;',
    '      "Delete report") rm -f "$REPORT"; write_result delete; break ;;',
    '      *) write_result close; break ;;',
    "    esac",
    "  done",
    "elif command -v kdialog >/dev/null 2>&1; then",
    "  while : ; do",
    '    SEL=$(kdialog --title "$HEAD" --menu "$TEXT" 1 "Send by e-mail" 2 "View contents" 3 "Open folder" 4 "Delete report" 5 "Close" 2>/dev/null)',
    "    case \"$SEL\" in",
    '      1) open_any "$(mail_url)"; write_result email; break ;;',
    '      2) kdialog --title "$HEAD" --textbox "$MANIFEST" 760 520 2>/dev/null ; continue ;;',
    '      3) open_any "$(dirname "$REPORT")"; write_result folder; break ;;',
    '      4) rm -f "$REPORT"; write_result delete; break ;;',
    '      *) write_result close; break ;;',
    "    esac",
    "  done",
    "elif command -v osascript >/dev/null 2>&1; then",
    "  while : ; do",
    `    BTN=$(osascript -e 'button returned of (display dialog "${info}" with title "kohane-index-desuno - file format report" buttons {"Send by e-mail", "View contents", "Open folder", "Delete report", "Close"} default button 1)' 2>/dev/null)`,
    "    case \"$BTN\" in",
    '      "Send by e-mail") open_any "$(mail_url)"; write_result email; break ;;',
    '      "View contents") open_any "$MANIFEST"; continue ;;',
    '      "Open folder") open_any "$(dirname "$REPORT")"; write_result folder; break ;;',
    '      "Delete report") rm -f "$REPORT"; write_result delete; break ;;',
    '      *) write_result close; break ;;',
    "    esac",
    "  done",
    "else",
    '  write_result unavailable',
    "fi",
  ].join("\n");
}

// Which shell shows the desktop dialog. PowerShell 7 ("pwsh") is preferred when this machine has
// it, so the dialog follows the user's current default; Windows PowerShell 5.1 stays as the
// fallback (both expose the same WinForms surface). KOHANE_PS_SHELL pins an explicit executable.
function resolvePowerShell() {
  const pinned = String(process.env.KOHANE_PS_SHELL || "").trim();
  if (pinned) return pinned;
  if (process.platform !== "win32") return "pwsh";
  const roots = [process.env.ProgramW6432, process.env.ProgramFiles, "C:\\Program Files", "C:\\Program Files (x86)"].filter(Boolean);
  const fixed = roots.map((r) => path.join(r, "PowerShell", "7", "pwsh.exe"));
  if (process.env.LOCALAPPDATA) fixed.push(path.join(process.env.LOCALAPPDATA, "Microsoft", "WindowsApps", "pwsh.exe"));
  for (const f of fixed) {
    try { if (fs.existsSync(f)) return f; } catch {}
  }
  for (const dir of String(process.env.PATH || "").split(path.delimiter)) {
    if (!dir) continue;
    const cand = path.join(dir, "pwsh.exe");
    try { if (fs.existsSync(cand)) return cand; } catch {}
  }
  return "powershell.exe";
}

// Scratch directory for the dialog's manifest/script/result files. It lives inside this
// installation's own library rather than the machine temp folder, so kohane writes nothing to a
// system drive it does not own; it is removed as soon as the dialog reports back.
function dialogWorkDir() {
  const root = path.join(libraryDir(), "tmp");
  fs.mkdirSync(root, { recursive: true });
  return fs.mkdtempSync(path.join(root, "dialog-"));
}

// Open the dialog and wait for the user's decision (or for autoCloseMs / self-test to end it).
async function runReportDialog(reportPath, opts = {}) {
  const manifest = zipReadEntry(fs.readFileSync(reportPath), "manifest.txt");
  const text = manifest ? manifest.toString("utf8").replace(/^\uFEFF/, "") : "manifest.txt could not be read from the archive.";
  const dir = dialogWorkDir();
  const manifestPath = path.join(dir, "manifest.txt");
  const resultPath = path.join(dir, "result.json");
  const scriptPath = path.join(dir, process.platform === "win32" ? "dialog.ps1" : "dialog.sh");
  fs.writeFileSync(manifestPath, "\uFEFF" + text, "utf8");
  fs.writeFileSync(scriptPath, process.platform === "win32" ? windowsReportDialogScript() : posixReportDialogScript(), "utf8");

  const subject = `[format report] kohane-index-desuno ${PLUGIN_VERSION}`;
  const body = "Attached: the format report archive prepared by kohane-index-desuno. It contains file extensions, magic-byte prefixes, counts and format relationships only - no file names, no folder paths and no file contents. Please attach the .zip that is selected in the folder window.";
  let command;
  let args;
  if (process.platform === "win32") {
    command = resolvePowerShell();
    args = ["-STA", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", scriptPath,
      "-ReportPath", reportPath, "-ManifestPath", manifestPath, "-ResultPath", resultPath,
      "-MailTo", REPORT_MAIL_TO, "-Subject", subject, "-Body", body];
    if (opts.selfTest) args.push("-SelfTest");
    if (opts.autoCloseMs > 0) args.push("-AutoCloseMs", String(opts.autoCloseMs));
  } else {
    command = "sh";
    // the encoded subject keeps the mailto: URL valid on Linux/macOS desktop handlers
    args = [scriptPath, reportPath, manifestPath, resultPath, REPORT_MAIL_TO, subject, encodeURIComponent(subject)];
  }

  const cleanup = () => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  };

  const shell = path.basename(command);
  const child = spawn(command, args, { stdio: "ignore", windowsHide: true, detached: false });
  const finished = new Promise((resolve) => {
    let waited = 0;
    const cap = Math.max(opts.timeoutMs || 0, opts.autoCloseMs || 0, 60000);
    const tick = setInterval(() => {
      waited += 250;
      if (fs.existsSync(resultPath)) {
        clearInterval(tick);
        let result = null;
        try {
          // tolerate a BOM: Windows PowerShell may add one even though the dialog writes ASCII JSON
          result = JSON.parse(fs.readFileSync(resultPath, "utf8").replace(/^\uFEFF/, "").trim());
        } catch {}
        resolve(result);
        return;
      }
      if (waited >= cap) { clearInterval(tick); resolve(null); }
    }, 250);
  });
  child.on("error", () => {});
  const result = await finished;
  cleanup();
  if (!result) {
    return { action: child.exitCode === null ? "pending" : "unavailable", gui: false, shell, note: "the dialog did not report back; no report was sent" };
  }
  const action = result.action || "closed";
  // "unavailable" means the script found no desktop toolkit: that host has no GUI to show.
  return { action, savedTo: result.savedTo || null, gui: action !== "unavailable", shell, at: result.at || null };
}

function makeId(type, sourceWorkspace, name) {
  const slug = String(name || "").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  // Time base + random suffix to avoid same-millisecond collisions for identical type+name.
  const stamp = Date.now().toString(36) + "-" + randomBytes(4).toString("hex");
  return `${type}-${slug || "obj"}-${stamp}`;
}

// ---------- Session store reading (kohane-native) ----------
// A harness keeps its conversation history as one compressed frame per record, so the store can be
// read without a harness library: locate the frame magic, decode frame by frame, and treat a torn
// tail as a fact to report rather than a guess. Everything here is a local read; only `record`
// writes, and it writes into the Library, never into the store.
const ZSTD_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd]);
const ZSTD_AVAILABLE = typeof nodeZlib.zstdDecompressSync === "function";
const SESSION_ARCHIVE_EXT = ".zip";

function sessionsDir() {
  return path.join(dshHome(), "sessions");
}

// Every offset where a zstd frame starts. DSH appends one frame per record, so this is also the
// record index for a live session file.
function zstdFrameOffsets(buf) {
  const offsets = [];
  let i = 0;
  while ((i = buf.indexOf(ZSTD_MAGIC, i)) !== -1) {
    offsets.push(i);
    i += ZSTD_MAGIC.length;
  }
  return offsets;
}

function timezoneInfo() {
  const now = new Date();
  let zone = null;
  try {
    zone = Intl.DateTimeFormat().resolvedOptions().timeZone || null;
  } catch {}
  return {
    zone,
    offsetMinutes: -now.getTimezoneOffset(),
    utc: now.toISOString(),
    local: new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().replace("Z", ""),
  };
}

// Decode a session body into records. A plain-text body is read as JSONL; a compressed body is
// decoded frame by frame. Bounds are always applied: a caller cannot accidentally pull a whole
// history into one answer.
function decodeSessionBuffer(buf, opts = {}) {
  const { firstFrames = 0, lastFrames = 0, maxRecords = 0, maxChars = 0 } = opts;
  const out = { records: [], frames: 0, failed: 0, truncated: false, compressed: false, bytes: buf.length };
  if (!buf || !buf.length) return out;
  let text = "";
  if (buf.length > 4 && buf.subarray(0, 4).equals(ZSTD_MAGIC)) {
    out.compressed = true;
    const offsets = zstdFrameOffsets(buf);
    out.frames = offsets.length;
    let chosen = offsets.map((start, i) => [start, i + 1 < offsets.length ? offsets[i + 1] : buf.length]);
    if (firstFrames > 0) chosen = chosen.slice(0, firstFrames);
    else if (lastFrames > 0) chosen = chosen.slice(-lastFrames);
    // A frame boundary is found by the compression magic, and that same four-byte pattern can occur
    // inside compressed data. So a chunk that will not decode is retried with the following chunk
    // appended before it is counted as torn: the merged range decodes the real frame, and only a
    // frame that still fails is reported as damage.
    const parts = [];
    for (let i = 0; i < chosen.length; i++) {
      const [start] = chosen[i];
      let ok = false;
      for (let j = i; j < chosen.length; j++) {
        const end = j + 1 < chosen.length ? chosen[j + 1][0] : buf.length;
        try {
          parts.push(nodeZlib.zstdDecompressSync(buf.subarray(start, end)).toString("utf8"));
          i = j;
          ok = true;
          break;
        } catch {
          // keep extending the range
        }
      }
      if (!ok) out.failed++;
    }
    text = parts.join("");
    if (out.failed) out.truncated = true;
  } else {
    out.frames = 1;
    text = buf.toString("utf8");
  }
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const s = line.trim();
    if (!s || s[0] !== "{") continue;
    if (maxRecords && out.records.length >= maxRecords) {
      out.truncated = true;
      break;
    }
    try {
      const rec = JSON.parse(s);
      if (maxChars) {
        const size = JSON.stringify(rec).length;
        if (size > maxChars) {
          out.truncated = true;
          out.records.push({ type: rec.type || null, truncated: true, bytes: size });
          continue;
        }
      }
      out.records.push(rec);
    } catch {
      out.failed++;
    }
  }
  return out;
}

function sessionText(value, ceiling) {
  const parts = [];
  const walk = (v) => {
    if (v === null || v === undefined) return;
    if (typeof v === "string") {
      parts.push(v);
      return;
    }
    if (Array.isArray(v)) {
      for (const x of v) walk(x);
      return;
    }
    if (typeof v === "object") {
      for (const k of ["text", "content", "message", "arguments", "detail", "note", "query", "command"]) {
        if (k in v) walk(v[k]);
      }
    }
  };
  walk(value);
  return parts.join(" ").replace(/\s+/g, " ").trim().slice(0, ceiling);
}

function sessionHeader(record) {
  if (!record || typeof record !== "object") return {};
  return {
    id: record.id || null,
    cwd: record.cwd || null,
    createdAt: record.createdAt || null,
    agentPreset: record.agentPreset || null,
    delegationDepth: typeof record.delegationDepth === "number" ? record.delegationDepth : null,
  };
}

// The title is the first human message, which is what a session list is actually scanned for.
function sessionTitle(records, ceiling = 120) {
  for (const rec of records) {
    const isHuman = rec && (rec.type === "user/message" || (rec.data && rec.data.role === "user"));
    if (!isHuman) continue;
    const text = sessionText(rec.data || rec, ceiling);
    if (text) return text.slice(0, ceiling);
  }
  return "";
}

// Live session files and exported archives are different shapes: a directory holding *.jsonl.zstd
// (one subdirectory per session) and archive members with their own paths.
function listSessionSources(dir, maxFiles = 200) {
  const live = [];
  const archives = [];
  const walk = (cur, depth) => {
    if (live.length + archives.length >= maxFiles || depth > 4) return;
    let ents;
    try {
      ents = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of ents) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) {
        walk(full, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      const lower = e.name.toLowerCase();
      if (lower.endsWith(SESSION_ARCHIVE_EXT)) archives.push(full);
      else if (lower.endsWith(".jsonl.zstd") || lower.endsWith(".jsonl") || lower.endsWith(".zstd")) live.push(full);
    }
  };
  walk(dir, 0);
  live.sort();
  archives.sort();
  return { live, archives };
}

// Resolve a caller's target: a file, a directory, an archive, "<archive>#<member>", or a fragment
// of a session id. A fragment is the convenient form - nobody wants to type a full path.
function resolveSessionTarget(target, dir) {
  const root = dir ? path.resolve(dir) : sessionsDir();
  const raw = String(target || "").trim();
  if (!raw) return { ok: false, note: "no target given" };
  const hash = raw.indexOf("#");
  if (hash > 0) {
    const zip = raw.slice(0, hash);
    const member = raw.slice(hash + 1);
    if (fs.existsSync(zip)) return { ok: true, kind: "archive-entry", archive: zip, member };
  }
  const direct = path.isAbsolute(raw) ? raw : path.resolve(root, raw);
  if (fs.existsSync(direct)) {
    let st;
    try {
      st = fs.statSync(direct);
    } catch {
      return { ok: false, note: `unreadable: ${direct}` };
    }
    if (st.isDirectory()) {
      const inner = listSessionSources(direct, 400);
      if (inner.live.length) return { ok: true, kind: "file", file: inner.live[0], note: "directory target: newest-first file chosen" };
      if (inner.archives.length) return { ok: true, kind: "archive", archive: inner.archives[0] };
      return { ok: false, note: `no session file under ${direct}` };
    }
    if (direct.toLowerCase().endsWith(SESSION_ARCHIVE_EXT)) return { ok: true, kind: "archive", archive: direct };
    return { ok: true, kind: "file", file: direct };
  }
  if (!fs.existsSync(root)) return { ok: false, note: `no session store here: ${root}` };
  const needle = raw.toLowerCase();
  const { live, archives } = listSessionSources(root, 4000);
  const hit = live.find((f) => f.toLowerCase().includes(needle));
  if (hit) return { ok: true, kind: "file", file: hit };
  const arch = archives.find((f) => f.toLowerCase().includes(needle));
  if (arch) return { ok: true, kind: "archive", archive: arch };
  return { ok: false, note: `no session matches "${raw}" under ${root}` };
}

// Read the resolved target into records, honouring the frame/record/character windows.
function readSessionTarget(resolved, opts = {}) {
  if (resolved.kind === "archive") {
    let buf;
    try {
      buf = fs.readFileSync(resolved.archive);
    } catch (e) {
      return { ok: false, note: `unreadable archive: ${String(e && e.message || e)}` };
    }
    const members = zipEntryNames(buf, 400).filter((n) => /\.jsonl(\.zstd)?$/i.test(n));
    const wanted = resolved.member ? members.filter((m) => m === resolved.member) : members;
    if (!wanted.length) return { ok: false, note: "no session log inside that archive", members };
    const all = [];
    let frames = 0, failed = 0;
    for (const m of wanted.slice(0, 200)) {
      const body = zipReadEntry(buf, m);
      if (!body) {
        failed++;
        continue;
      }
      const d = decodeSessionBuffer(body, opts);
      frames += d.frames;
      failed += d.failed;
      all.push(...d.records);
    }
    return { ok: true, kind: "archive", archive: resolved.archive, members: wanted, records: all, frames, failed };
  }
  let buf;
  try {
    buf = fs.readFileSync(resolved.file);
  } catch (e) {
    return { ok: false, note: `unreadable session: ${String(e && e.message || e)}` };
  }
  // A tail request only needs the last part of the file; a head request only the first.
  let slice = buf;
  if (opts.lastFrames && !opts.firstFrames && buf.length > 4 && buf.subarray(0, 4).equals(ZSTD_MAGIC)) {
    const offsets = zstdFrameOffsets(buf);
    if (offsets.length > opts.lastFrames) slice = buf.subarray(offsets[offsets.length - opts.lastFrames]);
  } else if (buf.length > 4 * 1024 * 1024) {
    slice = buf.subarray(0, 4 * 1024 * 1024);
  }
  const d = decodeSessionBuffer(slice, opts);
  return { ok: true, kind: "file", file: resolved.file, bytes: buf.length, records: d.records, frames: d.frames, failed: d.failed, truncated: d.truncated, compressed: d.compressed };
}

// A structural view of a session: who it was, when, which record kinds, and one line per message.
// The text itself only appears when the caller asks for content.
function sessionSummary(records, opts = {}) {
  const { content = false, maxChars = 20000, messages = 40 } = opts;
  const header = sessionHeader(records.find((r) => r && r.type === "session") || {});
  const types = new Map();
  const stamps = [];
  for (const rec of records) {
    const t = String((rec && rec.type) || "unknown");
    types.set(t, (types.get(t) || 0) + 1);
    const when = rec && (rec.time || (rec.data && rec.data.time));
    if (typeof when === "number") stamps.push(when);
  }
  const out = {
    header,
    title: sessionTitle(records),
    records: records.length,
    types: [...types.entries()].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count).slice(0, 14),
    timeRange: stamps.length ? { from: new Date(Math.min(...stamps)).toISOString(), to: new Date(Math.max(...stamps)).toISOString() } : null,
  };
  if (content) {
    let budget = maxChars;
    const lines = [];
    for (const rec of records) {
      if (budget <= 0) {
        lines.push({ truncated: true });
        break;
      }
      const role = (rec && rec.type) || "";
      if (!/message$|^user\/|^assistant\//.test(String(role))) continue;
      const text = sessionText((rec && rec.data) || rec, Math.min(600, budget));
      if (!text) continue;
      budget -= text.length;
      lines.push({ type: role, text });
      if (lines.length >= messages) break;
    }
    out.messages = lines;
  }
  return out;
}

// ---------- Index reconciliation (audit / index / verify / review / prune) ----------
// Three different questions, deliberately kept apart: what exists on disk that the Library has never
// recorded (audit), whether what IS recorded still points at something real (verify), and whether a
// sealed record was sealed for a reason anyone judged (review). Only the write-capable forms touch
// the index, and each of them demands an explicit confirmation plus a stated reason.
const HASH_HEAD_TAIL = 64 * 1024;

// Identity of a file: small files are hashed whole; large ones by size plus both ends, so a big
// artifact can still be recognised as changed without reading gigabytes into memory.
function sha256File(file, maxHashBytes = 16 * 1024 * 1024) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile()) return null;
    const h = createHash("sha256");
    if (st.size <= maxHashBytes) {
      h.update(fs.readFileSync(file));
    } else {
      const fd = fs.openSync(file, "r");
      const head = Buffer.alloc(HASH_HEAD_TAIL);
      const tail = Buffer.alloc(HASH_HEAD_TAIL);
      const hn = fs.readSync(fd, head, 0, HASH_HEAD_TAIL, 0);
      const tn = fs.readSync(fd, tail, 0, HASH_HEAD_TAIL, st.size - HASH_HEAD_TAIL);
      fs.closeSync(fd);
      h.update(String(st.size));
      h.update(head.subarray(0, hn));
      h.update(tail.subarray(0, tn));
    }
    return h.digest("hex");
  } catch {
    return null;
  }
}

// A drive root is refused by op=index: an indexer that walks a whole disk is the scan this Library
// exists to replace.
function isDriveRoot(p) {
  const r = path.resolve(p);
  return /^[A-Za-z]:[\\/]?$/.test(r) || r === "/" || r === path.parse(r).root;
}

function walkEntries(dir, opts = {}) {
  const depth = Math.min(Math.max(Number(opts.depth) || 2, 1), 6);
  const maxFiles = Math.min(Math.max(Number(opts.maxFiles) || 200, 1), 2000);
  const includeDirs = !!opts.includeDirs;
  const root = path.resolve(dir);
  const files = [];
  const dirs = [];
  let seen = 0;
  let truncated = false;
  const stack = [[root, 0]];
  while (stack.length) {
    const [cur, d] = stack.pop();
    let ents;
    try {
      ents = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    if (includeDirs && cur !== root) dirs.push(cur);
    for (const e of ents) {
      if (seen >= maxFiles) {
        truncated = true;
        break;
      }
      const full = path.join(cur, e.name);
      if (e.isDirectory()) {
        if (d < depth) stack.push([full, d + 1]);
        continue;
      }
      if (!e.isFile()) continue;
      seen++;
      files.push(full);
    }
    if (truncated) break;
  }
  files.sort();
  dirs.sort();
  return { files, dirs, truncated };
}

// Does this string name something the filesystem can be asked about? A service endpoint, a bare
// host:port or an IP is an ADDRESS, and an address is not a path: verify must not report it as a file
// that disappeared, and prune must never drop it.
function looksLikeFilePath(value) {
  const p = String(value || "").trim();
  if (!p) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(p)) return false;            // scheme://host
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(p)) return false;  // 127.0.0.1:8100
  if (/^[\w.-]+:\d+$/.test(p)) return false;                        // host:port
  if (p.startsWith("\\\\") || p.startsWith("/")) return true;      // UNC or POSIX absolute
  if (/^[A-Za-z]:[\\/]/.test(p)) return true;                        // drive-letter absolute
  return p.includes("/") || p.includes("\\");                        // anything with a separator
}

// A record's address is the path it claims. A sensitive record keeps its payload encrypted and has
// no visible path at all, so it can neither be reconciled nor pruned by path - and must not be.
function recordPath(o) {
  if (!o || o.sensitive || o.sens === 1) return null;
  const p = String(o.path || "").trim();
  return looksLikeFilePath(p) ? p : null;
}

function pathIsInside(file, root) {
  const a = path.resolve(String(file)).toLowerCase();
  const b = path.resolve(String(root)).toLowerCase();
  if (a === b) return true;
  return a.startsWith(b.endsWith(path.sep) ? b : b + path.sep);
}

// A hollow record carries a name and nothing else - what a write bug leaves behind, not a decision.
function isHollowObject(o) {
  return !recordPath(o) && !o.description && !o.summary && !(Array.isArray(o.tags) && o.tags.length) && !o.__content;
}

function indexStatusOf(index) {
  const byType = {};
  const bySource = {};
  let encrypted = 0, reviewed = 0, fingerprinted = 0, withPath = 0, addressOnly = 0, hollow = 0;
  const keys = new Map();
  for (const o of index.objects) {
    byType[o.type] = (byType[o.type] || 0) + 1;
    bySource[o.source] = (bySource[o.source] || 0) + 1;
    if (o.__content && o.__content.sens === 1) encrypted++;
    if (o.review && o.review.decision) reviewed++;
    if (recordPath(o)) withPath++;
    else addressOnly++;
    if (o.fingerprint) fingerprinted++;
    if (isHollowObject(o)) hollow++;
    const k = [o.type, o.name, o.source].join("::");
    keys.set(k, (keys.get(k) || 0) + 1);
  }
  return {
    objects: index.objects.length,
    byType, bySource, encrypted, reviewed, fingerprinted, withPath, addressOnly, hollow,
    duplicates: [...keys.entries()].filter(([, n]) => n > 1).map(([key, count]) => ({ key, count })),
    missingFields: index.objects.filter((o) => !o.id || !o.type || !o.name).map((o) => o.id || "(no id)").slice(0, 20),
    flagsWithoutBlob: index.objects.filter((o) => (o.sensitive || o.sens === 1) && !o.__content).map((o) => o.id).slice(0, 20),
  };
}

// The last disk-side findings, read back from the append-only log instead of walking the disk again.
function lastDiskFindings(limit = 6) {
  const out = [];
  try {
    const file = path.join(libraryDir(), "log.jsonl");
    if (!fs.existsSync(file)) return out;
    const lines = fs.readFileSync(file, "utf8").trim().split("\n").reverse();
    for (const line of lines) {
      let rec;
      try {
        rec = JSON.parse(line);
      } catch {
        continue;
      }
      if (!rec || !rec.op || !/audit|verify|prune|review|index/.test(rec.op)) continue;
      out.push({ at: rec.at || rec.time || rec.ts || null, op: rec.op, detail: String(rec.detail || "").slice(0, 160) });
      if (out.length >= limit) break;
    }
  } catch {}
  return out;
}

// Which of this object's fields made a sensitivity pattern fire (used by op=review what=candidates).
function sensitivityHits(obj) {
  const hay = [obj.name, obj.path, obj.description, obj.summary, (obj.tags || []).join(" "), obj.source].join(" ").toLowerCase();
  return SENSITIVE_PATTERNS.filter((p) => {
    const re = p instanceof RegExp ? p : new RegExp(String(p), "i");
    return re.test(hay);
  }).map((p) => String(p));
}

// ---------- Model-facing tools (shared across DSH / MCP / CLI) ----------



// A JSON-schema definition of each tool's input, matching the DSH parameters but expressed
// as an MCP JSON Schema (object + properties + required). Kept here so every entry point
// describes the tools consistently.
const TOOL_INPUT_SCHEMAS = {
  library_record: {
    type: "object",
    properties: {
      type: { type: "string", description: "Object type: tool|plugin|env|file|product|knowledge|persona|image|document|table|audio|work_record|log|workspace|reference|other" },
      name: { type: "string", description: "Object name, e.g. 'game-drive.ps1' / 'llm_toolkit_api' / 'daily report'" },
      source: { type: "string", description: "Source workspace/directory, e.g. 'D:\\projects\\demo' or '/home/user/projects/demo'" },
      path: { type: "string", description: "Absolute path of the object (tool/file/directory); for env/port, an address" },
      description: { type: "string", description: "One-line purpose/description" },
      tags: { type: "array", items: { type: "string" }, description: "Tags such as workspace/tool/python/sdk/game/vtuber/summary (used for retrieval filtering)" },
      summary: { type: "string", description: "Extra structured summary (may be multiline)" },
      links: { type: "array", items: { type: "string" }, description: "Cross-object links: object ids or 'type:name:source' keys to associate; stored as the object's related list" },
    },
    required: ["type", "name", "source"],
  },
  library_index: {
    type: "object",
    properties: {
      op: { type: "string", description: "rebuild (default) | status | audit | index | verify | review | prune | rotate" },
      dir: { type: "string", description: "audit/index: directory to reconcile or register; a drive root is refused by index" },
      depth: { type: "number", description: "audit/index: how many levels below dir to walk; default 2, max 6" },
      maxFiles: { type: "number", description: "audit/index: entry ceiling; default 200, max 2000" },
      includeDirs: { type: "boolean", description: "index: also register directories (as workspace records); default false" },
      type: { type: "string", description: "index: force one object type; default file" },
      what: { type: "string", description: "review: sealed | candidates | (omit to list reviewed records); prune: dead | hollow | leads (default dead)" },
      id: { type: "string", description: "review: the object to act on" },
      decision: { type: "string", description: "review: clear (make one encrypted body readable) | revoke (put the rule back)" },
      reason: { type: "string", description: "review/index: what the judgement was for; required by review and recorded in the append-only log" },
      after: { type: "string", description: "verify: cursor - the id of the last object checked; the next call continues after it" },
      maxHashBytes: { type: "number", description: "verify: up to this size a file is hashed whole, above it by size plus head and tail; default 16 MiB" },
      budgetMs: { type: "number", description: "verify: time budget for this slice; default 20000, max 600000" },
      confirm: { type: "boolean", description: "index/verify/prune: required by index and prune; for verify it records the observed fingerprints" },
    },
    additionalProperties: false,
    required: [],
  },
  library_query: {
    type: "object",
    properties: {
      query: { type: "string", description: "Free-text keyword, e.g. 'ffmpeg' / 'game automation' / 'vtuber daily'" },
      type: { type: "string", description: "Filter by type: tool|plugin|env|file|product|knowledge|persona|image|document|table|audio|work_record|log|workspace|reference|other" },
      tags: { type: "array", items: { type: "string" }, description: "Filter by tags, e.g. ['game'] or ['python','sdk']" },
      limit: { type: "number", description: "Max results, default 20, max 100" },
      cursor: { type: "string", description: "Pagination cursor: pass the previous nextCursor to continue (stream/batch)" },
      pageSize: { type: "number", description: "Page size with cursor: return this many per page (defaults to limit)" },
    },
    required: [],
  },
  library_detect: {
      "type": "object",
      "properties": {
          "op": {
              "type": "string",
              "description": "scan (default) | list | add | remove | propose"
          },
          "force": {
              "type": "boolean",
              "description": "scan: re-register even if already present; default skips already-registered items"
          },
          "cross": {
              "type": "boolean",
              "description": "scan: cross-check scanned items against known objects; list items not yet in the Library"
          },
          "type": {
              "type": "string",
              "description": "add: tool | env"
          },
          "name": {
              "type": "string",
              "description": "add/remove: candidate name"
          },
          "path": {
              "type": "string",
              "description": "add: absolute path (or a URL for a service env)"
          },
          "alts": {
              "type": "array",
              "items": {
                  "type": "string"
              },
              "description": "add: alternative paths across platforms (optional)"
          },
          "desc": {
              "type": "string",
              "description": "add: what the tool/env is for"
          },
          "dir": {
              "type": "string",
              "description": "propose: directory to look for executables/scripts"
          },
          "maxFiles": {
              "type": "number",
              "description": "propose: max files to inspect; default 500"
          },
          "confirm": {
              "type": "boolean",
              "description": "add: proceed despite a collision with a built-in candidate"
          }
      },
      "additionalProperties": false
  },
  library_vcs: {
    type: "object",
    properties: {
      op: { type: "string", description: "status (default) | decorate | repo | info" },
      path: { type: "string", description: "status/repo: the file or directory to ask about" },
      dir: { type: "string", description: "repo: a directory inside the repository (same as path)" },
      paths: { type: "array", items: { type: "string" }, description: "decorate: the paths to decorate in one call" },
      fresh: { type: "boolean", description: "bypass the per-repository cache (default false; the cache lives 2 seconds)" },
    },
    required: ["op"],
    additionalProperties: false,
  },

  library_audio: {
    type: "object",
    properties: {
      op: { type: "string", description: "peaks (default) | capabilities | export | pcm | play | score | sweep | info" },
      path: { type: "string", description: "peaks: one audio file to measure (WAV or AIFF, PCM)" },
      dir: { type: "string", description: "sweep: a directory to walk for audio files" },
      buckets: { type: "number", description: "how many min/max buckets to return; default 512, max 20000" },
      threads: { type: "number", description: "sweep: how many cores to use; defaults to the machine, and KOHANE_THREADS overrides it" },
      compare: { type: "boolean", description: "sweep: also run the same work on one core and report the speed-up" },
      maxFiles: { type: "number", description: "sweep: cap on files inspected; default 500, max 5000" },
    },
    required: ["op"],
    additionalProperties: false,
  },

  library_sniff: {
      "type": "object",
      "properties": {
          "path": {
              "type": "string",
              "description": "Absolute path of one file to identify"
          },
          "dir": {
              "type": "string",
              "description": "Directory to sweep for mismatches (alternative to path)"
          },
          "maxFiles": {
              "type": "number",
              "description": "Max files inspected in dir mode; default 500"
          },
          "deep": {
              "type": "boolean",
              "description": "Recurse into subdirectories in dir mode; default true"
          }
      },
      "additionalProperties": false
  },
  library_format: {
      "type": "object",
      "properties": {
          "op": {
              "type": "string",
              "description": "list | scan | learn | add | remove | analyzer-add | analyzer-remove | draft | deps | report | deliver | unseal"
          },
          "dir": {
              "type": "string",
              "description": "scan/report: directory to inspect"
          },
          "maxFiles": {
              "type": "number",
              "description": "scan/report: max files to inspect; default 1000 (scan) / 1500 (report)"
          },
          "out": {
              "type": "string",
              "description": "draft/report: output path; defaults to $DSH_HOME/library/reports[/drafts]/<kind>-<timestamp>.zip|json"
          },
          "draft": {
              "type": "string",
              "description": "report: draft id or path to build the archive from (only the items you select)"
          },
          "include": {
              "type": "array",
              "items": {
                  "type": "string"
              },
              "description": "report: item ids from the draft to include (e.g. [\"f1\",\"f3\"]); \"all\" or includeAll:true for every item"
          },
          "includeAll": {
              "type": "boolean",
              "description": "report: include every item of the draft"
          },
          "pathDetail": {
              "type": "string",
              "description": "draft/report: user-level path detail - none (default, no paths at all) | dirs (sanitised directory names) | full (sanitised paths)"
          },
          "depth": {
              "type": "number",
              "description": "draft/report: directory depth kept in dirs mode; default 3"
          },
          "excludeDir": {
              "type": "array",
              "items": {
                  "type": "string"
              },
              "description": "draft/report: literal strings to replace with <excluded> in any path"
          },
          "deps": {
              "type": "boolean",
              "description": "report: collect format->format relationships; default true"
          },
          "names": {
              "type": "boolean",
              "description": "deps/report: include imported DLL names (treated as user-level, sealable); default false"
          },
          "seal": {
              "type": "string",
              "description": "report: passphrase to seal the user-level fields (paths, DLL names) with AES-256-GCM - you keep the passphrase and can reopen it locally with op=unseal"
          },
          "passphrase": {
              "type": "string",
              "description": "unseal: the passphrase used when sealing"
          },
          "file": {
              "type": "string",
              "description": "deliver: the report archive to show (defaults to the newest one); unseal: the archive containing a sealed layer"
          },
          "ui": {
              "type": "boolean",
              "description": "report: after writing the archive, show it in the platform's own dialog so the user decides (mail / save / open / delete); never an automatic send"
          },
          "headless": {
              "type": "boolean",
              "description": "report/deliver: skip the dialog and return manual delivery instructions instead (servers, SSH, no GUI)"
          },
          "autoCloseMs": {
              "type": "number",
              "description": "report/deliver: close the dialog automatically after N ms (0 = wait for the user)"
          },
          "selfTest": {
              "type": "boolean",
              "description": "deliver: open the dialog and close it after ~1.5 s to verify that the window works on this host"
          },
          "keepLocal": {
              "type": "boolean",
              "description": "draft: also keep the RAW unredacted context locally as an encrypted Library object (open with library_decrypt)"
          },
          "ext": {
              "type": "string",
              "description": "learn/add/remove: file extension without the dot"
          },
          "paths": {
              "type": "array",
              "items": {
                  "type": "string"
              },
              "description": "learn: sample file paths of that type (2+ recommended; headers are intersected)"
          },
          "bytes": {
              "type": "number",
              "description": "learn: how many leading bytes of the intersected prefix to store; default 8 (drops version/build fields), min 2 max 16"
          },
          "format": {
              "type": "string",
              "description": "learn/add: format name to register (defaults to the extension)"
          },
          "type": {
              "type": "string",
              "description": "learn/add: family - document|image|audio|video|archive|executable|database|font|model"
          },
          "sig": {
              "type": "string",
              "description": "add: magic bytes as hex, e.g. \"50 4f 43 50\""
          },
          "textExtension": {
              "type": "string",
              "description": "add: register a plain-text extension instead (e.g. myext)"
          },
          "nameRule": {
              "type": "string",
              "description": "add: regex matched against name/path, defining a local artifact role"
          },
          "role": {
              "type": "string",
              "description": "add: role name used with nameRule"
          },
          "expect": {
              "type": "string",
              "description": "add: expected family for nameRule (enables mismatch checks on it)"
          },
          "note": {
              "type": "string",
              "description": "learn/add: short human note"
          },
          "confirm": {
              "type": "boolean",
              "description": "learn/add: proceed despite a built-in conflict or an unusually short signature"
          },
          "name": {
              "type": "string",
              "description": "analyzer-add/analyzer-remove: analyzer name (re-registering the same name replaces it)"
          },
          "exe": {
              "type": "string",
              "description": "analyzer-add: external command to invoke (absolute path, or a bare name resolved on PATH)"
          },
          "exts": {
              "type": "array",
              "items": {
                  "type": "string"
              },
              "description": "analyzer-add: file extensions this analyzer claims, e.g. [\"foo\",\"bar\"] (without dots)"
          },
          "matchName": {
              "type": "string",
              "description": "analyzer-add: regex matched against the file name - an alternative or addition to exts"
          },
          "args": {
              "type": "array",
              "items": {
                  "type": "string"
              },
              "description": "analyzer-add: argv template; every {path} is replaced with the target path"
          },
          "parse": {
              "type": "string",
              "description": "analyzer-add: json (stdout parsed into fields.data) | text (raw stdout into fields.text); default json"
          },
          "timeoutMs": {
              "type": "number",
              "description": "analyzer-add: command timeout in ms; default 30000 (clamped 1000-300000)"
          },
          "kind": {
              "type": "string",
              "description": "analyzer-add: the kind analyze_object reports for it; defaults to the analyzer name"
          }
      },
      "additionalProperties": false,
      "required": [
          "op"
      ]
  },

  library_decrypt: {
    type: "object",
    properties: {
      id: { type: "string", description: "Object id to decrypt (the id of a sensitive item from library_query)" },
    },
    required: ["id"],
  },
  library_export: {
    type: "object",
    properties: {
      format: { type: "string", description: "json | ndjson; default json" },
      path: { type: "string", description: "Absolute export target path; defaults to the library directory" },
    },
    required: [],
  },
  library_encoding: { type: "object", properties: {}, required: [] },
  library_adb: {
    type: "object",
    properties: {
      action: { type: "string", description: "Operation: devices|restart-server|reboot|reboot-recovery|reboot-bootloader|shell|info-system|info-cpu|info-memory|device-details|bugreport|install|uninstall|list-packages|logcat|push|pull|launch|screenshot|screenrecord|root-check|remote-connect" },
      device: { type: "string", description: "Device serial (from 'devices'); omit for single device" },
      command: { type: "string", description: "Shell command to run on device (action=shell)" },
      package: { type: "string", description: "Package name (action=install/uninstall/launch)" },
      apk: { type: "string", description: "Local APK path (action=install)" },
      local: { type: "string", description: "Local file/folder path (action=push/pull; also screenshot/screenrecord output)" },
      remote: { type: "string", description: "Device path (action=push/pull)" },
      target: { type: "string", description: "ip:port to connect (action=remote-connect)" },
      lines: { type: "number", description: "Logcat line count (default 100)" },
      seconds: { type: "number", description: "Screenrecord duration seconds (default 10, max 180)" },
      record: { type: "boolean", description: "When true, record this operation into the Library as a work_record" },
    },
    required: ["action"],
  },
  library_plugin: {
    type: "object",
    properties: {
      op: { type: "string", description: "list | show | roles | unlinked | numbered | scan | discover | learn | add | remove | rename | brand | provenance | export | export-links | import-links" },
      dir: { type: "string", description: "scan/learn: native plugin database directory; auto-detected when omitted" },
      roots: { type: "array", items: { type: "string" }, description: "discover/learn: plugin folders to inspect; defaults to the platform's VST3/CLAP/VST2 locations plus KOHANE_PLUGIN_ROOTS" },
      binaries: { type: "boolean", description: "learn: also walk the machine's plugin folders; default true" },
      target: { description: "show/remove/rename/provenance: an entry id or Kohane name; rename also accepts an array to rename several at once", oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }] },
      passphrase: { type: "string", description: "export-links/import-links: seal or open the link file with this passphrase" },
      capability: { type: "string", description: "add: the functional word of the new capability (e.g. \"Maximizer\")" },
      function: { type: "string", description: "add/rename: the functional word that follows the brand (Filter -> \"Kohane Bassline Filter\"); a batch rename may contain {n}, replaced by the target's position" },
      name: { type: "string", description: "rename: an explicit replacement name that wins over brand + function" },
      role: { type: "string", description: "add: one of the role taxonomy values (see op=roles)" },
      brand: { type: "string", description: "brand: the family name; omit to read the current one (default \"Kohane Bassline\")" },
      query: { type: "string", description: "list: keyword filter over the Kohane name, functional word and role" },
      limit: { type: "number", description: "list: max entries returned; default 100 (max 400)" },
      maxFiles: { type: "number", description: "scan/discover/learn: max files inspected; default 600 (max 5000)" },
      path: { type: "string", description: "export: output path; defaults to $DSH_HOME/library/plugins.<format>" },
      format: { type: "string", description: "export: json | ndjson | md; default json" },
      note: { type: "string", description: "add/rename: a short note kept with the entry" },
      confirm: { type: "boolean", description: "rename/add: proceed despite a name collision" },
      detail: { type: "boolean", description: "scan/discover/learn: also report the local locations that were inspected (omitted by default, so no location detail leaves the tool)" },
    },
    additionalProperties: false,
    required: ["op"],
  },
  library_sessions: {
    type: "object",
    properties: {
      op: { type: "string", description: "list (default) | read | tail | search | record | status" },
      target: { type: "string", description: "read/tail/record: a session file or directory, a ZIP archive, \"<zip>#<member>\", or a fragment of a session id" },
      dir: { type: "string", description: "list/search: directory to walk; default $DSH_HOME/sessions" },
      query: { type: "string", description: "search: the phrase to look for (case-insensitive)" },
      content: { type: "boolean", description: "read/record: include the message text, not only the structure; default false for read, true for record" },
      maxFiles: { type: "number", description: "list/search: how many sessions to look at; default 200 (list) / 40 (search), max 4000" },
      maxRecords: { type: "number", description: "read/tail: record ceiling; default 2000 (read) / 200 (tail), max 200000" },
      maxChars: { type: "number", description: "read/record: character ceiling for returned or recorded text; default 20000 (read) / 4000 (record), max 400000" },
      maxHits: { type: "number", description: "search: how many matches to return; default 40, max 500" },
      frames: { type: "number", description: "tail: how many trailing frames to decode; default 40, max 2000" },
      titles: { type: "boolean", description: "list: also read each session's title from its first records; default true" },
      type: { type: "string", description: "record: object type for the recorded session; default log" },
    },
    additionalProperties: false,
    required: ["op"],
  },
};

// TOOLS: the model-facing tools as plain async functions, each entry = { name, description, inputSchema, execute(args) }.
// The execute bodies are extracted verbatim from lib/index.js (defineTool.execute). Every harness
// (DSH, MCP, CLI) calls these same execute functions, so behavior is identical everywhere.
const TOOLS = [
  {
    name: "library_record",
    description:
      "Record a valuable object (tool, file, environment, product, knowledge, work record, etc.) encountered during work into the cross-workspace Library. Examples: an executable tool found in a workspace, a path/port/service in use, a produced file, a research conclusion or work record. Record one object per call; source and type are required.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_record,
    async execute(args) {
      if (!OBJ_TYPES.has(args.type)) {
        throw new Error(`library_record: invalid type "${args.type}", allowed: ${[...OBJ_TYPES].join(", ")}`);
      }
      if (!args.name || !args.source) {
        throw new Error("library_record: name and source are required");
      }
      const index = loadIndex();
      const name = clampField(args.name, "name");
      const source = clampField(args.source, "source");
      const path = clampField(args.path || "", "path");
      const description = clampField(args.description || "", "description");
      const tags = (args.tags || []).filter((t) => typeof t === "string");
      const summary = clampField(args.summary || "", "summary");
      const related = (args.links || []).filter((l) => typeof l === "string");

      // Change detection: find the same-key existing object (type+name+source). A sensitive
      // object is stored as an encrypted meta, so decrypt it before fingerprinting, otherwise
      // comparison would be wrong (sensitive objects would be repeatedly misjudged as changed).
      // Anchor change detection on the LATEST same-key object, not the first match. The
      // verify-type changed path appends a fresh version (index.harness consolidates versions),
      // so the first match can be a stale prior version - comparing against it would make every
      // subsequent call look "changed" and duplicate endlessly.
      const sameKey = index.objects.filter(
        (o) => o.type === args.type && o.name === name && o.source === source
      );
      const rawExisting = sameKey.length
        ? sameKey.reduce((a, b) => (String((b.createdAt || "")).localeCompare(String((a.createdAt || ""))) > 0 ? b : a))
        : null;
      const existing = rawExisting && rawExisting.__content
        ? decryptSensitive(rawExisting.__content)
        : rawExisting;
      const newFp = fingerprint({ path, description, summary, tags, related });
      const disposition = dispositionFor(args.type);

      if (existing && fingerprintObject(rawExisting) !== newFp) {
        // Content changed -> route by type.
        if (disposition === "verify") {
          // Auto-verifiable (tool/plugin/env): record the change, notify DSH to check and report to the user.
          const obj = {
            id: makeId(args.type, source, name),
            type: args.type,
            name,
            source,
            path,
            description,
            tags,
            summary,
            related,
            createdAt: new Date().toISOString(),
            changedAt: new Date().toISOString(),
          };
          const sens = commitRecord(index, obj, disposition, "content changed, recorded and notify DSH to check");
          return {
            id: obj.id,
            ok: true,
            count: index.objects.length,
            changed: true,
            disposition: "verify",
            message: `"${name}" differs from the last indexed result; a new version was recorded${sens ? " (sensitive content detected, stored encrypted)" : ""}. Please have DSH check the object's actual state (path/service/version consistency) and report the result to the user.`,
          };
        }
        // Immutable-file class: do not auto-overwrite; force user confirmation.
        // [1] Media evidence: for media-type immutable files, probe metadata via silent
        // ffprobe/MediaInfo and attach the evidence for the user to judge.
        const MEDIA_TYPES = new Set(["image", "audio", "video", "document", "file"]);
        let mediaNote = "";
        if (MEDIA_TYPES.has(args.type) && path) {
          const mf = await mediaFingerprint(path);
          if (mf.ok) mediaNote = `\nMedia evidence: ${mf.detail}`;
          else mediaNote = `\nMedia evidence: unavailable (${mf.detail})`;
        }
        appendLog({ op: "record", type: args.type, name, source, disposition, detail: "content changed, awaiting user confirmation" + (mediaNote ? " (with media evidence)" : "") });
        return {
          id: rawExisting.id,
          ok: false,
          count: index.objects.length,
          changed: true,
          disposition: "confirm",
          message: `"${name}" differs from the last indexed result (immutable-file class). Not auto-overwriting; the user must confirm the change or explain it before it is written/discarded.${mediaNote}Report the judgment to the user.`,
        };
      }

      // Unchanged or first record.
      if (existing) {
        // Already exists and unchanged -> do not rewrite or duplicate; just return.
        appendLog({ op: "record", type: args.type, name, source, disposition, detail: "unchanged (not re-recorded)" });
        return { id: rawExisting.id, ok: true, count: index.objects.length, changed: false, disposition, sensitive: !!(rawExisting && rawExisting.__content) };
      }
      // First record: write.
      const obj = {
        id: makeId(args.type, source, name),
        type: args.type,
        name,
        source,
        path,
        description,
        tags,
        summary,
        related,
        createdAt: new Date().toISOString(),
      };
      const sens = commitRecord(index, obj, disposition, "first record");
      return { id: obj.id, ok: true, count: index.objects.length, changed: false, disposition, sensitive: sens };
    },
  },
  {
    name: "library_index",
    description:
      "Three jobs on the Library index, kept apart on purpose. op=rebuild (default) dedupes by type+name+source, sorts by createdAt and rewrites index.json - the newest version of a key survives and the dropped ones are reported, so a rebuild never rolls a record back. op=audit dir=<path> reconciles a directory against the Library in both directions - entries on disk with no record, and records under that root whose path no longer exists (recorded is not the same as addressable) - and writes nothing. op=index dir=<path> confirm=true registers the missing entries, bounded by depth and an entry ceiling, with an optional type; a drive root is refused and a sensitive name is skipped rather than bulk-encrypted. op=verify recomputes a sha256 for every record that points at a regular file and reports unchanged / changed / gone / never fingerprinted - read-only unless confirm:true also records the observed fingerprints (that is how a baseline is established), with a time budget and an after cursor so a large Library walks in slices. op=review answers whether a sealed record was sealed for a reason anyone judged: what=sealed lists the encrypted records with no review marker, what=candidates lists what the current patterns would seal among the records readable right now, and with id + decision (clear|revoke) + reason it either makes one encrypted body readable or puts the rule back - per object, never by name or pattern, always logged, and a cleared record carries the review that let it through. op=prune confirm=true drops records: what=dead (the recorded path no longer exists), what=hollow (a name and nothing else - what a write bug leaves behind), or what=leads (this Library keeps no derived lead rows, so it reports that there is nothing to tighten). op=status answers what the Library holds in one read-only read - counts by type and source, encrypted and reviewed records, fingerprint coverage, recorded paths versus addresses, internal consistency - and repeats the last disk-side findings from the append-only log instead of walking the disk again.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_index,
    async execute(args = {}) {
      const op = String(args.op || "rebuild").toLowerCase();
      const index = loadIndex();

      if (op === "status") {
        return { ok: true, op, store: indexFile(), generatedAt: index.generatedAt || null, ...indexStatusOf(index), lastFindings: lastDiskFindings(), note: "read-only: nothing was written" };
      }

      if (op === "audit") {
        if (!args.dir) return { ok: false, op, note: "audit needs dir", wroteNothing: true };
        const dir = path.resolve(String(args.dir));
        let isDir = false;
        try {
          isDir = fs.statSync(dir).isDirectory();
        } catch {}
        if (!isDir) return { ok: false, op, dir, note: "dir is not a directory", wroteNothing: true };
        const walk = walkEntries(dir, args);
        const recorded = new Map();
        for (const o of index.objects) {
          const p = recordPath(o);
          if (p && pathIsInside(p, dir)) recorded.set(path.resolve(p).toLowerCase(), o);
        }
        const unrecorded = walk.files.filter((f) => !recorded.has(path.resolve(f).toLowerCase()));
        const missing = [...recorded.values()].filter((o) => !fs.existsSync(recordPath(o)));
        appendLog({ op: "audit", type: null, name: null, source: dir, disposition: null, detail: `audit ${dir}: ${walk.files.length} file(s) on disk, ${recorded.size} record(s) under it, ${unrecorded.length} unrecorded, ${missing.length} missing` });
        return {
          ok: true, op, dir, scanned: walk.files.length, truncated: walk.truncated,
          recordedUnderRoot: recorded.size, unrecorded: unrecorded.length, missing: missing.length,
          unrecordedSamples: unrecorded.slice(0, 20),
          missingSamples: missing.slice(0, 20).map((o) => ({ id: o.id, name: o.name, path: recordPath(o) })),
          wroteNothing: true,
          note: "read-only reconciliation: nothing was written, and a record whose file merely moved is reported as missing rather than silently dropped",
        };
      }

      if (op === "index") {
        if (!args.dir) return { ok: false, op, note: "index needs dir" };
        const dir = path.resolve(String(args.dir));
        if (isDriveRoot(dir)) return { ok: false, op, dir, note: "refusing a drive root: an indexer that walks a whole disk is the scan this Library exists to replace" };
        if (!args.confirm) return { ok: false, op, dir, note: "index needs confirm:true - it writes a record for every entry it finds" };
        let isDir = false;
        try {
          isDir = fs.statSync(dir).isDirectory();
        } catch {}
        if (!isDir) return { ok: false, op, dir, note: "dir is not a directory" };
        const type = String(args.type || "file");
        if (!OBJ_TYPES.has(type)) return { ok: false, op, note: `index: invalid type "${type}", allowed: ${[...OBJ_TYPES].join(", ")}` };
        const walk = walkEntries(dir, args);
        const known = new Set(index.objects.map((o) => recordPath(o)).filter(Boolean).map((p) => path.resolve(p).toLowerCase()));
        let added = 0, skippedSensitive = 0;
        for (const file of walk.files) {
          if (known.has(path.resolve(file).toLowerCase())) continue;
          const name = path.basename(file);
          // The sensitive rule is applied per entry: a sensitive name is skipped, never
          // bulk-encrypted - registering a secret is a decision, not a side effect of indexing.
          if (isSensitive({ name, path: file, source: dir, description: "", tags: [] })) {
            skippedSensitive++;
            continue;
          }
          const obj = {
            id: makeId(type, dir, name), type, name, source: dir, path: file,
            description: `indexed from ${dir}`, tags: ["indexed"],
            summary: args.reason ? `indexed (${String(args.reason).slice(0, 120)})` : "", related: [],
            createdAt: new Date().toISOString(),
          };
          const hash = sha256File(file);
          if (hash) obj.fingerprint = `sha256:${hash}`;
          storeObject(index, obj);
          added++;
        }
        index.generatedAt = new Date().toISOString();
        saveIndex(index);
        appendLog({ op: "index", type: null, name: null, source: dir, disposition: null, detail: `indexed ${dir}: +${added} record(s), ${skippedSensitive} sensitive name(s) skipped` });
        return { ok: true, op, dir, scanned: walk.files.length, truncated: walk.truncated, added, skippedSensitive, count: index.objects.length, reason: args.reason ? String(args.reason).slice(0, 160) : null, note: "a sensitive name is skipped by design and never sealed in bulk" };
      }

      if (op === "rotate") {
        // The default is a report: the caller sees what would happen, where the backup would go and
        // how many sealed records are involved. Nothing is written until confirm is given.
        const sealedCount = index.objects.filter((o) => o && o.__content && o.__content.sens === 1).length;
        if (args.confirm !== true) {
          return {
            ok: true, op, dryRun: true, sealedCount,
            wouldBackup: [".library.master", ".library.key", "index.json"].filter((n) => fs.existsSync(path.join(libraryDir(), n))),
            newMaster: args.newMaster === true,
            note: "nothing was written: pass confirm:true to rotate. A rotation backs the key files and the index up first, re-seals every sensitive record, and then proves each one opens again.",
          };
        }
        try {
          const result = rotateLibraryKeys(index, { newMaster: args.newMaster === true });
          saveIndex(index);
          appendLog({ kind: "rotate", at: new Date().toISOString(), sealed: result.sealed, resealed: result.resealed, reopened: result.reopened, backupDir: result.backupDir, newMaster: result.masterSecretReplaced });
          return Object.assign({ ok: true, op, dryRun: false }, result, {
            note: result.refusedAfter.length
              ? "some records could not be reopened after rotation: they are listed, and the originals are in the backup"
              : "every sealed record opens under the new key; the pre-rotation state is in the backup directory",
          });
        } catch (e) {
          return { ok: false, op, note: String((e && e.message) || e) };
        }
      }

      if (op === "verify") {
        const maxHashBytes = Math.min(Math.max(Number(args.maxHashBytes) || 16 * 1024 * 1024, 64 * 1024), 1024 * 1024 * 1024);
        const budgetMs = Math.min(Math.max(Number(args.budgetMs) || 20000, 200), 600000);
        const started = Date.now();
        const list = index.objects.filter((o) => recordPath(o));
        const startAt = args.after ? list.findIndex((o) => o.id === String(args.after)) + 1 : 0;
        const unchanged = [], changed = [], gone = [], never = [];
        let processed = 0, lastId = null;
        // Existence is a cheap local check; the hashing - the part that used to leave one core
        // sweating over nine thousand files - goes to the resident pool. The batch bounds one call;
        // the time budget is honoured between batches.
        const batch = Math.min(Math.max(Number(args.batch) || 400, 20), 5000);
        const slice = list.slice(startAt, startAt + batch);
        const present = [];
        for (const o of slice) {
          const p = recordPath(o);
          if (fs.existsSync(p)) present.push(o);
          else gone.push({ id: o.id, name: o.name, path: p });
        }
        const hashed = await poolMap(
          present.map((o) => ({ path: recordPath(o), maxBytes: maxHashBytes })),
          "hash",
          { label: "library-verify" },
        );
        present.forEach((o, i) => {
          const p = recordPath(o);
          const digest = hashed.results[i] && hashed.results[i].digest;
          if (!digest) { gone.push({ id: o.id, name: o.name, path: p }); return; }
          const hash = `sha256:${digest}`;
          if (!o.fingerprint) never.push({ id: o.id, name: o.name, observed: hash });
          else if (o.fingerprint === hash) unchanged.push(o.id);
          else changed.push({ id: o.id, name: o.name, path: p, was: o.fingerprint, now: hash });
        });
        processed = slice.length;
        if (slice.length) lastId = slice[slice.length - 1].id;
        void budgetMs;
        void started;
        const done = startAt + processed >= list.length;
        let recorded = 0;
        if (args.confirm) {
          const byId = new Map(index.objects.map((o) => [o.id, o]));
          for (const row of [...changed, ...never]) {
            const o = byId.get(row.id);
            // A changed row carries the freshly observed hash as `now`; a never-fingerprinted row
            // carries it as `observed`. Both mean the same thing here: this is what the file is.
            const observed = row.now || row.observed;
            if (!o || !observed) continue;
            o.fingerprint = observed;
            recorded++;
          }
          if (recorded) {
            index.generatedAt = new Date().toISOString();
            saveIndex(index);
          }
          appendLog({ op: "verify", type: null, name: null, source: null, disposition: null, detail: `verify: ${unchanged.length} unchanged, ${changed.length} changed, ${gone.length} gone, ${never.length} never fingerprinted${recorded ? `, ${recorded} fingerprint(s) recorded` : ""}` });
        }
        return {
          ok: true, op, checked: processed, total: list.length, cursor: done ? null : lastId,
          unchanged: unchanged.length, changed: changed.length, gone: gone.length, neverFingerprinted: never.length,
          changedSamples: changed.slice(0, 10), goneSamples: gone.slice(0, 10), neverSamples: never.slice(0, 5),
          recorded: args.confirm ? recorded : 0, wroteNothing: !args.confirm,
          note: args.confirm
            ? `observed fingerprints recorded for ${recorded} record(s); a baseline now exists for them`
            : "read-only: pass confirm:true to record the observed fingerprints, which is how a baseline is established",
        };
      }

      if (op === "review") {
        const what = String(args.what || "").toLowerCase();
        if (what === "sealed") {
          const sealed = index.objects.filter((o) => o.__content && o.__content.sens === 1 && !(o.review && o.review.decision));
          return { ok: true, op, what, sealed: sealed.length, entries: sealed.slice(0, 30).map((o) => ({ id: o.id, type: o.type, name: o.name, source: o.source, createdAt: o.createdAt })), wroteNothing: true, note: "encrypted records nobody has judged yet; settle one with id + decision clear|revoke + reason" };
        }
        if (what === "candidates") {
          const candidates = [];
          for (const o of index.objects) {
            if (o.__content && o.__content.sens === 1) continue;
            const hits = sensitivityHits(o);
            if (hits.length) candidates.push({ id: o.id, type: o.type, name: o.name, patterns: hits.slice(0, 3) });
          }
          return { ok: true, op, what, candidates: candidates.length, entries: candidates.slice(0, 30), wroteNothing: true, note: "what the current patterns would seal among the records readable right now - the check to run after a pattern changes" };
        }
        if (!what && !args.id) {
          const withReview = index.objects.filter((o) => o.review && o.review.decision);
          return { ok: true, op, withReview: withReview.length, entries: withReview.slice(0, 20).map((o) => ({ id: o.id, name: o.name, review: o.review })), note: "pass what=sealed | what=candidates to look, or id + decision + reason to settle one record" };
        }
        const id = String(args.id || "").trim();
        const decision = String(args.decision || "").toLowerCase();
        const reason = String(args.reason || "").trim();
        if (!id || !decision) return { ok: false, op, note: "review needs id + decision (clear|revoke) + reason" };
        if (!reason) return { ok: false, op, note: "review needs reason: the point is that a human judgement is recorded with it" };
        if (!["clear", "revoke"].includes(decision)) return { ok: false, op, note: `unknown decision "${decision}", allowed: clear, revoke` };
        const at = index.objects.findIndex((o) => o.id === id);
        if (at < 0) return { ok: false, op, note: `no object with id ${id}` };
        const o = index.objects[at];
        const marker = { decision, reason: reason.slice(0, 200), at: new Date().toISOString() };
        if (decision === "clear") {
          if (!o.__content) return { ok: false, op, note: `${id} is not an encrypted record; nothing to clear` };
          const plain = decryptSensitive(o.__content);
          if (!plain || plain.__decryptError) return { ok: false, op, note: "decrypt failed (key mismatch or corrupted data)" };
          delete plain.__decryptError;
          index.objects[at] = { ...plain, sensitive: false, reviewedCleared: true, review: marker };
        } else if (o.__content) {
          // Already sealed: putting the rule back means keeping the body and recording the judgement,
          // so the record stops looking like one nobody ever looked at.
          index.objects[at] = { ...o, review: marker };
        } else {
          const { id: oid, review: _previousReview, ...rest } = o;
          index.objects[at] = {
            id: oid, type: o.type, name: o.name, source: o.source, sensitive: true, createdAt: o.createdAt,
            __content: encryptSensitive(rest), review: marker,
          };
        }
        index.generatedAt = new Date().toISOString();
        saveIndex(index);
        appendLog({ op: "review", type: o.type, name: o.name, source: o.source, disposition: null, detail: `review ${decision} on ${id}: ${marker.reason}` });
        return {
          ok: true, op, id, decision, review: marker, count: index.objects.length,
          note: decision === "clear"
            ? "one encrypted body is readable now, and it carries the review that let it through"
            : "the seal stands on that record and the judgement is recorded with it, so it is no longer an unreviewed seal",
        };
      }

      if (op === "prune") {
        const what = String(args.what || "dead").toLowerCase();
        if (!args.confirm) return { ok: false, op, what, note: "prune needs confirm:true - it drops records" };
        if (what === "leads") {
          return { ok: true, op, what, removed: 0, note: "this Library keeps no derived lead rows (there is no mining pass here), so there is nothing to tighten" };
        }
        let doomed = [];
        if (what === "dead") {
          // An address is not a path and a locked file is not a missing one, so only a verifiable
          // ENOENT counts - and a sensitive record has no visible path at all, so it survives.
          doomed = index.objects.filter((o) => {
            const p = recordPath(o);
            if (!p) return false;
            try {
              fs.statSync(p);
              return false;
            } catch (e) {
              return !!(e && e.code === "ENOENT");
            }
          });
        } else if (what === "hollow") {
          doomed = index.objects.filter((o) => isHollowObject(o));
        } else {
          return { ok: false, op, what, note: `unknown what "${what}", allowed: dead, hollow, leads` };
        }
        const ids = new Set(doomed.map((o) => o.id));
        index.objects = index.objects.filter((o) => !ids.has(o.id));
        index.generatedAt = new Date().toISOString();
        saveIndex(index);
        appendLog({ op: "prune", type: null, name: null, source: null, disposition: null, detail: `pruned ${doomed.length} ${what} record(s)` });
        return { ok: true, op, what, removed: doomed.length, count: index.objects.length, samples: doomed.slice(0, 10).map((o) => ({ id: o.id, name: o.name, path: recordPath(o) })), note: what === "dead" ? "only records whose path is verifiably gone were dropped" : "only records carrying a name and nothing else were dropped" };
      }

      if (op !== "rebuild") {
        return { ok: false, op, note: `unknown op "${args.op}", allowed: rebuild, status, audit, index, verify, review, prune, rotate` };
      }

      const byKey = new Map();
      const conflicts = [];
      // Group same-key objects, then keep the LATEST (max createdAt) as the canonical record.
      // Older versions (with differing content) are reported in conflicts, never silently lost.
      for (const o of index.objects) {
        const key = [o.type, o.name, o.source].map((v) => String(v ?? "")).join("::");
        if (!byKey.has(key)) byKey.set(key, []);
        byKey.get(key).push(o);
      }
      const dedup = [];
      for (const [key, arr] of byKey) {
        let latest = arr[0];
        for (const o of arr) {
          if (String((o.createdAt || "")).localeCompare(String((latest.createdAt || ""))) > 0) latest = o;
        }
        for (const o of arr) {
          if (o.id !== latest.id && fingerprintObject(o) !== fingerprintObject(latest)) {
            conflicts.push({ key, kept: latest.id, dropped: o.id });
          }
        }
        dedup.push(latest);
      }
      dedup.sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
      index.objects = dedup;
      index.generatedAt = new Date().toISOString();
      saveIndex(index);
      appendLog({ op: "index", type: null, name: null, source: null, disposition: null, detail: `rebuilt index, ${dedup.length} objects, ${conflicts.length} conflicts` });
      return { count: dedup.length, store: indexFile(), conflicts };
    },
  },
  {
    name: "library_query",
    description:
      "Search recorded objects in the cross-workspace Library. Filter by keyword (matches name/description/summary/source), type, and tags. Used to: let new conversations inherit past records, research/learn what tools a workspace used, and locate a path/service/record.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_query,
    async execute(args) {
      if (args.type && !OBJ_TYPES.has(args.type)) {
        throw new Error(`library_query: invalid type "${args.type}", allowed: ${[...OBJ_TYPES].join(", ")}`);
      }
      const index = loadIndex();
      const q = (args.query || "").toLowerCase().trim();
      const limit = Math.min(Math.max(args.limit || 20, 1), 100);
      let results = index.objects;
      if (args.type && OBJ_TYPES.has(args.type)) {
        results = results.filter((o) => o.type === args.type);
      }
      if (Array.isArray(args.tags) && args.tags.length) {
        const tags = args.tags.map((t) => String(t).toLowerCase());
        results = results.filter((o) => tags.every((t) => (o.tags || []).some((x) => String(x).toLowerCase() === t)));
      }
      if (q) {
        results = results.filter((o) =>
          [o.name, o.description, o.summary, o.source, o.path, (o.tags || []).join(" ")]
            .join(" ")
            .toLowerCase()
            .includes(q)
        );
      }
      // Sensitive objects expose only metadata (sensitive:true + public fields); no auto-decrypt
      // and no leaking of the __content cipher block.
      const safeAll = results
        .map((o) => {
          if (o.sensitive || o.sens === 1) {
            return { id: o.id, type: o.type, name: o.name, source: o.source, sensitive: true, createdAt: o.createdAt };
          }
          const { __content, ...rest } = o;
          return rest;
        })
        .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
      // Pagination cursor: stable-sorted safeAll, offset anchored by "items already fetched".
      const pageSize = Math.min(Math.max(args.pageSize || limit, 1), 100);
      const offset = args.cursor ? parseInt(args.cursor, 10) || 0 : 0;
      const page = safeAll.slice(offset, offset + pageSize);
      const nextCursor = offset + pageSize < safeAll.length ? String(offset + pageSize) : null;
      return { count: safeAll.length, nextCursor, results: page };
    },
  },
  {
    name: "library_detect",
    description: "Scan machine tools/environments/toolchains and register the ones that exist into the Library (bootstraps the index on install/init; never installs anything). Scans the built-in list plus this machine's local candidate pack, so a private toolchain or service recorded once is recognised on every later scan. op=list shows both lists; op=add/remove manage the local pack (built-ins always win, collisions are refused unless confirm:true); op=propose dir=<directory> only *proposes* executables found there for you to decide about. Proposing records nothing and no candidate is ever executed - a path is only recorded and checked for existence.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_detect,
    async execute(args) {
      // An operation this tool does not implement must be refused before any work happens.
      const detectOps = ["scan", "list", "add", "remove", "propose"];
      if (args.op !== undefined && !detectOps.includes(String(args.op).toLowerCase())) {
        return { ok: false, op: String(args.op), note: `unknown op "${args.op}", allowed: scan, list, add, remove, propose` };
      }

      const op = String(args.op || "scan").toLowerCase();
      const file = candidatesFile();
      const pack = loadLocalCandidates();

      if (op === "list") {
        const list = allCandidates();
        return {
          ok: true, op, file, builtin: DETECT_CANDIDATES.length, local: pack.candidates.length,
          candidates: list.map((c) => ({ type: c.type, name: c.name, path: c.path, desc: c.desc, origin: c.origin, shadowed: !!c.shadowed })),
          note: fs.existsSync(file)
            ? `local candidate pack loaded; ${list.filter((c) => c.shadowed).length} local entr(ies) shadowed by built-ins`
            : "no local candidate pack yet (op=add or op=propose create one)",
        };
      }

      if (op === "add") {
        const type = args.type === "env" ? "env" : args.type === "tool" ? "tool" : null;
        if (!type) return { ok: false, op, file, note: 'add needs type: "tool" or "env"' };
        const name = String(args.name || "").trim();
        const p = String(args.path || "").trim();
        if (!name || !p) return { ok: false, op, file, note: "add needs name and path" };
        const conflicts = builtinCandidateConflicts({ type, name });
        if (conflicts.length && !args.confirm) {
          return { ok: false, op, file, conflicts, note: `refused: ${name} is already a built-in candidate - pass confirm:true only if you really want a local duplicate (the built-in still wins during scans)` };
        }
        const next = normalizeCandidatePack(pack);
        next.candidates = next.candidates.filter((c) => !(c.type === type && c.name.toLowerCase() === name.toLowerCase()));
        next.candidates.push({
          type, name, path: p,
          alts: (Array.isArray(args.alts) ? args.alts : []).map(String),
          desc: String(args.desc || "").slice(0, 300),
          createdAt: new Date().toISOString(),
        });
        saveLocalCandidates(next);
        appendLog({ op: "candidate-add", type, name, source: "local", disposition: null, detail: `local candidate recorded (exists now: ${fs.existsSync(p)})` });
        return {
          ok: true, op, file, builtin: DETECT_CANDIDATES.length, local: next.candidates.length, conflicts,
          note: `recorded ${type} ${name}${fs.existsSync(p) ? "" : " (path does not exist yet - scans will skip it until it does)"}`,
        };
      }

      if (op === "remove") {
        const name = String(args.name || "").trim().toLowerCase();
        if (!name) return { ok: false, op, file, note: "remove needs name" };
        const next = normalizeCandidatePack(pack);
        const before = next.candidates.length;
        next.candidates = next.candidates.filter((c) => c.name.toLowerCase() !== name);
        saveLocalCandidates(next);
        return { ok: true, op, file, builtin: DETECT_CANDIDATES.length, local: next.candidates.length, removed: before - next.candidates.length, note: `removed ${before - next.candidates.length} local candidate(s)` };
      }

      if (op === "propose") {
        if (!args.dir) return { ok: false, op, note: "propose needs dir", proposals: [] };
        const proposals = proposeCandidates(args.dir, args.maxFiles || 500).map((g) => ({
          ext: g.ext, count: g.count, dirs: g.dirs,
          samples: g.samples,
          suggested: g.samples.slice(0, 3).map((s) => ({ type: "tool", name: path.basename(s).replace(/\.[^.]+$/, ""), path: s, desc: `found in ${path.dirname(s)}` })),
        }));
        return {
          ok: true, op, file, builtin: DETECT_CANDIDATES.length, local: pack.candidates.length, proposals,
          note: `${proposals.length} executable/script group(s) proposed; nothing was recorded - use op=add for the ones you want`,
        };
      }

      const index = loadIndex();
      const force = !!args.force;
      const results = [];
      const conflicts = [];
      let registered = 0;
      for (const c of allCandidates()) {
        if (c.shadowed) {
          conflicts.push(`${c.type} ${c.name} (local entry shadowed by the built-in of the same name)`);
          continue;
        }
        const resolved = resolveCandidatePath(c);
        const exists = !!resolved;
        results.push({ type: c.type, name: c.name, desc: c.desc, origin: c.origin, path: resolved || c.path, exists });
        if (!exists) continue;
        // Skip if already registered (unless force).
        const dup = index.objects.find((o) => o.type === c.type && o.name === c.name && o.source === "detect");
        if (dup && !force) continue;
        const obj = {
          id: dup ? dup.id : makeId(c.type, "detect", c.name),
          type: c.type,
          name: c.name,
          source: "detect",
          path: resolved,
          description: c.desc,
          tags: ["tool", "env"].includes(c.type) ? [c.type, "detect", c.origin === "local" ? "local" : "builtin"] : ["detect"],
          summary: "",
          createdAt: new Date().toISOString(),
        };
        // Replace old same-key object (force re-scan) or append.
        if (dup) index.objects[index.objects.indexOf(dup)] = obj;
        else index.objects.push(obj);
        registered++;
      }
      index.generatedAt = new Date().toISOString();
      saveIndex(index);
      appendLog({ op: "detect", type: null, name: null, source: "detect", disposition: null, detail: `scan complete, ${registered} existing items to register` });
      // Cross-check against known objects: scanned but not-yet-registered items, to remind the static map.
      const cross = [];
      if (args.cross) {
        const knownKeys = new Set(index.objects.filter((o) => o.source === "detect").map((o) => `${o.type}::${o.name}`));
        for (const c of allCandidates()) {
          if (c.shadowed) continue;
          const resolved = resolveCandidatePath(c);
          if (resolved && !knownKeys.has(`${c.type}::${c.name}`)) {
            cross.push({ type: c.type, name: c.name, path: resolved, origin: c.origin, note: "scanned but not yet registered in Library (consider adding to workspace-map manually)" });
          }
        }
      }
      const found = results.filter((r) => r.exists).length;
      return {
        ok: true, op: "scan", file, builtin: DETECT_CANDIDATES.length, local: pack.candidates.length,
        found, registered, results, cross, conflicts,
        note: `${found} candidate(s) exist (${DETECT_CANDIDATES.length} built-in + ${pack.candidates.length} local), ${registered} to register${conflicts.length ? `, ${conflicts.length} shadowed by built-ins` : ""}`,
      };
    }
  },
  {
    name: "library_sniff",
    description: "Identify a file's true type from magic header bytes, independent of a spoofable extension, and flag name/content contradictions (a file claiming to be JSON/YAML/an image or a DSH artifact whose bytes say otherwise). Pass `path` for one file, or `dir` to sweep a directory (temp/session/storage) for mismatches. Returns {type, format, note, declared, artifact, spoofed, flags}.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_sniff,
    async execute(args) {
      if (args.path) {
        const a = assessFile(args.path);
        return { ...a, ok: true, scanned: 1, mismatches: [] };
      }
      const dir = args.dir;
      if (!dir) return { ok: false, detected: false, type: null, format: null, note: "missing path or dir", spoofed: false, flags: [], scanned: 0, mismatches: [] };
      const max = Math.min(Math.max(args.maxFiles || 500, 1), 5000);
      const deep = args.deep !== false;
      const files = [];
      const walk = (d) => {
        if (files.length >= max) return;
        let ents;
        try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
        for (const e of ents) {
          if (files.length >= max) return;
          const p = path.join(d, e.name);
          if (e.isDirectory()) { if (deep) walk(p); continue; }
          if (e.isFile()) files.push(p);
        }
      };
      walk(dir);
      const mismatches = [];
      for (const f of files) {
        const a = assessFile(f);
        if (a.spoofed) mismatches.push({ path: a.path, declared: a.declared, artifact: a.artifact, type: a.type, format: a.format, flags: a.flags });
      }
      return {
        ok: true, detected: true, type: null, format: null, spoofed: mismatches.length > 0, flags: [],
        note: `${files.length} file(s) inspected${files.length >= max ? ` (capped at ${max})` : ""}, ${mismatches.length} mismatch(es)`,
        scanned: files.length, mismatches,
      };
    }
  },
  {
    name: "library_vcs",
    description: "Read a path's working-tree state the way an editor's source-control view reports it, without writing anything and without touching the network. One git call per repository covers every path inside it, so a whole listing can be decorated cheaply. op=status answers for one file or directory with the decoration an editor would paint: a letter (M/A/D/R/C/T/U/I/!/S), the same state kept as two independent letters (index and worktree), the +N/-M line counts for the unstaged and the staged side separately, the colours an editor's default light and dark themes use for that state, the rename origin, conflict and submodule flags, and - for a directory - the union of everything underneath it. op=decorate takes many paths at once, which is what a list wants. op=repo summarises a repository the way a source-control panel shows it: branch name, upstream, ahead/behind, then staged, changed, untracked, conflicted and submodule entries as separate lists. op=info reports whether git is present here and what the caches hold. A path outside any repository, or a machine without git, is reported as such instead of failing. Read-only throughout: git runs with --no-optional-locks, a short timeout, a hidden window, no pager and no colour.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_vcs,
    async execute(args) {
      const op = String(args.op || "status").toLowerCase();

      if (op === "info") {
        const version = gitVersion();
        return {
          ok: true, op, available: !!version, git: version,
          cachedDirectories: repoRootCache.size, cachedRepositories: repoStatusCache.size,
          cacheTtlMs: VCS_TTL_MS, timeoutMs: GIT_TIMEOUT_MS, maxIgnoredEntries: VCS_MAX_IGNORED,
          note: version
            ? `git ${version} is available; every answer below is a read-only observation`
            : "this machine has no working git, so every path is reported as not being in a repository",
        };
      }

      if (op === "status") {
        if (!args.path) return { ok: false, op, note: "missing path" };
        return Object.assign({ ok: true, op }, decoratePath(args.path, args.fresh === true));
      }

      if (op === "decorate") {
        const list = Array.isArray(args.paths) ? args.paths.filter((p) => typeof p === "string" && p.trim()) : [];
        if (!list.length) return { ok: false, op, note: "missing paths" };
        const capped = list.slice(0, VCS_MAX_DECORATE);
        const items = capped.map((p) => {
          const d = decoratePath(p, args.fresh === true);
          return {
            path: d.path, relative: d.relative ?? null, repo: d.repo, state: d.state,
            letter: d.letter, label: d.label, labelEn: d.labelEn, colors: d.colors,
            staged: !!d.staged, unstaged: !!d.unstaged,
            added: d.added ?? null, deleted: d.deleted ?? null,
            stagedAdded: d.stagedAdded ?? null, stagedDeleted: d.stagedDeleted ?? null,
          };
        });
        const counts = {};
        for (const item of items) counts[item.state] = (counts[item.state] || 0) + 1;
        return { ok: true, op, asked: list.length, returned: items.length, cappedAt: VCS_MAX_DECORATE, counts, items };
      }

      if (op === "repo") {
        const target = args.path || args.dir;
        if (!target) return { ok: false, op, note: "missing path or dir" };
        return Object.assign({ op }, repoSummary(target, args.fresh === true));
      }

      return { ok: false, op, note: `unknown op "${args.op}", allowed: status, decorate, repo, info` };
    }
  },
  {
    name: "library_audio",
    description: "Measure audio the way a waveform display needs it, and spread the work over the machine's cores instead of leaving one of them to sweat. op=peaks reads one PCM WAV or AIFF and returns a min/max envelope (the shape a waveform viewer draws) plus the format facts: channels, sample rate, bit depth, frame count. op=sweep walks a directory and measures every audio file it finds through a worker pool, one repository-sized batch at a time, reporting how many cores it actually used and, with compare:true, what the same work costs on a single core. op=info reports the cores available, the pool's task table and the containers this reader decodes. Compressed formats are not decoded here - the answer says so rather than guessing. Local read only: nothing is written and nothing is uploaded.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_audio,
    async execute(args) {
      const op = String(args.op || "peaks").toLowerCase();
      const buckets = Math.min(Math.max(Number(args.buckets) || 512, 32), AUDIO_MAX_BUCKETS);

      if (op === "info") {
        // A FLAC stream is recognised by its own marker, and summarised from STREAMINFO by the
        // decoder we own (deps/decoders/flac.mjs, registered in the dependency manifest).
        if (args.path) {
          try {
            const head = Buffer.alloc(8);
            const fd = fs.openSync(String(args.path), "r");
            const read = fs.readSync(fd, head, 0, 8, 0);
            fs.closeSync(fd);
            // RIFF covers both AVI movies and WAVE audio: the container description comes from our
            // RIFF reader, while samples keep going through the PCM readers in op=peaks/pcm/play.
            if (read >= 4 && head.toString("latin1", 0, 4) === "RIFF") {
              const rf = readRiff(String(args.path));
              return Object.assign({ ok: true, op, path: args.path, format: "riff" }, rf);
            }
            if (read >= 4 && head.toString("latin1", 0, 4) === "OggS") {
              const og = readOgg(String(args.path));
              return Object.assign({ ok: true, op, path: args.path, format: "ogg" }, og);
            }
            if (read === 8 && head.toString("latin1", 4, 8) === "ftyp") {
              const mp4 = readIsoBmff(String(args.path));
              return Object.assign({ ok: true, op, path: args.path, format: "isobmff" }, mp4);
            }
            if (read === 4 && [0x1a, 0x45, 0xdf, 0xa3].every((b, i) => head[i] === b)) {
              const mk = readMatroska(String(args.path));
              return Object.assign({ ok: true, op, path: args.path, format: "matroska" }, mk);
            }
            if (read === 4 && head.toString("latin1") === "fLaC") {
              return Object.assign({ ok: true, op, path: args.path, format: "flac" }, readFlac(String(args.path)));
            }
          } catch (e) {
            return { ok: false, op, note: "FLAC marker seen but the stream could not be read: " + String((e && e.message) || e) };
          }
        }
        return {
          ok: true, op, cores: availableCores(), reportedCores: (() => { try { return os.cpus().length; } catch { return 1; } })(),
          envOverride: process.env.KOHANE_THREADS || null, tasks: [...KB_WORKER_TASKS],
          decodes: ["RIFF/WAVE PCM (8/16/24/32, float32)", "FORM/AIFF PCM (8/16/24/32)"],
          maxBuckets: AUDIO_MAX_BUCKETS,
          note: "waveforms are measured here; decoding MP3/FLAC/OGG belongs to a media provider",
        };
      }

      if (op === "peaks") {
        if (!args.path) return { ok: false, op, note: "missing path" };
        const measured = readAudioPeaks(args.path, buckets);
        return Object.assign({ op, buckets }, measured);
      }

      if (op === "export") {
        // An export is an export: the file this writes is a third-party container made for other
        // tools to read. Nothing kohane keeps for itself is stored this way - its own containers are
        // the .kb family - and the destination is always named by the caller, because the engine
        // does not assume any machine's directory layout.
        if (!args.path) return { ok: false, op, note: "missing path" };
        if (!args.out) return { ok: false, op, note: "missing out: an export writes where you say, so the destination is required" };
        const asked = String(args.format || "").toLowerCase();
        const out = String(args.out);
        const fromExtension = path.extname(out).replace(/^\./, "").toLowerCase();
        const format = asked || fromExtension;
        if (!["wav", "flac"].includes(format)) {
          return { ok: false, op, note: `unknown export format "${asked || fromExtension || "(none)"}", allowed: wav, flac` };
        }
        try {
          const decoded = kohaneDecodeAudio(args.path);
          const channels = Math.min(2, Math.max(1, decoded.channels));
          const options = { sampleRate: decoded.sampleRate, channels };
          const buf = format === "flac"
            ? encodeFlac(decoded.samples, Object.assign({ bitsPerSample: 16 }, options))
            : encodeWav16(decoded.samples, options);
          const receipt = {
            ok: true, op, exported: format, source: args.path, out,
            sourceFormat: decoded.format, sampleRate: decoded.sampleRate, channels,
            frames: decoded.frames, durationSec: decoded.sampleRate ? Math.round((decoded.frames / decoded.sampleRate) * 1000) / 1000 : null,
            bytes: buf.length,
            kind: "export",
            note: "this file is an export for other tools; kohane's own storage stays in its own containers",
          };
          if (args.dryRun) return Object.assign(receipt, { written: false });
          fs.writeFileSync(out, buf);
          return Object.assign(receipt, { written: true });
        } catch (e) {
          return { ok: false, op, note: String((e && e.message) || e) };
        }
      }

      if (op === "capabilities") {
        // The registry answers what KID can open, read, decode and write - assembled from what each
        // module declares, so the answer cannot drift away from the code.
        return Object.assign({ ok: true, op }, mediaCapabilities());
      }

      if (op === "pcm" || op === "play") {
        if (!args.path) return { ok: false, op, note: "missing path" };
        const staged = path.join(os.tmpdir(), "kohane-stage.wav");
        try {
          const decoded = kohaneDecodeAudio(args.path);
          const wav = kohaneStageWav(decoded);
          const target = args.stage ? String(args.stage) : staged;
          fs.writeFileSync(target, wav);
          const durationSec = decoded.sampleRate ? decoded.frames / decoded.sampleRate : 0;
          const receipt = {
            ok: true, op, path: args.path, container: decoded.format,
            sampleRate: decoded.sampleRate, channels: decoded.channels, bits: decoded.bits,
            frames: decoded.frames, durationSec: Math.round(durationSec * 1000) / 1000,
            staged: target, stagedBytes: wav.length,
          };
          if (op === "pcm" || args.dryRun) {
            return Object.assign(receipt, { played: false, note: op === "pcm" ? "samples staged as a canonical WAV" : "dryRun: nothing was played" });
          }
          if (process.platform !== "win32") {
            return Object.assign(receipt, { played: false, note: "playback is implemented for the Windows system player; the staged WAV is ready to be played by hand" });
          }
          // PlaySync in a detached child: the sound continues after this call returns, and the
          // receipt carries the child's pid so a caller can stop it if it must.
          const child = spawn("powershell", ["-NoProfile", "-Command", "(New-Object Media.SoundPlayer '" + target + "').PlaySync()"], { detached: true, stdio: "ignore", windowsHide: true });
          child.unref();
          return Object.assign(receipt, { played: true, player: "System.Media.SoundPlayer", playerPid: child.pid });
        } catch (e) {
          return { ok: false, op, note: String((e && e.message) || e) };
        }
      }

      if (op === "score") {
        if (!args.path) return { ok: false, op, note: "missing path" };
        try {
          return Object.assign({ ok: true, op }, readMidiScore(args.path));
        } catch (e) {
          return { ok: false, op, note: String((e && e.message) || e) };
        }
      }

      if (op === "sweep") {
        const dir = args.dir;
        if (!dir) return { ok: false, op, note: "missing dir" };
        const max = Math.min(Math.max(Number(args.maxFiles) || 500, 1), 5000);
        const files = [];
        const walk = (d) => {
          if (files.length >= max) return;
          let entries;
          try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
          for (const e of entries) {
            if (files.length >= max) return;
            const p = path.join(d, e.name);
            if (e.isDirectory()) { walk(p); continue; }
            if (e.isFile() && /.(wav|aif|aiff)$/i.test(e.name)) files.push(p);
          }
        };
        walk(dir);
        if (!files.length) return { ok: true, op, dir, files: 0, note: "no PCM audio found under that directory" };

        const threads = Math.min(Math.max(Number(args.threads) || availableCores(), 1), 64);
        const pooled = await poolMap(files.map((p) => ({ path: p, buckets })), "peaks", { threads, label: "audio-peaks" });
        let inlineMs = null;
        let speedup = null;
        if (args.compare === true) {
          const started = Date.now();
          for (const f of files) readAudioPeaks(f, buckets);
          inlineMs = Date.now() - started;
          speedup = Number((inlineMs / Math.max(pooled.ms, 1)).toFixed(2));
        }
        const results = pooled.results.map((r) => ({
          path: r.path, ok: r.ok !== false, channels: r.channelCount ?? null, sampleRate: r.sampleRate ?? null,
          bits: r.bits ?? null, frames: r.frames ?? null, buckets: r.peaks ? r.peaks.length : 0,
          note: r.ok === false ? r.note : undefined,
        }));
        return {
          ok: true, op, dir, files: files.length, threads: pooled.threads, mode: pooled.mode, poolSize: pooled.poolSize ?? null,
          ms: pooled.ms, inlineMs, speedup, measured: results.filter((r) => r.ok).length, results,
        };
      }

      return { ok: false, op, note: `unknown op "${args.op}", allowed: capabilities, export, peaks, pcm, play, score, sweep, info` };
    }
  },
  {
    name: "library_format",
    description: "Inspect and extend this installation's format library. op=list shows the local pack and the last report date; op=scan proposes file types the library cannot identify in a directory; op=learn registers a magic signature intersected from explicit sample files; op=add registers a signature, a plain-text extension, or a name rule by hand; op=remove drops a local entry; op=analyzer-add registers a user-defined analyzer (an external command plus an argv template containing {path}) that analyze_object runs for matching extensions or file names, and op=analyzer-remove drops one - built-in analyzers always run first, so a local one extends coverage but never shadows them; op=deps reports which formats reference which other formats (extensions only; DLL names opt-in); op=draft writes a reviewable checklist of candidates (optionally keeping the raw context locally, encrypted); op=report builds a small contribution archive from a directory or from selected draft items, and op=deliver shows such an archive in the platform's own window (a native dialog with a preview and Send by e-mail / Save a copy / Open folder / Delete buttons) so the USER decides whether it ever leaves the machine - pass headless:true on hosts without a desktop to get manual instructions instead. Paths are omitted by default, sanitised when requested, or sealed under a passphrase you hold (op=unseal reopens it). Built-ins are always matched first and conflicts are refused unless confirm:true. Scanning alone never learns anything and this tool performs no network I/O.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_format,
    async execute(args) {
      const op = String(args.op || "").toLowerCase();
      const packFile = localFormatsFile();
      const builtin = { signatures: FILE_SIGNATURES.length, textExtensions: TEXT_EXTENSIONS.length, zipPackages: Object.keys(ZIP_PACKAGE_FORMATS).length, dshArtifacts: DSH_ARTIFACTS.length };
      const summary = (p) => ({
        formats: p.formats.map((f) => ({ format: f.format, type: f.type, sig: hexSig(f.sig), bytes: f.sig.length, ext: f.ext, note: f.note })),
        textExtensions: p.textExtensions,
        nameRules: p.nameRules.map((r) => ({ re: String(r.re), role: r.role, expect: r.expect })),
        analyzers: (p.analyzers || []).map((a) => ({ name: a.name, kind: a.kind, exts: a.exts, matchName: a.matchName, exe: a.exe, args: a.args, parse: a.parse, timeoutMs: a.timeoutMs, note: a.note })),
        updatedAt: p.updatedAt,
      });
      const pack = loadLocalFormats();

      if (op === "list") {
        // Report cadence is a *reminder for the user*, never an automatic send.
        let lastReport = null;
        const at = (ms) => ({ at: new Date(ms).toISOString(), daysSince: Math.floor((Date.now() - ms) / 86400000) });
        try {
          const recs = loadIndex().objects.filter((o) => Array.isArray(o.tags) && o.tags.includes("format-report"));
          recs.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
          if (recs.length) {
            const t = Date.parse(recs[0].createdAt) || Date.now();
            lastReport = { file: recs[0].path || null, name: recs[0].name || null, ...at(t) };
          }
        } catch {}
        if (!lastReport) {
          try {
            const zips = fs.readdirSync(reportsDir()).filter((f) => f.endsWith(".zip")).sort();
            if (zips.length) {
              const newest = path.join(reportsDir(), zips[zips.length - 1]);
              lastReport = { file: newest, name: zips[zips.length - 1], ...at(fs.statSync(newest).mtimeMs) };
            }
          } catch {}
        }
        if (lastReport) lastReport.reminderDue = lastReport.daysSince >= 60;
        const hint = lastReport && lastReport.reminderDue
          ? ` - it has been ${lastReport.daysSince} days since the last format report; run op=report if you want to contribute again`
          : " - op=report builds a local format report you can choose to send (nothing is uploaded automatically)";
        return { ok: true, op, file: packFile, builtin, local: summary(pack), lastReport, note: (fs.existsSync(packFile) ? "local pack loaded" : "no local pack yet (add/learn creates it)") + hint };
      }

      if (op === "scan") {
        if (!args.dir) return { ok: false, op, note: "scan needs dir", scanned: 0, unidentified: [] };
        const { scanned, groups } = collectUnidentified(args.dir, args.maxFiles || 1000, 3, true);
        const unidentified = [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 25).map((g) => {
          const prefix = commonPrefix(g.heads);
          const suggestion = prefix.slice(0, 8);
          return {
            ext: g.ext, count: g.count, sampleCount: g.sampleCount, samples: g.samples,
            commonPrefix: prefix.length ? hexSig(prefix) : null,
            prefixBytes: prefix.length,
            suggestedSig: suggestion.length ? hexSig(suggestion) : null,
            conflicts: suggestion.length >= 2 ? builtinSigConflicts(suggestion) : [],
          };
        });
        return { ok: true, op, file: packFile, builtin, scanned, unidentified, note: `${unidentified.length} unidentified type(s) proposed; nothing was learned - call op=learn with samples to register one` };
      }

      // ---- draft: a checklist of candidates the user reviews before anything is built ----
      if (op === "draft") {
        if (!args.dir) return { ok: false, op, note: "draft needs dir", scanned: 0, unidentified: [] };
        const pathMode = ["none", "dirs", "full"].includes(String(args.pathDetail || "").toLowerCase()) ? String(args.pathDetail).toLowerCase() : "none";
        const depth = Math.min(Math.max(parseInt(args.depth, 10) || 3, 1), 8);
        const excl = (Array.isArray(args.excludeDir) ? args.excludeDir : []).map(String);
        const { scanned, groups } = collectUnidentified(args.dir, args.maxFiles || 1500, 6, true);
        const items = [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 200).map((g, i) => {
          const prefix = commonPrefix(g.heads);
          const suggestion = prefix.slice(0, 8);
          return {
            id: `f${i + 1}`,
            ext: g.ext, count: g.count, sampleCount: g.sampleCount,
            commonPrefix: prefix.length ? hexSig(prefix) : null,
            prefixBytes: prefix.length,
            suggestedSig: suggestion.length ? hexSig(suggestion) : null,
            conflicts: suggestion.length >= 2 ? builtinSigConflicts(suggestion) : [],
            dirs: pathMode === "none" ? [] : [...new Set(g.samples.map((s) => sanitizePath(s, "dirs", depth, excl)))].slice(0, 4),
            samplePaths: pathMode === "full" ? g.samples.map((s) => sanitizePath(s, "full", depth, excl)) : [],
          };
        });
        const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
        const draft = { version: 1, createdAt: new Date().toISOString(), source: args.dir, localOnly: "this draft file stays on this machine: it keeps the raw source path so a later op=report can re-scan for dependencies - share the archive, not the draft", scanned, pathDetail: pathMode, depth, excluded: excl, deps: args.deps !== false, items };
        const draftFile = args.out || path.join(draftsDir(), `draft-${stamp}.json`);
        fs.mkdirSync(path.dirname(draftFile), { recursive: true });
        fs.writeFileSync(draftFile, JSON.stringify(draft, null, 2), "utf8");
        let keptLocalId = null;
        if (args.keepLocal) {
          // Preserve the RAW (unredacted) context locally, encrypted with this install's
          // library key: nothing is lost, and only this machine can open it.
          const raw = { draft, rawSamples: [...groups.values()].sort((a, b) => b.count - a.count).slice(0, 200).map((g, i) => ({ id: `f${i + 1}`, ext: g.ext, count: g.count, samples: g.samples })) };
          const index = loadIndex();
          const id = makeId("knowledge", "local", `format-draft-${stamp}`);
          index.objects.push({
            id, type: "knowledge", name: `format draft (raw, encrypted) ${stamp}`, source: "local",
            description: `Unredacted format-draft context: ${items.length} unidentified type(s) with raw sample paths; encrypted with this install's library key - open with library_decrypt`,
            tags: ["format-draft", "local", "format"], summary: `kohane-index-desuno ${PLUGIN_VERSION}`, sensitive: true,
            createdAt: new Date().toISOString(), __content: encryptSensitive(raw),
          });
          index.generatedAt = new Date().toISOString();
          saveIndex(index);
          keptLocalId = id;
        }
        return {
          ok: true, op, file: draftFile, scanned, unidentifiedCount: items.length, keptLocalId,
          entries: items.slice(0, 60).map((it) => ({ name: it.id, ext: it.ext, count: it.count })),
          preview: items.slice(0, 40).map((it) => `${it.id.padEnd(5)} .${it.ext.padEnd(9)} x${String(it.count).padEnd(6)} prefix=${it.commonPrefix ?? "(none)"}${it.dirs.length ? "  dirs=" + it.dirs.join(", ") : ""}`).join("\n"),
          note: `draft written locally: ${items.length} candidate(s), nothing sent - review, then op=report draft=${path.basename(draftFile)} include=<ids|all>${keptLocalId ? `; raw context kept encrypted as ${keptLocalId}` : ""}`,
        };
      }

      // ---- deps: which formats reference which other formats (no paths, opt-in DLL names) ----
      if (op === "deps") {
        if (!args.dir) return { ok: false, op, note: "deps needs dir" };
        const r = collectDeps(args.dir, args.maxFiles || 2000, !!args.names);
        return {
          ok: true, op, scanned: r.scanned, unidentifiedCount: r.inspected,
          deps: r.edges, dllNames: args.names ? r.dllNames : [],
          preview: r.edges.slice(0, 40).map((e) => `${e.from} -> ${e.to}  x${e.count}`).join("\n"),
          note: `${r.edges.length} format relationship(s) from ${r.inspected} inspected file(s): extensions only${args.names ? ", plus DLL names (treat as user-level)" : ""}`,
        };
      }

      // ---- unseal: reopen a sealed layer locally with the user's own passphrase ----
      if (op === "unseal") {
        const file = args.file || args.path;
        if (!file || !fs.existsSync(file)) return { ok: false, op, note: "unseal needs file=<sealed archive>" };
        if (!args.passphrase) return { ok: false, op, note: "unseal needs passphrase (the one you sealed with)" };
        const entry = zipReadEntry(fs.readFileSync(file), "sealed.json");
        if (!entry) return { ok: false, op, note: "that archive has no sealed layer" };
        const plain = unsealWithPassphrase(args.passphrase, JSON.parse(entry.toString("utf8")));
        if (plain.__unsealError) return { ok: false, op, note: "wrong passphrase (or the sealed layer is corrupted)" };
        return { ok: true, op, file, preview: JSON.stringify(plain, null, 2).split("\n").slice(0, 40).join("\n"), note: "sealed layer opened locally; nothing left this machine" };
      }

      // ---- report: build a small, inspectable contribution archive (local, no network) ----
      if (op === "report") {
        let pathMode = ["none", "dirs", "full"].includes(String(args.pathDetail || "").toLowerCase()) ? String(args.pathDetail).toLowerCase() : "none";
        let depth = Math.min(Math.max(parseInt(args.depth, 10) || 3, 1), 8);
        let excl = (Array.isArray(args.excludeDir) ? args.excludeDir : []).map(String);
        let items, scanned, sourceDir = args.dir || null, prefDeps = true, fromDraft = null;
        if (args.draft) {
          const dp = resolveDraft(args.draft);
          if (!dp) return { ok: false, op, note: `draft not found: ${args.draft}` };
          const d = JSON.parse(fs.readFileSync(dp, "utf8"));
          fromDraft = dp;
          sourceDir = d.source || sourceDir;
          scanned = d.scanned || 0;
          prefDeps = d.deps !== false;
          // The draft already recorded how much path detail the user chose - keep it unless
          // this call overrides it explicitly.
          if (!args.pathDetail && ["none", "dirs", "full"].includes(String(d.pathDetail || ""))) pathMode = String(d.pathDetail);
          if (args.depth === undefined && d.depth) depth = Math.min(Math.max(parseInt(d.depth, 10) || 3, 1), 8);
          if (!args.excludeDir && Array.isArray(d.excluded) && d.excluded.length) excl = d.excluded.map(String);
          const want = Array.isArray(args.include) ? args.include.map(String) : String(args.include || "").split(",").map((s) => s.trim()).filter(Boolean);
          if (!want.length && args.includeAll !== true) {
            // Nothing preselected: return the checklist instead of quietly taking everything.
            return {
              ok: false, op, file: dp, unidentifiedCount: d.items.length,
              preview: d.items.slice(0, 40).map((it) => `${it.id.padEnd(5)} .${it.ext.padEnd(9)} x${String(it.count).padEnd(6)} prefix=${it.commonPrefix ?? "(none)"}`).join("\n"),
              note: "draft loaded - nothing was written. Choose what to include: include=[\"f1\",\"f3\"] (or includeAll:true), then run again",
            };
          }
          const all = want.includes("all") || args.includeAll === true;
          items = all ? d.items : d.items.filter((it) => want.includes(it.id));
          if (!items.length) return { ok: false, op, file: dp, note: "no matching ids in that draft (use include=f1,f3 or includeAll:true)" };
        } else {
          if (!args.dir) return { ok: false, op, note: "report needs dir (or draft)", scanned: 0, unidentified: [] };
          const fresh = collectUnidentified(args.dir, args.maxFiles || 1500, 6, pathMode !== "none");
          scanned = fresh.scanned;
          items = [...fresh.groups.values()].sort((a, b) => b.count - a.count).slice(0, 200).map((g, i) => {
            const prefix = commonPrefix(g.heads);
            const suggestion = prefix.slice(0, 8);
            return {
              id: `f${i + 1}`,
              ext: g.ext, count: g.count, sampleCount: g.sampleCount,
              commonPrefix: prefix.length ? hexSig(prefix) : null,
              prefixBytes: prefix.length,
              suggestedSig: suggestion.length ? hexSig(suggestion) : null,
              conflicts: suggestion.length >= 2 ? builtinSigConflicts(suggestion) : [],
              dirs: pathMode === "none" ? [] : [...new Set(g.samples.map((s) => sanitizePath(s, "dirs", depth, excl)))].slice(0, 4),
              samplePaths: pathMode === "full" ? g.samples.map((s) => sanitizePath(s, "full", depth, excl)) : [],
            };
          });
        }
        const unidentified = items.map((it) => ({
          ext: it.ext, count: it.count, sampleCount: it.sampleCount,
          commonPrefix: it.commonPrefix, prefixBytes: it.prefixBytes, suggestedSig: it.suggestedSig, conflicts: it.conflicts,
        }));
        // User-level fields: paths, and DLL names when asked for. Everything else is format knowledge.
        const userLevel = {};
        if (pathMode !== "none") {
          const dirs = [...new Set(items.flatMap((it) => it.dirs || []))].slice(0, 300);
          if (dirs.length) userLevel.dirs = dirs;
          if (pathMode === "full") {
            const sp = items.flatMap((it) => it.samplePaths || []).slice(0, 300);
            if (sp.length) userLevel.samplePaths = sp;
          }
        }
        const depsOn = args.deps !== undefined ? !!args.deps : prefDeps;
        let depsData = null;
        if (depsOn && sourceDir) {
          const dd = collectDeps(sourceDir, args.maxFiles || 1500, !!args.names);
          depsData = { edges: dd.edges.slice(0, 200), inspected: dd.inspected, dllCount: dd.dllNames.length };
          if (args.names && dd.dllNames.length) userLevel.dllNames = dd.dllNames;
        }
        const report = {
          report: "kohane-index-desuno format report",
          reportVersion: 2,
          plugin: "kohane-index-desuno",
          pluginVersion: PLUGIN_VERSION,
          generatedAt: new Date().toISOString(),
          pathDetail: pathMode,
          fromDraft: fromDraft ? path.basename(fromDraft) : null,
          privacy: "Collected: file extensions, magic-byte prefixes, counts, format->format relationships, plugin version, local pack entries (no notes). NOT collected: file contents and credentials. Directory information is user-level and controlled by you: omitted at pathDetail=none (default), sanitised with ...<drive>/<home>/<user>/<host>/<uuid>/<date>... placeholders at dirs (directory names only) or full (also sample file names), or sealed under your own passphrase. DLL names are user-level and opt-in.",
          scannedFiles: scanned,
          builtin,
          localPack: {
            formats: pack.formats.map((f) => ({ format: f.format, type: f.type, sig: hexSig(f.sig), ext: f.ext })),
            textExtensions: pack.textExtensions,
            nameRules: pack.nameRules.map((r) => ({ role: r.role, expect: r.expect })),
          },
          deps: depsData,
          unidentified,
        };
        const extraFiles = [];
        if (args.seal && Object.keys(userLevel).length) {
          const fieldCount = Object.values(userLevel).reduce((n, v) => n + v.length, 0);
          report.sealed = { fields: fieldCount, layers: Object.keys(userLevel), kdf: "hkdf-sha256/aes-256-gcm", howToOpen: "library_format op=unseal file=<this archive> passphrase=<yours>" };
          extraFiles.push({ name: "sealed.json", data: JSON.stringify(sealWithPassphrase(args.seal, { userLevel }), null, 2) });
        } else if (Object.keys(userLevel).length) {
          Object.assign(report, userLevel);
        }
        const manifest = [
          `${report.report} - v${report.reportVersion}`,
          `plugin       : ${report.plugin} ${report.pluginVersion}`,
          `generated at : ${report.generatedAt}`,
          `files scanned: ${scanned}`,
          `unidentified : ${unidentified.length} type(s)`,
          `path detail  : ${pathMode}${pathMode === "dirs" ? " (directory names only, sanitised: <drive>/<home>/<user>/<host>/<uuid>/<date>)" : pathMode === "full" ? " (sanitised paths incl. sample file names)" : " (no directory information at all)"}`,
          `dependencies : ${depsData ? `${depsData.edges.length} format relationship(s) - format names only` : "not collected"}`,
          report.sealed ? `sealed layer : ${report.sealed.fields} field(s) - sealed with YOUR passphrase, openable only by you (see below)` : null,
          "",
          "Contents of this archive:",
          "  report.json  - machine-readable summary (extensions, magic prefixes, counts, dependencies)",
          "  manifest.txt - this human-readable summary",
          report.sealed ? "  sealed.json  - AES-256-GCM layer you can reopen with op=unseal; cannot be read without your passphrase" : null,
          "",
          args.seal ? "Your passphrase protects the user-level layer, so you can share the archive without sharing paths." : "NOT included, by design: file names, file contents, user name, host name, credentials.",
          pathMode === "none" ? "You chose paths=none, so no directory information is present at all." : "Directory information present is sanitised, but please read it before sending.",
          "",
          "How to send it (manual - your decision, after reading this):",
          `  to     : ${REPORT_MAIL_TO}`,
          `  subject: [format report] kohane-index-desuno ${report.pluginVersion}`,
          "  attach : this .zip",
          "  (or upload it yourself, e.g. gigafile.nu, and send the link)",
          "",
          "This plugin performs no network I/O for reports: nothing was uploaded or e-mailed for you.",
          "",
          "Top unidentified types:",
          ...unidentified.slice(0, 40).map((u) => `  .${u.ext}  x${String(u.count).padEnd(6)} samples=${u.sampleCount}  prefix=${u.commonPrefix ?? "(none)"}`),
          ...(depsData && depsData.edges.length ? ["", "Format relationships (top 20):", ...depsData.edges.slice(0, 20).map((e) => `  ${e.from} -> ${e.to}  x${e.count}`)] : []),
        ].filter((l) => l !== null).join("\n");
        const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
        const outFile = args.out || path.join(reportsDir(), `format-report-${stamp}.zip`);
        fs.mkdirSync(path.dirname(outFile), { recursive: true });
        const reportJson = JSON.stringify(report, null, 2);
        // manifest gets a UTF-8 BOM so plain Windows tools (Notepad, mail preview) show it correctly.
        const buf = zipBuffer([{ name: "report.json", data: reportJson }, { name: "manifest.txt", data: "\uFEFF" + manifest }, ...extraFiles]);
        fs.writeFileSync(outFile, buf);
        // Record the produced archive in the Library (so library_query and the cadence
        // reminder can find it no matter where it was written).
        const index = loadIndex();
        const obj = {
          id: makeId("file", "local", `format-report-${stamp}`),
          type: "file",
          name: `format report ${stamp}`,
          source: "local",
          path: outFile,
          description: `Format-library contribution archive: ${unidentified.length} unidentified type(s) out of ${scanned} scanned file(s); extensions, magic prefixes and format relationships; paths=${pathMode}${report.sealed ? `, ${report.sealed.fields} user-level field(s) sealed` : ""}; built locally, not sent`,
          tags: ["format-report", "local", "format"],
          summary: `kohane-index-desuno ${PLUGIN_VERSION}, ${buf.length} bytes`,
          createdAt: new Date().toISOString(),
        };
        index.objects.push(obj);
        index.generatedAt = obj.createdAt;
        saveIndex(index);
        appendLog({ op: "format-report", type: "format", name: null, source: "local", disposition: null, detail: `report written locally: ${unidentified.length} unidentified type(s), paths=${pathMode}${report.sealed ? ", sealed" : ""}, ${buf.length} bytes (not sent)` });
        // Optional: hand the archive to the user in a native window right away (their choice,
        // never an automatic send).
        let delivery = null;
        if (args.ui && args.headless !== true) {
          const d = await runReportDialog(outFile, { autoCloseMs: parseInt(args.autoCloseMs, 10) || 0, selfTest: !!args.selfTest });
          delivery = { action: d.action, savedTo: d.savedTo, gui: d.gui, note: d.note || "the user chose what to do with the archive" };
          appendLog({ op: "format-deliver", type: "format", name: null, source: "local", disposition: null, detail: `delivery dialog: action=${d.action}` });
        }
        return {
          ok: true, op, file: outFile, bytes: buf.length, scanned, unidentifiedCount: unidentified.length,
          pathDetail: pathMode,
          deps: depsData ? depsData.edges : [],
          dllNames: args.names ? userLevel.dllNames || [] : [],
          sealed: report.sealed || null,
          entries: [
            { name: "report.json", bytes: Buffer.byteLength(reportJson) },
            { name: "manifest.txt", bytes: Buffer.byteLength(manifest) },
            ...extraFiles.map((f) => ({ name: f.name, bytes: Buffer.byteLength(f.data) })),
          ],
          mail: { to: REPORT_MAIL_TO, subject: `[format report] kohane-index-desuno ${PLUGIN_VERSION}`, attachment: outFile },
          delivery,
          preview: manifest.split("\n").slice(0, 28).join("\n"),
          note: `report written locally (${buf.length} bytes, ${unidentified.length} unidentified type(s), paths=${pathMode}${report.sealed ? `, ${report.sealed.fields} field(s) sealed with your passphrase` : ""}) - nothing was uploaded; ${delivery ? `the delivery dialog returned action=${delivery.action}` : "review manifest.txt, then send it yourself if you choose to"}`,
        };
      }

      // ---- deliver: show the report in a native window so the user decides what happens ----
      if (op === "deliver") {
        const file = args.file ? String(args.file) : latestReportFile();
        if (!file) return { ok: false, op, note: "no report archive found; run op=report first", steps: [] };
        if (!fs.existsSync(file)) return { ok: false, op, note: `report not found: ${file}`, steps: [] };
        const instructions = reportDeliveryInstructions(file);
        if (args.headless) {
          return { ok: true, op, file, headless: true, gui: false, action: "instructions", ...instructions };
        }
        const d = await runReportDialog(file, { autoCloseMs: parseInt(args.autoCloseMs, 10) || 0, selfTest: !!args.selfTest });
        appendLog({ op: "format-deliver", type: "format", name: null, source: "local", disposition: null, detail: `delivery dialog: action=${d.action}${d.gui ? "" : " (no GUI available)"}` });
        const done = ["email", "save", "delete", "close", "folder", "selftest"].includes(d.action);
        return {
          ok: done || d.action === "timeout" || d.action === "pending",
          op, file, action: d.action, savedTo: d.savedTo, gui: d.gui, shell: d.shell || null,
          mail: instructions.mail,
          steps: d.gui ? [] : instructions.steps,
          preview: instructions.steps.slice(0, 1).join("\n"),
          note: d.gui
            ? `the user was asked in a native window (${d.shell}) and chose: ${d.action}${d.savedTo ? ` (saved to ${d.savedTo})` : ""} - the plugin transmitted nothing`
            : `no GUI was available (${d.action}); deliver it manually: ${instructions.mail.to}`,
        };
      }

      if (op === "learn") {
        const ext = String(args.ext || "").replace(/^\./, "").toLowerCase();
        const paths = (Array.isArray(args.paths) ? args.paths : []).filter((p) => typeof p === "string");
        if (!ext || !paths.length) return { ok: false, op, note: "learn needs ext and at least one sample path", conflicts: [] };
        const heads = paths.filter((p) => fs.existsSync(p)).map((p) => readHeader(p, 16)).filter(Boolean);
        if (!heads.length) return { ok: false, op, note: "no readable sample path", conflicts: [] };
        const prefix = commonPrefix(heads);
        // The intersected prefix often includes version/build fields, so only the first
        // `bytes` bytes (default 8) are stored - a signature that also matches the next
        // release of the same format. Everything is reported for review.
        const wantBytes = Math.min(Math.max(parseInt(args.bytes, 10) || 8, 2), 16);
        const sig = prefix.slice(0, wantBytes);
        const truncated = prefix.length > sig.length;
        const conflicts = builtinSigConflicts(sig);
        const short = sig.length < 4;
        if (heads.length < 2) conflicts.push("only one sample: a shared prefix is not evidence (use 2+ files)");
        if ((conflicts.length || short) && !args.confirm) {
          return { ok: false, op, file: packFile, conflicts, learned: { samplePrefix: hexSig(prefix), bytes: prefix.length, stored: hexSig(sig), storedBytes: sig.length }, note: `refused: ${short ? "signature shorter than 4 bytes" : "signature collides with a built-in format"} - pass confirm:true to override` };
        }
        const format = String(args.format || ext).slice(0, 40);
        const entry = { format, type: String(args.type || "document"), sig, ext: [ext], note: String(args.note || `locally learned (.${ext})`).slice(0, 200), createdAt: new Date().toISOString() };
        const next = normalizeLocalPack({ ...pack, formats: [...pack.formats.filter((f) => f.format !== format && !f.ext.includes(ext)), entry] });
        saveLocalFormats(next);
        const verified = paths.filter((p) => fs.existsSync(p)).map((p) => {
          const r = sniffFileType(p);
          return { path: p, format: r ? r.format : null, ok: !!(r && r.format === format) };
        });
        appendLog({ op: "format-learn", type: "format", name: format, source: "local", disposition: null, detail: `learned ${hexSig(sig)} for .${ext} from ${heads.length} sample(s)` });
        return { ok: true, op, file: packFile, builtin, local: summary(loadLocalFormats()), conflicts, verified, learned: { samplePrefix: hexSig(prefix), bytes: prefix.length, stored: hexSig(sig), storedBytes: sig.length, truncated }, note: `learned ${format} = ${hexSig(sig)} (.${ext})${truncated ? ` - intersected prefix was ${prefix.length} bytes, stored first ${sig.length} for version tolerance` : ""}; verified on ${verified.filter((v) => v.ok).length}/${verified.length} sample(s)` };
      }

      if (op === "add") {
        const next = normalizeLocalPack(pack);
        const conflicts = [];
        let what = "";
        if (args.textExtension) {
          const e = String(args.textExtension).replace(/^\./, "").toLowerCase();
          if (!e) return { ok: false, op, note: "empty textExtension" };
          if (TEXT_EXTENSIONS.includes(e)) conflicts.push(`.${e} is already a built-in text extension`);
          if (conflicts.length && !args.confirm) return { ok: false, op, conflicts, note: "redundant with a built-in (pass confirm:true to keep it anyway)" };
          if (!next.textExtensions.includes(e)) next.textExtensions.push(e);
          what = `text extension .${e}`;
        } else if (args.nameRule) {
          let re;
          try { re = new RegExp(String(args.nameRule), "i"); } catch (err) { return { ok: false, op, note: `invalid nameRule regex: ${err.message}` }; }
          next.nameRules.push({ re, source: String(args.nameRule), role: String(args.role || "local"), expect: args.expect || null, note: String(args.note || "").slice(0, 200) });
          what = `name rule /${re.source}/ role=${args.role || "local"}`;
        } else {
          const sig = parseHexSig(args.sig);
          if (!sig) return { ok: false, op, note: "add needs sig (hex bytes), textExtension, or nameRule" };
          const format = String(args.format || "").slice(0, 40);
          if (!format) return { ok: false, op, note: "add with sig needs format" };
          conflicts.push(...builtinSigConflicts(sig));
          if (sig.length < 4) conflicts.push("prefix shorter than 4 bytes");
          if (conflicts.length && !args.confirm) return { ok: false, op, conflicts, note: "refused (pass confirm:true to override)" };
          const ext = String(args.ext || "").replace(/^\./, "").toLowerCase();
          next.formats = next.formats.filter((f) => f.format !== format);
          next.formats.push({ format, type: String(args.type || "document"), sig, ext: ext ? [ext] : [], note: String(args.note || "").slice(0, 200), createdAt: new Date().toISOString() });
          what = `signature ${format} = ${hexSig(sig)}`;
        }
        saveLocalFormats(next);
        appendLog({ op: "format-add", type: "format", name: args.format || args.textExtension || args.role || null, source: "local", disposition: null, detail: what });
        return { ok: true, op, file: packFile, local: summary(loadLocalFormats()), conflicts, note: `added ${what}` };
      }

      if (op === "remove") {
        const ext = String(args.ext || "").replace(/^\./, "").toLowerCase();
        const format = String(args.format || "");
        if (!ext && !format) return { ok: false, op, note: "remove needs ext or format" };
        const next = normalizeLocalPack(pack);
        const before = next.formats.length + next.textExtensions.length + next.nameRules.length;
        next.formats = next.formats.filter((f) => f.format !== format && !(ext && f.ext.includes(ext)));
        next.textExtensions = next.textExtensions.filter((e) => e !== ext);
        next.nameRules = next.nameRules.filter((r) => r.role !== format);
        const after = next.formats.length + next.textExtensions.length + next.nameRules.length;
        saveLocalFormats(next);
        return { ok: true, op, file: packFile, removed: before - after, local: summary(loadLocalFormats()), note: `removed ${before - after} local entr(ies)` };
      }

      // ---- DIY analyzers: let a user plug their own tool into analyze_object ----------------
      if (op === "analyzer-add") {
        const name = String(args.name || "").slice(0, 60).trim();
        if (!name) return { ok: false, op, note: "analyzer-add needs name" };
        const exe = String(args.exe || "").trim();
        if (!exe) return { ok: false, op, note: "analyzer-add needs exe (the external command to run)" };
        const exts = (Array.isArray(args.exts) ? args.exts : String(args.exts || "").split(","))
          .map((e) => String(e).toLowerCase().replace(/^\./, "").trim()).filter(Boolean);
        let matchName = null;
        if (args.matchName) {
          try { new RegExp(String(args.matchName), "i"); matchName = String(args.matchName); }
          catch (err) { return { ok: false, op, note: `invalid matchName regex: ${err.message}` }; }
        }
        if (!exts.length && !matchName) return { ok: false, op, note: "analyzer-add needs exts and/or matchName so the analyzer can match something" };
        const next = normalizeLocalPack(pack);
        const def = {
          name,
          kind: String(args.kind || name).slice(0, 40),
          exts,
          matchName,
          exe,
          args: (Array.isArray(args.args) ? args.args : []).map((x) => String(x)).slice(0, 40),
          timeoutMs: Math.min(Math.max(Number(args.timeoutMs) || 30000, 1000), 300000),
          parse: args.parse === "text" ? "text" : "json",
          note: String(args.note || "").slice(0, 200),
          createdAt: new Date().toISOString(),
        };
        next.analyzers = next.analyzers.filter((a) => a.name !== name); // re-register replaces
        next.analyzers.push(def);
        saveLocalFormats(next);
        appendLog({ op: "format-analyzer-add", type: "format", name, source: "local", disposition: null, detail: `local analyzer ${name} -> ${exe}` });
        return {
          ok: true, op, file: packFile, local: summary(loadLocalFormats()),
          note: `registered local analyzer "${name}" (exts: ${exts.join(", ") || "-"}${matchName ? `, name: /${matchName}/` : ""}, parse: ${def.parse}); analyze_object will run it after the built-ins`,
        };
      }

      if (op === "analyzer-remove") {
        const name = String(args.name || "").trim();
        if (!name) return { ok: false, op, note: "analyzer-remove needs name" };
        const next = normalizeLocalPack(pack);
        const before = next.analyzers.length;
        next.analyzers = next.analyzers.filter((a) => a.name !== name);
        saveLocalFormats(next);
        appendLog({ op: "format-analyzer-remove", type: "format", name, source: "local", disposition: null, detail: `removed local analyzer ${name}` });
        return { ok: true, op, file: packFile, removed: before - next.analyzers.length, local: summary(loadLocalFormats()), note: `removed ${before - next.analyzers.length} local analyzer(s)` };
      }

      return { ok: false, op, note: `unknown op "${args.op}", allowed: list, scan, learn, add, remove, analyzer-add, analyzer-remove, draft, deps, report, deliver, unseal` };
    }
  },

  {
    name: "library_plugin",
    description: "Kohane's own plugin directory: every plugin capability kohane adopts is named inside one family - the uniform brand \"Kohane Bassline\" plus a functional word for what it does - so kohane depends on no third-party plugin or host at runtime, and no third-party product name appears in any result. op=list shows the directory (capability slots plus what this machine links to them), op=show one entry, op=roles the taxonomy, op=scan reads a native plugin database (state files, headers only), op=discover walks the machine's plugin folders (VST3/CLAP/VST2 binaries, headers and version strings only - nothing is loaded, registered or executed), op=learn folds both into this installation's local adoption pack at $DSH_HOME/library/plugins.local.json, op=add/remove/rename/brand personalise the directory, op=export writes it out and op=provenance shows - only when explicitly asked - which local plugin provides one capability, for cross-checking. Scanning never modifies what it scans and this tool performs no network I/O.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_plugin,
    async execute(args) {
      const op = String(args.op || "").toLowerCase();
      const packFile = pluginPackFile();
      const pack = loadPluginPack();
      const brief = (e) => ({
        id: e.id,
        name: e.name,
        function: e.function,
        role: e.role,
        origin: e.renamed ? `${e.origin}+personalised` : e.origin,
        linked: e.linked || 0,
      });
      const words = (arr) => arr.map((p) => p.word || roleFunctionWord(p.role));

      if (op === "roles") {
        return { ok: true, op, brand: pack.brand, roles: KOHANE_PLUGIN_ROLES, flagship: KOHANE_PLUGIN_FLAGSHIP, vocabulary: PLUGIN_FUNCTION_VOCAB.length, note: "role = what a capability does; the functional word in a name is derived from it" };
      }

      if (op === "list") {
        const all = resolveKohanePlugins(pack);
        let list = all;
        if (args.role) list = list.filter((e) => e.role === String(args.role));
        const q = String(args.query || "").trim().toLowerCase();
        if (q) list = list.filter((e) => [e.name, e.function, e.role, e.note].join(" ").toLowerCase().includes(q));
        const limit = Math.min(Math.max(Number(args.limit) || 100, 1), 400);
        const byRole = {};
        for (const e of all) byRole[e.role] = (byRole[e.role] || 0) + 1;
        return {
          ok: true, op, file: packFile, brand: pack.brand,
          total: all.length, matched: list.length, linked: all.filter((e) => e.linked).length, byRole,
          entries: list.slice(0, limit).map(brief),
          preview: list.slice(0, limit).map((e) => `${e.name.padEnd(38)} ${e.role.padEnd(20)} ${e.linked ? `x${e.linked}` : "-"}`).join("\n"),
          note: "one family, one functional word per capability; run op=provenance for the local cross-check of a single entry",
        };
      }

      if (op === "show") {
        const key = String(args.target || "").trim().toLowerCase();
        if (!key) return { ok: false, op, note: "show needs target (id or Kohane name)" };
        const entries = resolveKohanePlugins(pack);
        const k = pluginKey(key);
        const hit = entries.find((e) => e.id === key || e.name.toLowerCase() === key)
          || entries.find((e) => pluginKey(e.name) === k)
          || entries.find((e) => `${e.name} ${e.function} ${e.role}`.toLowerCase().includes(key));
        if (!hit) return { ok: false, op, note: `no entry matches "${key}"` };
        return { ok: true, op, file: packFile, entry: brief(hit), roleMeaning: KOHANE_PLUGIN_ROLES[hit.role] || "", note: hit.note || "" };
      }

      // Two readiness reports over the directory: what this machine provides nothing for, and
       // which capabilities still carry a numbered fallback name instead of a chosen word.
      if (op === "unlinked" || op === "numbered") {
        const all = resolveKohanePlugins(pack);
        const byRole = {};
        for (const e of all) byRole[e.role] = (byRole[e.role] || 0) + 1;
        if (op === "unlinked") {
          const rows = all.filter((e) => !e.linked);
          return {
            ok: true, op, file: packFile, brand: pack.brand, total: all.length, unlinked: rows.length,
            byRole,
            entries: rows.map(brief),
            preview: rows.slice(0, 30).map((e) => `${e.name.padEnd(38)} ${e.role}`).join("\n"),
            note: "capabilities with no local link yet: run op=discover/learn to link this machine, or op=add / op=rename to shape the directory by hand",
          };
        }
        const numbered = all.filter((e) => /\s\d+$/.test(e.name));
        return {
          ok: true, op, file: packFile, brand: pack.brand, total: all.length, numbered: numbered.length,
          byRole,
          entries: numbered.map(brief),
          preview: numbered.slice(0, 30).map((e) => `${e.name.padEnd(38)} ${e.role}`).join("\n"),
          note: "numbered fallbacks come from the generic vocabulary; give one a chosen word with op=rename (target=<id or name>, function=\"<word>\")",
        };
      }

      if (op === "scan" || op === "discover" || op === "learn") {
        // Two discovery sources under one op family: an installation's own plugin database (state
        // files) and its plugin folders (VST3/CLAP/VST2 binaries). Both are read-only.
        const wantBinaries = op === "discover" || (op === "learn" && args.binaries !== false);
        const wantStates = op === "scan" || op === "learn";
        const doScan = op !== "discover";
        // A binary-only pass has no business looking at a state-file database.
        const dir = args.dir || (op === "discover" ? null : findPluginDatabase());
        const s = doScan && dir ? scanPluginDatabase(dir, Math.min(Math.max(Number(args.maxFiles) || 600, 1), 5000)) : null;
        const b = wantBinaries ? scanPluginInstallations({ maxFiles: args.maxFiles, roots: Array.isArray(args.roots) ? args.roots : null }) : null;
        if (op === "scan" && !dir) {
          return { ok: false, op, note: "no native plugin database found; pass dir or set KOHANE_FL_DIR (nothing was scanned)" };
        }
        if (op === "discover" && (!b || !b.roots.length)) {
          return { ok: false, op, note: "no plugin folder found; set KOHANE_PLUGIN_ROOTS to the folders to inspect (nothing was scanned)" };
        }

        const observed = [];
        if (s) for (const p of distinctPlugins(s.plugins)) {
          observed.push({
            ...p,
            kind: p.kind || "native-state",
            word: extractFunctionWord(p.localName),
            role: classifyPluginRole(p.localName, p.localCategory || ""),
          });
        }
        if (b) for (const p of b.plugins) observed.push(p);

        const known = new Map((pack.entries || []).map((e) => [pluginKey(e.localName), e]));
        const linked = [], fresh = [];
        for (const p of observed) (known.has(pluginKey(p.localName)) ? linked : fresh).push(p);

        if (op === "scan" || op === "discover") {
          const matched = words(observed.filter((p) => KOHANE_CAPABILITIES.some(([fn]) => pluginKey(fn) === pluginKey(p.word))));
          return {
            ok: true, op,
            source: [dir ? "native-plugin-database" : null, b && b.roots.length ? "plugin-folders" : null].filter(Boolean).join(" + "),
            ...(args.detail ? { dir: dir || null, roots: b ? b.roots : [] } : { dirs: [dir, ...(b ? b.roots : [])].filter(Boolean).length }),
            scanned: (s ? s.scanned : 0) + (b ? b.scanned : 0),
            states: s ? s.states : 0,
            plugins: observed.length,
            byKind: observed.reduce((a, p) => ((a[p.kind] = (a[p.kind] || 0) + 1), a), {}),
            arch: [...new Set(observed.map((p) => p.arch).filter(Boolean))],
            abi: [...new Set(observed.flatMap((p) => p.abi || []))],
            alreadyLinked: linked.length,
            newCapabilities: fresh.length,
            capabilityWords: [...new Set(matched)].sort().slice(0, 40),
            unmatchedWords: [...new Set(fresh.filter((p) => !p.word).map((p) => roleFunctionWord(p.role)))].sort(),
            truncated: (s ? s.truncated : false) || (b ? b.truncated : false),
            note: `read-only: ${observed.length} plugin(s) described by capability only; nothing was loaded, registered, executed or written - run op=learn to link them (pass detail:true to list the inspected locations)`,
          };
        }

        // learn: link observations to capabilities in the local pack (provenance stays local).
        const next = normalizePluginPack(pack);
        const byKey = new Map(next.entries.map((e) => [pluginKey(e.localName), e]));
        let added = 0, refreshed = 0;
        for (const p of observed) {
          const key = pluginKey(p.localName);
          if (!key) continue;
          const word = p.word || "";
          let e = byKey.get(key);
          if (!e) {
            e = {
              localName: p.localName, capability: word, name: "",
              role: p.role || classifyPluginRole(p.localName, p.localCategory || p.category || ""),
              kind: p.kind || "plugin", localCategory: p.localCategory || "", localVersion: p.version || null,
              localFile: p.file || "", origin: "discovered",
              note: word ? "" : "no functional word found in its name; give it one with op=rename",
              updatedAt: null,
            };
            next.entries.push(e);
            byKey.set(key, e);
            added++;
          } else {
            if (p.version) e.localVersion = p.version;
            if (p.file) e.localFile = p.file;
            if (p.localCategory && !e.localCategory) e.localCategory = p.localCategory;
            if (!e.capability) e.capability = word;
            refreshed++;
          }
        }
        const saved = savePluginPack(next);
        const after = resolveKohanePlugins(saved);
        appendLog({ op: "plugin-learn", type: "plugin", name: null, source: "local", disposition: null, detail: `linked ${added} new / ${refreshed} refreshed observation(s) across ${after.length} capabilities` });
        return {
          ok: true, op, file: packFile,
          ...(args.detail ? { dir: dir || null } : { dirs: 1 }),
          observed: observed.length, added, refreshed,
          total: after.length, linked: after.filter((e) => e.linked).length,
          generic: after.filter((e) => e.origin === "discovered" && !e.function).map((e) => e.name),
          byRole: after.reduce((acc, e) => ((acc[e.role] = (acc[e.role] || 0) + 1), acc), {}),
          note: "links are local bookkeeping: names stay kohane's own, and the local side is shown only by op=provenance",
        };
      }

      if (op === "add") {
        const word = String(args.capability || args.function || args.name || "").trim();
        if (!word) return { ok: false, op, note: "add needs capability (the functional word, e.g. \"Maximizer\")" };
        const role = String(args.role || "").trim() || classifyPluginRole(word, "");
        if (!KOHANE_PLUGIN_ROLES[role]) {
          return { ok: false, op, note: `unknown role "${role}"; allowed: ${Object.keys(KOHANE_PLUGIN_ROLES).join(", ")}` };
        }
        const next = normalizePluginPack(pack);
        const localName = `manual:${pluginSlug(word)}`;
        if (next.entries.some((e) => pluginKey(e.localName) === pluginKey(localName))) {
          return { ok: false, op, note: `capability "${word}" is already in the directory` };
        }
        next.entries.push({ localName, capability: word, name: "", role, kind: "capability", localCategory: "", localVersion: null, localFile: "", origin: "manual", note: String(args.note || "").slice(0, 200), updatedAt: null });
        const want = derivedKohaneName({ capability: word, role }, next.brand);
        if (!args.confirm && kohaneNameTaken(resolveKohanePlugins(next), want, localName)) {
          return { ok: false, op, note: `"${want}" is already taken; choose another functional word or pass confirm:true` };
        }
        const saved = savePluginPack(next);
        const now = resolveKohanePlugins(saved).find((e) => pluginKey(e.function) === pluginKey(word));
        appendLog({ op: "plugin-add", type: "plugin", name: now.name, source: "local", disposition: null, detail: `capability "${word}" added to the directory` });
        return { ok: true, op, file: packFile, entry: brief(now), note: `"${now.name}" is now part of the directory` };
      }

      if (op === "rename") {
        const targets = (Array.isArray(args.target) ? args.target : Array.isArray(args.targets) ? args.targets : [args.target])
          .map((t) => String(t || "").trim())
          .filter(Boolean);
        if (!targets.length) return { ok: false, op, note: "rename needs target (id or Kohane name); pass an array to rename several at once" };
        const fn = String(args.function || "").trim();
        const explicit = String(args.name || "").trim();
        if (!fn && !explicit) return { ok: false, op, note: "rename needs function (a functional word) and/or name (a full replacement name)" };
        if (explicit && targets.length > 1) {
          return { ok: false, op, note: "an explicit name can only be applied to one target; use function with {n} for a batch (e.g. \"Meter {n}\")" };
        }
        if (targets.length > 1 && fn && !fn.includes("{n}") && !args.confirm) {
          return { ok: false, op, note: `renaming ${targets.length} entries to one word would collide; put {n} in function (e.g. "Meter {n}") or pass confirm:true` };
        }
        let current = pack;
        const applied = [];
        const refused = [];
        for (let i = 0; i < targets.length; i++) {
          const key = targets[i];
          const resolved = resolveKohanePlugins(current);
          const k = pluginKey(key);
          const hit = resolved.find((e) => e.id === key.toLowerCase() || e.name.toLowerCase() === key.toLowerCase())
            || resolved.find((e) => pluginKey(e.name) === k)
            || resolved.find((e) => pluginKey(e.function) === k);
          if (!hit) {
            refused.push({ target: key, reason: "no entry matches" });
            continue;
          }
          const next = normalizePluginPack(current);
          const anchor = hit.sourceKey ? next.entries.find((x) => pluginKey(x.localName) === hit.sourceKey) : null;
          const e = anchor || (() => {
            const fresh = { localName: `manual:${pluginSlug(hit.function || hit.name)}`, capability: hit.function, name: "", role: hit.role, kind: "capability", localCategory: "", localVersion: null, localFile: "", origin: "manual", note: "", updatedAt: null };
            next.entries.push(fresh);
            return fresh;
          })();
          // {n} numbers a batch in the order the targets were given: that is what turns a pile of
          // numbered fallbacks into chosen words without hand-editing each one.
          const word = fn ? fn.replace(/\{n\}/g, String(i + 1)) : "";
          if (word) e.capability = word.slice(0, 40);
          if (explicit) e.name = explicit.slice(0, 80);
          if (args.note) e.note = String(args.note).slice(0, 200);
          e.updatedAt = new Date().toISOString();
          const want = derivedKohaneName({ ...e, function: e.capability }, next.brand);
          if (!args.confirm && kohaneNameTaken(resolved, want, e.localName)) {
            refused.push({ target: key, reason: `"${want}" is already taken` });
            continue;
          }
          current = next;
          applied.push({ from: hit.name, to: want });
        }
        if (!applied.length) {
          return { ok: false, op, note: `nothing renamed (${refused.map((r) => r.target + ": " + r.reason).join("; ")})` };
        }
        const saved = savePluginPack(current);
        const after = resolveKohanePlugins(saved);
        const last = applied[applied.length - 1].to;
        appendLog({ op: "plugin-rename", type: "plugin", name: last, source: "local", disposition: null, detail: `${applied.length} capability(ies) renamed, last: ${last}` });
        return {
          ok: true, op, file: packFile, renamed: applied.length, applied, refused,
          entry: applied.length === 1 ? brief(after.find((e) => e.name === last) || after[0]) : undefined,
          note: applied.length === 1 ? `renamed "${applied[0].from}" -> "${applied[0].to}"` : `renamed ${applied.length} entries; ${refused.length} refused`,
        };
      }

      if (op === "export-links" || op === "import-links") {
        // The local link table is what makes the directory true for THIS machine. Carrying it to
        // another one is a deliberate act: export writes plain JSON or a sealed envelope, and import
        // merges by observed name without overwriting an existing link unless asked.
        const file = args.path ? String(args.path) : path.join(libraryDir(), "links.json");
        if (op === "export-links") {
          const payload = {
            version: 1, brand: pack.brand, generatedAt: new Date().toISOString(),
            links: (pack.entries || []).map((e) => ({
              localName: e.localName, capability: e.capability, name: e.name, role: e.role, kind: e.kind,
              localCategory: e.localCategory, localVersion: e.localVersion, localFile: e.localFile,
              origin: e.origin, note: e.note,
            })),
          };
          const body = args.passphrase
            ? JSON.stringify(sealWithPassphrase(String(args.passphrase), payload))
            : JSON.stringify(payload, null, 2);
          fs.mkdirSync(path.dirname(file), { recursive: true });
          fs.writeFileSync(file, body, "utf8");
          appendLog({ op: "plugin-export-links", type: "plugin", name: path.basename(file), source: "local", disposition: null, detail: `exported ${payload.links.length} link(s)${args.passphrase ? " (sealed)" : ""}` });
          return { ok: true, op, file, links: payload.links.length, sealed: !!args.passphrase, bytes: Buffer.byteLength(body), note: args.passphrase ? "sealed with the passphrase you supplied; the same passphrase opens it on the other machine" : "plain JSON: every local observation is in it, so treat the file accordingly" };
        }
        if (!fs.existsSync(file)) return { ok: false, op, note: `no link file at ${file}` };
        let raw;
        try {
          raw = JSON.parse(fs.readFileSync(file, "utf8"));
        } catch (e) {
          return { ok: false, op, note: `unreadable link file: ${String(e && e.message || e)}` };
        }
        if (raw && raw.v === 1 && raw.ct) {
          if (!args.passphrase) return { ok: false, op, note: "that link file is sealed; pass passphrase" };
          const opened = unsealWithPassphrase(String(args.passphrase), raw);
          if (!opened || opened.__unsealError) return { ok: false, op, note: "unseal failed (wrong passphrase or corrupted file)" };
          raw = opened;
        }
        const links = Array.isArray(raw && raw.links) ? raw.links : [];
        if (!links.length) return { ok: false, op, file, note: "that file carries no links" };
        const next = normalizePluginPack(pack);
        const byKey = new Map(next.entries.map((e) => [pluginKey(e.localName), e]));
        let added = 0, updated = 0, skipped = 0;
        for (const l of links) {
          const localName = String((l && l.localName) || "").trim();
          if (!localName) continue;
          const key = pluginKey(localName);
          const row = {
            localName, capability: String(l.capability || "").slice(0, 40), name: String(l.name || "").slice(0, 80),
            role: KOHANE_PLUGIN_ROLES[l.role] ? l.role : "", kind: String(l.kind || "plugin").slice(0, 24),
            localCategory: String(l.localCategory || "").slice(0, 80), localVersion: l.localVersion ? String(l.localVersion).slice(0, 40) : null,
            localFile: String(l.localFile || "").slice(0, 260), origin: "discovered",
            note: String(l.note || "").slice(0, 200), updatedAt: new Date().toISOString(),
          };
          const hit = byKey.get(key);
          if (hit && !args.confirm) {
            skipped++;
            continue;
          }
          if (hit) {
            Object.assign(hit, row);
            updated++;
            continue;
          }
          next.entries.push(row);
          byKey.set(key, row);
          added++;
        }
        const saved = savePluginPack(next);
        appendLog({ op: "plugin-import-links", type: "plugin", name: path.basename(file), source: "local", disposition: null, detail: `imported links: +${added}, ~${updated}, skipped ${skipped}` });
        return { ok: true, op, file, added, updated, skipped, total: resolveKohanePlugins(saved).length, note: skipped ? `${skipped} existing link(s) left alone; pass confirm:true to overwrite them` : "links merged" };
      }

      if (op === "brand") {
        const entries = resolveKohanePlugins(pack);
        const brand = String(args.brand || "").trim();
        if (!brand) {
          return { ok: true, op, file: packFile, brand: pack.brand, sample: entries.slice(0, 6).map((e) => e.name), note: "no brand given: this is the current family name" };
        }
        const next = normalizePluginPack(pack);
        next.brand = brand.slice(0, 60);
        next.entries = next.entries.map((e) => ({ ...e }));
        const saved = savePluginPack(next);
        const after = resolveKohanePlugins(saved);
        // A renamed entry stores the name the brand was applied to, so a brand change would not
        // reach the numbered ones; re-derive the plain ones from their capability word.
        appendLog({ op: "plugin-brand", type: "plugin", name: saved.brand, source: "local", disposition: null, detail: `capability family renamed to ${saved.brand}` });
        return {
          ok: true, op, file: packFile, brand: saved.brand, total: after.length,
          personalised: after.filter((e) => e.renamed).length,
          sample: after.slice(0, 6).map((e) => e.name),
          note: `every capability that was not personalised by hand now reads "${saved.brand} <functional word>"`,
        };
      }

      if (op === "provenance") {
        // The only path that shows third-party names: local cross-check of ONE entry, on request.
        const key = String(args.target || "").trim();
        if (!key) return { ok: false, op, note: "provenance needs target (id or Kohane name); it shows the local cross-check for one entry only" };
        const k = pluginKey(key);
        const entries = resolveKohanePlugins(pack);
        const hit = entries.find((e) => e.id === key.toLowerCase() || e.name.toLowerCase() === key.toLowerCase()) || entries.find((e) => pluginKey(e.name) === k || pluginKey(e.function) === k);
        if (!hit) return { ok: false, op, note: `no entry matches "${key}"` };
        const rows = hit.sourceKey
          ? (pack.entries || []).filter((e) => pluginKey(e.localName) === hit.sourceKey)
          : [];
        return {
          ok: true, op, entry: { id: hit.id, name: hit.name, function: hit.function, role: hit.role },
          localCount: rows.length,
          local: rows.map((e) => ({ name: e.localName, kind: e.kind, category: e.localCategory || null, version: e.localVersion || null, file: e.localFile || null })),
          note: "local cross-check data, kept on this machine only; it is deliberately absent from the directory, its exports and every other result",
        };
      }

      if (op === "remove") {
        const key = String(args.target || "").trim();
        if (!key) return { ok: false, op, note: "remove needs target" };
        const k = pluginKey(key);
        const resolved = resolveKohanePlugins(pack);
        const hit = resolved.find((e) => e.id === key.toLowerCase() || e.name.toLowerCase() === key.toLowerCase())
          || resolved.find((e) => pluginKey(e.name) === k || pluginKey(e.function) === k);
        if (!hit) return { ok: false, op, note: `no entry matches "${key}"` };
        const next = normalizePluginPack(pack);
        const before = next.entries.length;
        // A curated capability with no local link has nothing to drop: the directory is code, the
        // links are data.
        next.entries = next.entries.filter((e) => pluginKey(e.localName) !== pluginKey(`manual:${pluginSlug(hit.function)}`) && pluginKey(e.capability || "") !== pluginKey(hit.function));
        if (next.entries.length === before) {
          return { ok: false, op, note: `"${hit.name}" is a curated capability with no local link; it cannot be removed (use op=rename to re-purpose it)` };
        }
        const saved = savePluginPack(next);
        appendLog({ op: "plugin-remove", type: "plugin", name: hit.name, source: "local", disposition: null, detail: `dropped ${before - next.entries.length} local link(s)` });
        return { ok: true, op, file: packFile, removed: before - next.entries.length, total: resolveKohanePlugins(saved).length, note: `dropped ${before - next.entries.length} local link(s); the capability directory is unaffected` };
      }

      if (op === "export") {
        const entries = resolveKohanePlugins(pack);
        const fmt = ["json", "ndjson", "md"].includes(String(args.format || "").toLowerCase()) ? String(args.format).toLowerCase() : "json";
        const out = args.path || path.join(libraryDir(), `plugins.${fmt}`);
        const row = (e) => ({ id: e.id, name: e.name, function: e.function, role: e.role, origin: e.origin, linked: e.linked || 0 });
        let body;
        if (fmt === "ndjson") {
          body = entries.map((e) => JSON.stringify(row(e))).join("\n") + "\n";
        } else if (fmt === "md") {
          body = [
            `# ${pack.brand} capability directory`,
            "",
            `Family brand: \`${pack.brand}\` - ${entries.length} capabilities. A capability is named for what it does; the local plugin that provides it is deliberately not part of this file.`,
            "",
            "| Kohane capability | role | functional word | origin | local links |",
            "|---|---|---|---|---|",
            ...entries.map((e) => `| ${e.name} | ${e.role} | ${e.function} | ${e.origin} | ${e.linked || 0} |`),
            "",
          ].join("\n");
        } else {
          body = JSON.stringify({ version: 2, brand: pack.brand, flagship: KOHANE_PLUGIN_FLAGSHIP, generatedAt: new Date().toISOString(), entries: entries.map(row) }, null, 2) + "\n";
        }
        fs.mkdirSync(path.dirname(out), { recursive: true });
        fs.writeFileSync(out, body, "utf8");
        appendLog({ op: "plugin-export", type: "plugin", name: path.basename(out), source: "local", disposition: null, detail: `exported ${entries.length} capabilities as ${fmt}` });
        return { ok: true, op, file: out, format: fmt, total: entries.length, bytes: Buffer.byteLength(body), note: "written locally; capability names only - the local side stays in the pack" };
      }

      return { ok: false, op, note: `unknown op "${args.op}", allowed: list, show, roles, unlinked, numbered, scan, discover, learn, add, remove, rename, brand, provenance, export, export-links, import-links` };
    }
  },

  {
    name: "library_sessions",
    description: "Read this machine's own harness sessions - the conversation store under $DSH_HOME/sessions (one compressed frame per record) plus any exported session-log ZIP archives found beside it. Use it to find what a past session decided, to pick up where one left off, or to record a session into the Library. op=list enumerates sessions and archive members from headers and titles only; op=read returns a structural summary unless content:true asks for text (bounded); op=tail decodes only the last frames; op=search scans frames for a phrase and returns snippets; op=record writes a session into the Library as a log object (the sensitive-content rule still applies); op=status reports what the store holds. Frames are located by the compression magic and decoded one at a time, so a torn tail is counted rather than guessed, and a runtime without a decoder says so instead of reporting an empty history. Every response carries the host timezone. This is a local read: nothing is uploaded and no session file is modified.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_sessions,
    async execute(args) {
      const op = String(args.op || "list").toLowerCase();
      const store = sessionsDir();
      if (!ZSTD_AVAILABLE) {
        return { ok: false, op, store, timezone: timezoneInfo(), note: "this runtime has no zstd decoder (node:zlib.zstdDecompressSync needs Node v22.15+/v23.8+), and sessions are stored compressed - the store cannot be read here" };
      }

      if (op === "status") {
        const exists = fs.existsSync(store);
        const { live, archives } = exists ? listSessionSources(store, 4000) : { live: [], archives: [] };
        let bytes = 0;
        for (const f of [...live, ...archives]) {
          try {
            bytes += fs.statSync(f).size;
          } catch {}
        }
        return {
          ok: true, op, store, exists, sessions: live.length, archives: archives.length, bytes,
          decoder: "zstd", timezone: timezoneInfo(),
          note: exists ? "session store readable" : "no session store under this DSH home",
        };
      }

      if (op === "list") {
        const dir = path.resolve(args.dir ? String(args.dir) : store);
        if (!fs.existsSync(dir)) return { ok: false, op, dir, timezone: timezoneInfo(), note: `not a directory: ${dir}` };
        const maxFiles = Math.min(Math.max(Number(args.maxFiles) || 200, 1), 4000);
        const wantTitles = args.titles !== false;
        const { live, archives } = listSessionSources(dir, maxFiles);
        const entries = [];
        for (const file of live.slice(0, maxFiles)) {
          let st = null;
          try {
            st = fs.statSync(file);
          } catch {
            continue;
          }
          // A title lives in the first records, so only the head of the file is decoded for a list.
          let head = null;
          try {
            const fd = fs.openSync(file, "r");
            const want = Math.min(st.size, 262144);
            const buf = Buffer.alloc(want);
            const got = fs.readSync(fd, buf, 0, want, 0);
            fs.closeSync(fd);
            head = buf.subarray(0, got);
          } catch {}
          let header = {}, title = "", frames = 0, failed = 0;
          if (head) {
            const d = decodeSessionBuffer(head, { maxRecords: wantTitles ? 4000 : 1, maxChars: 4 * 1024 * 1024 });
            frames = d.frames;
            failed = d.failed;
            const first = d.records.find((r) => r && r.type === "session");
            if (first) header = sessionHeader(first);
            if (wantTitles) title = sessionTitle(d.records);
          }
          entries.push({
            session: path.relative(dir, file) || path.basename(file),
            bytes: st.size,
            modified: new Date(st.mtimeMs).toISOString(),
            frames, failed, header, title,
          });
        }
        entries.sort((a, b) => String(b.modified).localeCompare(String(a.modified)));
        const archiveEntries = archives.slice(0, 40).map((file) => {
          let names = [];
          let size = 0;
          try {
            size = fs.statSync(file).size;
            names = zipEntryNames(fs.readFileSync(file), 400).filter((n) => /\.jsonl(\.zstd)?$/i.test(n));
          } catch {}
          return { archive: path.basename(file), bytes: size, members: names.slice(0, 40), memberCount: names.length };
        });
        return {
          ok: true, op, dir, store, sessions: live.length, archives: archives.length,
          entries, archivesDetail: archiveEntries,
          preview: entries.slice(0, 20).map((e) => `${String(e.modified).slice(0, 16)}  ${String(e.title || "(no title)").slice(0, 64)}`).join("\n"),
          timezone: timezoneInfo(),
          note: wantTitles ? "titles read from each session's first records; no transcript text is returned" : "titles skipped",
        };
      }

      if (op === "read" || op === "tail") {
        const resolved = resolveSessionTarget(args.target, args.dir);
        if (!resolved.ok) return { ok: false, op, timezone: timezoneInfo(), note: resolved.note };
        const maxRecords = Math.min(Math.max(Number(args.maxRecords) || (op === "tail" ? 200 : 2000), 1), 200000);
        const maxChars = Math.min(Math.max(Number(args.maxChars) || 20000, 100), 400000);
        const opts = op === "tail"
          ? { lastFrames: Math.min(Math.max(Number(args.frames) || 40, 1), 2000), maxRecords, maxChars }
          : { maxRecords, maxChars, firstFrames: 0 };
        const read = readSessionTarget(resolved, opts);
        if (!read.ok) return { ok: false, op, timezone: timezoneInfo(), note: read.note, members: read.members };
        const summary = sessionSummary(read.records, { content: !!args.content, maxChars });
        return {
          ok: true, op, target: resolved.file || resolved.archive || null, kind: read.kind,
          bytes: read.bytes || null, frames: read.frames, failed: read.failed, truncated: !!read.truncated,
          header: summary.header, title: summary.title, records: summary.records, types: summary.types,
          timeRange: summary.timeRange, messages: summary.messages || [],
          timezone: timezoneInfo(),
          note: args.content
            ? "message text included, bounded by maxChars; a torn tail is counted, never guessed"
            : "structural summary only (pass content:true for message text)",
        };
      }

      if (op === "search") {
        const needle = String(args.query || "").trim();
        if (!needle) return { ok: false, op, timezone: timezoneInfo(), note: "search needs query" };
        const dir = path.resolve(args.dir ? String(args.dir) : store);
        if (!fs.existsSync(dir)) return { ok: false, op, dir, timezone: timezoneInfo(), note: `not a directory: ${dir}` };
        const maxFiles = Math.min(Math.max(Number(args.maxFiles) || 40, 1), 4000);
        const maxHits = Math.min(Math.max(Number(args.maxHits) || 40, 1), 500);
        const { live } = listSessionSources(dir, maxFiles);
        const lower = needle.toLowerCase();
        const hits = [];
        let searched = 0, failed = 0, truncated = false;
        for (const file of live.slice(0, maxFiles)) {
          if (hits.length >= maxHits) {
            truncated = true;
            break;
          }
          searched++;
          const read = readSessionTarget({ kind: "file", file }, { maxRecords: 20000, maxChars: 2 * 1024 * 1024 });
          if (!read.ok) {
            failed++;
            continue;
          }
          const title = sessionTitle(read.records);
          read.records.forEach((rec, index) => {
            if (hits.length >= maxHits) return;
            const text = JSON.stringify(rec);
            const at = text.toLowerCase().indexOf(lower);
            if (at < 0) return;
            hits.push({
              session: path.relative(dir, file) || path.basename(file),
              title,
              record: index,
              type: (rec && rec.type) || null,
              snippet: text.slice(Math.max(0, at - 80), at + needle.length + 120).replace(/\s+/g, " "),
            });
          });
        }
        return {
          ok: true, op, dir, query: needle, searched, found: hits.length, hits, timezone: timezoneInfo(),
          truncated: truncated || undefined,
          note: `scanned ${searched} session file(s), case-insensitive; snippets are the matched records, not full transcripts`,
        };
      }

      if (op === "record") {
        const resolved = resolveSessionTarget(args.target, args.dir);
        if (!resolved.ok) return { ok: false, op, timezone: timezoneInfo(), note: resolved.note };
        const wantContent = args.content !== false;
        const maxChars = Math.min(Math.max(Number(args.maxChars) || 4000, 200), 400000);
        const read = readSessionTarget(resolved, { maxRecords: 20000, maxChars: 4 * 1024 * 1024 });
        if (!read.ok) return { ok: false, op, timezone: timezoneInfo(), note: read.note, members: read.members };
        const summary = sessionSummary(read.records, { content: wantContent, maxChars });
        const type = String(args.type || "log");
        if (!OBJ_TYPES.has(type)) {
          return { ok: false, op, timezone: timezoneInfo(), note: `library_sessions: invalid type "${type}", allowed: ${[...OBJ_TYPES].join(", ")}` };
        }
        const name = (summary.title || path.basename(resolved.file || resolved.archive || "session")).slice(0, 120);
        const source = "session-store";
        const digest = [
          `records: ${summary.records}`,
          summary.header && summary.header.id ? `session: ${summary.header.id}` : null,
          summary.header && summary.header.cwd ? `cwd: ${summary.header.cwd}` : null,
          summary.timeRange ? `time: ${summary.timeRange.from} .. ${summary.timeRange.to}` : null,
          (summary.types || []).slice(0, 8).map((t) => `${t.type} x${t.count}`).join(", "),
          wantContent && summary.messages ? summary.messages.map((m) => `[${m.type}] ${m.text}`).join("\n") : "",
        ].filter(Boolean).join("\n").slice(0, maxChars);
        const obj = {
          id: makeId(type, source, name),
          type,
          name,
          source,
          path: resolved.file || resolved.archive || "",
          description: `session recorded from the local store (${summary.records} record(s))`,
          tags: ["session", "local"],
          summary: digest,
          related: [],
          createdAt: new Date().toISOString(),
        };
        const index = loadIndex();
        const sens = commitRecord(index, obj, dispositionFor(type), "session recorded from local store");
        return {
          ok: true, op, id: obj.id, name, type, records: summary.records, sensitive: sens,
          store: obj.path, timezone: timezoneInfo(),
          note: sens ? "session recorded (sensitive content detected, stored encrypted)" : "session recorded",
        };
      }

      return { ok: false, op, timezone: timezoneInfo(), note: `unknown op "${args.op}", allowed: list, read, tail, search, record, status` };
    }
  },


  {
    name: "library_decrypt",
    description:
      "Manually decrypt an encrypted-isolated sensitive object (sensitive:true). Call only when the user explicitly needs to read its content; never auto-decrypt in any query. Returns the decrypted full object; if the object is not sensitive it is returned as-is.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_decrypt,
    async execute(args) {
      const index = loadIndex();
      const rec = index.objects.find((o) => o.id === args.id);
      if (!rec) throw new Error(`library_decrypt: object id "${args.id}" not found`);
      // A sensitive object is stored as {..., __content: cipherObj}; only decrypt if __content exists.
      if (rec.__content && rec.__content.sens === 1) {
        const plain = decryptSensitive(rec.__content);
        if (plain && plain.__decryptError) {
          appendLog({ op: "decrypt", type: null, name: null, source: null, disposition: null, detail: `decrypt failed id=${args.id}` });
          return { ok: false, object: null, message: "decrypt failed (key mismatch or corrupted data)" };
        }
        appendLog({ op: "decrypt", type: null, name: null, source: null, disposition: null, detail: `manual decrypt id=${args.id}` });
        return { ok: true, object: plain };
      }
      return { ok: true, object: rec };
    },
  },
  {
    name: "library_export",
    description:
      "Export the Library to standard JSON (or NDJSON). Sensitive objects stay encrypted (__content is not decrypted), so no plaintext is included. For cross-machine migration, backup, or sharing with other environments. path optional; defaults to a timestamped export-*.json in the library directory.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_export,
    async execute(args) {
      const index = loadIndex();
      const format = args.format === "ndjson" ? "ndjson" : "json";
      // Sensitive objects are exported with their encrypted __content block intact (NOT
      // decrypted, NOT dropped), so a migrated library can still decrypt them later.
      const exportable = index.objects.map((o) => {
        if (o.__content) {
          const { sensitive, ...rest } = o;
          return { ...rest, sensitive: true, __content: o.__content };
        }
        return o;
      });
      const out = args.path || path.join(libraryDir(), `export-${Date.now()}.${format === "ndjson" ? "ndjson" : "json"}`);
      if (format === "ndjson") {
        fs.writeFileSync(out, exportable.map((o) => JSON.stringify(o)).join("\n") + "\n", "utf8");
      } else {
        fs.writeFileSync(out, JSON.stringify({ version: 1, generatedAt: new Date().toISOString(), objects: exportable }, null, 2), "utf8");
      }
      appendLog({ op: "export", type: null, name: null, source: null, disposition: null, detail: `exported ${exportable.length} objects to ${out}` });
      return { ok: true, file: out, count: exportable.length };
    },
  },
  {
    name: "library_encoding",
    description:
      "Detect the host's system default encoding and report compatibility plus region-aware indicative guidance (Japan/Korea/Southeast Asia/China-Taiwan/Europe/Latin America). The library always persists as UTF-8; if the system default is NOT UTF-8, external-tool output and file reads may mojibake. Use this to advise the user on how to set UTF-8 so the plugin works without mojibake.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_encoding,
    async execute() {
      const enc = detectSystemEncoding();
      const hints = enc.utf8
        ? [{ region: "all", note: "System default encoding is UTF-8; no adaptation needed." }]
        : INDICATIVE_ENCODING_HINTS.filter((h) => enc.codepage == null || h.codepages.includes(enc.codepage));
      appendLog({ op: "encoding", type: null, name: null, source: null, disposition: null, detail: `detected ${enc.label} (utf8=${enc.utf8})` });
      return { utf8: enc.utf8, codepage: enc.codepage, label: enc.label, hints };
    },
  },
  {
    name: "library_adb",
    description:
      "Manage an Android device over ADB (Android Debug Bridge) with legitimate developer operations only. Actions: devices, restart-server, reboot, reboot-recovery, reboot-bootloader, shell, info-system, info-cpu, info-memory, device-details, bugreport, install, uninstall, list-packages, logcat, push, pull, launch, screenshot, screenrecord, root-check, remote-connect. Requires USB debugging enabled on the device. Use on your own test device only.",
    inputSchema: TOOL_INPUT_SCHEMAS.library_adb,
    async execute(args) {
      const action = args.action;
      const cfg = ADB_ACTIONS[action];
      if (!cfg) {
        throw new Error(`library_adb: unknown action "${action}", allowed: ${Object.keys(ADB_ACTIONS).join(", ")}`);
      }
      for (const k of cfg.need || []) {
        if (!args[k]) throw new Error(`library_adb: action "${action}" requires "${k}"`);
      }
      const device = args.device || "";
      let result;
      if (cfg.restart) {
        // kill-server / start-server are global (no -s).
        const k = await runAdb(["kill-server"]);
        const s = await runAdb(["start-server"]);
        result = { ok: s.ok || k.ok, code: s.code || k.code, out: (k.out + "\n" + s.out).trim(), err: (k.err + "\n" + s.err).trim() };
      } else if (cfg.details) {
        const props = ["ro.product.model", "ro.product.brand", "ro.product.manufacturer", "ro.build.version.release", "ro.build.version.sdk", "ro.product.device"];
        let out = "";
        let ok = false;
        for (const p of props) {
          const r = await runAdb(["shell", "getprop", p], { device });
          if (r.ok) { ok = true; out += `${p}=${r.out.trim()}\n`; }
        }
        result = { ok, code: ok ? 0 : -1, out, err: ok ? "" : "no device property returned" };
      } else if (cfg.screenshot || cfg.screenrecord) {
        const isShot = !!cfg.screenshot;
        ensureLibrary();
        const remote = `/sdcard/kohane-index-${isShot ? "shot" : "rec"}-${Date.now()}.${isShot ? "png" : "mp4"}`;
        const secs = Math.min(Math.max(args.seconds || 10, 1), 180);
        const capArgs = isShot
          ? ["shell", "screencap", "-p", remote]
          : ["shell", "screenrecord", "--time-limit", String(secs), remote];
        const cap = await runAdb(capArgs, { device, timeoutMs: isShot ? 30000 : (secs + 10) * 1000 });
        if (!cap.ok) {
          result = cap;
        } else {
          const local = args.local || path.join(payloadDir(), `${isShot ? "shot" : "rec"}-${Date.now()}.${isShot ? "png" : "mp4"}`);
          const pull = await runAdb(["pull", remote, local], { device });
          await runAdb(["shell", "rm", remote], { device });
          result = { ok: pull.ok, code: pull.code, out: pull.out, err: pull.err, local };
        }
      } else {
        result = await runAdb(cfg.args(args), { device, timeoutMs: cfg.timeoutMs });
      }
      let recorded = false;
      if (args.record) {
        const index = loadIndex();
        const obj = {
          id: makeId("work_record", "adb", action),
          type: "work_record",
          name: `adb:${action}`,
          source: "adb",
          path: device || String(result.out || "").split("\n")[0].slice(0, 300),
          description: `adb ${action}${device ? " on " + device : ""}`,
          tags: ["adb", "android"],
          summary: String(result.out || result.err || "").slice(0, 2000),
          createdAt: new Date().toISOString(),
        };
        commitRecord(index, obj, "confirm", "adb operation record");
        recorded = true;
      }
      appendLog({ op: "adb", type: null, name: null, source: "adb", disposition: null, detail: `action=${action} device=${device || "(auto)"} ok=${result.ok}` });
      return { ok: result.ok, action, code: result.code, out: result.out, err: result.err, ...(result.local ? { local: result.local } : {}), recorded };
    },
  },
  {
    name: "analyze_object",
    description: "Unified external analysis entry: describe a file, directory or project by invoking the matching analyzer - Unity project structure (zero editor launch), Blender .blend header and optional scene statistics, media fingerprint (ffprobe/MediaInfo), and magic-byte type. Unity projects are analysed without launching the editor; Blender scene statistics need the Blender CLI and only run when deep:true. Prefer this over guessing what a path is.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        path: { type: "string", description: "Absolute path of the file, directory or project to analyse" },
        deep: { type: "boolean", description: "Opt into heavyweight analysis (e.g. launch the Blender CLI for scene statistics); default false" },
      },
      required: ["path"],
    },
    execute: (args) => analyzeObject(args.path, { deep: !!(args && args.deep) }),
  },
  {
    name: "library_environment",
    description: "Detect the current runtime environment: harness (mcp/cli), platform, system encoding, home directory, available tools (ffprobe/mediainfo/adb/uv...), library state, and signature coverage. Use this to know what this plugin can and cannot do here (e.g. missing media tools, encoding warnings).",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { harness: { type: "string", description: "Optional harness label; auto-detected if omitted" } },
    },
    execute: (args) => detectEnvironment({ harness: args && args.harness }),
  },
];

// Runtime environment self-awareness: detect the current harness (mcp/cli), platform, system
// encoding, home, available tools, library state, and signature coverage - so any agent
// framework knows what this plugin can and cannot do in the current environment.
function inferHarness() {
  const entry = String(process.argv?.[1] || "").toLowerCase();
  if (entry.includes("mcp") || entry.includes("modelcontextprotocol")) return "mcp";
  if (entry.includes("cli")) return "cli";
  if (process.env.DSH_HOME) return "dsh";
  return "unknown";
}

function detectEnvironment(env = {}) {
  const harness = env.harness || inferHarness();
  return {
    harness,
    platform: process.platform,
    encoding: detectSystemEncoding(),
    home: dshHome(),
    availableTools: DETECT_CANDIDATES
      .map((c) => ({ name: c.name, path: resolveCandidatePath(c) }))
      .filter((c) => c.path),
    library: { count: loadIndex().objects.length, file: indexFile() },
    signatureCount: FILE_SIGNATURES.length,
    textExtensionCount: TEXT_EXTENSIONS.length,
  };
}

// Safe-JSON stringify that tolerates circular references / BigInt so results always print.
function safeStringify(value, indent = 0) {
  const seen = new WeakSet();
  return JSON.stringify(
    value,
    (k, v) => {
      if (typeof v === "bigint") return String(v) + "n";
      if (v && typeof v === "object") {
        if (seen.has(v)) return "[Circular]";
        seen.add(v);
      }
      return v;
    },
    indent
  );
}

export {
  MAX_LEN, clampField,
  dshHome, libraryDir, indexFile, payloadDir,
  OBJ_TYPES, DISPOSITION, dispositionFor, fingerprint,
  MEDIA_PROVIDERS, registerDefaultMediaProvider, mediaFingerprint,
  ANALYZER_PROVIDERS, registerDefaultAnalyzer, analyzeObject, readBlendHeader, findUnityProjectRoot, decodeNativeContainer,
  KOHANE_PLUGIN_BRAND, KOHANE_PLUGIN_ROLES, KOHANE_CAPABILITIES, KOHANE_PLUGIN_FLAGSHIP,
  PLUGIN_FUNCTION_VOCAB, resolveKohanePlugins, pluginKey, pluginSlug, kohanePluginName, classifyPluginRole,
  extractFunctionWord, derivedFunctionWord, derivedKohaneName, kohaneNameTaken, pluginProvenance,
  duplicateKohaneNames, dedupeKohaneNames, pluginPackFile, loadPluginPack, savePluginPack, scanPluginDatabase,
  distinctPlugins, looksLikePluginDatabase, findPluginDatabase, pluginRoots, scanPluginInstallations,
  resolvePowerShell, dialogWorkDir,
  sha256File, walkEntries, recordPath, looksLikeFilePath, pathIsInside, isHollowObject, indexStatusOf, lastDiskFindings,
  sensitivityHits, isDriveRoot,
  sessionsDir, zstdFrameOffsets, timezoneInfo, decodeSessionBuffer, sessionHeader, sessionTitle,
  sessionText, sessionSummary, listSessionSources, resolveSessionTarget, readSessionTarget, ZSTD_AVAILABLE,
  collectPluginBinaries, readPluginBinary,
  runLocalAnalyzer, localAnalyzerMatches,
  appendLog,
  runSilent, resolveTool,
  adbPath, runAdb, ADB_ACTIONS,
  INDICATIVE_ENCODING_HINTS, detectSystemEncoding, detectSystemEncodingSync,
  FILE_SIGNATURES, readHeader, sniffFileType, TEXT_EXTENSIONS, NATIVE_CONTAINER_FORMATS, NATIVE_SIGNATURES, NATIVE_TEXT_EXTENSIONS,
  DETECT_CANDIDATES, resolveCandidatePath,
  SENSITIVE_PATTERNS, isSensitive, keyFile, masterFile,
  getMasterSecret, getOrCreateKey, encryptSensitive, decryptSensitive,
  sealWithPassphrase, unsealWithPassphrase, KEY_INFO, KEY_INFO_LEGACY, SEAL_INFO, SEAL_INFO_LEGACY,
  storeObject, commitRecord, ensureLibrary, loadIndex, saveIndex, makeId,
  TOOLS, TOOL_INPUT_SCHEMAS, safeStringify, detectEnvironment, inferHarness,
  PLUGIN_VERSION,
};

// Every tool's input closes its key set: an unknown key is a mistake, not an extension point. It is
// enforced here rather than repeated on each schema, so a tool added later cannot forget it.
for (const schema of Object.values(TOOL_INPUT_SCHEMAS)) {
  if (schema && schema.type === "object" && schema.additionalProperties === undefined) schema.additionalProperties = false;
}
for (const tool of TOOLS) {
  if (tool.inputSchema && tool.inputSchema.type === "object" && tool.inputSchema.additionalProperties === undefined) {
    tool.inputSchema.additionalProperties = false;
  }
}

// ---------- worker entry ----------
// A worker is this same module started with a marker: it stays resident and answers one chunk per
// message. Keeping it last means every helper above is already defined.
if (!isMainThread && workerData && workerData.kbWorker) {
  parentPort.on("message", (message) => {
    try {
      const results = (message.items || []).map((item) => runWorkerTask(workerData.kbWorker, item));
      parentPort.postMessage({ id: message.id, results });
    } catch (e) {
      parentPort.postMessage({ id: message.id, results: [], error: String((e && e.message) || e) });
    }
  });
}
