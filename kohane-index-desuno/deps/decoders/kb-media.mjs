// Kohane's own media containers: the .kbs score, .kbw wave envelope and .kbv view layout.
//
// These three are the "作编混" side of the .kb family - what kohane stores itself in, where
// third-party formats (MIDI, WAV, .sf2) are read as input and produced only as exports. The
// shapes follow the KPB design (research/notes/2026-10-15-kpb-design.md section 2):
//
//   .kbs  谱  tempo / key / parts / notes            replaces host-project semantics
//   .kbw  波  waveform envelope (min/max buckets)    shared by visualisation and mixing
//   .kbv  视  waterfall layout and palette            replaces the MIDIFall theme sheet
//
// All three share one envelope - { format, version } with a per-family marker - and are JSON
// documents. The readers are strict about what they accept: a file that is not the container
// fails with the container's own name ("not a kohane score"), never a vague "unknown format",
// and a note list that fails shape checks is refused instead of being handed downstream.
//
// The score's note events use the same second-space shape as the synth (t/dur in seconds, pitch
// as a MIDI key), so a score read here replays through synthesize() with no conversion at all.
import { synthesize } from "./synth.mjs";

const MARKERS = {
  kbs: "kohane-score",
  kbw: "kohane-wave",
  kbv: "kohane-view",
  kbm: "kohane-mix",
};
const WAVES = ["sine", "square", "saw", "triangle", "noise"];

const isNum = (v) => typeof v === "number" && Number.isFinite(v);
const isStr = (v) => typeof v === "string";

function envelope(kind) {
  return { format: MARKERS[kind], version: 1 };
}

function open(buf, kind, what) {
  let doc;
  try { doc = JSON.parse(Buffer.isBuffer(buf) ? buf.toString("utf8") : String(buf)); }
  catch { throw new Error(`not a ${what} (the bytes are not the container's JSON envelope)`); }
  if (!doc || doc.format !== MARKERS[kind]) throw new Error(`not a ${what} (missing the ${MARKERS[kind]} marker)`);
  if (doc.version !== 1) throw new Error(`not a ${what} (unknown version ${JSON.stringify(doc.version)})`);
  return doc;
}

function seal(kind, body) {
  return Buffer.from(JSON.stringify(Object.assign(envelope(kind), body)), "utf8");
}

// ---------------------------------------------------------------- .kbs score

export function writeKbs(score = {}) {
  const notes = Array.isArray(score.notes) ? score.notes : [];
  const parts = Array.isArray(score.parts) ? score.parts.map(String) : [];
  const instruments = score.instruments && typeof score.instruments === "object" ? score.instruments : {};
  const body = {
    title: isStr(score.title) && score.title ? score.title : "untitled score",
    bpm: isNum(score.bpm) && score.bpm > 0 ? score.bpm : 120,
    key: isStr(score.key) && score.key ? score.key : "C",
    sampleRate: isNum(score.sampleRate) && score.sampleRate > 0 ? score.sampleRate : 44100,
    wave: WAVES.includes(score.wave) ? score.wave : "square",
    adsr: score.adsr && typeof score.adsr === "object" ? score.adsr : undefined,
    parts,
    instruments,
    notes,
  };
  return seal("kbs", body);
}

export function readKbs(buf) {
  const doc = open(buf, "kbs", "kohane score");
  const notes = Array.isArray(doc.notes) ? doc.notes : null;
  if (!notes) throw new Error("not a kohane score (notes is not a list)");
  for (let i = 0; i < notes.length; i++) {
    const n = notes[i];
    if (!n || typeof n !== "object" || !isNum(n.t) || !isNum(n.dur) || n.t < 0 || n.dur < 0 ||
        !Number.isInteger(n.pitch) || n.pitch < 0 || n.pitch > 127) {
      throw new Error(`not a kohane score (note ${i} is not a {t, dur, pitch} event)`);
    }
    if (n.vel !== undefined && (!isNum(n.vel) || n.vel < 0 || n.vel > 1)) {
      throw new Error(`not a kohane score (note ${i} velocity is not a 0..1 level)`);
    }
    if (n.wave !== undefined && !WAVES.includes(n.wave)) {
      throw new Error(`not a kohane score (note ${i} wave "${n.wave}" is not a kohane oscillator)`);
    }
  }
  return {
    format: doc.format, version: doc.version,
    title: isStr(doc.title) ? doc.title : "untitled score",
    bpm: isNum(doc.bpm) && doc.bpm > 0 ? doc.bpm : 120,
    key: isStr(doc.key) ? doc.key : "C",
    sampleRate: isNum(doc.sampleRate) && doc.sampleRate > 0 ? doc.sampleRate : 44100,
    wave: WAVES.includes(doc.wave) ? doc.wave : "square",
    adsr: doc.adsr && typeof doc.adsr === "object" ? doc.adsr : undefined,
    parts: Array.isArray(doc.parts) ? doc.parts.map(String) : [],
    instruments: doc.instruments && typeof doc.instruments === "object" ? doc.instruments : {},
    notes,
  };
}

/** Replay a .kbs score through the synth - the "the score plays back" half of the bundle's self-proof. */
export function replayKbs(buf, options = {}) {
  const score = readKbs(buf);
  const rendered = synthesize({
    sampleRate: options.sampleRate || score.sampleRate || 44100,
    notes: score.notes,
    wave: options.wave || score.wave,
    adsr: score.adsr || options.adsr,
  });
  return { score, rendered };
}

// ---------------------------------------------------------------- .kbw wave envelope

export function writeKbw(wave = {}) {
  const buckets = Array.isArray(wave.buckets) ? wave.buckets : [];
  const body = {
    sampleRate: isNum(wave.sampleRate) && wave.sampleRate > 0 ? wave.sampleRate : 44100,
    frames: isNum(wave.frames) && wave.frames >= 0 ? Math.round(wave.frames) : 0,
    channelCount: isNum(wave.channelCount) && wave.channelCount > 0 ? Math.round(wave.channelCount) : 1,
    bucketSize: isNum(wave.bucketSize) && wave.bucketSize > 0 ? Math.round(wave.bucketSize) : 512,
    buckets,
  };
  return seal("kbw", body);
}

export function readKbw(buf) {
  const doc = open(buf, "kbw", "kohane wave envelope");
  const buckets = Array.isArray(doc.buckets) ? doc.buckets : null;
  if (!buckets || !buckets.length) throw new Error("not a kohane wave envelope (buckets is empty)");
  if (!isNum(doc.sampleRate) || doc.sampleRate <= 0) throw new Error("not a kohane wave envelope (bad sample rate)");
  if (!isNum(doc.frames) || doc.frames < 0) throw new Error("not a kohane wave envelope (bad frame count)");
  if (!isNum(doc.bucketSize) || doc.bucketSize <= 0) throw new Error("not a kohane wave envelope (bad bucket size)");
  for (let i = 0; i < buckets.length; i++) {
    const b = buckets[i];
    if (!Array.isArray(b) || b.length !== 2 || !isNum(b[0]) || !isNum(b[1]) || b[0] > b[1] || b[0] < -1 || b[1] > 1) {
      throw new Error(`not a kohane wave envelope (bucket ${i} is not a [min, max] pair in -1..1)`);
    }
  }
  const coverage = buckets.length * doc.bucketSize;
  return {
    format: doc.format, version: doc.version,
    sampleRate: doc.sampleRate, frames: doc.frames,
    channelCount: isNum(doc.channelCount) && doc.channelCount > 0 ? Math.round(doc.channelCount) : 1,
    bucketSize: doc.bucketSize, buckets,
    coverage, coversAll: coverage >= doc.frames,
    durationSec: doc.frames / doc.sampleRate,
  };
}

// ---------------------------------------------------------------- .kbv view layout

export function writeKbv(view = {}) {
  const body = {
    title: isStr(view.title) && view.title ? view.title : "untitled view",
    lanes: isNum(view.lanes) && view.lanes > 0 ? Math.round(view.lanes) : 1,
    octaveLines: Array.isArray(view.octaveLines) ? view.octaveLines.filter(isNum).map(Math.round) : [],
    palette: Array.isArray(view.palette) ? view.palette.filter(isStr).map(String) : [],
  };
  return seal("kbv", body);
}

export function readKbv(buf) {
  const doc = open(buf, "kbv", "kohane view layout");
  if (!isNum(doc.lanes) || doc.lanes < 1) throw new Error("not a kohane view layout (lanes is not a positive count)");
  if (!Array.isArray(doc.palette)) throw new Error("not a kohane view layout (palette is not a list)");
  return {
    format: doc.format, version: doc.version,
    title: isStr(doc.title) ? doc.title : "untitled view",
    lanes: Math.round(doc.lanes),
    octaveLines: Array.isArray(doc.octaveLines) ? doc.octaveLines.filter(isNum).map(Math.round) : [],
    palette: doc.palette.map(String),
  };
}

// ---------------------------------------------------------------- .kbm mix

export function writeKbm(mix = {}) {
  const tracks = Array.isArray(mix.tracks) ? mix.tracks : [];
  const buses = Array.isArray(mix.buses) ? mix.buses : [];
  const cleanTrack = (t) => ({
    name: isStr(t.name) && t.name ? t.name : "track",
    gain: isNum(t.gain) ? t.gain : 1,
    pan: isNum(t.pan) ? Math.max(-1, Math.min(1, t.pan)) : 0,
    route: isStr(t.route) && t.route ? t.route : "master",
    effects: Array.isArray(t.effects) ? t.effects.map((f) => ({ kind: String(f.kind || "?"), note: isStr(f.note) ? f.note : undefined })) : [],
  });
  const cleanBus = (b) => ({
    name: isStr(b.name) && b.name ? b.name : "bus",
    gain: isNum(b.gain) ? b.gain : 1,
    effects: Array.isArray(b.effects) ? b.effects.map((f) => ({ kind: String(f.kind || "?"), note: isStr(f.note) ? f.note : undefined })) : [],
  });
  const master = mix.master && typeof mix.master === "object" ? mix.master : {};
  const body = {
    title: isStr(mix.title) && mix.title ? mix.title : "untitled mix",
    sampleRate: isNum(mix.sampleRate) && mix.sampleRate > 0 ? mix.sampleRate : 44100,
    tracks: tracks.map(cleanTrack),
    buses: buses.map(cleanBus),
    master: {
      gain: isNum(master.gain) ? master.gain : 1,
      effects: Array.isArray(master.effects) ? master.effects.map((f) => ({ kind: String(f.kind || "?"), note: isStr(f.note) ? f.note : undefined })) : [],
    },
  };
  return seal("kbm", body);
}

export function readKbm(buf) {
  const doc = open(buf, "kbm", "kohane mix");
  if (!Array.isArray(doc.tracks)) throw new Error("not a kohane mix (tracks is not a list)");
  if (!Array.isArray(doc.buses)) throw new Error("not a kohane mix (buses is not a list)");
  if (!doc.master || typeof doc.master !== "object") throw new Error("not a kohane mix (master is not an object)");
  const busNames = doc.buses.map((b) => String(b && b.name || ""));
  const tracks = doc.tracks.map((t, i) => {
    if (!t || typeof t !== "object") throw new Error(`not a kohane mix (track ${i} is not an object)`);
    const gain = t.gain;
    const pan = t.pan;
    if (gain !== undefined && (!isNum(gain) || gain < 0)) throw new Error(`not a kohane mix (track ${i} gain is not a level)`);
    if (pan !== undefined && (!isNum(pan) || pan < -1 || pan > 1)) throw new Error(`not a kohane mix (track ${i} pan is outside -1..1)`);
    const route = isStr(t.route) && t.route ? t.route : "master";
    if (route !== "master" && !busNames.includes(route)) throw new Error(`not a kohane mix (track ${i} routes to unknown bus "${route}")`);
    return {
      name: isStr(t.name) ? t.name : "track",
      gain: gain === undefined ? 1 : gain,
      pan: pan === undefined ? 0 : pan,
      route,
      effects: Array.isArray(t.effects) ? t.effects : [],
    };
  });
  const buses = doc.buses.map((b, i) => {
    if (!b || typeof b !== "object") throw new Error(`not a kohane mix (bus ${i} is not an object)`);
    if (b.gain !== undefined && (!isNum(b.gain) || b.gain < 0)) throw new Error(`not a kohane mix (bus ${i} gain is not a level)`);
    return {
      name: isStr(b.name) ? b.name : "bus",
      gain: b.gain === undefined ? 1 : b.gain,
      effects: Array.isArray(b.effects) ? b.effects : [],
    };
  });
  const master = doc.master;
  if (master.gain !== undefined && (!isNum(master.gain) || master.gain < 0)) throw new Error("not a kohane mix (master gain is not a level)");
  return {
    format: doc.format, version: doc.version,
    title: isStr(doc.title) ? doc.title : "untitled mix",
    sampleRate: isNum(doc.sampleRate) && doc.sampleRate > 0 ? doc.sampleRate : 44100,
    tracks, buses,
    master: { gain: master.gain === undefined ? 1 : master.gain, effects: Array.isArray(master.effects) ? master.effects : [] },
  };
}

// ---------------------------------------------------------------- registry face

const kbsCapabilities = {
  id: "kbs",
  kohaneName: "Kohane Bassline Score",
  container: "kbs",
  read: { level: "full", detail: "the score document: title, tempo, key, parts, instruments and the note list - note events in the synth's second space, so a read score replays directly" },
  decode: { level: "none", detail: "a score is data, not audio: the sound is generated by the synth, and the .kbw envelope describes any rendered waveform" },
  encode: { level: "full", detail: "writes the .kbs score document" },
  verifiedAgainst: "the selfcheck kpb media section: write/read round trip, replay frame counts, tampered-score refusal, and the bundle self-proof",
};

const kbwCapabilities = {
  id: "kbw",
  kohaneName: "Kohane Bassline Wave",
  container: "kbw",
  read: { level: "full", detail: "the waveform envelope document: sample rate, frame count, bucket size and the min/max bucket pairs - enough to draw the waveform" },
  decode: { level: "none", detail: "the envelope describes audio, it does not carry samples" },
  encode: { level: "full", detail: "writes the .kbw envelope document from min/max buckets" },
  verifiedAgainst: "the selfcheck kpb media section: write/read round trip, bucket coverage against the declared frame count",
};

const kbvCapabilities = {
  id: "kbv",
  kohaneName: "Kohane Bassline View",
  container: "kbv",
  read: { level: "full", detail: "the waterfall layout document: title, lane count, octave lines and the palette" },
  decode: { level: "none", detail: "a layout has no samples" },
  encode: { level: "full", detail: "writes the .kbv layout document" },
  verifiedAgainst: "the selfcheck kpb media section: write/read round trip, lane and palette checks",
};

const kbmCapabilities = {
  id: "kbm",
  kohaneName: "Kohane Bassline Mix",
  container: "kbm",
  read: { level: "full", detail: "the mix document: tracks with gain/pan/route, buses with gain, master gain, and the declared effect chains" },
  decode: { level: "none", detail: "a mix is instructions, not audio: the mixer renders stems through it (deps/decoders/mix.mjs)" },
  encode: { level: "full", detail: "writes the .kbm mix document" },
  verifiedAgainst: "the selfcheck kpb mix (stage 4) section: write/read round trip, route validation against declared buses, and the mixer's own verified judges",
};

export const capabilities = [kbsCapabilities, kbwCapabilities, kbvCapabilities, kbmCapabilities];
