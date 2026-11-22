// Generates the kb-media cross-check fixtures: the JS originals write the containers and record
// their own receipts and refusal sentences, so the Rust tests compare against the JS behavior
// itself rather than against a re-typed expectation.
//
//   node gen-kb-fixtures.mjs
//
// Outputs land in tests/fixtures/kbmedia/ and are committed with the crate.
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  writeKbs, readKbs, writeKbw, readKbw, writeKbv, readKbv, writeKbm, readKbm,
} from "../../kohane-index-desuno/deps/decoders/kb-media.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, "tests", "fixtures", "kbmedia");
mkdirSync(out, { recursive: true });

const write = (name, data) => writeFileSync(path.join(out, name), data);

// ---------------------------------------------------------------- the four containers

const score = {
  title: "fixture score",
  bpm: 148.5,
  key: "Am",
  sampleRate: 48000,
  wave: "saw",
  adsr: { a: 0.005, d: 0.12, s: 0.7, r: 0.3 },
  parts: ["lead", "bass", "pad"],
  instruments: { lead: "sd90-synth", bass: "lm4-kick" },
  notes: [
    { t: 0, dur: 0.5, pitch: 60, vel: 0.9, wave: "square" },
    { t: 0.5, dur: 0.25, pitch: 64 },
    { t: 1, dur: 1, pitch: 67, vel: 0.4 },
  ],
};
const wave = {
  sampleRate: 44100,
  frames: 1024.7,
  channelCount: 2,
  bucketSize: 512,
  buckets: [[-0.8, 0.1], [0.2, 0.9], [-1, -0.05]],
};
const view = {
  title: "fixture view",
  lanes: 3.5,
  octaveLines: [0, 12.4, -0.25, 24],
  palette: ["#39C5BB", "#FFF8E7", "#000000"],
};
const mix = {
  title: "fixture mix",
  sampleRate: 48000,
  tracks: [
    { name: "drums", gain: 0.8, pan: 1.7, route: "master", effects: [{ kind: "eq", note: "low shelf" }, { kind: "", note: "" }] },
    { name: "synth", gain: 1.2, pan: -0.4, route: "reverb", effects: [] },
  ],
  buses: [{ name: "reverb", gain: 0.6, effects: [{ kind: "delay", note: "dotted 8th" }] }],
  master: { gain: 0.9, effects: [] },
};

write("js-score.kbs", writeKbs(score));
write("js-wave.kbw", writeKbw(wave));
write("js-view.kbv", writeKbv(view));
write("js-mix.kbm", writeKbm(mix));

// The params the Rust writer takes: the same objects, as JSON.
write("score-params.json", Buffer.from(JSON.stringify(score)));
write("wave-params.json", Buffer.from(JSON.stringify(wave)));
write("view-params.json", Buffer.from(JSON.stringify(view)));
write("mix-params.json", Buffer.from(JSON.stringify(mix)));

// The JS readers' own receipts, for field-for-field (string-for-string) comparison.
write("js-read-kbs.json", Buffer.from(JSON.stringify(readKbs(writeKbs(score)))));
write("js-read-kbw.json", Buffer.from(JSON.stringify(readKbw(writeKbw(wave)))));
write("js-read-kbv.json", Buffer.from(JSON.stringify(readKbv(writeKbv(view)))));
write("js-read-kbm.json", Buffer.from(JSON.stringify(readKbm(writeKbm(mix)))));

// ---------------------------------------------------------------- tampered refusals

const tamper = (source, edit, name) => {
  const doc = JSON.parse(source.toString("utf8"));
  edit(doc);
  return Buffer.from(JSON.stringify(doc));
};

const refusals = [
  ["bad-note.kbs", tamper(writeKbs(score), (d) => { d.notes[1].pitch = 200; }), (b) => readKbs(b)],
  ["bad-velocity.kbs", tamper(writeKbs(score), (d) => { d.notes[0].vel = 2; }), (b) => readKbs(b)],
  ["bad-wave.kbs", tamper(writeKbs(score), (d) => { d.notes[0].wave = "flute"; }), (b) => readKbs(b)],
  ["notes-not-list.kbs", tamper(writeKbs(score), (d) => { d.notes = "nope"; }), (b) => readKbs(b)],
  ["bad-marker.kbs", tamper(writeKbs(score), (d) => { d.format = "kohane-other"; }), (b) => readKbs(b)],
  ["bad-version.kbs", tamper(writeKbs(score), (d) => { d.version = 2; }), (b) => readKbs(b)],
  ["bad-json.kbs", Buffer.from('{"format": "kohane-score",'), (b) => readKbs(b)],
  ["empty-buckets.kbw", tamper(writeKbw(wave), (d) => { d.buckets = []; }), (b) => readKbw(b)],
  ["bad-bucket.kbw", tamper(writeKbw(wave), (d) => { d.buckets[0] = [0.5, -0.5]; }), (b) => readKbw(b)],
  ["bad-rate.kbw", tamper(writeKbw(wave), (d) => { d.sampleRate = 0; }), (b) => readKbw(b)],
  ["bad-lanes.kbv", tamper(writeKbv(view), (d) => { d.lanes = 0; }), (b) => readKbv(b)],
  ["palette-not-list.kbv", tamper(writeKbv(view), (d) => { d.palette = {}; }), (b) => readKbv(b)],
  ["unknown-route.kbm", tamper(writeKbm(mix), (d) => { d.tracks[0].route = "missing"; }), (b) => readKbm(b)],
  ["bad-track-gain.kbm", tamper(writeKbm(mix), (d) => { d.tracks[0].gain = -1; }), (b) => readKbm(b)],
  ["bad-pan.kbm", tamper(writeKbm(mix), (d) => { d.tracks[1].pan = 1.5; }), (b) => readKbm(b)],
  ["no-master.kbm", tamper(writeKbm(mix), (d) => { delete d.master; }), (b) => readKbm(b)],
  ["bad-master-gain.kbm", tamper(writeKbm(mix), (d) => { d.master.gain = -0.1; }), (b) => readKbm(b)],
];

for (const [name, bytes, reader] of refusals) {
  write(name, bytes);
  let message = "";
  try {
    reader(bytes);
    message = "(accepted - the reader did not refuse)";
  } catch (e) {
    message = e.message;
  }
  write(`${name}.err.txt`, Buffer.from(message, "utf8"));
}

console.log(`fixtures written to ${out}`);
