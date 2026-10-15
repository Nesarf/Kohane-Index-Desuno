#!/usr/bin/env node
// The engine's measuring stick.
//
// A number without its conditions is not a measurement, so every run records the machine it ran on
// (cores, memory, node version, platform) and writes a baseline beside it. Operations are measured
// with a warm-up iteration first, because the first call in a process pays for module loading and
// caching - measuring that instead of the operation is the classic way to produce a useless baseline.
//
// Everything here is read-only against the real library: an isolated DSH_HOME is used, and the inputs
// are files the harness generates itself. Usage: node tools/bench.mjs [--json <path>]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const PKG = path.join(ROOT, "kohane-index-desuno");
const BASE_TMP = process.env.KOHANE_HARNESS_TMP || path.join("E:", "DaShaoHuo", "cache", "tmp");
const WORK = path.join(BASE_TMP, "kohane-bench");

fs.rmSync(WORK, { recursive: true, force: true });
fs.mkdirSync(WORK, { recursive: true });
process.env.DSH_HOME = path.join(WORK, "dsh");

const core = await import(pathToFileURL(path.join(PKG, "lib", "core.mjs")).href);
const tool = (name) => core.TOOLS.find((t) => t.name === name);

// ---------- inputs the harness makes for itself ----------
function makeWav(file, seconds, sampleRate = 44100, channels = 2) {
  const frames = seconds * sampleRate;
  const pcm = Buffer.alloc(frames * channels * 2);
  for (let i = 0; i < frames; i++) {
    const v = Math.round(Math.sin((2 * Math.PI * 440 * i) / sampleRate) * 12000);
    for (let c = 0; c < channels; c++) pcm.writeInt16LE(v, (i * channels + c) * 2);
  }
  const head = Buffer.alloc(44);
  head.write("RIFF", 0, "latin1");
  head.writeUInt32LE(36 + pcm.length, 4);
  head.write("WAVEfmt ", 8, "latin1");
  head.writeUInt32LE(16, 16);
  head.writeUInt16LE(1, 20);
  head.writeUInt16LE(channels, 22);
  head.writeUInt32LE(sampleRate, 24);
  head.writeUInt32LE(sampleRate * channels * 2, 28);
  head.writeUInt16LE(channels * 2, 32);
  head.writeUInt16LE(16, 34);
  head.write("data", 36, "latin1");
  head.writeUInt32LE(pcm.length, 40);
  fs.writeFileSync(file, Buffer.concat([head, pcm]));
  return file;
}

const oneWav = makeWav(path.join(WORK, "one.wav"), 10);
const many = [];
for (let i = 0; i < 12; i++) many.push(makeWav(path.join(WORK, `sweep-${String(i).padStart(2, "0")}.wav`), 5));
const png = path.join(WORK, "img.png");
fs.writeFileSync(png, Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(1024 * 1024)]));
const text = path.join(WORK, "note.txt");
fs.writeFileSync(text, "a plain text file for the signature path\n".repeat(4096));
const midi = "E:/hc-fl/kohane-yunooka-no-asa.mid";

// ---------- the measuring loop ----------
const results = [];
async function measure(name, iterations, fn, note = "") {
  await fn();                              // warm-up: pays for loading, so the numbers are the operation
  const times = [];
  for (let i = 0; i < iterations; i++) {
    const t0 = process.hrtime.bigint();
    await fn();
    times.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  times.sort((a, b) => a - b);
  const median = times[Math.floor(times.length / 2)];
  const min = times[0];
  results.push({ name, iterations, medianMs: Math.round(median * 100) / 100, minMs: Math.round(min * 100) / 100, note });
  console.log(`  ${name.padEnd(34)} median ${median.toFixed(2).padStart(8)} ms   min ${min.toFixed(2).padStart(8)} ms  ${note}`);
  return median;
}

console.log("engine benchmark");
console.log(`  machine: ${os.cpus().length} logical core(s), ${(os.totalmem() / 1024 ** 3).toFixed(1)} GB RAM, ${os.platform()} ${os.release()}`);
console.log(`  node: ${process.version}   inputs: ${WORK}`);
console.log("");

await measure("sniff: 1 MB png", 20, () => tool("library_sniff").execute({ path: png }));
await measure("sniff: 160 KB text", 20, () => tool("library_sniff").execute({ path: text }));
await measure("audio peaks: 10 s stereo wav", 10, () => tool("library_audio").execute({ op: "peaks", path: oneWav, buckets: 2000 }));
await measure("audio sweep: 12 files, all cores", 3, () => tool("library_audio").execute({ op: "sweep", dir: WORK }), `threads=${os.cpus().length}`);

if (fs.existsSync(midi)) {
  await measure("score: 13 parts, 3527 notes", 10, () => tool("library_audio").execute({ op: "score", path: midi }));
} else {
  console.log("  score: skipped (no midi input present)");
}

// the library side: records in an isolated store, then a query over them
const record = tool("library_record");
for (let i = 0; i < 40; i++) {
  await record.execute({ type: "file", name: `bench-${i}`, source: WORK, path: path.join(WORK, `sweep-${String(i % 12).padStart(2, "0")}.wav`), description: "benchmark fixture", tags: ["bench"] });
}
await measure("query: 40 records, 1 hit", 20, () => tool("library_query").execute({ query: "bench-37" }));
await measure("index verify: 40 records, pooled", 5, () => tool("library_index").execute({ op: "verify", batch: 40 }));

// the pool's own comparison: same work, one core versus all of them
const threadsAll = os.cpus().length;
const sweepAll = await measure("sweep: 12 files, all cores (repeat)", 3, () => tool("library_audio").execute({ op: "sweep", dir: WORK, threads: threadsAll }));
const sweepOne = await measure("sweep: 12 files, one core", 3, () => tool("library_audio").execute({ op: "sweep", dir: WORK, threads: 1 }));
const speedup = Math.round((sweepOne / sweepAll) * 100) / 100;

const baseline = {
  measuredAt: new Date().toISOString(),
  note: "measured on an interactive development machine, not a quiet one: compare runs on the same machine and treat the absolute values as indicative, the ratios as the useful part",
  conditions: {
    platform: `${os.platform()} ${os.release()}`,
    cpu: os.cpus()[0]?.model || "unknown",
    logicalCores: os.cpus().length,
    totalMemoryGB: Math.round((os.totalmem() / 1024 ** 3) * 10) / 10,
    node: process.version,
    threadsUsed: threadsAll,
  },
  results,
  ratios: { poolSpeedupOnSweep: speedup, poolOneCoreMs: Math.round(sweepOne * 100) / 100, poolAllCoresMs: Math.round(sweepAll * 100) / 100 },
};

const jsonAt = process.argv.includes("--json") ? process.argv[process.argv.indexOf("--json") + 1] : path.join(HERE, "bench-baseline.json");
fs.writeFileSync(jsonAt, JSON.stringify(baseline, null, 2) + "\n", "utf8");

console.log("");
console.log(`  pool: ${threadsAll} cores ${sweepAll.toFixed(2)} ms vs one core ${sweepOne.toFixed(2)} ms -> ${speedup}x`);
console.log(`  baseline written to ${jsonAt}`);
console.log(`  ${results.length} measurement(s); conditions recorded with them, because a number without them is not a measurement`);
