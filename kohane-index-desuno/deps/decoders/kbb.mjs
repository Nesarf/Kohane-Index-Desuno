// Kohane's instrument bank (.kbb): a SoundFont converted into kohane's own containers.
//
// The design (research/notes/2026-10-15-kpb-design.md) says third-party formats are read as input
// and kohane stores itself in its own containers, so this module turns .sf2 into .kbb: every
// preset's zones are enumerated with their key and velocity ranges, loop points and root key, and
// the sample PCM is deduplicated by content hash and stored as .kba (ADPCM by default, after an
// honest 2:1 downsample when the source rate allows). Nothing third-party survives the conversion -
// the bank alone must be enough to enumerate every instrument's samples, key ranges and loops.
import fs from "node:fs";
import { createHash } from "node:crypto";
import { readSf2 } from "./sf2.mjs";
import { encodeKba, downsample2 } from "./kba.mjs";

const GEN = { instrument: 41, keyRange: 43, velRange: 44, startLoopOffset: 45, endLoopOffset: 46, sampleID: 53, sampleModes: 54 };

function rangeOf(amount) {
  return { lo: amount & 0xff, hi: (amount >> 8) & 0xff };
}

function gensOf(genTable, bag, count) {
  const out = {};
  for (let i = 0; i < count && bag + i < genTable.length; i++) {
    const g = genTable[bag + i];
    if (g && g.oper !== 0) out[g.oper] = g.amount;
  }
  return out;
}

/** Convert a .sf2 file into a .kbb document (as a plain object, not yet serialised). */
export function convertSf2ToKbb(file, options = {}) {
  const font = readSf2(file);
  if (!font.samples.length) throw new Error("the SoundFont declares no samples");
  if (font.smplAt === null) throw new Error("the SoundFont carries no sample data (no smpl chunk)");
  const targetRate = Number(options.targetRate) || 22050;
  const tier = String(options.tier || "adpcm");
  const buf = fs.readFileSync(file);

  // walk preset zones -> instrument zones, collecting (sample, key range, velocity, loop) per zone
  const zones = [];
  for (let pi = 0; pi < font.presets.length; pi++) {
    const p = font.presets[pi];
    const next = pi + 1 < font.presets.length ? font.presets[pi + 1].bagIndex : font.pbags.length;
    for (let b = p.bagIndex; b < next && b < font.pbags.length; b++) {
      // Real fonts vary on genCount: the spec-faithful write the count, some editors write 0 and
      // leave the count as the gap to the next bag's genIndex. Take the count when present, the
      // gap otherwise - and a bag with no generators at all is the terminator, not a zone.
      const gap = (b + 1 < font.pbags.length ? font.pbags[b + 1].genIndex : font.pgens.length) - font.pbags[b].genIndex;
      const genCount = font.pbags[b].genCount || gap;
      if (genCount <= 0) continue;
      const pg = gensOf(font.pgens, font.pbags[b].genIndex, genCount);
      const keyRange = pg[GEN.keyRange] !== undefined ? rangeOf(pg[GEN.keyRange]) : { lo: 0, hi: 127 };
      const velRange = pg[GEN.velRange] !== undefined ? rangeOf(pg[GEN.velRange]) : { lo: 0, hi: 127 };
      if (pg[GEN.instrument] === undefined) continue;   // a preset bag that names no instrument is not a zone
      const instIdx = pg[GEN.instrument];
      const inst = font.instruments[instIdx];
      if (!inst) continue;
      const inext = instIdx + 1 < font.instruments.length ? font.instruments[instIdx + 1].bagIndex : font.ibags.length;
      for (let ib = inst.bagIndex; ib < inext && ib < font.ibags.length; ib++) {
        const igap = (ib + 1 < font.ibags.length ? font.ibags[ib + 1].genIndex : font.igens.length) - font.ibags[ib].genIndex;
        const igenCount = font.ibags[ib].genCount || igap;
        if (igenCount <= 0) continue;
        const ig = gensOf(font.igens, font.ibags[ib].genIndex, igenCount);
        const sampleIdx = ig[GEN.sampleID] ?? 0;
        const s = font.samples[sampleIdx];
        if (!s) continue;
        const k = ig[GEN.keyRange] !== undefined ? rangeOf(ig[GEN.keyRange]) : keyRange;
        const v = ig[GEN.velRange] !== undefined ? rangeOf(ig[GEN.velRange]) : velRange;
        const loopMode = ig[GEN.sampleModes] ?? 0;
        const startLoop = s.startLoop + (ig[GEN.startLoopOffset] !== undefined ? (ig[GEN.startLoopOffset] << 16 >> 16) * 2 : 0);
        const endLoop = s.endLoop + (ig[GEN.endLoopOffset] !== undefined ? (ig[GEN.endLoopOffset] << 16 >> 16) * 2 : 0);
        zones.push({
          preset: pi, instrument: inst.name, instrumentIdx: instIdx, sample: sampleIdx,
          loKey: k.lo, hiKey: k.hi, velLo: v.lo, velHi: v.hi,
          rootKey: s.originalPitch + s.pitchCorrection,
          loopStart: Math.max(0, Math.floor((startLoop - s.start) / 2)),
          loopEnd: Math.min(Math.floor((s.end - s.start) / 2), Math.floor((endLoop - s.start) / 2)),
          loopMode,
        });
      }
    }
  }

  // extract and dedupe the sample PCM: identical bytes share one stored sample
  const unique = new Map();
  const samples = [];
  for (let i = 0; i < font.samples.length; i++) {
    const s = font.samples[i];
    const byteLen = Math.min(Math.max(0, s.end - s.start), buf.length - font.smplAt);
    const raw = buf.subarray(font.smplAt + s.start, font.smplAt + s.start + byteLen);
    const digest = createHash("sha256").update(raw).digest("hex");
    let rec = unique.get(digest);
    if (!rec) {
      // Read through the Buffer API rather than an Int16Array view: the file Buffer may sit at an
      // odd offset inside the pool Node hands out, and a typed-array view would then refuse to start.
      const frames = Math.floor(raw.length / 2);
      let pcm = new Int16Array(frames);
      for (let i = 0; i < frames; i++) pcm[i] = raw.readInt16LE(i * 2);
      let rate = s.sampleRate || targetRate;
      if (rate >= targetRate * 2) {
        pcm = downsample2(pcm);
        rate = Math.round(rate / 2);
      }
      const kba = encodeKba(pcm, { sampleRate: rate, channels: 1, tier });
      rec = { name: s.name, rate, frames: pcm.length, sha256: digest, kba: kba.toString("base64"), refs: [] };
      unique.set(digest, rec);
      samples.push(rec);
    }
    rec.refs.push(i);
  }

  const presets = font.presets.map((p, pi) => ({
    name: p.name, bank: p.bank, preset: p.preset,
    zones: zones.filter((z) => z.preset === pi).map((z) => ({
      instrument: z.instrument, loKey: z.loKey, hiKey: z.hiKey, velLo: z.velLo, velHi: z.velHi,
      sample: z.sample, rootKey: z.rootKey, loopStart: z.loopStart, loopEnd: z.loopEnd, loopMode: z.loopMode,
    })),
  }));

  const kbb = {
    format: "kohane-bank", version: 1,
    name: options.name || presets[0]?.name || "converted bank",
    sampleRate: targetRate, tier,
    presets, samples,
  };
  const kbbBytes = Buffer.byteLength(JSON.stringify(kbb), "utf8");
  return {
    kbb,
    report: {
      sourceBytes: font.size,
      kbbBytes,
      ratio: Math.round((kbbBytes / Math.max(1, font.size)) * 1000) / 1000,
      presets: font.presets.length,
      zones: zones.length,
      samples: font.samples.length,
      uniqueSamples: samples.length,
      deduped: font.samples.length - samples.length,
    },
  };
}

/** Validate and open a .kbb document; the kba payloads stay base64 (decoding is the audio tier's job). */
export function readKbb(buf) {
  let doc;
  try { doc = JSON.parse(Buffer.isBuffer(buf) ? buf.toString("utf8") : String(buf)); }
  catch { throw new Error("not a kohane bank (the bytes are not the container's JSON envelope)"); }
  if (!doc || doc.format !== "kohane-bank") throw new Error("not a kohane bank (missing the kohane-bank marker)");
  if (doc.version !== 1) throw new Error(`not a kohane bank (unknown version ${JSON.stringify(doc.version)})`);
  if (!Array.isArray(doc.presets)) throw new Error("not a kohane bank (presets is not a list)");
  if (!Array.isArray(doc.samples) || !doc.samples.length) throw new Error("not a kohane bank (no samples)");
  for (let i = 0; i < doc.samples.length; i++) {
    const s = doc.samples[i];
    if (!s || typeof s.kba !== "string" || !s.kba.length) throw new Error(`not a kohane bank (sample ${i} carries no kba payload)`);
  }
  return doc;
}

/** The design's acceptance question: can the bank alone enumerate instruments, key ranges and loops? */
export function kbbSummary(doc) {
  const zones = doc.presets.reduce((n, p) => n + (p.zones || []).length, 0);
  const keyRanges = zones > 0 && doc.presets.every((p) => (p.zones || []).every((z) => Number.isInteger(z.loKey) && Number.isInteger(z.hiKey)));
  const loops = zones > 0 && doc.presets.every((p) => (p.zones || []).every((z) => Number.isInteger(z.loopStart) && Number.isInteger(z.loopEnd)));
  return {
    presets: doc.presets.length, zones, samples: doc.samples.length, tier: doc.tier,
    enumerable: { keyRanges, loops, samples: doc.samples.length > 0 },
  };
}

export const capabilities = {
  id: "kbb",
  kohaneName: "Kohane Bassline Bank",
  container: "kbb",
  read: { level: "full", detail: "the bank document: presets, zones with key/velocity ranges and loop points, and the deduplicated sample payloads" },
  decode: { level: "none", detail: "a bank holds .kba payloads; decoding them is the audio container's job" },
  encode: { level: "full", detail: "converts a SoundFont into the bank: zone enumeration, content-hash deduplication, honest 2:1 downsampling, ADPCM by default" },
  verifiedAgainst: "the selfcheck kpb assets (stage 5) section: the real Romantic Tp.sf2 converts inside the 8%-20% volume window, deduplication keeps one payload per content hash, and the bank alone enumerates key ranges and loops",
};
