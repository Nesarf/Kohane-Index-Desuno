// Kohane's mixer: gain, pan and bus routing over rendered stems - the "混" of the KPB.
//
// The split mirrors how the work is actually done: each stem (one track of the score) is rendered
// independently - in the worker pool, on its own core - and only the sum is linear work in one
// place. A track's gain and pan are applied per stem, the routed sums are gathered per bus, and the
// master gain closes the chain. Everything a .kbm declares beyond gain/pan is refused at render
// time instead of being silently ignored: the exported audio must equal the mix document, so a
// mix that names an effect this build cannot execute does not render at all.
//
// pan is equal-power: p in -1..1, 0 dead centre; -1 puts the stem fully left, +1 fully right.

export function panCoeffs(pan) {
  const p = Math.max(-1, Math.min(1, Number.isFinite(pan) ? pan : 0));
  return { panL: Math.cos((p + 1) * Math.PI / 4), panR: Math.sin((p + 1) * Math.PI / 4) };
}

/** The effects this build executes. Empty today: gain and pan are track fields, and every effect
 *  entry in a mix document is therefore refused - honesty over silence. */
export const implementedEffectKinds = new Set();

/** Throw unless every declared effect is one this build executes. */
export function assertRenderable(mix) {
  const walk = (label, holder) => {
    const effects = holder && Array.isArray(holder.effects) ? holder.effects : [];
    for (const fx of effects) {
      const kind = String((fx && fx.kind) || "?");
      if (!implementedEffectKinds.has(kind)) {
        throw new Error(`${label} declares effect "${kind}"${fx && fx.note ? ` (${fx.note})` : ""}, which this build does not execute - refusing rather than rendering something the mix does not say`);
      }
    }
  };
  for (const t of mix.tracks || []) walk(`track "${t.name}"`, t);
  for (const b of mix.buses || []) walk(`bus "${b.name}"`, b);
  walk("master", mix.master);
}

/**
 * Mix rendered stems into one interleaved stereo buffer.
 *
 * stems: [{ frames, l: Float32Array, r: Float32Array, route }] - route names a bus or "master".
 * mix:   { buses: [{ name, gain }], master: { gain } } - bus gain applied on the way in, master last.
 * Returns { frames, sampleRate, samples: Float32Array (LRLR...) }.
 */
export function mixStems(stems, mix, options = {}) {
  const sampleRate = Number(options.sampleRate) || 44100;
  const frames = stems.reduce((m, s) => Math.max(m, s.frames || 0), 0);
  const busGain = new Map((mix.buses || []).map((b) => [String(b.name), Number.isFinite(b.gain) ? b.gain : 1]));
  const masterGain = mix.master && Number.isFinite(mix.master.gain) ? mix.master.gain : 1;

  const outL = new Float32Array(frames);
  const outR = new Float32Array(frames);
  const busL = new Map();
  const busR = new Map();
  for (const name of busGain.keys()) {
    busL.set(name, new Float32Array(frames));
    busR.set(name, new Float32Array(frames));
  }
  for (const s of stems) {
    const n = Math.min(s.frames || 0, frames);
    const route = String(s.route || "master");
    const targetL = route === "master" ? outL : busL.get(route);
    const targetR = route === "master" ? outR : busR.get(route);
    if (!targetL) throw new Error(`track routed to unknown bus "${route}" (declared buses: ${[...busGain.keys()].join(", ") || "none"})`);
    for (let i = 0; i < n; i++) {
      targetL[i] += s.l[i];
      targetR[i] += s.r[i];
    }
  }
  for (const name of busGain.keys()) {
    const g = busGain.get(name);
    const l = busL.get(name);
    const r = busR.get(name);
    for (let i = 0; i < frames; i++) {
      outL[i] += l[i] * g;
      outR[i] += r[i] * g;
    }
  }
  const samples = new Float32Array(frames * 2);
  for (let i = 0; i < frames; i++) {
    samples[i * 2] = outL[i] * masterGain;
    samples[i * 2 + 1] = outR[i] * masterGain;
  }
  return { frames, sampleRate, samples, channels: 2 };
}

export const capabilities = {
  id: "mix",
  kohaneName: "Kohane Bassline Mixer",
  container: "kbm",
  read: { level: "full", detail: "the mix document: tracks with gain/pan/route, buses with gain, master gain, and the declared effect chains" },
  decode: { level: "full", detail: "renders stems into one interleaved stereo buffer through gain, equal-power pan, bus routing and master gain" },
  encode: { level: "full", detail: "writes the .kbm mix document" },
  verifiedAgainst: "the selfcheck kpb mix (stage 4) section: per-track gain matches the analytic signal sample for sample, pan extremes isolate channels, bus routing scales, the sum equals the parts, and undeclared effects are refused",
};
