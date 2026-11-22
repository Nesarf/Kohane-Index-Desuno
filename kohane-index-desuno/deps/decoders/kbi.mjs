// Kohane's single-instrument container (.kbi): one patch, kohane's own words.
//
// The design (research/notes/2026-10-15-kpb-design.md) replaces a single .fxp preset or one
// SoundFont preset with a .kbi. What a patch IS - a name, a role in kohane's own vocabulary, and
// the parameters - is carried here; WHOSE patch it was is not, because a delivered kohane file
// carries no third-party product names. The parameter body is kept byte-faithful for now (the
// semantic mapping is per-plugin reverse-engineering work), with a recipe field reserved for the
// day the parameters are understood well enough to be written as a kohane synthesis recipe.
//
// Two preset file shapes convert in: the FL FPCh preset (CcnK envelope) and the plain four-char
// plugin id plus binary body (the FabFilter .ffp shape), whose name comes from the file name.
import fs from "node:fs";
import { parseFpch } from "./fxp.mjs";

export function writeKbi(instrument = {}) {
  const name = typeof instrument.name === "string" && instrument.name ? instrument.name : "untitled instrument";
  const role = typeof instrument.role === "string" && instrument.role ? instrument.role : "unknown";
  const body = {
    name,
    kind: instrument.kind === "bank" ? "bank" : "preset",
    role,
    source: typeof instrument.source === "string" && instrument.source ? instrument.source : "preset",
    params: typeof instrument.params === "string" ? instrument.params : "",
    paramBytes: Number.isFinite(instrument.paramBytes) && instrument.paramBytes > 0 ? Math.round(instrument.paramBytes) : 0,
    recipe: instrument.recipe && typeof instrument.recipe === "object" ? instrument.recipe : undefined,
  };
  return Buffer.from(JSON.stringify({ format: "kohane-instrument", version: 1, ...body }), "utf8");
}

export function readKbi(buf) {
  let doc;
  try { doc = JSON.parse(Buffer.isBuffer(buf) ? buf.toString("utf8") : String(buf)); }
  catch { throw new Error("not a kohane instrument (the bytes are not the container's JSON envelope)"); }
  if (!doc || doc.format !== "kohane-instrument") throw new Error("not a kohane instrument (missing the kohane-instrument marker)");
  if (doc.version !== 1) throw new Error(`not a kohane instrument (unknown version ${JSON.stringify(doc.version)})`);
  if (typeof doc.name !== "string" || !doc.name) throw new Error("not a kohane instrument (no name)");
  if (typeof doc.params !== "string") throw new Error("not a kohane instrument (params is not a payload)");
  return {
    format: doc.format, version: doc.version,
    name: doc.name,
    kind: doc.kind === "bank" ? "bank" : "preset",
    role: typeof doc.role === "string" && doc.role ? doc.role : "unknown",
    source: typeof doc.source === "string" && doc.source ? doc.source : "preset",
    params: doc.params,
    paramBytes: Number.isFinite(doc.paramBytes) ? doc.paramBytes : 0,
    recipe: doc.recipe && typeof doc.recipe === "object" ? doc.recipe : undefined,
  };
}

/** Convert one preset file's bytes into a .kbi document; `role` is kohane's own classification
 *  (the caller decides it - this module never names a product), `name` overrides the file's own. */
export function convertPresetToKbi({ bytes, name, role = "unknown" }) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf.length >= 4 && buf.toString("latin1", 0, 4) === "CcnK") {
    const p = parseFpch(buf);
    const params = buf.subarray(p.bodyAt, p.bodyAt + p.bodyBytes);
    return {
      format: "kohane-instrument", version: 1,
      name: name || p.name || "untitled instrument",
      kind: p.kind === "bank" ? "bank" : "preset",
      role,
      source: p.kind === "bank" ? "fxb" : "fxp",
      params: params.toString("base64"),
      paramBytes: p.bodyBytes,
    };
  }
  // the plain four-char id + binary body shape: the id is the file's own word for itself, the
  // name is the file name, and everything after the id is the parameter body
  if (buf.length < 5) throw new Error("not a preset file (too short)");
  const id = buf.toString("latin1", 0, 4);
  if (!/^[\x20-\x7e]{4}$/.test(id)) throw new Error("not a preset file (no four-character id)");
  return {
    format: "kohane-instrument", version: 1,
    name: name || "untitled instrument",
    kind: "preset",
    role,
    source: "ffp",
    params: buf.subarray(4).toString("base64"),
    paramBytes: buf.length - 4,
  };
}

/** Convert every preset file under a directory; `roleOf(pluginId)` maps a plugin id to kohane's
 *  own classification. Returns facts, not files - writing is the caller's decision. */
export function convertPresetBatch(dir, { ext = ".fxp", maxFiles = 10000, roleOf = null } = {}) {
  const out = { files: 0, ok: 0, failed: 0, bytes: 0, paramBytes: 0, plugins: new Map(), failedNames: [] };
  const walk = (d) => {
    if (out.ok + out.failed >= maxFiles) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.ok + out.failed >= maxFiles) return;
      const p = d + "/" + e.name;
      if (e.isDirectory()) { walk(p); continue; }
      if (!e.name.toLowerCase().endsWith(ext)) continue;
      out.files++;
      try {
        const bytes = fs.readFileSync(p);
        const name = e.name.slice(0, -ext.length);
        const pluginId = bytes.length >= 4 && bytes.toString("latin1", 0, 4) === "CcnK" ? parseFpch(bytes).plugin : bytes.toString("latin1", 0, 4);
        const role = typeof roleOf === "function" ? roleOf(pluginId) : "unknown";
        const doc = convertPresetToKbi({ bytes, name, role });
        const rec = out.plugins.get(pluginId) || { count: 0, bytes: 0 };
        rec.count++; rec.bytes += bytes.length;
        out.plugins.set(pluginId, rec);
        out.bytes += bytes.length;
        out.paramBytes += doc.paramBytes;
        out.ok++;
      } catch (err) {
        out.failed++;
        if (out.failedNames.length < 5) out.failedNames.push(`${e.name}: ${String((err && err.message) || err)}`);
      }
    }
  };
  walk(dir);
  return out;
}

export const capabilities = {
  id: "kbi",
  kohaneName: "Kohane Bassline Instrument",
  container: "kbi",
  read: { level: "full", detail: "the instrument document: name, kind, kohane role, source format, and the parameter payload" },
  decode: { level: "none", detail: "a patch is parameters, not audio; the recipe field is reserved for the day the parameters are written as a kohane synthesis recipe" },
  encode: { level: "full", detail: "writes the .kbi document, and converts FL FPCh presets and four-char-id binary presets into it - with kohane's own role vocabulary, never a product name" },
  verifiedAgainst: "the selfcheck kbi preset conversion section: field round trips, FPCh and four-char-id conversions, foreign-byte refusal, and the real Sylenth1 and FabFilter corpora where present",
};
