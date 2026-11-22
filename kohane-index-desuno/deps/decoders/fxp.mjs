// FL preset chunks (.fxp / .fxb), read natively - the index view.
//
// A Fruity preset file is a CcnK block holding an FPCh chunk: plugin id (4 chars), a preset name
// (u32be length + bytes), then the plugin's own parameter body. Different plugins put different
// things in the body, but the indexable facts - which plugin, which name, how big the body is -
// are in the same place for every plugin, and those facts are what a preset library index is made
// of. The body is reported by offset and length; interpreting parameters is per-plugin work that
// belongs elsewhere.
export const capabilities = {
  id: "fxp",
  kohaneName: "Kohane Bassline Preset Reader (FL)",
  container: "fxp/fxb",
  read: { level: "metadata", detail: "the CcnK/FPCh envelope: plugin id, preset name, and the parameter body offset and size" },
  decode: { level: "none", detail: "the parameter body is plugin-specific and is reported, not interpreted" },
  encode: { level: "none", detail: "writing presets is not a goal" },
  verifiedAgainst: "a synthesised FPCh whose values were chosen in advance, plus real Sylenth1 and Darbuka presets where present",
};

import fs from "node:fs";

export function parseFpch(buf) {
  if (buf.length < 28 || buf.toString("latin1", 0, 4) !== "CcnK") throw new Error("not a FL preset (no CcnK envelope)");
  const kind = buf.toString("latin1", 8, 12);
  if (kind !== "FPCh" && kind !== "FBCh") throw new Error(`not a FL preset (no FPCh/FBCh chunk, saw ${kind})`);
  const envelopeSize = buf.readUInt32BE(4);
  const plugin = buf.toString("latin1", 16, 20);
  // The name is a NUL-terminated string; the u32 before it is plugin-specific bookkeeping, not a
  // name length (real Sylenth1 and Darbuka presets proved that by carrying parameters inside the
  // field). The three indexable facts are plugin, name, and file size - the parameter body is
  // reported as the rest, not interpreted.
  let nameEnd = 28;
  while (nameEnd < buf.length && nameEnd < 28 + 512 && buf[nameEnd] !== 0) nameEnd++;
  const name = buf.toString("latin1", 28, nameEnd);
  const bodyAt = nameEnd + 1;
  const bodyBytes = Math.max(0, Math.min(buf.length, envelopeSize + 8) - bodyAt);
  return { kind: kind === "FBCh" ? "bank" : "preset", plugin, name, nameBytes: nameEnd - 28, bodyAt, bodyBytes, fileBytes: buf.length };
}

export function readFxp(file) {
  return Object.assign({ container: "fxp", path: file }, parseFpch(fs.readFileSync(file)));
}
