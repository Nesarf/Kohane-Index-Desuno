#!/usr/bin/env node
// KID's dependency layer, proved rather than asserted.
//
// The engine's core is pure Node, so "what does KID depend on" has a short and checkable answer: the
// manifest under deps/ plus the package's own declared dependency. This checker refuses three
// comfortable lies - an entry without a licence or a purpose, a shipped file whose bytes are not the
// ones recorded, and a bare import that no entry accounts for.
//
// Usage: node tools/check-deps.mjs
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PKG = path.join(ROOT, "kohane-index-desuno");
const MANIFEST = path.join(PKG, "deps", "manifest.json");
const problems = [];
const notes = [];

const sha256 = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

// 1. the manifest itself
if (!fs.existsSync(MANIFEST)) {
  console.error("check-deps: deps/manifest.json is missing");
  process.exit(1);
}
let manifest;
try {
  manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
} catch (e) {
  console.error(`check-deps: manifest does not parse (${String((e && e.message) || e)})`);
  process.exit(1);
}
if (manifest.manifestVersion !== 1) problems.push(`manifestVersion is ${manifest.manifestVersion}, expected 1`);
if (!Array.isArray(manifest.entries)) problems.push("manifest has no entries array");

const ids = new Set();
for (const entry of manifest.entries || []) {
  const label = entry.id || "(entry without an id)";
  if (!entry.id) problems.push("an entry has no id");
  if (ids.has(entry.id)) problems.push(`${label}: duplicate id`);
  ids.add(entry.id);
  if (!entry.kind) problems.push(`${label}: no kind`);
  if (!entry.licence) problems.push(`${label}: no licence recorded`);
  if (!entry.purpose) problems.push(`${label}: no purpose recorded - an unused dependency should be removed, not documented`);
  if (!Array.isArray(entry.usedBy) || entry.usedBy.length === 0) problems.push(`${label}: usedBy is empty`);

  if (entry.file) {
    const file = path.join(PKG, entry.file);
    if (!fs.existsSync(file)) {
      problems.push(`${label}: listed file does not exist (${entry.file})`);
      continue;
    }
    const bytes = fs.statSync(file).size;
    if (entry.bytes !== null && entry.bytes !== bytes) problems.push(`${label}: recorded ${entry.bytes} bytes, the file has ${bytes}`);
    const digest = sha256(file);
    if (entry.sha256 !== digest) problems.push(`${label}: recorded sha256 ${String(entry.sha256).slice(0, 12)}..., the file is ${digest.slice(0, 12)}...`);
  } else if (entry.path) {
    // A borrowed tool lives outside the package: it is looked up at run time, so an absent one is a
    // state to report, not a failure to blame - but if it IS there, its bytes must match the record.
    if (fs.existsSync(entry.path)) {
      const bytes = fs.statSync(entry.path).size;
      if (entry.bytes !== null && entry.bytes !== bytes) problems.push(`${label}: recorded ${entry.bytes} bytes, the tool is ${bytes}`);
      const digest = sha256(entry.path);
      if (entry.sha256 !== digest) problems.push(`${label}: recorded sha256 ${String(entry.sha256).slice(0, 12)}..., the tool is ${digest.slice(0, 12)}...`);
    } else {
      notes.push(`${label}: borrowed tool not present at the recorded path (${entry.path}) - the engine reports it as missing when asked for it`);
    }
  } else if (entry.sha256 !== null) {
    problems.push(`${label}: records a hash but names neither a packaged file nor an external path`);
  }
}

// 2. the planned section must not quietly become real: it states what is not decided yet
for (const item of manifest.planned || []) {
  if (!item.id || !item.purpose) problems.push("a planned item lacks an id or a purpose");
  if (item.state === undefined) problems.push(`${item.id}: planned item does not say what state it is in`);
}

// 3. the package's declared dependency set must match the manifest
let pkg;
try {
  pkg = JSON.parse(fs.readFileSync(path.join(PKG, "package.json"), "utf8"));
} catch (e) {
  problems.push(`package.json does not parse (${String((e && e.message) || e)})`);
}
const declared = Object.keys((pkg && pkg.dependencies) || {});
const registered = new Set((manifest.entries || []).filter((e) => e.kind === "library").map((e) => e.name));
for (const name of declared) {
  if (!registered.has(name)) problems.push(`package.json depends on ${name}, but the manifest has no entry for it`);
}

// 4. no bare import in shipped code that the manifest does not account for
// An import may name a subpath ("pkg/sub/entry.js"); what has to be declared is the PACKAGE, so
// compare the package part and let the rest be the entry point inside it.
const packageOf = (spec) => (spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0]);
const ALLOWED_BARE = new Set(["@modelcontextprotocol/sdk", ...registered]);
const shipped = [];
for (const dir of ["lib", "cli", "mcp", "deps"]) {
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(mjs|js)$/.test(e.name)) shipped.push(p);
    }
  };
  if (fs.existsSync(path.join(PKG, dir))) walk(path.join(PKG, dir));
}

for (const file of shipped) {
  const text = fs.readFileSync(file, "utf8");
  const rel = path.relative(PKG, file).split(path.sep).join("/");
  for (const m of text.matchAll(/(?:^|\n)\s*import\s+(?:[\s\S]*?\sfrom\s+)?["']([^"']+)["']/g)) {
    const spec = m[1];
    if (spec.startsWith("node:") || spec.startsWith(".") || spec.startsWith("/")) continue;
    if (spec.startsWith("file:")) continue;
    if (!ALLOWED_BARE.has(packageOf(spec))) problems.push(`${rel}: imports "${spec}" (package ${packageOf(spec)}), which no manifest entry accounts for`);
  }
  for (const m of text.matchAll(/require\(\s*["']([^"']+)["']\s*\)/g)) {
    const spec = m[1];
    if (spec.startsWith("node:") || spec.startsWith(".")) continue;
    if (!ALLOWED_BARE.has(packageOf(spec))) problems.push(`${rel}: requires "${spec}" (package ${packageOf(spec)}), which no manifest entry accounts for`);
  }
  // a runtime fetch is the one way a dependency could appear without ever being declared
  if (/https?:\/\/[^\s"']+/.test(text) && !/^\s*(\/\/|\*)/.test(text)) {
    const lines = text.split("\n").filter((l) => /https?:\/\//.test(l) && !/^\s*(\/\/|\*)/.test(l));
    for (const line of lines) problems.push(`${rel}: a URL appears outside a comment, and nothing may be fetched at runtime`);
  }
}

for (const n of notes) console.log(`  note: ${n}`);

if (problems.length) {
  console.log(`check-deps: ${problems.length} finding(s)`);
  for (const p of problems.slice(0, 30)) console.log("  " + p);
  process.exit(1);
}
console.log(
  `check-deps: OK - manifest v${manifest.manifestVersion} with ${(manifest.entries || []).length} entr(ies), ` +
  `${(manifest.planned || []).length} planned, ${notes.length} borrowed tool(s) absent, ${shipped.length} shipped script(s) with no unaccounted import and no runtime fetch`,
);
