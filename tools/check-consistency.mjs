#!/usr/bin/env node
// Consistency proofread: documentation against code, tool/op wiring, counts, and the safety claims
// this package makes about itself (no network, no leftover debug output, no dangling markers).
// Dependency-free on purpose, so it can always run.
//
// Usage: node tools/check-consistency.mjs        (exit 1 on any finding)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PKG = path.join(ROOT, "kohane-index-desuno");
const SRC = path.join(PKG, "lib", "core.mjs");
const README = path.join(PKG, "README.md");
const CLI = path.join(PKG, "cli", "index.mjs");

const src = fs.readFileSync(SRC, "utf8");
const readme = fs.readFileSync(README, "utf8");
const cli = fs.readFileSync(CLI, "utf8");
const problems = [];
const m = await import(pathToFileURL(SRC).href);

// 1. the README documents exactly the registered tools
const names = m.TOOLS.map((t) => t.name);
for (const name of names) {
  if (!readme.includes(`\`${name}\``)) problems.push(`README.md does not document the tool ${name}`);
}
const documented = [...readme.matchAll(/^- `([a-z_]+)` - /gm)].map((x) => x[1]);
for (const doc of documented) {
  if (!names.includes(doc)) problems.push(`README.md documents a tool that is not registered: ${doc}`);
}
const countWord = readme.match(/exposing (\d+) tools/);
if (!countWord) problems.push("README.md does not state the tool count");
else if (Number(countWord[1]) !== names.length) problems.push(`README.md says ${countWord[1]} tools, the registry has ${names.length}`);

// 2. the CLI header lists the same tools
const cliHeader = cli.slice(0, cli.indexOf("import "));
const cliMissing = names.filter((n) => !cliHeader.includes(n));
if (cliMissing.length) problems.push(`cli/index.mjs header does not list: ${cliMissing.join(", ")}`);

// 3. every op a tool advertises is the op set it enforces
for (const tool of m.TOOLS) {
  const schema = m.TOOL_INPUT_SCHEMAS[tool.name];
  const declared = schema && schema.properties && schema.properties.op ? String(schema.properties.op.description) : "";
  // The schema lists operations as "a (default) | b | c"; anything else in a description is prose.
  const advertised = declared
    .split("|")
    .map((part) => part.trim().replace(/\s*\(.*$/, ""))
    .filter((part) => /^[a-z][a-z-]*$/.test(part));
  const body = String(tool.execute);
  // The dispatch's own list is the LAST "allowed:" in the body; earlier ones belong to smaller
  // decisions (a review can only be clear or revoke, which is not the tool's op surface).
  const allowed = [...body.matchAll(/allowed: ([a-z][a-z-]*(?:, [a-z][a-z-]*)*)/g)];
  if (!allowed.length) continue;
  const enforced = allowed[allowed.length - 1][1].split(",").map((s) => s.trim()).filter(Boolean);
  for (const op of enforced) {
    if (advertised.length && !advertised.includes(op)) problems.push(`${tool.name}: enforces op "${op}" that its schema description does not mention`);
  }
  for (const op of advertised) {
    if (enforced.length && !enforced.includes(op)) problems.push(`${tool.name}: schema mentions op "${op}" that the dispatch does not accept`);
  }
}

// 4. safety claims this package makes about itself
if (/fetch\s*\(|https?\.request|net\.connect|node:https|node:net/.test(src)) {
  problems.push("lib/core.mjs claims no network I/O but references a network API");
}
const debug = src.split("\n").map((l, i) => [i + 1, l]).filter(([, l]) => /console\.(log|debug)\(/.test(l) && !/^\s*\/\//.test(l));
if (debug.length) problems.push(`lib/core.mjs has ${debug.length} console output call(s) (line ${debug[0][0]}) - a library must stay silent`);
const markers = src.split("\n").map((l, i) => [i + 1, l]).filter(([, l]) => /\b(TODO|FIXME|XXX|HACK)\b/.test(l) && !/^\s*\/\//.test(l));
if (markers.length) problems.push(`lib/core.mjs carries ${markers.length} dangling marker(s) (line ${markers[0][0]})`);

// 5. numbers quoted in the README must match the live tables
const sigClaim = readme.match(/\((\d+) signatures\)/);
if (sigClaim && Number(sigClaim[1]) !== m.FILE_SIGNATURES.length) {
  problems.push(`README.md claims ${sigClaim[1]} signatures, the table has ${m.FILE_SIGNATURES.length}`);
}
for (const [label, value] of [["FILE_SIGNATURES", m.FILE_SIGNATURES.length], ["TOOLS", names.length]]) {
  if (!Number.isInteger(value)) problems.push(`${label} is not a number`);
}

if (problems.length) {
  console.log(`check-consistency: ${problems.length} finding(s)`);
  for (const p of problems.slice(0, 40)) console.log("  " + p);
  process.exit(1);
}
console.log(`check-consistency: OK - ${names.length} tools, ${m.FILE_SIGNATURES.length} signatures, docs and dispatch agree`);
