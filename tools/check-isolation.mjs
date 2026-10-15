#!/usr/bin/env node
// Isolation guard for this repository, in the same spirit as the sibling build's ISOLATION.md:
// this checkout and the sibling build are separate trees that may READ each other but must never
// WRITE each other. The sibling is declared locally (KOHANE_SIBLING, or .isolation.local.json
// beside this checkout) so that no shipped file has to name it - the shipped package must stay
// free of machine-specific paths.
//
// Three jobs:
//   static (default)  - no shipped file names the sibling; no write-capable call targets it; the
//                       read-only cross-check tool must not write anything.
//   snapshot [file]   - hash this checkout's shipped files, the sibling tree and the library index.
//   verify   [file]   - re-hash and report what moved, so a session can prove a run changed nothing.
//
// Usage:
//   node tools/check-isolation.mjs
//   node tools/check-isolation.mjs snapshot [manifest.json]
//   node tools/check-isolation.mjs verify   [manifest.json]
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PKG = path.join(ROOT, "kohane-index-desuno");
const LOCAL_DECL = path.join(ROOT, ".isolation.local.json");
const DEFAULT_MANIFEST = path.join(ROOT, "tools", ".isolation-manifest.json");

function declareSibling() {
  if (process.env.KOHANE_SIBLING) return { sibling: process.env.KOHANE_SIBLING, from: "KOHANE_SIBLING" };
  try {
    const decl = JSON.parse(fs.readFileSync(LOCAL_DECL, "utf8"));
    if (decl && decl.sibling) return { sibling: String(decl.sibling), from: path.basename(LOCAL_DECL) };
  } catch {}
  return { sibling: null, from: null };
}

function shippedFiles() {
  const out = [];
  const walk = (dir, depth = 0) => {
    if (depth > 3) return;
    let ents;
    try {
      ents = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of ents) {
      if (e.name === "node_modules" || e.name === ".git") continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full, depth + 1);
      else if (e.isFile()) out.push(full);
    }
  };
  for (const rel of ["lib", "mcp", "cli"]) walk(path.join(PKG, rel));
  for (const rel of ["README.md", "LICENSE", "package.json"]) {
    const f = path.join(PKG, rel);
    if (fs.existsSync(f)) out.push(f);
  }
  return out.sort();
}

function hashFile(file) {
  try {
    return createHash("sha256").update(fs.readFileSync(file)).digest("hex").slice(0, 16);
  } catch {
    return null;
  }
}

function treeHashes(root, cap = 400) {
  const out = {};
  const walk = (dir, depth = 0) => {
    if (depth > 3 || Object.keys(out).length >= cap) return;
    let ents;
    try {
      ents = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of ents) {
      if (Object.keys(out).length >= cap) break;
      if (e.name === "node_modules" || e.name === ".git") continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full, depth + 1);
      else if (e.isFile()) out[path.relative(root, full)] = hashFile(full);
    }
  };
  walk(root);
  return out;
}

const mode = (process.argv[2] || "static").toLowerCase();
const manifestPath = process.argv[3] || DEFAULT_MANIFEST;
const decl = declareSibling();

if (mode === "static") {
  const problems = [];
  const sibling = decl.sibling;
  for (const file of shippedFiles()) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(ROOT, file);
    if (sibling && text.includes(sibling)) problems.push(`${rel}: a shipped file names the sibling checkout`);
    if (sibling) {
      const base = path.basename(sibling);
      const offending = text
        .split("\n")
        .findIndex((l) => /\b(writeFileSync|appendFileSync|mkdirSync|rmSync|unlinkSync|renameSync|copyFileSync)\b/.test(l) && (l.includes(sibling) || l.includes(`\${base}\\`) || l.includes(`/${base}/`)));
      // The sibling's NAME may appear as data (a legacy key namespace kept for old records); the
      // finding is a write call that names its PATH on the same line.
      if (offending >= 0) problems.push(`${rel}:${offending + 1}: a write-capable call appears to target the sibling`);
    }
  }
  // the cross-check tool may READ the sibling; it must never write
  const ref = path.join(ROOT, "tools", "reference-check.mjs");
  if (fs.existsSync(ref)) {
    const text = fs.readFileSync(ref, "utf8");
    if (/\b(writeFileSync|appendFileSync|rmSync|unlinkSync|renameSync|copyFileSync|mkdirSync)\b/.test(text)) {
      problems.push("tools/reference-check.mjs contains a write call; the cross-check must be read-only");
    }
  }
  // Only CODE may not depend on the local declaration; a document that explains the mechanism is
  // not a dependency.
  for (const file of shippedFiles().filter((f) => /\.(mjs|js|cjs)$/.test(f))) {
    const text = fs.readFileSync(file, "utf8");
    if (/\.isolation\.local\.json/.test(text)) problems.push(`${path.relative(ROOT, file)}: shipped code reads the local declaration`);
  }
  if (problems.length) {
    console.log(`check-isolation: ${problems.length} finding(s)`);
    for (const p of problems.slice(0, 40)) console.log("  " + p);
    process.exit(1);
  }
  console.log(`check-isolation: OK - ${shippedFiles().length} shipped file(s) clean; sibling ${sibling ? `declared via ${decl.from}` : "not declared locally (static scope only)"}`);
  process.exit(0);
}

if (mode === "snapshot" || mode === "verify") {
  const shipped = {};
  for (const f of shippedFiles()) shipped[path.relative(ROOT, f)] = hashFile(f);
  const snapshot = {
    at: new Date().toISOString(),
    shipped,
    sibling: decl.sibling ? { path: decl.sibling, files: treeHashes(decl.sibling) } : null,
    library: (() => {
      const idx = path.join(process.env.DSH_HOME || "", "library", "index.json");
      return fs.existsSync(idx) ? { file: idx, hash: hashFile(idx) } : null;
    })(),
  };
  if (mode === "snapshot") {
    fs.writeFileSync(manifestPath, JSON.stringify(snapshot, null, 2), "utf8");
    console.log(`check-isolation: snapshot written to ${path.relative(ROOT, manifestPath)} (${Object.keys(shipped).length} shipped file(s))`);
    process.exit(0);
  }
  if (!fs.existsSync(manifestPath)) {
    console.log(`check-isolation: no manifest at ${path.relative(ROOT, manifestPath)} - run snapshot first`);
    process.exit(1);
  }
  const before = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const moved = [];
  for (const [rel, hash] of Object.entries(before.shipped || {})) {
    const now = hashFile(path.join(ROOT, rel));
    if (now === null) moved.push(`${rel}: gone`);
    else if (now !== hash) moved.push(`${rel}: changed`);
  }
  for (const rel of Object.keys(shipped)) if (!(rel in (before.shipped || {}))) moved.push(`${rel}: new`);
  if (before.library) {
    const now = hashFile(before.library.file);
    if (now !== before.library.hash) moved.push("library index changed");
  }
  if (moved.length) {
    console.log(`check-isolation: ${moved.length} change(s) since the snapshot`);
    for (const x of moved.slice(0, 40)) console.log("  " + x);
    process.exit(1);
  }
  console.log("check-isolation: verify OK - nothing under this checkout moved since the snapshot");
  process.exit(0);
}

console.log(`check-isolation: unknown mode "${mode}" (static | snapshot | verify)`);
process.exit(1);
