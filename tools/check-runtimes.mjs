#!/usr/bin/env node
// Runtime portability, checked rather than claimed.
//
// The core is written against the built-ins that several runtimes provide (Node >= 18, Deno and Bun all
// expose the `node:` namespace). Anything a runtime may lack has to be optional and resolved at boot,
// never imported outright - a static import of it would fail at load time on that runtime, which is
// exactly the kind of one-environment dependency this check exists to catch.
//
// Usage: node tools/check-runtimes.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PKG = path.join(ROOT, "kohane-index-desuno");

/** Built-ins that the declared runtime set all provide. */
const PORTABLE = new Set([
  "node:fs", "node:path", "node:os", "node:crypto", "node:zlib", "node:url", "node:util",
  "node:buffer", "node:stream", "node:events", "node:assert", "node:string_decoder", "node:module",
  "node:child_process", "node:readline", "node:process", "node:timers", "node:querystring",
]);

/** Built-ins a runtime may lack: allowed, but only behind a resolution that can fail gracefully. */
const OPTIONAL = new Set(["node:worker_threads"]);

const problems = [];
const used = new Map();
const files = [];
for (const dir of ["lib", "cli", "mcp", "deps"]) {
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name === "node_modules") continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(mjs|cjs|js)$/.test(e.name)) files.push(p);
    }
  };
  const start = path.join(PKG, dir);
  if (fs.existsSync(start)) walk(start);
}

for (const file of files) {
  const text = fs.readFileSync(file, "utf8");
  const rel = path.relative(PKG, file).split(path.sep).join("/");
  const lines = text.split("\n");
  for (const m of text.matchAll(/from\s+"(node:[a-z_]+)"/g)) {
    const mod = m[1];
    used.set(mod, (used.get(mod) || 0) + 1);
    if (PORTABLE.has(mod)) continue;
    if (OPTIONAL.has(mod)) {
      // a static import of an optional module is a load-time dependency on one runtime
      const line = lines.find((l) => l.includes('from "' + mod + '"'));
      const isStatic = line && /^\s*import\s/.test(line) && !/await\s+import/.test(line);
      if (isStatic) problems.push(`${rel}: imports ${mod} statically, so a runtime without it cannot even load this file`);
      else used.set(mod + " (optional)", (used.get(mod + " (optional)") || 0) + 1);
      continue;
    }
    problems.push(`${rel}: uses ${mod}, which is not in the portable set and is not declared optional`);
  }
  for (const m of text.matchAll(/await\s+import\("(node:[a-z_]+)"\)/g)) {
    const mod = m[1];
    if (!OPTIONAL.has(mod) && !PORTABLE.has(mod)) problems.push(`${rel}: resolves ${mod} dynamically, which is neither declared portable nor declared optional`);
  }
}

if (problems.length) {
  console.log(`check-runtimes: ${problems.length} finding(s)`);
  for (const p of problems.slice(0, 20)) console.log("  " + p);
  process.exit(1);
}
const summary = [...used.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([k, v]) => `${k.replace("node:", "")}${k.includes("optional") ? "(optional)" : ""}:${v}`).join(" ");
console.log(
  `check-runtimes: OK - ${files.length} shipped script(s) use only the portable built-in set ` +
  `(Node >= 18, Deno and Bun all provide it), with ${OPTIONAL.size} declared optional module(s) resolved rather than imported. used: ${summary}`,
);
