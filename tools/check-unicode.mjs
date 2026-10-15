#!/usr/bin/env node
// Repository invariant: every shipped file is CORRECT UNICODE - not ASCII.
//
// The shipped package may speak any script it likes: kohane is a Unicode tool, and the people it is
// built for read Chinese and Japanese. What it may not carry is *broken* text -
//   * bytes that are not valid UTF-8,
//   * the U+FFFD replacement character (the fingerprint of a decode that already lost something),
//   * a lone surrogate (which cannot be encoded at all, and corrupts anything it is written into),
//   * a byte-order mark at the head of a file that Node reads as source,
//   * control characters other than tab, line feed and carriage return,
//   * a carriage return in a source file (the package is checked out and diffed as LF).
// The report is also informational on purpose: it prints which scripts each file actually uses, so
// a drift towards or away from a language is visible instead of silent.
//
// Scope is the SHIPPED package (lib/, mcp/, cli/, README.md, LICENSE, package.json). Everything
// outside it - research/ (evidence notes), tools/ (harnesses), TODO.md, workstation/ - is a working
// document rather than the product.
//
// Usage: node tools/check-unicode.mjs        (exit 1 on any finding)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PKG = path.join(ROOT, "kohane-index-desuno");
const SHIPPED = [
  path.join(PKG, "lib", "core.mjs"),
  path.join(PKG, "mcp", "index.mjs"),
  path.join(PKG, "cli", "index.mjs"),
  path.join(PKG, "README.md"),
  path.join(PKG, "LICENSE"),
  path.join(PKG, "package.json"),
];

const problems = [];
const rows = [];

/** Which script does this code point belong to? Coarse on purpose - the point is drift, not taxonomy. */
function scriptOf(cp) {
  if (cp < 0x80) return cp < 0x20 || cp === 0x7f ? "ctrl" : "latin";
  if (cp >= 0x3040 && cp <= 0x30ff) return "kana";
  if (cp >= 0x31f0 && cp <= 0x31ff) return "kana";
  if (cp >= 0x4e00 && cp <= 0x9fff) return "han";
  if (cp >= 0x3400 && cp <= 0x4dbf) return "han";
  if (cp >= 0xf900 && cp <= 0xfaff) return "han";
  if (cp >= 0xac00 && cp <= 0xd7af) return "hangul";
  if (cp >= 0x3000 && cp <= 0x303f) return "cjk-punct";
  if (cp >= 0xff00 && cp <= 0xffef) return "fullwidth";
  if (cp >= 0x2000 && cp <= 0x206f) return "typography";
  return "other";
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

for (const file of SHIPPED) {
  const rel = path.relative(ROOT, file);
  let bytes;
  try {
    bytes = fs.readFileSync(file);
  } catch {
    problems.push(`${rel}: missing`);
    continue;
  }

  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (e) {
    problems.push(`${rel}: not valid UTF-8 (${e.message})`);
    continue;
  }

  if (text.charCodeAt(0) === 0xfeff) problems.push(`${rel}: begins with a byte-order mark`);
  const replacement = (text.match(/\uFFFD/g) || []).length;
  if (replacement) problems.push(`${rel}: contains U+FFFD x${replacement} - a decode already lost text here`);
  if (LONE_SURROGATE.test(text)) problems.push(`${rel}: contains a lone surrogate (it cannot be encoded)`);
  const control = [...text.matchAll(new RegExp(CONTROL, "g"))].map((m) => "U+" + m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, "0"));
  if (control.length) problems.push(`${rel}: control character(s) ${[...new Set(control)].join(", ")}`);
  const cr = (text.match(/\r/g) || []).length;
  if (cr) problems.push(`${rel}: ${cr} carriage return(s) - the package is line-feed only`);

  const scripts = {};
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp < 0x80) continue;
    const name = scriptOf(cp);
    scripts[name] = (scripts[name] || 0) + 1;
  }
  rows.push({
    file: rel.replace(/\\/g, "/"),
    kb: (bytes.length / 1024).toFixed(1),
    lines: text.split("\n").length,
    nonAscii: Object.values(scripts).reduce((a, b) => a + b, 0),
    scripts: Object.entries(scripts).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}:${v}`).join(" ") || "-",
  });
}

console.log("shipped files (Unicode is allowed; broken text is not)");
for (const r of rows) {
  console.log(`  ${r.file.padEnd(34)} ${String(r.kb).padStart(7)} KB  ${String(r.lines).padStart(6)} lines  non-ASCII ${String(r.nonAscii).padStart(6)}  ${r.scripts}`);
}

if (problems.length) {
  console.log(`\ncheck-unicode: ${problems.length} finding(s)`);
  for (const p of problems.slice(0, 40)) console.log("  " + p);
  process.exit(1);
}
console.log(`\ncheck-unicode: OK - ${SHIPPED.length} shipped file(s) decode as valid UTF-8 with no replacement characters, lone surrogates, BOM, stray control characters or carriage returns`);
