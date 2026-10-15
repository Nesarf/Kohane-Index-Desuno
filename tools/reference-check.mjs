// READ-ONLY cross-reference checker for kohane-index-desuno.
//
// ARCHITECTURE RULE (do not violate):
//   kohane-index-desuno is the universal + extended build; the other project is the narrower
//   host-only plugin. That project is a REFERENCE and, when necessary, a PROOFREADING SOURCE
//   (校对源) for kohane-index-desuno — never an input that may modify it. Until kohane-index-desuno
//   is finished, nothing from mega-index-map may affect it.
//
// This tool therefore NEVER WRITES. It only reads both trees, extracts the blocks that are
// comparable across the two, and reports where they differ, so a human can deliberately decide
// what (if anything) to adopt. There is intentionally NO port/sync/apply mode; the previous
// one-way writer was removed because it overwrote the newer, wider build with the older one.
//
//   node tools/reference-check.mjs
//
// Exit code is always 0 (this is a report, not a gate).
import fs from "node:fs";

const REFERENCE = "E:/mega-index-map/lib/index.js";                                  // read-only reference
const TARGET = "E:/kohane-index-desuno/kohane-index-desuno/lib/core.mjs";            // the build under development

function readOrNull(p) {
  try { return fs.readFileSync(p, "utf8"); } catch { return null; }
}

// Brace/paren matcher that respects strings, template literals and comments.
function matchFrom(src, openIdx) {
  const open = src[openIdx];
  const close = open === "{" ? "}" : open === "[" ? "]" : ")";
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      i++;
      while (i < src.length) {
        if (src[i] === "\\") { i += 2; continue; }
        if (src[i] === q) break;
        i++;
      }
      continue;
    }
    if (c === "/" && src[i + 1] === "/") { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (c === "/" && src[i + 1] === "*") { i += 2; while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++; i++; continue; }
    if (c === open) depth++;
    else if (c === close) { depth--; if (depth === 0) return i; }
  }
  return -1;
}
function sliceBlock(src, marker, kind) {
  const start = src.indexOf(marker);
  if (start < 0) return null;
  if (kind === "func") {
    const open = src.indexOf("{", src.indexOf("(", start));
    const end = matchFrom(src, open);
    return end < 0 ? null : src.slice(start, end + 1);
  }
  const openIdx = src.indexOf(kind === "array" ? "[" : "{", start);
  const end = matchFrom(src, openIdx);
  return end < 0 ? null : src.slice(start, end + 1);
}
function countMatches(src, re) {
  return (src.match(re) || []).length;
}
function firstDiff(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i;
  return a.length === b.length ? -1 : n;
}

const ref = readOrNull(REFERENCE);
const tgt = readOrNull(TARGET);

if (!ref) {
  console.log(`reference not found (skipped): ${REFERENCE}`);
  process.exit(0);
}
if (!tgt) {
  console.log(`target not found: ${TARGET}`);
  process.exit(0);
}

console.log("kohane-index-desuno vs mega-index-map - READ-ONLY reference check");
console.log(`  reference : ${REFERENCE}  (${ref.length} chars)`);
console.log(`  target    : ${TARGET}  (${tgt.length} chars)`);
console.log("  rule: mega-index-map is reference-only and must not modify kohane-index-desuno.\n");

// Comparable blocks: same construct exists in both trees, so a diff is meaningful.
const BLOCKS = [
  { label: "FILE_SIGNATURES", marker: "const FILE_SIGNATURES = [", kind: "array" },
  { label: "TEXT_EXTENSIONS", marker: "const TEXT_EXTENSIONS = [", kind: "array" },
  { label: "DETECT_CANDIDATES", marker: "const DETECT_CANDIDATES = [", kind: "array" },
  { label: "INDICATIVE_ENCODING_HINTS", marker: "const INDICATIVE_ENCODING_HINTS = [", kind: "array" },
  { label: "sniffFileType", marker: "function sniffFileType(filePath) {", kind: "func" },
  { label: "detectSystemEncoding", marker: "function detectSystemEncoding() {", kind: "func" },
  { label: "detectSystemEncodingSync", marker: "function detectSystemEncodingSync() {", kind: "func" },
];

const rows = [];
for (const b of BLOCKS) {
  const r = sliceBlock(ref, b.marker, b.kind);
  const t = sliceBlock(tgt, b.marker, b.kind);
  const present = r != null && t != null;
  const equal = present && r === t;
  const at = present && !equal ? firstDiff(r, t) : -1;
  rows.push({
    block: b.label,
    reference: r == null ? "-" : `${r.length}c`,
    target: t == null ? "-" : `${t.length}c`,
    verdict: !present ? (r == null ? "reference only" : "target only") : (equal ? "identical" : "differs"),
    at: at >= 0 ? `~${at}` : "",
  });
}

const pad = (s, n) => String(s).padEnd(n);
console.log(pad("BLOCK", 28) + pad("REFERENCE", 12) + pad("TARGET", 12) + pad("VERDICT", 14) + "FIRST-DIFF");
console.log("-".repeat(80));
for (const r of rows) console.log(pad(r.block, 28) + pad(r.reference, 12) + pad(r.target, 12) + pad(r.verdict, 14) + r.at);

// Counts that make a difference actionable at a glance.
console.log("\ncounts (a larger target count means kohane-index-desuno extends the reference):");
const sigRef = countMatches(sliceBlock(ref, "const FILE_SIGNATURES = [", "array") || "", /\{ sig: \[/g);
const sigTgt = countMatches(sliceBlock(tgt, "const FILE_SIGNATURES = [", "array") || "", /\{ sig: \[/g);
const candRef = countMatches(sliceBlock(ref, "const DETECT_CANDIDATES = [", "array") || "", /\{ type:/g);
const candTgt = countMatches(sliceBlock(tgt, "const DETECT_CANDIDATES = [", "array") || "", /\{ type:/g);
console.log(`  FILE_SIGNATURES   reference ${sigRef}  target ${sigTgt}  (${sigTgt - sigRef >= 0 ? "+" : ""}${sigTgt - sigRef})`);
console.log(`  DETECT_CANDIDATES reference ${candRef}  target ${candTgt}  (${candTgt - candRef >= 0 ? "+" : ""}${candTgt - candRef})`);

console.log("\nNo files were written. Adopt anything from the reference manually and deliberately.");
