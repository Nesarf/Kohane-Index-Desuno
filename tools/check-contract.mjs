#!/usr/bin/env node
// Contract proofread: every tool must be the shape it advertises, and must answer an unknown or
// missing operation with a refusal instead of work. This is a static-plus-read-only pass: the core is
// imported against a throwaway DSH_HOME under the disk-guard temp directory, and only probes that are
// documented as read-only (info / list / status) are actually executed - nothing here mutates a real
// library, and nothing throws.
//
// Usage: node tools/check-contract.mjs        (exit 1 on any finding)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CORE = path.join(ROOT, "kohane-index-desuno", "lib", "core.mjs");
// The temp root follows the disk-guard discipline on this machine, but any machine - a CI runner, for
// instance - can point it elsewhere: KOHANE_HARNESS_TMP overrides it.
const TMP = process.env.KOHANE_HARNESS_TMP
  ? path.join(process.env.KOHANE_HARNESS_TMP, "kohane-contract")
  : path.join("E:", "DaShaoHuo", "cache", "tmp", "kohane-contract");

fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });
process.env.DSH_HOME = path.join(TMP, "dsh");

const m = await import(pathToFileURL(CORE).href);
let problems = [];
const check = (cond, message) => { if (!cond) problems.push(message); };

// The read-only probe each op-ful tool offers, and the argument it needs. Anything not listed here is
// only inspected, never executed.
const SAFE_PROBE = {
  library_index: { op: "status" },
  library_query: { op: "query" },
  library_detect: { op: "scan" },
  library_format: { op: "list" },
  library_plugin: { op: "list" },
  library_sessions: { op: "status" },
  library_vcs: { op: "info" },
  library_audio: { op: "info" },
  library_environment: {},
  library_encoding: {},
  library_export: null,          // writes a file by design: inspected but never executed
  library_record: null,
  library_decrypt: null,
  library_adb: null,             // touches a device: inspected only
  library_sniff: null,
  analyze_object: null,
};

const names = new Set();
for (const tool of m.TOOLS) {
  const label = tool.name;

  // 1. registry shape
  check(typeof tool.name === "string" && /^[a-z][a-z0-9_]*$/.test(tool.name), `${label}: name is not snake_case`);
  check(!names.has(tool.name), `${label}: duplicate tool name`);
  names.add(tool.name);
  check(typeof tool.execute === "function", `${label}: execute is not a function`);
  check(typeof tool.description === "string" && tool.description.length >= 40, `${label}: description is too thin to be useful`);
  check(!/\b(TODO|FIXME|XXX|HACK)\b/.test(tool.description), `${label}: description carries a dangling marker`);

  // 2. schema shape
  const schema = tool.inputSchema;
  check(schema && typeof schema === "object", `${label}: no inputSchema`);
  if (!schema) continue;
  check(schema.type === "object", `${label}: inputSchema is not an object schema`);
  check(schema.properties && typeof schema.properties === "object", `${label}: inputSchema has no properties`);
  check(schema.additionalProperties === false, `${label}: inputSchema does not refuse unknown keys`);
  for (const key of schema.required || []) {
    check(Object.prototype.hasOwnProperty.call(schema.properties || {}, key), `${label}: required key "${key}" has no property definition`);
  }
  const registered = m.TOOL_INPUT_SCHEMAS[tool.name];
  // A tool may carry its schema inline; the table copy only has to agree when it exists.
  if (!registered) { problems.push(`${label}: schema lives inline rather than in TOOL_INPUT_SCHEMAS (allowed, noted)`); }
  if (registered) check(registered === schema || JSON.stringify(registered) === JSON.stringify(schema), `${label}: TOOL_INPUT_SCHEMAS and the tool disagree`);

  // 3. an op-ful tool must advertise its ops and refuse an unknown one without working
  const hasOp = schema.properties && schema.properties.op;
  if (hasOp) {
    const advertised = String(hasOp.description || "")
      .split("|")
      .map((part) => part.trim().replace(/\s*\(.*$/, ""))
      .filter((part) => /^[a-z][a-z-]*$/.test(part));
    check(advertised.length >= 2, `${label}: advertises an op but lists fewer than two`);
    // A default documented in the op description is a contract of its own: op may stay optional then.
    const documentedDefault = /\(default\)|\(\u9ed8\u8ba4\)/i.test(String(hasOp.description || ""));
    check(documentedDefault || (schema.required || []).includes("op"), `${label}: op is optional while the tool is op-driven, and no default is documented`);
  }
}

// 4. behaviour: an unknown op must be refused, not performed - and it must not throw
for (const tool of m.TOOLS) {
  const hasOp = tool.inputSchema && tool.inputSchema.properties && tool.inputSchema.properties.op;
  if (!hasOp) continue;
  let result;
  try {
    result = await tool.execute({ op: "definitely-not-an-op" });
  } catch (e) {
    problems.push(`${tool.name}: threw on an unknown op (${String((e && e.message) || e)})`);
    continue;
  }
  check(result && typeof result === "object", `${tool.name}: unknown op returned a non-object`);
  check(result && result.ok === false, `${tool.name}: unknown op did not refuse (ok=${result && result.ok})`);
  const note = String((result && result.note) || "");
  check(/allowed:/.test(note), `${tool.name}: refusal does not name the ops it accepts`);
  check(!/^\s*unknown op\s+"[^"]*"\s*$/.test(note), `${tool.name}: refusal names no acceptable op`);
}

// 5. behaviour: the documented read-only probes answer, and their answer survives JSON
const jsonSafe = (value) => {
  try { JSON.stringify(value); return true; } catch { return false; }
};
for (const [name, args] of Object.entries(SAFE_PROBE)) {
  if (args === null) continue;
  const tool = m.TOOLS.find((t) => t.name === name);
  if (!tool) { problems.push(`probe target ${name} is not registered`); continue; }
  let result;
  try {
    result = await tool.execute(args);
  } catch (e) {
    problems.push(`${name} ${JSON.stringify(args)}: threw (${String((e && e.message) || e)})`);
    continue;
  }
  check(result && typeof result === "object", `${name} ${JSON.stringify(args)}: returned a non-object`);
  check(jsonSafe(result), `${name} ${JSON.stringify(args)}: answer is not JSON-serialisable`);
}

// 6. the tools the surface claims must be exactly the tools registered
const unsafe = Object.keys(SAFE_PROBE).filter((n) => !m.TOOLS.some((t) => t.name === n));
check(unsafe.length === 0, `the probe table names tools that do not exist: ${unsafe.join(", ")}`);
const uncovered = m.TOOLS.map((t) => t.name).filter((n) => !(n in SAFE_PROBE));
check(uncovered.length === 0, `tools with no stated probe policy: ${uncovered.join(", ")}`);

// the inline-schema notes above are informational: a schema may live on the tool itself
problems = problems.filter((p) => !/lives inline rather than/.test(p));

if (problems.length) {
  console.log(`check-contract: ${problems.length} finding(s)`);
  for (const p of problems.slice(0, 40)) console.log("  " + p);
  process.exit(1);
}
console.log(`check-contract: OK - ${m.TOOLS.length} tools declare a name, a description, a closed schema and an op surface; unknown ops are refused with the accepted list; ${Object.values(SAFE_PROBE).filter(Boolean).length} read-only probes answered`);
