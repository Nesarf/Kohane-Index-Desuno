#!/usr/bin/env node
// kohane-index-desuno - command-line driver for the cross-harness shared core.
//
// Usage:
//   node cli/index.mjs <tool> [--key value | --key=value | '{"json":...}']
//   node cli/index.mjs sniff <path>            # shortcut for library_sniff --path <path>
//   node cli/index.mjs                          # print usage + available tools
//
// Runs the same TOOLS.execute functions used by the DSH plugin and the MCP server, and
// writes the JSON result to stdout. Exit code 1 on unknown command or execute failure.
//
// Tools: the 16 tools below (library_record, library_index, library_query, library_detect,
// library_sniff, library_vcs, library_audio, library_format, library_plugin, library_sessions,
// library_decrypt, library_export, library_encoding, library_adb, analyze_object,
// library_environment), registered in lib/core.mjs.

import { TOOLS, registerDefaultMediaProvider, safeStringify } from "../lib/core.mjs";

// Media providers are cheap to register and make media fingerprints (ffprobe/MediaInfo) work.
registerDefaultMediaProvider();

// Coerce a `--key value` string into a primitive (number/boolean/null) when it looks like one,
// otherwise keep it as a string. Paths and free text stay strings; counts/durations become numbers.
function coerceValue(v) {
  if (v === "true") return true;
  if (v === "false") return false;
  if (v === "null") return null;
  if (v !== "" && Number.isFinite(Number(v))) return Number(v);
  return v;
}

// Parse the argv tokens (everything after the command name) into:
//   flags       -> from --key value / --key=value / bare --flag
//   json        -> from any positional token that is a JSON object (merged)
//   positionals -> remaining positional tokens (strings, not JSON objects)
function parseTokens(tokens) {
  const flags = {};
  const json = {};
  const positionals = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.startsWith("--")) {
      const body = t.slice(2);
      const eq = body.indexOf("=");
      if (eq >= 0) {
        flags[body.slice(0, eq)] = coerceValue(body.slice(eq + 1));
      } else {
        const next = tokens[i + 1];
        if (next !== undefined && !next.startsWith("--")) {
          flags[body] = coerceValue(next);
          i++; // consume the value token
        } else {
          flags[body] = true; // bare boolean flag
        }
      }
    } else {
      let parsed = null;
      try { parsed = JSON.parse(t); } catch { /* not JSON */ }
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        Object.assign(json, parsed);
      } else {
        positionals.push(t);
      }
    }
  }
  return { flags, json, positionals };
}

const tokens = process.argv.slice(2);
const command = tokens[0];

if (!command) {
  console.log(`kohane-index-desuno CLI\n\nUsage:\n  node cli/index.mjs <tool> [--key value | --key=value | '{"json":...}']\n  node cli/index.mjs sniff <path>\n\nTools:\n  ${TOOLS
    .map((t) => `${t.name}\n      ${t.description}`)
    .join("\n  ")}\n\nAlso: sniff <path>  (shortcut for library_sniff)`);
  process.exit(0);
}

let name = command;
// Only parse the tokens after the command name (tokens[0] is the command itself).
const { flags, json, positionals } = parseTokens(tokens.slice(1));
let args = { ...json, ...flags };

// `sniff <path>` shortcut maps to library_sniff and fills `path` from the positional arg.
if (name === "sniff") {
  name = "library_sniff";
  if (!args.path && positionals.length) args.path = positionals[0];
}

const tool = TOOLS.find((t) => t.name === name);
if (!tool) {
  console.error(`kohane-index-desuno: unknown command "${name}".\nAvailable tools: ${TOOLS.map((t) => t.name).join(", ")}\nShortcut: sniff <path>`);
  process.exit(1);
}

try {
  const result = await tool.execute(args);
  console.log(safeStringify(result, 2));
} catch (e) {
  console.error(String((e && e.message) || e));
  process.exit(1);
}
