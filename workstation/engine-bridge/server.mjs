#!/usr/bin/env node
// kohane-index-desuno — workstation engine bridge.
//
// A tiny localhost HTTP server that reuses the pure-Node engine (lib/core.mjs) — the SAME
// TOOLS.execute functions the MCP server exposes — so the WinUI workstation can analyze files
// and drive the Library over HTTP instead of spawning a CLI process per call.
//
//   node server.mjs                 # -> http://127.0.0.1:8787
//   GET  /tools/list                # -> { tools: [ ...tool names ] }
//   POST /tools/call  {name, args}  # -> the tool's JSON result
//
// The Library lives under <workstation>/data (DSH_HOME), keeping it inside this workspace.

import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Keep the workstation Library local. A DSH_HOME inherited from the surrounding shell must NOT
// silently redirect the workstation into the machine-wide library (the promise in README.md is that
// this stays inside the workspace), so sharing one has to be asked for:
//   KOHANE_BRIDGE_SHARED=1   reuse the exported DSH_HOME
//   KOHANE_BRIDGE_DSH_HOME   point the workstation library somewhere else
// The engine reads DSH_HOME per call, so setting it here (after the import) still takes effect.
const WORKSTATION_ROOT = path.resolve(__dirname, "..");
const LOCAL_LIBRARY = path.join(WORKSTATION_ROOT, "data");

if (process.env.KOHANE_BRIDGE_SHARED === "1" && process.env.DSH_HOME) {
  // the caller explicitly asked to share the machine-wide library
} else {
  process.env.DSH_HOME = process.env.KOHANE_BRIDGE_DSH_HOME || LOCAL_LIBRARY;
}

// Reuse the cross-harness engine core. Pure Node; no DSH / MCP SDK dependency here.
// (Relative ESM path from engine-bridge/ to the engine's lib/core.mjs.)
import { TOOLS, registerDefaultMediaProvider, safeStringify } from "../../kohane-index-desuno/lib/core.mjs";
registerDefaultMediaProvider();

const PORT = Number(process.env.KOHANE_BRIDGE_PORT || 8787);

function send(res, code, obj) {
  const body = safeStringify(obj);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");

  if (req.method === "OPTIONS") return send(res, 204, {});
  if (req.method === "GET" && url.pathname === "/tools/list") {
    return send(res, 200, { tools: TOOLS.map((t) => t.name) });
  }
  if (req.method === "POST" && url.pathname === "/tools/call") {
    let body = "";
    for await (const chunk of req) body += chunk;
    let payload;
    try { payload = JSON.parse(body || "{}"); } catch { return send(res, 400, { ok: false, error: "bad json" }); }

    const tool = TOOLS.find((t) => t.name === payload.name);
    if (!tool) return send(res, 404, { ok: false, error: `unknown tool: ${payload.name}` });

    try {
      const result = await tool.execute(payload.args || {});
      return send(res, 200, result);
    } catch (e) {
      return send(res, 500, { ok: false, error: String((e && e.message) || e) });
    }
  }
  return send(res, 404, { ok: false, error: "not found" });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`kohane engine bridge  http://127.0.0.1:${PORT}`);
  console.log(`DSH_HOME (library)    ${process.env.DSH_HOME}`);
  console.log(`tools                 ${TOOLS.map((t) => t.name).join(", ")}`);
});
