#!/usr/bin/env node
// kohane-index-desuno - MCP (Model Context Protocol) stdio server.
//
// Exposes the same 12 tools as the CLI over MCP's stdio transport. It consumes the
// cross-harness shared core (lib/core.mjs), so the MCP and CLI tool logic is identical.
//
// Input schemas are plain JSON Schemas (object + properties + required) derived from the DSH
// parameters, registered directly via the low-level MCP `Server` (which accepts JSON Schema
// for tools/list and allows raw JSON for tool args). It does NOT depend on the DSH_HOME gate:
// the library + tools are always available and DSH_HOME defaults to ~/.dsh when unset.
//
// Run with:  node ./mcp/index.mjs   (spawn as an MCP stdio server, e.g. "command": "node", "args": ["./mcp/index.mjs"])

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema, McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { TOOLS, registerDefaultMediaProvider, safeStringify, PLUGIN_VERSION } from "../lib/core.mjs";

// MCP is an independent local service: always register media providers so media fingerprints
// (ffprobe/MediaInfo) work, regardless of whether DSH_HOME is set.
registerDefaultMediaProvider();

// The server identity reports the version the core read from package.json, so it can never drift
// from the released package the way a second hardcoded literal would.
const server = new Server(
  { name: "kohane-index-desuno", version: PLUGIN_VERSION },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, () => ({
  tools: TOOLS.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const tool = TOOLS.find((t) => t.name === request.params.name);
  if (!tool) {
    throw new McpError(ErrorCode.InvalidParams, `Unknown tool: ${request.params.name}`);
  }
  try {
    const result = await tool.execute(request.params.arguments || {});
    const text = safeStringify(result, 2);
    return {
      content: [{ type: "text", text }],
      structuredContent: result,
    };
  } catch (e) {
    return {
      isError: true,
      content: [{ type: "text", text: String((e && e.message) || e) }],
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
