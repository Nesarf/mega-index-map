#!/usr/bin/env node
// mega-index-map — MCP (Model Context Protocol) stdio server.
//
// Exposes the same 9 tools as the DSH plugin over MCP's stdio transport. It consumes the
// cross-harness shared core (lib/core.mjs), so the tool logic is identical to the DSH plugin.
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
import { TOOLS, registerDefaultMediaProvider, safeStringify } from "../lib/core.mjs";

// MCP is an independent local service: always register media providers so media fingerprints
// (ffprobe/MediaInfo) work, regardless of whether DSH_HOME is set.
registerDefaultMediaProvider();

const server = new Server(
  { name: "mega-index-map", version: "0.1.0" },
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
