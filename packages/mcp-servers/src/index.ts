// @sentinelforge/mcp-servers — one MCP server per engine (spec §8).
// External agents: spawn `node dist/index.js serve <name>` and speak JSON-RPC 2.0
// (initialize → tools/list → tools/call, NDJSON stdio). In-repo callers (API
// Copilot) use callLocal() — identical handlers, no process cost.
export { serve, McpClient, type ToolDef, type ServerSpec } from './protocol.js';
export { SERVERS, callLocal, listLocalTools, type McpServerName } from './registry.js';
export { epssLookup, type EpssResult } from './epss.js';

import { serve } from './protocol.js';
import { SERVERS, type McpServerName } from './registry.js';

if (process.argv[2] === 'serve') {
  const name = process.argv[3] as McpServerName;
  const spec = SERVERS[name];
  if (!spec) {
    console.error(`unknown server '${name}'. Available: ${Object.keys(SERVERS).join(', ')}`);
    process.exit(1);
  }
  await serve(name, spec);
}
