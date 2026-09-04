// Tool registry — one MCP server per engine (spec §8). Handlers call the REAL
// stage modules (@sentinelforge/workers, @sentinelforge/graph-service); the stdio
// transport (protocol.ts) and the API Copilot both invoke THIS registry, so chat
// answers and external agents share identical tool semantics.
import {
  detectContainers,
  planUnpack,
  parseCallGraph,
  traceTaint,
  fuzz,
  demoHarness,
  verifyPatch,
  startSession,
  getSession,
  feedInput,
  takeSnapshot,
  replay,
} from '@sentinelforge/workers';
import { buildAttackGraph, shortestPaths, demoSample } from '@sentinelforge/graph-service';
import { epssLookup } from './epss.js';
import { createHash } from 'node:crypto';
import type { ServerSpec, ToolDef, ToolHandler } from './protocol.js';

const hexBytes = (hex: string, maxLen = 4 * 1024 * 1024): Uint8Array => {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) throw new Error('imageHex must be even-length hex');
  const b = Buffer.from(hex, 'hex');
  if (b.length === 0 || b.length > maxLen) throw new Error(`image size 1..${maxLen} bytes required`);
  return new Uint8Array(b);
};
const str = (v: unknown, name: string, max = 4096): string => {
  if (typeof v !== 'string' || !v.length || v.length > max) throw new Error(`${name}: non-empty string ≤${max} chars required`);
  return v;
};

export const SERVERS = {
  'binwalk-mcp': {
    version: '0.1.0',
    tools: {
      detect_containers: {
        def: { name: 'detect_containers', description: 'Detect firmware container magics (squashfs/UBI/TRX/ELF/…)', inputSchema: { type: 'object', properties: { imageHex: { type: 'string' } }, required: ['imageHex'] } },
        handler: (a) => detectContainers(hexBytes(str(a.imageHex, 'imageHex', 8 * 1024 * 1024))),
      },
      unpack_plan: {
        def: { name: 'unpack_plan', description: 'Plan extraction tool invocations for detected containers', inputSchema: { type: 'object', properties: { imageHex: { type: 'string' } }, required: ['imageHex'] } },
        handler: (a) => planUnpack(hexBytes(str(a.imageHex, 'imageHex', 8 * 1024 * 1024))),
      },
    },
  },
  'qemu-mcp': {
    version: '0.1.0',
    tools: {
      session_boot: {
        def: { name: 'session_boot', description: 'Boot an emulator digital twin', inputSchema: { type: 'object', properties: { arch: { type: 'string' }, memoryMb: { type: 'number' } }, required: ['arch'] } },
        handler: (a) => {
          const arch = str(a.arch, 'arch', 16);
          if (!['arm', 'aarch64', 'mips', 'mipsel', 'x86', 'x86_64', 'riscv64'].includes(arch))
            throw new Error(`arch: one of arm|aarch64|mips|mipsel|x86|x86_64|riscv64 (got '${arch}')`);
          return startSession({ arch: arch as 'arm', memoryMb: typeof a.memoryMb === 'number' ? a.memoryMb : 256 });
        },
      },
      session_input: {
        def: { name: 'session_input', description: 'Feed console input to a twin', inputSchema: { type: 'object', properties: { sessionId: { type: 'string' }, input: { type: 'string' } }, required: ['sessionId', 'input'] } },
        handler: (a) => {
          const s = getSession(str(a.sessionId, 'sessionId', 64));
          if (!s) throw new Error('session not found');
          return { id: s.id, inputs: feedInput(s, str(a.input, 'input')).inputTrace.length };
        },
      },
      session_snapshot: {
        def: { name: 'session_snapshot', description: 'Snapshot twin state for replay', inputSchema: { type: 'object', properties: { sessionId: { type: 'string' }, note: { type: 'string' } }, required: ['sessionId'] } },
        handler: (a) => {
          const s = getSession(str(a.sessionId, 'sessionId', 64));
          if (!s) throw new Error('session not found');
          return takeSnapshot(s, typeof a.note === 'string' ? a.note.slice(0, 200) : undefined);
        },
      },
      session_replay: {
        def: { name: 'session_replay', description: 'Step-by-step replay of a snapshot', inputSchema: { type: 'object', properties: { sessionId: { type: 'string' }, snapshotId: { type: 'string' } }, required: ['sessionId', 'snapshotId'] } },
        handler: (a) => {
          const s = getSession(str(a.sessionId, 'sessionId', 64));
          if (!s) throw new Error('session not found');
          return replay(s, str(a.snapshotId, 'snapshotId', 64));
        },
      },
    },
  },
  'symbolic-exec-mcp': {
    version: '0.1.0',
    tools: {
      trace_taint: {
        def: { name: 'trace_taint', description: 'Trace attacker-controlled sources to dangerous sinks over a call graph', inputSchema: { type: 'object', properties: { graphText: { type: 'string' } }, required: ['graphText'] } },
        handler: (a) => traceTaint(parseCallGraph(str(a.graphText, 'graphText', 65536))),
      },
    },
  },
  'fuzz-orchestrator-mcp': {
    version: '0.1.0',
    tools: {
      campaign_run: {
        def: { name: 'campaign_run', description: 'Run a bounded coverage-guided campaign (demo target until QEMU harness lands)', inputSchema: { type: 'object', properties: { seeds: { type: 'array' }, iterations: { type: 'number' } }, required: ['seeds'] } },
        handler: (a) => {
          if (!Array.isArray(a.seeds) || !a.seeds.every((s) => typeof s === 'string')) throw new Error('seeds: string[] required');
          const iterations = Math.min(Math.max(typeof a.iterations === 'number' ? Math.floor(a.iterations) : 1000, 1), 20000);
          const r = fuzz(demoHarness, { seeds: (a.seeds as string[]).map((s) => Buffer.from(s, 'latin1')), iterations });
          return { execs: r.execs, coverage: r.coverage, crashCount: r.crashes.length, crashes: r.crashes.slice(0, 25), guidance: r.guidance };
        },
      },
    },
  },
  'bindiff-mcp': {
    version: '0.1.0',
    tools: {
      verify_patch: {
        def: { name: 'verify_patch', description: 'Prove a rebuild removed the vulnerable path (sink + secret comparison)', inputSchema: { type: 'object', properties: { oldText: { type: 'string' }, newText: { type: 'string' }, vulnSink: { type: 'string' } }, required: ['oldText', 'newText'] } },
        handler: (a) => {
          return verifyPatch({
            oldRaw: Buffer.from(str(a.oldText, 'oldText', 2_000_000), 'latin1'),
            newRaw: Buffer.from(str(a.newText, 'newText', 2_000_000), 'latin1'),
            oldText: str(a.oldText, 'oldText', 2_000_000),
            newText: str(a.newText, 'newText', 2_000_000),
            ...(typeof a.vulnSink === 'string' ? { vulnSink: a.vulnSink.slice(0, 64) } : {}),
          });
        },
      },
      similarity: {
        def: { name: 'similarity', description: 'Coarse 4KiB-block similarity between two builds (pre-filter; function-level diff lands with patch verification)', inputSchema: { type: 'object', properties: { oldHex: { type: 'string' }, newHex: { type: 'string' } }, required: ['oldHex', 'newHex'] } },
        handler: (a) => {
          const oldB = Buffer.from(hexBytes(str(a.oldHex, 'oldHex', 64 * 1024 * 1024)));
          const newB = Buffer.from(hexBytes(str(a.newHex, 'newHex', 64 * 1024 * 1024)));
          const blocks = (b: Buffer) => {
            const set = new Set<string>();
            for (let o = 0; o < b.length; o += 4096) set.add(createHash('sha256').update(b.subarray(o, o + 4096)).digest('hex'));
            return set;
          };
          const A = blocks(oldB);
          const B = blocks(newB);
          const common = [...A].filter((h) => B.has(h)).length;
          return { similarity: +((2 * common) / (A.size + B.size)).toFixed(4), commonBlocks: common, oldBlocks: A.size, newBlocks: B.size };
        },
      },
    },
  },
  'cve-epss-mcp': {
    version: '0.2.0',
    tools: {
      epss_lookup: {
        def: { name: 'epss_lookup', description: 'Exploitation probability for a CVE (live FIRST.org with cache; bundled samples offline)', inputSchema: { type: 'object', properties: { cve: { type: 'string' } }, required: ['cve'] } },
        handler: async (a) => epssLookup(str(a.cve, 'cve', 32)),
      },
    },
  },
  'graph-query-mcp': {
    version: '0.1.0',
    tools: {
      attack_paths: {
        def: { name: 'attack_paths', description: 'Ranked exploit chains from taint evidence', inputSchema: { type: 'object', properties: { taintPaths: { type: 'array' } }, required: ['taintPaths'] } },
        handler: (a) => {
          if (!Array.isArray(a.taintPaths)) throw new Error('taintPaths: array required');
          const g = buildAttackGraph({ taintPaths: a.taintPaths as { source: string; sink: string; path: string[] }[] });
          return shortestPaths(g);
        },
      },
      demo_graph: {
        def: { name: 'demo_graph', description: 'Canned attack graph + ranked chains for exploration', inputSchema: { type: 'object', properties: {} } },
        handler: () => demoSample(),
      },
    },
  },
} satisfies Record<string, ServerSpec>;

export type McpServerName = keyof typeof SERVERS;

// In-process invocation — same handlers the stdio servers expose, used by the API Copilot.
export async function callLocal(server: McpServerName, tool: string, args: Record<string, unknown> = {}): Promise<{ server: McpServerName; tool: string; output: unknown }> {
  const tools = SERVERS[server].tools as Record<string, { def: ToolDef; handler: ToolHandler }>;
  const t = tools[tool];
  if (!t) throw new Error(`unknown tool ${server}/${tool}`);
  return { server, tool, output: await t.handler(args) };
}

export function listLocalTools(): { server: McpServerName; tools: string[] }[] {
  return (Object.keys(SERVERS) as McpServerName[]).map((s) => ({ server: s, tools: Object.keys(SERVERS[s].tools) }));
}
