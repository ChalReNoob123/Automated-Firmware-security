// Symbolic execution & taint tracking — prototype (spec: Autonomous Discovery Engine §2).
// Production runs angr over Ghidra-headless output; this module owns the ANALYSIS
// SEMANTICS so the engine swaps without changing downstream code: attacker-controlled
// sources → dangerous sinks over a call graph, with sanitizer awareness and full
// path reporting. Feed it a Ghidra-exported graph in prod, `parseCallGraph` text here.
import { DANGEROUS_SINKS } from './static.js';

export type CallGraph = Record<string, string[]>; // caller -> callees

// Attacker-controlled entry points: network, IPC, peripheral and env inputs.
export const TAINT_SOURCES = [
  'recv',
  'recvfrom',
  'read',
  'fgets',
  'fread',
  'getenv',
  'getchar',
  'mqtt_payload',
  'mqtt_subscribe_cb',
  'coap_payload',
  'ble_gatt_write',
  'zigbee_cluster_rx',
  'uart_read',
  'argv',
  'cgi_param',
  'http_query_param',
] as const;

export const TAINT_SINKS: readonly string[] = DANGEROUS_SINKS;

// Checks that neutralize taint along a path (bounded copy, validation, …).
export const SANITIZERS = [
  'strncpy',
  'strncat',
  'snprintf',
  'vsnprintf',
  'memcpy_s',
  'validate_len',
  'check_bounds',
  'sanitize_input',
] as const;

export type TaintPath = {
  source: string;
  sink: string;
  path: string[]; // function chain source → … → sink
  sanitized: boolean; // a sanitizer sits on the path (lower priority, still reported)
};

// Parse `caller -> callee` edge lines (one per line, `#` comments). This is the
// interchange format the Ghidra-headless exporter will emit in production.
export function parseCallGraph(text: string): CallGraph {
  const g: CallGraph = {};
  for (const raw of text.split('\n')) {
    const line = raw.split('#')[0].trim();
    if (!line) continue;
    const m = line.match(/^(\S+)\s*->\s*(\S+)\s*$/);
    if (!m) throw new Error(`bad edge (want 'caller -> callee'): ${line}`);
    (g[m[1]] ??= []).push(m[2]);
    g[m[2]] ??= [];
  }
  return g;
}

export function traceTaint(
  graph: CallGraph,
  opts: { sources?: readonly string[]; sinks?: readonly string[]; sanitizers?: readonly string[]; maxDepth?: number } = {}
): TaintPath[] {
  const sources = new Set(opts.sources ?? TAINT_SOURCES);
  const sinks = new Set(opts.sinks ?? TAINT_SINKS);
  const sanitizers = new Set<string>(opts.sanitizers ?? SANITIZERS);
  const maxDepth = opts.maxDepth ?? 12;
  const out: TaintPath[] = [];

  for (const src of Object.keys(graph)) {
    if (!sources.has(src)) continue;
    // BFS over (node, path) — shortest source→sink chains first
    const queue: string[][] = [[src]];
    const visited = new Set<string>([src]);
    while (queue.length > 0) {
      const path = queue.shift()!;
      const node = path[path.length - 1];
      if (node !== src && sinks.has(node)) {
        out.push({ source: src, sink: node, path, sanitized: path.some((n) => sanitizers.has(n)) });
        continue; // keep searching — one source can reach several sinks
      }
      if (path.length > maxDepth) continue;
      for (const next of graph[node] ?? []) {
        if (!visited.has(next)) {
          visited.add(next);
          queue.push([...path, next]);
        }
      }
    }
  }
  return out.sort((a, b) => Number(a.sanitized) - Number(b.sanitized) || a.path.length - b.path.length);
}

// Reverse query for the attack-chain graph (Module 7): who can reach this sink?
export function callersOf(graph: CallGraph, sink: string, maxDepth = 8): string[][] {
  const rev: Record<string, string[]> = {};
  for (const [caller, callees] of Object.entries(graph))
    for (const c of callees) (rev[c] ??=[]).push(caller);
  const paths: string[][] = [];
  const queue: string[][] = [[sink]];
  while (queue.length > 0) {
    const path = queue.shift()!;
    const node = path[0];
    const callers = rev[node] ?? [];
    // Paths are stored caller-first ([caller, …, sink]) since callers prepend.
    if (callers.length === 0 || path.length > maxDepth) {
      if (path.length > 1) paths.push([...path]);
      continue;
    }
    for (const c of callers) {
      if (!path.includes(c)) queue.push([c, ...path]);
      else if (path.length > 1) paths.push([...path]);
    }
  }
  return paths;
}
