// Attack-chain graph service (spec: cross-component attack-chain graph).
// Builds the graph from discovery evidence (taint paths + exposed secrets),
// computes shortest exploit paths from "network-reachable, unauthenticated" to
// impact assets, and produces deterministic 3D layouts for the explorer UI.
//
// Persistence seam: `GraphStore` (in-memory default). The Neo4j adapter implements
// the same interface with `MATCH p = shortestPath((e:Entry)-[*]->(a:Asset))` —
// wire it when NEO4J_URL is provisioned; no behavior change for callers.
export type NodeKind = 'entry' | 'function' | 'sink' | 'asset' | 'secret';

export type AttackNode = { id: string; label: string; kind: NodeKind; x?: number; y?: number; z?: number };
export type AttackEdge = { from: string; to: string; label?: string };
export type AttackGraph = { nodes: AttackNode[]; edges: AttackEdge[] };
export type AttackPath = { nodes: string[]; hops: number; risk: number };

// Sinks that directly yield command execution → root/persistent impact.
const EXEC_SINKS = new Set(['system', 'popen', 'execve', 'execl', 'execvp', 'shell_exec']);

export function buildAttackGraph(input: {
  taintPaths: { source: string; sink: string; path: string[] }[];
  secrets?: { ruleId: string }[];
}): AttackGraph {
  const nodes = new Map<string, AttackNode>();
  const edges: AttackEdge[] = [];
  const edgeKeys = new Set<string>();
  const addNode = (id: string, label: string, kind: NodeKind) => {
    if (!nodes.has(id)) nodes.set(id, { id, label, kind });
  };
  const addEdge = (from: string, to: string, label?: string) => {
    const k = `${from}→${to}`;
    if (!edgeKeys.has(k)) {
      edgeKeys.add(k);
      edges.push({ from, to, ...(label ? { label } : {}) });
    }
  };

  addNode('entry:network', 'network-reachable, unauthenticated', 'entry');
  for (const t of input.taintPaths) {
    addNode(`fn:${t.source}`, t.source, 'function');
    addEdge('entry:network', `fn:${t.source}`, 'reaches');
    for (let i = 0; i < t.path.length - 1; i++) {
      const fromId = nodeIdFor(t, i);
      const toId = nodeIdFor(t, i + 1);
      addNode(fromId, t.path[i], i === 0 ? 'function' : 'function');
      addNode(toId, t.path[i + 1], i + 1 === t.path.length - 1 ? 'sink' : 'function');
      addEdge(fromId, toId, 'calls');
    }
    const exec = EXEC_SINKS.has(t.sink);
    const assetId = exec ? 'asset:root-shell' : 'asset:control-flow';
    addNode(assetId, exec ? 'root / persistent' : 'control-flow hijack candidate', 'asset');
    addEdge(`sink:${t.sink}`, assetId, 'impacts');
  }
  for (const s of input.secrets ?? []) {
    const id = `secret:${s.ruleId}`;
    addNode(id, `exposed secret: ${s.ruleId}`, 'secret');
    addEdge('entry:network', id, 'reads'); // unauthenticated readability — assumed until reachability analysis lands
  }
  return { nodes: [...nodes.values()], edges };
}

function nodeIdFor(t: { source: string; sink: string; path: string[] }, i: number): string {
  const name = t.path[i];
  if (i === t.path.length - 1) return `sink:${name}`;
  return `fn:${name}`;
}

// BFS shortest chains from an entry node — one per dangerous sink, extended to its
// impact asset. Per-sink (not per-asset) so no exploit chain hides behind a shared
// asset node. Risk favors short chains: the attacker's cheapest path first.
export function shortestPaths(graph: AttackGraph, fromId = 'entry:network'): AttackPath[] {
  const adj = new Map<string, string[]>();
  for (const e of graph.edges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from)!.push(e.to);
  }
  const assetOf = new Map<string, string>();
  for (const e of graph.edges) {
    const to = graph.nodes.find((n) => n.id === e.to);
    if (to?.kind === 'asset') assetOf.set(e.from, e.to);
  }
  const sinks = graph.nodes.filter((n) => n.kind === 'sink').map((n) => n.id);
  const prev = new Map<string, string | null>([[fromId, null]]);
  const queue = [fromId];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const next of adj.get(cur) ?? []) {
      if (!prev.has(next)) {
        prev.set(next, cur);
        queue.push(next);
      }
    }
  }
  const out: AttackPath[] = [];
  for (const s of sinks) {
    if (!prev.has(s)) continue; // unreachable sink
    const chain = [s];
    let cur: string | null = s;
    while ((cur = prev.get(cur!) ?? null)) chain.unshift(cur);
    const asset = assetOf.get(s);
    if (asset) chain.push(asset);
    const hops = chain.length - 1;
    out.push({ nodes: chain, hops, risk: Math.max(10, 100 - 15 * (hops - 1)) });
  }
  return out.sort((a, b) => b.risk - a.risk);
}

// Deterministic 3D force layout (Fruchterman–Reingold in a cube, seeded PRNG) so
// server, API demo and UI agree on positions without shipping a layout engine twice.
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function layoutForce(graph: AttackGraph, opts: { iterations?: number; seed?: number } = {}): AttackGraph {
  const iters = opts.iterations ?? 200;
  const rng = mulberry32(opts.seed ?? 0x6A4F);
  const pos = new Map<string, [number, number, number]>();
  for (const n of graph.nodes) pos.set(n.id, [(rng() - 0.5) * 10, (rng() - 0.5) * 10, (rng() - 0.5) * 10]);
  const ids = graph.nodes.map((n) => n.id);
  let temp = 2;
  const cool = 0.97;
  for (let it = 0; it < iters; it++) {
    const disp = new Map<string, [number, number, number]>(ids.map((id) => [id, [0, 0, 0]]));
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = pos.get(ids[i])!;
        const b = pos.get(ids[j])!;
        const d = [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
        const dist = Math.max(0.1, Math.hypot(...d));
        const f = (4 * 4) / dist; // repulsion k²/d, k=4
        for (let k = 0; k < 3; k++) {
          disp.get(ids[i])![k] += (d[k] / dist) * f;
          disp.get(ids[j])![k] -= (d[k] / dist) * f;
        }
      }
    }
    for (const e of graph.edges) {
      const a = pos.get(e.from)!;
      const b = pos.get(e.to)!;
      const d = [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
      const dist = Math.max(0.1, Math.hypot(...d));
      const f = (dist * dist) / 4; // attraction d²/k
      for (let k = 0; k < 3; k++) {
        disp.get(e.from)![k] -= (d[k] / dist) * f;
        disp.get(e.to)![k] += (d[k] / dist) * f;
      }
    }
    for (const id of ids) {
      const p = pos.get(id)!;
      const dd = disp.get(id)!;
      const len = Math.max(0.1, Math.hypot(...dd));
      const step = Math.min(len, temp);
      for (let k = 0; k < 3; k++) p[k] += (dd[k] / len) * step;
    }
    temp *= cool;
  }
  return {
    nodes: graph.nodes.map((n) => {
      const [x, y, z] = pos.get(n.id)!;
      return { ...n, x: +x.toFixed(3), y: +y.toFixed(3), z: +z.toFixed(3) };
    }),
    edges: graph.edges,
  };
}

export interface GraphStore {
  upsert(graph: AttackGraph): Promise<void>;
  shortest(fromId?: string): Promise<AttackPath[]>;
}

export class InMemoryStore implements GraphStore {
  private graph: AttackGraph = { nodes: [], edges: [] };
  async upsert(graph: AttackGraph): Promise<void> {
    this.graph = graph;
  }
  async shortest(fromId = 'entry:network'): Promise<AttackPath[]> {
    return shortestPaths(this.graph, fromId);
  }
}

// Canned evidence powering GET /v1/graph/demo and the explorer's first paint.
export function demoSample(): { graph: AttackGraph; paths: AttackPath[] } {
  const graph = layoutForce(
    buildAttackGraph({
      taintPaths: [
        { source: 'recv', sink: 'strcpy', path: ['recv', 'parse_query', 'strcpy'] },
        { source: 'recv', sink: 'system', path: ['recv', 'handle_cmd', 'system'] },
        { source: 'ble_gatt_write', sink: 'memcpy', path: ['ble_gatt_write', 'memcpy'] },
      ],
      secrets: [{ ruleId: 'hardcoded-password' }],
    })
  );
  return { graph, paths: shortestPaths(graph) };
}
