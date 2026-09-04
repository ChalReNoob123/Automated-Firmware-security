import { describe, expect, it } from 'vitest';
import { InMemoryStore, buildAttackGraph, demoSample, layoutForce, shortestPaths } from '../src/index.js';

describe('attack graph', () => {
  it('surfaces one chain per sink, ranked', () => {
    const { graph, paths } = demoSample();
    expect(graph.nodes.length).toBeGreaterThan(5);
    expect(paths.map((p) => p.risk)).toEqual([70, 55, 55]);
    expect(paths[0].nodes).toEqual(['entry:network', 'fn:ble_gatt_write', 'sink:memcpy', 'asset:control-flow']);
  });
  it('excludes unreachable sinks', () => {
    const g = buildAttackGraph({ taintPaths: [{ source: 'recv', sink: 'system', path: ['recv', 'system'] }] });
    expect(shortestPaths(g).length).toBe(1);
    expect(shortestPaths({ nodes: [], edges: [] })).toEqual([]);
  });
  it('lays out deterministically in 3D', () => {
    const a = JSON.stringify(layoutForce(buildAttackGraph({ taintPaths: [{ source: 's', sink: 'strcpy', path: ['s', 'strcpy'] }] })).nodes);
    const g2 = layoutForce(buildAttackGraph({ taintPaths: [{ source: 's', sink: 'strcpy', path: ['s', 'strcpy'] }] }));
    expect(JSON.stringify(g2.nodes)).toBe(a);
    expect(g2.nodes.every((n) => typeof n.x === 'number' && typeof n.y === 'number' && typeof n.z === 'number')).toBe(true);
  });
  it('stores and queries via the store seam', async () => {
    const store = new InMemoryStore();
    const { graph } = demoSample();
    await store.upsert(graph);
    expect((await store.shortest()).length).toBe(3);
  });
});
