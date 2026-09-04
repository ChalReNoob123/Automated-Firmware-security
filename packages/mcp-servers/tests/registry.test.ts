import { describe, expect, it } from 'vitest';
import { callLocal, listLocalTools } from '../src/index.js';

process.env.EPSS_LIVE = '0'; // deterministic: never hit the network in unit tests

describe('mcp registry', () => {
  it('lists all seven servers', () => {
    expect(listLocalTools().map((s) => s.server).sort()).toEqual([
      'bindiff-mcp',
      'binwalk-mcp',
      'cve-epss-mcp',
      'fuzz-orchestrator-mcp',
      'graph-query-mcp',
      'qemu-mcp',
      'symbolic-exec-mcp',
    ]);
  });
  it('detects containers through binwalk-mcp', async () => {
    const r = await callLocal('binwalk-mcp', 'detect_containers', { imageHex: '68737173' });
    expect(r.output).toEqual([{ kind: 'squashfs', offset: 0, tool: 'sasquatch/unsquashfs' }]);
  });
  it('rejects bad hex', async () => {
    await expect(callLocal('binwalk-mcp', 'detect_containers', { imageHex: 'zz' })).rejects.toThrow();
  });
  it('runs a stateful qemu session', async () => {
    const b = await callLocal('qemu-mcp', 'session_boot', { arch: 'arm' });
    const sid = (b.output as { id: string }).id;
    await expect(callLocal('qemu-mcp', 'session_boot', { arch: 'bogus' })).rejects.toThrow(/arch/);
    const inp = await callLocal('qemu-mcp', 'session_input', { sessionId: sid, input: 'root' });
    expect((inp.output as { inputs: number }).inputs).toBe(1);
    const snap = await callLocal('qemu-mcp', 'session_snapshot', { sessionId: sid });
    const rep = await callLocal('qemu-mcp', 'session_replay', { sessionId: sid, snapshotId: (snap.output as { id: string }).id });
    expect((rep.output as { match: boolean }).match).toBe(true);
  });
  it('traces taint and validates edges', async () => {
    const r = await callLocal('symbolic-exec-mcp', 'trace_taint', { graphText: 'recv -> strcpy' });
    expect(r.output).toEqual([{ source: 'recv', sink: 'strcpy', path: ['recv', 'strcpy'], sanitized: false }]);
    await expect(callLocal('symbolic-exec-mcp', 'trace_taint', { graphText: 'junk' })).rejects.toThrow();
  });
  it('scores CVEs and rejects bad formats', async () => {
    const miss = await callLocal('cve-epss-mcp', 'epss_lookup', { cve: 'CVE-2024-3094' });
    expect((miss.output as { epss: null }).epss).toBeNull();
    await expect(callLocal('cve-epss-mcp', 'epss_lookup', { cve: 'nope' })).rejects.toThrow();
  });
  it('verifies patches and diffs builds', async () => {
    const v = await callLocal('bindiff-mcp', 'verify_patch', { oldText: 'strcpy(d,s);', newText: 'strncpy(d,s,8);', vulnSink: 'strcpy' });
    expect((v.output as { verdict: string }).verdict).toBe('patched');
  });
  it('rejects unknown servers and tools', async () => {
    await expect(callLocal('nope-mcp' as never, 'x')).rejects.toThrow();
    await expect(callLocal('binwalk-mcp', 'nope')).rejects.toThrow();
  });
});
