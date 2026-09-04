// Pipeline integration tests — including the artifacts-clobber regression:
// unpack stores binary evidence BEFORE sbom/vex are attached, and all of it
// must survive to the final state.
import { describe, expect, it } from 'vitest';
import { getRun, runPipeline } from '../src/index.js';

const elfImage = () => {
  const elf = Buffer.alloc(64);
  elf.writeUInt32LE(0x464c457f, 0);
  elf[4] = 2;
  elf[5] = 1;
  elf.writeUInt16LE(40, 18);
  return new Uint8Array(elf);
};

describe('runPipeline', () => {
  it('runs acquisition→discovery and keeps every artifact', async () => {
    const s = await runPipeline(elfImage(), { version: '9.9' }, {
      textForStatic: 'strcpy(d,s);\n',
      rotEvidence: {
        chain: [{ name: 'rom', hash: 'a', signed: true, signatureValid: true, keyRef: 'f', immutable: true, measuresNext: 'b' }, { name: 'bl', hash: 'b', signed: true, signatureValid: true, keyRef: 'OEM' }],
        rollback: { version: '9.9', rollbackCounter: 2, antiRollbackFuse: true },
        probeText: 'atecc608',
      },
      discovery: { callGraphText: 'recv -> strcpy', fuzzHarness: 'demo', fuzzIterations: 500 },
      patchCompare: {
        oldRaw: new Uint8Array(1024).fill(1),
        newRaw: new Uint8Array(1024).fill(2),
        oldText: 'strcpy(d,s);',
        newText: 'strncpy(d,s,8);',
        vulnSink: 'strcpy',
      },
    });
    expect(s.stages).toMatchObject({ acquisition: 'done', unpack: 'done', static: 'done', sbom: 'done', 'root-of-trust': 'done', discovery: 'done' });
    expect(s.artifacts.sbom).toBeDefined();
    expect(s.artifacts.vex).toBeDefined();
    expect(s.artifacts.binary?.elf).toMatchObject({ valid: true, machine: 'ARM' });
    expect(s.rotReport?.chain.ok).toBe(true);
    expect(s.consensus[0]).toMatchObject({ key: 'sink:strcpy', confidence: 'Confirmed' });
    expect(s.patchVerdict?.verdict).toBe('patched');
    expect(getRun(s.runId)?.runId).toBe(s.runId);
  });

  it('leaves later stages pending without evidence', async () => {
    const s = await runPipeline(new Uint8Array([9, 9]), { version: '0.1' });
    expect(s.stages['root-of-trust']).toBe('pending');
    expect(s.stages.discovery).toBe('pending');
    expect(s.consensus).toEqual([]);
  });
});
