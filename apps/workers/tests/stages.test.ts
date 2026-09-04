// SentinelForge workers — stage unit tests. Every assertion below pins behavior
// that previously broke or was only ever verified by ad-hoc scripts.
import { describe, expect, it } from 'vitest';
import {
  acquire,
  buildSbom,
  callersOf,
  carveGzip,
  checkRollback,
  classifyKeyStorage,
  confidenceOf,
  correlate,
  detectContainers,
  feedInput,
  fuzz,
  demoHarness,
  inferComponents,
  mapPsa,
  matchSbom,
  parseCallGraph,
  parseElf,
  planUnpack,
  priorityOf,
  probeDebugInterfaces,
  recordCrash,
  replay,
  scanSecrets,
  scanSinks,
  startSession,
  takeSnapshot,
  traceTaint,
  verifyChain,
  verifyPatch,
  verifyRootOfTrust,
  parseNvd,
} from '../src/index.js';
import { gzipSync } from 'node:zlib';

describe('acquisition', () => {
  it('hashes and records', () => {
    const fw = acquire(new Uint8Array([1, 2, 3]), { version: '1.0' });
    expect(fw.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(fw.bytes).toBe(3);
    expect(fw.encryptedAtRest).toBe(true);
  });
  it('rejects empty images', () => {
    expect(() => acquire(new Uint8Array(), { version: '1' })).toThrow();
  });
});

describe('unpack', () => {
  it('detects squashfs + gzip', () => {
    const hits = detectContainers(new Uint8Array([0x68, 0x73, 0x71, 0x73, 0x1f, 0x8b]));
    expect(hits.map((h) => h.kind)).toEqual(['squashfs', 'gzip']);
  });
  it('plans extraction per hit', () => {
    const plan = planUnpack(new Uint8Array([0x7f, 0x45, 0x4c, 0x46]));
    expect(plan.extractable).toBe(true);
    expect(plan.hits[0].kind).toBe('elf');
  });
  it('reports unextractable blobs honestly', () => {
    expect(planUnpack(new Uint8Array([9, 9, 9])).extractable).toBe(false);
  });
});

describe('static', () => {
  it('finds secrets with redacted previews', () => {
    const f = scanSecrets('password = "s3cret-key"\nAKIAIOSFODNN7EXAMPLE\n');
    expect(f.map((x) => x.ruleId).sort()).toEqual(['aws-access-key', 'hardcoded-password']);
    expect(f[0].preview).not.toContain('s3cret-key');
  });
  it('counts dangerous sinks', () => {
    expect(scanSinks('strcpy(a,b); strcpy(c,d); memcpy(x,y,1);')).toEqual([
      { sink: 'strcpy', count: 2 },
      { sink: 'memcpy', count: 1 },
    ]);
  });
});

describe('sbom', () => {
  it('builds CycloneDX with firmware hash', () => {
    const fw = acquire(new Uint8Array([1]), { version: '2.0' });
    const sbom = buildSbom(fw, inferComponents([{ kind: 'squashfs', offset: 0, tool: 'x' }]));
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.metadata.component.hashes[0].content).toBe(fw.sha256);
    expect(sbom.components.some((c) => c.name === 'linux')).toBe(true);
  });
});

describe('root-of-trust', () => {
  const goodChain = [
    { name: 'rom', hash: 'a1', signed: true, signatureValid: true, keyRef: 'fused', immutable: true, measuresNext: 'b2' },
    { name: 'uboot', hash: 'b2', signed: true, signatureValid: true, keyRef: 'OEM' },
  ];
  it('verifies a linked chain', () => {
    expect(verifyChain(goodChain).ok).toBe(true);
  });
  it('fails unsigned stages and trust gaps', () => {
    const r = verifyChain([{ name: 'rom', hash: 'a1', signed: false, signatureValid: false, keyRef: 'none' }]);
    expect(r.ok).toBe(false);
    expect(r.issues.length).toBeGreaterThan(0);
  });
  it('catches measurement mismatch', () => {
    const r = verifyChain([{ ...goodChain[0], measuresNext: 'ff' }, goodChain[1]]);
    expect(r.ok).toBe(false);
  });
  it('detects downgrades and missing fuses', () => {
    expect(checkRollback({ version: '1.0', prevVersion: '2.0', rollbackCounter: 1, antiRollbackFuse: true }).downgrade).toBe(true);
    expect(checkRollback({ version: '1.0' }).protected).toBe(false);
    expect(checkRollback({ version: '1.0', rollbackCounter: 4, antiRollbackFuse: true }).protected).toBe(true);
  });
  it('probes debug interfaces', () => {
    const d = probeDebugInterfaces('console=ttyS0,115200\ntelnetd\n');
    expect(d.map((x) => x.id).sort()).toEqual(['telnetd', 'uart-console']);
  });
  it('classifies key storage', () => {
    expect(classifyKeyStorage('keys in atecc608').storage).toBe('hardware');
    expect(classifyKeyStorage('-----BEGIN PRIVATE KEY-----').storage).toBe('unprotected');
    expect(classifyKeyStorage('nothing here').storage).toBe('unknown');
  });
  it('maps PSA readiness and gates pass on debug exposure', () => {
    expect(mapPsa(true, true, 'hardware').level).toBe('Level 3-indicators');
    const r = verifyRootOfTrust({
      chain: goodChain,
      rollback: { version: '1', rollbackCounter: 1, antiRollbackFuse: true },
      probeText: 'console=ttyS0 atecc608',
    });
    expect(r.passed).toBe(false); // UART exposed despite L3 indicators
    expect(r.debug[0].id).toBe('uart-console');
  });
});

describe('taint', () => {
  it('parses edge text and rejects garbage', () => {
    expect(parseCallGraph('a -> b\n# comment\n')).toEqual({ a: ['b'], b: [] });
    expect(() => parseCallGraph('not an edge')).toThrow();
  });
  it('traces shortest source→sink paths, sanitizers last', () => {
    const g = parseCallGraph('recv -> parse\nparse -> strcpy\nrecv -> snprintf\nsnprintf -> sprintf');
    const paths = traceTaint(g);
    expect(paths[0]).toMatchObject({ source: 'recv', sink: 'strcpy' });
    expect(paths[paths.length - 1].sanitized).toBe(true);
  });
  it('lists callers caller-first', () => {
    const paths = callersOf(parseCallGraph('a -> b\nb -> strcpy\na -> strcpy'), 'strcpy');
    expect(paths).toContainEqual(['a', 'strcpy']);
    expect(paths).toContainEqual(['a', 'b', 'strcpy']);
  });
});

describe('fuzz', () => {
  it('is deterministic per seed and finds the demo overflow', () => {
    const o = { seeds: [Buffer.from('GET /')], iterations: 3000 };
    const a = fuzz(demoHarness, o);
    const b = fuzz(demoHarness, o);
    expect(a.crashes).toEqual(b.crashes);
    expect(a.crashes.length).toBeGreaterThan(0);
    expect(a.coverage).toContain(6);
  });
  it('caps runaway iterations', () => {
    const r = fuzz(demoHarness, { seeds: [Buffer.from('x')], iterations: 1e9, seed: 1 });
    expect(r.execs).toBeLessThanOrEqual(100001);
  });
});

describe('consensus', () => {
  it('gates confidence on corroboration', () => {
    expect(confidenceOf(['taint', 'static'])).toBe('Confirmed');
    expect(confidenceOf(['fuzz'])).toBe('Likely');
    expect(confidenceOf(['static'])).toBe('Unconfirmed');
  });
  it('weights priority by confidence + EPSS + SSVC', () => {
    expect(priorityOf({ engines: ['taint', 'static'], epss: 0.8, ssvc: 'Act' })).toBe(100);
    expect(priorityOf({ engines: ['static'] })).toBe(10);
  });
  it('correlates engines by sink key', () => {
    const out = correlate({
      taintPaths: [{ sink: 'strcpy', path: ['recv', 'strcpy'], sanitized: false }],
      fuzzCrashes: [{ reason: 'stack-overflow in strcpy (x)', inputHex: 'ab' }],
      sinks: [{ sink: 'strcpy', count: 1 }],
      secrets: [],
    });
    expect(out[0].key).toBe('sink:strcpy');
    expect(out[0].confidence).toBe('Confirmed');
    expect(out[0].engines).toEqual(expect.arrayContaining(['taint', 'fuzz', 'static']));
  });
});

describe('nday', () => {
  const adv = { id: 'CVE-1', published: 'x', summary: '', affected: [{ name: 'lib', versionEnd: '2.0', versionEndType: 'excluding' as const }] };
  it('matches in-range installs and clears fixed ones', () => {
    expect(matchSbom([{ name: 'lib', version: '1.5' }], adv)[0].inRange).toBe(true);
    expect(matchSbom([{ name: 'lib', version: '3.0' }], adv)[0].inRange).toBe(false);
  });
  it('assumes affected when versions are unknown', () => {
    expect(matchSbom([{ name: 'lib', version: 'unknown' }], adv)[0].inRange).toBe(true);
  });
  it('parses NVD CPE nodes', () => {
    const [a] = parseNvd([
      { id: 'CVE-9', published: 'x', configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:acme:httpd:1.0:*:*:*:*:*:*:*', versionEndExcluding: '2.0' }] }] }] },
    ]);
    expect(a.affected).toEqual([{ name: 'httpd', versionEnd: '2.0', versionEndType: 'excluding' }]);
  });
});

describe('patchVerify', () => {
  const oldRaw = new Uint8Array(2048).fill(1);
  const newRaw = new Uint8Array(2048).fill(2);
  it('confirms a real fix and catches a fake', () => {
    const fixed = verifyPatch({ oldRaw, newRaw, oldText: 'strcpy(d,s);', newText: 'strncpy(d,s,8);', vulnSink: 'strcpy' });
    expect(fixed.verdict).toBe('patched');
    const fake = verifyPatch({ oldRaw, newRaw: oldRaw, oldText: 'strcpy(d,s);', newText: 'strcpy(d,s);', vulnSink: 'strcpy' });
    expect(fake.verdict).toBe('not-patched');
    expect(fake.similarity).toBe(1);
  });
});

describe('binary', () => {
  it('decodes ELF64 headers', () => {
    const elf = Buffer.alloc(64);
    elf.writeUInt32LE(0x464c457f, 0);
    elf[4] = 2;
    elf[5] = 1;
    elf.writeUInt16LE(40, 18);
    const info = parseElf(new Uint8Array(elf));
    expect(info).toMatchObject({ valid: true, bits: 64, endian: 'little', machine: 'ARM' });
  });
  it('rejects non-ELF', () => {
    expect(parseElf(new Uint8Array([1, 2, 3]))).toEqual({ valid: false, reason: expect.any(String) });
  });
  it('carves gzip members with inflate proof', () => {
    const gz = gzipSync(Buffer.from('hello-firmware-world'));
    const [m] = carveGzip(new Uint8Array(gz));
    expect(m.offset).toBe(0);
    expect(m.inflatedBytes).toBe(20);
  });
});

describe('emulator', () => {
  it('snapshots, crashes with repro, replays match', () => {
    const s = startSession({ arch: 'arm', memoryMb: 128 });
    feedInput(s, 'root');
    const snap = takeSnapshot(s, 'base');
    feedInput(s, '%x'.repeat(8));
    const crash = recordCrash(s, 'boom');
    expect(crash.snapshotId).not.toBeNull();
    expect(replay(s, snap.id).match).toBe(true);
    expect(s.status).toBe('crashed');
  });
});
