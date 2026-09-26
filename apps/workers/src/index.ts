// SentinelForge workers entry — Modules 2+3: acquisition → unpack → static+secrets → SBOM/VEX → RoT.
// Later stages (discovery/fuzz, network, report) are sequenced here but
// owned by Modules 5–7; see pipeline.ts handoff.
export { PIPELINE_ORDER, runPipeline, getRun, type RunState, type PipelineStage, type StageStatus } from './pipeline.js';
export { acquire, type FirmwareRecord } from './stages/acquisition.js';
export { detectContainers, planUnpack, type ContainerHit, type UnpackPlan } from './stages/unpack.js';
export { scanSecrets, scanSinks, DANGEROUS_SINKS, YARA_PACKS } from './stages/static.js';
export { buildSbom, buildVex, inferComponents } from './stages/sbom.js';
export { verifyRootOfTrust, verifyChain, checkRollback, probeDebugInterfaces, classifyKeyStorage, mapPsa, type RoTReport, type RoTEvidence } from './stages/rootOfTrust.js';
export { startSession, getSession, feedInput, takeSnapshot, replay, recordCrash, stopSession, qemuAvailable, type BootSession, type EmulatorConfig, type Snapshot, type CrashRecord } from './stages/emulator.js';
export { parseCallGraph, traceTaint, callersOf, TAINT_SOURCES, TAINT_SINKS, SANITIZERS, type TaintPath, type CallGraph } from './stages/taint.js';
export { fuzz, demoHarness, noveltyGuidance, DEFAULT_DICT, type Harness, type GuidanceModel, type FuzzResult, type FuzzCrash } from './stages/fuzz.js';
export { correlate, confidenceOf, priorityOf, type EngineId, type Confidence, type Candidate, type ScoredFinding, type SsvcDecision } from './stages/consensus.js';
export { matchSbom, verdictFor, parseNvd, demoAdvisories, type CveAdvisory, type SbomRef, type ComponentMatch, type RadarVerdict } from './stages/nday.js';
export { verifyPatch, type PatchReport, type PatchVerdict } from './stages/patchVerify.js';
export { parseElf, carveGzip, detectNativeTools, type ElfInfo, type GzipMember, type NativeCaps } from './stages/binary.js';
export { strictTarget, buggyGattTarget, fuzzProtocol, BLE_GATT, MQTT, MODBUS, type Machine, type ProtoFinding, type ProtoResult } from './stages/protocol.js';
export { GenomeIndex, shingles, jaccard, minhash, minhashSimilarity, SHINGLE_N, SHINGLE_STRIDE, MINHASH_K, type GenomeHit } from './stages/genome.js';
export { publish, subscribe } from './bus.js';

import { runPipeline } from './pipeline.js';
import { startSession, feedInput, takeSnapshot, replay, recordCrash } from './stages/emulator.js';
import { verifyPatch } from './stages/patchVerify.js';
import { matchSbom, verdictFor, demoAdvisories } from './stages/nday.js';
import { BLE_GATT, MQTT, MODBUS, buggyGattTarget, fuzzProtocol, strictTarget } from './stages/protocol.js';
import { GenomeIndex } from './stages/genome.js';

// CLI demo: `npm run dev -- demo` runs a synthetic image through stages 1–5 (incl. RoT).
if (process.argv[2] === 'demo') {
  const fake = new Uint8Array([0x68, 0x73, 0x71, 0x73, 0x00, 0x01, 0x1f, 0x8b]);
  const text = 'password = "s3cret-ota-key"\nstrcpy(dst, src);\nAKIAIOSFODNN7EXAMPLE\nconsole=ttyS0,115200\n';
  runPipeline(
    fake,
    { version: '1.0-demo' },
    {
      textForStatic: text,
      rotEvidence: {
        chain: [
          { name: 'rom-rot', hash: 'aa01', signed: true, signatureValid: true, keyRef: 'die-fused', immutable: true, measuresNext: 'bb02' },
          { name: 'u-boot', hash: 'bb02', signed: true, signatureValid: true, keyRef: 'OEM-root-CA', measuresNext: 'cc03' },
          { name: 'kernel', hash: 'cc03', signed: true, signatureValid: true, keyRef: 'OEM-root-CA' },
        ],
        rollback: { version: '1.0-demo', prevVersion: '0.9', rollbackCounter: 7, antiRollbackFuse: true },
        probeText: text + 'keys in atecc608 secure element\n',
      },
    }
  ).then((s) => {
    console.log(JSON.stringify({ runId: s.runId, sha256: s.firmware.sha256, stages: s.stages, secrets: s.findings.secrets, sinks: s.findings.sinks, sbomComponents: s.artifacts.sbom?.components, rot: s.rotReport }, null, 2));
  });
}

// CLI demo: `npm run dev -- demo-emu` exercises snapshot → crash → step-by-step replay.
if (process.argv[2] === 'demo-emu') {
  const s = startSession({ arch: 'arm', memoryMb: 256 });
  feedInput(s, 'root');
  const snap = takeSnapshot(s, 'pre-fuzz baseline');
  feedInput(s, '%x'.repeat(64)); // crash-inducing input
  const crash = recordCrash(s, 'SIGSEGV in httpd (demo)');
  const r = replay(s, snap.id);
  console.log(JSON.stringify({ session: s.id, backend: s.backend, snapshot: snap.id, crash, replay: r }, null, 2));
}

// CLI demo: `npm run dev -- demo-patch` proves a real fix and catches a fake one.
if (process.argv[2] === 'demo-patch') {
  const pad = (n: number) => new Uint8Array(n);
  const oldRaw = Uint8Array.from([...Buffer.from('FIRMWARE-v1'), ...pad(2048)]);
  const newRaw = Uint8Array.from([...Buffer.from('FIRMWARE-v2'), ...pad(2048)]);
  const oldText = 'strcpy(dst, src);\npassword = "s3cret"\n';
  const fixedText = 'strncpy(dst, src, sizeof(dst));\n';
  console.log(
    JSON.stringify(
      {
        realFix: verifyPatch({ oldRaw, newRaw, oldText, newText: fixedText, vulnSink: 'strcpy', oldVersion: '1.0', newVersion: '1.1' }),
        fakePatch: verifyPatch({ oldRaw, newRaw: oldRaw, oldText, newText: oldText, vulnSink: 'strcpy', oldVersion: '1.0', newVersion: '1.1' }),
      },
      null,
      2
    )
  );
}

// CLI demo: `npm run dev -- demo-radar` matches a feed against an SBOM.
if (process.argv[2] === 'demo-radar') {
  const sbom = [
    { name: 'httpd', version: '1.9', purl: 'pkg:generic/httpd@1.9' },
    { name: 'tls-mini', version: '1.4.2' },
  ];
  for (const adv of demoAdvisories()) {
    const matches = matchSbom(sbom, adv);
    console.log(JSON.stringify({ advisory: adv.id, verdict: verdictFor(matches, adv, 'fw-demo') }, null, 2));
  }
}

// CLI demo: `npm run dev -- demo-proto` differential protocol fuzzing.
if (process.argv[2] === 'demo-proto') {
  for (const [name, m] of [['ble-gatt', BLE_GATT], ['mqtt', MQTT], ['modbus', MODBUS]] as const) {
    const buggy = fuzzProtocol(m, name === 'ble-gatt' ? buggyGattTarget(m) : strictTarget(m), { iterations: 3000 });
    const clean = fuzzProtocol(m, strictTarget(m), { iterations: 3000 });
    console.log(JSON.stringify({ machine: name, buggyFindings: buggy.findings.slice(0, 3), cleanFindings: clean.findings.length }, null, 2));
  }
}

// CLI demo: `npm run dev -- demo-genome` cross-image similarity search.
if (process.argv[2] === 'demo-genome') {
  const idx = new GenomeIndex();
  const lib = Buffer.from('vulnerable-lib-crypto-routines-v1.2.'); 
  const libPatch = Buffer.from('vulnerable-lib-crypto-routines-v1.3.');
  const other = Buffer.from('totally-unrelated-bootloader-blob-xyz');
  idx.add('fw-a:libcrypto', new Uint8Array(lib));
  idx.add('fw-b:bootloader', new Uint8Array(other));
  console.log(JSON.stringify(idx.query(new Uint8Array(libPatch), 0.3), null, 2));
}

// CLI demo: `npm run dev -- demo-discovery` runs taint + fuzz + consensus end to end.
if (process.argv[2] === 'demo-discovery') {
  const fake = new Uint8Array([0x68, 0x73, 0x71, 0x73]);
  runPipeline(
    fake,
    { version: '1.0-demo' },
    {
      textForStatic: 'strcpy(dst, src);\nmemcpy(d, s, n);\n',
      discovery: {
        callGraphText: ['recv -> parse_query', 'parse_query -> strcpy', 'ble_gatt_write -> memcpy', 'main -> recv'].join('\n'),
        fuzzHarness: 'demo',
        fuzzIterations: 3000,
      },
    }
  ).then((s) => {
    console.log(
      JSON.stringify(
        { stages: s.stages, taintPaths: s.taintPaths, fuzz: s.fuzz ? { execs: s.fuzz.execs, coverage: s.fuzz.coverage, crashes: s.fuzz.crashes } : null, consensus: s.consensus },
        null,
        2
      )
    );
  });
}
