// Stage 4 — SBOM (CycloneDX 1.5) + VEX (CISA exploitability statements).
// Components come from unpack evidence + static findings; N-day radar (Module 9) later
// re-runs the digital twin the moment a CVE hits any component listed here.
import type { FirmwareRecord } from './acquisition.js';
import type { ContainerHit } from './unpack.js';
import type { SecretFinding, SinkHit } from './static.js';

export type SbomComponent = {
  type: 'library' | 'operating-system' | 'firmware';
  name: string;
  version: string;
  purl?: string;
  evidence: string; // why we believe it's present, e.g. 'squashfs@0x0 strings match'
};

export type CycloneDxSbom = {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  version: 1;
  metadata: { timestamp: string; component: { type: 'firmware'; name: string; version: string; hashes: { alg: 'SHA-256'; content: string }[] } };
  components: { type: string; name: string; version: string; purl?: string; evidence?: { licenses?: unknown[] } }[];
};

export type VexStatement = {
  cve: string;
  status: 'affected' | 'not_affected' | 'under_investigation' | 'fixed';
  justification?: string;
};

export function buildSbom(fw: FirmwareRecord, components: SbomComponent[]): CycloneDxSbom {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: {
        type: 'firmware',
        name: fw.id,
        version: fw.version,
        hashes: [{ alg: 'SHA-256', content: fw.sha256 }],
      },
    },
    components: components.map((c) => ({ type: c.type, name: c.name, version: c.version, ...(c.purl ? { purl: c.purl } : {}) })),
  };
}

// Heuristic component inference from container hits — real SBOM enrichment (package
// versions via strings/headers) is the Module 2 follow-up inside the unpack container.
export function inferComponents(hits: ContainerHit[]): SbomComponent[] {
  const comps: SbomComponent[] = [];
  if (hits.some((h) => h.kind === 'squashfs' || h.kind === 'jffs2' || h.kind === 'ubi' || h.kind === 'yaffs2')) {
    comps.push({ type: 'operating-system', name: 'linux', version: 'unknown', purl: 'pkg:generic/linux@unknown', evidence: 'embedded filesystem detected' });
  }
  if (hits.some((h) => h.kind === 'uimage' || h.kind === 'elf')) {
    comps.push({ type: 'firmware', name: 'bootloader/kernel', version: 'unknown', evidence: 'uImage/ELF header detected' });
  }
  return comps;
}

export function buildVex(
  statements: VexStatement[]
): { bomFormat: 'CycloneDX'; specVersion: '1.5'; version: 1; vulnerabilities: unknown[] } {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    vulnerabilities: statements.map((s) => ({
      id: s.cve,
      analysis: { state: s.status === 'affected' ? 'exploitable' : s.status === 'fixed' ? 'resolved' : 'in_triage', ...(s.justification ? { detail: s.justification } : {}) },
    })),
  };
}

export type Stage4Result = {
  sbom: CycloneDxSbom;
  secrets: SecretFinding[];
  sinks: SinkHit[];
  vex: ReturnType<typeof buildVex>;
};
