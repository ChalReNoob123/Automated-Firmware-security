// Predictive N-day radar (spec: reacts the instant a new CVE hits your SBOM).
// Flow: ingest advisory → match SBOM components → exploitability verdict →
// re-queue the digital twin. Matching is REAL (name + purl + version-range);
// the twin re-run hook is a run descriptor the orchestrator executes.
// Feed parsing maps the NVD 2.0 CVE schema subset we actually consume.
export type AdvisoryComponent = { name: string; purl?: string; versionEnd?: string; versionEndType?: 'excluding' | 'including' };

export type CveAdvisory = {
  id: string; // CVE-YYYY-NNNN
  published: string; // ISO date
  summary: string;
  affected: AdvisoryComponent[];
  hasPoc?: boolean;
  epss?: number;
};

export type SbomRef = { name: string; version: string; purl?: string };

export type ComponentMatch = {
  advisoryId: string;
  component: string;
  installedVersion: string;
  inRange: boolean; // installed version falls inside the affected range (or range unknown)
  rangeNote: string;
};

function cmpVersions(a: string, b: string): number {
  const pa = a.split(/[.\-+]/).map((x) => parseInt(x, 10));
  const pb = b.split(/[.\-+]/).map((x) => parseInt(x, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = isNaN(pa[i] ?? NaN) ? 0 : (pa[i] ?? 0);
    const y = isNaN(pb[i] ?? NaN) ? 0 : (pb[i] ?? 0);
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

const norm = (s: string) => s.toLowerCase().replace(/[-_]/g, '');

export function matchSbom(sbom: SbomRef[], advisory: CveAdvisory): ComponentMatch[] {
  const out: ComponentMatch[] = [];
  for (const aff of advisory.affected) {
    const hit = sbom.find((c) => norm(c.name) === norm(aff.name) || (aff.purl && c.purl === aff.purl));
    if (!hit) continue;
    if (!aff.versionEnd) {
      out.push({ advisoryId: advisory.id, component: hit.name, installedVersion: hit.version, inRange: true, rangeNote: 'advisory lists no fixed version — assume affected until triaged' });
      continue;
    }
    if (hit.version === 'unknown') {
      out.push({ advisoryId: advisory.id, component: hit.name, installedVersion: hit.version, inRange: true, rangeNote: 'installed version unknown (see SBOM enrichment) — assume affected' });
      continue;
    }
    const cmp = cmpVersions(hit.version, aff.versionEnd);
    const inside = aff.versionEndType === 'including' ? cmp <= 0 : cmp < 0;
    out.push({
      advisoryId: advisory.id,
      component: hit.name,
      installedVersion: hit.version,
      inRange: inside,
      rangeNote: inside ? `installed ${hit.version} < fixed ${aff.versionEnd}` : `installed ${hit.version} already past fixed ${aff.versionEnd}`,
    });
  }
  return out;
}

export type RadarVerdict = {
  advisoryId: string;
  exposed: boolean;
  urgency: 'act-now' | 'triage' | 'clear';
  detail: string;
  twinReRun: { firmwareRef: string; focus: string } | null;
};

// Verdict policy: exposed + PoC-or-high-EPSS → act-now; exposed → triage with a
// twin re-run focused on the component; no match → clear.
export function verdictFor(match: ComponentMatch[], advisory: CveAdvisory, firmwareRef: string): RadarVerdict {
  const exposed = match.filter((m) => m.inRange);
  if (exposed.length === 0)
    return { advisoryId: advisory.id, exposed: false, urgency: 'clear', detail: 'no SBOM component in affected range', twinReRun: null };
  const hot = (advisory.hasPoc ?? false) || (advisory.epss ?? 0) >= 0.5;
  const names = exposed.map((m) => `${m.component}@${m.installedVersion}`).join(', ');
  return {
    advisoryId: advisory.id,
    exposed: true,
    urgency: hot ? 'act-now' : 'triage',
    detail: `${advisory.id} affects ${names}${advisory.hasPoc ? ' — public PoC observed' : ''}${advisory.epss !== undefined ? ` (EPSS ${advisory.epss})` : ''}`,
    twinReRun: { firmwareRef, focus: exposed.map((m) => m.component).join(',') },
  };
}

// Minimal NVD 2.0 mapping — consumes configurations[].nodes[].cpeMatch[]
// (vulnerable=true) + descriptions + published + optional EPSS sidecar.
export function parseNvd(items: {
  id: string;
  published: string;
  descriptions?: { lang: string; value: string }[];
  configurations?: { nodes?: { cpeMatch?: { vulnerable?: boolean; criteria?: string; versionEndExcluding?: string; versionEndIncluding?: string }[] }[] }[];
  epss?: number;
  hasPoc?: boolean;
}[]): CveAdvisory[] {
  return items.map((it) => {
    const affected: AdvisoryComponent[] = [];
    for (const cfg of it.configurations ?? [])
      for (const node of cfg.nodes ?? [])
        for (const m of node.cpeMatch ?? []) {
          if (m.vulnerable === false || !m.criteria) continue;
          const parts = m.criteria.split(':');
          const name = parts[4] ?? 'unknown'; // cpe:2.3:a:vendor:PRODUCT:version:…
          affected.push({
            name,
            ...(m.versionEndExcluding ? { versionEnd: m.versionEndExcluding, versionEndType: 'excluding' as const } : {}),
            ...(m.versionEndIncluding ? { versionEnd: m.versionEndIncluding, versionEndType: 'including' as const } : {}),
          });
        }
    return {
      id: it.id,
      published: it.published,
      summary: it.descriptions?.find((d) => d.lang === 'en')?.value ?? '',
      affected,
      ...(it.epss !== undefined ? { epss: it.epss } : {}),
      ...(it.hasPoc !== undefined ? { hasPoc: it.hasPoc } : {}),
    };
  });
}

// Canned feed for the demo endpoint + UI first paint (clearly labeled sample data).
export function demoAdvisories(): CveAdvisory[] {
  return [
    {
      id: 'CVE-2024-DEMO--httpd',
      published: '2024-11-02T00:00:00Z',
      summary: 'Sample: stack overflow in demo httpd query parser before v2.0 (training data only).',
      affected: [{ name: 'httpd', versionEnd: '2.0', versionEndType: 'excluding' }],
      hasPoc: true,
      epss: 0.78,
    },
    {
      id: 'CVE-2024-DEMO-tls',
      published: '2024-10-18T00:00:00Z',
      summary: 'Sample: timing side-channel in demo TLS stack (training data only).',
      affected: [{ name: 'tls-mini', versionEnd: '1.4.2', versionEndType: 'excluding' }],
      epss: 0.12,
    },
  ];
}
