import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import Reports from './Reports';

export default function ReportsPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 1100 }}>
        <PageHeader
          eyebrow="SENTINELFORGE v3 · EVIDENCE OUT"
          title="Export the verdict."
          sub="Markdown narrative for humans, JSON for pipelines, CycloneDX VEX for your vulnerability management — every finding with its confidence and repro ref."
        />
        <div style={{ marginTop: 8 }}>
          <Reports />
        </div>
      </main>
    </>
  );
}
