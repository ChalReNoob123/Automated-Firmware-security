import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import RadarClient from './RadarClient';

export default function RadarPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 1180 }}>
        <PageHeader
          eyebrow="SENTINELFORGE v3 · PREDICTIVE DEFENSE"
          title="Disclosed today. Verdict in minutes."
          sub="The radar matches fresh advisories against every SBOM you hold and re-queues the twin — while patch verification proves fixes removed the path instead of renaming the version."
        />
        <div style={{ marginTop: 8 }}>
          <RadarClient />
        </div>
      </main>
    </>
  );
}
