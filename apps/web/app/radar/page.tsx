import AmbientScene from '../AmbientScene';
import RadarClient from './RadarClient';

export default function RadarPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 1180 }}>
        <p className="sf-eyebrow">SENTINELFORGE v3 · PREDICTIVE DEFENSE</p>
        <h1 className="sf-h1 sf-gradient-text">Disclosed today. Verdict in minutes.</h1>
        <p className="sf-sub">
          The radar matches fresh advisories against every SBOM you hold and re-queues the twin —
          while patch verification proves fixes removed the path instead of renaming the version.
        </p>
        <div style={{ marginTop: 8 }}>
          <RadarClient />
        </div>
      </main>
    </>
  );
}
