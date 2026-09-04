import AmbientScene from '../AmbientScene';
import AndroidLab from './AndroidLab';

export default function LabPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 1180 }}>
        <p className="sf-eyebrow">SENTINELFORGE v3 · DEVICE LAB</p>
        <h1 className="sf-h1 sf-gradient-text">Bench hardware, virtually.</h1>
        <p className="sf-sub">
          Power on a profile, drive its apps, tail logcat, work the ADB shell — then bridge the
          same architecture to a backend twin for instrumentation and attack runs.
        </p>
        <div style={{ marginTop: 8 }}>
          <AndroidLab />
        </div>
      </main>
    </>
  );
}
