import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import AndroidLab from './AndroidLab';

export default function LabPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 1180 }}>
        <PageHeader
          eyebrow="SENTINELFORGE v3 · DEVICE LAB"
          title="Bench hardware, virtually."
          sub="Power on a profile, drive its apps, tail logcat, work the ADB shell — then bridge the same architecture to a backend twin for instrumentation and attack runs."
        />
        <div style={{ marginTop: 8 }}>
          <AndroidLab />
        </div>
      </main>
    </>
  );
}
