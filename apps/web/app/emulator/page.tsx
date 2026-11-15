import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import EmulatorPanel from '../EmulatorPanel';

export default function EmulatorPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page">
        <PageHeader
          eyebrow="SENTINELFORGE v3 · DIGITAL TWIN"
          title="Boot it. Break it. Replay it."
          sub="Live twin console with snapshotting — every crash captures its own repro bundle (snapshot + input trace), so any finding replays step by step."
        />
        <EmulatorPanel />
      </main>
    </>
  );
}
