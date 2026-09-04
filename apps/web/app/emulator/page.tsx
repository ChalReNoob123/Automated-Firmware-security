import AmbientScene from '../AmbientScene';
import EmulatorPanel from '../EmulatorPanel';

export default function EmulatorPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page">
        <p className="sf-eyebrow">SENTINELFORGE v3 · DIGITAL TWIN</p>
        <h1 className="sf-h1 sf-gradient-text">Boot it. Break it. Replay it.</h1>
        <p className="sf-sub">
          Live twin console with snapshotting — every crash captures its own repro bundle
          (snapshot + input trace), so any finding replays step by step.
        </p>
        <EmulatorPanel />
      </main>
    </>
  );
}
