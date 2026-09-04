import AmbientScene from '../AmbientScene';
import AttackRunner from './AttackRunner';

export default function AttacksPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 1180 }}>
        <p className="sf-eyebrow">SENTINELFORGE v3 · ADVERSARY EMULATION</p>
        <h1 className="sf-h1 sf-gradient-text">Attack it before they do.</h1>
        <p className="sf-sub">
          Each scenario boots a fresh twin and performs the intrusion live — inputs, snapshots,
          impact record with repro bundle. Pick a scenario, execute, then replay the kill chain.
        </p>
        <div style={{ marginTop: 8 }}>
          <AttackRunner />
        </div>
      </main>
    </>
  );
}
