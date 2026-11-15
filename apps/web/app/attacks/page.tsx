import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import AttackRunner from './AttackRunner';

export default function AttacksPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 1180 }}>
        <PageHeader
          eyebrow="SENTINELFORGE v3 · ADVERSARY EMULATION"
          title="Attack it before they do."
          sub="Each scenario boots a fresh twin and performs the intrusion live — inputs, snapshots, impact record with repro bundle. Pick a scenario, execute, then replay the kill chain."
        />
        <div style={{ marginTop: 8 }}>
          <AttackRunner />
        </div>
      </main>
    </>
  );
}
