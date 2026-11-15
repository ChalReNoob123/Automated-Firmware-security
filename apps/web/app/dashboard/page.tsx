import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import Dashboard from './Dashboard';

export default function DashboardPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 1180 }}>
        <PageHeader
          eyebrow="SENTINELFORGE v3 · FLEET POSTURE"
          title="One glance. Whole fleet."
          sub={
            <>
              Consensus health, priority queue, and engine coverage — computed live from
              your findings. Export the story from <a href="/reports" style={{ color: '#22d3ee' }}>/reports</a>.
            </>
          }
        />
        <div style={{ marginTop: 8 }}>
          <Dashboard />
        </div>
      </main>
    </>
  );
}
