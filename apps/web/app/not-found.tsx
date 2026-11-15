import AmbientScene from './AmbientScene';
import { PageHeader } from './motionKit';

export default function NotFound() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ textAlign: 'center', paddingTop: 90 }}>
        <PageHeader
          eyebrow="404 · OFF THE MAP"
          title="No attack surface here."
          sub="The page you probed doesn't exist. The twins, chains and scenarios are one click away."
        />
        <div style={{ display: 'flex', gap: 12, justifyContent: 'center', marginTop: 26, flexWrap: 'wrap' }}>
          <a className="sf-btn-primary" href="/">Back to Forge</a>
          <a className="sf-btn-ghost" href="/attacks">Run an attack sim</a>
        </div>
      </main>
    </>
  );
}
