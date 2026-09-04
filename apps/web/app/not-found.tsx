export default function NotFound() {
  return (
    <main className="sf-page" style={{ textAlign: 'center', paddingTop: 90 }}>
      <p className="sf-eyebrow">404 · OFF THE MAP</p>
      <h1 className="sf-h1 sf-gradient-text">No attack surface here.</h1>
      <p className="sf-sub" style={{ margin: '0 auto' }}>The page you probed doesn&apos;t exist. The twins, chains and scenarios are one click away.</p>
      <div style={{ display: 'flex', gap: 12, justifyContent: 'center', marginTop: 26, flexWrap: 'wrap' }}>
        <a className="sf-btn-primary" href="/">Back to Forge</a>
        <a className="sf-btn-ghost" href="/attacks">Run an attack sim</a>
      </div>
    </main>
  );
}
