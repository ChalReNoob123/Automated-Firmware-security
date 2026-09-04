'use client';

// Route-level error boundary: a crashed section degrades to a styled panel,
// never a blank page. `reset` retries the render.
export default function Error({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="sf-page" style={{ textAlign: 'center', paddingTop: 90 }}>
      <p className="sf-eyebrow">RENDER FAULT CONTAINED</p>
      <h1 className="sf-h1">Something glitched.</h1>
      <p className="sf-sub" style={{ margin: '0 auto' }}>{error.message || 'An unexpected render error occurred.'}</p>
      <div style={{ display: 'flex', gap: 12, justifyContent: 'center', marginTop: 24 }}>
        <button className="sf-btn sf-btn-accent" onClick={reset}>Retry section</button>
        <a className="sf-btn-ghost" href="/">Back to Forge</a>
      </div>
    </main>
  );
}
