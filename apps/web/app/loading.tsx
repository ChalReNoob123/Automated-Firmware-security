export default function Loading() {
  return (
    <main className="sf-page" style={{ textAlign: 'center', paddingTop: 90 }}>
      <p style={{ color: '#22d3ee', letterSpacing: 4, fontSize: 13 }}>TRACING…</p>
      <div style={{ width: 220, height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.08)', margin: '18px auto 0', overflow: 'hidden' }}>
        <div className="sf-pipe-dot" style={{ position: 'relative', top: 0, marginTop: -3, animationDuration: '1.6s' }} />
      </div>
    </main>
  );
}
