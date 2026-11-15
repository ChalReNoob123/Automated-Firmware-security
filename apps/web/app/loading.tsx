export default function Loading() {
  return (
    <main className="sf-page" style={{ textAlign: 'center', paddingTop: 90 }}>
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        <div className="uv-loader" />
      </div>
      <p style={{ color: '#22d3ee', letterSpacing: 4, fontSize: 13, marginTop: 22 }}>TRACING…</p>
    </main>
  );
}
