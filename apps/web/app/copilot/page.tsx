import AmbientScene from '../AmbientScene';
import CopilotPanel from '../CopilotPanel';

export default function CopilotPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page">
        <p className="sf-eyebrow">SENTINELFORGE v3 · SECURITY COPILOT</p>
        <h1 className="sf-h1 sf-gradient-text">Ask the engines.</h1>
        <p className="sf-sub">
          Every answer is grounded in live tool output — attack paths, taint traces, fuzz results,
          EPSS lookups — with the producing MCP server cited. Read-only, always.
        </p>
        <CopilotPanel />
      </main>
    </>
  );
}
