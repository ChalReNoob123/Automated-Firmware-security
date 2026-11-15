import AmbientScene from '../AmbientScene';
import { PageHeader } from '../motionKit';
import CopilotPanel from '../CopilotPanel';

export default function CopilotPage() {
  return (
    <>
      <AmbientScene />
      <main className="sf-page">
        <PageHeader
          eyebrow="SENTINELFORGE v3 · SECURITY COPILOT"
          title="Ask the engines."
          sub="Every answer is grounded in live tool output — attack paths, taint traces, fuzz results, EPSS lookups — with the producing MCP server cited. Read-only, always."
        />
        <CopilotPanel />
      </main>
    </>
  );
}
