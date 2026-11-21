import AmbientScene from '../../AmbientScene';
import { PageHeader } from '../../motionKit';
import FindingDetail from './FindingDetail';

// Round 33 — the evidence chain. The queue could show a verdict and a title;
// the reasoning that produced it only existed as a punctuation-separated string
// in the API. This page is that string, reconstructed: which engines fired,
// which families they belong to, which rule awarded the confidence, the exact
// priority arithmetic, and the snapshot the finding can be replayed from.
//
// The data is auth-scoped (memory token + silent refresh), so the fetch lives in
// the client component and the shell stays static.
export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <>
      <AmbientScene />
      <main className="sf-page" style={{ maxWidth: 1180 }}>
        <PageHeader
          eyebrow="SENTINELFORGE v3 · EVIDENCE CHAIN"
          title="Show the work."
          sub={
            <>
              Every verdict carries its reasoning: the engines that spoke, the families they belong to, the rule that
              set the confidence, and the arithmetic behind the priority. Replay the repro from the twin instead of
              trusting the number.
            </>
          }
        />
        <div style={{ marginTop: 8 }}>
          <FindingDetail id={id} />
        </div>
      </main>
    </>
  );
}
