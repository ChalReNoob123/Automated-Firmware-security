// In-memory store — analysis run ordering (no database required).
//
// The Postgres branch is covered by postgres.test.ts; this pins the same rules for
// the fallback that dev and every test without DATABASE_URL actually run on.
// A run's verdicts are written in one step ordered by its sequence: a later run
// prunes what it no longer produces, a run that is already behind writes nothing,
// manual findings are never touched, and concurrent writes for one image queue.
import { describe, expect, it } from 'vitest';
import {
  createFinding,
  listFindings,
  nextAnalysisRunSeq,
  persistAnalysisRun,
} from '../src/store.js';

const ORG = 'org-memory-reconcile';
const startedAt = '2026-01-01T00:00:00.000Z';

const verdict = (title: string, confidence: 'Confirmed' | 'Likely' = 'Likely') => ({
  title,
  confidence,
  engines: ['taint'],
});

const titles = async (firmwareId: string) =>
  (await listFindings(ORG, { limit: 100 })).filter((f) => f.firmware_id === firmwareId).map((f) => f.title).sort();

describe('in-memory analysis run ordering', () => {
  it('a later run prunes what it no longer produces and never touches manual rows', async () => {
    const fw = 'fw-memory-prune';
    const seqA = await nextAnalysisRunSeq();
    expect(await persistAnalysisRun(ORG, fw, { seq: seqA, startedAt }, [verdict('X'), verdict('Y')])).toMatchObject({ applied: true });
    await createFinding({ orgId: ORG, firmwareId: fw, title: 'Analyst note', confidence: 'Confirmed', engines: [], source: 'manual' });

    const seqB = await nextAnalysisRunSeq();
    const second = await persistAnalysisRun(ORG, fw, { seq: seqB, startedAt }, [verdict('Y')]);
    expect(second.applied).toBe(true);
    expect(second.removed).toEqual(['X']);
    expect(await titles(fw)).toEqual(['Analyst note', 'Y']);

    // A run that produced nothing still clears the remaining verdict.
    const seqC = await nextAnalysisRunSeq();
    expect((await persistAnalysisRun(ORG, fw, { seq: seqC, startedAt }, [])).removed).toEqual(['Y']);
    expect(await titles(fw)).toEqual(['Analyst note']);
  });

  it('a run whose sequence is already behind the image writes nothing', async () => {
    const fw = 'fw-memory-superseded';
    const older = await nextAnalysisRunSeq();
    const newer = await nextAnalysisRunSeq();
    expect((await persistAnalysisRun(ORG, fw, { seq: newer, startedAt }, [verdict('New')])).applied).toBe(true);

    // The late, older run is refused before it writes a single row.
    expect(await persistAnalysisRun(ORG, fw, { seq: older, startedAt }, [verdict('Old')])).toEqual({
      applied: false,
      rows: [],
      removed: [],
    });
    expect(await titles(fw)).toEqual(['New']);

    // Re-applying the same sequence is refused too, so a retry cannot duplicate work.
    expect((await persistAnalysisRun(ORG, fw, { seq: newer, startedAt }, [verdict('New')])).applied).toBe(false);
  });

  it('treats a row without a run sequence as stale', async () => {
    const fw = 'fw-memory-legacy';
    await createFinding({ orgId: ORG, firmwareId: fw, title: 'Legacy verdict', confidence: 'Likely', engines: ['taint'], source: 'analysis' });
    const seq = await nextAnalysisRunSeq();
    expect((await persistAnalysisRun(ORG, fw, { seq, startedAt }, [])).removed).toEqual(['Legacy verdict']);
    expect(await titles(fw)).toEqual([]);
  });

  it('serializes concurrent writes for one image, so the newer run wins', async () => {
    const fw = 'fw-memory-concurrent';
    const older = await nextAnalysisRunSeq();
    const newer = await nextAnalysisRunSeq();

    const [olderWrite, newerWrite] = await Promise.all([
      persistAnalysisRun(ORG, fw, { seq: older, startedAt }, [verdict('Old')]),
      persistAnalysisRun(ORG, fw, { seq: newer, startedAt }, [verdict('New')]),
    ]);

    // Whichever one ran first, the queue holds only the newer run's verdict: if the
    // older ran first its row is pruned, if it ran second it is refused outright.
    expect(await titles(fw)).toEqual(['New']);
    expect(newerWrite.applied).toBe(true);
    // Older first: the newer run prunes its row. Older second: it is refused.
    expect(olderWrite.applied || newerWrite.removed.includes('Old')).toBe(true);
  });
});
