// In-memory store — analysis reconciliation (no database required).
//
// The Postgres branch is covered by postgres.test.ts; this pins the same ordering
// rules for the fallback that dev and every test without DATABASE_URL actually
// run on: a reconcile only prunes rows produced by runs that started earlier, and
// it never touches manual findings.
import { describe, expect, it } from 'vitest';
import { createFinding, listFindings, reconcileFindingsForFirmware, upsertFindingForFirmware } from '../src/store.js';

const ORG = 'org-memory-reconcile';
const t = (seconds: number) => new Date(Date.UTC(2026, 0, 1, 0, 0, seconds)).toISOString();

const analysis = (firmwareId: string, title: string, analysisRunAt?: string) => ({
  orgId: ORG,
  firmwareId,
  title,
  confidence: 'Likely' as const,
  engines: ['taint'],
  source: 'analysis' as const,
  ...(analysisRunAt ? { analysisRunAt } : {}),
});

const titles = async (firmwareId: string) =>
  (await listFindings(ORG, { limit: 100 })).filter((f) => f.firmware_id === firmwareId).map((f) => f.title).sort();

describe('in-memory finding reconciliation', () => {
  it('keeps a newer concurrent run’s findings when an older run reconciles', async () => {
    const fw = 'fw-memory-concurrent';
    const aX = await upsertFindingForFirmware(analysis(fw, 'X', t(0)));
    const bX = await upsertFindingForFirmware(analysis(fw, 'X', t(5)));
    await upsertFindingForFirmware(analysis(fw, 'Y', t(5)));
    await createFinding({ ...analysis(fw, 'Analyst note', t(0)), source: 'manual', confidence: 'Confirmed' });
    // Same (org, firmware, title) → one row, so B's upsert reuses A's id.
    expect(bX.id).toBe(aX.id);

    // Run A (started at t0) finishes while B (started at t5) is still running.
    expect(await reconcileFindingsForFirmware(ORG, fw, [aX.id], t(0))).toEqual([]);
    expect(await titles(fw)).toEqual(['Analyst note', 'X', 'Y']);
  });

  it('prunes older verdicts, survives manual rows, and handles an empty keep list', async () => {
    const fw = 'fw-memory-concurrent';
    const y = await upsertFindingForFirmware(analysis(fw, 'Y', t(5)));

    // A run that started at t10 yields only Y: X (last written at t5) is stale.
    expect((await reconcileFindingsForFirmware(ORG, fw, [y.id], t(10))).sort()).toEqual(['X']);
    expect(await titles(fw)).toEqual(['Analyst note', 'Y']);

    // A run that produced nothing still clears the remaining verdict.
    expect(await reconcileFindingsForFirmware(ORG, fw, [], t(15))).toEqual(['Y']);
    expect(await titles(fw)).toEqual(['Analyst note']);
  });

  it('treats a row without a run stamp as stale', async () => {
    const fw = 'fw-memory-legacy';
    await createFinding(analysis(fw, 'Legacy verdict'));
    expect(await reconcileFindingsForFirmware(ORG, fw, [], t(0))).toEqual(['Legacy verdict']);
    expect(await titles(fw)).toEqual([]);
  });
});
