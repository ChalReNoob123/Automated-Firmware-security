// SentinelForge API — Postgres integration suite (real database, one command).
//
// These paths only exist when a database does: a session left in `booting` by an
// API that died mid-launch must settle to `failed` on the next read, and two
// analyses of the same image must not delete each other's findings. Both are
// invisible to the in-memory suite.
//
//   npm test -w @sentinelforge/api       (whole suite, this file included)
//   npm run test:pg -w @sentinelforge/api (just this file)
//
// No database setup is needed: pgHarness boots a throwaway embedded PostgreSQL in
// the OS temp directory, then removes it. To reuse an existing server instead
// (e.g. a CI service container) set SF_TEST_DATABASE_URL; because the suite drops
// and rebuilds the public schema, that database's name must contain "test".
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { readdir, readFile } from 'node:fs/promises';
import { Client } from 'pg';
import type { Express } from 'express';
import { ensureTestDatabase, type TestDatabase } from './pgHarness.js';

const dbDir = new URL('../../../packages/db/', import.meta.url);
const ORG = '11111111-1111-4111-8111-111111111111';
const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-secret-change-me';

// An independent connection standing in for the API process that died: its rows
// survive, its promises do not.
let outside: Client;
let app: Express;
let store: typeof import('../src/store.js');
let pool: (typeof import('../src/db.js'))['pool'];
let db: TestDatabase;

const token = () =>
  jwt.sign({ sub: '22222222-2222-4222-8222-222222222222', org: ORG, role: 'Analyst', jti: `pg-${Date.now()}` }, JWT_SECRET, {
    expiresIn: '15m',
    issuer: 'sentinelforge',
    audience: 'sentinelforge-api',
  });

const auth = () => ({ Authorization: `Bearer ${token()}` });

// Write a session row exactly like a live launch would, but through the outside
// connection: nothing in this process holds a launch promise for it.
async function seedBootingSession(id: string, deadlineOffsetMs: number) {
  const startedAt = new Date(Date.now() - 60_000).toISOString();
  const doc = {
    id,
    arch: 'arm',
    memoryMb: 256,
    kernelArgs: '',
    backend: 'image-bound',
    execution: 'none',
    status: 'booting',
    bootLog: ['[image] 1.0 · sha256:deadbeef… · 1024 bytes', 'login: '],
    inputTrace: [],
    snapshots: [],
    crashes: [],
    bootDeadline: new Date(Date.now() + deadlineOffsetMs).toISOString(),
    startedAt,
    updatedAt: startedAt,
  };
  await outside.query(`INSERT INTO emulator_sessions (id, org_id, data, updated_at) VALUES ($1,$2,$3,now())`, [id, ORG, JSON.stringify(doc)]);
}

const readStatus = async (id: string) => {
  const r = await outside.query(`SELECT data->>'status' AS status FROM emulator_sessions WHERE id=$1`, [id]);
  return r.rows[0]?.status as string | undefined;
};

describe('postgres integration', () => {
  beforeAll(async () => {
    db = await ensureTestDatabase();
    outside = new Client({ connectionString: db.url });
    await outside.connect();
    // Rebuild from the shipped SQL so the suite proves the migrations themselves,
    // not a schema someone applied by hand.
    await outside.query('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;');
    const migrations = (await readdir(dbDir)).filter((f) => /^migrate-\d+\.sql$/.test(f)).sort();
    for (const file of ['schema.sql', ...migrations]) {
      await outside.query(await readFile(new URL(file, dbDir), 'utf8'));
    }
    await outside.query(`INSERT INTO orgs (id, name) VALUES ($1,'integration-org')`, [ORG]);

    // The app reads DATABASE_URL at import time, so set it before loading it.
    process.env.DATABASE_URL = db.url;
    ({ app } = await import('../src/app.js'));
    store = await import('../src/store.js');
    ({ pool } = await import('../src/db.js'));
  }, 120000);

  afterAll(async () => {
    await pool?.end().catch(() => undefined);
    await outside?.end().catch(() => undefined);
    delete process.env.DATABASE_URL;
    // Stops and deletes the embedded cluster (a no-op for a supplied database).
    // Optional because a beforeAll failure can leave nothing to stop.
    await db?.stop();
  }, 30000);

  it('settles a booting session left behind by a dead API into failed, and persists it', async () => {
    const id = 'emu_restart_expired';
    // Deadline passed 15 s ago: the launch this row waited on died with the API.
    await seedBootingSession(id, -15_000);
    expect(await readStatus(id)).toBe('booting');

    const res = await request(app).get(`/v1/emulator/sessions/${id}`).set(auth()).expect(200);
    expect(res.body.status).toBe('failed');
    expect(res.body.launchError).toMatch(/deadline/);
    expect(res.body.bootDeadline).toBeUndefined();
    // The transition is written back, so a second reader (and a second instance)
    // sees the same answer instead of re-deriving it.
    expect(await readStatus(id)).toBe('failed');

    const again = await request(app).get(`/v1/emulator/sessions/${id}`).set(auth()).expect(200);
    expect(again.body.status).toBe('failed');
  });

  it('leaves a boot that is still within its deadline alone', async () => {
    const id = 'emu_restart_live';
    await seedBootingSession(id, 300_000);
    const res = await request(app).get(`/v1/emulator/sessions/${id}`).set(auth()).expect(200);
    expect(res.body.status).toBe('booting');
    expect(await readStatus(id)).toBe('booting');
  });

  it('does not let a reconcile delete a concurrent run’s findings', async () => {
    const fw = '33333333-3333-4333-8333-333333333333';
    await outside.query(`INSERT INTO firmware (id, org_id, version, sha256, bytes) VALUES ($1,$2,'1.0',$3,1024)`, [fw, ORG, 'a'.repeat(64)]);

    const t1 = '2026-01-01T00:00:00.000Z';
    const t2 = '2026-01-01T00:00:05.000Z';
    const t3 = '2026-01-01T00:00:10.000Z';
    const t4 = '2026-01-01T00:00:15.000Z';
    const finding = (title: string, analysisRunAt: string, source: 'analysis' | 'manual' = 'analysis') => ({
      orgId: ORG,
      firmwareId: fw,
      title,
      confidence: 'Likely' as const,
      engines: ['taint'],
      source,
      analysisRunAt,
    });

    // Run A starts at t1; run B starts at t2 while A is still working. B produces
    // X and Y, A only X — sharing the X row thanks to the (org, firmware, title) key.
    const aX = await store.upsertFindingForFirmware(finding('X', t1));
    const bX = await store.upsertFindingForFirmware(finding('X', t2));
    const bY = await store.upsertFindingForFirmware(finding('Y', t2));
    expect(bX.id).toBe(aX.id);
    const manual = await store.createFinding(finding('Analyst note', t1, 'manual'));

    // A finishes first. Its keep list has never heard of Y, but Y belongs to a
    // newer run, so A must not touch it.
    expect(await store.reconcileFindingsForFirmware(ORG, fw, [aX.id], t1)).toEqual([]);

    // A later run that yields only Y still prunes X (and never the manual row).
    expect((await store.reconcileFindingsForFirmware(ORG, fw, [bY.id], t3)).sort()).toEqual(['X']);

    // A run that produced nothing at all clears the remaining verdict — this is
    // also the empty keep list, which must still bind as a uuid[].
    expect(await store.reconcileFindingsForFirmware(ORG, fw, [], t4)).toEqual(['Y']);

    const left = await store.listFindings(ORG, { limit: 50 });
    expect(left.map((f) => f.title)).toEqual(['Analyst note']);
    expect(left.find((f) => f.title === 'Analyst note')?.id).toBe(manual.id);
  });
});

