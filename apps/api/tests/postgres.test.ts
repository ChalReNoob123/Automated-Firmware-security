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

  it('writes a run in one transaction: a superseded run changes nothing', async () => {
    const fw = '44444444-4444-4444-8444-444444444444';
    await outside.query(`INSERT INTO firmware (id, org_id, version, sha256, bytes) VALUES ($1,$2,'2.0',$3,2048)`, [fw, ORG, 'b'.repeat(64)]);

    const first = await store.nextAnalysisRunSeq();
    const second = await store.nextAnalysisRunSeq();
    const third = await store.nextAnalysisRunSeq();
    expect(second).toBeGreaterThan(first);
    expect(third).toBeGreaterThan(second);
    const startedAt = '2026-01-01T00:00:00.000Z';
    const verdict = (title: string, confidence: 'Confirmed' | 'Likely' = 'Likely') => ({ title, confidence, engines: ['taint'] });

    // `second` writes X and Y, then a manual row that no run may ever delete.
    const write = await store.persistAnalysisRun(ORG, fw, { seq: second, startedAt }, [verdict('X'), verdict('Y')]);
    expect(write.applied).toBe(true);
    expect(write.rows.map((r) => r.title).sort()).toEqual(['X', 'Y']);
    const manual = await store.createFinding({ orgId: ORG, firmwareId: fw, title: 'Analyst note', confidence: 'Confirmed', engines: [], source: 'manual' });

    // The late `first` run is behind the applied sequence: it writes nothing at all.
    expect(await store.persistAnalysisRun(ORG, fw, { seq: first, startedAt }, [verdict('Old')])).toEqual({
      applied: false,
      rows: [],
      removed: [],
    });

    // A later run that yields only Y prunes X inside its own transaction.
    const later = await store.persistAnalysisRun(ORG, fw, { seq: third, startedAt }, [verdict('Y')]);
    expect(later.applied).toBe(true);
    expect(later.removed).toEqual(['X']);

    const left = await store.listFindings(ORG, { limit: 50 });
    expect(left.map((f) => f.title).sort()).toEqual(['Analyst note', 'Y']);
    expect(left.find((f) => f.title === 'Analyst note')?.id).toBe(manual.id);
  });

  it('serializes concurrent runs of one image, so an older run cannot leave findings behind', async () => {
    const fw = '55555555-5555-4555-8555-555555555555';
    await outside.query(`INSERT INTO firmware (id, org_id, version, sha256, bytes) VALUES ($1,$2,'3.0',$3,4096)`, [fw, ORG, 'c'.repeat(64)]);
    const startedAt = '2026-01-01T00:00:00.000Z';
    const older = await store.nextAnalysisRunSeq();
    const newer = await store.nextAnalysisRunSeq();
    expect(newer).toBeGreaterThan(older);

    // Start both while neither has committed: the firmware row lock decides who
    // writes first. This is the interleaving plain claim-then-write could not
    // express — the older run holding the lock would still write after the newer
    // one pruned.
    const [olderWrite, newerWrite] = await Promise.all([
      store.persistAnalysisRun(ORG, fw, { seq: older, startedAt }, [{ title: 'Old', confidence: 'Likely', engines: ['taint'] }]),
      store.persistAnalysisRun(ORG, fw, { seq: newer, startedAt }, [{ title: 'New', confidence: 'Confirmed', engines: ['taint', 'fuzz'] }]),
    ]);

    const left = await store.listFindings(ORG, { limit: 50 }).then((rows) => rows.filter((f) => f.firmware_id === fw));
    expect(left.map((f) => f.title)).toEqual(['New']);
    expect(left[0]?.confidence).toBe('Confirmed');
    // If the older run committed first the newer pruned its row; if the newer run
    // committed first the older was refused outright.
    expect(newerWrite.applied).toBe(true);
    expect(olderWrite.applied || newerWrite.removed.includes('Old')).toBe(true);
  });
  it('a superseded run through POST /v1/pipeline/runs writes nothing and keeps the newer findings', async () => {
    const stamp = `${Date.now()}-${Math.round(Math.random() * 1e6)}`;
    const user = await store.createUser({
      orgId: ORG,
      email: `route-${stamp}@t.test`,
      username: `route-${stamp}`,
      passwordHash: 'not-a-real-hash',
      role: 'Analyst',
    });
    const bearer = jwt.sign({ sub: user.id, org: ORG, role: 'Analyst', jti: `route-${stamp}` }, JWT_SECRET, {
      expiresIn: '15m',
      issuer: 'sentinelforge',
      audience: 'sentinelforge-api',
    });
    const auth = (extra: Record<string, string> = {}) => ({ Authorization: `Bearer ${bearer}`, ...extra });

    // Uploaded through the real route, so the bytes the run analyses are the bytes
    // the API stored.
    const device = await request(app).post('/v1/devices').set(auth()).send({ name: 'route bench', transport: 'usb' }).expect(201);
    const attestation = await request(app)
      .post('/v1/attestations')
      .set(auth())
      .send({ deviceId: device.body.id, scope: 'firmware-extract,emulate', legalBasis: 'route test' })
      .expect(201);
    const image = Buffer.alloc(256);
    image.writeUInt32LE(0x464c457f, 0);
    image[4] = 2;
    image[5] = 1;
    image.write('recv(buf);\nstrcpy(d, s);\npassword = "hunter2hunter2";\n', 64);
    const firmware = await request(app)
      .post('/v1/firmware?version=route-1')
      .set(auth({ 'x-attestation-id': attestation.body.id, 'Content-Type': 'application/octet-stream' }))
      .send(image)
      .expect(201);
    const fw = firmware.body.id as string;

    // A newer run has already applied its verdicts for this image.
    const newerSeq = await store.nextAnalysisRunSeq();
    await store.persistAnalysisRun(ORG, fw, { seq: newerSeq, startedAt: new Date().toISOString() }, [
      { title: 'Newer verdict', confidence: 'Confirmed', engines: ['taint', 'fuzz'] },
    ]);
    // Push the applied sequence past anything the API can allocate next, so the run
    // the route accepts is guaranteed to be the superseded one.
    await outside.query(`UPDATE firmware SET applied_run_seq = (SELECT nextval('analysis_run_seq')) + 1000 WHERE id=$1`, [fw]);
    const appliedBefore = (await outside.query(`SELECT applied_run_seq FROM firmware WHERE id=$1`, [fw])).rows[0].applied_run_seq;

    const queued = await request(app)
      .post('/v1/pipeline/runs')
      .set(auth({ 'x-attestation-id': attestation.body.id }))
      .send({ firmwareId: fw })
      .expect(202);

    // The run executes in the background, so poll the same endpoint the UI does.
    const runId = queued.body.runId as string;
    let run: Record<string, unknown> | undefined;
    for (let i = 0; i < 200; i++) {
      const poll = await request(app).get(`/v1/pipeline/runs/${runId}`).set(auth()).expect(200);
      if (poll.body.status === 'done' || poll.body.status === 'failed') {
        run = poll.body as Record<string, unknown>;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    expect(run, 'the run never settled').toBeDefined();
    expect(run?.status).toBe('done');
    expect(run?.superseded).toBe(true);
    expect(run?.findingsCount).toBe(0);
    expect(run?.findings).toEqual([]);

    // Nothing was written: the applied sequence and the queue are untouched.
    const appliedAfter = (await outside.query(`SELECT applied_run_seq FROM firmware WHERE id=$1`, [fw])).rows[0].applied_run_seq;
    expect(String(appliedAfter)).toBe(String(appliedBefore));
    const left = (await store.listFindings(ORG, { limit: 100 })).filter((f) => f.firmware_id === fw);
    expect(left.map((f) => f.title)).toEqual(['Newer verdict']);
    expect(left[0]?.confidence).toBe('Confirmed');
  });
});

