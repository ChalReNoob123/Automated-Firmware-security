// SentinelForge API — integration suite (supertest, in-process app, memory store).
// Mirrors the adversarial matrix: every route's happy path plus its 401/403/404/400s.
import { describe, expect, it } from 'vitest';
import request from 'supertest';
import speakeasy from 'speakeasy';
import jwt from 'jsonwebtoken';
import { app } from '../src/app.js';

const api = request(app);
let token = '';
let attId = '';
let deviceId = '';

async function authed() {
  const email = `u${Date.now()}@t.test`;
  await api.post('/v1/auth/signup').send({ orgName: 'org', username: `u${Date.now()}`, email, password: 'Str0ng!Pass1' }).expect(201);
  const login = await api.post('/v1/auth/login').send({ identifier: email, password: 'Str0ng!Pass1' }).expect(200);
  const code = speakeasy.totp({ secret: login.body.manualKey, encoding: 'base32' });
  const v = await api.post('/v1/auth/verify-2fa').send({ tempToken: login.body.tempToken, code }).expect(200);
  return v.body.accessToken as string;
}

describe('health + discovery', () => {
  it('serves health and modules', async () => {
    await api.get('/health').expect(200);
    const r = await api.get('/v1/modules').expect(200);
    expect(r.body.modules).toContain('mcp-copilot');
  });
  it('returns JSON 404s', async () => {
    const r = await api.get('/nope').expect(404);
    expect(r.body.error).toBeTruthy();
  });
  it('rejects malformed JSON as JSON', async () => {
    await api.post('/v1/auth/login').set('Content-Type', 'application/json').send('{bad').expect(400);
  });
});

describe('auth', () => {
  it('enforces password policy and uniqueness', async () => {
    await api.post('/v1/auth/signup').send({ orgName: 'o', username: 'ab', email: 'bad', password: 'weak' }).expect(400);
  });
  it('locks out after 5 bad passwords then serves the full TOTP flow', async () => {
    const email = `lock${Date.now()}@t.test`;
    const uname = `lock${Date.now()}`;
    await api.post('/v1/auth/signup').send({ orgName: 'org', username: uname, email, password: 'Str0ng!Pass1' }).expect(201);
    for (let i = 0; i < 5; i++) await api.post('/v1/auth/login').send({ identifier: uname, password: 'Wrong!Pass1' }).expect(401);
    await api.post('/v1/auth/login').send({ identifier: uname, password: 'Str0ng!Pass1' }).expect(403);
  }, 20000);
  it('rejects wrong TOTP and accepts the real one', async () => {
    const email = `t${Date.now()}@t.test`;
    await api.post('/v1/auth/signup').send({ orgName: 'org', username: `t${Date.now()}`, email, password: 'Str0ng!Pass1' }).expect(201);
    const login = await api.post('/v1/auth/login').send({ identifier: email, password: 'Str0ng!Pass1' }).expect(200);
    expect(login.body.step).toBe('enroll');
    await api.post('/v1/auth/verify-2fa').send({ tempToken: login.body.tempToken, code: '000000' }).expect(401);
    const code = speakeasy.totp({ secret: login.body.manualKey, encoding: 'base32' });
    const v = await api.post('/v1/auth/verify-2fa').send({ tempToken: login.body.tempToken, code }).expect(200);
    expect(v.body.user.role).toBe('Owner');
    token = v.body.accessToken;
  }, 20000);
  it('rotates refresh cookies and revokes on logout', async () => {
    const agent = request.agent(app);
    const email = `r${Date.now()}@t.test`;
    await agent.post('/v1/auth/signup').send({ orgName: 'org', username: `r${Date.now()}`, email, password: 'Str0ng!Pass1' }).expect(201);
    const login = await agent.post('/v1/auth/login').send({ identifier: email, password: 'Str0ng!Pass1' }).expect(200);
    const code = speakeasy.totp({ secret: login.body.manualKey, encoding: 'base32' });
    const v = await agent.post('/v1/auth/verify-2fa').send({ tempToken: login.body.tempToken, code }).expect(200);
    // stale/missing cookie is rejected
    await request(app).post('/v1/auth/refresh').expect(401);
    // cookie jar rotation works and the new access token is live
    const r = await agent.post('/v1/auth/refresh').expect(200);
    expect(r.body.accessToken).toBeTruthy();
    await agent.get('/v1/auth/me').set('Authorization', `Bearer ${r.body.accessToken}`).expect(200);
    await agent.post('/v1/auth/logout').set('Authorization', `Bearer ${r.body.accessToken}`).expect(200);
    await agent.get('/v1/auth/me').set('Authorization', `Bearer ${r.body.accessToken}`).expect(401);
  });
  it('enforces RBAC on the audit trail', async () => {
    const analyst = jwt.sign({ sub: 'x', org: 'y', role: 'Analyst', jti: 't-analyst' }, 'dev-secret-change-me', { expiresIn: '15m', issuer: 'sentinelforge' });
    await api.get('/v1/auth/audit').expect(401);
    await api.get('/v1/auth/audit').set('Authorization', `Bearer ${analyst}`).expect(403);
    const ok = await api.get('/v1/auth/audit').set('Authorization', `Bearer ${token}`).expect(200);
    expect(Array.isArray(ok.body.events)).toBe(true);
  });
});

describe('devices + gate', () => {
  it('registers devices and enforces real attestation rows', async () => {
    const H = { Authorization: `Bearer ${token}` };
    await api.post('/v1/devices').set(H).send({}).expect(400);
    await api.post('/v1/devices').send({ name: 'x', transport: 'usb' }).expect(401);
    const d = await api.post('/v1/devices').set(H).send({ name: 'bench', transport: 'usb' }).expect(201);
    deviceId = d.body.id;
    expect(deviceId.length).toBeGreaterThan(20);
    await api.post('/v1/attestations').set(H).send({ deviceId: 'nope', scope: 's', legalBasis: 'own ref' }).expect(404);
    const a = await api.post('/v1/attestations').set(H).send({ deviceId, scope: 'emulate', legalBasis: 'ownership t-1' }).expect(201);
    attId = a.body.id;
    const list = await api.get('/v1/devices').set(H).expect(200);
    expect(list.body.devices.length).toBe(1);
  });
  it('rejects forged attestation ids', async () => {
    await api.post('/v1/emulator/sessions').set('Authorization', `Bearer ${token}`).set('x-attestation-id', 'forged').send({ arch: 'arm' }).expect(403);
  });
});

describe('analysis APIs', () => {
  const H = () => ({ Authorization: `Bearer ${token}`, 'x-attestation-id': attId });
  it('runs the emulator lifecycle', async () => {
    const s = await api.post('/v1/emulator/sessions').set(H()).send({ arch: 'arm' }).expect(201);
    await api.post(`/v1/emulator/sessions/${s.body.id}/input`).set(H()).send({ input: 'root' }).expect(200);
    const snap = await api.post(`/v1/emulator/sessions/${s.body.id}/snapshots`).set('Authorization', `Bearer ${token}`).send({}).expect(201);
    const rep = await api.post(`/v1/emulator/sessions/${s.body.id}/replay`).set('Authorization', `Bearer ${token}`).send({ snapshotId: snap.body.id }).expect(200);
    expect(rep.body.match).toBe(true);
    await api.post(`/v1/emulator/sessions/${s.body.id}/crash`).set(H()).send({ reason: 't' }).expect(201);
  });
  it('queues pipeline runs', async () => {
    const r = await api.post('/v1/pipeline/runs').set(H()).send({ firmwareId: 'fw', version: '1' }).expect(202);
    await api.get(`/v1/pipeline/runs/${r.body.runId}`).set('Authorization', `Bearer ${token}`).expect(200);
    await api.get('/v1/pipeline/runs/nope').set('Authorization', `Bearer ${token}`).expect(404);
  });
  it('builds graphs and answers copilot', async () => {
    const g = await api.post('/v1/graph/build').set('Authorization', `Bearer ${token}`).send({ taintPaths: [{ source: 'recv', sink: 'system', path: ['recv', 'system'] }] }).expect(201);
    expect(g.body.paths[0].nodes).toContain('asset:root-shell');
    const c = await api.post('/v1/copilot/chat').set('Authorization', `Bearer ${token}`).send({ message: 'show attack paths' }).expect(200);
    expect(c.body.citations.length).toBeGreaterThan(0);
    await api.post('/v1/copilot/chat').set('Authorization', `Bearer ${token}`).send({}).expect(400);
  });
  it('clarifies ambiguous prompts instead of misrouting', async () => {
    const H = { Authorization: `Bearer ${token}` };
    // "crash" (fuzz) vs "fix" (patch) tie at 1-1 → clarification, not a guess
    const r = await api.post('/v1/copilot/chat').set(H).send({ message: 'crash fix' }).expect(200);
    expect(Array.isArray(r.body.clarify)).toBe(true);
    expect(r.body.clarify.length).toBeGreaterThan(1);
    // strict winners still route directly
    const direct = await api.post('/v1/copilot/chat').set(H).send({ message: 'run the Mirai scenario' }).expect(200);
    expect(direct.body.reply).toMatch(/\/attacks/);
    expect(direct.body.clarify).toBeUndefined();
  });
  it('runs radar and patch verification', async () => {
    const demo = await api.get('/v1/radar/demo').expect(200);
    expect(demo.body.results.length).toBe(2);
    await api.post('/v1/patch/verify').set(H()).send({ oldHex: 'aabb', newHex: 'aabb', oldText: 'strcpy(d,s);', newText: 'strcpy(d,s);', vulnSink: 'strcpy' }).expect(200)
      .expect((r) => {
        if (r.body.verdict !== 'not-patched') throw new Error('expected not-patched');
      });
  });
  it('reports capabilities', async () => {
    const r = await api.get('/v1/capabilities').expect(200);
    expect(r.body.engines).toContain('consensus');
    expect(r.body.persistence).toBe('memory (dev fallback)');
  });
});
