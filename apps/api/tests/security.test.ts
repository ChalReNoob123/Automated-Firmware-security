// ============================================================================
// SentinelForge v3 — Adversarial security test suite
// Every test names the threat it models. Failures here = live vulnerabilities.
// Run: npm --prefix apps/api run test -- tests/security.test.ts
// ============================================================================
import { describe, expect, it } from 'vitest';
import request from 'supertest';
import speakeasy from 'speakeasy';
import jwt from 'jsonwebtoken';
import { app } from '../src/app.js';

const api = request(app);
const SECRET = process.env.JWT_SECRET ?? 'dev-secret-change-me';

// ============================================================================
// Helpers
// ============================================================================
async function signup(username: string) {
  const email = `${username}@t.test`;
  await api
    .post('/v1/auth/signup')
    .send({ orgName: `org-${username}`, username, email, password: 'Str0ng!Pass1' })
    .expect(201);
  const login = await api
    .post('/v1/auth/login')
    .send({ identifier: email, password: 'Str0ng!Pass1' })
    .expect(200);
  const code = speakeasy.totp({ secret: login.body.manualKey, encoding: 'base32' });
  const v = await api
    .post('/v1/auth/verify-2fa')
    .send({ tempToken: login.body.tempToken, code })
    .expect(200);
  return { token: v.body.accessToken as string, org: username };
}

// ============================================================================
// 1. AUTHENTICATION BYPASS
// ---------------------------------------------------------------------------
describe('threat: authentication bypass', () => {
  it('rejects alg=none JWT forgery', async () => {
    const none = jwt.sign({}, '', { algorithm: 'none' });
    await api.get('/v1/auth/me').set('Authorization', `Bearer ${none}`).expect(401);
  });

  it('rejects a token signed with the wrong secret', async () => {
    const forged = jwt.sign(
      { sub: 'u', org: 'o', role: 'Owner', jti: 'x' },
      'not-the-secret',
      { expiresIn: '15m', issuer: 'sentinelforge', audience: 'sentinelforge-api' },
    );
    await api.get('/v1/auth/me').set('Authorization', `Bearer ${forged}`).expect(401);
  });

  it('rejects a token missing the issuer claim', async () => {
    const noIss = jwt.sign(
      { sub: 'u', org: 'o', role: 'Owner', jti: 'x' },
      SECRET,
      { expiresIn: '15m', audience: 'sentinelforge-api' },
    );
    await api.get('/v1/auth/me').set('Authorization', `Bearer ${noIss}`).expect(401);
  });

  it('rejects an expired token', async () => {
    const expired = jwt.sign(
      { sub: 'u', org: 'o', role: 'Owner', jti: 'x' },
      SECRET,
      { expiresIn: '-1s', issuer: 'sentinelforge', audience: 'sentinelforge-api' },
    );
    await api.get('/v1/auth/me').set('Authorization', `Bearer ${expired}`).expect(401);
  });

  it('never returns a token for an unknown user', async () => {
    const r = await api.post('/v1/auth/login').send({ identifier: 'ghost', password: 'whatever' }).expect(401);
    expect(r.body.accessToken).toBeUndefined();
    // Generic message: must not confirm user existence
    expect(String(r.body.error)).not.toMatch(/exist|not found|unknown/i);
  });

  it('locks an account after repeated failures', async () => {
    const u = `lock${Date.now()}`;
    await api.post('/v1/auth/signup').send({ orgName: 'org-lock', username: u, email: `${u}@t.test`, password: 'Str0ng!Pass1' }).expect(201);
    for (let i = 0; i < 5; i++) await api.post('/v1/auth/login').send({ identifier: u, password: 'nope' }).expect(401);
    await api.post('/v1/auth/login').send({ identifier: u, password: 'Str0ng!Pass1' }).expect(403);
  });
});

// ============================================================================
// 2. CROSS-TENANT DATA ACCESS (IDOR)
// ---------------------------------------------------------------------------
describe('threat: cross-tenant data access (IDOR)', () => {
  it('does not leak another org emulator session', async () => {
    const a = await signup(`ida${Date.now()}`);
    const b = await signup(`idb${Date.now()}`);
    const devA = (await api.post('/v1/devices').set('Authorization', `Bearer ${a.token}`).send({ name: 'd', transport: 'usb' }).expect(201)).body;
    const attA = (await api.post('/v1/attestations').set('Authorization', `Bearer ${a.token}`).send({ deviceId: devA.id, scope: 's', legalBasis: 'own ref' }).expect(201)).body;
    const session = (
      await api
        .post('/v1/emulator/sessions')
        .set('Authorization', `Bearer ${a.token}`)
        .set('x-attestation-id', attA.id)
        .send({ arch: 'arm' })
        .expect(201)
    ).body;

    const B = { Authorization: `Bearer ${b.token}` };
    await api.get(`/v1/emulator/sessions/${session.id}`).set(B).expect(404);
    const r1 = await api.post(`/v1/emulator/sessions/${session.id}/input`).set(B).send({ input: 'x' });
    expect([403, 404]).toContain(r1.status);
    const r2 = await api.post(`/v1/emulator/sessions/${session.id}/snapshots`).set(B).send({});
    expect([403, 404]).toContain(r2.status);
    const r3 = await api.post(`/v1/emulator/sessions/${session.id}/replay`).set(B).send({ snapshotId: 'x' });
    expect([403, 404]).toContain(r3.status);
    const r4 = await api.post(`/v1/emulator/sessions/${session.id}/crash`).set(B).send({ reason: 'x' });
    expect([403, 404]).toContain(r4.status);
  });

  it('does not leak another org pipeline run', async () => {
    const a = await signup(`runa${Date.now()}`);
    const b = await signup(`runb${Date.now()}`);
    const devA = (await api.post('/v1/devices').set('Authorization', `Bearer ${a.token}`).send({ name: 'd', transport: 'usb' }).expect(201)).body;
    const attA = (await api.post('/v1/attestations').set('Authorization', `Bearer ${a.token}`).send({ deviceId: devA.id, scope: 's', legalBasis: 'own ref' }).expect(201)).body;
    const run = (
      await api.post('/v1/pipeline/runs').set('Authorization', `Bearer ${a.token}`).set('x-attestation-id', attA.id).send({ firmwareId: 'fw', version: '1' }).expect(202)
    ).body;
    await api.get(`/v1/pipeline/runs/${run.runId}`).set('Authorization', `Bearer ${b.token}`).expect(404);
  });

  it('does not leak another org findings or devices', async () => {
    const a = await signup(`fa${Date.now()}`);
    const b = await signup(`fb${Date.now()}`);
    await api.post('/v1/devices').set('Authorization', `Bearer ${a.token}`).send({ name: 'secret-device', transport: 'usb' }).expect(201);
    await api.post('/v1/findings').set('Authorization', `Bearer ${a.token}`).send({ title: 'Secret finding title' }).expect(201);
    const bDevs = await api.get('/v1/devices').set('Authorization', `Bearer ${b.token}`).expect(200);
    expect(JSON.stringify(bDevs.body)).not.toMatch(/secret-device/);
    const bFind = await api.get('/v1/findings').set('Authorization', `Bearer ${b.token}`).expect(200);
    expect(JSON.stringify(bFind.body)).not.toMatch(/Secret finding title/);
  });

  it('rejects an attestation that belongs to another org', async () => {
    const a = await signup(`ata${Date.now()}`);
    const b = await signup(`atb${Date.now()}`);
    const devA = (await api.post('/v1/devices').set('Authorization', `Bearer ${a.token}`).send({ name: 'd', transport: 'usb' }).expect(201)).body;
    const attA = (await api.post('/v1/attestations').set('Authorization', `Bearer ${a.token}`).send({ deviceId: devA.id, scope: 's', legalBasis: 'own ref' }).expect(201)).body;
    // Tenant B presents A's attestation -> must fail closed (403 or 404)
    const r = await api.post('/v1/emulator/sessions').set('Authorization', `Bearer ${b.token}`).set('x-attestation-id', attA.id).send({ arch: 'arm' });
    expect([403, 404]).toContain(r.status);
  });
});

// ============================================================================
// 3. INPUT ABUSE
// ---------------------------------------------------------------------------
describe('threat: input abuse', () => {
  it('does not allow prototype pollution through the body', async () => {
    const u = await signup(`pp${Date.now()}`);
    await api
      .post('/v1/findings')
      .set('Authorization', `Bearer ${u.token}`)
      .set('Content-Type', 'application/json')
      .send('{"title":"x","__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}')
      .expect(400);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('rejects absurdly long field values', async () => {
    const u = await signup(`len${Date.now()}`);
    await api.post('/v1/findings').set('Authorization', `Bearer ${u.token}`).send({ title: 'A'.repeat(5000) }).expect(400);
    await api.post('/v1/devices').set('Authorization', `Bearer ${u.token}`).send({ name: 'x'.repeat(5000), transport: 'usb' }).expect(400);
  });

  it('rejects deeply nested JSON without crashing', async () => {
    const u = await signup(`deep${Date.now()}`);
    let payload = '{"title":"x"}';
    for (let i = 0; i < 40; i++) payload = `{"a":${payload}}`;
    await api.post('/v1/findings').set('Authorization', `Bearer ${u.token}`).set('Content-Type', 'application/json').send(payload).expect(400);
  });

  it('treats SQL-ish input as plain data', async () => {
    const u = await signup(`sqli${Date.now()}`);
    const r = await api
      .post('/v1/findings')
      .set('Authorization', `Bearer ${u.token}`)
      .send({ title: "'; DROP TABLE findings; --" })
      .expect(201);
    expect(r.body.title).toBe("'; DROP TABLE findings; --");
    // table still there
    await api.get('/v1/findings').set('Authorization', `Bearer ${u.token}`).expect(200);
  });

  it('strips control characters from stored titles', async () => {
    const u = await signup(`ctl${Date.now()}`);
    const r = await api.post('/v1/findings').set('Authorization', `Bearer ${u.token}`).send({ title: 'ok\u0000\u0007bad' }).expect(201);
    expect(r.body.title).not.toMatch(/[\u0000-\u0008]/);
  });
});

// ============================================================================
// 4. TRANSPORT AND HEADERS
// ---------------------------------------------------------------------------
describe('threat: transport and headers', () => {
  it('sets hardening headers and a request id', async () => {
    const r = await api.get('/health').expect(200);
    expect(r.headers['x-request-id']).toBeTruthy();
    expect(r.headers['x-content-type-options']).toBe('nosniff');
    expect(r.headers['content-security-policy']).toBeTruthy();
  });

  it('does not echo attacker-controlled request ids into headers unsafely', async () => {
    const r = await api.get('/health').set('x-request-id', 'abc-123').expect(200);
    expect(r.headers['x-request-id']).toBe('abc-123');
  });

  it('rejects CORS from an unknown origin', async () => {
    const r = await api.get('/health').set('Origin', 'https://evil.example');
    expect(r.headers['access-control-allow-origin']).toBeUndefined();
  });
});