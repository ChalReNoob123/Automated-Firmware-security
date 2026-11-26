// Account Security Center — session inventory, per-device revocation, password
// rotation with re-auth, authenticator re-enrollment, sign-out-everywhere.
// Supertest + in-process app + memory store; each agent = one "device" with
// its own cookie jar. TOTP codes come from speakeasy (the server's library).
// The enrollment secret is captured once from the first (enroll-step) login
// and reused for every later device — an enrolled login only returns a
// tempToken, never the secret.
import { describe, expect, it } from 'vitest';
import request from 'supertest';
import speakeasy from 'speakeasy';
import { app } from '../src/app.js';
import { ROTATED_PASSWORD, TEST_PASSWORD, WRONG_PASSWORD } from './testCredentials.js';

const api = request(app);
type Agent = ReturnType<typeof request.agent>;

type Device = { agent: Agent; bearer: string; sessionId: string };

const PASSWORD = TEST_PASSWORD;

async function signup(prefix: string): Promise<string> {
  const email = `${prefix}${Date.now()}@t.test`;
  await api.post('/v1/auth/signup').send({ orgName: 'org', username: `${prefix}${Date.now()}`, email, password: PASSWORD }).expect(201);
  return email;
}

// First device: login hits the enroll step and RETURNS the secret.
async function firstDevice(email: string, password: string): Promise<Device & { secret: string; recoveryCodes: string[] }> {
  const agent = request.agent(app);
  const login = await agent.post('/v1/auth/login').send({ identifier: email, password }).expect(200);
  expect(login.body.step).toBe('enroll');
  const secret = login.body.manualKey as string;
  const code = speakeasy.totp({ secret, encoding: 'base32' });
  const v = await agent.post('/v1/auth/verify-2fa').send({ tempToken: login.body.tempToken, code }).expect(200);
  // completing enrollment issues the one-time recovery-code set (round 22)
  expect(Array.isArray(v.body.recoveryCodes)).toBe(true);
  return { agent, bearer: v.body.accessToken, sessionId: v.body.sessionId, secret, recoveryCodes: v.body.recoveryCodes as string[] };
}

// Later devices: the secret is known — an enrolled login returns only a tempToken.
async function otherDevice(email: string, password: string, secret: string): Promise<Device> {
  const agent = request.agent(app);
  const login = await agent.post('/v1/auth/login').send({ identifier: email, password }).expect(200);
  expect(login.body.step).toBe('2fa');
  const code = speakeasy.totp({ secret, encoding: 'base32' });
  const v = await agent.post('/v1/auth/verify-2fa').send({ tempToken: login.body.tempToken, code }).expect(200);
  return { agent, bearer: v.body.accessToken, sessionId: v.body.sessionId };
}

describe('account security center — auth gates', () => {
  it('every endpoint requires a session', async () => {
    await api.get('/v1/auth/sessions').expect(401);
    await api.post('/v1/auth/sessions/revoke').send({ jti: 'x'.repeat(16) }).expect(401);
    await api.post('/v1/auth/sessions/revoke-all').expect(401);
    await api.post('/v1/auth/password').send({ currentPassword: 'a', newPassword: TEST_PASSWORD }).expect(401);
    await api.post('/v1/auth/totp/re-enroll').send({ password: 'a' }).expect(401);
  });
});

describe('account security center — sessions', () => {
  it('marks the current device and kills exactly the revoked one', async () => {
    const email = await signup('sess');
    const a = await firstDevice(email, PASSWORD);
    const b = await otherDevice(email, PASSWORD, a.secret);

    const list = await a.agent.get('/v1/auth/sessions').set('Authorization', `Bearer ${a.bearer}`).expect(200);
    const rows = list.body.sessions as Array<{ id: string; current: boolean }>;
    expect(rows.length).toBe(2);
    expect(rows.find((r) => r.id === a.sessionId)?.current).toBe(true);
    expect(rows.find((r) => r.id === b.sessionId)?.current).toBe(false);

    await a.agent.post('/v1/auth/sessions/revoke').set('Authorization', `Bearer ${a.bearer}`).send({ jti: b.sessionId }).expect(200);
    // device B cannot rotate anymore
    await b.agent.post('/v1/auth/refresh').expect(401);
    // device A keeps rotating
    await a.agent.post('/v1/auth/refresh').expect(200);
    // unknown / already-revoked jtis all 404
    await a.agent.post('/v1/auth/sessions/revoke').set('Authorization', `Bearer ${a.bearer}`).send({ jti: b.sessionId }).expect(404);
    await a.agent.post('/v1/auth/sessions/revoke').set('Authorization', `Bearer ${a.bearer}`).send({ jti: 'ffffffffffffffff' }).expect(404);
  });

  it('revoke-all signs out every device including the caller', async () => {
    const email = await signup('allout');
    const a = await firstDevice(email, PASSWORD);
    await otherDevice(email, PASSWORD, a.secret);
    const list = await a.agent.get('/v1/auth/sessions').set('Authorization', `Bearer ${a.bearer}`).expect(200);
    expect(list.body.sessions.length).toBe(2);
    const ra = await a.agent.post('/v1/auth/sessions/revoke-all').set('Authorization', `Bearer ${a.bearer}`).expect(200);
    expect(ra.body.revoked).toBe(2);
    await a.agent.post('/v1/auth/refresh').expect(401);
    // the presented access token is denied too
    await a.agent.get('/v1/auth/me').set('Authorization', `Bearer ${a.bearer}`).expect(401);
  });

  it('revoking your OWN session acts as a logout (cookie cleared, access denied)', async () => {
    const email = await signup('selfrv');
    const a = await firstDevice(email, PASSWORD);
    const r = await a.agent
      .post('/v1/auth/sessions/revoke')
      .set('Authorization', `Bearer ${a.bearer}`)
      .send({ jti: a.sessionId })
      .expect(200);
    expect(r.body.selfRevoked).toBe(true);
    // refresh cookie was cleared by the server — the replay is a quiet 401
    await a.agent.post('/v1/auth/refresh').expect(401);
    // the presented access token is denied too
    await a.agent.get('/v1/auth/me').set('Authorization', `Bearer ${a.bearer}`).expect(401);
  });
});

describe('account security center — password rotation', () => {
  it('re-auths, enforces the policy, kills other sessions, keeps this one', async () => {
    const email = await signup('pwrot');
    const a = await firstDevice(email, PASSWORD);
    const b = await otherDevice(email, PASSWORD, a.secret);

    // wrong current password → 401 (per-user reauth cap counts it)
    await a.agent.post('/v1/auth/password').set('Authorization', `Bearer ${a.bearer}`).send({ currentPassword: WRONG_PASSWORD, newPassword: ROTATED_PASSWORD }).expect(401);
    // policy + sameness checks use the signup rules
    await a.agent.post('/v1/auth/password').set('Authorization', `Bearer ${a.bearer}`).send({ currentPassword: PASSWORD, newPassword: 'weak' }).expect(400);
    await a.agent.post('/v1/auth/password').set('Authorization', `Bearer ${a.bearer}`).send({ currentPassword: PASSWORD, newPassword: PASSWORD }).expect(400);
    const ok = await a.agent.post('/v1/auth/password').set('Authorization', `Bearer ${a.bearer}`).send({ currentPassword: PASSWORD, newPassword: ROTATED_PASSWORD }).expect(200);
    expect(ok.body.revokedOtherSessions).toBe(1);

    // old password is dead (uniform failure message)
    const bad = await api.post('/v1/auth/login').send({ identifier: email, password: PASSWORD }).expect(401);
    expect(bad.body.error).toBe('Invalid credentials');
    // new password logs in, straight to 2FA (still enrolled)
    const relogin = await api.post('/v1/auth/login').send({ identifier: email, password: ROTATED_PASSWORD }).expect(200);
    expect(relogin.body.step).toBe('2fa');
    // device B died with the rotation
    await b.agent.post('/v1/auth/refresh').expect(401);
    // device A survived its own rotation
    await a.agent.post('/v1/auth/refresh').expect(200);
  }, 20000);
});

describe('account security center — authenticator re-enrollment', () => {
  it('re-auths, replaces the secret (old codes die), completes via verify-2fa', async () => {
    const email = await signup('reenr');
    const a = await firstDevice(email, PASSWORD);

    await a.agent.post('/v1/auth/totp/re-enroll').set('Authorization', `Bearer ${a.bearer}`).send({ password: WRONG_PASSWORD }).expect(401);
    const re = await a.agent.post('/v1/auth/totp/re-enroll').set('Authorization', `Bearer ${a.bearer}`).send({ password: PASSWORD }).expect(200);
    expect(re.body.manualKey).toBeTruthy();
    expect(re.body.tempToken).toBeTruthy();

    // the OLD secret's current code is now invalid
    const oldCode = speakeasy.totp({ secret: a.secret, encoding: 'base32' });
    await a.agent.post('/v1/auth/verify-2fa').send({ tempToken: re.body.tempToken, code: oldCode }).expect(401);
    // the NEW secret's code completes the flow
    const newCode = speakeasy.totp({ secret: re.body.manualKey, encoding: 'base32' });
    const v = await a.agent.post('/v1/auth/verify-2fa').send({ tempToken: re.body.tempToken, code: newCode }).expect(200);
    expect(v.body.sessionId).toBeTruthy();
    // enrolled again — a fresh login goes straight to the 2FA step
    const after = await api.post('/v1/auth/login').send({ identifier: email, password: PASSWORD }).expect(200);
    expect(after.body.step).toBe('2fa');
  }, 20000);
});

describe('account security center — recovery codes (round 22)', () => {
  it('issues 10 unique unambiguous codes at enrollment; count endpoint is auth-gated', async () => {
    const email = await signup('reccodes');
    const a = await firstDevice(email, PASSWORD);
    expect(a.recoveryCodes).toHaveLength(10);
    expect(new Set(a.recoveryCodes).size).toBe(10);
    for (const c of a.recoveryCodes) expect(c).toMatch(/^[2-9A-HJKMNP-Z]{5}-[2-9A-HJKMNP-Z]{5}$/); // alphabet excludes only I, L, O

    await api.get('/v1/auth/recovery-codes').expect(401);
    const c0 = await a.agent.get('/v1/auth/recovery-codes').set('Authorization', `Bearer ${a.bearer}`).expect(200);
    expect(c0.body.remaining).toBe(10);
  });

  it('one code recovers a fresh device; replays and junk fail; recovery login forces re-enrollment', async () => {
    const email = await signup('reclogin');
    const a = await firstDevice(email, PASSWORD);

    // wrong code first (grind cap counts it — stay well under 5)
    const lBad = await api.post('/v1/auth/login').send({ identifier: email, password: PASSWORD }).expect(200);
    await api.post('/v1/auth/verify-2fa').send({ tempToken: lBad.body.tempToken, recoveryCode: 'AAAAA-BBBBB' }).expect(401);

    // the real thing: a fresh device recovers with ONE unused code
    const l = await api.post('/v1/auth/login').send({ identifier: email, password: PASSWORD }).expect(200);
    const rec = await api.post('/v1/auth/verify-2fa').send({ tempToken: l.body.tempToken, recoveryCode: a.recoveryCodes[3] }).expect(200);
    expect(rec.body.usedRecoveryCode).toBe(true);
    expect(rec.body.recoveryRemaining).toBe(9); // junk attempt consumed nothing; this one did
    expect(rec.body.sessionId).toBeTruthy();
    expect(rec.body.accessToken).toBeTruthy();

    // replaying the SAME code fails
    const l2 = await api.post('/v1/auth/login').send({ identifier: email, password: PASSWORD }).expect(200);
    const replay = await api.post('/v1/auth/verify-2fa').send({ tempToken: l2.body.tempToken, recoveryCode: a.recoveryCodes[3] });
    expect(replay.status).toBe(401);
    expect(replay.body.error).toBe('Invalid recovery code');

    // the account is NOT enrolled anymore: the next login re-enrolls from scratch
    const l3 = await api.post('/v1/auth/login').send({ identifier: email, password: PASSWORD }).expect(200);
    expect(l3.body.step).toBe('enroll');
    // completing THAT enrollment issues a fresh set and invalidates the old one
    const v3 = await api
      .post('/v1/auth/verify-2fa')
      .send({ tempToken: l3.body.tempToken, code: speakeasy.totp({ secret: l3.body.manualKey, encoding: 'base32' }) })
      .expect(200);
    expect(v3.body.recoveryCodes).toHaveLength(10);
    const oldTry = await api.post('/v1/auth/login').send({ identifier: email, password: PASSWORD }).expect(200);
    await api.post('/v1/auth/verify-2fa').send({ tempToken: oldTry.body.tempToken, recoveryCode: a.recoveryCodes[4] }).expect(401);
  }, 30000);

  it('regeneration requires password re-auth and fully replaces the set', async () => {
    const email = await signup('recregen');
    const a = await firstDevice(email, PASSWORD);

    await api.post('/v1/auth/recovery-codes').send({ password: 'nope' }).expect(401);
    const bad = await a.agent.post('/v1/auth/recovery-codes').set('Authorization', `Bearer ${a.bearer}`).send({ password: WRONG_PASSWORD }).expect(401);
    expect(bad.body.error).toBe('Current password is incorrect');
    const ok = await a.agent.post('/v1/auth/recovery-codes').set('Authorization', `Bearer ${a.bearer}`).send({ password: PASSWORD }).expect(200);
    expect(ok.body.codes).toHaveLength(10);
    expect(ok.body.remaining).toBe(10);

    // an OLD code no longer works
    const l = await api.post('/v1/auth/login').send({ identifier: email, password: PASSWORD }).expect(200);
    await api.post('/v1/auth/verify-2fa').send({ tempToken: l.body.tempToken, recoveryCode: a.recoveryCodes[0] }).expect(401);
    // a NEW one does
    const l2 = await api.post('/v1/auth/login').send({ identifier: email, password: PASSWORD }).expect(200);
    const use = await api.post('/v1/auth/verify-2fa').send({ tempToken: l2.body.tempToken, recoveryCode: ok.body.codes[0] }).expect(200);
    expect(use.body.usedRecoveryCode).toBe(true);
  }, 30000);
});
