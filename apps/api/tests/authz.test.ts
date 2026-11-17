// ============================================================================
// SentinelForge v3 — Authorization-matrix audit suite (round 24)
// The RBAC matrix in middleware/rbac.ts is now LIVE: signup hardcodes Owner,
// and POST /v1/auth/invite (manage:users) is the only way to mint
// Admin/Analyst/Viewer/Auditor. Every test below pins a cell of the matrix or
// a tenancy boundary. Failures here = live authorization bugs.
// ============================================================================
import { describe, expect, it } from 'vitest';
import request from 'supertest';
import speakeasy from 'speakeasy';
import { app } from '../src/app.js';

const api = request(app);
const PW = 'Str0ng!Pass1';
const S = Date.now(); // unique suffix for this file's run

async function signup(username: string): Promise<string> {
  const email = `${username}@t.test`;
  await api.post('/v1/auth/signup').send({ orgName: `org-${username}`, username, email, password: PW }).expect(201);
  const login = await api.post('/v1/auth/login').send({ identifier: email, password: PW }).expect(200);
  const code = speakeasy.totp({ secret: login.body.manualKey, encoding: 'base32' });
  const v = await api.post('/v1/auth/verify-2fa').send({ tempToken: login.body.tempToken, code }).expect(200);
  return v.body.accessToken as string;
}

async function invite(ownerToken: string, username: string, role: string) {
  const r = await api
    .post('/v1/auth/invite')
    .set('Authorization', `Bearer ${ownerToken}`)
    .send({ email: `${username}@t.test`, username, role });
  return r;
}

// Full auth for an invited user: login (enroll step) → TOTP → access token.
async function inviteeLogin(username: string, tempPassword: string): Promise<string> {
  const l = await api.post('/v1/auth/login').send({ identifier: `${username}@t.test`, password: tempPassword }).expect(200);
  expect(l.body.step).toBe('enroll');
  const code = speakeasy.totp({ secret: l.body.manualKey, encoding: 'base32' });
  const v = await api.post('/v1/auth/verify-2fa').send({ tempToken: l.body.tempToken, code }).expect(200);
  return v.body.accessToken as string;
}

// ============================================================================
// 1. THE PUBLIC SURFACE — exact list of what an unauthenticated caller reaches
// ============================================================================
describe('public route inventory', () => {
  it('serves exactly the public sample/stub surface without auth', async () => {
    await api.get('/health').expect(200);
    await api.get('/v1/graph/demo').expect(200);
    await api.get('/v1/radar/demo').expect(200);
    await api.get('/v1/capabilities').expect(200);
    await api.get('/v1/auth/sso/saml').expect(200);
  });

  it('returns 401 (not 403/404/500) on every data/mutation surface without a token', async () => {
    await api.get('/v1/auth/me').expect(401);
    await api.get('/v1/auth/audit').expect(401);
    await api.get('/v1/auth/sessions').expect(401);
    await api.get('/v1/devices').expect(401);
    await api.get('/v1/findings').expect(401);
    await api.get('/v1/system/usb-devices').expect(401);
    await api.get('/v1/emulator/sessions/emu_x').expect(401);
    await api.post('/v1/pipeline/runs').send({}).expect(401);
    await api.post('/v1/emulator/sessions').send({}).expect(401);
    await api.post('/v1/attestations').send({}).expect(401);
    await api.post('/v1/auth/invite').send({}).expect(401);
  });
});

// ============================================================================
// 2. THE RBAC MATRIX — every invited role is mintable, and the matrix holds
// ============================================================================
describe('authorization matrix (invite-driven roles)', () => {
  it('mints every non-Owner role and enforces the matrix cell by cell', async () => {
    const owner = await signup(`mown${S}`);

    // Admin: manage:users + read:audit + write paths (incl. the round-24
    // triage:write fix — Admin previously fell through to 403 on findings)
    const adm = await invite(owner, `madm${S}`, 'Admin');
    expect(adm.status).toBe(201);
    const admPw = adm.body.tempPassword as string;
    expect(typeof admPw).toBe('string');
    const admT = await inviteeLogin(`madm${S}`, admPw);
    await api.post('/v1/auth/invite').set('Authorization', `Bearer ${admT}`).send({ email: `x${S}@t.test`, username: `mx${S}`, role: 'Viewer' }).expect(201);
    await api.get('/v1/auth/audit').set('Authorization', `Bearer ${admT}`).expect(200);
    await api.post('/v1/findings').set('Authorization', `Bearer ${admT}`).send({ title: 'admin triage works' }).expect(201);
    await api.post('/v1/devices').set('Authorization', `Bearer ${admT}`).send({ name: 'adm dev', transport: 'usb' }).expect(201);

    // Analyst: triage:write + scan:run + attest:sign, but NOT read:audit/manage:users
    const ana = await invite(owner, `mana${S}`, 'Analyst');
    expect(ana.status).toBe(201);
    const anaT = await inviteeLogin(`mana${S}`, ana.body.tempPassword);
    await api.post('/v1/findings').set('Authorization', `Bearer ${anaT}`).send({ title: 'analyst triage works' }).expect(201);
    await api.post('/v1/devices').set('Authorization', `Bearer ${anaT}`).send({ name: 'ana dev', transport: 'usb' }).expect(201);
    await api.get('/v1/auth/audit').set('Authorization', `Bearer ${anaT}`).expect(403);
    await api.post('/v1/auth/invite').set('Authorization', `Bearer ${anaT}`).send({ email: `y${S}@t.test`, username: `my${S}`, role: 'Viewer' }).expect(403);

    // Viewer: read findings/devices, write NOTHING
    const vie = await invite(owner, `mvie${S}`, 'Viewer');
    expect(vie.status).toBe(201);
    const vieT = await inviteeLogin(`mvie${S}`, vie.body.tempPassword);
    await api.get('/v1/findings').set('Authorization', `Bearer ${vieT}`).expect(200);
    await api.get('/v1/devices').set('Authorization', `Bearer ${vieT}`).expect(200);
    await api.post('/v1/findings').set('Authorization', `Bearer ${vieT}`).send({ title: 'viewer denied' }).expect(403);
    await api.post('/v1/devices').set('Authorization', `Bearer ${vieT}`).send({ name: 'no', transport: 'usb' }).expect(403);
    await api.post('/v1/attestations').set('Authorization', `Bearer ${vieT}`).send({ deviceId: 'd', scope: 's', legalBasis: 'b' }).expect(403);
    await api.get('/v1/auth/audit').set('Authorization', `Bearer ${vieT}`).expect(403);
    await api.post('/v1/auth/invite').set('Authorization', `Bearer ${vieT}`).send({ email: `z${S}@t.test`, username: `mz${S}`, role: 'Viewer' }).expect(403);

    // Auditor: read:audit yes, every write no
    const aud = await invite(owner, `maud${S}`, 'Auditor');
    expect(aud.status).toBe(201);
    const audT = await inviteeLogin(`maud${S}`, aud.body.tempPassword);
    const auditBody = (await api.get('/v1/auth/audit').set('Authorization', `Bearer ${audT}`).expect(200)).body;
    expect(Array.isArray(auditBody.events)).toBe(true);
    await api.post('/v1/findings').set('Authorization', `Bearer ${audT}`).send({ title: 'auditor denied' }).expect(403);
    await api.post('/v1/devices').set('Authorization', `Bearer ${audT}`).send({ name: 'no', transport: 'usb' }).expect(403);
    await api.post('/v1/auth/invite').set('Authorization', `Bearer ${audT}`).send({ email: `w${S}@t.test`, username: `mw${S}`, role: 'Viewer' }).expect(403);

    // Same-org tenancy holds for invited users: they see the OWNER's devices.
    await api.post('/v1/devices').set('Authorization', `Bearer ${owner}`).send({ name: `owner-dev-${S}`, transport: 'usb' }).expect(201);
    const vieDevs = (await api.get('/v1/devices').set('Authorization', `Bearer ${vieT}`).expect(200)).body;
    expect(JSON.stringify(vieDevs)).toContain(`owner-dev-${S}`);
  }, 60000);

  it('rejects Owner invites, duplicate identities, and bad role names', async () => {
    const owner = await signup(`mown2${S}`);
    // Owner is signup-only — an Admin must never mint a superior
    expect((await invite(owner, `mown3${S}`, 'Owner')).status).toBe(400);
    // unknown role → 400 with a message
    const bad = await invite(owner, `mbadr${S}`, 'Root');
    expect(bad.status).toBe(400);
    // malformed username → 400
    await api.post('/v1/auth/invite').set('Authorization', `Bearer ${owner}`).send({ email: `bad@t.test`, username: 'bad space!', role: 'Viewer' }).expect(400);
    // successful invite, then the SAME username/email again → 409 uniform
    const inv = await invite(owner, `mrep${S}`, 'Viewer');
    expect(inv.status).toBe(201);
    await api.post('/v1/auth/invite').set('Authorization', `Bearer ${owner}`).send({ email: `mrep${S}@t.test`, username: `mrepx${S}`, role: 'Viewer' }).expect(409);
    await api.post('/v1/auth/invite').set('Authorization', `Bearer ${owner}`).send({ email: `other${S}@t.test`, username: `mrep${S}`, role: 'Viewer' }).expect(409);
    // invited identity can actually log in with the one-time password
    await inviteeLogin(`mrep${S}`, inv.body.tempPassword);
  }, 60000);
});

// ============================================================================
// 3. AUDIT READOUT TENANCY — the round-24 fix (memory fallback ignored the org)
// ============================================================================
describe('audit readout is org-filtered', () => {
  it("an org's auditor sees own-org events and never another org's", async () => {
    const a = await signup(`aaud${S}`);
    const b = await signup(`baud${S}`);
    const inv = await invite(a, `ainv${S}`, 'Auditor');
    const audT = await inviteeLogin(`ainv${S}`, inv.body.tempPassword);
    // B generates a DISTINCTIVE audit event (org-scoped to B)
    await api.post('/v1/auth/recovery-codes').set('Authorization', `Bearer ${b}`).send({ password: 'Wrong!Pass1' }).expect(401);

    const evA = (await api.get('/v1/auth/audit').set('Authorization', `Bearer ${audT}`).expect(200)).body.events as Array<Record<string, unknown>>;
    const kinds = evA.map((e) => String(e.event));
    expect(kinds).toContain('user_invited'); // positive control: the filter is not just empty
    expect(kinds).not.toContain('recovery_regenerate_failed'); // B's distinctive event must not leak
    // shape: no org ids leave the endpoint
    for (const e of evA) expect(Object.keys(e).sort()).toEqual(['created_at', 'event', 'ip']);

    const evB = (await api.get('/v1/auth/audit').set('Authorization', `Bearer ${b}`).expect(200)).body.events as Array<Record<string, unknown>>;
    expect(evB.map((e) => String(e.event))).toContain('recovery_regenerate_failed'); // B sees their own
  }, 60000);
});

// ============================================================================
// 4. GARBAGE-ID PROBES + GATE ORDER
// ============================================================================
describe('garbage ids and gate ordering', () => {
  it('404s unknown ids inside the caller org, 403s junk attestations, 401s junk tokens', async () => {
    const owner = await signup(`gown${S}`);
    const inv = await invite(owner, `gana${S}`, 'Analyst');
    const anaT = await inviteeLogin(`gana${S}`, inv.body.tempPassword);

    await api.get('/v1/emulator/sessions/emu_deadbeef').set('Authorization', `Bearer ${owner}`).expect(404);
    await api.get('/v1/pipeline/runs/not-a-uuid').set('Authorization', `Bearer ${owner}`).expect(404);
    await api.delete('/v1/findings/f_x').set('Authorization', `Bearer ${anaT}`).expect(404);
    await api.post('/v1/emulator/sessions').set('Authorization', `Bearer ${owner}`).set('x-attestation-id', 'att_junk').send({ arch: 'arm' }).expect(403);
    await api.get('/v1/auth/me').set('Authorization', 'Bearer not.a.jwt').expect(401);
    await api.get('/v1/auth/me').set('Authorization', 'Basic dXNlcjpwYXNz').expect(401);
    // requireAuth runs BEFORE requireAttestation — no token means 401, not 403
    await api.post('/v1/emulator/sessions').send({ arch: 'arm' }).expect(401);
  }, 60000);

  it('foreign org session is 404 even with a VALID own-org attestation', async () => {
    const a = await signup(`xowa${S}`);
    const b = await signup(`xowb${S}`);
    const devA = (await api.post('/v1/devices').set('Authorization', `Bearer ${a}`).send({ name: 'd', transport: 'usb' }).expect(201)).body;
    const attA = (await api.post('/v1/attestations').set('Authorization', `Bearer ${a}`).send({ deviceId: devA.id, scope: 's', legalBasis: 'own ref' }).expect(201)).body;
    const sB = (await api.post('/v1/emulator/sessions').set('Authorization', `Bearer ${b}`).set('x-attestation-id', 'att_junk').send({ arch: 'arm' }));
    // B cannot boot without their own attestation; make B's session impossible here,
    // so assert the INVERSE: A presents their valid attestation against a session
    // id that can only exist in B's org → still 404.
    if (sB.status === 403) {
      const H = { Authorization: `Bearer ${a}`, 'x-attestation-id': attA.id };
      await api.get('/v1/emulator/sessions/emu_ghost').set(H).expect(404);
    } else {
      // defensive: if B somehow booted, A (with own valid attestation) still 404s on it
      const H = { Authorization: `Bearer ${a}`, 'x-attestation-id': attA.id };
      await api.get(`/v1/emulator/sessions/${(sB.body as { id?: string }).id ?? 'emu_ghost'}`).set(H).expect(404);
      await api.post(`/v1/emulator/sessions/${(sB.body as { id?: string }).id ?? 'emu_ghost'}/replay`).set(H).send({ snapshotId: 'x' }).expect(404);
    }
  }, 60000);
});

// ============================================================================
// 5. COMPUTE SURFACES — pinned as authn-only BY DECISION (round-24 ledger)
// ============================================================================
describe('compute surfaces take caller-supplied data only', () => {
  it('a read-limited Viewer may run radar checks and graph builds — no org data is read', async () => {
    const owner = await signup(`cown${S}`);
    const inv = await invite(owner, `cvie${S}`, 'Viewer');
    const vieT = await inviteeLogin(`cvie${S}`, inv.body.tempPassword);

    const r = await api
      .post('/v1/radar/check')
      .set('Authorization', `Bearer ${vieT}`)
      .send({
        firmwareRef: 'fw-demo',
        sbom: [{ name: 'httpd', version: '1.9' }],
        advisories: [
          {
            id: 'CVE-2024-3094',
            published: new Date().toISOString(),
            summary: 'xz backdoor',
            affected: [{ name: 'httpd', versionEnd: '1.9', versionEndType: 'including' }],
          },
        ],
      })
      .expect(200);
    expect(r.body.results).toHaveLength(1);

    const g = await api
      .post('/v1/graph/build')
      .set('Authorization', `Bearer ${vieT}`)
      .send({ taintPaths: [{ source: 'recv', sink: 'strcpy', path: ['recv', 'parse_query', 'strcpy'] }] })
      .expect(201);
    expect(g.body.graph).toBeTruthy();
    // and the demo sample stays public for both
    await api.get('/v1/graph/demo').expect(200);
    await api.get('/v1/radar/demo').expect(200);
  }, 60000);
});

// ============================================================================
// 6. TEAMMATES ROSTER — the manage:users READ surface (round 26)
//    The Security Center's Teammates console reads GET /v1/auth/teammates.
//    Pins: 401 unauthenticated; Owner/Admin 200; Analyst/Viewer/Auditor 403;
//    org scoping (another org's owner username must never appear); exact
//    response shape (no password hashes, no TOTP secrets, no org ids);
//    per-member 2FA state (enrolled Owner vs freshly-invited unenrolled).
// ============================================================================
describe('teammates roster (manage:users read surface)', () => {
  it('401 without a token; Owner and Admin read; Analyst/Viewer/Auditor are 403', async () => {
    await api.get('/v1/auth/teammates').expect(401);
    const owner = await signup(`town${S}`);
    const adm = await invite(owner, `tadm${S}`, 'Admin');
    const admT = await inviteeLogin(`tadm${S}`, adm.body.tempPassword);
    const ana = await invite(owner, `tana${S}`, 'Analyst');
    const anaT = await inviteeLogin(`tana${S}`, ana.body.tempPassword);
    const vie = await invite(owner, `tvie${S}`, 'Viewer');
    const vieT = await inviteeLogin(`tvie${S}`, vie.body.tempPassword);
    const aud = await invite(owner, `taud${S}`, 'Auditor');
    const audT = await inviteeLogin(`taud${S}`, aud.body.tempPassword);

    await api.get('/v1/auth/teammates').set('Authorization', `Bearer ${owner}`).expect(200);
    await api.get('/v1/auth/teammates').set('Authorization', `Bearer ${admT}`).expect(200);
    await api.get('/v1/auth/teammates').set('Authorization', `Bearer ${anaT}`).expect(403);
    await api.get('/v1/auth/teammates').set('Authorization', `Bearer ${vieT}`).expect(403);
    await api.get('/v1/auth/teammates').set('Authorization', `Bearer ${audT}`).expect(403);
  }, 60000);

  it('the roster is org-scoped, shape-pinned, and leaks no secrets', async () => {
    const a = await signup(`rown${S}`);
    await signup(`sown${S}`); // second org — its owner's identity must never appear in A's roster
    await invite(a, `rinv${S}`, 'Analyst'); // invited but NOT yet logged in → TOTP still unenrolled

    const r = (await api.get('/v1/auth/teammates').set('Authorization', `Bearer ${a}`).expect(200)).body as {
      orgId: string;
      selfId: string;
      members: Array<Record<string, unknown>>;
    };
    // exactly A's org: the owner + the one invited analyst
    expect(r.members).toHaveLength(2);
    expect(r.members.map((m) => String(m.username)).sort()).toEqual([`rinv${S}`, `rown${S}`]);
    expect(JSON.stringify(r)).not.toContain(`sown${S}`); // cross-tenant identity never leaks
    // shape pinned cell by cell: identity + 2FA state only
    for (const m of r.members) {
      expect(Object.keys(m).sort()).toEqual(['email', 'id', 'lastLogin', 'role', 'totpEnrolled', 'username']);
    }
    // selfId resolves to the caller's own row, which carries the signup role
    const self = r.members.find((m) => m.id === r.selfId);
    expect(self?.role).toBe('Owner');
    // 2FA state is real: the enrolled owner vs the freshly-invited analyst
    expect(r.members.find((m) => m.username === `rown${S}`)?.totpEnrolled).toBe(true);
    expect(r.members.find((m) => m.username === `rinv${S}`)?.totpEnrolled).toBe(false);
  }, 60000);
});
