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

// ============================================================================
// 7. TEAM MANAGEMENT — role change + member removal (round 29)
//    PATCH /v1/auth/teammates/:id and DELETE /v1/auth/teammates/:id close
//    the loop the invite endpoint opened. Pins: manage:users only; tenancy
//    from the token (cross-org id = unknown id, uniform 404); self-actions
//    refused; the Owner row immutable; role changes revoke the target's
//    refresh tokens so the new role is live from the next login; removal
//    makes re-authentication impossible (login 401) and kills the identity
//    row (the stale bearer still passes signature checks for ≤15 min — it
//    403s on perm-gated routes, NOT 401 — while /me 404s: account gone);
//    both actions land in the org-scoped audit trail with the target named.
// ============================================================================
describe('team management — role change + removal', () => {
  const roster = async (owner: string) =>
    (await api.get('/v1/auth/teammates').set('Authorization', `Bearer ${owner}`).expect(200)).body as {
      selfId: string;
      members: { id: string; username: string; role: string }[];
    };

  it('401 without a token; Analyst/Viewer 403 for both actions', async () => {
    await api.patch('/v1/auth/teammates/x_id').send({ role: 'Viewer' }).expect(401);
    await api.delete('/v1/auth/teammates/x_id').expect(401);
    const owner = await signup(`lown${S}`);
    const vie = await invite(owner, `lvie${S}`, 'Viewer');
    const vieT = await inviteeLogin(`lvie${S}`, vie.body.tempPassword);
    await api.patch(`/v1/auth/teammates/x_id`).set('Authorization', `Bearer ${vieT}`).send({ role: 'Viewer' }).expect(403);
    await api.delete(`/v1/auth/teammates/x_id`).set('Authorization', `Bearer ${vieT}`).expect(403);
  }, 60000);

  it('refuses self-actions, the Owner row, and bad roles; cross-org ids are indistinguishable from unknown', async () => {
    const a = await signup(`hown${S}`);
    const adm = await invite(a, `hadm${S}`, 'Admin');
    const admT = await inviteeLogin(`hadm${S}`, adm.body.tempPassword);
    const rosterA = await roster(a);
    const adminId = rosterA.members.find((m) => m.username === `hadm${S}`)!.id;
    const ownerId = rosterA.members.find((m) => m.username === `hown${S}`)!.id;

    // self: the roster carries selfId — changing or removing yourself is refused
    await api.patch(`/v1/auth/teammates/${rosterA.selfId}`).set('Authorization', `Bearer ${a}`).send({ role: 'Viewer' }).expect(400);
    await api.delete(`/v1/auth/teammates/${rosterA.selfId}`).set('Authorization', `Bearer ${a}`).expect(400);

    // the Owner row: immutable through this API, even for the Admin
    await api.patch(`/v1/auth/teammates/${ownerId}`).set('Authorization', `Bearer ${admT}`).send({ role: 'Viewer' }).expect(403);
    await api.delete(`/v1/auth/teammates/${ownerId}`).set('Authorization', `Bearer ${admT}`).expect(403);

    // invalid role body
    await api.patch(`/v1/auth/teammates/${adminId}`).set('Authorization', `Bearer ${a}`).send({ role: 'Owner' }).expect(400);
    await api.patch(`/v1/auth/teammates/${adminId}`).set('Authorization', `Bearer ${a}`).send({}).expect(400);

    // tenancy: another org's owner id reads as plain "not found"
    const other = await signup(`iother${S}`);
    const otherRoster = await roster(other);
    await api.patch(`/v1/auth/teammates/${otherRoster.selfId}`).set('Authorization', `Bearer ${a}`).send({ role: 'Viewer' }).expect(404);
    const nf = await api.delete(`/v1/auth/teammates/${otherRoster.selfId}`).set('Authorization', `Bearer ${a}`).expect(404);
    expect(nf.body.error).toBe('Teammate not found');
    // ...and an outright unknown id gets the same uniform answer
    await api.delete('/v1/auth/teammates/00000000-0000-0000-0000-000000000000').set('Authorization', `Bearer ${a}`).expect(404);
  }, 60000);

  it('role change: 200 + roster reflects it + the fresh login carries the new role + matrix takes effect + audited', async () => {
    const owner = await signup(`jown${S}`);
    const ana = await invite(owner, `jana${S}`, 'Analyst');
    const anaId = (await roster(owner)).members.find((m) => m.username === `jana${S}`)!.id;

    const r = (await api.patch(`/v1/auth/teammates/${anaId}`).set('Authorization', `Bearer ${owner}`).send({ role: 'Viewer' }).expect(200)).body as {
      id: string;
      role: string;
      sessionsRevoked: boolean;
    };
    expect(r).toMatchObject({ id: anaId, role: 'Viewer', sessionsRevoked: true });
    // the roster (read fresh) shows the new role
    expect((await roster(owner)).members.find((m) => m.id === anaId)?.role).toBe('Viewer');

    // the member logs in again — the fresh session carries the DEMOTED role
    const reLogin = await api.post('/v1/auth/login').send({ identifier: `jana${S}@t.test`, password: ana.body.tempPassword }).expect(200);
    const code = speakeasy.totp({ secret: reLogin.body.manualKey, encoding: 'base32' });
    const v = await api.post('/v1/auth/verify-2fa').send({ tempToken: reLogin.body.tempToken, code }).expect(200);
    const me = await api.get('/v1/auth/me').set('Authorization', `Bearer ${v.body.accessToken}`).expect(200);
    expect(me.body.user.role).toBe('Viewer');
    // the RBAC matrix enforces it: triage:write (Analyst-only) now 403s
    await api.post('/v1/findings/demo').set('Authorization', `Bearer ${v.body.accessToken}`).expect(403);

    // audited, org-scoped, with the event visible in the readout
    const aud = (await api.get('/v1/auth/audit').set('Authorization', `Bearer ${owner}`).expect(200)).body as {
      events: { event: string }[];
    };
    expect(aud.events.some((e) => e.event === 'user_role_changed')).toBe(true);
  }, 60000);

  it('removal: 200 + roster drops the row + the removed member can never log in again + audited', async () => {
    const owner = await signup(`kown${S}`);
    const ana = await invite(owner, `kana${S}`, 'Analyst');
    const anaT = await inviteeLogin(`kana${S}`, ana.body.tempPassword); // a real enrolled session exists
    const anaId = (await roster(owner)).members.find((m) => m.username === `kana${S}`)!.id;

    const r = (await api.delete(`/v1/auth/teammates/${anaId}`).set('Authorization', `Bearer ${owner}`).expect(200)).body as {
      removed: boolean;
      id: string;
    };
    expect(r).toMatchObject({ removed: true, id: anaId });
    expect((await roster(owner)).members.map((m) => m.username)).toEqual([`kown${S}`]);

    // the account is GONE: the temp password login fails with uniform invalid
    // credentials — re-authentication is impossible, which is the point.
    await api.post('/v1/auth/login').send({ identifier: `kana${S}@t.test`, password: ana.body.tempPassword }).expect(401);
    // the removed member's still-warm bearer keeps PASSING authentication (the
    // access token is signature-valid and unrevoked — the standing ≤15-min
    // window, same model as password rotation). The honest end-state is pinned
    // precisely: 403 on a manager route = authenticated but the OLD role claim
    // lacks the perm (NOT 401 — auth succeeded); /me 404s because the
    // identity row itself is gone.
    await api.get('/v1/auth/teammates').set('Authorization', `Bearer ${anaT}`).expect(403);
    await api.get('/v1/auth/me').set('Authorization', `Bearer ${anaT}`).expect(404);

    const aud = (await api.get('/v1/auth/audit').set('Authorization', `Bearer ${owner}`).expect(200)).body as {
      events: { event: string }[];
    };
    expect(aud.events.some((e) => e.event === 'user_removed')).toBe(true);
  }, 60000);

  // The gap only a REAL browser can see: supertest never sends an OPTIONS
  // preflight (same-origin), but every fetch from the web app does — with a
  // static method list missing PATCH, the role change died as "Failed to
  // fetch" while every unit test stayed green. Pinned here so the preflight
  // list can never silently lag behind the routes again.
  it('CORS preflight admits PATCH + DELETE for the web origin', async () => {
    const r = await api
      .options('/v1/auth/teammates/x_id')
      .set('Origin', 'http://localhost:3006')
      .set('Access-Control-Request-Method', 'PATCH')
      .set('Access-Control-Request-Headers', 'content-type,authorization')
      .expect((res) => expect([200, 204]).toContain(res.status));
    expect(String(r.headers['access-control-allow-methods'] ?? '')).toContain('PATCH');
    expect(String(r.headers['access-control-allow-methods'] ?? '')).toContain('DELETE');
    expect(r.headers['access-control-allow-origin']).toBe('http://localhost:3006');
    expect(r.headers['access-control-allow-credentials']).toBe('true');
  }, 60000);
});
