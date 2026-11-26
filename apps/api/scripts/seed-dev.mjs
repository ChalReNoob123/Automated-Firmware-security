#!/usr/bin/env node
// Dev-only seed: a known account and the demo finding queue, with no hand-rolled
// 2FA.
//
// POST /v1/auth/signup creates the org + Owner, then /v1/auth/login answers with
// an enrollment step carrying the TOTP key, and this script completes
// /v1/auth/verify-2fa itself with a live code. The key is kept in
// .seed-dev.json (gitignored) so later runs can log in the same account again.
// Refuses to run in production, and only seeds findings when the org has none.
//
//   npm --prefix apps/api run seed:dev
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import speakeasy from 'speakeasy';

const STATE = join(dirname(fileURLToPath(import.meta.url)), '..', '.seed-dev.json');
const API = (process.env.SF_API_URL ?? 'http://localhost:4000').replace(/\/+$/, '');
const WEB = process.env.SF_WEB_URL ?? 'http://localhost:3005';
const ACCOUNT = {
  orgName: 'SentinelForge Dev',
  username: 'dev',
  email: 'dev@sentinelforge.local',
  // Meets the signup policy (length, upper, lower, digit, symbol).
  password: 'SentinelForge#dev2026',
};

if (process.env.NODE_ENV === 'production') {
  console.error('seed:dev refuses to run with NODE_ENV=production.');
  process.exit(1);
}

const call = async (path, body, token) => {
  const r = await fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body ?? {}),
  });
  let json = null;
  try {
    json = await r.json();
  } catch {
    /* no body */
  }
  return { status: r.status, json };
};
const fail = (message, detail) => {
  console.error(`seed:dev: ${message}`);
  if (detail) console.error(JSON.stringify(detail));
  process.exit(1);
};

const totpCode = (secret) => speakeasy.totp({ secret, encoding: 'base32' });

// The API may be on Postgres or its in-memory fallback; either way the seed
// drives the real HTTP surface, so no store internals are involved.
try {
  const health = await fetch(API + '/health');
  if (!health.ok) fail(`${API}/health answered ${health.status}; is that the API?`);
} catch {
  fail(`cannot reach ${API} — start it with: npm --prefix apps/api run dev`);
}

let state = null;
if (existsSync(STATE)) {
  try {
    state = JSON.parse(readFileSync(STATE, 'utf8'));
  } catch {
    fail(`${STATE} is not valid JSON; delete it to start over`);
  }
}

// 1. Account. 409 means it exists already, which is the normal re-run path.
const signup = await call('/v1/auth/signup', ACCOUNT);
if (![200, 201, 409].includes(signup.status)) fail('signup failed', signup);

// 2. Password step. A fresh account answers with the enrollment step (totp key);
// an enrolled account asks for a code, which needs the key from a prior run.
const login = await call('/v1/auth/login', {
  identifier: ACCOUNT.email,
  password: ACCOUNT.password,
  rememberMe: true,
});
if (login.status !== 200 || !login.json?.tempToken) fail('login failed', login);

// manualKey is only present while enrolling; afterwards the key must come from
// the state file, and only if it belongs to this same account.
const stored = state?.email === ACCOUNT.email ? state?.totpSecret : null;
const secret = login.json.manualKey ?? stored ?? null;
if (!secret) {
  fail('this account is already enrolled and .seed-dev.json has no key; delete it to enroll fresh');
}

// 3. Finish 2FA with a code generated from that key — no app, no QR scan.
const code = totpCode(secret);
const verify = await call('/v1/auth/verify-2fa', { tempToken: login.json.tempToken, code, rememberMe: true });
if (verify.status !== 200 || !verify.json?.accessToken) fail('2FA verification failed', verify);
writeFileSync(STATE, JSON.stringify({ email: ACCOUNT.email, totpSecret: secret }, null, 2) + '\n');

// 4. Demo findings, only when the queue is empty (the demo route appends).
const auth = { Authorization: `Bearer ${verify.json.accessToken}` };
const listRes = await fetch(API + '/v1/findings', { headers: auth });
if (!listRes.ok) fail(`could not read the existing queue (${listRes.status})`);
const existing = (await listRes.json()).findings ?? [];
let seeded = 0;
if (existing.length === 0) {
  const seed = await call('/v1/findings/demo', {}, verify.json.accessToken);
  if (seed.status !== 201) fail('findings seed failed', seed);
  seeded = seed.json?.seeded ?? 0;
}

console.log(`
  SentinelForge dev seed
  ----------------------
  URL        ${WEB}/login
  email      ${ACCOUNT.email}
  password   ${ACCOUNT.password}
  TOTP key   ${secret}
  code now   ${totpCode(secret)}
  findings   ${seeded > 0 ? `${seeded} seeded` : `${existing.length} already present (not re-seeded)`}
`);
