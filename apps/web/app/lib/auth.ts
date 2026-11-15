'use client';
// Auth session: access token lives in MEMORY ONLY (never localStorage —
// XSS-readable storage is the quality gap this closes). The HttpOnly refresh
// cookie (same-site across localhost ports, Secure in prod) silently mints new
// access tokens on boot and on 401-retry. Attestation ids stay in localStorage:
// they authorize test scope, not identity, and must survive reloads for UX.
// One API base URL for the whole app — import { API_URL } everywhere instead of
// re-reading process.env in each component.
export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
const API = API_URL;

let access: string | null = null;
let refreshInflight: Promise<string | null> | null = null;
let refreshFailedUntil = 0; // dedupes the browser's unavoidable 401 net-logs

export function setAccess(token: string | null) {
  access = token;
}

async function silentRefresh(): Promise<string | null> {
  if (!refreshInflight) {
    if (Date.now() < refreshFailedUntil) return null; // just failed — don't re-ping
    refreshInflight = (async () => {
      try {
        const r = await fetch(`${API}/v1/auth/refresh`, { method: 'POST', credentials: 'include' });
        if (!r.ok) {
          refreshFailedUntil = Date.now() + 10_000;
          return null;
        }
        const j = await r.json();
        return (j.accessToken as string) ?? null;
      } catch {
        refreshFailedUntil = Date.now() + 10_000;
        return null;
      } finally {
        refreshInflight = null;
      }
    })();
  }
  const tok = await refreshInflight;
  access = tok;
  return tok;
}

export async function getAccess(): Promise<string | null> {
  if (access) return access;
  return silentRefresh();
}

// Authenticated fetch: attaches memory token, retries ONCE after silent refresh
// on 401. Returns the final Response — callers handle status as before.
export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (!headers.has('Content-Type') && init.body !== undefined) headers.set('Content-Type', 'application/json');
  let tok = await getAccess();
  if (tok) headers.set('Authorization', `Bearer ${tok}`);
  let r = await fetch(`${API}${path}`, { ...init, headers, credentials: 'include' });
  if (r.status === 401) {
    access = null;
    tok = await silentRefresh();
    if (tok) {
      headers.set('Authorization', `Bearer ${tok}`);
      r = await fetch(`${API}${path}`, { ...init, headers, credentials: 'include' });
    }
  }
  return r;
}

export async function logoutEverywhere(): Promise<void> {
  try {
    await apiFetch('/v1/auth/logout', { method: 'POST' });
  } catch {
    /* already gone */
  } finally {
    access = null;
  }
}

// Who is signed in? Resolves null when there is no live session (or the
// account vanished server-side). Used by the nav session chip and any UI that
// needs the user's name/role without re-asking the API in every panel.
export async function getMe(): Promise<{ username: string; email: string; role: string; orgId: string } | null> {
  const tok = await getAccess();
  if (!tok) return null;
  try {
    const r = await apiFetch('/v1/auth/me');
    if (!r.ok) return null;
    const j = (await r.json()) as { user?: { username: string; email: string; role: string; orgId: string } };
    return j.user ?? null;
  } catch {
    return null;
  }
}
