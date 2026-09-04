'use client';
// Auth session: access token lives in MEMORY ONLY (never localStorage —
// XSS-readable storage is the quality gap this closes). The HttpOnly refresh
// cookie (same-site across localhost ports, Secure in prod) silently mints new
// access tokens on boot and on 401-retry. Attestation ids stay in localStorage:
// they authorize test scope, not identity, and must survive reloads for UX.
const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

let access: string | null = null;
let refreshInflight: Promise<string | null> | null = null;

export function setAccess(token: string | null) {
  access = token;
}

async function silentRefresh(): Promise<string | null> {
  if (!refreshInflight) {
    refreshInflight = (async () => {
      try {
        const r = await fetch(`${API}/v1/auth/refresh`, { method: 'POST', credentials: 'include' });
        if (!r.ok) return null;
        const j = await r.json();
        return (j.accessToken as string) ?? null;
      } catch {
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
