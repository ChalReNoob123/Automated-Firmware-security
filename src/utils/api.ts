/**
 * SentinelGrid API Utility — Production-Hardened
 * All API calls go through here so the base URL is never hardcoded.
 * Gap #24 fix: API URL driven by VITE_API_URL environment variable.
 */

export const API_BASE = (import.meta.env.VITE_API_URL || 'http://localhost:3001').replace(/\/$/, '');
export const WS_BASE  = (import.meta.env.VITE_WS_URL  || 'ws://localhost:3001').replace(/\/$/, '');

/* ── storage fallback for Safari Private / IE ───────────────────── */
const _memStorage: Record<string, string> = {};
const SafeStorage = {
  get: (key: string) => {
    try { return localStorage.getItem(key); }
    catch { return _memStorage[key] || null; }
  },
  set: (key: string, val: string) => {
    try { localStorage.setItem(key, val); }
    catch { _memStorage[key] = val; }
  },
  remove: (key: string) => {
    try { localStorage.removeItem(key); }
    catch { delete _memStorage[key]; }
  }
};

/* ── token helpers ──────────────────────────────────────────────── */
let _accessToken = '';

export const Token = {
  getAccess:   ()    => _accessToken,
  setAccess:   (t: string) => { _accessToken = t; },
  clearAll:    ()    => {
    _accessToken = '';
    SafeStorage.remove('sg_auth_token');
  },
  isLoggedIn:  ()    => !!_accessToken,
};

/* ── auth headers ───────────────────────────────────────────────── */
export function authHeaders(): HeadersInit {
  const t = Token.getAccess();
  return {
    'Content-Type': 'application/json',
    ...(t ? { Authorization: `Bearer ${t}` } : {}),
  };
}

/* ── token refresh ──────────────────────────────────────────────── */
let _refreshing: Promise<boolean> | null = null;

export async function refreshAccessToken(): Promise<boolean> {
  if (_refreshing) return _refreshing; // deduplicate concurrent refresh calls
  _refreshing = (async () => {

    try {
      const res = await fetch(`${API_BASE}/api/auth/refresh`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include' // Send HttpOnly cookie
      });
      if (!res.ok) { Token.clearAll(); return false; }
      const { accessToken } = await res.json();
      Token.setAccess(accessToken);
      return true;
    } catch {
      Token.clearAll();
      return false;
    } finally {
      _refreshing = null;
    }
  })();
  return _refreshing;
}

/* ── generic fetch with auto-refresh ───────────────────────────── */
async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const finalInit = { ...init, credentials: 'include' as RequestCredentials, headers: { ...authHeaders(), ...(init.headers ?? {}) } };
  const res = await fetch(url, finalInit);
  if (res.status === 401) {
    const refreshed = await refreshAccessToken();
    if (!refreshed) { Token.clearAll(); window.location.reload(); throw new Error('Session expired'); }
    return fetch(url, { ...finalInit, headers: { ...authHeaders(), ...(init.headers ?? {}) } });
  }
  return res;
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await apiFetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json();
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await apiFetch(`${API_BASE}${path}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `POST ${path} → ${res.status}`);
  }
  return res.json();
}

export async function logout() {
  try {
    await fetch(`${API_BASE}/api/auth/logout`, {
      method: 'POST',
      credentials: 'include',
      headers: authHeaders()
    });
  } catch (e) {
    // Ignore errors on logout
  } finally {
    Token.clearAll();
    window.location.reload();
  }
}
