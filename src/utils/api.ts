/**
 * SentinelGrid API Utility — Production-Hardened
 * All API calls go through here so the base URL is never hardcoded.
 * Gap #24 fix: API URL driven by VITE_API_URL environment variable.
 */

export const API_BASE = (import.meta.env.VITE_API_URL || 'http://localhost:3001').replace(/\/$/, '');
export const WS_BASE  = (import.meta.env.VITE_WS_URL  || 'ws://localhost:3001').replace(/\/$/, '');

/* ── storage fallback for Safari Private / IE ───────────────────── */
type ApiCacheEntry<T = unknown> = {
  value: T;
  expiresAt: number;
};

const API_GET_CACHE_MS = Number(import.meta.env.VITE_API_GET_CACHE_MS || 2000);
const _apiGetCache = new Map<string, ApiCacheEntry>();

export function clearApiCache() {
  _apiGetCache.clear();
}

function getApiCacheKey(path: string) {
  return `${API_BASE}${path}`;
}

function clearLegacyStoredToken() {
  try {
    localStorage.removeItem('sg_auth_token');
  } catch {
    // Restricted browser modes can deny storage access.
  }
}

/* ── token helpers ──────────────────────────────────────────────── */
let _accessToken = '';
let _user: User | null = null;

export type User = {
  id: number;
  username: string;
  email: string;
  role: string;
  lastLogin?: string;
  createdAt?: string;
};

export const Token = {
  getAccess:   ()    => _accessToken,
  getUser:     ()    => _user,
  setAccess:   (t: string) => { 
    _accessToken = t;
    clearLegacyStoredToken();
  },
  setUser:     (u: User | null) => { _user = u; },
  clearAll:    ()    => {
    _accessToken = '';
    _user = null;
    clearLegacyStoredToken();
    clearApiCache();
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

export async function fetchMe(): Promise<User | null> {
  try {
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers: authHeaders()
    });
    if (!res.ok) return null;
    const data = await res.json();
    Token.setUser(data.user);
    return data.user;
  } catch {
    return null;
  }
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
      
      // Also fetch user info after refresh
      await fetchMe();
      
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

async function apiFetch(url: string, init: RequestInit = {}, retries = 2): Promise<Response> {
  const finalInit = { ...init, credentials: 'include' as RequestCredentials, headers: { ...authHeaders(), ...(init.headers ?? {}) } };
  
  try {
    const res = await fetch(url, finalInit);
    if (res.status === 401) {
      const refreshed = await refreshAccessToken();
      if (!refreshed) { Token.clearAll(); window.location.reload(); throw new Error('Session expired'); }
      return fetch(url, { ...finalInit, headers: { ...authHeaders(), ...(init.headers ?? {}) } });
    }
    return res;
  } catch (err) {
    if (retries > 0 && err instanceof TypeError) {
      // TypeError usually indicates network failure
      await new Promise(r => setTimeout(r, 1000 * (3 - retries)));
      return apiFetch(url, init, retries - 1);
    }
    throw err;
  }
}

export async function apiGet<T>(path: string, options: { cacheMs?: number; force?: boolean } = {}): Promise<T> {
  const ttl = options.cacheMs ?? API_GET_CACHE_MS;
  const cacheKey = getApiCacheKey(path);
  if (!options.force && ttl > 0) {
    const cached = _apiGetCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) return cached.value as T;
    if (cached) _apiGetCache.delete(cacheKey);
  }

  const res = await apiFetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  const data = await res.json();
  if (ttl > 0) {
    _apiGetCache.set(cacheKey, { value: data, expiresAt: Date.now() + ttl });
  }
  return data;
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
  clearApiCache();
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
    clearApiCache();
    window.location.reload();
  }
}
