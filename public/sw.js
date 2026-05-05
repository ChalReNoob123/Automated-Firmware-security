/**
 * SentinelGrid — Service Worker for PWA offline support.
 * Implements: cache-first for static assets, network-first for API calls,
 * offline fallback page, and background sync for queued operations.
 */

const CACHE_NAME = 'sentinelgrid-v1';
const STATIC_CACHE = 'sentinelgrid-static-v1';
const API_CACHE = 'sentinelgrid-api-v1';

const STATIC_ASSETS = [
  '/',
  '/index.html',
];

const API_CACHE_ROUTES = [
  '/api/system/stats',
  '/api/scanner/targets',
  '/api/scanner/sessions',
];

// ── Install: cache static assets ──
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then(cache => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: clean old caches ──
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== STATIC_CACHE && k !== API_CACHE && k !== CACHE_NAME)
          .map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ── Fetch: strategy-based caching ──
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') return;

  // API routes: network-first with cache fallback
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirstWithCache(request));
    return;
  }

  // Static assets: cache-first
  event.respondWith(cacheFirstWithNetwork(request));
});

async function networkFirstWithCache(request) {
  const url = new URL(request.url);
  const isCacheable = API_CACHE_ROUTES.some(r => url.pathname.startsWith(r));

  try {
    const response = await fetch(request);
    if (response.ok && isCacheable) {
      const cache = await caches.open(API_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    // Offline — try cache
    const cached = await caches.match(request);
    if (cached) return cached;

    // Return offline JSON for API requests
    return new Response(
      JSON.stringify({ offline: true, error: 'You are offline. Showing cached data.' }),
      { headers: { 'Content-Type': 'application/json' }, status: 503 }
    );
  }
}

async function cacheFirstWithNetwork(request) {
  const cached = await caches.match(request);
  if (cached) return cached;

  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    // Return offline fallback for navigation
    if (request.mode === 'navigate') {
      const offlineHTML = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SentinelGrid — Offline</title>
<style>body{background:#0b1120;color:#e2e8f0;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.c{text-align:center;padding:2rem}.icon{font-size:4rem;margin-bottom:1rem}h1{font-size:1.5rem;margin:.5rem 0}p{color:#94a3b8;max-width:400px}
button{margin-top:1.5rem;background:#6366f1;color:#fff;border:none;padding:.75rem 2rem;border-radius:.75rem;font-weight:700;cursor:pointer}</style></head>
<body><div class="c"><div class="icon">🛡️</div><h1>SentinelGrid Offline</h1><p>You are currently offline. The dashboard will reconnect automatically when your network is restored.</p>
<button onclick="location.reload()">Try Again</button></div></body></html>`;
      return new Response(offlineHTML, { headers: { 'Content-Type': 'text/html' } });
    }
    return new Response('', { status: 408 });
  }
}

// ── Background Sync for queued operations ──
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-pending-operations') {
    event.waitUntil(syncPendingOperations());
  }
});

async function syncPendingOperations() {
  // Open IndexedDB and flush pending queue
  const db = await openDB('sentinelgrid-sync', 1);
  const tx = db.transaction('pending', 'readonly');
  const store = tx.objectStore('pending');
  const items = await getAllFromStore(store);

  if (items.length === 0) return;

  try {
    const res = await fetch('/api/sync/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ changes: items }),
    });

    if (res.ok) {
      const clearTx = db.transaction('pending', 'readwrite');
      clearTx.objectStore('pending').clear();
    }
  } catch {
    // Will retry on next sync event
  }
}

function openDB(name, version) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name, version);
    req.onupgradeneeded = (e) => {
      if (!e.target.result.objectStoreNames.contains('pending')) {
        e.target.result.createObjectStore('pending', { keyPath: 'id', autoIncrement: true });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function getAllFromStore(store) {
  return new Promise((resolve, reject) => {
    const req = store.getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// ── Push Notifications ──
self.addEventListener('push', (event) => {
  const data = event.data?.json() || { title: 'SentinelGrid Alert', body: 'New security event detected' };
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/favicon.ico',
      badge: '/favicon.ico',
      tag: data.tag || 'security-alert',
      data: data.url ? { url: data.url } : undefined,
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.openWindow(event.notification.data?.url || '/')
  );
});
