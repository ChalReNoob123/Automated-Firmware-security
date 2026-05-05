/**
 * Real-time Data Sync Service
 * Handles online/offline scenarios, conflict resolution, and client-side state management.
 * Uses a sync protocol over WebSocket with operation-based CRDT-lite conflict resolution.
 */

/**
 * SyncManager — manages bidirectional data sync between client and server.
 * Supports: offline queue, conflict resolution, delta sync, and reconnection.
 */
export class SyncManager {
  constructor(db, logger, broadcastFn) {
    this.db = db;
    this.logger = logger;
    this.broadcast = broadcastFn;
    this._ensureTables();
    this.conflictStrategy = 'last-write-wins'; // 'last-write-wins' | 'server-wins' | 'client-wins' | 'manual'
  }

  _ensureTables() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sync_changelog (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        operation TEXT NOT NULL,
        payload TEXT,
        version INTEGER NOT NULL DEFAULT 1,
        timestamp INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        client_id TEXT,
        user_id INTEGER,
        synced INTEGER DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_sync_entity ON sync_changelog(entity_type, entity_id);
      CREATE INDEX IF NOT EXISTS idx_sync_ts ON sync_changelog(timestamp);
      CREATE INDEX IF NOT EXISTS idx_sync_unsynced ON sync_changelog(synced) WHERE synced = 0;

      CREATE TABLE IF NOT EXISTS sync_clients (
        client_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        last_sync_ts INTEGER DEFAULT 0,
        device_info TEXT,
        registered_at INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
      );
    `);
  }

  /** Record a change to the changelog */
  recordChange(entityType, entityId, operation, payload, userId, clientId = null) {
    const existing = this.db.prepare(
      'SELECT MAX(version) as v FROM sync_changelog WHERE entity_type = ? AND entity_id = ?'
    ).get(entityType, entityId);

    const version = (existing?.v || 0) + 1;

    this.db.prepare(`
      INSERT INTO sync_changelog (entity_type, entity_id, operation, payload, version, timestamp, client_id, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(entityType, entityId, operation, JSON.stringify(payload), version, Date.now(), clientId, userId);

    // Broadcast to connected clients
    this.broadcast?.({
      event: 'sync_update',
      data: { entityType, entityId, operation, version, timestamp: Date.now() },
    });

    return version;
  }

  /** Get changes since a timestamp for delta sync */
  getChangesSince(sinceTs, userId = null, limit = 500) {
    let query = 'SELECT * FROM sync_changelog WHERE timestamp > ?';
    const params = [sinceTs];
    if (userId) { query += ' AND user_id = ?'; params.push(userId); }
    query += ' ORDER BY timestamp ASC LIMIT ?';
    params.push(limit);

    const changes = this.db.prepare(query).all(...params);
    return changes.map(c => ({
      ...c,
      payload: c.payload ? JSON.parse(c.payload) : null,
    }));
  }

  /** Resolve a conflict between client and server versions */
  resolveConflict(entityType, entityId, clientPayload, clientTimestamp, clientId) {
    const serverEntry = this.db.prepare(
      'SELECT * FROM sync_changelog WHERE entity_type = ? AND entity_id = ? ORDER BY version DESC LIMIT 1'
    ).get(entityType, entityId);

    if (!serverEntry) {
      // No server version — accept client
      return { resolution: 'accept_client', merged: clientPayload };
    }

    const serverPayload = serverEntry.payload ? JSON.parse(serverEntry.payload) : {};

    switch (this.conflictStrategy) {
      case 'last-write-wins':
        if (clientTimestamp > serverEntry.timestamp) {
          return { resolution: 'accept_client', merged: clientPayload };
        }
        return { resolution: 'accept_server', merged: serverPayload };

      case 'server-wins':
        return { resolution: 'accept_server', merged: serverPayload };

      case 'client-wins':
        return { resolution: 'accept_client', merged: clientPayload };

      case 'manual':
        // Return both for manual resolution
        return {
          resolution: 'conflict',
          serverVersion: serverPayload,
          clientVersion: clientPayload,
          serverTimestamp: serverEntry.timestamp,
          clientTimestamp,
        };

      default:
        return { resolution: 'accept_server', merged: serverPayload };
    }
  }

  /** Process a batch of client changes (sync upload) */
  processClientSync(clientId, userId, changes) {
    const results = [];

    for (const change of changes) {
      const conflict = this.resolveConflict(
        change.entityType, change.entityId,
        change.payload, change.timestamp, clientId
      );

      if (conflict.resolution === 'accept_client' || conflict.resolution === 'accept_server') {
        const finalPayload = conflict.merged;
        const version = this.recordChange(
          change.entityType, change.entityId, change.operation,
          finalPayload, userId, clientId
        );
        results.push({
          entityType: change.entityType,
          entityId: change.entityId,
          resolution: conflict.resolution,
          version,
          accepted: true,
        });
      } else {
        results.push({
          entityType: change.entityType,
          entityId: change.entityId,
          resolution: 'conflict',
          serverVersion: conflict.serverVersion,
          clientVersion: conflict.clientVersion,
          accepted: false,
        });
      }
    }

    // Update client sync timestamp
    this.db.prepare(`
      INSERT INTO sync_clients (client_id, user_id, last_sync_ts, registered_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(client_id) DO UPDATE SET last_sync_ts = excluded.last_sync_ts
    `).run(clientId, userId, Date.now(), Date.now());

    return results;
  }

  /** Get sync status for a client */
  getClientSyncStatus(clientId) {
    const client = this.db.prepare('SELECT * FROM sync_clients WHERE client_id = ?').get(clientId);
    if (!client) return { registered: false, pendingChanges: 0 };

    const pending = this.db.prepare(
      'SELECT COUNT(*) as c FROM sync_changelog WHERE timestamp > ? AND client_id != ?'
    ).get(client.last_sync_ts, clientId);

    return {
      registered: true,
      lastSync: client.last_sync_ts,
      pendingChanges: pending.c,
      deviceInfo: client.device_info ? JSON.parse(client.device_info) : null,
    };
  }
}

/**
 * Client-side offline queue (for use in frontend service worker or React context).
 * Exported as a class for the frontend to use with IndexedDB.
 */
export const OfflineQueueScript = `
class OfflineQueue {
  constructor(dbName = 'sentinelgrid-sync') {
    this.dbName = dbName;
    this.db = null;
  }
  async init() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, 1);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('pending')) {
          db.createObjectStore('pending', { keyPath: 'id', autoIncrement: true });
        }
      };
      req.onsuccess = (e) => { this.db = e.target.result; resolve(); };
      req.onerror = () => reject(req.error);
    });
  }
  async enqueue(change) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('pending', 'readwrite');
      tx.objectStore('pending').add({ ...change, queuedAt: Date.now() });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
  async flush() {
    const items = await new Promise((resolve, reject) => {
      const tx = this.db.transaction('pending', 'readonly');
      const req = tx.objectStore('pending').getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (items.length === 0) return [];
    // Send to server in batch
    const res = await fetch('/api/sync/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + localStorage.getItem('sg_auth_token') },
      body: JSON.stringify({ changes: items }),
    });
    if (res.ok) {
      // Clear queue on success
      const tx = this.db.transaction('pending', 'readwrite');
      tx.objectStore('pending').clear();
      return await res.json();
    }
    throw new Error('Sync failed: ' + res.status);
  }
}
`;
