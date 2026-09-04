import logger from '../utils/logger.js';
import db from '../config/db.js';
import { SyncManager } from '../../services/syncService.js';

// Instantiate the SyncManager
const syncManager = new SyncManager(db, logger);

export const getChanges = (req, res) => {
  try {
    const since = parseInt(req.query.since || '0');
    const changes = syncManager.getChangesSince(since, req.user.sub);
    res.json({ changes });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch changes' });
  }
};

export const uploadChanges = (req, res) => {
  try {
    const clientId = req.headers['x-client-id'] || 'web-' + req.user.sub;
    const results = syncManager.processClientSync(clientId, req.user.sub, req.body.changes || []);
    res.json({ results });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to upload changes' });
  }
};

export const getStatus = (req, res) => {
  try {
    const clientId = req.query.clientId || 'web-' + req.user.sub;
    res.json(syncManager.getClientSyncStatus(clientId));
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch status' });
  }
};
