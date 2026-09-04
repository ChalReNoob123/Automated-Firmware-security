import * as telemetryService from '../services/telemetryService.js';
import * as aiService from '../services/aiService.js';
import logger from '../utils/logger.js';
import os from 'os';

export const getSystemInfo = async (req, res) => {
  try {
    const info = await telemetryService.getSystemTelemetry();
    res.json(info);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch system info' });
  }
};

export const getStats = async (req, res) => {
  try {
    const stats = await telemetryService.getStats();
    res.json(stats);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
};

export const getAnalyze = async (req, res) => {
  try {
    const snapshot = await telemetryService.collectSnapshot();
    res.json(snapshot);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Analysis failed' });
  }
};

export const getLiveLogs = async (req, res) => {
  const { channel, max } = req.query;
  try {
    const logs = await telemetryService.getWindowsLogs(parseInt(max) || 100);
    res.json({ logs, computer: os.hostname() });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch live logs' });
  }
};

export const getDatabaseLogs = async (req, res) => {
  try {
    const databaseLogs = telemetryService.getHistoricalLogs();
    res.json({ databaseLogs });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch database logs' });
  }
};

export const getInsights = async (req, res) => {
  try {
    const insights = await aiService.getAnalyticalInsights();
    res.json(insights);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch insights' });
  }
};

export const getSystemPermissions = (req, res) => {
  const ROLE_PERMISSIONS = {
    admin: ['read:all', 'write:all', 'exec:kill', 'manage:users'],
    analyst: ['read:all', 'write:logs'],
    viewer: ['read:telemetry']
  };
  
  res.json({
    role: req.user.role,
    permissions: ROLE_PERMISSIONS[req.user.role] || []
  });
};

export const getPlugins = (req, res) => {
  import('../services/pluginService.js').then(({ getActivePlugins }) => {
    res.json(getActivePlugins());
  }).catch(err => {
    res.status(500).json({ error: 'Failed to fetch plugins' });
  });
};

export const getSystemMigrations = (req, res) => {
  try {
    import('../config/db.js').then(({ default: db }) => {
      const migrations = db.prepare('SELECT * FROM _migrations ORDER BY applied_at DESC').all();
      res.json(migrations);
    }).catch(e => res.json([]));
  } catch (err) {
    res.json([]);
  }
};
