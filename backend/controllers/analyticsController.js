import db from '../config/db.js';
import logger from '../utils/logger.js';
import * as analyticsEngine from '../../services/analyticsEngine.js'; // Using existing root service

export const getGlobal = (req, res) => {
  try {
    const data = analyticsEngine.getGlobalAnalytics();
    res.json(data);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch global analytics' });
  }
};

export const getSegments = (req, res) => {
  try {
    const data = analyticsEngine.getSegmentAnalytics();
    res.json(data);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch segment analytics' });
  }
};

export const getSegmentDetails = (req, res) => {
  try {
    const { id } = req.params;
    const segments = analyticsEngine.getSegmentAnalytics();
    const segment = segments.find(s => s.id === id);
    if (!segment) return res.status(404).json({ error: 'Segment not found' });
    res.json(segment);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch segment details' });
  }
};

export const getSegmentTimeseries = (req, res) => {
  try {
    const { id } = req.params;
    const { metric, period } = req.query;
    const timeseries = analyticsEngine.getTimeseries(id, metric || 'riskScore', period || '24h');
    res.json({ timeseries });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch timeseries' });
  }
};

export const getSegmentComparison = (req, res) => {
  try {
    const { id } = req.params;
    const { target } = req.query;
    const comparison = analyticsEngine.compareSegments(id, target);
    res.json(comparison);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch comparison' });
  }
};

export const getAlerts = (req, res) => {
  try {
    const { segment, severity, unacked } = req.query;
    let query = 'SELECT * FROM segment_alerts WHERE 1=1';
    const params = [];
    if (segment && segment !== 'all') { query += ' AND segment = ?'; params.push(segment); }
    if (severity && severity !== 'all') { query += ' AND severity = ?'; params.push(severity); }
    if (unacked === 'true') { query += ' AND acknowledged = 0'; }
    query += ' ORDER BY created_at DESC LIMIT 100';
    
    const alerts = db.prepare(query).all(...params);
    res.json({ alerts: alerts.map(a => ({ ...a, context: JSON.parse(a.context || '{}') })) });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
};

export const ackAlert = (req, res) => {
  try {
    const { id } = req.params;
    const result = db.prepare('UPDATE segment_alerts SET acknowledged = 1, acked_by = ?, acked_at = ? WHERE id = ?')
                     .run(req.user.username, new Date().toISOString(), id);
    if (result.changes === 0) return res.status(404).json({ error: 'Alert not found' });
    res.json({ success: true });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to ack alert' });
  }
};

export const getThresholds = (req, res) => {
  try {
    res.json(analyticsEngine.getThresholds());
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch thresholds' });
  }
};

export const updateThresholds = (req, res) => {
  try {
    const { segment, thresholds } = req.body;
    analyticsEngine.updateThresholds(segment, thresholds);
    res.json({ success: true });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to update thresholds' });
  }
};

export const engageMitigation = (req, res) => {
  try {
    const { action, target, context } = req.body;
    const result = analyticsEngine.engageMitigation(action, target, context, req.user.username);
    res.json(result);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Mitigation failed' });
  }
};

export const getSnapshot = (req, res) => {
  try {
    const { id } = req.params;
    const snapshot = db.prepare('SELECT * FROM state_snapshots WHERE id = ?').get(id);
    if (!snapshot) return res.status(404).json({ error: 'Snapshot not found' });
    res.json({ ...snapshot, state_data: JSON.parse(snapshot.state_data) });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch snapshot' });
  }
};

export const getBenchmarks = (req, res) => {
  try {
    res.json(analyticsEngine.getBenchmarks());
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch benchmarks' });
  }
};
