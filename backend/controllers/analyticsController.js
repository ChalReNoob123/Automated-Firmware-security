import db from '../config/db.js';
import logger from '../utils/logger.js';
import { AnalyticsEngine, BENCHMARKS } from '../../services/analyticsEngine.js';

const engine = new AnalyticsEngine(db, logger);

export const getGlobal = (req, res) => {
  try {
    const data = engine.getGlobalKPIs();
    res.json(data);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch global analytics' });
  }
};

export const getSegments = (req, res) => {
  try {
    const segments = engine.getSegmentRanking();
    res.json({ segments });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch segment analytics' });
  }
};

export const getSegmentDetails = (req, res) => {
  try {
    const { id } = req.params;
    const segments = engine.getSegmentRanking();
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
    // const { metric, period } = req.query; // Ignored for simplicity right now
    const timeseries = engine.getSegmentTimeSeries(id);
    res.json({ timeseries });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch timeseries' });
  }
};

export const getSegmentComparison = (req, res) => {
  try {
    const { id } = req.params;
    const comparison = engine.getHistoricalComparison(id);
    res.json(comparison);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch comparison' });
  }
};

export const getAlerts = (req, res) => {
  try {
    const { segment, severity, unacked } = req.query;
    let query = 'SELECT * FROM analytics_alerts WHERE 1=1';
    const params = [];
    if (segment && segment !== 'all') { query += ' AND segment = ?'; params.push(segment); }
    if (severity && severity !== 'all') { query += ' AND severity = ?'; params.push(severity); }
    if (unacked === 'true') { query += ' AND acknowledged = 0'; }
    query += ' ORDER BY ts DESC LIMIT 100';
    
    const alerts = db.prepare(query).all(...params);
    // analytics_alerts table uses ts and message, map them or return directly.
    res.json({ alerts });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
};

export const ackAlert = (req, res) => {
  try {
    const { id } = req.params;
    const result = engine.acknowledgeAlert(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Alert not found' });
    res.json({ success: true });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to ack alert' });
  }
};

export const getThresholds = (req, res) => {
  try {
    res.json(engine.getThresholds());
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch thresholds' });
  }
};

export const updateThresholds = (req, res) => {
  try {
    const { segment, thresholds } = req.body;
    // Assuming thresholds is an object { metric: { warning: X, critical: Y, direction: Z } }
    if (thresholds && typeof thresholds === 'object') {
      for (const [metric, vals] of Object.entries(thresholds)) {
        engine.updateThreshold(segment, metric, vals.warning, vals.critical, vals.direction || 'above');
      }
    }
    res.json({ success: true });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to update thresholds' });
  }
};

export const engageMitigation = (req, res) => {
  try {
    const { action, target, context } = req.body;
    // Mocking mitigation response for analytics since engine doesn't have it
    logger.info({ action, target, user: req.user.username }, 'Engaged mitigation');
    res.json({ success: true, message: 'Mitigation engaged successfully' });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Mitigation failed' });
  }
};

export const getSnapshot = (req, res) => {
  try {
    const { id } = req.params;
    const snapshot = db.prepare('SELECT * FROM segment_kpi_snapshots WHERE id = ?').get(id);
    if (!snapshot) return res.status(404).json({ error: 'Snapshot not found' });
    res.json(snapshot);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch snapshot' });
  }
};

export const getBenchmarks = (req, res) => {
  try {
    res.json(BENCHMARKS);
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch benchmarks' });
  }
};
