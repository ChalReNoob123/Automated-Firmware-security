import logger from '../utils/logger.js';
import db from '../config/db.js';
import { SecurityAuditLogger, DDoSProtection } from '../../services/securityMiddleware.js';

const auditLogger = new SecurityAuditLogger(db, logger);
const ddosProtection = new DDoSProtection(db, logger);

export const getAuditLogs = (req, res) => {
  try {
    const { type, severity, since, limit } = req.query;
    const logs = auditLogger.query({ 
      eventType: type, 
      severity, 
      since: since ? parseInt(since) : null, 
      limit: parseInt(limit || '100') 
    });
    res.json({ logs });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
};

export const getDdosStats = (req, res) => {
  try {
    res.json(ddosProtection.getStats());
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to fetch DDoS stats' });
  }
};
