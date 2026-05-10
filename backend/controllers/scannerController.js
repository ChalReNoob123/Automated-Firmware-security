import db from '../config/db.js';
import logger from '../utils/logger.js';
import * as scannerEngine from '../../scanner/engine.js';
import * as exporters from '../../scanner/exporters.js';

export const getTargets = (req, res) => {
  try {
    const targets = scannerEngine.getAvailableTargets();
    res.json({ targets });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch targets' });
  }
};

export const getStatus = (req, res) => {
  try {
    const status = scannerEngine.getScanStatus();
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch status' });
  }
};

export const startScan = (req, res) => {
  try {
    const { targets, options } = req.body;
    scannerEngine.startScan(targets, options);
    res.json({ success: true, message: 'Scan started' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

export const stopScan = (req, res) => {
  try {
    scannerEngine.stopScan();
    res.json({ success: true, message: 'Scan stopped' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

export const getSessions = (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const offset = parseInt(req.query.offset) || 0;
    const status = req.query.status;
    
    let query = 'SELECT * FROM scan_sessions WHERE 1=1';
    const params = [];
    if (status && status !== 'all') { query += ' AND status = ?'; params.push(status); }
    query += ' ORDER BY start_time DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);
    
    const sessions = db.prepare(query).all(...params);
    res.json({ sessions: sessions.map(s => ({ ...s, summary: s.summary ? JSON.parse(s.summary) : null })) });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
};

export const getSessionDetails = (req, res) => {
  try {
    const { id } = req.params;
    const session = db.prepare('SELECT * FROM scan_sessions WHERE id = ?').get(id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ ...session, summary: session.summary ? JSON.parse(session.summary) : null });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch session' });
  }
};

export const getSessionFindings = (req, res) => {
  try {
    const { id } = req.params;
    const { status, sort } = req.query;
    
    let query = 'SELECT * FROM scan_findings WHERE session_id = ?';
    const params = [id];
    if (status && status !== 'all') { query += ' AND status = ?'; params.push(status); }
    query += sort === 'name' ? ' ORDER BY file_name ASC' : ' ORDER BY risk_score DESC';
    query += ' LIMIT 500';
    
    const findings = db.prepare(query).all(...params);
    res.json({ 
      findings: findings.map(f => ({ 
        ...f, 
        risk_factors: JSON.parse(f.risk_factors || '[]'), 
        mitre_techniques: JSON.parse(f.mitre_techniques || '[]'), 
        ads_streams: JSON.parse(f.ads_streams || '[]') 
      })) 
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch findings' });
  }
};

export const exportFindings = (req, res) => {
  try {
    const { sessionId, format } = req.params;
    const session = db.prepare('SELECT * FROM scan_sessions WHERE id = ?').get(sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    const findings = db.prepare('SELECT * FROM scan_findings WHERE session_id = ? ORDER BY risk_score DESC').all(sessionId);
    const exporterMap = { 
      json: exporters.exportJSON, 
      csv: exporters.exportCSV, 
      stix: exporters.exportSTIX, 
      splunk: exporters.exportSplunkCIM, 
      html: exporters.exportHTML 
    };
    
    const exporter = exporterMap[format];
    if (!exporter) return res.status(400).json({ error: 'Unsupported format. Use: json, csv, stix, splunk, html' });
    
    const content = format === 'csv' ? exporter(findings) : exporter(session, findings);
    const types = { 
      json: 'application/json', 
      csv: 'text/csv', 
      stix: 'application/json', 
      splunk: 'application/x-ndjson', 
      html: 'text/html' 
    };
    
    res.setHeader('Content-Type', types[format]);
    res.setHeader('Content-Disposition', `attachment; filename="scan-${sessionId}.${format === 'html' ? 'html' : format === 'splunk' ? 'ndjson' : format}"`);
    res.send(content);
  } catch (err) {
    res.status(500).json({ error: 'Export failed' });
  }
};
