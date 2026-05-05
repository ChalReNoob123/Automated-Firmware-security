/**
 * Scanner Module Entry Point
 * Sets up DB tables, API routes, and returns the scanner engine.
 * Called from backend.js: setupScanner({ db, logger, app, broadcastFn, verifyAuth })
 */
import { ScannerEngine } from './engine.js';
import { exportJSON, exportCSV, exportSTIX, exportSplunkCIM, exportHTML } from './exporters.js';

export function setupScanner({ db, logger, app, broadcastFn, verifyAuth }) {
  // ── DB Tables ──
  db.exec(`
    CREATE TABLE IF NOT EXISTS scan_sessions (
      id TEXT PRIMARY KEY,
      started_at INTEGER NOT NULL,
      completed_at INTEGER,
      status TEXT DEFAULT 'running',
      config TEXT,
      total_files INTEGER DEFAULT 0,
      scanned_files INTEGER DEFAULT 0,
      findings INTEGER DEFAULT 0,
      risk_score REAL DEFAULT 0,
      summary TEXT
    );
    CREATE TABLE IF NOT EXISTS scan_findings (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      file_path TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_size INTEGER,
      file_modified INTEGER,
      sha256 TEXT,
      entropy REAL,
      is_signed INTEGER DEFAULT 0,
      signature_status TEXT,
      signer TEXT,
      has_ads INTEGER DEFAULT 0,
      ads_streams TEXT,
      risk_score REAL DEFAULT 0,
      risk_factors TEXT,
      mitre_techniques TEXT,
      directory_category TEXT,
      directory_criticality TEXT,
      target_label TEXT,
      status TEXT DEFAULT 'clean',
      created_at INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_findings_session ON scan_findings(session_id);
    CREATE INDEX IF NOT EXISTS idx_findings_risk ON scan_findings(risk_score DESC);
    CREATE INDEX IF NOT EXISTS idx_findings_status ON scan_findings(status);
  `);

  const engine = new ScannerEngine(db, logger, broadcastFn);

  // ── Middleware: auth check ──
  const auth = (req, res, next) => {
    try {
      verifyAuth(req);
      next();
    } catch {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
    }
  };

  // ── API Routes ──

  // GET /api/scanner/targets — list available scan targets
  app.get('/api/scanner/targets', auth, (req, res) => {
    res.json({ targets: engine.getTargets() });
  });

  // GET /api/scanner/status — current scan status
  app.get('/api/scanner/status', auth, (req, res) => {
    res.json(engine.getStatus());
  });

  // POST /api/scanner/start — start a new scan
  app.post('/api/scanner/start', auth, async (req, res) => {
    try {
      const config = req.body || {};
      // Run scan async — respond immediately with session ID
      const sessionId = crypto.randomUUID();
      res.json({ sessionId, status: 'starting' });
      // Start scan in background (don't await in request handler)
      engine.startScan({ ...config }).catch(err => logger.error(err, 'Background scan error'));
    } catch (err) {
      res.status(409).json({ error: err.message });
    }
  });

  // POST /api/scanner/stop — stop active scan
  app.post('/api/scanner/stop', auth, (req, res) => {
    const stopped = engine.stopScan();
    res.json({ stopped });
  });

  // GET /api/scanner/sessions — list all scan sessions
  app.get('/api/scanner/sessions', auth, (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const sessions = db.prepare('SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?').all(limit);
    res.json({ sessions: sessions.map(s => ({ ...s, summary: s.summary ? JSON.parse(s.summary) : null, config: s.config ? JSON.parse(s.config) : null })) });
  });

  // GET /api/scanner/sessions/:id — get session details
  app.get('/api/scanner/sessions/:id', auth, (req, res) => {
    const session = db.prepare('SELECT * FROM scan_sessions WHERE id = ?').get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json({ ...session, summary: session.summary ? JSON.parse(session.summary) : null, config: session.config ? JSON.parse(session.config) : null });
  });

  // GET /api/scanner/sessions/:id/findings — get findings for a session
  app.get('/api/scanner/sessions/:id/findings', auth, (req, res) => {
    const { status, minRisk, sort } = req.query;
    let query = 'SELECT * FROM scan_findings WHERE session_id = ?';
    const params = [req.params.id];
    if (status && status !== 'all') { query += ' AND status = ?'; params.push(status); }
    if (minRisk) { query += ' AND risk_score >= ?'; params.push(parseFloat(minRisk)); }
    query += sort === 'name' ? ' ORDER BY file_name ASC' : ' ORDER BY risk_score DESC';
    query += ' LIMIT 500';
    const findings = db.prepare(query).all(...params);
    res.json({
      findings: findings.map(f => ({
        ...f,
        risk_factors: JSON.parse(f.risk_factors || '[]'),
        mitre_techniques: JSON.parse(f.mitre_techniques || '[]'),
        ads_streams: JSON.parse(f.ads_streams || '[]'),
      })),
    });
  });

  // GET /api/scanner/export/:id/:format — export scan results
  app.get('/api/scanner/export/:id/:format', auth, (req, res) => {
    const session = db.prepare('SELECT * FROM scan_sessions WHERE id = ?').get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    const findings = db.prepare('SELECT * FROM scan_findings WHERE session_id = ? ORDER BY risk_score DESC').all(req.params.id);

    switch (req.params.format) {
      case 'json':
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="scan-${req.params.id}.json"`);
        return res.end(exportJSON(session, findings));
      case 'csv':
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="scan-${req.params.id}.csv"`);
        return res.end(exportCSV(findings));
      case 'stix':
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="scan-${req.params.id}-stix.json"`);
        return res.end(exportSTIX(session, findings));
      case 'splunk':
        res.setHeader('Content-Type', 'application/x-ndjson');
        res.setHeader('Content-Disposition', `attachment; filename="scan-${req.params.id}-splunk.ndjson"`);
        return res.end(exportSplunkCIM(session, findings));
      case 'html':
        res.setHeader('Content-Type', 'text/html');
        res.setHeader('Content-Disposition', `attachment; filename="scan-${req.params.id}-report.html"`);
        return res.end(exportHTML(session, findings));
      default:
        return res.status(400).json({ error: 'Unsupported format. Use: json, csv, stix, splunk, html' });
    }
  });

  logger.info('Scanner module initialized with API routes');
  return engine;
}
