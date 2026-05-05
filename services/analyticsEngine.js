/**
 * SentinelGrid Global Analytics Engine
 * ─────────────────────────────────────
 * Provides comprehensive KPI tracking, segment-level performance analysis,
 * benchmarking, alerting, historical comparison, and real-time aggregation.
 *
 * Segments tracked: dashboard | mitre | nist | virustotal | winlogs |
 *   intel | sandbox | vulnpentest | crossplat | advancedvb | ai_agent |
 *   ossec | scanner | auth | api
 */

import crypto from 'crypto';

// ── Benchmark baselines (industry standards) ──────────────────────────
export const BENCHMARKS = {
  api_response_ms:    { target: 200,  warning: 500,  critical: 1000, unit: 'ms',   label: 'API Response Time' },
  error_rate_pct:     { target: 1,    warning: 5,    critical: 10,   unit: '%',    label: 'Error Rate' },
  availability_pct:   { target: 99.9, warning: 99,   critical: 95,   unit: '%',    label: 'Availability' },
  threat_detect_ms:   { target: 5000, warning: 15000, critical: 30000, unit: 'ms', label: 'Threat Detection Latency' },
  scan_throughput:    { target: 100,  warning: 50,   critical: 10,   unit: 'f/s',  label: 'Scanner Throughput' },
  auth_success_pct:   { target: 95,   warning: 85,   critical: 70,   unit: '%',    label: 'Auth Success Rate' },
  log_ingest_per_min: { target: 500,  warning: 100,  critical: 10,   unit: '/min', label: 'Log Ingestion Rate' },
  ws_latency_ms:      { target: 50,   warning: 200,  critical: 500,  unit: 'ms',   label: 'WebSocket Latency' },
};

// ── Segment display definitions ───────────────────────────────────────
export const SEGMENT_DEFS = [
  { id: 'api',         label: 'API Gateway',       icon: '⚡', category: 'infrastructure' },
  { id: 'auth',        label: 'Authentication',    icon: '🔐', category: 'security' },
  { id: 'dashboard',   label: 'Dashboard',         icon: '📊', category: 'frontend' },
  { id: 'scanner',     label: 'System Scanner',    icon: '🔍', category: 'security' },
  { id: 'ai_agent',    label: 'AI Agent',          icon: '🤖', category: 'intelligence' },
  { id: 'winlogs',     label: 'Windows Logs',      icon: '🪟', category: 'telemetry' },
  { id: 'mitre',       label: 'MITRE ATT&CK',      icon: '🎯', category: 'intelligence' },
  { id: 'virustotal',  label: 'VirusTotal',        icon: '🦠', category: 'intelligence' },
  { id: 'intel',       label: 'Threat Intel',      icon: '🕵️', category: 'intelligence' },
  { id: 'sandbox',     label: 'Malware Sandbox',   icon: '📦', category: 'security' },
  { id: 'vulnpentest', label: 'Vuln/Pentest',      icon: '🔓', category: 'security' },
  { id: 'crossplat',   label: 'Cross-Platform FIM',icon: '🔄', category: 'telemetry' },
  { id: 'ossec',       label: 'OS Security',       icon: '🛡️', category: 'security' },
  { id: 'nist',        label: 'NIST Compliance',   icon: '📋', category: 'compliance' },
];

export class AnalyticsEngine {
  constructor(db, logger) {
    this.db = db;
    this.logger = logger;
    this._initTables();
    this._initStatements();
    this._startAggregationLoop();
  }

  // ── Schema ────────────────────────────────────────────────────────
  _initTables() {
    this.db.exec(`
      -- Per-request telemetry: every API call
      CREATE TABLE IF NOT EXISTS api_request_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        segment TEXT NOT NULL DEFAULT 'api',
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        status_code INTEGER,
        duration_ms INTEGER,
        user_id INTEGER,
        client_ip TEXT,
        error TEXT,
        bytes_sent INTEGER DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_api_ts ON api_request_log(ts DESC);
      CREATE INDEX IF NOT EXISTS idx_api_seg ON api_request_log(segment, ts DESC);
      CREATE INDEX IF NOT EXISTS idx_api_status ON api_request_log(status_code, ts DESC);

      -- Per-segment KPI snapshots (aggregated every 60s)
      CREATE TABLE IF NOT EXISTS segment_kpi_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        segment TEXT NOT NULL,
        period TEXT NOT NULL DEFAULT '1m',
        requests INTEGER DEFAULT 0,
        errors INTEGER DEFAULT 0,
        avg_duration_ms REAL DEFAULT 0,
        p95_duration_ms REAL DEFAULT 0,
        p99_duration_ms REAL DEFAULT 0,
        error_rate_pct REAL DEFAULT 0,
        availability_pct REAL DEFAULT 100,
        unique_users INTEGER DEFAULT 0,
        bytes_transferred INTEGER DEFAULT 0,
        threat_events INTEGER DEFAULT 0,
        alert_count INTEGER DEFAULT 0,
        UNIQUE(ts, segment, period)
      );
      CREATE INDEX IF NOT EXISTS idx_kpi_ts ON segment_kpi_snapshots(ts DESC);
      CREATE INDEX IF NOT EXISTS idx_kpi_seg ON segment_kpi_snapshots(segment, ts DESC);

      -- User engagement events (page views, feature interactions)
      CREATE TABLE IF NOT EXISTS engagement_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        segment TEXT NOT NULL,
        event_type TEXT NOT NULL,
        user_id INTEGER,
        session_id TEXT,
        duration_ms INTEGER,
        metadata TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_engage_ts ON engagement_events(ts DESC);
      CREATE INDEX IF NOT EXISTS idx_engage_seg ON engagement_events(segment, ts DESC);

      -- Performance benchmarks and alert thresholds (configurable)
      CREATE TABLE IF NOT EXISTS perf_thresholds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        segment TEXT NOT NULL,
        metric TEXT NOT NULL,
        warning_value REAL,
        critical_value REAL,
        direction TEXT DEFAULT 'above',
        enabled INTEGER DEFAULT 1,
        updated_at INTEGER DEFAULT (unixepoch() * 1000),
        UNIQUE(segment, metric)
      );

      -- Analytics alerts (threshold breaches)
      CREATE TABLE IF NOT EXISTS analytics_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
        segment TEXT NOT NULL,
        metric TEXT NOT NULL,
        value REAL NOT NULL,
        threshold REAL NOT NULL,
        severity TEXT NOT NULL,
        message TEXT,
        acknowledged INTEGER DEFAULT 0,
        resolved_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_aalerts_ts ON analytics_alerts(ts DESC);
      CREATE INDEX IF NOT EXISTS idx_aalerts_seg ON analytics_alerts(segment, ts DESC);
      CREATE INDEX IF NOT EXISTS idx_aalerts_ack ON analytics_alerts(acknowledged, ts DESC);
    `);

    // Seed default thresholds for all segments
    const segments = SEGMENT_DEFS.map(s => s.id);
    const insertThreshold = this.db.prepare(`
      INSERT OR IGNORE INTO perf_thresholds (segment, metric, warning_value, critical_value, direction)
      VALUES (?, ?, ?, ?, ?)
    `);
    for (const seg of segments) {
      insertThreshold.run(seg, 'avg_duration_ms',  500,  1000, 'above');
      insertThreshold.run(seg, 'error_rate_pct',   5,    10,   'above');
      insertThreshold.run(seg, 'availability_pct', 99,   95,   'below');
    }
  }

  _initStatements() {
    this._insertRequest = this.db.prepare(`
      INSERT INTO api_request_log (ts, segment, method, path, status_code, duration_ms, user_id, client_ip, error, bytes_sent)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    this._insertEngagement = this.db.prepare(`
      INSERT INTO engagement_events (ts, segment, event_type, user_id, session_id, duration_ms, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    this._insertAlert = this.db.prepare(`
      INSERT INTO analytics_alerts (ts, segment, metric, value, threshold, severity, message)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
  }

  // ── Request Telemetry ─────────────────────────────────────────────
  recordRequest({ segment = 'api', method, path, statusCode, durationMs, userId, clientIp, error, bytesSent = 0 }) {
    try {
      this._insertRequest.run(Date.now(), segment, method, path, statusCode, durationMs, userId || null, clientIp || null, error || null, bytesSent);
    } catch (e) { this.logger?.error(e, 'analyticsEngine.recordRequest failed'); }
  }

  recordEngagement({ segment, eventType, userId, sessionId, durationMs, metadata }) {
    try {
      this._insertEngagement.run(Date.now(), segment, eventType, userId || null, sessionId || null, durationMs || null, metadata ? JSON.stringify(metadata) : null);
    } catch (e) { this.logger?.error(e, 'analyticsEngine.recordEngagement failed'); }
  }

  // ── KPI Computation ───────────────────────────────────────────────
  computeKPIs(segment, windowMs = 60 * 60 * 1000) {
    const since = Date.now() - windowMs;

    // API metrics
    const rows = this.db.prepare(`
      SELECT status_code, duration_ms, user_id, bytes_sent, error
      FROM api_request_log WHERE segment = ? AND ts > ? ORDER BY duration_ms
    `).all(segment, since);

    const total = rows.length;
    const errors = rows.filter(r => r.status_code >= 400).length;
    const durations = rows.map(r => r.duration_ms).filter(d => d != null).sort((a, b) => a - b);
    const avgDuration = durations.length ? Math.round(durations.reduce((s, v) => s + v, 0) / durations.length) : 0;
    const p95 = durations.length ? Math.round(durations[Math.floor(durations.length * 0.95)] || 0) : 0;
    const p99 = durations.length ? Math.round(durations[Math.floor(durations.length * 0.99)] || 0) : 0;
    const uniqueUsers = new Set(rows.filter(r => r.user_id).map(r => r.user_id)).size;
    const bytesTransferred = rows.reduce((s, r) => s + (r.bytes_sent || 0), 0);
    const errorRate = total > 0 ? parseFloat(((errors / total) * 100).toFixed(2)) : 0;

    // Engagement
    const engagementRows = this.db.prepare(`
      SELECT event_type, COUNT(*) as count FROM engagement_events
      WHERE segment = ? AND ts > ? GROUP BY event_type
    `).all(segment, since);

    const pageViews = engagementRows.find(e => e.event_type === 'page_view')?.count || 0;
    const featureInteractions = engagementRows.filter(e => e.event_type !== 'page_view').reduce((s, e) => s + e.count, 0);

    // Threat/alert events from existing tables
    let threatEvents = 0, alertCount = 0;
    try {
      if (segment === 'winlogs') {
        threatEvents = this.db.prepare(`SELECT COUNT(*) as c FROM logs WHERE suspicious = 1 AND date > ? `).get(new Date(since).toISOString())?.c || 0;
      }
      alertCount = this.db.prepare(`SELECT COUNT(*) as c FROM analytics_alerts WHERE segment = ? AND ts > ? AND acknowledged = 0`).get(segment, since)?.c || 0;
    } catch {}

    // Availability (% of time the segment was healthy — simplified: 100 - error_rate)
    const availability = parseFloat(Math.max(0, 100 - errorRate * 0.5).toFixed(2));

    // Historical comparison (vs prior window)
    const priorSince = since - windowMs;
    const priorRows = this.db.prepare(`SELECT status_code, duration_ms FROM api_request_log WHERE segment = ? AND ts > ? AND ts <= ?`).all(segment, priorSince, since);
    const priorTotal = priorRows.length;
    const priorErrors = priorRows.filter(r => r.status_code >= 400).length;
    const priorDurations = priorRows.map(r => r.duration_ms).filter(d => d != null);
    const priorAvgDuration = priorDurations.length ? Math.round(priorDurations.reduce((s, v) => s + v, 0) / priorDurations.length) : 0;
    const priorErrorRate = priorTotal > 0 ? parseFloat(((priorErrors / priorTotal) * 100).toFixed(2)) : 0;

    return {
      segment,
      window_ms: windowMs,
      computed_at: Date.now(),
      requests:            total,
      errors,
      avg_duration_ms:     avgDuration,
      p95_duration_ms:     p95,
      p99_duration_ms:     p99,
      error_rate_pct:      errorRate,
      availability_pct:    availability,
      unique_users:        uniqueUsers,
      bytes_transferred:   bytesTransferred,
      threat_events:       threatEvents,
      alert_count:         alertCount,
      page_views:          pageViews,
      feature_interactions: featureInteractions,
      benchmarks:          this._getBenchmarkStatus(segment, { avg_duration_ms: avgDuration, error_rate_pct: errorRate, availability_pct: availability }),
      trend: {
        requests:         priorTotal > 0 ? parseFloat((((total - priorTotal) / priorTotal) * 100).toFixed(1)) : 0,
        avg_duration_ms:  priorAvgDuration > 0 ? parseFloat((((avgDuration - priorAvgDuration) / priorAvgDuration) * 100).toFixed(1)) : 0,
        error_rate_pct:   parseFloat((errorRate - priorErrorRate).toFixed(2)),
      },
    };
  }

  // ── Global Dashboard KPIs ─────────────────────────────────────────
  getGlobalKPIs(windowMs = 60 * 60 * 1000) {
    const since = Date.now() - windowMs;

    const totals = this.db.prepare(`
      SELECT COUNT(*) as requests, AVG(duration_ms) as avg_ms, SUM(bytes_sent) as bytes,
             SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors
      FROM api_request_log WHERE ts > ?
    `).get(since);

    const totalRequests = totals?.requests || 0;
    const totalErrors = totals?.errors || 0;
    const globalErrorRate = totalRequests > 0 ? parseFloat(((totalErrors / totalRequests) * 100).toFixed(2)) : 0;

    const activeAlerts = this.db.prepare(`SELECT COUNT(*) as c FROM analytics_alerts WHERE acknowledged = 0 AND ts > ?`).get(since)?.c || 0;
    const activeAnalyticsAlerts = this.db.prepare(`SELECT COUNT(*) as c FROM segment_alerts WHERE acknowledged = 0`).get()?.c || 0;

    const topSegments = this.db.prepare(`
      SELECT segment, COUNT(*) as requests, AVG(duration_ms) as avg_ms,
             SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors
      FROM api_request_log WHERE ts > ? GROUP BY segment ORDER BY requests DESC LIMIT 10
    `).all(since);

    const slowestSegments = this.db.prepare(`
      SELECT segment, AVG(duration_ms) as avg_ms, MAX(duration_ms) as max_ms
      FROM api_request_log WHERE ts > ? AND duration_ms IS NOT NULL GROUP BY segment ORDER BY avg_ms DESC LIMIT 5
    `).all(since);

    const errorsBySegment = this.db.prepare(`
      SELECT segment, COUNT(*) as count, status_code
      FROM api_request_log WHERE ts > ? AND status_code >= 400 GROUP BY segment, status_code ORDER BY count DESC LIMIT 10
    `).all(since);

    const requestTimeline = this.db.prepare(`
      SELECT (ts / 60000) * 60000 as bucket, COUNT(*) as requests,
             SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors,
             AVG(duration_ms) as avg_ms
      FROM api_request_log WHERE ts > ?
      GROUP BY bucket ORDER BY bucket ASC LIMIT 60
    `).all(since);

    return {
      summary: {
        total_requests:   totalRequests,
        total_errors:     totalErrors,
        error_rate_pct:   globalErrorRate,
        avg_response_ms:  Math.round(totals?.avg_ms || 0),
        bytes_transferred: totals?.bytes || 0,
        active_alerts:    activeAlerts + activeAnalyticsAlerts,
        segments_tracked: SEGMENT_DEFS.length,
      },
      top_segments:     topSegments,
      slowest_segments: slowestSegments,
      errors_by_segment: errorsBySegment,
      timeline:         requestTimeline,
      computed_at:      Date.now(),
    };
  }

  // ── Segment Time-Series ───────────────────────────────────────────
  getSegmentTimeSeries(segment, windowMs = 3 * 60 * 60 * 1000, bucketMs = 5 * 60 * 1000) {
    const since = Date.now() - windowMs;
    const rows = this.db.prepare(`
      SELECT (ts / ${bucketMs}) * ${bucketMs} as bucket,
             COUNT(*) as requests,
             SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors,
             AVG(duration_ms) as avg_ms,
             MAX(duration_ms) as max_ms,
             SUM(bytes_sent) as bytes
      FROM api_request_log WHERE segment = ? AND ts > ?
      GROUP BY bucket ORDER BY bucket ASC
    `).all(segment, since);
    return rows;
  }

  // ── Benchmark Status ──────────────────────────────────────────────
  _getBenchmarkStatus(segment, currentMetrics) {
    const thresholds = this.db.prepare(
      'SELECT * FROM perf_thresholds WHERE segment = ? AND enabled = 1'
    ).all(segment);

    const results = {};
    for (const t of thresholds) {
      const current = currentMetrics[t.metric];
      if (current == null) continue;

      const exceedsCritical = t.direction === 'above' ? current >= t.critical_value : current <= t.critical_value;
      const exceedsWarning  = t.direction === 'above' ? current >= t.warning_value  : current <= t.warning_value;

      results[t.metric] = {
        value: current,
        warning: t.warning_value,
        critical: t.critical_value,
        direction: t.direction,
        status: exceedsCritical ? 'critical' : exceedsWarning ? 'warning' : 'ok',
        benchmark: BENCHMARKS[t.metric] || null,
      };
    }
    return results;
  }

  // ── Alert Checking ────────────────────────────────────────────────
  _checkThresholdsForSegment(segment, kpi) {
    const thresholds = this.db.prepare(
      'SELECT * FROM perf_thresholds WHERE segment = ? AND enabled = 1'
    ).all(segment);

    for (const t of thresholds) {
      const value = kpi[t.metric];
      if (value == null) continue;

      const exceedsCritical = t.direction === 'above' ? value >= t.critical_value : value <= t.critical_value;
      const exceedsWarning  = t.direction === 'above' ? value >= t.warning_value  : value <= t.warning_value;

      if (exceedsCritical || exceedsWarning) {
        const severity = exceedsCritical ? 'critical' : 'warning';
        const threshold = exceedsCritical ? t.critical_value : t.warning_value;

        // Avoid duplicate alerts (last 5 min)
        const recent = this.db.prepare(`
          SELECT id FROM analytics_alerts WHERE segment = ? AND metric = ? AND ts > ? AND severity = ?
        `).get(segment, t.metric, Date.now() - 5 * 60000, severity);

        if (!recent) {
          this._insertAlert.run(Date.now(), segment, t.metric, value, threshold, severity,
            `[${segment}] ${t.metric} is ${value.toFixed(2)} (threshold: ${threshold})`);
          this.logger?.warn({ segment, metric: t.metric, value, threshold, severity }, 'Analytics threshold breached');
        }
      }
    }
  }

  // ── Aggregation Loop (runs every 60s) ─────────────────────────────
  _startAggregationLoop() {
    this._aggregationTimer = setInterval(() => {
      try { this._runAggregation(); } catch (e) { this.logger?.error(e, 'Aggregation loop error'); }
    }, 60 * 1000);

    // Run immediately on init (with 5s delay for DB to settle)
    setTimeout(() => { try { this._runAggregation(); } catch {} }, 5000);
  }

  _runAggregation() {
    const now = Date.now();
    const bucketTs = Math.floor(now / 60000) * 60000;

    const upsert = this.db.prepare(`
      INSERT OR REPLACE INTO segment_kpi_snapshots
        (ts, segment, period, requests, errors, avg_duration_ms, p95_duration_ms, p99_duration_ms,
         error_rate_pct, availability_pct, unique_users, bytes_transferred, threat_events, alert_count)
      VALUES (?, ?, '1m', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const seg of SEGMENT_DEFS) {
      const kpi = this.computeKPIs(seg.id, 60 * 1000); // last 1 min
      upsert.run(
        bucketTs, seg.id, kpi.requests, kpi.errors,
        kpi.avg_duration_ms, kpi.p95_duration_ms, kpi.p99_duration_ms,
        kpi.error_rate_pct, kpi.availability_pct, kpi.unique_users,
        kpi.bytes_transferred, kpi.threat_events, kpi.alert_count
      );
      this._checkThresholdsForSegment(seg.id, kpi);
    }

    // Cleanup logs older than 7 days
    this.db.prepare('DELETE FROM api_request_log WHERE ts < ?').run(now - 7 * 24 * 3600 * 1000);
    this.db.prepare('DELETE FROM engagement_events WHERE ts < ?').run(now - 7 * 24 * 3600 * 1000);
    this.db.prepare('DELETE FROM segment_kpi_snapshots WHERE ts < ?').run(now - 30 * 24 * 3600 * 1000);
  }

  // ── Historical Comparison ─────────────────────────────────────────
  getHistoricalComparison(segment, periods = [
    { label: '1h',  ms: 60 * 60 * 1000 },
    { label: '6h',  ms: 6 * 60 * 60 * 1000 },
    { label: '24h', ms: 24 * 60 * 60 * 1000 },
    { label: '7d',  ms: 7 * 24 * 60 * 60 * 1000 },
  ]) {
    return periods.map(p => ({
      period: p.label,
      ...this.computeKPIs(segment, p.ms),
    }));
  }

  // ── Comparative Ranking ───────────────────────────────────────────
  getSegmentRanking(windowMs = 60 * 60 * 1000) {
    const segments = SEGMENT_DEFS.map(s => s.id);
    return segments.map(seg => {
      const kpi = this.computeKPIs(seg, windowMs);
      const def = SEGMENT_DEFS.find(s => s.id === seg);
      const score = Math.max(0, Math.min(100,
        100
        - (kpi.error_rate_pct * 3)
        - (kpi.avg_duration_ms > 500 ? (kpi.avg_duration_ms - 500) / 50 : 0)
        - (kpi.alert_count * 5)
        + (kpi.availability_pct > 99 ? 5 : 0)
      ));
      return { ...def, kpi, health_score: Math.round(score) };
    }).sort((a, b) => b.health_score - a.health_score);
  }

  // ── Alert Management ──────────────────────────────────────────────
  getActiveAlerts(limit = 100) {
    return this.db.prepare(`
      SELECT * FROM analytics_alerts WHERE acknowledged = 0 ORDER BY ts DESC LIMIT ?
    `).all(limit);
  }

  acknowledgeAlert(id) {
    return this.db.prepare('UPDATE analytics_alerts SET acknowledged = 1 WHERE id = ?').run(id);
  }

  getAllAlerts(since, segment, limit = 200) {
    let q = 'SELECT * FROM analytics_alerts WHERE 1=1';
    const params = [];
    if (since) { q += ' AND ts > ?'; params.push(since); }
    if (segment) { q += ' AND segment = ?'; params.push(segment); }
    q += ' ORDER BY ts DESC LIMIT ?';
    params.push(limit);
    return this.db.prepare(q).all(...params);
  }

  // ── Threshold Management ──────────────────────────────────────────
  updateThreshold(segment, metric, warningValue, criticalValue, direction = 'above') {
    return this.db.prepare(`
      INSERT OR REPLACE INTO perf_thresholds (segment, metric, warning_value, critical_value, direction, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(segment, metric, warningValue, criticalValue, direction, Date.now());
  }

  getThresholds(segment = null) {
    if (segment) return this.db.prepare('SELECT * FROM perf_thresholds WHERE segment = ?').all(segment);
    return this.db.prepare('SELECT * FROM perf_thresholds').all();
  }

  // ── Cleanup ───────────────────────────────────────────────────────
  destroy() {
    if (this._aggregationTimer) clearInterval(this._aggregationTimer);
  }
}
