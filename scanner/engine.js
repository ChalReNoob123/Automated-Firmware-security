/**
 * ScannerEngine — orchestrates multi-threaded directory scanning
 */
import { Worker } from 'worker_threads';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import { SCAN_TARGETS, TECHNIQUES } from './mitre.js';

const WORKER_PATH = new URL('./worker.js', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1');

export class ScannerEngine {
  constructor(db, logger, broadcastFn) {
    this.db = db;
    this.logger = logger;
    this.broadcast = broadcastFn;
    this.activeScan = null;
    this.workers = [];
    this.maxWorkers = Math.max(1, Math.min(4, os.cpus().length - 2));
    this.aborted = false;
  }

  /** List available scan targets (resolves dynamic paths) */
  getTargets() {
    return SCAN_TARGETS.map(t => {
      const resolved = t.resolvePath ? t.resolvePath() : t.path;
      const exists = resolved ? fs.existsSync(resolved) : false;
      return { ...t, resolvedPath: resolved, exists, path: undefined, resolvePath: undefined };
    });
  }

  /** Start a new scan session */
  async startScan(config = {}) {
    if (this.activeScan) throw new Error('Scan already in progress');
    this.aborted = false;

    const sessionId = crypto.randomUUID();
    const selectedTargets = config.targets || SCAN_TARGETS.map(t => t.id);
    const scanConfig = {
      targets: selectedTargets,
      maxDepth: config.maxDepth ?? 2,
      checkSignatures: config.checkSignatures ?? true,
      checkADS: config.checkADS ?? true,
      maxFileSizeMB: config.maxFileSizeMB ?? 100,
    };

    // Create session record
    this.db.prepare(`
      INSERT INTO scan_sessions (id, started_at, status, config, total_files, scanned_files, findings)
      VALUES (?, ?, 'running', ?, 0, 0, 0)
    `).run(sessionId, Date.now(), JSON.stringify(scanConfig));

    this.activeScan = {
      sessionId, config: scanConfig,
      totalFiles: 0, scannedFiles: 0, findings: 0,
      currentDir: '', startedAt: Date.now(),
    };

    this.logger.info({ sessionId, config: scanConfig }, 'Scan started');
    this._broadcastProgress();

    // Process targets sequentially, files in parallel
    try {
      const targets = SCAN_TARGETS.filter(t => selectedTargets.includes(t.id));
      for (const target of targets) {
        if (this.aborted) break;
        const resolved = target.resolvePath ? target.resolvePath() : target.path;
        if (!resolved || !fs.existsSync(resolved)) {
          this.logger.info({ path: resolved, target: target.id }, 'Target not found, skipping');
          continue;
        }
        this.activeScan.currentDir = resolved;
        this._broadcastProgress();
        await this._scanDirectory(resolved, target, scanConfig, sessionId);
      }

      // Compute session summary
      const findings = this.db.prepare('SELECT COUNT(*) as c FROM scan_findings WHERE session_id = ?').get(sessionId);
      const critical = this.db.prepare("SELECT COUNT(*) as c FROM scan_findings WHERE session_id = ? AND status = 'critical'").get(sessionId);
      const suspicious = this.db.prepare("SELECT COUNT(*) as c FROM scan_findings WHERE session_id = ? AND status = 'suspicious'").get(sessionId);
      const avgRisk = this.db.prepare('SELECT AVG(risk_score) as avg FROM scan_findings WHERE session_id = ?').get(sessionId);

      const summary = {
        totalFiles: this.activeScan.totalFiles,
        scannedFiles: this.activeScan.scannedFiles,
        findings: findings.c,
        critical: critical.c,
        suspicious: suspicious.c,
        avgRiskScore: Math.round((avgRisk.avg || 0) * 10) / 10,
        duration: Date.now() - this.activeScan.startedAt,
      };

      this.db.prepare(`
        UPDATE scan_sessions SET completed_at = ?, status = ?, total_files = ?, scanned_files = ?, findings = ?, risk_score = ?, summary = ?
        WHERE id = ?
      `).run(Date.now(), this.aborted ? 'cancelled' : 'completed', summary.totalFiles, summary.scannedFiles, summary.findings, summary.avgRiskScore, JSON.stringify(summary), sessionId);

      this.logger.info({ sessionId, summary }, 'Scan completed');
      this.broadcast?.({ event: 'scanner_complete', data: { sessionId, summary } });
    } catch (err) {
      this.logger.error(err, 'Scan failed');
      this.db.prepare("UPDATE scan_sessions SET status = 'failed', completed_at = ? WHERE id = ?").run(Date.now(), sessionId);
    } finally {
      this.activeScan = null;
      this.workers.forEach(w => w.terminate());
      this.workers = [];
    }

    return sessionId;
  }

  /** Stop an active scan */
  stopScan() {
    if (!this.activeScan) return false;
    this.aborted = true;
    this.workers.forEach(w => w.terminate());
    this.workers = [];
    return true;
  }

  /** Get current scan status */
  getStatus() {
    if (!this.activeScan) return { scanning: false };
    return {
      scanning: true,
      sessionId: this.activeScan.sessionId,
      totalFiles: this.activeScan.totalFiles,
      scannedFiles: this.activeScan.scannedFiles,
      findings: this.activeScan.findings,
      currentDir: this.activeScan.currentDir,
      elapsed: Date.now() - this.activeScan.startedAt,
    };
  }

  /** Walk a directory and dispatch files to workers */
  async _scanDirectory(dirPath, target, config, sessionId) {
    const files = [];
    this._walkDir(dirPath, target, config, files, 0);
    this.activeScan.totalFiles += files.length;
    this._broadcastProgress();

    if (files.length === 0) return;

    // Split files into batches for workers
    const batchSize = Math.max(5, Math.ceil(files.length / this.maxWorkers));
    const batches = [];
    for (let i = 0; i < files.length; i += batchSize) {
      batches.push(files.slice(i, i + batchSize));
    }

    await Promise.all(batches.map((batch, idx) =>
      this._runWorkerBatch(batch, target, config, sessionId, `${target.id}-${idx}`)
    ));
  }

  /** Recursive directory walker with depth and extension filters */
  _walkDir(dirPath, target, config, results, depth) {
    if (depth > (config.maxDepth ?? target.maxDepth ?? 2)) return;
    if (this.aborted) return;

    let entries;
    try { entries = fs.readdirSync(dirPath, { withFileTypes: true }); } catch { return; }

    for (const entry of entries) {
      if (this.aborted) return;
      const fullPath = path.join(dirPath, entry.name);
      try {
        if (entry.isDirectory()) {
          this._walkDir(fullPath, target, config, results, depth + 1);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          if (target.extensions && !target.extensions.includes(ext)) continue;
          results.push(fullPath);
        }
      } catch { /* skip inaccessible entries */ }
    }
  }

  /** Run a batch of files through a worker thread */
  _runWorkerBatch(files, target, config, sessionId, batchId) {
    return new Promise((resolve) => {
      const workerTarget = { ...target, path: undefined, resolvePath: undefined };
      let worker;
      try {
        worker = new Worker(WORKER_PATH);
      } catch (err) {
        this.logger.error(err, 'Failed to create worker — falling back to inline processing');
        resolve();
        return;
      }
      this.workers.push(worker);

      worker.on('message', (msg) => {
        if (msg.type === 'file_done') {
          this.activeScan.scannedFiles++;
          if (this.activeScan.scannedFiles % 20 === 0) this._broadcastProgress();
        }
        if (msg.type === 'batch_done') {
          for (const result of msg.results) {
            if (result.error) continue;
            this._storeFinding(sessionId, result);
            if (result.riskScore >= 20) this.activeScan.findings++;
          }
          this._broadcastProgress();
          resolve();
        }
      });

      worker.on('error', (err) => {
        this.logger.error(err, 'Worker error');
        resolve();
      });

      worker.postMessage({
        type: 'process_batch', files, batchId,
        target: workerTarget,
        options: { checkSignatures: config.checkSignatures, checkADS: config.checkADS },
      });
    });
  }

  /** Store a finding in the database */
  _storeFinding(sessionId, result) {
    try {
      const id = crypto.randomUUID();
      this.db.prepare(`
        INSERT INTO scan_findings (id, session_id, file_path, file_name, file_size, file_modified,
          sha256, entropy, is_signed, signature_status, signer, has_ads, ads_streams,
          risk_score, risk_factors, mitre_techniques, directory_category, directory_criticality,
          status, target_label, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).run(
        id, sessionId, result.filePath, result.fileName, result.fileSize, result.fileModified,
        result.sha256, result.entropy, result.isSigned ? 1 : 0, result.signatureStatus, result.signer,
        result.hasADS ? 1 : 0, JSON.stringify(result.adsStreams),
        result.riskScore, JSON.stringify(result.riskFactors), JSON.stringify(result.mitreTechniques),
        result.directoryCategory, result.directoryCriticality, result.status, result.targetLabel, Date.now()
      );
    } catch (e) {
      this.logger.error(e, 'Failed to store finding');
    }
  }

  _broadcastProgress() {
    if (!this.activeScan) return;
    this.broadcast?.({
      event: 'scanner_progress',
      data: {
        sessionId: this.activeScan.sessionId,
        totalFiles: this.activeScan.totalFiles,
        scannedFiles: this.activeScan.scannedFiles,
        findings: this.activeScan.findings,
        currentDir: this.activeScan.currentDir,
        elapsed: Date.now() - this.activeScan.startedAt,
      },
    });
  }
}
