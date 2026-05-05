/**
 * Scanner Worker Thread
 * Processes batches of file paths: hashing, entropy, ADS detection, signature verification.
 * Runs in a worker_thread to avoid blocking the main event loop.
 */
import { parentPort, workerData } from 'worker_threads';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/** Shannon entropy of a buffer (0-8 for bytes) */
function calculateEntropy(buffer) {
  if (buffer.length === 0) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) freq[buffer[i]]++;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 1000) / 1000;
}

/** SHA-256 of file, reading first 10MB max to avoid huge-file stalls */
function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath, { start: 0, end: 10 * 1024 * 1024 - 1 });
    stream.on('data', d => hash.update(d));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/** Check for Alternate Data Streams via PowerShell */
async function checkADS(filePath) {
  try {
    const escaped = filePath.replace(/'/g, "''");
    const { stdout } = await execAsync(
      `powershell -NoProfile -Command "Get-Item -LiteralPath '${escaped}' -Stream * | Where-Object { $_.Stream -ne ':$DATA' } | Select-Object -ExpandProperty Stream"`,
      { timeout: 5000 }
    );
    const streams = stdout.trim().split('\n').map(s => s.trim()).filter(Boolean);
    return { hasADS: streams.length > 0, streams };
  } catch {
    return { hasADS: false, streams: [] };
  }
}

/** Verify digital signature via PowerShell Get-AuthenticodeSignature */
async function checkSignature(filePath) {
  try {
    const escaped = filePath.replace(/'/g, "''");
    const { stdout } = await execAsync(
      `powershell -NoProfile -Command "$s = Get-AuthenticodeSignature -LiteralPath '${escaped}'; [PSCustomObject]@{Status=$s.Status.ToString();Signer=$s.SignerCertificate.Subject} | ConvertTo-Json"`,
      { timeout: 8000 }
    );
    const data = JSON.parse(stdout.trim());
    return {
      isSigned: data.Status === 'Valid',
      status: data.Status || 'Unknown',
      signer: data.Signer || null,
    };
  } catch {
    return { isSigned: false, status: 'Error', signer: null };
  }
}

/** Parse a Windows scheduled task XML for suspicious content */
function parseScheduledTaskXML(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const findings = [];

    // Check for suspicious command execution
    const execMatch = content.match(/<Command>(.*?)<\/Command>/gi);
    if (execMatch) {
      for (const cmd of execMatch) {
        const cmdText = cmd.replace(/<\/?Command>/gi, '').trim().toLowerCase();
        const suspicious = ['powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta', 'certutil',
          'bitsadmin', 'regsvr32', 'rundll32', 'msiexec'].some(s => cmdText.includes(s));
        if (suspicious) {
          findings.push({ type: 'suspicious_command', value: cmdText, severity: 'high' });
        }
      }
    }

    // Check for encoded arguments
    if (content.toLowerCase().includes('-encodedcommand') || content.toLowerCase().includes('-enc ')) {
      findings.push({ type: 'encoded_command', value: 'Base64-encoded PowerShell detected', severity: 'critical' });
    }

    // Check for remote downloads
    if (content.match(/https?:\/\//i) && (content.includes('Download') || content.includes('Invoke-WebRequest'))) {
      findings.push({ type: 'remote_download', value: 'Remote file download in task', severity: 'high' });
    }

    return findings;
  } catch {
    return [];
  }
}

/** Process a single file */
async function processFile(filePath, target, options = {}) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return null;

    const ext = path.extname(filePath).toLowerCase();
    const fileName = path.basename(filePath);
    const result = {
      filePath, fileName, ext,
      fileSize: stat.size,
      fileModified: stat.mtimeMs,
      fileCreated: stat.birthtimeMs,
      directoryCategory: target.category,
      directoryCriticality: target.criticality,
      targetLabel: target.label,
      sha256: null, entropy: null,
      isSigned: false, signatureStatus: 'NotChecked', signer: null,
      hasADS: false, adsStreams: [],
      riskScore: 0, riskFactors: [],
      mitreTechniques: [...(target.mitre || [])],
      taskFindings: [],
      status: 'clean',
    };

    // SHA-256 hash (skip huge files > 100MB)
    if (stat.size > 0 && stat.size < 100 * 1024 * 1024) {
      result.sha256 = await hashFile(filePath);
    }

    // Entropy (read first 64KB for performance)
    if (stat.size > 0 && stat.size < 50 * 1024 * 1024) {
      const sampleSize = Math.min(stat.size, 65536);
      const buf = Buffer.alloc(sampleSize);
      const fd = fs.openSync(filePath, 'r');
      fs.readSync(fd, buf, 0, sampleSize, 0);
      fs.closeSync(fd);
      result.entropy = calculateEntropy(buf);
    }

    // Signature check for executables only (performance)
    if (options.checkSignatures !== false && ['.exe', '.dll', '.sys', '.drv', '.ocx'].includes(ext)) {
      const sig = await checkSignature(filePath);
      result.isSigned = sig.isSigned;
      result.signatureStatus = sig.status;
      result.signer = sig.signer;
    }

    // ADS check
    if (options.checkADS !== false) {
      const ads = await checkADS(filePath);
      result.hasADS = ads.hasADS;
      result.adsStreams = ads.streams;
    }

    // Scheduled task XML parsing
    if (target.category === 'scheduled_tasks' && (ext === '' || ext === '.xml' || ext === '.job')) {
      result.taskFindings = parseScheduledTaskXML(filePath);
    }

    // ----- RISK SCORING -----
    let risk = 0;
    const factors = [];

    // Directory criticality
    if (target.criticality === 'critical') risk += 15;
    else if (target.criticality === 'high') risk += 10;
    else if (target.criticality === 'medium') risk += 5;

    // Unsigned binary in system directory
    if (['.exe', '.dll', '.sys'].includes(ext) && !result.isSigned && target.category === 'system_binaries') {
      risk += 35;
      factors.push('Unsigned binary in system directory');
      result.mitreTechniques.push('T1036.005');
    }

    // High entropy (possible obfuscation/packing)
    if (result.entropy !== null) {
      const scriptExts = ['.ps1', '.vbs', '.js', '.bat', '.cmd', '.hta'];
      const threshold = scriptExts.includes(ext) ? 5.5 : 7.2;
      if (result.entropy > threshold) {
        risk += 25;
        factors.push(`High entropy (${result.entropy.toFixed(2)}) — possible obfuscation`);
        result.mitreTechniques.push('T1027');
      }
    }

    // Alternate Data Streams
    if (result.hasADS) {
      risk += 30;
      factors.push(`Hidden ADS: ${result.adsStreams.join(', ')}`);
      result.mitreTechniques.push('T1564.004');
    }

    // Executable in temp directory
    if (target.category === 'temp_files' && ['.exe', '.dll', '.scr'].includes(ext)) {
      risk += 20;
      factors.push('Executable in temp directory');
      result.mitreTechniques.push('T1105');
    }

    // Script in startup folder
    if (target.category === 'startup') {
      risk += 20;
      factors.push('File in startup folder');
    }

    // Web shell indicators
    if (target.category === 'web_server' && ['.asp', '.aspx', '.php', '.jsp'].includes(ext)) {
      risk += 15;
      factors.push('Script file in web root');
    }

    // Suspicious scheduled task
    if (result.taskFindings.length > 0) {
      const critCount = result.taskFindings.filter(f => f.severity === 'critical').length;
      risk += critCount * 30 + (result.taskFindings.length - critCount) * 15;
      factors.push(`Suspicious task content (${result.taskFindings.length} findings)`);
    }

    // Recently modified system binary
    if (target.category === 'system_binaries') {
      const hoursSinceModified = (Date.now() - stat.mtimeMs) / 3600000;
      if (hoursSinceModified < 24) {
        risk += 15;
        factors.push(`Recently modified (${Math.round(hoursSinceModified)}h ago)`);
      }
    }

    result.riskScore = Math.min(100, risk);
    result.riskFactors = factors;
    result.mitreTechniques = [...new Set(result.mitreTechniques)];

    if (risk >= 70) result.status = 'critical';
    else if (risk >= 40) result.status = 'suspicious';
    else if (risk >= 20) result.status = 'warning';

    return result;
  } catch (err) {
    return { filePath, error: err.message, status: 'error', riskScore: 0 };
  }
}

// ── Worker message handler ──
parentPort.on('message', async (msg) => {
  if (msg.type === 'process_batch') {
    const { files, target, options, batchId } = msg;
    const results = [];
    for (const filePath of files) {
      const result = await processFile(filePath, target, options);
      if (result) results.push(result);
      // Report progress per file
      parentPort.postMessage({ type: 'file_done', batchId, filePath });
    }
    parentPort.postMessage({ type: 'batch_done', batchId, results });
  }
});
