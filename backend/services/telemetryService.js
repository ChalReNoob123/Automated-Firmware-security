import os from 'os';
import crypto from 'crypto';
import { promisify } from 'util';
import { exec } from 'child_process';
import db from '../config/db.js';
import logger from '../utils/logger.js';
import fs from 'fs';
import path from 'path';

const execAsync = promisify(exec);

export const MITRE_MAP = {
  '4625': { id: 'T1110',     name: 'Brute Force',                  tactic: 'Credential Access' },
  '4648': { id: 'T1078',     name: 'Valid Accounts',               tactic: 'Defense Evasion' },
  '4672': { id: 'T1078.003', name: 'Local Account — High Priv',    tactic: 'Privilege Escalation' },
  '4688': { id: 'T1059',     name: 'Command & Scripting Interp.',  tactic: 'Execution' },
  '4698': { id: 'T1053.005', name: 'Scheduled Task',               tactic: 'Persistence' },
  '4720': { id: 'T1136.001', name: 'Local Account Created',        tactic: 'Persistence' },
  '4724': { id: 'T1098',     name: 'Account Manipulation',        tactic: 'Persistence' },
  '4732': { id: 'T1098',     name: 'Account Manipulation',        tactic: 'Persistence' },
  '7045': { id: 'T1543.003', name: 'New Windows Service',          tactic: 'Persistence' },
  '1102': { id: 'T1070.001', name: 'Clear Windows Event Logs',     tactic: 'Defense Evasion' },
  '4776': { id: 'T1110',     name: 'Credential Validation',       tactic: 'Credential Access' },
  '4768': { id: 'T1558.003', name: 'Kerberoasting',                tactic: 'Credential Access' },
  '4769': { id: 'T1558.003', name: 'Kerberos Service Ticket',      tactic: 'Credential Access' },
};

export const SUSPICIOUS_IDS = new Set(Object.keys(MITRE_MAP));

let cache = {
  system: null,
  network: [],
  files: [],
  ts: 0
};

const CACHE_TTL = 5000; // 5 seconds

export const getSystemTelemetry = async (force = false) => {
  if (!force && cache.system && Date.now() - cache.ts < CACHE_TTL) return cache.system;
  
  const info = {
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    cpu: os.cpus()[0]?.model || 'Unknown',
    cores: os.cpus().length,
    totalMem: (os.totalmem() / 1024 / 1024 / 1024).toFixed(2) + ' GB',
    freeMem: (os.freemem() / 1024 / 1024 / 1024).toFixed(2) + ' GB',
    uptime: (os.uptime() / 3600).toFixed(2) + ' Hours',
    hostname: os.hostname(),
  };
  
  cache.system = info;
  cache.ts = Date.now();
  return info;
};

export const getNetworkTraffic = async (force = false) => {
  if (!force && cache.network.length && Date.now() - cache.ts < CACHE_TTL) return cache.network;
  
  try {
    const platform = os.platform();
    let cmd = 'netstat -ano';
    if (platform === 'linux')  cmd = 'ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null';
    if (platform === 'darwin') cmd = 'netstat -an 2>/dev/null';
    const { stdout } = await execAsync(cmd);
    
    const lines = stdout.split('\n').filter(l => l.trim());
    const connections = [];

    if (platform === 'win32') {
      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4 && (parts[0] === 'TCP' || parts[0] === 'UDP')) {
          connections.push({ protocol: parts[0], local: parts[1], foreign: parts[2], state: parts[3], pid: parts[4] });
        }
      });
    } else {
      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 3) {
          connections.push({ protocol: parts[0], local: parts[1], foreign: parts[2], state: parts[3] || 'UNKNOWN', pid: parts[parts.length-1] });
        }
      });
    }
    const result = connections.slice(0, 100);
    cache.network = result;
    return result;
  } catch (e) { 
    logger.error(e, 'Error fetching network traffic');
    return []; 
  }
};

export const getFileChanges = async (force = false) => {
  if (!force && cache.files.length && Date.now() - cache.ts < CACHE_TTL) return cache.files;

  try {
    const platform = os.platform();
    let targetDirs = [];
    if (platform === 'win32') {
      targetDirs = [
        path.join(process.env.windir || 'C:\\Windows', 'System32\\drivers\\etc'),
        process.env.APPDATA || path.join(os.homedir(), 'AppData\\Roaming')
      ];
    } else if (platform === 'linux') {
      targetDirs = ['/etc', '/var/spool/cron'];
    } else if (platform === 'darwin') {
      targetDirs = ['/etc', '/Library/LaunchDaemons'];
    }

    let results = [];
    for (const dir of targetDirs) {
      if (!fs.existsSync(dir)) continue;
      try {
        const files = fs.readdirSync(dir);
        for(const f of files.slice(0, 50)) {
          try {
            const fullPath = path.join(dir, f);
            const stats = fs.statSync(fullPath);
            if (stats.isFile()) {
              results.push({ name: f, path: fullPath, size: stats.size, modified: stats.mtime });
            }
          } catch (e) {}
        }
      } catch (e) {}
    }
    const result = results.sort((a, b) => b.modified - a.modified).slice(0, 15);
    cache.files = result;
    return result;
  } catch (e) {
    return [];
  }
};

export const analyzeTelemetry = async (logs, network, files) => {
  const analysis = {
    summary: "System baseline operating within normal parameters.",
    score: 100,
    threats: [],
    mitreMappings: [],
  };

  let riskScore = 0;
  const threatDetails = [];
  const mitreSet = new Set();

  // Process Logs
  logs.forEach(log => {
    const id = log.Id?.toString() || '';
    if (MITRE_MAP[id]) {
      const { name, id: mitreId, tactic } = MITRE_MAP[id];
      riskScore += 20;
      threatDetails.push(`[${tactic}] ${name} detected via log analysis.`);
      mitreSet.add(`${mitreId} - ${name}`);
    }
    
    const msg = (log.Message || '').toLowerCase();
    if (msg.includes('mimikatz') || msg.includes('cobalt strike') || msg.includes('metasploit')) {
      riskScore += 50;
      threatDetails.push(`CRITICAL: Known exploit tool signature detected in log: ${log.Message}`);
      mitreSet.add('T1003 - OS Credential Dumping');
    }
  });

  // Process Network
  network.forEach(conn => {
    const port = parseInt(conn.local?.split(':').pop() || '0');
    const state = conn.state || '';
    
    if (state === 'LISTENING' && [3389, 445, 139, 22, 21].includes(port)) {
      riskScore += 10;
      threatDetails.push(`Potentially exposed service on port ${port} (${state}).`);
      mitreSet.add('T1021 - Remote Services');
    }
    
    if (conn.foreign && (conn.foreign.includes('185.162.') || conn.foreign.includes('95.213.'))) {
      riskScore += 40;
      threatDetails.push(`Connection to known malicious IP range: ${conn.foreign}`);
      mitreSet.add('T1071 - Application Layer Protocol');
    }
  });

  // Process Registry/Config (Windows Specific)
  if (os.platform() === 'win32') {
    try {
      const reg = await getRegistryModifications();
      if (Array.isArray(reg)) {
         reg.forEach(entry => {
           // Check for suspicious Run keys
           Object.entries(entry).forEach(([key, value]) => {
             const val = String(value).toLowerCase();
             if (val.includes('powershell') || val.includes('cmd.exe') || val.includes('temp') || val.includes('http')) {
               riskScore += 25;
               threatDetails.push(`CRITICAL: Suspicious startup entry in registry: ${key} -> ${value}`);
               mitreSet.add('T1547.001 - Boot or Logon Autostart Execution');
             }
           });
           
           if (Object.keys(entry).length > 15) {
             riskScore += 10;
             threatDetails.push('Unusual density of startup entries detected in registry hive.');
           }
         });
      }
    } catch (e) {}
  }

  // Vulnerability detection (Simple version)
  const uptime = os.uptime();
  if (uptime > 30 * 24 * 3600) { // 30 days
    riskScore += 5;
    threatDetails.push('System has been running for over 30 days. Reboot recommended for security updates.');
  }

  analysis.score = Math.max(0, 100 - riskScore);
  analysis.threats = threatDetails;
  analysis.mitreMappings = Array.from(mitreSet);

  if (analysis.score < 50) {
    analysis.summary = "CRITICAL: Multiple high-risk indicators detected. Immediate investigation required.";
  } else if (analysis.score < 80) {
    analysis.summary = "WARNING: Suspicious activity patterns identified. Analyst review recommended.";
  }

  return analysis;
};

const NOISE_BLACKLIST = [
  'ApiSet Function:',
  'Microsoft-Windows-AppModel',
  'The application-specific permission settings do not grant Local Activation permission',
  'The description for Event ID',
  'Information: The service was started',
  'Information: The service was stopped',
];

export const getWindowsLogs = async (maxEvents = 100) => {
  if (os.platform() !== 'win32') return [];
  
  const psScript = `
    try {
      $ProgressPreference = 'SilentlyContinue'
      $channels = @('Security', 'System', 'Application')
      $evts = Get-WinEvent -LogName $channels -MaxEvents ${maxEvents} -ErrorAction SilentlyContinue
      if ($null -eq $evts) { return '[]' }
      $arr = @($evts | Select-Object @{Name='Id';Expression={[int]$_.Id}}, TimeCreated, LevelDisplayName, TaskDisplayName, ProviderName, LogName, Message)
      return ($arr | ConvertTo-Json -Compress -Depth 2)
    } catch { return '[]' }
  `;

  try {
    const encoded = Buffer.from(psScript, 'utf16le').toString('base64');
    const { stdout } = await execAsync(`powershell -NoProfile -NonInteractive -EncodedCommand ${encoded}`, { timeout: 15000 });
    
    // Defensive extraction to bypass any #< CLIXML or stray progress outputs
    const jsonStart = stdout.indexOf('[');
    const jsonEnd = stdout.lastIndexOf(']') + 1;
    if (jsonStart === -1 || jsonEnd === 0) return [];
    
    const cleanJson = stdout.substring(jsonStart, jsonEnd);
    if (!cleanJson || cleanJson === '[]') return [];
    
    const parsed = JSON.parse(cleanJson);
    return (Array.isArray(parsed) ? parsed : [parsed]).filter(l => {
      const msg = l.Message || '';
      return !NOISE_BLACKLIST.some(noise => msg.includes(noise));
    });
  } catch (err) {
    logger.warn({ err: err.message }, 'Failed to fetch Windows logs');
    return [];
  }
};

export const getLinuxLogs = async (maxEvents = 100) => {
  if (os.platform() !== 'linux') return [];
  
  try {
    const { stdout } = await execAsync(`journalctl -n ${maxEvents} --no-pager -o json`, { timeout: 10000 });
    const lines = stdout.trim().split('\n').filter(Boolean);
    return lines.map(line => {
      try {
        const j = JSON.parse(line);
        return {
          Id: j.PRIORITY || '0',
          TimeCreated: j.__REALTIME_TIMESTAMP ? new Date(parseInt(j.__REALTIME_TIMESTAMP) / 1000).toISOString() : new Date().toISOString(),
          LevelDisplayName: ['0','1','2','3'].includes(j.PRIORITY) ? 'Critical' : j.PRIORITY === '4' ? 'Warning' : 'Information',
          TaskDisplayName: j._SYSTEMD_UNIT || 'System',
          ProviderName: j.SYSLOG_IDENTIFIER || 'journald',
          LogName: 'System Journal',
          Message: j.MESSAGE || ''
        };
      } catch { return null; }
    }).filter(Boolean);
  } catch (err) {
    logger.warn({ err: err.message }, 'Failed to fetch Linux logs');
    return [];
  }
};

export const getAndroidLogs = async (maxEvents = 100) => {
  try {
    const { stdout } = await execAsync(`adb logcat -d -v time -t ${maxEvents}`, { timeout: 5000 });
    const lines = stdout.trim().split('\n').filter(Boolean);
    return lines.map((line, i) => ({
      Id: `ANDR-${i}`,
      TimeCreated: new Date().toISOString(),
      LevelDisplayName: line.includes(' E ') ? 'Error' : (line.includes(' W ') ? 'Warning' : 'Information'),
      TaskDisplayName: 'AndroidSystem',
      ProviderName: 'ADB',
      LogName: 'Logcat',
      Message: line
    }));
  } catch (err) {
    // ADB not available, return empty
    return [];
  }
};

export const getRegistryModifications = async () => {
  if (os.platform() !== 'win32') return [];
  
  const psScript = `
    $paths = @(
      "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
    )
    $results = foreach ($path in $paths) {
      if (Test-Path $path) {
        Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
      }
    }
    return ($results | ConvertTo-Json -Compress)
  `;

  try {
    const encoded = Buffer.from(psScript, 'utf16le').toString('base64');
    const { stdout } = await execAsync(`powershell -NoProfile -NonInteractive -EncodedCommand ${encoded}`);
    return JSON.parse(stdout || '[]');
  } catch (err) {
    return [];
  }
};

// ... (existing imports)

export const saveLogsToDb = (logs) => {
  const insert = db.prepare(`
    INSERT OR IGNORE INTO logs (hash, eventId, date, level, task, source, description, suspicious, segment, zone)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  
  try {
    db.exec('BEGIN TRANSACTION');
    for (const log of logs) {
      const logString = `${log.Id}-${log.TimeCreated}-${log.Message}`;
      const hash = crypto.createHash('md5').update(logString).digest('hex');
      
      insert.run(
        hash,
        String(log.Id),
        log.TimeCreated,
        log.LevelDisplayName,
        log.TaskDisplayName || 'System',
        log.ProviderName || 'System',
        log.Message,
        log.Suspicious ? 1 : 0,
        log.LogName || 'unknown',
        log.Zone || 'local'
      );
    }
    db.exec('COMMIT');
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch {}
    logger.error(err, 'Failed to save logs to DB');
  }
};

export const getHistoricalLogs = (limit = 1000) => {
  try {
    const rows = db.prepare('SELECT * FROM logs ORDER BY date DESC LIMIT ?').all(limit);
    // Defensive: validate and sanitize each row before returning
    return rows.map(row => ({
      ...row,
      // Ensure mitre field is valid — parse safely or null
      mitre: (() => {
        if (!row.mitre || row.mitre === 'null' || row.mitre === 'undefined') return null;
        try {
          const parsed = JSON.parse(row.mitre);
          return parsed && typeof parsed === 'object' ? parsed : null;
        } catch {
          return null;
        }
      })()
    }));
  } catch (err) {
    logger.error({ err: err.message }, 'Failed to fetch historical logs from DB');
    return [];
  }
};

export const collectSnapshot = async (force = false) => {
  const [system, network, files, winLogs, linuxLogs, androidLogs] = await Promise.all([
    getSystemTelemetry(force),
    getNetworkTraffic(force),
    getFileChanges(force),
    getWindowsLogs(50),
    getLinuxLogs(50),
    getAndroidLogs(50)
  ]);
  
  const allLogs = [...winLogs, ...linuxLogs, ...androidLogs];
  
  // Persist to DB for historical accuracy
  saveLogsToDb(allLogs);
  
  const analysis = await analyzeTelemetry(allLogs, network, files);
  
  return {
    system,
    network,
    files,
    logs: allLogs,
    analysis,
    ts: Date.now()
  };
};

let lastCpuSample = os.cpus();
export const getStats = async () => {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  
  const currentCpuSample = os.cpus();
  let idleDifference = 0;
  let totalDifference = 0;
  
  for (let i = 0; i < currentCpuSample.length; i++) {
    const prev = lastCpuSample[i].times;
    const curr = currentCpuSample[i].times;
    
    const prevTotal = Object.values(prev).reduce((a, b) => a + b, 0);
    const currTotal = Object.values(curr).reduce((a, b) => a + b, 0);
    
    totalDifference += currTotal - prevTotal;
    idleDifference += curr.idle - prev.idle;
  }
  lastCpuSample = currentCpuSample;
  
  const cpuUsage = totalDifference === 0 ? 0 : 100 - Math.floor(100 * idleDifference / totalDifference);

  return {
    cpu: cpuUsage.toFixed(1),
    memory: (((totalMem - freeMem) / totalMem) * 100).toFixed(1),
    uptime: os.uptime(),
    timestamp: Date.now()
  };
};
