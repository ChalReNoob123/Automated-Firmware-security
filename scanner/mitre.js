/**
 * MITRE ATT&CK Technique Mappings for Windows System Scanner
 * Maps filesystem paths, patterns, and anomalies to ATT&CK techniques.
 */

export const TECHNIQUES = {
  'T1547.001': { id: 'T1547.001', name: 'Registry Run Keys / Startup Folder', tactic: 'Persistence', severity: 'high' },
  'T1053.005': { id: 'T1053.005', name: 'Scheduled Task', tactic: 'Execution', severity: 'high' },
  'T1543.003': { id: 'T1543.003', name: 'Windows Service', tactic: 'Persistence', severity: 'high' },
  'T1574.001': { id: 'T1574.001', name: 'DLL Search Order Hijacking', tactic: 'Persistence', severity: 'critical' },
  'T1574.002': { id: 'T1574.002', name: 'DLL Side-Loading', tactic: 'Defense Evasion', severity: 'critical' },
  'T1036.005': { id: 'T1036.005', name: 'Match Legitimate Name or Location', tactic: 'Defense Evasion', severity: 'high' },
  'T1218':     { id: 'T1218',     name: 'System Binary Proxy Execution', tactic: 'Defense Evasion', severity: 'medium' },
  'T1027':     { id: 'T1027',     name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', severity: 'high' },
  'T1564.004': { id: 'T1564.004', name: 'NTFS File Attributes (ADS)', tactic: 'Defense Evasion', severity: 'critical' },
  'T1059.001': { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', severity: 'medium' },
  'T1059.005': { id: 'T1059.005', name: 'Visual Basic', tactic: 'Execution', severity: 'medium' },
  'T1059.007': { id: 'T1059.007', name: 'JavaScript', tactic: 'Execution', severity: 'medium' },
  'T1105':     { id: 'T1105',     name: 'Ingress Tool Transfer', tactic: 'Command and Control', severity: 'high' },
  'T1074.001': { id: 'T1074.001', name: 'Local Data Staging', tactic: 'Collection', severity: 'medium' },
  'T1190':     { id: 'T1190',     name: 'Exploit Public-Facing Application', tactic: 'Initial Access', severity: 'critical' },
  'T1505.003': { id: 'T1505.003', name: 'Web Shell', tactic: 'Persistence', severity: 'critical' },
  'T1546.003': { id: 'T1546.003', name: 'WMI Event Subscription', tactic: 'Persistence', severity: 'high' },
  'T1112':     { id: 'T1112',     name: 'Modify Registry', tactic: 'Defense Evasion', severity: 'medium' },
  'T1055':     { id: 'T1055',     name: 'Process Injection', tactic: 'Defense Evasion', severity: 'critical' },
  'T1204.002': { id: 'T1204.002', name: 'Malicious File', tactic: 'Execution', severity: 'high' },
};

/** Scan target definitions with MITRE mapping and criticality */
export const SCAN_TARGETS = [
  {
    id: 'system32',
    path: 'C:\\Windows\\System32',
    label: 'System Binaries (System32)',
    category: 'system_binaries',
    criticality: 'critical',
    maxDepth: 1,
    extensions: ['.exe', '.dll', '.sys', '.drv', '.ocx'],
    mitre: ['T1574.001', 'T1574.002', 'T1036.005', 'T1218'],
  },
  {
    id: 'syswow64',
    path: 'C:\\Windows\\SysWOW64',
    label: 'System Binaries (SysWOW64)',
    category: 'system_binaries',
    criticality: 'critical',
    maxDepth: 1,
    extensions: ['.exe', '.dll', '.sys'],
    mitre: ['T1574.001', 'T1574.002', 'T1036.005'],
  },
  {
    id: 'scheduled_tasks',
    path: 'C:\\Windows\\System32\\Tasks',
    label: 'Scheduled Tasks',
    category: 'scheduled_tasks',
    criticality: 'high',
    maxDepth: 3,
    extensions: null,
    mitre: ['T1053.005'],
  },
  {
    id: 'legacy_tasks',
    path: 'C:\\Windows\\Tasks',
    label: 'Legacy Tasks',
    category: 'scheduled_tasks',
    criticality: 'high',
    maxDepth: 1,
    extensions: ['.job'],
    mitre: ['T1053.005'],
  },
  {
    id: 'registry_hives',
    path: 'C:\\Windows\\System32\\config',
    label: 'Registry Hives',
    category: 'registry',
    criticality: 'critical',
    maxDepth: 1,
    extensions: null,
    mitre: ['T1547.001', 'T1543.003', 'T1112'],
  },
  {
    id: 'appdata',
    path: null, // Resolved dynamically per user
    label: 'User AppData',
    category: 'user_data',
    criticality: 'medium',
    maxDepth: 2,
    extensions: ['.exe', '.dll', '.ps1', '.vbs', '.js', '.bat', '.cmd', '.hta', '.scr'],
    mitre: ['T1547.001', 'T1059.001', 'T1204.002'],
    resolvePath: () => {
      const home = process.env.USERPROFILE || process.env.HOME || '';
      return `${home}\\AppData`;
    },
  },
  {
    id: 'programdata',
    path: 'C:\\ProgramData',
    label: 'Machine-Wide App Data',
    category: 'program_data',
    criticality: 'medium',
    maxDepth: 2,
    extensions: ['.exe', '.dll', '.ps1', '.vbs', '.js', '.bat', '.cmd'],
    mitre: ['T1543.003', 'T1547.001'],
  },
  {
    id: 'win_temp',
    path: 'C:\\Windows\\Temp',
    label: 'Windows Temp',
    category: 'temp_files',
    criticality: 'high',
    maxDepth: 2,
    extensions: ['.exe', '.dll', '.ps1', '.vbs', '.js', '.bat', '.cmd', '.hta', '.scr', '.tmp'],
    mitre: ['T1105', 'T1204.002', 'T1027'],
  },
  {
    id: 'user_temp',
    path: null,
    label: 'User Temp',
    category: 'temp_files',
    criticality: 'high',
    maxDepth: 2,
    extensions: ['.exe', '.dll', '.ps1', '.vbs', '.js', '.bat', '.cmd', '.hta', '.scr'],
    mitre: ['T1105', 'T1204.002'],
    resolvePath: () => {
      const home = process.env.USERPROFILE || process.env.HOME || '';
      return `${home}\\AppData\\Local\\Temp`;
    },
  },
  {
    id: 'perflogs',
    path: 'C:\\PerfLogs',
    label: 'Performance Logs',
    category: 'perf_logs',
    criticality: 'low',
    maxDepth: 2,
    extensions: null,
    mitre: ['T1074.001'],
  },
  {
    id: 'machine_startup',
    path: 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp',
    label: 'Machine Startup Folder',
    category: 'startup',
    criticality: 'critical',
    maxDepth: 1,
    extensions: null,
    mitre: ['T1547.001'],
  },
  {
    id: 'user_startup',
    path: null,
    label: 'User Startup Folder',
    category: 'startup',
    criticality: 'critical',
    maxDepth: 1,
    extensions: null,
    mitre: ['T1547.001'],
    resolvePath: () => {
      const home = process.env.USERPROFILE || process.env.HOME || '';
      return `${home}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup`;
    },
  },
  {
    id: 'iis_root',
    path: 'C:\\inetpub\\wwwroot',
    label: 'IIS Web Root',
    category: 'web_server',
    criticality: 'critical',
    maxDepth: 3,
    extensions: ['.asp', '.aspx', '.php', '.jsp', '.ashx', '.asmx', '.exe', '.dll', '.ps1', '.cmd'],
    mitre: ['T1190', 'T1505.003'],
  },
];

/** Map file extension to likely MITRE technique */
export function techniquesByExtension(ext) {
  const map = {
    '.ps1': ['T1059.001'], '.psm1': ['T1059.001'], '.psd1': ['T1059.001'],
    '.vbs': ['T1059.005'], '.vbe': ['T1059.005'],
    '.js':  ['T1059.007'], '.jse': ['T1059.007'],
    '.hta': ['T1218'], '.msi': ['T1218'],
    '.exe': ['T1204.002'], '.scr': ['T1204.002'],
    '.dll': ['T1574.001', 'T1574.002'],
    '.sys': ['T1543.003'],
    '.asp': ['T1505.003'], '.aspx': ['T1505.003'],
    '.php': ['T1505.003'], '.jsp': ['T1505.003'],
  };
  return map[ext?.toLowerCase()] || [];
}

/** Determine if entropy suggests obfuscation */
export function isHighEntropy(entropy, ext) {
  const scriptExts = ['.ps1', '.vbs', '.js', '.bat', '.cmd', '.hta'];
  if (scriptExts.includes(ext?.toLowerCase())) return entropy > 5.5;
  return entropy > 7.2;
}
