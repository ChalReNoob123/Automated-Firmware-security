export type ThreatActor = {
  name: string;
  origin: string;
  motivation: string;
  ttps: string[];
  targetSectors: string[];
  sophistication: "Nation-State" | "Criminal" | "Hacktivist" | "Insider";
};

export type MalwareSignature = {
  id: string;
  name: string;
  family: string;
  type: "Ransomware" | "RAT" | "Infostealer" | "Rootkit" | "Wiper" | "Dropper" | "Botnet" | "Cryptominer";
  md5: string;
  sha256: string;
  sha1: string;
  vtDetections: number;
  vtTotal: number;
  vtRatio: string;
  firstSeen: string;
  lastSeen: string;
  description: string;
  iocs: string[];
  mitreIds: string[];
  severity: "low" | "medium" | "high" | "critical";
  yara: string;
};

export type IOC = {
  id: string;
  type: "ip" | "domain" | "hash" | "url" | "email" | "registry";
  value: string;
  confidence: number;
  severity: "low" | "medium" | "high" | "critical";
  source: string;
  tags: string[];
  firstSeen: number;
  lastSeen: number;
  hits: number;
  malwareFamily?: string;
  action: "block" | "monitor" | "quarantine";
};

export const THREAT_ACTORS: ThreatActor[] = [
  {
    name: "APT29 (Cozy Bear)",
    origin: "Russia",
    motivation: "Espionage, Intelligence Collection",
    ttps: ["T1566", "T1078", "T1071", "T1573", "T1003"],
    targetSectors: ["Government", "Think Tanks", "Healthcare"],
    sophistication: "Nation-State"
  },
  {
    name: "APT41 (Double Dragon)",
    origin: "China",
    motivation: "Espionage + Financial Gain",
    ttps: ["T1190", "T1059", "T1055", "T1486", "T1558"],
    targetSectors: ["Technology", "Healthcare", "Telecommunications"],
    sophistication: "Nation-State"
  },
  {
    name: "Lazarus Group",
    origin: "North Korea",
    motivation: "Financial, Sanctions Evasion",
    ttps: ["T1566", "T1486", "T1021", "T1048", "T1543"],
    targetSectors: ["Financial", "Cryptocurrency", "Defense"],
    sophistication: "Nation-State"
  },
  {
    name: "FIN7 (Carbanak)",
    origin: "Eastern Europe",
    motivation: "Financial Crime",
    ttps: ["T1566", "T1204", "T1059", "T1547", "T1048"],
    targetSectors: ["Retail", "Financial", "Hospitality"],
    sophistication: "Criminal"
  },
  {
    name: "LockBit 3.0",
    origin: "Russia (RaaS)",
    motivation: "Ransomware Extortion",
    ttps: ["T1486", "T1490", "T1070", "T1562", "T1021"],
    targetSectors: ["Healthcare", "Manufacturing", "Legal"],
    sophistication: "Criminal"
  },
];

export const MALWARE_SIGNATURES: MalwareSignature[] = [
  {
    id: "mal-001",
    name: "Mimikatz v2.2.0",
    family: "Mimikatz",
    type: "Infostealer",
    md5: "e4b60e87e1d3a520a8e8b8d66c7d0ade",
    sha256: "92b45fc3f0b0c5c08cd2ae2e31f37f7a6ef5e0b9c3f1d83a5e9cf31b70a7d4e1",
    sha1: "71ee7da0e8af0c63c14b7be4b6a05d36e3e4d5f8",
    vtDetections: 67,
    vtTotal: 72,
    vtRatio: "67/72",
    firstSeen: "2014-09-14",
    lastSeen: "2025-11-01",
    description: "Open-source credential dumper targeting LSASS memory, SAM database, and Active Directory. Used by virtually every sophisticated threat actor.",
    iocs: ["sekurlsa::", "lsadump::sam", "kerberos::golden", "C:\\Users\\Public\\mim.exe"],
    mitreIds: ["T1003", "T1558", "T1134"],
    severity: "critical",
    yara: `rule Mimikatz {\n  meta:\n    description = "Mimikatz credential dumper"\n    author = "SOC Analyst"\n  strings:\n    $a = "sekurlsa::"\n    $b = "kerberos::golden"\n    $c = "lsadump::sam"\n    $d = { 6D 69 6D 69 6B 61 74 7A }\n  condition:\n    any of them\n}`
  },
  {
    id: "mal-002",
    name: "CobaltStrike Beacon 4.8",
    family: "Cobalt Strike",
    type: "RAT",
    md5: "d41d8cd98f00b204e9800998ecf8427e",
    sha256: "a5f3b14c9e2d87f4c0a1e6b8d2f9c3e5b7a0d4f6e8c1b3a5d7f9e2c4b6a8d0f2",
    sha1: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    vtDetections: 58,
    vtTotal: 72,
    vtRatio: "58/72",
    firstSeen: "2020-03-01",
    lastSeen: "2025-11-01",
    description: "Commercial C2 framework widely abused by threat actors. Beacon implant provides full RAT capabilities including keylogging, credential theft, and lateral movement.",
    iocs: ["JA3: 51c64c77e60f3980eea90869b68d58d8", "HTTP GET /jquery-3.3.1.min.js", "pipe: \\msagent_", "beacon sleep 60"],
    mitreIds: ["T1071", "T1573", "T1055", "T1021"],
    severity: "critical",
    yara: `rule CobaltStrike_Beacon {\n  meta:\n    description = "CobaltStrike Beacon Payload"\n    author = "SOC Analyst"\n  strings:\n    $a = { 69 68 69 68 69 6B }\n    $b = "ReflectiveLoader"\n    $c = "%s (admin)" fullword\n    $d = "beacon" nocase\n  condition:\n    2 of them\n}`
  },
  {
    id: "mal-003",
    name: "LockBit 3.0 Ransomware",
    family: "LockBit",
    type: "Ransomware",
    md5: "f3c6a7b4e9d2c8f1a5b7c3e9d4f6a8b0",
    sha256: "e1f3a5b7c9d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4",
    sha1: "b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1",
    vtDetections: 71,
    vtTotal: 72,
    vtRatio: "71/72",
    firstSeen: "2022-06-27",
    lastSeen: "2025-10-28",
    description: "LockBit 3.0 (Black) ransomware with triple extortion. Deletes shadow copies, terminates security tools, and encrypts files with custom extension.",
    iocs: ["vssadmin delete shadows /all /quiet", "bcdedit /set {default} recoveryenabled No", "*.lockbit extension", "Restore-My-Files.txt"],
    mitreIds: ["T1486", "T1490", "T1562", "T1070"],
    severity: "critical",
    yara: `rule LockBit3 {\n  meta:\n    description = "LockBit 3.0 Ransomware"\n  strings:\n    $a = "LockBit" wide\n    $b = "vssadmin delete shadows"\n    $c = ".lockbit" wide\n    $d = "Restore-My-Files.txt" wide\n  condition:\n    2 of them\n}`
  },
  {
    id: "mal-004",
    name: "RedLine Stealer v6",
    family: "RedLine",
    type: "Infostealer",
    md5: "8b1a3c5e7f9b2d4f6a8c0e2g4i6k8m0",
    sha256: "c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4",
    sha1: "d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2",
    vtDetections: 62,
    vtTotal: 72,
    vtRatio: "62/72",
    firstSeen: "2020-11-01",
    lastSeen: "2025-10-30",
    description: "MaaS infostealer targeting browser credentials, cryptocurrency wallets, VPN credentials, and Discord tokens. Exfiltrates to Telegram C2.",
    iocs: ["Login Data SQLite access", "wallet.dat enumeration", "telegram bot C2", "%LocalAppData%\\Google\\Chrome\\User Data\\Default\\Login Data"],
    mitreIds: ["T1003", "T1005", "T1071", "T1048"],
    severity: "high",
    yara: `rule RedLineStealer {\n  meta:\n    description = "RedLine Stealer"\n  strings:\n    $a = "Login Data" wide\n    $b = "wallet.dat" wide\n    $c = "Telegram" wide\n    $d = "ChromeVersion" wide\n  condition:\n    3 of them\n}`
  },
  {
    id: "mal-005",
    name: "XMRig Cryptominer",
    family: "XMRig",
    type: "Cryptominer",
    md5: "1a3c5e7f9b2d4f6a8c0e2f4a6b8c0d2e",
    sha256: "b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2",
    sha1: "e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4",
    vtDetections: 51,
    vtTotal: 72,
    vtRatio: "51/72",
    firstSeen: "2018-01-15",
    lastSeen: "2025-11-01",
    description: "Open-source Monero miner commonly deployed as a secondary payload. High CPU usage, network connections to Monero pools, and process injection into legitimate processes.",
    iocs: ["pool.minexmr.com:4444", "stratum+tcp://", "CPU usage > 80% sustained", "xmrig.exe or renamed variant"],
    mitreIds: ["T1496", "T1055", "T1036"],
    severity: "medium",
    yara: `rule XMRig {\n  meta:\n    description = "XMRig Cryptominer"\n  strings:\n    $a = "stratum+tcp://" wide\n    $b = "xmrig" nocase wide\n    $c = "donate-level" wide\n    $d = "pool.minexmr.com" wide\n  condition:\n    2 of them\n}`
  },
];

export const LIVE_IOCS: IOC[] = [
  {
    id: "ioc-001", type: "ip", value: "185.220.101.47", confidence: 96, severity: "critical",
    source: "Threat Intelligence Feed (TOR exit node + C2)", tags: ["TOR", "C2", "Brute-Force"],
    firstSeen: Date.now() - 7_200_000, lastSeen: Date.now() - 120_000, hits: 47,
    malwareFamily: "Cobalt Strike", action: "block"
  },
  {
    id: "ioc-002", type: "ip", value: "91.223.77.18", confidence: 88, severity: "critical",
    source: "VirusTotal / AbuseIPDB", tags: ["Ransomware", "LockBit", "RaaS"],
    firstSeen: Date.now() - 86_400_000, lastSeen: Date.now() - 3_600_000, hits: 12,
    malwareFamily: "LockBit 3.0", action: "block"
  },
  {
    id: "ioc-003", type: "domain", value: "update-microsoft-sync[.]com", confidence: 94, severity: "critical",
    source: "MISP Community / Passive DNS", tags: ["Phishing", "C2", "DGA"],
    firstSeen: Date.now() - 172_800_000, lastSeen: Date.now() - 600_000, hits: 8,
    malwareFamily: "RedLine Stealer", action: "block"
  },
  {
    id: "ioc-004", type: "hash", value: "92b45fc3f0b0c5c08cd2ae2e31f37f7a6ef5e0b9", confidence: 99, severity: "critical",
    source: "VirusTotal (67/72 detections)", tags: ["Mimikatz", "CredDump", "LSASS"],
    firstSeen: Date.now() - 43_200_000, lastSeen: Date.now() - 1_800_000, hits: 3,
    malwareFamily: "Mimikatz", action: "quarantine"
  },
  {
    id: "ioc-005", type: "url", value: "http://185.220.101.47/p.ps1", confidence: 97, severity: "critical",
    source: "Endpoint telemetry / Registry analysis", tags: ["PowerShell", "Dropper", "Stage2"],
    firstSeen: Date.now() - 900_000, lastSeen: Date.now() - 300_000, hits: 2,
    malwareFamily: "Cobalt Strike", action: "block"
  },
  {
    id: "ioc-006", type: "domain", value: "pool.minexmr[.]com", confidence: 78, severity: "medium",
    source: "XMRig threat intel", tags: ["Cryptominer", "Monero", "Resource hijack"],
    firstSeen: Date.now() - 259_200_000, lastSeen: Date.now() - 86_400_000, hits: 6,
    malwareFamily: "XMRig", action: "block"
  },
  {
    id: "ioc-007", type: "email", value: "invoice-urgent@secureupd8.ru", confidence: 85, severity: "high",
    source: "Phishing campaign feed", tags: ["Phishing", "BEC", "Initial Access"],
    firstSeen: Date.now() - 604_800_000, lastSeen: Date.now() - 7_200_000, hits: 19,
    malwareFamily: "RedLine Stealer", action: "quarantine"
  },
  {
    id: "ioc-008", type: "registry", value: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateHelper", confidence: 92, severity: "high",
    source: "Registry anomaly detection", tags: ["Persistence", "Autorun", "T1547"],
    firstSeen: Date.now() - 1_800_000, lastSeen: Date.now() - 300_000, hits: 1,
    malwareFamily: "Unknown dropper", action: "quarantine"
  },
];
