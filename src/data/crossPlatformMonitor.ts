/**
 * Cross-Platform Security Monitoring Engine
 * Windows & Linux OS File & Activity Detection
 */

export type OperatingSystem = "windows" | "linux" | "macos";
export type FileAction = "created" | "modified" | "deleted" | "executed" | "accessed" | "permission_changed";
export type PermissionChange = "chmod" | "chown" | "setuid" | "setgid" | "acl_modified";

export type CrossPlatformFile = {
  id: string;
  os: OperatingSystem;
  host: string;
  path: string;
  filename: string;
  extension: string;
  owner: string;
  group: string;
  permissions: string;
  size: number;
  hash: string;
  modified: number;
  action: FileAction;
  suspicious: boolean;
  riskScore: number;
  reason: string;
  mitreTechnique: string;
  processName?: string;
  processId?: number;
  userContext?: string;
};

export type LinuxAuditEvent = {
  id: string;
  timestamp: number;
  host: string;
  eventType: "syscall" | "file_watch" | "user_login" | "privilege" | "network" | "cron" | "system";
  auditKey: string;
  uid: number;
  auid: number;
  gid: number;
  pid: number;
  ppid: number;
  comm: string;
  exe: string;
  syscall: string;
  success: "yes" | "no";
  syscallReturn: string;
  arguments: Record<string, string>;
  resource?: string;
  rawLog: string;
  suspicious: boolean;
  mitreTechnique: string;
  threatCategory: string;
};

export type WindowsFileActivity = {
  id: string;
  timestamp: number;
  host: string;
  eventId: number;
  processName: string;
  processId: number;
  targetPath: string;
  accessMask: string;
  fileName?: string;
  fileObject?: string;
  status: "success" | "failure";
  userAccount: string;
  privilegesUsed?: string;
  suspicious: boolean;
  mitreTechnique: string;
  rawXml: string;
};

export type EncryptedData = {
  id: string;
  type: "file" | "connection" | "registry" | "memory" | "archive" | "database" | "network";
  host: string;
  path?: string;
  algorithm: string;
  keySize: number;
  isDecrypted: boolean;
  decryptedContent?: string;
  originalSize: number;
  entropy: number;
  suspicious: boolean;
  reason: string;
  mitreTechnique?: string;
  classification: "confidential" | "secret" | "top_secret" | "public";
  iocs?: string[];
};

export const CRITICAL_LINUX_FILES = [
  "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
  "/etc/crontab", "/etc/cron.d/", "/etc/systemd/system/",
  "/root/.ssh/authorized_keys", "/var/log/auth.log", "/var/log/secure",
  "/var/log/audit/audit.log", "/etc/audit/audit.rules", "/etc/pam.d/",
  "/boot/grub2/grub.cfg", "/etc/ld.so.preload", "/etc/ld.so.conf",
  "/etc/fstab", "/etc/hosts", "/etc/resolv.conf", "/proc/self/mountinfo",
  "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/ssh",
  "/lib/systemd/system/", "/etc/docker/daemon.json", "/etc/kubernetes/",
  "/var/lib/tor/", "/tmp/.ICE-unix/", "/dev/shm/", "/var/tmp/",
  "/etc/nginx/nginx.conf", "/etc/apache2/", "/etc/mysql/",
  "/var/lib/mysql/", "/etc/postgresql/", "/etc/redis/",
  "/etc/vault/", "/etc/consul/", "/etc/envoy/",
];

export const CRITICAL_WINDOWS_FILES = [
  "C:\\Windows\\System32\\config\\SYSTEM",
  "C:\\Windows\\System32\\config\\SAM",
  "C:\\Windows\\System32\\config\\SECURITY",
  "C:\\Windows\\System32\\drivers\\etc\\hosts",
  "C:\\Windows\\System32\\drivers\\etc\\lmhosts",
  "C:\\Windows\\System32\\drivers\\etc\\networks",
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\profile.ps1",
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\",
  "C:\\Windows\\System32\\GroupPolicy\\",
  "C:\\Windows\\System32\\Spool\\Drivers\\Color\\",
  "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
  "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
  "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
  "C:\\Windows\\System32\\config\\DEFAULT",
  "C:\\Windows\\System32\\config\\SOFTWARE",
  "C:\\Windows\\System32\\inetsrv\\",
  "C:\\Windows\\System32\\msvcrt.dll",
  "C:\\Windows\\System32\\ntoskrnl.exe",
  "C:\\Windows\\System32\\cmd.exe",
  "C:\\Windows\\System32\\rundll32.exe",
  "C:\\Windows\\System32\\regsvr32.exe",
  "C:\\Windows\\System32\\mshta.exe",
  "C:\\Windows\\System32\\certutil.exe",
  "C:\\Windows\\System32\\bitsadmin.exe",
  "C:\\Windows\\System32\\wscript.exe",
  "C:\\Windows\\System32\\cscript.exe",
  "C:\\Windows\\System32\\powershell.exe",
  "C:\\Windows\\SysWOW64\\",
];

export const ENCRYPTION_ALGORITHMS = {
  symmetric: ["AES-128", "AES-192", "AES-256", "DES", "3DES", "Blowfish", "ChaCha20", "RC4", "XOR"],
  asymmetric: ["RSA-1024", "RSA-2048", "RSA-4096", "ECC-P256", "ECC-P384", "Ed25519"],
  hashing: ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "BCrypt", "Argon2", "Scrypt"],
  transport: ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "SSL 2.0", "SSL 3.0", "SSH"],
};

export const LINUX_AUDIT_RULES = [
  { rule: "-w /etc/passwd -p wa -k passwd_changes", description: "Monitor user account changes" },
  { rule: "-w /etc/shadow -p wa -k shadow_changes", description: "Monitor password hash changes" },
  { rule: "-w /etc/sudoers -p wa -k sudoers_changes", description: "Monitor sudo configuration" },
  { rule: "-w /etc/ssh/sshd_config -p wa -k ssh_config", description: "Monitor SSH configuration" },
  { rule: "-a always,exit -F arch=b64 -S execve -k execve_syscalls", description: "Track command execution" },
  { rule: "-a always,exit -F arch=b64 -S connect -k network_connections", description: "Monitor network connections" },
  { rule: "-w /var/log/auth.log -p wa -k auth_logs", description: "Monitor authentication logs" },
  { rule: "-a always,exit -F dir=/tmp -p x -k tmp_execution", description: "Track /tmp executions" },
  { rule: "-w /etc/crontab -p wa -k cron_changes", description: "Monitor scheduled tasks" },
  { rule: "-a always,exit -F arch=b64 -S mount -k mount_events", description: "Track filesystem mounts" },
  { rule: "-w /etc/ld.so.preload -p wa -k ld_preload", description: "Monitor LD_PRELOAD hijacking" },
  { rule: "-w /root/.ssh/ -p rwa -k root_ssh_keys", description: "Monitor root SSH access" },
];

// Linux audit event templates
export const LINUX_AUDIT_TEMPLATES: Omit<LinuxAuditEvent, "id" | "timestamp">[] = [
  {
    host: "ubuntu-server-01",
    eventType: "syscall",
    auditKey: "execve_syscalls",
    uid: 0,
    auid: 1000,
    gid: 0,
    pid: 4521,
    ppid: 3012,
    comm: "python3",
    exe: "/usr/bin/python3",
    syscall: "execve",
    success: "yes",
    syscallReturn: "success",
    arguments: { "cmdline": "/usr/bin/python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", "cwd": "/tmp" },
    resource: "/usr/bin/python3",
    rawLog: `type=SYSCALL msg=audit(1700000000.123:4521): arch=c000003e syscall=59 success=yes exit=0 a0=55a6b8c7d900 a1=7ffd4a5b6c80 a2=7ffd4a5b6c88 a3=0 items=1 ppid=3012 pid=4521 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=8 comm="python3" exe="/usr/bin/python3" key="execve_syscalls"`,
    suspicious: true,
    mitreTechnique: "T1059.006",
    threatCategory: "Suspicious Python Execution",
  },
  {
    host: "web-server-prod",
    eventType: "file_watch",
    auditKey: "passwd_changes",
    uid: 0,
    auid: 0,
    gid: 0,
    pid: 7842,
    ppid: 7841,
    comm: "useradd",
    exe: "/usr/sbin/useradd",
    syscall: "openat",
    success: "yes",
    syscallReturn: "success",
    arguments: { "filename": "/etc/passwd", "flags": "O_WRONLY|O_CREAT", "mode": "0644" },
    resource: "/etc/passwd",
    rawLog: `type=SYSCALL msg=audit(1700000100.456:7842): arch=c000003e syscall=257 success=yes exit=0 a0=ffffff9c a1=7ffd12345678 a2=241 a3=1b6 items=1 ppid=7841 pid=7842 auid=0 uid=0 gid=0 comm="useradd" exe="/usr/sbin/useradd" key="passwd_changes"`,
    suspicious: true,
    mitreTechnique: "T1136",
    threatCategory: "Account Creation",
  },
  {
    host: "database-01",
    eventType: "syscall",
    auditKey: "network_connections",
    uid: 33,
    auid: 33,
    gid: 33,
    pid: 9102,
    ppid: 9101,
    comm: "mysqld",
    exe: "/usr/sbin/mysqld",
    syscall: "connect",
    success: "yes",
    syscallReturn: "success",
    arguments: { "saddr": "10.10.20.50:3306", "daddr": "185.220.101.47:4444" },
    rawLog: `type=SYSCALL msg=audit(1700000200.789:9102): arch=c000003e syscall=42 success=yes exit=0 a0=1a a1=7ffdabcdef01 a2=10 items=0 ppid=9101 pid=9102 auid=33 uid=33 gid=33 comm="mysqld" key="network_connections"`,
    suspicious: true,
    mitreTechnique: "T1071",
    threatCategory: "C2 Communication",
  },
  {
    host: "dev-workstation-07",
    eventType: "privilege",
    auditKey: "privilege_escalation",
    uid: 1001,
    auid: 1001,
    gid: 1001,
    pid: 12345,
    ppid: 12344,
    comm: "sudo",
    exe: "/usr/bin/sudo",
    syscall: "execve",
    success: "yes",
    syscallReturn: "success",
    arguments: { "cmdline": "sudo /bin/bash", "terminal": "pts/2" },
    rawLog: `type=USER msg=audit(1700000300.012:12345): pid=12345 uid=1001 auid=1001 ses=12 msg='op=PAM:authentication grantors=pam_unix acct="analyst1" exe="/usr/bin/sudo" terminal=/dev/pts/2 res=success'`,
    suspicious: true,
    mitreTechnique: "T1548",
    threatCategory: "Privilege Escalation",
  },
  {
    host: "kubernetes-worker-03",
    eventType: "cron",
    auditKey: "cron_changes",
    uid: 0,
    auid: 0,
    gid: 0,
    pid: 8765,
    ppid: 8764,
    comm: "crontab",
    exe: "/usr/bin/crontab",
    syscall: "openat",
    success: "yes",
    syscallReturn: "success",
    arguments: { "filename": "/var/spool/cron/crontabs/root", "action": "write" },
    resource: "/var/spool/cron/crontabs/root",
    rawLog: `type=SYSCALL msg=audit(1700000400.345:8765): arch=c000003e syscall=257 success=yes exit=0 items=1 ppid=8764 pid=8765 uid=0 comm="crontab" key="cron_changes"`,
    suspicious: true,
    mitreTechnique: "T1053.003",
    threatCategory: "Cron Persistence",
  },
];

// Encrypted data templates
export const ENCRYPTED_DATA_TEMPLATES: Omit<EncryptedData, "id">[] = [
  {
    type: "file",
    host: "web-server-prod",
    path: "/opt/backup/customer_data.sql.gz.enc",
    algorithm: "AES-256",
    keySize: 256,
    isDecrypted: false,
    originalSize: 524288000,
    entropy: 7.98,
    suspicious: false,
    reason: "Legitimate encrypted backup - AES-256 with proper key management",
    classification: "confidential",
  },
  {
    type: "file",
    host: "workstation-12",
    path: "/tmp/.hidden/exfil_archive.tar.gz.enc",
    algorithm: "XOR",
    keySize: 8,
    isDecrypted: true,
    decryptedContent: "SSH keys, database credentials, API tokens",
    originalSize: 15728640,
    entropy: 4.23,
    suspicious: true,
    reason: "Weak XOR encryption used for exfiltration staging - indicates data theft preparation",
    mitreTechnique: "T1560",
    classification: "secret",
    iocs: ["185.220.101.47:443", "SHA256:e93a7b...", "base64_encoded_ssh_key"],
  },
  {
    type: "connection",
    host: "database-02",
    path: "TLS 1.2 → 45.33.32.156:8443",
    algorithm: "RSA-2048 + AES-128-GCM",
    keySize: 2048,
    isDecrypted: false,
    originalSize: 0,
    entropy: 7.82,
    suspicious: true,
    reason: "Suspicious encrypted connection to known malicious IP - potential C2 channel",
    mitreTechnique: "T1573",
    classification: "top_secret",
    iocs: ["45.33.32.156", "JA3: 51c64c77e60f3980eea90869b68d58d8"],
  },
  {
    type: "memory",
    host: "dc01.corp.local",
    path: "LSASS.EXE memory region",
    algorithm: "AES-256-CTS",
    keySize: 256,
    isDecrypted: true,
    decryptedContent: "NTLM hashes, Kerberos tickets, cleartext passwords",
    originalSize: 10485760,
    entropy: 6.45,
    suspicious: true,
    reason: "LSASS memory dump detected - indicates credential theft attempt via Mimikatz",
    mitreTechnique: "T1003.001",
    classification: "top_secret",
    iocs: ["SHA256:92b45fc3f0b0c5c08cd2ae2e31f37f7a", "mimikatz.exe"],
  },
  {
    type: "archive",
    host: "file-server-01",
    path: "/var/staging/sensitive_reports.zip.enc",
    algorithm: "AES-256",
    keySize: 256,
    isDecrypted: false,
    originalSize: 209715200,
    entropy: 7.95,
    suspicious: true,
    reason: "Large encrypted archive in unusual staging directory - potential exfiltration payload",
    mitreTechnique: "T1560.002",
    classification: "secret",
  },
  {
    type: "database",
    host: "mongo-prod-01",
    path: "MongoDB encrypted field: payment_cards",
    algorithm: "AES-256-CTR",
    keySize: 256,
    isDecrypted: false,
    originalSize: 0,
    entropy: 7.89,
    suspicious: false,
    reason: "Field-level encryption properly implemented for PCI DSS compliance",
    classification: "top_secret",
  },
  {
    type: "network",
    host: "proxy-internet",
    path: "HTTPS tunnel: office → tor-exit-node",
    algorithm: "TLS 1.3 (ECDHE-RSA-AES256-GCM)",
    keySize: 256,
    isDecrypted: false,
    originalSize: 0,
    entropy: 7.99,
    suspicious: true,
    reason: "Encrypted tunnel to TOR exit node detected - potential covert communication channel",
    mitreTechnique: "T1090",
    classification: "secret",
    iocs: ["185.220.101.x", "tor exit node"],
  },
];

export function generateLinuxAuditEvent(): LinuxAuditEvent {
  const template = LINUX_AUDIT_TEMPLATES[Math.floor(Math.random() * LINUX_AUDIT_TEMPLATES.length)];
  return {
    ...template,
    id: `linux-audit-${Math.random().toString(36).slice(2, 10)}`,
    timestamp: Date.now() - Math.floor(Math.random() * 30000),
  };
}

export function generateWindowsFileActivity(): WindowsFileActivity {
  const activities = [
    {
      eventId: 4656,
      processName: "svchost.exe",
      processId: 912,
      targetPath: "C:\\Windows\\System32\\config\\SAM",
      accessMask: "0x1000",
      status: "failure" as const,
      userAccount: "NT AUTHORITY\\SYSTEM",
      suspicious: true,
      mitreTechnique: "T1003.002",
    },
    {
      eventId: 4663,
      processName: "powershell.exe",
      processId: 4521,
      targetPath: "C:\\Windows\\System32\\drivers\\etc\\hosts",
      accessMask: "0x2",
      status: "success" as const,
      userAccount: "CORP\\admin",
      suspicious: true,
      mitreTechnique: "T1565.001",
    },
    {
      eventId: 4656,
      processName: "lsass.exe",
      processId: 620,
      targetPath: "\\Device\\HarddiskVolume1\\Windows\\System32\\config\\SECURITY",
      accessMask: "0x100080",
      status: "success" as const,
      userAccount: "NT AUTHORITY\\SYSTEM",
      suspicious: true,
      mitreTechnique: "T1003.001",
    },
  ];
  const activity = activities[Math.floor(Math.random() * activities.length)];
  return {
    ...activity,
    id: `win-file-${Math.random().toString(36).slice(2, 10)}`,
    timestamp: Date.now() - Math.floor(Math.random() * 20000),
    host: "WS-FINANCE-04",
    rawXml: `<Event><System><EventID>${activity.eventId}</EventID></System></Event>`,
  };
}

export function analyzeEntropy(data: string): number {
  const freq: Record<string, number> = {};
  for (const char of data) {
    freq[char] = (freq[char] || 0) + 1;
  }
  const len = data.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function isEncryptedContent(data: string): { isEncrypted: boolean; confidence: number; entropy: number } {
  const entropy = analyzeEntropy(data);
  const isEncrypted = entropy > 7.0;
  const confidence = isEncrypted ? Math.min(100, Math.round((entropy / 8) * 100)) : Math.round((entropy / 8) * 100);
  return { isEncrypted, confidence, entropy };
}
