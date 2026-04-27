/**
 * Real-World System Logs & Event IDs
 * Production-grade Windows Event Log monitoring with actual Event IDs
 */

export type RealLogEntry = {
  id: string;
  timestamp: number;
  eventId: number;
  logName: "Security" | "System" | "Application" | "Microsoft-Windows-Sysmon/Operational" | "Microsoft-Windows-PowerShell/Operational" | "Setup" | "ForwardedEvents";
  level: "Critical" | "Error" | "Warning" | "Information" | "Verbose";
  source: string;
  category: string;
  message: string;
  rawXml: string;
  mitreTechnique?: string;
  mitreTactic?: string;
  iocs?: string[];
  recommendation: string;
  falsePositiveRate: number; // 0-100, higher = more likely false positive
  severity: "critical" | "high" | "medium" | "low" | "informational";
};

// Real Windows Security Event IDs used in production SOC environments
export const CRITICAL_EVENT_IDS: Record<number, { name: string; description: string; mitreId: string; severity: RealLogEntry["severity"] }> = {
  // Account Management
  4720: { name: "User Account Created", description: "A user account was created", mitreId: "T1136.001", severity: "medium" },
  4722: { name: "User Account Enabled", description: "A user account was enabled", mitreId: "T1098", severity: "medium" },
  4723: { name: "Password Change Attempt", description: "An attempt was made to change an account's password", mitreId: "T1556", severity: "low" },
  4724: { name: "Password Reset Attempt", description: "An attempt was made to reset an account's password", mitreId: "T1556", severity: "medium" },
  4725: { name: "User Account Disabled", description: "A user account was disabled", mitreId: "T1098", severity: "low" },
  4726: { name: "User Account Deleted", description: "A user account was deleted", mitreId: "T1136.001", severity: "high" },
  4728: { name: "Member Added to Global Group", description: "A member was added to a security-enabled global group", mitreId: "T1098.004", severity: "high" },
  4732: { name: "Member Added to Local Group", description: "A member was added to a security-enabled local group", mitreId: "T1098.004", severity: "high" },
  4738: { name: "User Account Changed", description: "A user account was changed", mitreId: "T1098", severity: "medium" },
  4740: { name: "User Account Locked Out", description: "A user account was locked out", mitreId: "T1110", severity: "low" },
  4756: { name: "Member Added to Universal Group", description: "A member was added to a security-enabled universal group", mitreId: "T1098.004", severity: "high" },
  4767: { name: "User Account Unlocked", description: "A user account was unlocked", mitreId: "T1098", severity: "medium" },
  
  // Logon Events
  4624: { name: "Successful Logon", description: "An account was successfully logged on", mitreId: "T1078", severity: "informational" },
  4625: { name: "Failed Logon", description: "An account failed to log on", mitreId: "T1110", severity: "medium" },
  4634: { name: "Account Logoff", description: "An account was logged off", mitreId: "", severity: "informational" },
  4647: { name: "User Initiated Logoff", description: "User initiated logoff", mitreId: "", severity: "informational" },
  4648: { name: "Explicit Credential Use", description: "A logon was attempted using explicit credentials", mitreId: "T1078", severity: "medium" },
  4672: { name: "Special Privileges Assigned", description: "Special privileges assigned to new logon", mitreId: "T1134", severity: "high" },
  4768: { name: "Kerberos TGT Requested", description: "A Kerberos authentication ticket (TGT) was requested", mitreId: "T1558.003", severity: "medium" },
  4769: { name: "Kerberos Service Ticket Requested", description: "A Kerberos service ticket was requested", mitreId: "T1558", severity: "medium" },
  4771: { name: "Kerberos Pre-Auth Failed", description: "Kerberos pre-authentication failed", mitreId: "T1110", severity: "medium" },
  4776: { name: "Credential Validation", description: "The domain controller attempted to validate credentials", mitreId: "T1110", severity: "medium" },
  
  // Object Access
  4661: { name: "Handle Requested", description: "A handle to an object was requested", mitreId: "T1078", severity: "low" },
  4663: { name: "Object Access Attempt", description: "An attempt was made to access an object", mitreId: "T1078", severity: "low" },
  4656: { name: "Handle Requested (Fail)", description: "A handle to an object was requested (failure)", mitreId: "T1078", severity: "low" },
  4673: { name: "Privileged Service Called", description: "A privileged service was called", mitreId: "T1134", severity: "medium" },
  4674: { name: "Privileged Object Operation", description: "An operation was attempted on a privileged object", mitreId: "T1134", severity: "medium" },
  
  // Process Tracking
  4688: { name: "Process Created", description: "A new process has been created", mitreId: "T1204", severity: "informational" },
  4689: { name: "Process Exited", description: "A process has exited", mitreId: "", severity: "informational" },
  
  // System Events
  1102: { name: "Audit Log Cleared", description: "The audit log was cleared", mitreId: "T1070.001", severity: "critical" },
  4608: { name: "Windows Starting", description: "Windows is starting up", mitreId: "", severity: "informational" },
  4609: { name: "Windows Shutting Down", description: "Windows is shutting down", mitreId: "", severity: "informational" },
  1100: { name: "Event Log Service Shutdown", description: "The event logging service has shut down", mitreId: "T1070.001", severity: "high" },
  
  // Policy Changes
  4719: { name: "Audit Policy Changed", description: "System audit policy was changed", mitreId: "T1562.002", severity: "critical" },
  4739: { name: "Domain Policy Changed", description: "Domain Policy was changed", mitreId: "T1484", severity: "high" },
  4817: { name: "Audit Policy Modified", description: "Audit policy was modified", mitreId: "T1562.002", severity: "critical" },
  
  // Privilege Use
  576: { name: "Special Privilege Assigned", description: "Special privileges assigned to new logon", mitreId: "T1134", severity: "high" },
  577: { name: "Privileged Operation", description: "Privileged operation attempted", mitreId: "T1134", severity: "medium" },
  578: { name: "Privileged Object Access", description: "Privileged object accessed", mitreId: "T1134", severity: "medium" },
  
  // Account Lockout
  539: { name: "Logon Failure - Locked", description: "Logon failure - account locked out", mitreId: "T1110", severity: "low" },
  644: { name: "Account Locked Out", description: "User account locked out", mitreId: "T1110", severity: "low" },
  
  // Schannel / SSL
  36888: { name: "Schannel Fatal Alert", description: "A fatal alert was generated by Schannel", mitreId: "T1573", severity: "medium" },
  36874: { name: "SSL Certificate Request", description: "An SSL certificate request was received", mitreId: "T1573", severity: "low" },
};

// Sysmon Event IDs
export const SYSMON_EVENT_IDS: Record<number, { name: string; description: string; mitreId: string; severity: RealLogEntry["severity"] }> = {
  1: { name: "Process Create", description: "Process creation", mitreId: "T1204", severity: "informational" },
  2: { name: "File Creation Time Changed", description: "A process changed a file creation time", mitreId: "T1070.006", severity: "medium" },
  3: { name: "Network Connect", description: "Network connection detected", mitreId: "T1071", severity: "informational" },
  4: { name: "Sysmon Service State Changed", description: "Sysmon service state changed", mitreId: "", severity: "informational" },
  5: { name: "Process Terminated", description: "Process terminated", mitreId: "", severity: "informational" },
  6: { name: "Driver Loaded", description: "Driver loaded", mitreId: "T1068", severity: "medium" },
  7: { name: "Image Loaded", description: "Image loaded", mitreId: "T1073", severity: "low" },
  8: { name: "CreateRemoteThread", description: "CreateRemoteThread detected", mitreId: "T1055.002", severity: "critical" },
  9: { name: "RawAccessRead", description: "Raw disk access", mitreId: "T1003.002", severity: "high" },
  10: { name: "ProcessAccess", description: "Process accessed", mitreId: "T1003.001", severity: "high" },
  11: { name: "FileCreate", description: "File created", mitreId: "T1041", severity: "informational" },
  12: { name: "Registry Object Added/Deleted", description: "Registry object added or deleted", mitreId: "T1547.001", severity: "medium" },
  13: { name: "Registry Value Set", description: "Registry value set", mitreId: "T1547.001", severity: "medium" },
  14: { name: "Registry Object Renamed", description: "Registry object renamed", mitreId: "T1547.001", severity: "medium" },
  15: { name: "FileCreateStreamHash", description: "File create stream hash", mitreId: "T1567", severity: "medium" },
  16: { name: "Sysmon Config Change", description: "Sysmon configuration changed", mitreId: "T1562.001", severity: "critical" },
  17: { name: "Pipe Created", description: "Named pipe created", mitreId: "T1021.002", severity: "medium" },
  18: { name: "Pipe Connected", description: "Named pipe connected", mitreId: "T1021.002", severity: "medium" },
  19: { name: "WmiEventFilter", description: "WMI event filter activity detected", mitreId: "T1546.003", severity: "critical" },
  20: { name: "WmiEventConsumer", description: "WMI event consumer activity detected", mitreId: "T1546.003", severity: "critical" },
  21: { name: "WmiEventBinding", description: "WMI event binding activity detected", mitreId: "T1546.003", severity: "critical" },
  22: { name: "DnsQuery", description: "DNS query", mitreId: "T1071.004", severity: "informational" },
  23: { name: "FileDeleted", description: "File deleted", mitreId: "T1070.004", severity: "medium" },
  24: { name: "ClipboardChange", description: "Clipboard contents changed", mitreId: "T1115", severity: "low" },
  25: { name: "ProcessTampering", description: "Process tampering detected", mitreId: "T1055", severity: "critical" },
  26: { name: "FileDeleteLogged", description: "File delete logged", mitreId: "T1070.004", severity: "medium" },
  27: { name: "FileBlockExecutable", description: "File block executable", mitreId: "T1105", severity: "high" },
  28: { name: "FileBlockShredding", description: "File block shredding", mitreId: "T1070.004", severity: "high" },
  29: { name: "FileExecutableDetected", description: "File executable detected", mitreId: "T1105", severity: "medium" },
  255: { name: "Sysmon Error", description: "Sysmon error", mitreId: "", severity: "critical" },
};

// PowerShell Event IDs
export const POWERSHELL_EVENT_IDS: Record<number, { name: string; description: string; mitreId: string; severity: RealLogEntry["severity"] }> = {
  400: { name: "Engine Started", description: "Engine state is changed from None to Available", mitreId: "T1059.001", severity: "informational" },
  403: { name: "Engine Stopped", description: "Engine state is changed from Available to Stopped", mitreId: "T1059.001", severity: "informational" },
  600: { name: "Provider Started", description: "Provider is started", mitreId: "T1059.001", severity: "informational" },
  800: { name: "Pipeline Execution", description: "Pipeline execution details", mitreId: "T1059.001", severity: "informational" },
  4103: { name: "Module Logging", description: "Module logging", mitreId: "T1059.001", severity: "medium" },
  4104: { name: "Script Block Logging", description: "Script block text", mitreId: "T1059.001", severity: "high" },
  4105: { name: "Command Started", description: "Command started", mitreId: "T1059.001", severity: "informational" },
  4106: { name: "Command Stopped", description: "Command stopped", mitreId: "T1059.001", severity: "informational" },
};

// Real log templates for generation
export const REAL_LOG_TEMPLATES: Omit<RealLogEntry, "id" | "timestamp">[] = [
  {
    eventId: 4625,
    logName: "Security",
    level: "Warning",
    source: "Microsoft-Windows-Security-Auditing",
    category: "Logon",
    message: "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tWORKSTATION$\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x3E7\n\nLogon Type:\t\t\t10\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nCalling Workstation:\t\tWORKSTATION01\n\nNetwork Information:\n\tWorkstation Name:\tWORKSTATION01\n\tSource Network Address:\t192.168.1.105\n\tSource Port:\t\t49217",
    rawXml: `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4625</EventID>`,
    mitreTechnique: "T1110",
    mitreTactic: "Credential Access",
    recommendation: "Investigate source IP for brute force attack. Consider account lockout policy enforcement.",
    falsePositiveRate: 15,
    severity: "medium",
    iocs: ["192.168.1.105"],
  },
  {
    eventId: 4688,
    logName: "Security",
    level: "Information",
    source: "Microsoft-Windows-Security-Auditing",
    category: "Process Tracking",
    message: "A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tS-1-5-21-1234567890-1234567890-1234567890-1001\n\tAccount Name:\t\tjsmith\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0x12345678\n\nTarget Subject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nProcess Information:\n\tNew Process ID:\t\t0x1234\n\tNew Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n\tToken Elevation Type:\tTokenElevationTypeLimited (3)\n\tCreator Process ID:\t0x4567\n\tCreator Process Name:\tC:\\Windows\\explorer.exe\n\tProcess Command Line:\tpowershell.exe -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAwAA==",
    rawXml: `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4688</EventID>`,
    mitreTechnique: "T1059.001",
    mitreTactic: "Execution",
    recommendation: "Decode base64 command line. PowerShell with encoded commands is suspicious.",
    falsePositiveRate: 35,
    severity: "high",
    iocs: ["powershell.exe", "-enc", "base64_encoded"],
  },
  {
    eventId: 1,
    logName: "Microsoft-Windows-Sysmon/Operational",
    level: "Information",
    source: "Microsoft-Windows-Sysmon",
    category: "ProcessCreate",
    message: "Process Create:\nRuleName: technique_id=T1204,technique_name=User Execution\nUtcTime: 2024-01-15 14:32:18.123\nProcessGuid: {12345678-1234-1234-1234-123456789012}\nProcessId: 1234\nImage: C:\\Users\\jsmith\\AppData\\Local\\Temp\\invoice_2024.xlsm\nCommandLine: \"C:\\Users\\jsmith\\AppData\\Local\\Temp\\invoice_2024.xlsm\"\nCurrentDirectory: C:\\Users\\jsmith\\AppData\\Local\\Temp\\\nUser: CORP\\jsmith\nLogonGuid: {87654321-4321-4321-4321-210987654321}\nLogonId: 0x12345678\nTerminalSessionId: 1\nIntegrityLevel: Medium\nHashes: MD5=A3B8C9D4E5F678901234567890123456,SHA256=B4C9D0E5F6A7890123456789012345678901234567890ABCDEF1234567890ABCD\nParentProcessGuid: {11111111-2222-3333-4444-555555555555}\nParentProcessId: 5678\nParentImage: C:\\Windows\\explorer.exe\nParentCommandLine: C:\\Windows\\Explorer.EXE",
    rawXml: `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID>`,
    mitreTechnique: "T1204.002",
    mitreTactic: "Execution",
    recommendation: "Office document executed from temp folder. Likely phishing/macro malware. Isolate endpoint.",
    falsePositiveRate: 5,
    severity: "critical",
    iocs: ["invoice_2024.xlsm", "MD5:A3B8C9D4E5F678901234567890123456"],
  },
  {
    eventId: 8,
    logName: "Microsoft-Windows-Sysmon/Operational",
    level: "Critical",
    source: "Microsoft-Windows-Sysmon",
    category: "CreateRemoteThread",
    message: "CreateRemoteThread detected:\nRuleName: technique_id=T1055,technique_name=Process Injection\nUtcTime: 2024-01-15 14:32:45.789\nSourceProcessGuid: {12345678-1234-1234-1234-123456789012}\nSourceProcessId: 1234\nSourceImage: C:\\Users\\jsmith\\AppData\\Local\\Temp\\invoice_2024.xlsm\nTargetProcessGuid: {AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}\nTargetProcessId: 456\nTargetImage: C:\\Windows\\System32\\svchost.exe\nNewThreadId: 7890\nStartAddress: 0x00007FF123456789\nStartModule: -\nStartFunction: -",
    rawXml: `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>8</EventID>`,
    mitreTechnique: "T1055.002",
    mitreTactic: "Defense Evasion",
    recommendation: "CRITICAL: Process injection detected into svchost.exe. Likely malware. Immediate isolation required.",
    falsePositiveRate: 2,
    severity: "critical",
    iocs: ["svchost.exe", "0x00007FF123456789"],
  },
  {
    eventId: 1102,
    logName: "Security",
    level: "Critical",
    source: "Microsoft-Windows-Eventlog",
    category: "System",
    message: "The audit log was cleared.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-21-1234567890-1234567890-1234567890-500\n\tAccount Name:\t\tAdministrator\n\tAccount Domain:\t\tCORP\n\tLogon ID:\t\t0xABCDEF",
    rawXml: `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID>`,
    mitreTechnique: "T1070.001",
    mitreTactic: "Defense Evasion",
    recommendation: "CRITICAL: Event logs cleared by administrator account. Possible cover-up activity. Investigate immediately.",
    falsePositiveRate: 5,
    severity: "critical",
    iocs: [],
  },
];

// Generate a realistic log entry
export function generateRealLogEntry(): RealLogEntry {
  const template = REAL_LOG_TEMPLATES[Math.floor(Math.random() * REAL_LOG_TEMPLATES.length)];
  const timestamp = Date.now() - Math.floor(Math.random() * 24 * 60 * 60 * 1000); // Within last 24 hours
  
  return {
    id: `evt-${timestamp}-${Math.random().toString(36).slice(2, 6)}`,
    timestamp,
    ...template,
  };
}

// Export for batch generation
export function generateLogBatch(count: number): RealLogEntry[] {
  return Array.from({ length: count }, generateRealLogEntry);
}
