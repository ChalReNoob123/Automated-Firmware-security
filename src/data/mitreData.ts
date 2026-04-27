export type MitreTactic = {
  id: string;
  name: string;
  shortName: string;
  description: string;
  techniques: MitreTechnique[];
};

export type MitreTechnique = {
  id: string;
  name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  subTechniques?: string[];
  detectionLogic: string;
  iocPatterns: string[];
  mitigation: string;
  dataSource: string;
};

export const MITRE_TACTICS: MitreTactic[] = [
  {
    id: "TA0001", name: "Initial Access", shortName: "InitAccess",
    description: "Techniques to gain initial foothold within a network.",
    techniques: [
      {
        id: "T1190", name: "Exploit Public-Facing Application", severity: "critical",
        description: "Adversaries exploit weaknesses in internet-facing applications.",
        detectionLogic: "Anomalous HTTP status codes, unusual URI patterns, WAF bypass attempts",
        iocPatterns: ["../../etc/passwd", "' OR 1=1", "<script>alert(", "cmd.exe /c"],
        mitigation: "Regular patching, WAF, input validation, network segmentation",
        dataSource: "Application logs, Network traffic, IDS",
        subTechniques: ["T1190.001 – SQL Injection", "T1190.002 – Command Injection"]
      },
      {
        id: "T1566", name: "Phishing", severity: "high",
        description: "Adversaries send malicious emails with links or attachments.",
        detectionLogic: "Malicious attachment hashes, suspicious sender domains, embedded macros",
        iocPatterns: [".doc macro", "powershell -enc", "base64 payload", "vbscript"],
        mitigation: "Email filtering, user training, attachment sandboxing, DMARC/DKIM",
        dataSource: "Email gateway, Endpoint telemetry, DNS logs",
        subTechniques: ["T1566.001 – Spearphishing Attachment", "T1566.002 – Spearphishing Link"]
      },
    ]
  },
  {
    id: "TA0002", name: "Execution", shortName: "Exec",
    description: "Techniques resulting in adversary-controlled code running on a local or remote system.",
    techniques: [
      {
        id: "T1059", name: "Command and Scripting Interpreter", severity: "high",
        description: "Adversaries abuse command and script interpreters to execute commands.",
        detectionLogic: "Suspicious PowerShell, WScript, Cmd.exe, encoded commands, LOLBAS usage",
        iocPatterns: ["powershell -nop -w hidden", "cmd.exe /c whoami", "wscript.exe", "-EncodedCommand"],
        mitigation: "PowerShell constrained language mode, script block logging, AppLocker",
        dataSource: "Process creation logs (Sysmon ID 1), Script block logs, 4688",
        subTechniques: ["T1059.001 – PowerShell", "T1059.003 – Windows Command Shell", "T1059.005 – Visual Basic"]
      },
      {
        id: "T1204", name: "User Execution", severity: "medium",
        description: "Adversaries rely on user action to execute malicious code.",
        detectionLogic: "Office macro execution, double-extension files, LNK file spawning processes",
        iocPatterns: ["WINWORD.EXE spawning cmd", "mshta.exe", ".lnk execution", "AutoOpen macro"],
        mitigation: "Disable macros, MOTW enforcement, user training, application control",
        dataSource: "Process creation, Office audit logs, Sysmon ID 11",
        subTechniques: ["T1204.001 – Malicious Link", "T1204.002 – Malicious File"]
      },
    ]
  },
  {
    id: "TA0003", name: "Persistence", shortName: "Persist",
    description: "Techniques adversaries use to keep access to systems across restarts or credential changes.",
    techniques: [
      {
        id: "T1053", name: "Scheduled Task/Job", severity: "high",
        description: "Adversaries use task schedulers to run programs or scripts.",
        detectionLogic: "schtasks.exe usage, AT command, WMI scheduled tasks, Event ID 4698",
        iocPatterns: ["schtasks /create", "at.exe", "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule"],
        mitigation: "Audit scheduled tasks, restrict task creation, monitor Event 4698/4699",
        dataSource: "Windows Event 4698, Sysmon ID 1, Registry monitoring",
        subTechniques: ["T1053.005 – Scheduled Task", "T1053.002 – At Command"]
      },
      {
        id: "T1547", name: "Boot or Logon Autostart Execution", severity: "critical",
        description: "Adversaries configure system to execute programs during system boot or account logon.",
        detectionLogic: "Run key modifications, startup folder changes, Sysmon 12/13 registry events",
        iocPatterns: ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "Startup folder"],
        mitigation: "Baseline Run keys, monitor registry changes, restrict user write access",
        dataSource: "Registry monitoring, Sysmon 12/13, Event ID 4657",
        subTechniques: ["T1547.001 – Registry Run Keys / Startup Folder", "T1547.004 – Winlogon Helper DLL"]
      },
      {
        id: "T1543", name: "Create or Modify System Process", severity: "critical",
        description: "Adversaries create or modify system-level processes to execute malicious code.",
        detectionLogic: "New service installations, driver loads, SC command usage, Event 7045",
        iocPatterns: ["sc.exe create", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "InstallUtil.exe"],
        mitigation: "Audit service creation, require code signing, monitor 7045/4697",
        dataSource: "Windows Event 7045, 4697, Sysmon ID 6, SC manager audit",
        subTechniques: ["T1543.003 – Windows Service"]
      },
    ]
  },
  {
    id: "TA0004", name: "Privilege Escalation", shortName: "PrivEsc",
    description: "Techniques to gain higher-level permissions on a system or network.",
    techniques: [
      {
        id: "T1055", name: "Process Injection", severity: "critical",
        description: "Adversaries inject code into legitimate processes to evade detection.",
        detectionLogic: "CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, Sysmon ID 8/10",
        iocPatterns: ["CreateRemoteThread into svchost", "lsass.exe memory access", "reflective DLL load", "process hollowing"],
        mitigation: "Credential Guard, ASR rules, Sysmon 8/10, behavioral monitoring",
        dataSource: "Sysmon ID 8, 10, 25, Windows Defender telemetry",
        subTechniques: ["T1055.001 – DLL Injection", "T1055.002 – Portable Executable Injection", "T1055.012 – Process Hollowing"]
      },
      {
        id: "T1134", name: "Access Token Manipulation", severity: "high",
        description: "Adversaries modify access tokens to escalate privileges or evade detection.",
        detectionLogic: "Token duplication, impersonation, SeDebugPrivilege assignment, Event 4648",
        iocPatterns: ["DuplicateTokenEx", "ImpersonateLoggedOnUser", "SeDebugPrivilege", "whoami /priv"],
        mitigation: "Limit privileged accounts, Credential Guard, audit logon events",
        dataSource: "Windows Event 4624, 4648, 4672, Sysmon process telemetry",
        subTechniques: ["T1134.001 – Token Impersonation/Theft", "T1134.002 – Create Process with Token"]
      },
    ]
  },
  {
    id: "TA0005", name: "Defense Evasion", shortName: "DefEvade",
    description: "Techniques to avoid detection throughout the attack lifecycle.",
    techniques: [
      {
        id: "T1562", name: "Impair Defenses", severity: "critical",
        description: "Adversaries disable or tamper with security tools and logging.",
        detectionLogic: "AV/EDR process termination, audit log clearing, Event 1102/4719",
        iocPatterns: ["net stop \"Windows Defender\"", "Set-MpPreference -DisableRealtimeMonitoring", "wevtutil cl Security", "BCDEdit /set"],
        mitigation: "Tamper protection, protected audit logs, WDAC, MDM policy",
        dataSource: "Windows Event 1102, 4719, 7036, Sysmon ID 1",
        subTechniques: ["T1562.001 – Disable or Modify Tools", "T1562.002 – Disable Windows Event Logging"]
      },
      {
        id: "T1036", name: "Masquerading", severity: "high",
        description: "Adversaries manipulate file names, paths, or extensions to disguise malicious content.",
        detectionLogic: "svchost.exe not in System32, signed binary path mismatch, double extension",
        iocPatterns: ["svchost.exe from Temp", "explorer.exe parent anomaly", "file.pdf.exe", "chrome.exe from %APPDATA%"],
        mitigation: "Process path validation, binary signing enforcement, EDR behavioral rules",
        dataSource: "Sysmon ID 1 parent/child analysis, PE header inspection, file hash",
        subTechniques: ["T1036.003 – Rename System Utilities", "T1036.005 – Match Legitimate Name or Location"]
      },
    ]
  },
  {
    id: "TA0006", name: "Credential Access", shortName: "CredAccess",
    description: "Techniques to steal credentials like passwords, tokens, or hashes.",
    techniques: [
      {
        id: "T1003", name: "OS Credential Dumping", severity: "critical",
        description: "Adversaries dump credentials to obtain account hashes and plaintext passwords.",
        detectionLogic: "LSASS memory access, procdump.exe, Mimikatz signatures, Event 4656 on LSASS",
        iocPatterns: ["lsass.exe handle request", "sekurlsa::", "comsvcs.dll MiniDump", "procdump -ma lsass"],
        mitigation: "Credential Guard, Protected Users group, block LSASS read access",
        dataSource: "Windows Event 4656, 10 (Sysmon), WD telemetry, memory forensics",
        subTechniques: ["T1003.001 – LSASS Memory", "T1003.002 – Security Account Manager"]
      },
      {
        id: "T1558", name: "Steal or Forge Kerberos Tickets", severity: "critical",
        description: "Adversaries steal Kerberos tickets for privilege escalation and lateral movement.",
        detectionLogic: "Golden/Silver ticket indicators, unusual TGS requests, Event 4769 anomalies",
        iocPatterns: ["kerberoast", "RC4 encryption downgrade", "forged PAC", "mimikatz kerberos::golden"],
        mitigation: "AES encryption enforcement, Kerberos hardening, Event 4769 monitoring",
        dataSource: "Windows Event 4768, 4769, 4771, Domain controller logs",
        subTechniques: ["T1558.001 – Golden Ticket", "T1558.003 – Kerberoasting"]
      },
    ]
  },
  {
    id: "TA0007", name: "Discovery", shortName: "Discover",
    description: "Techniques adversaries use to gain knowledge of the environment.",
    techniques: [
      {
        id: "T1082", name: "System Information Discovery", severity: "medium",
        description: "Adversaries attempt to get detailed information about the operating system.",
        detectionLogic: "Rapid execution of systeminfo, hostname, ipconfig, ver commands",
        iocPatterns: ["systeminfo.exe", "Get-ComputerInfo", "wmic os get", "reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT"],
        mitigation: "Restrict WMI access, monitor enumeration commands, EDR behavioral rules",
        dataSource: "Process creation (Sysmon ID 1), 4688 with command line",
        subTechniques: []
      },
      {
        id: "T1046", name: "Network Service Discovery", severity: "high",
        description: "Adversaries scan the network to identify hosts and running services.",
        detectionLogic: "Sequential port sweeps, Nmap signatures, ARP sweeps, SYN flood patterns",
        iocPatterns: ["nmap -sS", "port sweep SYN packets", "masscan", "arp -a enumeration"],
        mitigation: "Network segmentation, IDS/IPS scanning signatures, firewall logging",
        dataSource: "Network flow data, firewall logs, IDS alerts",
        subTechniques: []
      },
    ]
  },
  {
    id: "TA0008", name: "Lateral Movement", shortName: "LatMov",
    description: "Techniques adversaries use to enter and control remote systems on a network.",
    techniques: [
      {
        id: "T1021", name: "Remote Services", severity: "high",
        description: "Adversaries use valid accounts to log into a service over the network.",
        detectionLogic: "RDP/SSH from unusual sources, SMB connections to ADMIN$, PsExec patterns",
        iocPatterns: ["psexec.exe", "wmic /node:", "net use \\\\", "Enter-PSSession", "xfreerdp"],
        mitigation: "MFA on remote access, network segmentation, privileged access workstations",
        dataSource: "Windows Event 4624 type 3/10, 5140, 5145, Sysmon ID 3",
        subTechniques: ["T1021.001 – Remote Desktop Protocol", "T1021.002 – SMB/Windows Admin Shares"]
      },
    ]
  },
  {
    id: "TA0009", name: "Collection", shortName: "Collect",
    description: "Techniques adversaries use to gather information relevant to their goal.",
    techniques: [
      {
        id: "T1005", name: "Data from Local System", severity: "medium",
        description: "Adversaries search local system sources to find files of interest.",
        detectionLogic: "Mass file enumeration, access to sensitive directories, archive creation",
        iocPatterns: ["dir /s /b *.docx", "Get-ChildItem -Recurse", "7z.exe a archive", "robocopy to temp"],
        mitigation: "File access auditing, DLP controls, data classification",
        dataSource: "Windows Event 4663, Sysmon ID 11, File audit logs",
        subTechniques: []
      },
    ]
  },
  {
    id: "TA0010", name: "Exfiltration", shortName: "Exfil",
    description: "Techniques adversaries use to steal data from your network.",
    techniques: [
      {
        id: "T1048", name: "Exfiltration Over Alternative Protocol", severity: "critical",
        description: "Adversaries steal data by encoding it within protocol traffic (DNS, ICMP, SMTP).",
        detectionLogic: "High-entropy DNS queries, large DNS TXT records, ICMP data payloads, SMTP with large attachments",
        iocPatterns: ["DNS query > 50 chars", "ICMP payload > 100 bytes", "base64 in DNS", "subdomain beacon pattern"],
        mitigation: "DNS inspection, ICMP filtering, DLP on email, anomaly detection on protocol baselines",
        dataSource: "DNS logs, Network flow, Sysmon ID 22, Firewall logs",
        subTechniques: ["T1048.001 – Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "T1048.003 – DNS Exfiltration"]
      },
    ]
  },
  {
    id: "TA0011", name: "Command & Control", shortName: "C2",
    description: "Techniques adversaries use to communicate with compromised systems.",
    techniques: [
      {
        id: "T1071", name: "Application Layer Protocol", severity: "critical",
        description: "Adversaries communicate using application layer protocols to avoid detection.",
        detectionLogic: "Periodic beaconing intervals, JA3/JA3S TLS fingerprints, domain fronting, unusual user-agents",
        iocPatterns: ["Cobalt Strike beacon", "JA3: 51c64c77e60f3980eea90869b68d58d8", "HTTP beaconing every 60s", "unusual SNI mismatch"],
        mitigation: "TLS inspection, JA3 blocking, DNS sinkhole, anomaly-based NDR",
        dataSource: "Network flow, TLS metadata, DNS logs, proxy logs, Sysmon ID 3",
        subTechniques: ["T1071.001 – Web Protocols", "T1071.004 – DNS"]
      },
      {
        id: "T1573", name: "Encrypted Channel", severity: "high",
        description: "Adversaries use encryption to conceal C2 communications.",
        detectionLogic: "Expired/self-signed certs on outbound, unusual certificate CNs, custom TLS implementations",
        iocPatterns: ["self-signed cert outbound", "certificate CN mismatch", "unusual TLS version", "pinned certificate bypass"],
        mitigation: "TLS inspection, certificate transparency monitoring, anomalous cert alerting",
        dataSource: "TLS metadata, Zeek logs, Proxy SSL inspection logs",
        subTechniques: ["T1573.001 – Symmetric Cryptography", "T1573.002 – Asymmetric Cryptography"]
      },
    ]
  },
  {
    id: "TA0040", name: "Impact", shortName: "Impact",
    description: "Techniques adversaries use to disrupt availability or compromise integrity.",
    techniques: [
      {
        id: "T1486", name: "Data Encrypted for Impact (Ransomware)", severity: "critical",
        description: "Adversaries encrypt files on target systems to interrupt availability.",
        detectionLogic: "Mass file rename/extension change, VSS deletion, rapid file modification, ransom note creation",
        iocPatterns: ["vssadmin delete shadows", "bcdedit /set recoveryenabled No", "mass .locked extension", "README_DECRYPT.txt"],
        mitigation: "Immutable backups, Controlled Folder Access, VSS protection, EDR ransomware detection",
        dataSource: "File system monitoring, Sysmon ID 11, Windows Event 4663, Defender alerts",
        subTechniques: []
      },
      {
        id: "T1499", name: "Endpoint Denial of Service", severity: "high",
        description: "Adversaries flood systems or services to reduce their availability.",
        detectionLogic: "Traffic volume spikes, SYN flood patterns, resource exhaustion indicators",
        iocPatterns: ["SYN flood", "UDP amplification", "HTTP/2 rapid reset", "slowloris pattern"],
        mitigation: "Rate limiting, DDoS mitigation services, connection limits, BGP blackholing",
        dataSource: "Netflow, IDS, Firewall logs, Load balancer metrics",
        subTechniques: ["T1499.001 – OS Exhaustion Flood", "T1499.002 – Service Exhaustion Flood"]
      },
    ]
  },
];

export const ALL_TECHNIQUES = MITRE_TACTICS.flatMap(t => t.techniques);
