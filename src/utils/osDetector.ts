/**
 * OS Detection Utility — SentinelGrid SOC Platform
 * Detects client-side OS type, version, architecture, and generates
 * security posture assessments for the monitoring dashboard.
 */

export type OSInfo = {
  name: string;
  version: string;
  architecture: string;
  platform: string;
  buildId?: string;
  kernelVersion?: string;
  isEOL: boolean;
  eolDate?: string;
  securityLevel: "high" | "medium" | "low" | "critical";
  vulnerabilities: string[];
  recommendations: string[];
  patchStatus: "up-to-date" | "outdated" | "critical" | "unknown";
  detectedAt: number;
};

export type OSSecurityProfile = {
  os: OSInfo;
  browserInfo: BrowserInfo;
  securityScore: number;
  riskFactors: RiskFactor[];
  complianceStatus: ComplianceStatus;
};

export type BrowserInfo = {
  name: string;
  version: string;
  engine: string;
  isSecure: boolean;
};

export type RiskFactor = {
  id: string;
  title: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  mitreId?: string;
  cve?: string;
};

export type ComplianceStatus = {
  nist: "compliant" | "partial" | "non-compliant";
  cis: "compliant" | "partial" | "non-compliant";
  details: string[];
};

// Windows version EOL database
const WINDOWS_EOL_DB: Record<string, { name: string; eolDate: string; isEOL: boolean }> = {
  "10.0.19041": { name: "Windows 10 2004", eolDate: "2021-12-14", isEOL: true },
  "10.0.19042": { name: "Windows 10 20H2", eolDate: "2022-05-10", isEOL: true },
  "10.0.19043": { name: "Windows 10 21H1", eolDate: "2022-12-13", isEOL: true },
  "10.0.19044": { name: "Windows 10 21H2", eolDate: "2023-06-13", isEOL: true },
  "10.0.19045": { name: "Windows 10 22H2", eolDate: "2025-10-14", isEOL: false },
  "10.0.22000": { name: "Windows 11 21H2", eolDate: "2023-10-10", isEOL: true },
  "10.0.22621": { name: "Windows 11 22H2", eolDate: "2024-10-08", isEOL: true },
  "10.0.22631": { name: "Windows 11 23H2", eolDate: "2025-11-11", isEOL: false },
  "10.0.26100": { name: "Windows 11 24H2", eolDate: "2026-10-13", isEOL: false },
};

// macOS version EOL database
const MACOS_EOL_DB: Record<string, { name: string; eolDate: string; isEOL: boolean }> = {
  "10.15": { name: "macOS Catalina", eolDate: "2022-11-01", isEOL: true },
  "11":    { name: "macOS Big Sur",   eolDate: "2023-09-26", isEOL: true },
  "12":    { name: "macOS Monterey",  eolDate: "2024-09-16", isEOL: true },
  "13":    { name: "macOS Ventura",   eolDate: "2025-09-01", isEOL: false },
  "14":    { name: "macOS Sonoma",    eolDate: "2026-09-01", isEOL: false },
  "15":    { name: "macOS Sequoia",   eolDate: "2027-09-01", isEOL: false },
};

function detectWindowsVersion(ua: string): { version: string; build: string; name: string } {
  // Windows 11 reports as NT 10.0 in UA; distinguish via build
  if (ua.includes("Windows NT 10.0")) {
    // Modern browsers expose userAgentData with Windows 11 hint
    if (typeof navigator !== "undefined" && (navigator as any).userAgentData) {
      return { version: "10.0+", build: "22000+", name: "Windows 10/11" };
    }
    return { version: "10.0", build: "19041+", name: "Windows 10/11" };
  }
  if (ua.includes("Windows NT 6.3")) return { version: "8.1", build: "9600", name: "Windows 8.1" };
  if (ua.includes("Windows NT 6.2")) return { version: "8",   build: "9200", name: "Windows 8" };
  if (ua.includes("Windows NT 6.1")) return { version: "7",   build: "7601", name: "Windows 7" };
  if (ua.includes("Windows NT 6.0")) return { version: "Vista", build: "6000", name: "Windows Vista" };
  if (ua.includes("Windows NT 5.1")) return { version: "XP", build: "2600", name: "Windows XP" };
  return { version: "Unknown", build: "Unknown", name: "Windows (Unknown Version)" };
}

function detectMacOSVersion(ua: string): { version: string; name: string } {
  const match = ua.match(/Mac OS X ([\d_]+)/);
  if (match) {
    const raw = match[1].replace(/_/g, ".");
    const major = raw.split(".")[0];
    const minor = raw.split(".")[1] ?? "0";
    const lookupKey = parseInt(major) >= 11 ? major : `${major}.${minor}`;
    const entry = MACOS_EOL_DB[lookupKey];
    return {
      version: raw,
      name: entry?.name ?? `macOS ${raw}`,
    };
  }
  return { version: "Unknown", name: "macOS (Unknown)" };
}

function detectLinuxDistro(ua: string): { version: string; name: string } {
  if (ua.includes("Ubuntu")) return { version: "Ubuntu", name: "Ubuntu Linux" };
  if (ua.includes("Fedora")) return { version: "Fedora", name: "Fedora Linux" };
  if (ua.includes("Debian")) return { version: "Debian", name: "Debian Linux" };
  if (ua.includes("CentOS")) return { version: "CentOS", name: "CentOS Linux" };
  if (ua.includes("RHEL") || ua.includes("Red Hat")) return { version: "RHEL", name: "Red Hat Enterprise Linux" };
  return { version: "Unknown Distro", name: "Linux (Unknown Distro)" };
}

function detectBrowser(ua: string): BrowserInfo {
  let name = "Unknown";
  let version = "Unknown";
  let engine = "Unknown";

  if (ua.includes("Edg/")) {
    name = "Microsoft Edge";
    engine = "Blink";
    const m = ua.match(/Edg\/([\d.]+)/);
    version = m ? m[1] : "Unknown";
  } else if (ua.includes("Chrome/")) {
    name = "Google Chrome";
    engine = "Blink";
    const m = ua.match(/Chrome\/([\d.]+)/);
    version = m ? m[1] : "Unknown";
  } else if (ua.includes("Firefox/")) {
    name = "Mozilla Firefox";
    engine = "Gecko";
    const m = ua.match(/Firefox\/([\d.]+)/);
    version = m ? m[1] : "Unknown";
  } else if (ua.includes("Safari/") && !ua.includes("Chrome")) {
    name = "Apple Safari";
    engine = "WebKit";
    const m = ua.match(/Version\/([\d.]+)/);
    version = m ? m[1] : "Unknown";
  } else if (ua.includes("OPR/") || ua.includes("Opera/")) {
    name = "Opera";
    engine = "Blink";
    const m = ua.match(/OPR\/([\d.]+)/);
    version = m ? m[1] : "Unknown";
  }

  // Browsers are "secure" if running over HTTPS or localhost
  const isSecure =
    typeof location !== "undefined" &&
    (location.protocol === "https:" || location.hostname === "localhost" || location.hostname === "127.0.0.1");

  return { name, version, engine, isSecure };
}

function getArchitecture(ua: string): string {
  if (ua.includes("x64") || ua.includes("Win64") || ua.includes("WOW64")) return "x86_64 (64-bit)";
  if (ua.includes("ARM64") || ua.includes("aarch64")) return "ARM64";
  if (ua.includes("ARM")) return "ARM (32-bit)";
  return "x86 (32-bit)";
}

function buildWindowsRiskFactors(version: string, isEOL: boolean): RiskFactor[] {
  const risks: RiskFactor[] = [];

  if (version === "7" || version === "Vista" || version === "XP") {
    risks.push({
      id: "WIN-EOL-CRITICAL",
      title: `Windows ${version} End-of-Life — No Security Patches`,
      description: `Microsoft no longer releases security updates for Windows ${version}. This system is critically vulnerable to all known unpatched CVEs.`,
      severity: "critical",
      mitreId: "T1190",
      cve: "Multiple unpatched critical CVEs",
    });
    risks.push({
      id: "WIN-PATCH-CRITICAL",
      title: "No kernel-level security mitigations available",
      description: "Spectre, Meltdown, PrintNightmare, EternalBlue and other kernel exploits remain unpatched.",
      severity: "critical",
      mitreId: "T1068",
      cve: "CVE-2021-34527, CVE-2017-0144",
    });
  }

  if (version === "8" || version === "8.1") {
    risks.push({
      id: "WIN-81-EOL",
      title: "Windows 8.1 End-of-Life (January 2023)",
      description: "Windows 8.1 reached end-of-life on January 10, 2023. No further security patches are available.",
      severity: "critical",
      mitreId: "T1190",
    });
  }

  risks.push({
    id: "WIN-SMB-MONITOR",
    title: "SMB Protocol Lateral Movement Vector",
    description: "SMB (port 445) is a common lateral movement vector. Ensure SMBv1 is disabled and firewall rules are enforced.",
    severity: "medium",
    mitreId: "T1021.002",
    cve: "CVE-2017-0144 (EternalBlue)",
  });

  risks.push({
    id: "WIN-RDP-EXPOSURE",
    title: "RDP Exposure Risk",
    description: "Remote Desktop Protocol (port 3389) should be restricted. Ensure Network Level Authentication (NLA) is enforced.",
    severity: "medium",
    mitreId: "T1021.001",
  });

  if (isEOL) {
    risks.push({
      id: "WIN-UNSUPPORTED",
      title: "Running Unsupported Windows Version",
      description: "This Windows version is past its end-of-support date. Upgrade to Windows 11 24H2 for full security coverage.",
      severity: "high",
      mitreId: "T1190",
    });
  }

  return risks;
}

function buildMacOSRiskFactors(version: string): RiskFactor[] {
  const risks: RiskFactor[] = [];
  const major = parseInt(version.split(".")[0]);

  if (major < 12) {
    risks.push({
      id: "MAC-EOL",
      title: `macOS ${version} — End-of-Life`,
      description: "This macOS version no longer receives security updates from Apple. Upgrade immediately.",
      severity: "critical",
      mitreId: "T1190",
    });
  }

  risks.push({
    id: "MAC-GATEKEEPER",
    title: "Verify Gatekeeper & SIP Status",
    description: "Ensure System Integrity Protection (SIP) and Gatekeeper are enabled. Disabling these creates significant attack surface.",
    severity: "medium",
    mitreId: "T1553.001",
  });

  risks.push({
    id: "MAC-XPC",
    title: "macOS XPC Service Injection Risk",
    description: "Monitor for unauthorized XPC service connections that could indicate privilege escalation attempts.",
    severity: "low",
    mitreId: "T1543.004",
  });

  return risks;
}

function buildLinuxRiskFactors(): RiskFactor[] {
  return [
    {
      id: "LINUX-PRIVESC",
      title: "Linux Privilege Escalation Vectors",
      description: "Ensure kernel is up-to-date. Monitor for dirty-pipe (CVE-2022-0847) and similar kernel exploits.",
      severity: "high",
      mitreId: "T1068",
      cve: "CVE-2022-0847",
    },
    {
      id: "LINUX-SUDO",
      title: "Sudo Configuration Audit Required",
      description: "Misconfigured sudo rules (NOPASSWD, shell escapes) are a primary local privilege escalation vector.",
      severity: "medium",
      mitreId: "T1548.003",
    },
    {
      id: "LINUX-SSH",
      title: "SSH Key Management",
      description: "Enforce SSH key-based authentication. Disable password auth in sshd_config. Monitor ~/.ssh/authorized_keys changes.",
      severity: "medium",
      mitreId: "T1098.004",
    },
    {
      id: "LINUX-CRON",
      title: "Cron Job Persistence Monitoring",
      description: "Monitor crontab changes for unauthorized scheduled task persistence (T1053.003).",
      severity: "low",
      mitreId: "T1053.003",
    },
  ];
}

function calculateSecurityScore(os: OSInfo, browser: BrowserInfo): number {
  let score = 100;

  // OS penalties
  if (os.isEOL) score -= 40;
  if (os.securityLevel === "critical") score -= 30;
  else if (os.securityLevel === "low") score -= 20;
  else if (os.securityLevel === "medium") score -= 10;

  // Vulnerability penalties
  score -= os.vulnerabilities.length * 5;

  // Risk factor penalties
  const criticalVulns = os.vulnerabilities.filter(v => v.toLowerCase().includes("critical")).length;
  score -= criticalVulns * 10;

  // Browser penalties
  if (!browser.isSecure) score -= 15;

  return Math.max(0, Math.min(100, score));
}

function getComplianceStatus(os: OSInfo): ComplianceStatus {
  const details: string[] = [];
  let nist: ComplianceStatus["nist"] = "compliant";
  let cis: ComplianceStatus["cis"] = "compliant";

  if (os.isEOL) {
    nist = "non-compliant";
    cis = "non-compliant";
    details.push("NIST SP 800-40: Unsupported OS violates patch management policy");
    details.push("CIS Control 2.2: Software inventory shows EOL operating system");
  } else if (os.securityLevel === "medium") {
    nist = "partial";
    cis = "partial";
    details.push("NIST ID.AM-2: Some software components may be outdated");
    details.push("CIS Control 4: Admin privileges require review");
  } else {
    details.push("NIST PR.IP-12: OS patch management policy appears compliant");
    details.push("CIS Control 2: Software inventory and EOL status — PASS");
  }

  details.push("NIST PR.AC-4: Verify least privilege enforcement on this endpoint");
  details.push("CIS Control 5: Account management policy audit recommended");

  return { nist, cis, details };
}

/**
 * Main detection function — detects OS and browser and returns a full security profile.
 */
export function detectOSSecurityProfile(): OSSecurityProfile {
  const ua = navigator.userAgent;
  const platform = navigator.platform || "";

  let osName = "Unknown OS";
  let osVersion = "Unknown";
  let architecture = getArchitecture(ua);
  let isEOL = false;
  let eolDate: string | undefined;
  let securityLevel: OSInfo["securityLevel"] = "high";
  let vulnerabilities: string[] = [];
  let recommendations: string[] = [];
  let patchStatus: OSInfo["patchStatus"] = "unknown";
  let riskFactors: RiskFactor[] = [];
  let osPlatform = "unknown";

  if (ua.includes("Windows")) {
    osPlatform = "win32";
    const win = detectWindowsVersion(ua);
    osName = win.name;
    osVersion = win.version;

    const eolEntry = Object.values(WINDOWS_EOL_DB).find(e =>
      e.name.toLowerCase().includes(win.name.toLowerCase().replace("windows ", ""))
    );

    if (eolEntry) {
      isEOL = eolEntry.isEOL;
      eolDate = eolEntry.eolDate;
    }

    if (win.version === "7" || win.version === "Vista" || win.version === "XP") {
      securityLevel = "critical";
      vulnerabilities = [
        "Critical: No security patches available",
        "Critical: Kernel unpatched (EternalBlue, PrintNightmare)",
        "High: SMBv1 likely enabled",
        "High: No Spectre/Meltdown mitigations",
      ];
      patchStatus = "critical";
    } else if (win.version === "8" || win.version === "8.1") {
      securityLevel = "low";
      vulnerabilities = [
        "Critical: EOL — no security patches since Jan 2023",
        "High: Missing modern security features (Credential Guard, etc.)",
      ];
      patchStatus = "critical";
    } else {
      securityLevel = isEOL ? "medium" : "high";
      vulnerabilities = isEOL
        ? ["High: Running EOL Windows build — upgrade required"]
        : ["Info: Ensure Windows Update is set to automatic"];
      patchStatus = isEOL ? "outdated" : "unknown";
    }

    recommendations = [
      "Enable Windows Defender and ensure real-time protection is active",
      "Enable BitLocker full-disk encryption on all volumes",
      "Configure Windows Firewall to block SMBv1 (port 445 inbound)",
      "Disable RDP if not required; enable NLA if RDP is needed",
      "Enable Credential Guard and HVCI (Hypervisor-Protected Code Integrity)",
      "Apply all pending Windows Updates via Windows Update or WSUS",
      "Enable audit policy for logon events, object access, and privilege use",
    ];

    riskFactors = buildWindowsRiskFactors(win.version, isEOL);

  } else if (ua.includes("Mac OS X") || ua.includes("Macintosh")) {
    osPlatform = "darwin";
    const mac = detectMacOSVersion(ua);
    osName = mac.name;
    osVersion = mac.version;
    architecture = ua.includes("Intel") ? "x86_64 (Intel)" : "ARM64 (Apple Silicon)";

    const major = parseInt(osVersion.split(".")[0]);
    const macEntry = MACOS_EOL_DB[major >= 11 ? String(major) : `10.${osVersion.split(".")[1]}`];
    isEOL = macEntry?.isEOL ?? (major < 13);
    eolDate = macEntry?.eolDate;
    securityLevel = isEOL ? "low" : "high";
    patchStatus = isEOL ? "outdated" : "unknown";

    vulnerabilities = isEOL
      ? ["Critical: macOS version EOL — no security updates from Apple"]
      : ["Info: Keep macOS updated via Software Update"];

    recommendations = [
      "Ensure System Integrity Protection (SIP) is enabled (csrutil status)",
      "Enable FileVault full-disk encryption",
      "Enable macOS Firewall in System Settings → Network → Firewall",
      "Review installed kernel extensions and system extensions",
      "Use Apple's built-in XProtect and MRT for malware remediation",
      "Enable Lockdown Mode for high-risk users",
    ];

    riskFactors = buildMacOSRiskFactors(osVersion);

  } else if (ua.includes("Linux") || platform.startsWith("Linux")) {
    osPlatform = "linux";
    const linux = detectLinuxDistro(ua);
    osName = linux.name;
    osVersion = linux.version;
    securityLevel = "medium";
    patchStatus = "unknown";
    isEOL = false;

    vulnerabilities = [
      "Info: Verify kernel version and apply security patches (apt/yum update)",
      "Medium: Check for Dirty Pipe (CVE-2022-0847) if kernel < 5.16.11",
      "Medium: Ensure SELinux/AppArmor is enforcing",
    ];

    recommendations = [
      "Enable and configure SELinux (RHEL/Fedora) or AppArmor (Ubuntu/Debian)",
      "Regularly run 'unattended-upgrades' or equivalent auto-patching",
      "Audit open ports with 'ss -tulnp' and disable unnecessary services",
      "Use auditd for system call and file access auditing",
      "Enforce SSH key authentication — disable PasswordAuthentication",
      "Monitor /etc/crontab, /etc/cron.d, and user crontabs for persistence",
      "Enable kernel hardening via sysctl (kernel.randomize_va_space=2, etc.)",
    ];

    riskFactors = buildLinuxRiskFactors();
  }

  const browser = detectBrowser(ua);

  const osInfo: OSInfo = {
    name: osName,
    version: osVersion,
    architecture,
    platform: osPlatform,
    isEOL,
    eolDate,
    securityLevel,
    vulnerabilities,
    recommendations,
    patchStatus,
    detectedAt: Date.now(),
  };

  const securityScore = calculateSecurityScore(osInfo, browser);
  const complianceStatus = getComplianceStatus(osInfo);

  return {
    os: osInfo,
    browserInfo: browser,
    securityScore,
    riskFactors,
    complianceStatus,
  };
}
