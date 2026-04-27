/**
 * Penetration Testing Framework & Methodology
 * PTES, OWASP, OSSTMM, NIST 800-115
 */

export type PentestPhase = "pre-engagement" | "intelligence" | "threat-modeling" | "vulnerability-analysis" | "exploitation" | "post-exploitation" | "reporting";
export type PentestScope = "blackbox" | "graybox" | "whitebox";
export type PentestType = "network" | "web-application" | "wireless" | "social-engineering" | "physical" | "cloud" | "mobile" | "red-team";

export type PentestProject = {
  id: string;
  name: string;
  scope: PentestScope;
  type: PentestType;
  startDate: number;
  endDate: number;
  status: "planning" | "active" | "completed" | "paused" | "cancelled";
  currentPhase: PentestPhase;
  phaseProgress: number;
  methodology: string;
  testerName: string;
  findings: PentestFinding[];
  overallRisk: number;
  objectives: string[];
  targets: PentestTarget[];
};

export type PentestTarget = {
  id: string;
  type: "ip" | "domain" | "application" | "network-segment" | "wireless" | "physical";
  value: string;
  os?: string;
  services?: string[];
  status: "pending" | "scanning" | "testing" | "exploited" | "reported";
};

export type PentestFinding = {
  id: string;
  phase: PentestPhase;
  title: string;
  description: string;
  cvssScore: number;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  category: string;
  evidence: string[];
  exploitSteps: string[];
  remediation: string;
  complianceGap?: string;
  affectedTarget: string;
  discoveryMethod: string;
  confidence: number;
  referenceUrls: string[];
  mitreTechnique?: string;
};

export type PentestPhaseTemplate = {
  phase: PentestPhase;
  name: string;
  description: string;
  objectives: string[];
  tools: string[];
  techniques: string[];
  deliverables: string[];
  estimatedDuration: string;
};

export const PENTEST_PHASES: PentestPhaseTemplate[] = [
  {
    phase: "pre-engagement",
    name: "1. Pre-Engagement",
    description: "Planning and scoping activities including rules of engagement, legal agreements, and scope definition.",
    objectives: [
      "Define scope and boundaries",
      "Establish rules of engagement",
      "Sign legal agreements (NDA, SOW)",
      "Identify critical assets",
      "Set up communication channels",
    ],
    tools: ["Project management tools", "Communication platforms", "Legal document templates"],
    techniques: ["Scope definition workshops", "Stakeholder interviews", "Risk assessment review"],
    deliverables: ["Rules of Engagement (RoE)", "Statement of Work (SOW)", "Authorization letters", "Project timeline"],
    estimatedDuration: "1-2 weeks",
  },
  {
    phase: "intelligence",
    name: "2. Intelligence Gathering",
    description: "Collecting information about the target organization, systems, and potential attack vectors.",
    objectives: [
      "OSINT reconnaissance",
      "Network range identification",
      "Technology stack discovery",
      "Email address harvesting",
      "Subdomain enumeration",
      "Employee information gathering",
    ],
    tools: ["Nmap", "Recon-ng", "Maltego", "theHarvester", "Shodan", "Censys", "DNSrecon", "AMASS"],
    techniques: [
      "Passive reconnaissance (OSINT)",
      "DNS enumeration",
      "WHOIS lookups",
      "Google dorking",
      "Social media analysis",
      "Code repository scanning",
    ],
    deliverables: ["Intelligence report", "Network topology map", "Technology inventory", "Email list", "Attack surface map"],
    estimatedDuration: "1-2 weeks",
  },
  {
    phase: "threat-modeling",
    name: "3. Threat Modeling",
    description: "Identifying potential threats and attack scenarios based on gathered intelligence.",
    objectives: [
      "Identify threat actors",
      "Map attack trees",
      "Prioritize attack vectors",
      "Develop attack scenarios",
      "Assess threat likelihood",
    ],
    tools: ["Microsoft Threat Modeling Tool", "OWASP Threat Dragon", "STRIDE framework", "Kill Chain mapping"],
    techniques: [
      "STRIDE threat modeling",
      "Attack tree analysis",
      "MITRE ATT&CK mapping",
      "Kill chain modeling",
      "Risk scoring (DREAD)",
    ],
    deliverables: ["Threat model document", "Attack scenarios", "Prioritized attack plan", "Risk assessment matrix"],
    estimatedDuration: "3-5 days",
  },
  {
    phase: "vulnerability-analysis",
    name: "4. Vulnerability Analysis",
    description: "Identifying and analyzing security weaknesses in the target systems.",
    objectives: [
      "Run automated scanners",
      "Manual vulnerability testing",
      "Configuration review",
      "Identify misconfigurations",
      "Validate discovered vulnerabilities",
    ],
    tools: ["Nessus", "Qualys", "OpenVAS", "Burp Suite", "OWASP ZAP", "Nuclei", "Nikto", "Wapiti"],
    techniques: [
      "Automated scanning",
      "Manual code review",
      "Configuration analysis",
      "Authentication testing",
      "API security testing",
      "Business logic testing",
    ],
    deliverables: ["Vulnerability report", "CVSS scoring", "Evidence documentation", "Affected assets list"],
    estimatedDuration: "1-2 weeks",
  },
  {
    phase: "exploitation",
    name: "5. Exploitation",
    description: "Actively exploiting discovered vulnerabilities to verify findings and assess impact.",
    objectives: [
      "Validate vulnerabilities",
      "Demonstrate impact",
      "Obtain initial access",
      "Document exploitation steps",
      "Assess defense mechanisms",
    ],
    tools: ["Metasploit", "Cobalt Strike", "Burp Suite Pro", "BloodHound", "Mimikatz", "Impacket", "CrackMapExec", "Responder"],
    techniques: [
      "Web application exploitation",
      "Network service exploitation",
      "Client-side attacks",
      "Social engineering",
      "Credential attacks",
      "Privilege escalation",
    ],
    deliverables: ["Exploitation report", "Proof of concept", "Captured credentials", "Access evidence"],
    estimatedDuration: "1-2 weeks",
  },
  {
    phase: "post-exploitation",
    name: "6. Post-Exploitation",
    description: "Assessing the depth of compromise and potential business impact.",
    objectives: [
      "Assess lateral movement",
      "Evaluate data access",
      "Test persistence mechanisms",
      "Assess detection capabilities",
      "Document attack path",
    ],
    tools: ["BloodHound", "PowerView", "Mimikatz", "SharpHound", "Seatbelt", "SharpUp"],
    techniques: [
      "Lateral movement testing",
      "Data exfiltration simulation",
      "Persistence mechanism testing",
      "Defense evasion assessment",
      "Privilege escalation",
      "Domain enumeration",
    ],
    deliverables: ["Post-exploitation report", "Attack path documentation", "Data access evidence", "Detection gaps identified"],
    estimatedDuration: "3-5 days",
  },
  {
    phase: "reporting",
    name: "7. Reporting",
    description: "Comprehensive documentation of all findings with executive summary and technical details.",
    objectives: [
      "Document all findings",
      "Provide executive summary",
      "Detail technical evidence",
      "Include remediation guidance",
      "Present risk assessment",
    ],
    tools: ["Report templates", "CVSS calculators", "MITRE ATT&CK references"],
    techniques: [
      "Risk-based prioritization",
      "Evidence documentation",
      "Remediation planning",
      "Executive briefing",
      "Technical workshop",
    ],
    deliverables: [
      "Executive summary report",
      "Detailed technical report",
      "Remediation roadmap",
      "Presentation materials",
      "Certificate of completion",
    ],
    estimatedDuration: "1-2 weeks",
  },
];

export const SAMPLE_PENTEST_FINDINGS: PentestFinding[] = [
  {
    id: "find-001",
    phase: "exploitation",
    title: "SQL Injection in Customer Portal Login",
    description: "The customer portal login form is vulnerable to SQL injection, allowing bypass of authentication and access to the database.",
    cvssScore: 9.8,
    severity: "critical",
    category: "OWASP A03:2021",
    evidence: [
      "Input: admin' OR '1'='1' --",
      "Response: Login successful without valid credentials",
      "Database query manipulated successfully",
    ],
    exploitSteps: [
      "Navigate to /login",
      "Enter SQL injection payload in username field",
      "Authentication bypassed, admin session obtained",
      "Accessed /admin/dashboard",
    ],
    remediation: "Implement parameterized queries, input validation, and WAF rules to prevent SQL injection.",
    complianceGap: "PCI DSS 6.5.1 - Injection Flaws",
    affectedTarget: "https://portal.customer.com",
    discoveryMethod: "Burp Suite manual testing",
    confidence: 100,
    referenceUrls: ["https://owasp.org/www-community/attacks/SQL_Injection"],
    mitreTechnique: "T1190",
  },
  {
    id: "find-002",
    phase: "exploitation",
    title: "Unauthenticated API Access to Sensitive Data",
    description: "The /api/v2/users endpoint returns full user details including PII without authentication.",
    cvssScore: 7.5,
    severity: "high",
    category: "OWASP A01:2021",
    evidence: [
      "GET /api/v2/users returns 200 OK",
      "Response contains: email, phone, SSN, address",
      "No authentication headers required",
    ],
    exploitSteps: [
      "Send GET request to /api/v2/users",
      "Observe complete user records returned",
      "No authentication token validated",
    ],
    remediation: "Implement authentication enforcement on all API endpoints, add rate limiting.",
    complianceGap: "GDPR Article 25 - Data Protection by Design",
    affectedTarget: "https://api.company.com",
    discoveryMethod: "Nmap + manual API testing",
    confidence: 100,
    referenceUrls: ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    mitreTechnique: "T1213",
  },
  {
    id: "find-003",
    phase: "vulnerability-analysis",
    title: "Outdated OpenSSL Version with Known Vulnerabilities",
    description: "The web server is running OpenSSL 1.0.2k which is end-of-life and contains multiple CVEs.",
    cvssScore: 8.1,
    severity: "high",
    category: "OWASP A06:2021",
    evidence: [
      "OpenSSL version: 1.0.2k (EOL since Dec 2019)",
      "CVE-2016-2183 (SWEET32) - High",
      "CVE-2017-3731 - High",
    ],
    exploitSteps: [
      "Run: openssl version",
      "Compare against known vulnerable versions",
      "Cross-reference with NVD database",
    ],
    remediation: "Upgrade OpenSSL to latest stable version (3.x), implement patch management process.",
    complianceGap: "CIS Control 7 - Continuous Vulnerability Management",
    affectedTarget: "web-prod-01:443",
    discoveryMethod: "Version detection scan",
    confidence: 100,
    referenceUrls: ["https://www.openssl.org/news/vulnerabilities.html"],
  },
  {
    id: "find-004",
    phase: "exploitation",
    title: "Weak Kerberos Configuration Allows Kerberoasting",
    description: "Active Directory accounts with SPNs use RC4 encryption, enabling offline password cracking.",
    cvssScore: 7.5,
    severity: "high",
    category: "MITRE T1558",
    evidence: [
      "User: svc_web with SPN: HTTP/web01.corp.local",
      "Encryption type: RC4_HMAC_MD5 (0x17)",
      "Successfully requested TGS ticket",
    ],
    exploitSteps: [
      "Enumerate SPNs with GetUserSPNs.py",
      "Request TGS ticket for service account",
      "Crack offline with hashcat",
    ],
    remediation: "Migrate to AES-only Kerberos encryption, enforce RC4 deprecation.",
    complianceGap: "NIST SP 800-53 IA-5",
    affectedTarget: "dc01.corp.local",
    discoveryMethod: "BloodHound + Impacket",
    confidence: 100,
    referenceUrls: ["https://attack.mitre.org/techniques/T1558/"],
    mitreTechnique: "T1558",
  },
  {
    id: "find-005",
    phase: "post-exploitation",
    title: "Privilege Escalation via Sudo Misconfiguration",
    description: "User account can execute ANY command as root via sudo without password.",
    cvssScore: 7.8,
    severity: "high",
    category: "MITRE T1548",
    evidence: [
      "User: analyst1",
      "Sudo output: analyst1 ALL=(ALL) NOPASSWD: ALL",
      "Successfully escalated to root",
    ],
    exploitSteps: [
      "Check sudo permissions: sudo -l",
      "Execute: sudo bash -p",
      "Verify: id (uid=0(root))",
    ],
    remediation: "Implement least privilege sudo rules, require password for sudo.",
    complianceGap: "CIS Control 5 - Account Management",
    affectedTarget: "linux-dev-07",
    discoveryMethod: "LinPEAS automation",
    confidence: 100,
    referenceUrls: ["https://gtfobins.github.io/"],
    mitreTechnique: "T1548",
  },
  {
    id: "find-006",
    phase: "intelligence",
    title: "Sensitive Information in Public GitHub Repository",
    description: "AWS credentials and database connection strings found in public GitHub repository.",
    cvssScore: 9.8,
    severity: "critical",
    category: "OWASP A05:2021",
    evidence: [
      "Repository contains AWS credentials",
      "DATABASE_URL with plaintext credentials found",
      "Repository appears to be public",
    ],
    exploitSteps: [
      "Clone repository",
      "Search for secrets with grep/regex",
      "Extract credentials and test access",
    ],
    remediation: "Remove sensitive data from repository, rotate all exposed credentials.",
    complianceGap: "CIS Control 3 - Data Protection",
    affectedTarget: "github.com/company",
    discoveryMethod: "TruffleHog + manual search",
    confidence: 100,
    referenceUrls: ["https://owasp.org/www-project-secrets-detection/"],
  },
  {
    id: "find-007",
    phase: "vulnerability-analysis",
    title: "SQL Server with Default SA Account Active",
    description: "Microsoft SQL Server has the SA account enabled with a weak password.",
    cvssScore: 8.5,
    severity: "high",
    category: "OWASP A07:2021",
    evidence: [
      "SQL Server 2019 on db-prod-01:1433",
      "SA account is enabled",
      "Weak password detected",
    ],
    exploitSteps: [
      "Connect with SA credentials",
      "Verify sysadmin privileges",
      "Execute OS commands via xp_cmdshell",
    ],
    remediation: "Disable SA account, implement strong password policy.",
    complianceGap: "PCI DSS 2.1 - Default Configurations",
    affectedTarget: "db-prod-01:1433",
    discoveryMethod: "Nmap MSSQL script",
    confidence: 100,
    referenceUrls: ["https://www.tenable.com/plugins/nessus/94394"],
  },
  {
    id: "find-008",
    phase: "exploitation",
    title: "LFI to RCE via Log Poisoning",
    description: "Local file inclusion vulnerability can be exploited to achieve remote code execution.",
    cvssScore: 9.8,
    severity: "critical",
    category: "OWASP A03:2021",
    evidence: [
      "Parameter vulnerable to path traversal",
      "Successfully read /etc/passwd",
      "Apache access log writable and included",
    ],
    exploitSteps: [
      "Test LFI with path traversal",
      "Poison Apache access log with PHP payload",
      "Include log file to execute code",
    ],
    remediation: "Remove file inclusion functionality, implement input validation.",
    complianceGap: "OWASP A03:2021 Injection",
    affectedTarget: "https://app.company.com",
    discoveryMethod: "Burp Suite",
    confidence: 100,
    referenceUrls: ["https://owasp.org/www-community/attacks/Includes"],
    mitreTechnique: "T1190",
  },
];

export const PENTEST_METHODOLOGIES = {
  ptes: {
    name: "Penetration Testing Execution Standard (PTES)",
    version: "1.1",
    phases: 7,
    focus: "Full-scope, end-to-end penetration testing",
    bestFor: "Enterprise-level comprehensive security assessments",
    compliance: ["PCI DSS", "ISO 27001", "HIPAA", "SOC 2"],
  },
  owasp: {
    name: "OWASP Testing Guide",
    version: "4.2",
    phases: 11,
    focus: "Web application security testing",
    bestFor: "SaaS platforms, e-commerce, web APIs",
    compliance: ["PCI DSS", "SOC 2", "GDPR"],
  },
  nist: {
    name: "NIST SP 800-115",
    version: "2008",
    phases: 6,
    focus: "Formal security assessment methodology",
    bestFor: "Government and regulated industries",
    compliance: ["FISMA", "FedRAMP", "HIPAA", "NIST 800-53"],
  },
  osstmm: {
    name: "Open Source Security Testing Methodology Manual",
    version: "3.0",
    phases: 5,
    focus: "Operational security testing with metrics",
    bestFor: "Holistic security assessment with quantitative scores",
    compliance: ["ISO 27001", "PCI DSS", "Custom"],
  },
};

export function generatePentestProject(): PentestProject {
  const phases: PentestPhase[] = ["pre-engagement", "intelligence", "threat-modeling", "vulnerability-analysis", "exploitation", "post-exploitation", "reporting"];
  const phaseIndex = Math.floor(Math.random() * phases.length);
  const selectedFindings = SAMPLE_PENTEST_FINDINGS.filter(() => Math.random() > 0.5);
  
  return {
    id: `pentest-${Math.random().toString(36).slice(2, 8)}`,
    name: `External Penetration Test - ${["Production", "Staging", "Development"][Math.floor(Math.random() * 3)]}`,
    scope: ["blackbox", "graybox", "whitebox"][Math.floor(Math.random() * 3)] as PentestScope,
    type: ["network", "web-application", "red-team"][Math.floor(Math.random() * 3)] as PentestType,
    startDate: Date.now() - (7 - phaseIndex) * 86400000,
    endDate: Date.now() + (7 - phaseIndex) * 86400000,
    status: "active",
    currentPhase: phases[phaseIndex],
    phaseProgress: Math.floor(Math.random() * 100),
    methodology: "PTES",
    testerName: ["John Smith", "Sarah Chen", "Alex Rivera"][Math.floor(Math.random() * 3)],
    findings: selectedFindings,
    overallRisk: Math.round(selectedFindings.reduce((sum, f) => sum + f.cvssScore, 0) / selectedFindings.length * 10),
    objectives: [
      "Identify critical vulnerabilities",
      "Assess network perimeter security",
      "Test web application security",
      "Evaluate incident response capabilities",
    ],
    targets: [
      { id: "t1", type: "ip", value: "203.0.113.0/24", services: ["HTTP", "HTTPS", "SSH", "RDP"], status: "testing" },
      { id: "t2", type: "domain", value: "*.company.com", services: ["DNS", "HTTP"], status: "reported" },
      { id: "t3", type: "application", value: "https://portal.company.com", status: "exploited" },
    ],
  };
}
