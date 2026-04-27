/**
 * Government & Enterprise Security Standards
 * FIPS 140-2, Common Criteria, NIST SP 800-53, FedRAMP, ISO 15408
 */

export type ComplianceFramework = {
  id: string;
  name: string;
  version: string;
  authority: string;
  description: string;
  controls: SecurityControl[];
  complianceScore: number;
  lastAudit: number;
  nextAuditDue: number;
  status: "compliant" | "non-compliant" | "remediation-required" | "not-assessed";
};

export type SecurityControl = {
  id: string;
  name: string;
  description: string;
  family: string;
  severity: "low" | "moderate" | "high" | "critical";
  implementation: "technical" | "operational" | "management";
  status: "implemented" | "partial" | "planned" | "not-implemented";
  evidence: string[];
  testResults: TestResult[];
  mitreMappings: string[];
};

export type TestResult = {
  timestamp: number;
  tester: string;
  result: "pass" | "fail" | "partial";
  findings: string[];
  remediationPlan?: string;
};

export type DigitalSignature = {
  filePath: string;
  hash: string;
  algorithm: "SHA-256" | "SHA-384" | "SHA-512";
  signed: boolean;
  valid: boolean;
  certificate: CertificateInfo | null;
  timestamp: number;
  counterSigners: number;
  signatureType: "embedded" | "catalog" | "external";
  validationChain: CertificateChain[];
};

export type CertificateInfo = {
  subject: string;
  issuer: string;
  serialNumber: string;
  thumbprint: string;
  validFrom: number;
  validTo: number;
  keyAlgorithm: string;
  keySize: number;
  isCA: boolean;
  pathLength: number;
  extensions: CertificateExtension[];
  revocationStatus: "good" | "revoked" | "unknown" | "checking";
  ocspResponse?: string;
  crlDistributionPoints: string[];
};

export type CertificateExtension = {
  oid: string;
  name: string;
  critical: boolean;
  value: string;
};

export type CertificateChain = {
  level: number;
  subject: string;
  issuer: string;
  thumbprint: string;
  valid: boolean;
  trusted: boolean;
  selfSigned: boolean;
};

// FIPS 140-2 Cryptographic Modules
export const FIPS_140_2_COMPLIANCE: ComplianceFramework = {
  id: "fips-140-2",
  name: "FIPS 140-2 Cryptographic Module Validation",
  version: "2.0",
  authority: "NIST / CMVP",
  description: "Federal Information Processing Standards Publication 140-2 for cryptographic modules",
  complianceScore: 98,
  lastAudit: Date.now() - 30 * 24 * 60 * 60 * 1000,
  nextAuditDue: Date.now() + 60 * 24 * 60 * 60 * 1000,
  status: "compliant",
  controls: [
    {
      id: "FIPS-C1",
      name: "Cryptographic Module Specification",
      description: "Module must be tested and validated against FIPS 140-2 standards",
      family: "Cryptographic",
      severity: "critical",
      implementation: "technical",
      status: "implemented",
      evidence: [
        "Certificate #4281 - OpenSSL FIPS Object Module",
        "Certificate #3862 - Microsoft Windows 10 FIPS 140-2",
        "Certificate #4412 - Linux Kernel Crypto API",
      ],
      testResults: [
        {
          timestamp: Date.now() - 45 * 24 * 60 * 60 * 1000,
          tester: "NIST CMVP Lab",
          result: "pass",
          findings: ["All cryptographic algorithms validated", "Self-tests passing"],
        },
      ],
      mitreMappings: ["T1573", "T1600"],
    },
    {
      id: "FIPS-C2",
      name: "Cryptographic Module Ports and Interfaces",
      description: "All data entry and exit points must be identified and secured",
      family: "Cryptographic",
      severity: "critical",
      implementation: "technical",
      status: "implemented",
      evidence: [
        "Physical ports documented and monitored",
        "Logical interfaces secured with TLS 1.3",
        "API endpoints protected with mutual TLS",
      ],
      testResults: [
        {
          timestamp: Date.now() - 30 * 24 * 60 * 60 * 1000,
          tester: "Internal Security Team",
          result: "pass",
          findings: ["All interfaces identified", "No unauthorized access detected"],
        },
      ],
      mitreMappings: ["T1190", "T1090"],
    },
    {
      id: "FIPS-C3",
      name: "Roles, Services, and Authentication",
      description: "Authorized roles and services must be clearly defined and authenticated",
      family: "Access Control",
      severity: "high",
      implementation: "operational",
      status: "implemented",
      evidence: [
        "RBAC implemented with MFA",
        "Service accounts documented and monitored",
        "Crypto officer role defined and enforced",
      ],
      testResults: [
        {
          timestamp: Date.now() - 20 * 24 * 60 * 60 * 1000,
          tester: "SOC Analyst Team",
          result: "pass",
          findings: ["Role separation verified", "Authentication mechanisms validated"],
        },
      ],
      mitreMappings: ["T1078", "T1552"],
    },
    {
      id: "FIPS-C4",
      name: "Finite State Model",
      description: "Module must operate in defined states with clear transitions",
      family: "Operational",
      severity: "high",
      implementation: "technical",
      status: "implemented",
      evidence: [
        "State machine documented",
        "Error handling validated",
        "Power-up self-tests implemented",
      ],
      testResults: [
        {
          timestamp: Date.now() - 15 * 24 * 60 * 60 * 1000,
          tester: "DevSecOps Team",
          result: "pass",
          findings: ["All state transitions verified", "Error conditions handled properly"],
        },
      ],
      mitreMappings: ["T1499"],
    },
  ],
};

// Common Criteria (ISO/IEC 15408)
export const COMMON_CRITERIA_EAL4: ComplianceFramework = {
  id: "common-criteria-eal4",
  name: "Common Criteria Evaluation Assurance Level 4+",
  version: "3.1 R5",
  authority: "ISO/IEC 15408 / NIAP",
  description: "Methodically designed, tested, and reviewed with semi-formal analysis",
  complianceScore: 94,
  lastAudit: Date.now() - 60 * 24 * 60 * 60 * 1000,
  nextAuditDue: Date.now() + 90 * 24 * 60 * 60 * 1000,
  status: "compliant",
  controls: [
    {
      id: "CC-ACM",
      name: "Configuration Management",
      description: "Automated configuration management with version control and baselines",
      family: "Lifecycle",
      severity: "critical",
      implementation: "operational",
      status: "implemented",
      evidence: [
        "Git version control with signed commits",
        "CI/CD pipeline with artifact signing",
        "Configuration baselines documented",
        "Change control board established",
      ],
      testResults: [
        {
          timestamp: Date.now() - 90 * 24 * 60 * 60 * 1000,
          tester: "NIAP-CCEVS Lab",
          result: "pass",
          findings: ["CM automation verified", "Baseline integrity confirmed"],
        },
      ],
      mitreMappings: ["T1078", "T1195"],
    },
    {
      id: "CC-ADO",
      name: "Delivery and Operation",
      description: "Secure delivery procedures and operational documentation",
      family: "Lifecycle",
      severity: "high",
      implementation: "operational",
      status: "implemented",
      evidence: [
        "Secure distribution channels (TLS 1.3 + mTLS)",
        "Installation procedures documented",
        "Operational guidance published",
        "Training materials validated",
      ],
      testResults: [
        {
          timestamp: Date.now() - 75 * 24 * 60 * 60 * 1000,
          tester: "Operations Team",
          result: "pass",
          findings: ["Delivery integrity verified", "Operational readiness confirmed"],
        },
      ],
      mitreMappings: ["T1195", "T1204"],
    },
    {
      id: "CC-ADV",
      name: "Development",
      description: "Semi-formal functional specification and high-level design",
      family: "Development",
      severity: "critical",
      implementation: "technical",
      status: "implemented",
      evidence: [
        "Functional specification document",
        "High-level design with security architecture",
        "Low-level design for critical components",
        "Implementation representation (source code)",
      ],
      testResults: [
        {
          timestamp: Date.now() - 80 * 24 * 60 * 60 * 1000,
          tester: "Security Architecture Team",
          result: "pass",
          findings: ["Design correctness verified", "Security mechanisms validated"],
        },
      ],
      mitreMappings: ["T1190"],
    },
    {
      id: "CC-AGD",
      name: "Guidance Documents",
      description: "Administrator and user guidance for secure operation",
      family: "Operational",
      severity: "moderate",
      implementation: "operational",
      status: "implemented",
      evidence: [
        "Administrator guide (security configuration)",
        "User guidance (secure usage)",
        "Security procedures documented",
        "Incident response playbook",
      ],
      testResults: [
        {
          timestamp: Date.now() - 70 * 24 * 60 * 60 * 1000,
          tester: "Documentation Team",
          result: "pass",
          findings: ["Documentation completeness verified", "Accuracy validated"],
        },
      ],
      mitreMappings: ["T1592"],
    },
  ],
};

// NIST SP 800-53 Rev 5
export const NIST_SP_800_53_REV5: ComplianceFramework = {
  id: "nist-800-53-r5",
  name: "NIST SP 800-53 Rev 5 Security and Privacy Controls",
  version: "Revision 5",
  authority: "NIST / OMB",
  description: "Security and Privacy Controls for Information Systems and Organizations",
  complianceScore: 96,
  lastAudit: Date.now() - 15 * 24 * 60 * 60 * 1000,
  nextAuditDue: Date.now() + 45 * 24 * 60 * 60 * 1000,
  status: "compliant",
  controls: [
    {
      id: "AC-2",
      name: "Account Management",
      description: "Automated system account management with privileged access controls",
      family: "Access Control",
      severity: "critical",
      implementation: "technical",
      status: "implemented",
      evidence: [
        "Automated provisioning/deprovisioning",
        "Privileged Access Management (PAM) solution",
        "Just-in-time (JIT) access implemented",
        "Regular access reviews (quarterly)",
      ],
      testResults: [
        {
          timestamp: Date.now() - 10 * 24 * 60 * 60 * 1000,
          tester: "Identity Team",
          result: "pass",
          findings: ["All accounts inventoried", "Privileged access audited"],
        },
      ],
      mitreMappings: ["T1078", "T1098"],
    },
    {
      id: "AU-6",
      name: "Audit Review",
      description: "Automated audit review and analysis with anomaly detection",
      family: "Audit and Accountability",
      severity: "high",
      implementation: "technical",
      status: "implemented",
      evidence: [
        "SIEM with automated correlation rules",
        "UEBA for anomaly detection",
        "Daily automated audit reports",
        "SOC 24/7 monitoring",
      ],
      testResults: [
        {
          timestamp: Date.now() - 7 * 24 * 60 * 60 * 1000,
          tester: "SOC Manager",
          result: "pass",
          findings: ["Audit coverage verified", "Anomalies detected and investigated"],
        },
      ],
      mitreMappings: ["T1562", "T1070"],
    },
    {
      id: "SI-4",
      name: "Information System Monitoring",
      description: "Continuous monitoring with intrusion detection and prevention",
      family: "System and Information Integrity",
      severity: "critical",
      implementation: "technical",
      status: "implemented",
      evidence: [
        "Network IDS/IPS (Suricata, Snort)",
        "Host-based IDS (OSSEC, Wazuh)",
        "Malware sandbox analysis",
        "Behavioral analytics",
      ],
      testResults: [
        {
          timestamp: Date.now() - 5 * 24 * 60 * 60 * 1000,
          tester: "Security Engineering",
          result: "pass",
          findings: ["Monitoring coverage 100%", "Detection rules validated"],
        },
      ],
      mitreMappings: ["T1071", "T1041", "T1048"],
    },
    {
      id: "IR-4",
      name: "Incident Handling",
      description: "Automated incident handling with predefined procedures",
      family: "Incident Response",
      severity: "high",
      implementation: "operational",
      status: "implemented",
      evidence: [
        "Incident response plan documented",
        "Automated containment playbooks",
        "Forensic analysis capabilities",
        "Post-incident review process",
      ],
      testResults: [
        {
          timestamp: Date.now() - 20 * 24 * 60 * 60 * 1000,
          tester: "Incident Response Team",
          result: "pass",
          findings: ["Tabletop exercise completed", "Response time within SLA"],
        },
      ],
      mitreMappings: ["T1059", "T1204"],
    },
  ],
};

// FedRAMP High
export const FEDRAMP_HIGH: ComplianceFramework = {
  id: "fedramp-high",
  name: "FedRAMP High Security Baseline",
  version: "Rev 4",
  authority: "FedRAMP / GSA",
  description: "Federal Risk and Authorization Management Program - High Impact Level",
  complianceScore: 97,
  lastAudit: Date.now() - 25 * 24 * 60 * 60 * 1000,
  nextAuditDue: Date.now() + 95 * 24 * 60 * 60 * 1000,
  status: "compliant",
  controls: [
    {
      id: "FED-AC-17",
      name: "Remote Access",
      description: "Multi-factor authentication required for all remote access with continuous verification",
      family: "Access Control",
      severity: "critical",
      implementation: "technical",
      status: "implemented",
      evidence: [
        "FIDO2/WebAuthn hardware keys required",
        "Certificate-based VPN access",
        "Privileged access requires jump servers",
        "Session recording for all privileged access",
      ],
      testResults: [
        {
          timestamp: Date.now() - 20 * 24 * 60 * 60 * 1000,
          tester: "FedRAMP 3PAO",
          result: "pass",
          findings: ["MFA enforced for all remote access", "No bypass mechanisms found"],
        },
      ],
      mitreMappings: ["T1076", "T1133"],
    },
    {
      id: "FED-SC-7",
      name: "Boundary Protection",
      description: "Defense-in-depth boundary protection with DMZ and micro-segmentation",
      family: "System and Communications Protection",
      severity: "critical",
      implementation: "technical",
      status: "implemented",
      evidence: [
        "Next-gen firewall with deep packet inspection",
        "Zero Trust Network Architecture (ZTNA)",
        "Software-defined perimeters (SDP)",
        "DLP at all egress points",
      ],
      testResults: [
        {
          timestamp: Date.now() - 18 * 24 * 60 * 60 * 1000,
          tester: "Network Security Team",
          result: "pass",
          findings: ["All boundaries protected", "Segmentation validated"],
        },
      ],
      mitreMappings: ["T1090", "T1048"],
    },
  ],
};

// Certificate Validation for Digital Signatures
export const ROOT_CA_STORE = [
  {
    name: "Microsoft Root Certificate Authority",
    thumbprint: "8F43288AD272F3103B6FB1428485EA3014C0BCFE",
    validFrom: 931392000000,
    validTo: 2216784000000,
    trusted: true,
  },
  {
    name: "DigiCert Trusted Root G4",
    thumbprint: "552F7BDC1D69E982A4A1B483275E2E1F5E2D1E5C",
    validFrom: 1388448000000,
    validTo: 2004048000000,
    trusted: true,
  },
  {
    name: "GlobalSign Root CA",
    thumbprint: "B1BC968BD4F49D622AA89A81F2150152A41D829C",
    validFrom: 953596800000,
    validTo: 2048678400000,
    trusted: true,
  },
  {
    name: "Symantec Enterprise Mobile Root",
    thumbprint: "7F4CD8BFD10DE29357C50D31F00C5F0A9B7F88E7",
    validFrom: 1356998400000,
    validTo: 1704067200000,
    trusted: false, // Revoked example
  },
];

// Digital Signature Templates
export const DIGITAL_SIGNATURE_TEMPLATES: DigitalSignature[] = [
  {
    filePath: "C:\\Windows\\System32\\svchost.exe",
    hash: "a3b8c9d4e5f6789012345678901234567890abcd",
    algorithm: "SHA-256",
    signed: true,
    valid: true,
    certificate: {
      subject: "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      issuer: "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      serialNumber: "3300000266BD1580EFA78DA4C3000000020266",
      thumbprint: "F2C7B3E8D4A5F6E7B8C9D0A1B2C3D4E5F6A7B8C",
      validFrom: 1577836800000,
      validTo: 1893456000000,
      keyAlgorithm: "RSA",
      keySize: 2048,
      isCA: false,
      pathLength: 0,
      extensions: [
        { oid: "2.5.29.19", name: "Basic Constraints", critical: true, value: "CA:FALSE" },
        { oid: "2.5.29.15", name: "Key Usage", critical: true, value: "Digital Signature" },
        { oid: "2.5.29.37", name: "Extended Key Usage", critical: false, value: "Code Signing" },
      ],
      revocationStatus: "good",
      crlDistributionPoints: [
        "http://crl.microsoft.com/pki/crl/products/MicrosoftWindowsSigning.crl",
      ],
    },
    timestamp: 1609459200000,
    counterSigners: 1,
    signatureType: "embedded",
    validationChain: [
      {
        level: 0,
        subject: "Microsoft Windows",
        issuer: "Microsoft Windows Production PCA 2011",
        thumbprint: "F2C7B3E8D4A5F6E7B8C9D0A1B2C3D4E5F6A7B8C",
        valid: true,
        trusted: true,
        selfSigned: false,
      },
      {
        level: 1,
        subject: "Microsoft Windows Production PCA 2011",
        issuer: "Microsoft Root Certificate Authority 2010",
        thumbprint: "8F43288AD272F3103B6FB1428485EA3014C0BCFE",
        valid: true,
        trusted: true,
        selfSigned: false,
      },
      {
        level: 2,
        subject: "Microsoft Root Certificate Authority 2010",
        issuer: "Microsoft Root Certificate Authority 2010",
        thumbprint: "8F43288AD272F3103B6FB1428485EA3014C0BCFE",
        valid: true,
        trusted: true,
        selfSigned: true,
      },
    ],
  },
  {
    filePath: "C:\\Users\\Public\\Downloads\\suspicious_driver.sys",
    hash: "e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6",
    algorithm: "SHA-256",
    signed: true,
    valid: false,
    certificate: {
      subject: "CN=Unknown Developer, O=Suspicious Corp, L=Unknown, C=XX",
      issuer: "CN=Untrusted CA, O=Malicious Authority, C=XX",
      serialNumber: "DEADBEEF1234567890",
      thumbprint: "A1B2C3D4E5F6789012345678901234567890ABCD",
      validFrom: 1609459200000,
      validTo: 1672531200000,
      keyAlgorithm: "RSA",
      keySize: 1024,
      isCA: false,
      pathLength: 0,
      extensions: [],
      revocationStatus: "revoked",
      ocspResponse: "REVOKED - Certificate compromised",
      crlDistributionPoints: ["http://untrusted-ca.example.com/crl.pem"],
    },
    timestamp: 1640995200000,
    counterSigners: 0,
    signatureType: "embedded",
    validationChain: [
      {
        level: 0,
        subject: "Unknown Developer",
        issuer: "Untrusted CA",
        thumbprint: "A1B2C3D4E5F6789012345678901234567890ABCD",
        valid: false,
        trusted: false,
        selfSigned: false,
      },
    ],
  },
  {
    filePath: "/opt/malware/cobalt_strike_beacon",
    hash: "deadbeefcafebabe1234567890abcdef12345678",
    algorithm: "SHA-256",
    signed: false,
    valid: false,
    certificate: null,
    timestamp: 0,
    counterSigners: 0,
    signatureType: "external",
    validationChain: [],
  },
];

// Advanced Threat Indicators for Government-Grade Detection
export const GOVERNMENT_THREAT_INDICATORS = {
  aptGroups: [
    { id: "APT28", name: "Fancy Bear", country: "Russia", motivation: "Intelligence Gathering", targets: "Government, Military" },
    { id: "APT29", name: "Cozy Bear", country: "Russia", motivation: "Espionage", targets: "Government, Healthcare" },
    { id: "APT1", name: "Comment Crew", country: "China", motivation: "Economic Espionage", targets: "Technology, Defense" },
    { id: "APT41", name: "Winnti", country: "China", motivation: "Dual Criminal/Espionage", targets: "Gaming, Healthcare" },
    { id: "LAZARUS", name: "Lazarus Group", country: "North Korea", motivation: "Financial Gain", targets: "Financial, Cryptocurrency" },
  ],
  
  iocTypes: {
    network: ["C2 Beacon", "Data Exfiltration", "DNS Tunnel", "Tor Exit Node"],
    file: ["Steganography", "Polyglot File", "ADS (Alternate Data Stream)", "NTFS $LogFile manipulation"],
    memory: ["Process Injection", "APC Injection", "Thread Hijacking", "Memory Resident Malware"],
    registry: ["Run Keys Persistence", "COM Hijacking", "AppCert DLLs", "Winlogon Notification Packages"],
  },
};

// Validation Functions
export function validateCertificateChain(cert: CertificateInfo | null): { valid: boolean; reason: string } {
  if (!cert) return { valid: false, reason: "No certificate present" };
  
  const now = Date.now();
  if (now < cert.validFrom) return { valid: false, reason: "Certificate not yet valid" };
  if (now > cert.validTo) return { valid: false, reason: "Certificate expired" };
  if (cert.revocationStatus === "revoked") return { valid: false, reason: "Certificate revoked" };
  if (cert.keySize < 2048) return { valid: false, reason: "Weak key size" };
  
  return { valid: true, reason: "Certificate chain valid and trusted" };
}

export function calculateFileTrustScore(sig: DigitalSignature): number {
  let score = 0;
  
  if (!sig.signed) return 0;
  if (sig.valid) score += 30;
  if (sig.certificate?.revocationStatus === "good") score += 30;
  if ((sig.certificate?.keySize ?? 0) >= 2048) score += 20;
  if (sig.counterSigners > 0) score += 10;
  if (sig.validationChain.length >= 2) score += 10;
  
  return Math.min(100, score);
}

export const ALL_COMPLIANCE_FRAMEWORKS = [
  FIPS_140_2_COMPLIANCE,
  COMMON_CRITERIA_EAL4,
  NIST_SP_800_53_REV5,
  FEDRAMP_HIGH,
];
