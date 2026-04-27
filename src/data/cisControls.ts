export type ImplementationGroup = "IG1" | "IG2" | "IG3";
export type CISControl = {
  id: string;
  number: number;
  title: string;
  description: string;
  implementationGroups: ImplementationGroup[];
  safeguards: CISSafeguard[];
  nistMapping: string[];
  coverage: number; // percentage of MITRE techniques covered
  attacksCovered: number;
};

export type CISSafeguard = {
  id: string;
  title: string;
  description: string;
  implementationGroups: ImplementationGroup[];
  status: "implemented" | "partial" | "planned" | "not-applicable";
  maturityLevel: 1 | 2 | 3 | 4 | 5;
  evidenceItems: number;
};

export const CIS_CONTROLS_V81: CISControl[] = [
  {
    id: "cis-1",
    number: 1,
    title: "Inventory and Control of Enterprise Assets",
    description: "Establish and maintain accurate, detailed, and up-to-date inventories of all enterprise assets.",
    implementationGroups: ["IG1", "IG2", "IG3"],
    nistMapping: ["ID.AM-01", "ID.AM-02"],
    coverage: 78,
    attacksCovered: 156,
    safeguards: [
      {
        id: "cis-1-1",
        title: "Establish and Maintain Detailed Enterprise Asset Inventory",
        description: "Develop and maintain an accurate, detailed and up-to-date inventory of all enterprise assets with the potential to impact cybersecurity.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 4,
        evidenceItems: 12,
      },
      {
        id: "cis-1-2",
        title: "Address Unauthorized Assets",
        description: "Ensure that hardware devices, software, and network services are managed through a formal, documented process.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 3,
        evidenceItems: 8,
      },
    ],
  },
  {
    id: "cis-2",
    number: 2,
    title: "Inventory and Control of Software Assets",
    description: "Manage and maintain centralized, accurate information on software licenses and authorized software.",
    implementationGroups: ["IG1", "IG2", "IG3"],
    nistMapping: ["ID.AM-01", "PR.PS-02"],
    coverage: 72,
    attacksCovered: 144,
    safeguards: [
      {
        id: "cis-2-1",
        title: "Establish and Maintain Software Inventory",
        description: "Establish and maintain an accurate, detailed inventory of all authorized software installed or otherwise in use.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 4,
        evidenceItems: 15,
      },
    ],
  },
  {
    id: "cis-3",
    number: 3,
    title: "Data Protection",
    description: "Develop and maintain comprehensive data protection strategies to protect all data types.",
    implementationGroups: ["IG1", "IG2", "IG3"],
    nistMapping: ["PR.DS-01", "PR.DS-02"],
    coverage: 85,
    attacksCovered: 170,
    safeguards: [
      {
        id: "cis-3-1",
        title: "Establish and Maintain Data Handling Process",
        description: "Maintain data handling processes and technical controls to protect data at rest, in transit, and in use.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 5,
        evidenceItems: 18,
      },
    ],
  },
  {
    id: "cis-4",
    number: 4,
    title: "Secure Configuration of Enterprise Assets and Software",
    description: "Establish and maintain secure configuration processes for enterprise assets and software.",
    implementationGroups: ["IG1", "IG2", "IG3"],
    nistMapping: ["PR.PS-01"],
    coverage: 88,
    attacksCovered: 176,
    safeguards: [
      {
        id: "cis-4-1",
        title: "Establish and Maintain a Secure Configuration Process",
        description: "Establish and maintain a documented secure configuration process for all enterprise assets and software.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 4,
        evidenceItems: 10,
      },
      {
        id: "cis-4-2",
        title: "Deploy System Configuration Management Tools",
        description: "Deploy system configuration management tools to establish secure baseline configurations and enforce them across the enterprise.",
        implementationGroups: ["IG2", "IG3"],
        status: "partial",
        maturityLevel: 3,
        evidenceItems: 6,
      },
    ],
  },
  {
    id: "cis-5",
    number: 5,
    title: "Account Management",
    description: "Manage and monitor the creation, modification, usage and removal of accounts.",
    implementationGroups: ["IG1", "IG2", "IG3"],
    nistMapping: ["PR.AA-01", "PR.AA-02"],
    coverage: 82,
    attacksCovered: 164,
    safeguards: [
      {
        id: "cis-5-1",
        title: "Establish and Maintain Inventory of Accounts",
        description: "Establish and maintain an inventory of accounts and identities authorized to access enterprise assets.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 4,
        evidenceItems: 9,
      },
    ],
  },
  {
    id: "cis-6",
    number: 6,
    title: "Access Control Management",
    description: "Use processes and tools to create, assign, manage, and revoke access credentials and privileges.",
    implementationGroups: ["IG1", "IG2", "IG3"],
    nistMapping: ["PR.AA-03", "PR.AA-04", "PR.AA-05"],
    coverage: 91,
    attacksCovered: 182,
    safeguards: [
      {
        id: "cis-6-1",
        title: "Establish an Access Granting Process",
        description: "Establish and follow a process, preferably automated, for granting access to enterprise assets upon new hire, rights grant, or role change.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 5,
        evidenceItems: 11,
      },
      {
        id: "cis-6-2",
        title: "Establish an Access Revoking Process",
        description: "Establish and follow a process for revoking access to enterprise assets as soon as an individual is terminated.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 4,
        evidenceItems: 7,
      },
      {
        id: "cis-6-3",
        title: "Require MFA for Externally-Exposed Applications",
        description: "Require all externally-exposed enterprise or third-party applications to enforce MFA before granting access to the application.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 5,
        evidenceItems: 13,
      },
    ],
  },
  {
    id: "cis-7",
    number: 7,
    title: "Continuous Vulnerability Management",
    description: "Establish and maintain processes to identify, classify, remediate, and mitigate vulnerabilities.",
    implementationGroups: ["IG1", "IG2", "IG3"],
    nistMapping: ["ID.RA-01", "ID.RA-02"],
    coverage: 79,
    attacksCovered: 158,
    safeguards: [
      {
        id: "cis-7-1",
        title: "Establish and Maintain a Vulnerability Management Process",
        description: "Establish and maintain a documented vulnerability management process that includes identification, assessment, remediation, and reporting.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 4,
        evidenceItems: 14,
      },
    ],
  },
  {
    id: "cis-8",
    number: 8,
    title: "Audit Log Management",
    description: "Establish, manage, and protect centralized logging for security events and non-security events on network devices.",
    implementationGroups: ["IG1", "IG2", "IG3"],
    nistMapping: ["DE.CM-01", "DE.CM-03"],
    coverage: 86,
    attacksCovered: 172,
    safeguards: [
      {
        id: "cis-8-1",
        title: "Establish Centralized Logging",
        description: "Establish and implement a process to centralize, maintain, and manage log data from all enterprise assets.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 5,
        evidenceItems: 16,
      },
    ],
  },
  {
    id: "cis-9",
    number: 9,
    title: "Email and Web Browser Protections",
    description: "Establish processes to protect against spoof, phishing, and other web-based malicious attacks.",
    implementationGroups: ["IG1", "IG2", "IG3"],
    nistMapping: ["PR.PT-01", "DE.CM-01"],
    coverage: 74,
    attacksCovered: 148,
    safeguards: [
      {
        id: "cis-9-1",
        title: "Establish and Maintain Email Security Controls",
        description: "Establish and maintain email security controls to protect against malicious email threats including spam, phishing, and malware.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 4,
        evidenceItems: 8,
      },
    ],
  },
  {
    id: "cis-10",
    number: 10,
    title: "Malware Defenses",
    description: "Establish and maintain processes to prevent, detect, and remediate malware incidents.",
    implementationGroups: ["IG1", "IG2", "IG3"],
    nistMapping: ["PR.PT-03", "DE.CM-04"],
    coverage: 81,
    attacksCovered: 162,
    safeguards: [
      {
        id: "cis-10-1",
        title: "Deploy and Maintain Anti-Malware Software",
        description: "Deploy and maintain the latest versions of anti-malware software on all enterprise assets and keep it up to date.",
        implementationGroups: ["IG1", "IG2", "IG3"],
        status: "implemented",
        maturityLevel: 5,
        evidenceItems: 12,
      },
    ],
  },
];

export const getCISMaturityScore = (controls: CISControl[]): number => {
  const avgMaturity = controls.reduce((sum, control) => {
    const safeguardAvg = control.safeguards.reduce((s, safeguard) => s + safeguard.maturityLevel, 0) / control.safeguards.length;
    return sum + safeguardAvg;
  }, 0) / controls.length;
  return Math.round(avgMaturity * 20); // Convert 1-5 to 0-100
};

export const getCISCoverageByIG = (ig: ImplementationGroup): { controls: number; attacks: number } => {
  const filtered = CIS_CONTROLS_V81.filter(c => c.implementationGroups.includes(ig));
  return {
    controls: filtered.length,
    attacks: filtered.reduce((s, c) => s + c.attacksCovered, 0),
  };
};
