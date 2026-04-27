export type ISO27001Domain = {
  id: string;
  code: string;
  title: string;
  description: string;
  controls: ISO27001Control[];
  complianceScore: number;
  riskArea: "critical" | "high" | "medium" | "low";
};

export type ISO27001Control = {
  id: string;
  code: string;
  title: string;
  description: string;
  implementation: "technical" | "organizational" | "physical" | "hybrid";
  status: "compliant" | "partial" | "non-compliant" | "not-applicable";
  evidenceCount: number;
  auditFrequency: "monthly" | "quarterly" | "semi-annual" | "annual";
  relatedCIS: string[];
  relatedNIST: string[];
};

export const ISO_27001_DOMAINS: ISO27001Domain[] = [
  {
    id: "a5",
    code: "A.5",
    title: "Organizational Controls (37 controls)",
    description: "Information security policies, roles, responsibilities, and organizational arrangements.",
    riskArea: "critical",
    complianceScore: 88,
    controls: [
      {
        id: "a5-1",
        code: "A.5.1",
        title: "Policies for information security",
        description: "Management shall establish, document, implement and maintain policies for information security covering all required areas.",
        implementation: "organizational",
        status: "compliant",
        evidenceCount: 5,
        auditFrequency: "annual",
        relatedCIS: ["CIS-1", "CIS-5"],
        relatedNIST: ["GV.PO-01", "GV.OC-01"],
      },
      {
        id: "a5-2",
        code: "A.5.2",
        title: "Information security roles and responsibilities",
        description: "All information security responsibilities shall be clearly defined and allocated.",
        implementation: "organizational",
        status: "compliant",
        evidenceCount: 4,
        auditFrequency: "annual",
        relatedCIS: ["CIS-5"],
        relatedNIST: ["GV.RR-01"],
      },
      {
        id: "a5-3",
        code: "A.5.3",
        title: "Segregation of duties",
        description: "Conflicting duties and areas of responsibility shall be segregated to reduce opportunities for unauthorized or unintentional modification of information.",
        implementation: "organizational",
        status: "partial",
        evidenceCount: 3,
        auditFrequency: "semi-annual",
        relatedCIS: ["CIS-6"],
        relatedNIST: ["PR.AA-04"],
      },
    ],
  },
  {
    id: "a8",
    code: "A.8",
    title: "Technical Controls (32 controls)",
    description: "User endpoint devices, access control, cryptography, system acquisition, malware defense, and network security.",
    riskArea: "critical",
    complianceScore: 92,
    controls: [
      {
        id: "a8-1",
        code: "A.8.1",
        title: "User endpoint devices",
        description: "Protect devices used to access information with appropriate controls including encryption and monitoring.",
        implementation: "technical",
        status: "compliant",
        evidenceCount: 8,
        auditFrequency: "monthly",
        relatedCIS: ["CIS-1", "CIS-4"],
        relatedNIST: ["PR.PS-01"],
      },
      {
        id: "a8-2",
        code: "A.8.2",
        title: "Privileged access rights",
        description: "The allocation and use of privileged access rights shall be restricted and managed.",
        implementation: "technical",
        status: "compliant",
        evidenceCount: 6,
        auditFrequency: "quarterly",
        relatedCIS: ["CIS-6"],
        relatedNIST: ["PR.AA-03"],
      },
      {
        id: "a8-3",
        code: "A.8.3",
        title: "Information access restriction",
        description: "Access to information and application functions shall be restricted in accordance with the access control policy.",
        implementation: "technical",
        status: "compliant",
        evidenceCount: 7,
        auditFrequency: "quarterly",
        relatedCIS: ["CIS-6"],
        relatedNIST: ["PR.AA-02", "PR.AA-05"],
      },
      {
        id: "a8-5",
        code: "A.8.5",
        title: "Secure authentication",
        description: "User and system access shall be authenticated using strong authentication mechanisms.",
        implementation: "technical",
        status: "compliant",
        evidenceCount: 9,
        auditFrequency: "monthly",
        relatedCIS: ["CIS-5", "CIS-6"],
        relatedNIST: ["PR.AA-01", "PR.AA-02"],
      },
      {
        id: "a8-7",
        code: "A.8.7",
        title: "Protection against malware",
        description: "Detection, prevention, and recovery controls against malware shall be implemented.",
        implementation: "technical",
        status: "compliant",
        evidenceCount: 5,
        auditFrequency: "monthly",
        relatedCIS: ["CIS-10"],
        relatedNIST: ["DE.CM-04"],
      },
      {
        id: "a8-8",
        code: "A.8.8",
        title: "Management of technical vulnerabilities",
        description: "Information about technical vulnerabilities of information systems being used shall be obtained in a timely manner.",
        implementation: "technical",
        status: "partial",
        evidenceCount: 6,
        auditFrequency: "monthly",
        relatedCIS: ["CIS-7"],
        relatedNIST: ["ID.RA-01"],
      },
      {
        id: "a8-10",
        code: "A.8.10",
        title: "Information deletion",
        description: "Information stored in information processing facilities, devices, or storage media shall be securely deleted when no longer required.",
        implementation: "technical",
        status: "compliant",
        evidenceCount: 4,
        auditFrequency: "quarterly",
        relatedCIS: ["CIS-3"],
        relatedNIST: ["PR.DS-03"],
      },
      {
        id: "a8-20",
        code: "A.8.20",
        title: "Networks security",
        description: "Groups of information services, users and information systems shall be segregated on the network.",
        implementation: "technical",
        status: "compliant",
        evidenceCount: 5,
        auditFrequency: "semi-annual",
        relatedCIS: ["CIS-4"],
        relatedNIST: ["PR.PS-01"],
      },
    ],
  },
  {
    id: "a7",
    code: "A.7",
    title: "Physical Controls (14 controls)",
    description: "Physical security perimeters, entry control, equipment siting, cabling, and facilities management.",
    riskArea: "high",
    complianceScore: 86,
    controls: [
      {
        id: "a7-1",
        code: "A.7.1",
        title: "Physical security perimeters",
        description: "Physical security perimeters shall be defined and used to protect areas containing information systems and related facilities.",
        implementation: "physical",
        status: "compliant",
        evidenceCount: 4,
        auditFrequency: "annual",
        relatedCIS: [],
        relatedNIST: ["PR.PS-01"],
      },
      {
        id: "a7-2",
        code: "A.7.2",
        title: "Physical entry",
        description: "Buildings and rooms containing information systems shall be protected by appropriate physical barriers and access controls.",
        implementation: "physical",
        status: "compliant",
        evidenceCount: 6,
        auditFrequency: "semi-annual",
        relatedCIS: [],
        relatedNIST: ["PR.PS-01"],
      },
      {
        id: "a7-4",
        code: "A.7.4",
        title: "Physical security monitoring",
        description: "Appropriate monitoring and recording systems shall be implemented within facilities containing information systems.",
        implementation: "hybrid",
        status: "compliant",
        evidenceCount: 5,
        auditFrequency: "quarterly",
        relatedCIS: ["CIS-8"],
        relatedNIST: ["DE.CM-01"],
      },
    ],
  },
  {
    id: "a16",
    code: "A.16",
    title: "Incident Management (5 controls)",
    description: "Information security incident management, response, and follow-up.",
    riskArea: "critical",
    complianceScore: 89,
    controls: [
      {
        id: "a16-1",
        code: "A.16.1",
        title: "Information security incident management",
        description: "The organization shall establish and implement a process to detect, report, assess, and respond to information security incidents.",
        implementation: "organizational",
        status: "compliant",
        evidenceCount: 8,
        auditFrequency: "monthly",
        relatedCIS: ["CIS-8"],
        relatedNIST: ["RS.MA-01", "RS.AN-01"],
      },
      {
        id: "a16-2",
        code: "A.16.2",
        title: "Information security improvement",
        description: "Knowledge and experience from information security incidents shall be used to improve information security controls.",
        implementation: "organizational",
        status: "partial",
        evidenceCount: 3,
        auditFrequency: "quarterly",
        relatedCIS: [],
        relatedNIST: ["RS.MI-02"],
      },
    ],
  },
  {
    id: "a14",
    code: "A.14",
    title: "System Development & Maintenance (12 controls)",
    description: "Secure development lifecycle, testing, change management, and maintenance.",
    riskArea: "high",
    complianceScore: 81,
    controls: [
      {
        id: "a14-1",
        code: "A.14.1",
        title: "Information security requirements analysis and specification",
        description: "Information security requirements shall be defined, documented and approved.",
        implementation: "organizational",
        status: "partial",
        evidenceCount: 5,
        auditFrequency: "semi-annual",
        relatedCIS: ["CIS-4"],
        relatedNIST: ["ID.IM-01"],
      },
      {
        id: "a14-2",
        code: "A.14.2",
        title: "Secure system development policy, processes and procedures",
        description: "Rules for the development of software and systems shall be established and applied to all system development activities.",
        implementation: "organizational",
        status: "compliant",
        evidenceCount: 6,
        auditFrequency: "semi-annual",
        relatedCIS: ["CIS-4"],
        relatedNIST: ["PR.PS-06"],
      },
    ],
  },
];

export const getISO27001ComplianceScore = (): number => {
  const avgScore = ISO_27001_DOMAINS.reduce((sum, domain) => sum + domain.complianceScore, 0) / ISO_27001_DOMAINS.length;
  return Math.round(avgScore);
};

export const getISO27001RiskAreas = (): Record<string, number> => {
  return ISO_27001_DOMAINS.reduce(
    (acc, domain) => {
      const key = domain.riskArea;
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );
};
