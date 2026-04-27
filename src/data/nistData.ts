export type NistFunction = {
  id: string;
  name: string;
  color: string;
  ringColor: string;
  description: string;
  categories: NistCategory[];
};

export type NistCategory = {
  id: string;
  name: string;
  description: string;
  complianceScore: number;
  subcategories: NistSubcategory[];
};

export type NistSubcategory = {
  id: string;
  name: string;
  status: "compliant" | "partial" | "non-compliant" | "not-assessed";
  lastAssessed: string;
};

export const NIST_FUNCTIONS: NistFunction[] = [
  {
    id: "GV", name: "Govern", color: "purple", ringColor: "ring-purple-500/30",
    description: "Establish and oversee cybersecurity risk management strategy and policy.",
    categories: [
      {
        id: "GV.OC", name: "Organizational Context", complianceScore: 88,
        description: "Circumstances surrounding cybersecurity risk management decisions are understood.",
        subcategories: [
          { id: "GV.OC-01", name: "Organizational mission informs cybersecurity risk management", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "GV.OC-02", name: "Internal and external stakeholders needs are understood", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "GV.OC-03", name: "Legal, regulatory, contractual requirements are managed", status: "partial", lastAssessed: "2025-10-15" },
          { id: "GV.OC-05", name: "Organization dependencies are understood", status: "compliant", lastAssessed: "2025-11-01" },
        ]
      },
      {
        id: "GV.RM", name: "Risk Management Strategy", complianceScore: 76,
        description: "Organization's risk tolerance and priorities are established and communicated.",
        subcategories: [
          { id: "GV.RM-01", name: "Risk management objectives are established", status: "compliant", lastAssessed: "2025-10-20" },
          { id: "GV.RM-02", name: "Risk appetite and tolerance statements are maintained", status: "partial", lastAssessed: "2025-10-20" },
          { id: "GV.RM-06", name: "Standardized risk calculation method is established", status: "partial", lastAssessed: "2025-09-01" },
          { id: "GV.RM-07", name: "Strategic risk opportunities are characterized", status: "non-compliant", lastAssessed: "2025-08-01" },
        ]
      },
      {
        id: "GV.SC", name: "Supply Chain Risk Management", complianceScore: 62,
        description: "Cybersecurity supply chain risk management processes are identified and prioritized.",
        subcategories: [
          { id: "GV.SC-01", name: "Cybersecurity supply chain risk management policy established", status: "partial", lastAssessed: "2025-09-15" },
          { id: "GV.SC-03", name: "Supplier cybersecurity activities are included in agreements", status: "partial", lastAssessed: "2025-09-15" },
          { id: "GV.SC-06", name: "Planning and due diligence performed before entering into supplier relationships", status: "non-compliant", lastAssessed: "2025-07-01" },
        ]
      }
    ]
  },
  {
    id: "ID", name: "Identify", color: "blue", ringColor: "ring-blue-500/30",
    description: "Understand organizational context, assets, and associated cybersecurity risks.",
    categories: [
      {
        id: "ID.AM", name: "Asset Management", complianceScore: 82,
        description: "Inventory and manage assets commensurate with their risk.",
        subcategories: [
          { id: "ID.AM-01", name: "Inventories of hardware assets are maintained", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "ID.AM-02", name: "Inventories of software assets are maintained", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "ID.AM-03", name: "Representations of the org's authorized network communication are maintained", status: "partial", lastAssessed: "2025-10-01" },
          { id: "ID.AM-07", name: "Inventories of data and corresponding meta-data are maintained", status: "partial", lastAssessed: "2025-10-01" },
        ]
      },
      {
        id: "ID.RA", name: "Risk Assessment", complianceScore: 79,
        description: "Understand cybersecurity risks to operations, assets, and individuals.",
        subcategories: [
          { id: "ID.RA-01", name: "Vulnerabilities in assets are identified, validated, and recorded", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "ID.RA-04", name: "Potential impacts and likelihoods of threats are identified and recorded", status: "compliant", lastAssessed: "2025-10-15" },
          { id: "ID.RA-05", name: "Threats, vulnerabilities, likelihoods, and impacts are prioritized", status: "partial", lastAssessed: "2025-10-15" },
          { id: "ID.RA-09", name: "Authenticity and integrity of hardware and software are assessed", status: "non-compliant", lastAssessed: "2025-08-01" },
        ]
      }
    ]
  },
  {
    id: "PR", name: "Protect", color: "emerald", ringColor: "ring-emerald-500/30",
    description: "Implement safeguards to manage cybersecurity risks to critical services.",
    categories: [
      {
        id: "PR.AA", name: "Identity Management & Access Control", complianceScore: 91,
        description: "Access to assets is limited to authorized users, services, and hardware.",
        subcategories: [
          { id: "PR.AA-01", name: "Identities and credentials are issued, managed, verified, and revoked", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "PR.AA-02", name: "Identities are proofed and bound to credentials based on context", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "PR.AA-03", name: "Users, services, and hardware are authenticated", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "PR.AA-05", name: "Access permissions and authorizations are managed", status: "compliant", lastAssessed: "2025-11-01" },
        ]
      },
      {
        id: "PR.DS", name: "Data Security", complianceScore: 74,
        description: "Data is managed consistent with the organization's risk strategy.",
        subcategories: [
          { id: "PR.DS-01", name: "Data-at-rest is protected", status: "compliant", lastAssessed: "2025-10-15" },
          { id: "PR.DS-02", name: "Data-in-transit is protected", status: "compliant", lastAssessed: "2025-10-15" },
          { id: "PR.DS-10", name: "Data-in-use is protected", status: "partial", lastAssessed: "2025-09-01" },
          { id: "PR.DS-11", name: "Backups of data are created, protected, maintained, and tested", status: "partial", lastAssessed: "2025-09-01" },
        ]
      },
      {
        id: "PR.PS", name: "Platform Security", complianceScore: 83,
        description: "Hardware and software are managed consistent with risk strategy.",
        subcategories: [
          { id: "PR.PS-01", name: "Configuration management practices are established and applied", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "PR.PS-02", name: "Software is maintained, replaced, and removed commensurate with risk", status: "compliant", lastAssessed: "2025-10-15" },
          { id: "PR.PS-04", name: "Log records are generated and made available for monitoring", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "PR.PS-06", name: "Secure software development practices are integrated", status: "partial", lastAssessed: "2025-09-15" },
        ]
      }
    ]
  },
  {
    id: "DE", name: "Detect", color: "amber", ringColor: "ring-amber-500/30",
    description: "Find and analyze possible cybersecurity attacks and compromises.",
    categories: [
      {
        id: "DE.CM", name: "Continuous Monitoring", complianceScore: 95,
        description: "Assets are monitored to find anomalies, indicators of compromise, and attacks.",
        subcategories: [
          { id: "DE.CM-01", name: "Networks and network services are monitored", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "DE.CM-02", name: "Physical environment is monitored", status: "compliant", lastAssessed: "2025-10-15" },
          { id: "DE.CM-03", name: "Personnel activity and technology usage are monitored", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "DE.CM-06", name: "External service provider activities and services are monitored", status: "partial", lastAssessed: "2025-10-01" },
          { id: "DE.CM-09", name: "Computing hardware and software, runtime environments are monitored", status: "compliant", lastAssessed: "2025-11-01" },
        ]
      },
      {
        id: "DE.AE", name: "Adverse Event Analysis", complianceScore: 88,
        description: "Anomalies, indicators of compromise, and other potentially adverse events are analyzed.",
        subcategories: [
          { id: "DE.AE-02", name: "Potentially adverse events are analyzed to better characterize attacks", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "DE.AE-03", name: "Information is correlated from multiple sources", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "DE.AE-04", name: "The estimated impact and scope of adverse events are understood", status: "partial", lastAssessed: "2025-10-01" },
          { id: "DE.AE-06", name: "Information on adverse events is provided to authorized staff", status: "compliant", lastAssessed: "2025-11-01" },
        ]
      }
    ]
  },
  {
    id: "RS", name: "Respond", color: "orange", ringColor: "ring-orange-500/30",
    description: "Take action regarding detected cybersecurity incidents.",
    categories: [
      {
        id: "RS.MA", name: "Incident Management", complianceScore: 87,
        description: "Responses to detected cybersecurity incidents are managed.",
        subcategories: [
          { id: "RS.MA-01", name: "Incident response plan is executed in coordination with relevant third parties", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "RS.MA-02", name: "Incident reports are triaged and validated", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "RS.MA-03", name: "Incidents are categorized and prioritized", status: "compliant", lastAssessed: "2025-10-15" },
          { id: "RS.MA-04", name: "Incidents are escalated or elevated as needed", status: "partial", lastAssessed: "2025-10-01" },
        ]
      },
      {
        id: "RS.MI", name: "Incident Mitigation", complianceScore: 91,
        description: "Activities are performed to prevent expansion of an event and eradicate the incident.",
        subcategories: [
          { id: "RS.MI-01", name: "Incidents are contained", status: "compliant", lastAssessed: "2025-11-01" },
          { id: "RS.MI-02", name: "Incidents are eradicated", status: "compliant", lastAssessed: "2025-11-01" },
        ]
      }
    ]
  },
  {
    id: "RC", name: "Recover", color: "cyan", ringColor: "ring-cyan-500/30",
    description: "Restore assets and operations that were impacted by a cybersecurity incident.",
    categories: [
      {
        id: "RC.RP", name: "Incident Recovery Plan Execution", complianceScore: 72,
        description: "Restoration activities are performed to ensure operational availability.",
        subcategories: [
          { id: "RC.RP-01", name: "The recovery portion of the incident response plan is executed", status: "compliant", lastAssessed: "2025-10-15" },
          { id: "RC.RP-03", name: "Recovery activities and progress in restoring operational capabilities are communicated", status: "partial", lastAssessed: "2025-09-15" },
          { id: "RC.RP-04", name: "The integrity of backups and other restoration assets is verified before using them", status: "partial", lastAssessed: "2025-09-01" },
          { id: "RC.RP-06", name: "The extent of the incident and the effectiveness of the response are documented", status: "non-compliant", lastAssessed: "2025-07-01" },
        ]
      }
    ]
  }
];
