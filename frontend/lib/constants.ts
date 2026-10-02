export const APP_NAME = "KEVIDENCE";
export const APP_DESCRIPTOR = "Vulnerability Intelligence & Risk Prioritization";

export const SCORING_WEIGHTS = {
  cvss: {
    weight: 0.30,
    percentage: "30%",
    label: "CVSS Severity",
    description: "Normalized technical severity from CVSS v3.1 base score",
  },
  epss: {
    weight: 0.30,
    percentage: "30%",
    label: "EPSS Likelihood",
    description: "Empirical exploit prediction scoring system probability",
  },
  kev: {
    weight: 0.40,
    percentage: "40%",
    label: "CISA KEV Status",
    description: "Active weaponization confirmed in CISA Known Exploited catalog",
  },
};

export const PRIORITY_THRESHOLDS = {
  CRITICAL: 0.75,
  HIGH: 0.50,
  MEDIUM: 0.25,
  LOW: 0.00,
};

export const RECOMMENDED_ACTIONS: Record<string, string> = {
  CRITICAL: "Patch immediately or apply vendor-recommended mitigations within 24 hours.",
  HIGH: "Prioritize patching within the next 7 days; apply mitigations if a patch is not yet available.",
  MEDIUM: "Schedule patching within the next 30 days as part of regular maintenance.",
  LOW: "Monitor for changes; patch during the next scheduled maintenance window.",
};

export const ORG_CONTEXT = {
  organization: "Acme Technologies Global",
  industry: "Financial Services & FinTech Infrastructure",
  assetCriticality: "Tier-1 Mission Critical",
  internetExposure: "High (Public-Facing Edge Gateways & API Endpoints)",
  affectedAsset: "Core Transaction Processing Cluster / Microservices Mesh",
  businessImpact: "High — Potential unauthorized data exfiltration or service disruption",
  relevanceByPriority: {
    CRITICAL: "HIGH",
    HIGH: "HIGH",
    MEDIUM: "MEDIUM",
    LOW: "LOW",
  } as Record<string, "HIGH" | "MEDIUM" | "LOW">,
};

export const INDUSTRIES = [
  "Financial Services & FinTech",
  "Healthcare & Life Sciences",
  "E-Commerce & Retail",
  "Cloud & SaaS Infrastructure",
  "Telecommunications",
];
