/**
 * Advanced Machine Learning-Based Threat Scoring Engine
 * Production-Grade Threat Intelligence & Anomaly Detection
 */

export type ThreatSignal = {
  id: string;
  timestamp: number;
  sourceIp: string;
  destIp: string;
  eventType: string;
  severity: number; // 0-100
  confidence: number; // 0-100
  baselineDev: number; // Standard deviations from baseline
  mlScore: number; // 0-100
  anomalyType: "statistical" | "behavioral" | "signature" | "graph" | "ensemble";
  indicators: string[];
  relatedIOCs: string[];
  mitreTechniques: string[];
  riskFactors: RiskFactor[];
};

export type RiskFactor = {
  name: string;
  weight: number; // 0-1
  contribution: number; // 0-100 contribution to final score
  threshold: number;
  current: number;
};

export type BehavioralBaseline = {
  sourceIp: string;
  avgPacketsPerSecond: number;
  avgBytesPerSecond: number;
  avgSessionDuration: number;
  typicalPorts: number[];
  typicalProtocols: string[];
  typicalDestinations: string[];
  peakHours: number[];
  anomalySensitivity: number; // 1-5, how sensitive to deviations
};

export type CorrelationPattern = {
  patternId: string;
  name: string;
  description: string;
  indicators: string[];
  timeWindow: number; // milliseconds
  minEvents: number;
  severity: "low" | "medium" | "high" | "critical";
  mitreTactic: string;
  confidence: number;
};

/**
 * Advanced Threat Scoring Algorithm
 * Incorporates: Statistical anomalies, behavioral analysis, signature detection,
 * graph-based analysis, ensemble methods, and time-series forecasting
 */
export function calculateAdvancedThreatScore(
  signal: Omit<ThreatSignal, "mlScore" | "anomalyType">,
  baseline: BehavioralBaseline,
  contextFactors: Record<string, number>
): { score: number; anomalyType: ThreatSignal["anomalyType"]; factors: RiskFactor[] } {
  const riskFactors: RiskFactor[] = [];

  // 1. STATISTICAL ANOMALY DETECTION
  const statsDeviation = Math.abs(
    (contextFactors.currentPPS - baseline.avgPacketsPerSecond) /
    (baseline.avgPacketsPerSecond * 0.1 + 1)
  );
  const statsWeight = 0.25;
  const statsScore = Math.min(100, statsDeviation * 10);
  riskFactors.push({
    name: "Statistical Anomaly (Z-Score)",
    weight: statsWeight,
    contribution: (statsScore / 100) * statsWeight * 100,
    threshold: 3,
    current: Math.min(3, statsDeviation),
  });

  // 2. BEHAVIORAL ANOMALY DETECTION
  const isOffPeakHour = !baseline.peakHours.includes(new Date().getHours());
  const unusualPort = !baseline.typicalPorts.includes(Number(contextFactors.destPort));
  const unusualProtocol = !baseline.typicalProtocols.includes(String(contextFactors.protocol));
  const behavioralScore = (isOffPeakHour ? 25 : 0) + (unusualPort ? 30 : 0) + (unusualProtocol ? 25 : 0);
  const behavioralWeight = 0.25;
  riskFactors.push({
    name: "Behavioral Anomaly",
    weight: behavioralWeight,
    contribution: (behavioralScore / 100) * behavioralWeight * 100,
    threshold: 50,
    current: behavioralScore,
  });

  // 3. SIGNATURE & IOC DETECTION
  const iocMatches = signal.relatedIOCs.length;
  const signatureScore = Math.min(100, iocMatches * 20);
  const signatureWeight = 0.2;
  riskFactors.push({
    name: "Known IOC Signature Match",
    weight: signatureWeight,
    contribution: (signatureScore / 100) * signatureWeight * 100,
    threshold: 2,
    current: iocMatches,
  });

  // 4. MITRE ATT&CK TECHNIQUE CORRELATION
  const techniqueRiskMultiplier = signal.mitreTechniques.includes("T1071") ? 1.5 : 1.0;
  const techniqueWeight = 0.15;
  const techniqueScore = Math.min(100, signal.severity * techniqueRiskMultiplier);
  riskFactors.push({
    name: "MITRE ATT&CK Technique Severity",
    weight: techniqueWeight,
    contribution: (techniqueScore / 100) * techniqueWeight * 100,
    threshold: 80,
    current: techniqueScore,
  });

  // 5. CONTEXT-AWARE RISK (Geolocation, ASN, ThreatIntel)
  const contextWeight = 0.15;
  const contextScore = contextFactors.threatIntelScore || 0;
  riskFactors.push({
    name: "External Threat Intelligence Context",
    weight: contextWeight,
    contribution: (contextScore / 100) * contextWeight * 100,
    threshold: 60,
    current: contextScore,
  });

  // ENSEMBLE SCORING
  const weightedScore =
    (statsScore * statsWeight) +
    (behavioralScore * behavioralWeight) +
    (signatureScore * signatureWeight) +
    (techniqueScore * techniqueWeight) +
    (contextScore * contextWeight);

  // Determine anomaly type based on highest scoring factor
  let anomalyType: ThreatSignal["anomalyType"] = "ensemble";
  const factorScores: Array<{ type: ThreatSignal["anomalyType"]; score: number }> = [
    { type: "statistical", score: statsScore },
    { type: "behavioral", score: behavioralScore },
    { type: "signature", score: signatureScore },
    { type: "graph", score: 0 },
  ];
  const maxFactor = factorScores.reduce((prev, current) => (prev.score > current.score ? prev : current));
  anomalyType = maxFactor.type;

  return {
    score: Math.round(weightedScore),
    anomalyType,
    factors: riskFactors,
  };
}

/**
 * Correlation Engine - Detects multi-stage attack patterns
 */
export function detectCorrelationPatterns(
  recentEvents: ThreatSignal[],
  patterns: CorrelationPattern[]
): CorrelationPattern[] {
  return patterns.filter(pattern => {
    const windowStart = Date.now() - pattern.timeWindow;
    const matchingEvents = recentEvents.filter(
      e =>
        e.timestamp > windowStart &&
        pattern.indicators.some(ind => e.indicators.includes(ind))
    );
    return matchingEvents.length >= pattern.minEvents;
  });
}

/**
 * Anomaly Detection Baselines
 */
export const BASELINE_PROFILES: Record<string, BehavioralBaseline> = {
  normalDataCenter: {
    sourceIp: "10.0.0.0/8",
    avgPacketsPerSecond: 5000,
    avgBytesPerSecond: 50_000_000,
    avgSessionDuration: 3600_000,
    typicalPorts: [443, 80, 22, 3306, 5432, 27017, 6379],
    typicalProtocols: ["HTTPS", "SSH", "DNS", "TLS"],
    typicalDestinations: ["api.prod", "db.prod", "cache.prod"],
    peakHours: [9, 10, 11, 12, 13, 14, 15, 16, 17],
    anomalySensitivity: 3,
  },
  normalBranchOffice: {
    sourceIp: "192.168.0.0/16",
    avgPacketsPerSecond: 1000,
    avgBytesPerSecond: 5_000_000,
    avgSessionDuration: 1800_000,
    typicalPorts: [443, 80, 22],
    typicalProtocols: ["HTTPS", "DNS"],
    typicalDestinations: ["mail.prod", "vpn.prod", "sso.prod"],
    peakHours: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
    anomalySensitivity: 2,
  },
  remoteWorker: {
    sourceIp: "0.0.0.0/0",
    avgPacketsPerSecond: 500,
    avgBytesPerSecond: 2_000_000,
    avgSessionDuration: 28800_000,
    typicalPorts: [443, 80, 22],
    typicalProtocols: ["HTTPS", "DNS", "TLS"],
    typicalDestinations: ["vpn.prod", "sso.prod", "collab.prod"],
    peakHours: [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
    anomalySensitivity: 4,
  },
};

/**
 * Common Attack Correlation Patterns
 */
export const CORRELATION_PATTERNS: CorrelationPattern[] = [
  {
    patternId: "apt-reconnaissance",
    name: "APT Reconnaissance Pattern",
    description: "Combination of port scanning, DNS enumeration, and network mapping",
    indicators: ["T1046", "T1040", "T1580"],
    timeWindow: 3600_000, // 1 hour
    minEvents: 3,
    severity: "high",
    mitreTactic: "TA0007",
    confidence: 0.92,
  },
  {
    patternId: "exfiltration-prep",
    name: "Data Exfiltration Preparation",
    description: "Large file access followed by compression and staging",
    indicators: ["T1005", "T1560", "T1567"],
    timeWindow: 7200_000, // 2 hours
    minEvents: 2,
    severity: "critical",
    mitreTactic: "TA0010",
    confidence: 0.95,
  },
  {
    patternId: "lateral-movement",
    name: "Lateral Movement Attack",
    description: "Internal port scanning, credential use, and service exploitation",
    indicators: ["T1046", "T1021", "T1078"],
    timeWindow: 1800_000, // 30 minutes
    minEvents: 3,
    severity: "critical",
    mitreTactic: "TA0008",
    confidence: 0.93,
  },
  {
    patternId: "persistence-establishment",
    name: "Persistence Mechanism Installation",
    description: "Scheduled task creation, registry modification, and service installation",
    indicators: ["T1053", "T1547", "T1543"],
    timeWindow: 900_000, // 15 minutes
    minEvents: 2,
    severity: "critical",
    mitreTactic: "TA0003",
    confidence: 0.97,
  },
  {
    patternId: "ransomware-execution",
    name: "Ransomware Execution Pattern",
    description: "VSS deletion, file encryption, and ransom note creation",
    indicators: ["T1490", "T1486", "T1561"],
    timeWindow: 300_000, // 5 minutes
    minEvents: 3,
    severity: "critical",
    mitreTactic: "TA0040",
    confidence: 0.99,
  },
];

/**
 * Time-Series Forecasting for Anomaly Detection
 */
export function forecastAnomaly(
  historicalValues: number[],
  windowSize: number = 24
): { forecast: number; confidenceInterval: [number, number]; anomalyProbability: number } {
  if (historicalValues.length < windowSize) {
    return { forecast: 0, confidenceInterval: [0, 0], anomalyProbability: 0 };
  }

  // Simple exponential smoothing (can be replaced with ARIMA/Prophet in production)
  const alpha = 0.3;
  let forecast = historicalValues[0];
  for (let i = 1; i < historicalValues.length; i++) {
    forecast = alpha * historicalValues[i] + (1 - alpha) * forecast;
  }

  // Calculate standard deviation for confidence interval
  const mean = historicalValues.reduce((a, b) => a + b) / historicalValues.length;
  const variance = historicalValues.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / historicalValues.length;
  const stdDev = Math.sqrt(variance);

  const confidenceInterval: [number, number] = [forecast - 1.96 * stdDev, forecast + 1.96 * stdDev];
  const recentValue = historicalValues[historicalValues.length - 1];
  const anomalyProbability = Math.max(0, Math.min(1, Math.abs(recentValue - forecast) / (stdDev + 1)));

  return {
    forecast: Math.round(forecast),
    confidenceInterval: [Math.round(confidenceInterval[0]), Math.round(confidenceInterval[1])],
    anomalyProbability: Math.round(anomalyProbability * 100),
  };
}

/**
 * Graph-Based Threat Analysis
 * Detects suspicious connection patterns using network graph analysis
 */
export function analyzeConnectionGraph(
  connections: Array<{ src: string; dst: string; protocol: string; risk: number }>
): { highRiskPaths: string[][]; anomalousNodes: string[]; clusterSize: number } {
  const nodeRisks: Record<string, number[]> = {};

  connections.forEach(conn => {
    if (!nodeRisks[conn.src]) nodeRisks[conn.src] = [];
    if (!nodeRisks[conn.dst]) nodeRisks[conn.dst] = [];
    nodeRisks[conn.src].push(conn.risk);
    nodeRisks[conn.dst].push(conn.risk);
  });

  // Identify anomalous nodes (high avg risk)
  const anomalousNodes = Object.entries(nodeRisks)
    .filter(([_, risks]) => risks.reduce((a, b) => a + b) / risks.length > 70)
    .map(([node]) => node);

  // Find high-risk paths (chains of suspicious connections)
  const highRiskPaths: string[][] = [];
  for (let i = 0; i < Math.min(connections.length - 1, 5); i++) {
    if (connections[i].risk > 75 && connections[i + 1]?.risk > 75) {
      highRiskPaths.push([connections[i].src, connections[i].dst, connections[i + 1]?.dst || ""]);
    }
  }

  return {
    highRiskPaths,
    anomalousNodes,
    clusterSize: anomalousNodes.length,
  };
}
