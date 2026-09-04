/**
 * SentinelGrid SOC — Centralized State Store (Zustand)
 * 
 * Single source of truth for all real-time telemetry, segment data,
 * WebSocket status, and system metrics. Replaces scattered useState
 * calls in App.tsx with a performant, subscription-based store.
 * 
 * Components only re-render when the specific slice they subscribe to changes.
 */

import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import type { User } from '../utils/api';

/* ── Shared Types ── */
export type Severity = "low" | "medium" | "high" | "critical";
export type Protocol = "HTTPS" | "SSH" | "RDP" | "DNS" | "TLS" | "MQTT" | "SMB" | "FTP" | "LDAP" | "SYSTEM";
export type ConnStatus = "active" | "observing" | "dropped" | "quarantined" | "blocked";
export type TabId = "dashboard" | "analytics" | "mitre" | "nist" | "virustotal" | "winlogs" | "intel" | "sandbox" | "vulnpentest" | "crossplat" | "advancedvb" | "ai_agent" | "ossec" | "scanner" | "vm";

export type Connection = {
  id: string;
  srcIp: string;
  dstIp: string;
  dstHost: string;
  protocol: Protocol;
  port: number;
  pps: number;
  latency: number;
  risk: number;
  status: ConnStatus;
  zone: string;
  geo: string;
  bytes: number;
  lastSeen: number;
  mitreId?: string;
};

export type Alert = {
  id: string;
  ts: number;
  srcIp: string;
  dstHost: string;
  protocol: Protocol;
  category: string;
  severity: Severity;
  mitreId: string;
  mitreName: string;
  signature: string;
  score: number;
  action: string;
  status: "auto-contained" | "investigating" | "false-positive";
  malicious: boolean;
  zone: string;
  killed: boolean;
};

export type TrafficPoint = {
  ts: number;
  t: string;
  traffic: number;
  threats: number;
  blocked: number;
  analysis: string;
};

export type SystemStats = {
  cpu: number;
  memory: number;
  uptime: number;
  timestamp: number;
  plugins?: number;
};

export type SegmentMetrics = {
  connections?: number;
  authEvents?: number;
  failedLogons?: number;
  totalProcesses?: number;
  suspiciousProcesses?: number;
  highRiskProcesses?: number;
  active?: number;
  risk?: number;
  [key: string]: unknown;
};

export type SegmentData = {
  segments: unknown[];
  health: unknown[];
  summary: unknown[];
  metrics: Record<string, SegmentMetrics>;
  alerts: unknown[];
  advancedMonitoring: {
    defender?: { Enabled: boolean };
    fimChanges?: unknown[];
    usbDevices?: { connected: unknown[] };
  } | null;
};

export type Permissions = {
  isAdmin: boolean;
  isElevated: boolean;
  canAccessSecurityLog: boolean;
  canAccessProcessMemory: boolean;
  canMonitorUSB: boolean;
  platform: string;
  recommendations: { priority: string; message: string }[];
} | null;

export type WsStatus = 'connecting' | 'connected' | 'disconnected';

export type TelemetrySourceCounts = {
  network: number;
  logs: number;
  segmentAlerts: number;
  permissions: number;
  systemStats: number;
  plugins: number;
};

export type TelemetryMeta = {
  authenticatedAt: number | null;
  lastUpdateAt: number | null;
  lastEvent: string;
  samplesReceived: number;
  malformedMessages: number;
  sourceCounts: TelemetrySourceCounts;
};

/* ── Store Shape ── */
type SOCState = {
  // Auth
  authReady: boolean;
  isAuthenticated: boolean;
  user: User | null;

  // Navigation
  tab: TabId;

  // Real-time data
  connections: Connection[];
  alerts: Alert[];
  traffic: TrafficPoint[];
  systemStats: SystemStats;
  statsHistory: { ts: number; cpu: number; mem: number }[];
  
  // Segment data
  segmentData: SegmentData;
  permissions: Permissions;

  // WebSocket
  wsStatus: WsStatus;
  wsLatency: number;

  // Response log
  responseLog: string[];

  // Telemetry integrity
  telemetryMeta: TelemetryMeta;

  // Actions
  setAuth: (authReady: boolean, isAuthenticated: boolean, user: User | null) => void;
  setTab: (tab: TabId) => void;
  setConnections: (connections: Connection[]) => void;
  setAlerts: (alerts: Alert[]) => void;
  pushTrafficPoint: (point: TrafficPoint) => void;
  setSystemStats: (stats: SystemStats) => void;
  pushStatsHistory: (point: { ts: number; cpu: number; mem: number }) => void;
  updateSegmentData: (partial: Partial<SegmentData>) => void;
  setPermissions: (perms: Permissions) => void;
  setWsStatus: (status: WsStatus) => void;
  setWsLatency: (latency: number) => void;
  pushResponseLog: (entry: string) => void;
  markTelemetryAuthenticated: (ts?: number) => void;
  recordTelemetryEvent: (event: string, sourceCounts?: Partial<TelemetrySourceCounts>) => void;
  recordMalformedTelemetry: () => void;
  resetStore: () => void;
};

const INITIAL_SEGMENT_DATA: SegmentData = {
  segments: [],
  health: [],
  summary: [],
  metrics: {},
  alerts: [],
  advancedMonitoring: null,
};

const INITIAL_STATS: SystemStats = { cpu: 0, memory: 0, uptime: 0, timestamp: Date.now() };

const INITIAL_SOURCE_COUNTS: TelemetrySourceCounts = {
  network: 0,
  logs: 0,
  segmentAlerts: 0,
  permissions: 0,
  systemStats: 0,
  plugins: 0,
};

const INITIAL_TELEMETRY_META: TelemetryMeta = {
  authenticatedAt: null,
  lastUpdateAt: null,
  lastEvent: 'awaiting-stream',
  samplesReceived: 0,
  malformedMessages: 0,
  sourceCounts: INITIAL_SOURCE_COUNTS,
};

export const useSOCStore = create<SOCState>()(
  subscribeWithSelector((set) => ({
    // Auth
    authReady: false,
    isAuthenticated: false,
    user: null,

    // Navigation
    tab: 'dashboard' as TabId,

    // Real-time data
    connections: [],
    alerts: [],
    traffic: [],
    systemStats: INITIAL_STATS,
    statsHistory: [],

    // Segment data
    segmentData: INITIAL_SEGMENT_DATA,
    permissions: null,

    // WebSocket
    wsStatus: 'disconnected' as WsStatus,
    wsLatency: 0,

    // Response log
    responseLog: [`System monitoring initialized at ${new Date().toLocaleTimeString()}`],

    // Telemetry integrity
    telemetryMeta: INITIAL_TELEMETRY_META,

    // Actions
    setAuth: (authReady, isAuthenticated, user) =>
      set({ authReady, isAuthenticated, user }),

    setTab: (tab) => set({ tab }),

    setConnections: (connections) => set({ connections }),

    setAlerts: (alerts) => set({ alerts }),

    pushTrafficPoint: (point) =>
      set((s) => ({ traffic: [...s.traffic.slice(-119), point] })),

    setSystemStats: (stats) => set({ systemStats: stats }),

    pushStatsHistory: (point) =>
      set((s) => ({ statsHistory: [...s.statsHistory.slice(-29), point] })),

    updateSegmentData: (partial) =>
      set((s) => ({ segmentData: { ...s.segmentData, ...partial } })),

    setPermissions: (perms) => set({ permissions: perms }),

    setWsStatus: (status) => set({ wsStatus: status }),

    setWsLatency: (latency) => set({ wsLatency: latency }),

    pushResponseLog: (entry) =>
      set((s) => ({ responseLog: [entry, ...s.responseLog].slice(0, 15) })),

    markTelemetryAuthenticated: (ts = Date.now()) =>
      set((s) => ({
        telemetryMeta: {
          ...s.telemetryMeta,
          authenticatedAt: ts,
          lastEvent: 'auth_ok',
        },
      })),

    recordTelemetryEvent: (event, sourceCounts = {}) =>
      set((s) => ({
        telemetryMeta: {
          ...s.telemetryMeta,
          lastUpdateAt: Date.now(),
          lastEvent: event,
          samplesReceived: s.telemetryMeta.samplesReceived + 1,
          sourceCounts: {
            ...s.telemetryMeta.sourceCounts,
            ...sourceCounts,
          },
        },
      })),

    recordMalformedTelemetry: () =>
      set((s) => ({
        telemetryMeta: {
          ...s.telemetryMeta,
          malformedMessages: s.telemetryMeta.malformedMessages + 1,
          lastEvent: 'malformed-message',
        },
      })),

    resetStore: () =>
      set({
        authReady: false,
        isAuthenticated: false,
        user: null,
        connections: [],
        alerts: [],
        traffic: [],
        systemStats: INITIAL_STATS,
        statsHistory: [],
        segmentData: INITIAL_SEGMENT_DATA,
        permissions: null,
        wsStatus: 'disconnected',
        wsLatency: 0,
        responseLog: [],
        telemetryMeta: INITIAL_TELEMETRY_META,
      }),
  }))
);

/* ── Derived Selectors (memoized via Zustand subscribeWithSelector) ── */

export const selectActiveCnt = (s: SOCState) =>
  s.connections.filter((c) => c.status === 'active' || c.status === 'observing').length;

export const selectBlockedCnt = (s: SOCState) =>
  s.connections.filter((c) => ['dropped', 'quarantined', 'blocked'].includes(c.status)).length;

export const selectMalAlerts = (s: SOCState) =>
  s.alerts.filter((a) => a.malicious);

export const selectCriticalCnt = (s: SOCState) =>
  s.alerts.filter((a) => a.severity === 'critical').length;

export const selectContainedCnt = (s: SOCState) =>
  s.alerts.filter((a) => a.status === 'auto-contained').length;

export const selectAvgRisk = (s: SOCState) =>
  s.connections.length > 0
    ? Math.round(s.connections.reduce((sum, c) => sum + c.risk, 0) / s.connections.length)
    : 0;

export const selectThreatPressure = (s: SOCState) => {
  const avgRisk = selectAvgRisk(s);
  const malCount = selectMalAlerts(s).length;
  return Math.min(100, Math.round((avgRisk + Math.min(100, malCount * 5)) / 2));
};

export const selectTotalPps = (s: SOCState) =>
  s.connections.reduce((sum, c) => sum + c.pps, 0);

export const selectTotalBytes = (s: SOCState) =>
  s.connections.reduce((sum, c) => sum + c.bytes, 0);

export const selectSevDist = (s: SOCState) =>
  s.alerts.reduce(
    (acc, a) => { acc[a.severity]++; return acc; },
    { low: 0, medium: 0, high: 0, critical: 0 } as Record<Severity, number>
  );

export const selectCatDist = (s: SOCState) => {
  const map = new Map<string, number>();
  s.alerts.forEach((a) => map.set(a.category, (map.get(a.category) ?? 0) + 1));
  return [...map.entries()].map(([name, value]) => ({ name, value }));
};
