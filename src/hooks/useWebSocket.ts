/**
 * useWebSocket — Centralized WebSocket hook
 * 
 * Manages the WS lifecycle (connect, auth, heartbeat, reconnect)
 * and pushes all incoming data directly into the Zustand store.
 * 
 * Extracted from App.tsx to improve code quality and reusability.
 */

import { useEffect, useRef } from 'react';
import { useSOCStore } from '../stores/socStore';
import { Token, WS_BASE } from '../utils/api';
import type { Connection, Alert, TrafficPoint, Permissions, SegmentData, SegmentMetrics } from '../stores/socStore';

type RawRecord = Record<string, unknown>;
type WsMessage = {
  event?: string;
  data?: unknown;
  ts?: number;
};

function timelineLabel(ts: number) {
  return new Intl.DateTimeFormat('en-US', {
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).format(ts);
}

function clock(ts: number) {
  return new Intl.DateTimeFormat('en-US', {
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  }).format(ts);
}

// Suspicious port risk map
const SUSPICIOUS_PORTS: Record<number, number> = {
  21: 20, 22: 10, 23: 30, 25: 25, 53: 15, 80: 10, 135: 30, 139: 30,
  443: 10, 445: 40, 1433: 35, 1521: 35, 3306: 35, 3389: 40, 5432: 30,
  5900: 25, 5901: 25, 6379: 30, 8080: 20, 8443: 15, 9200: 25, 9300: 25,
};

function isRecord(value: unknown): value is RawRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asRecordArray(value: unknown): RawRecord[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' && value.trim() ? value : fallback;
}

function asNumber(value: unknown, fallback = 0): number {
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function asTimestamp(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = new Date(value).getTime();
    if (Number.isFinite(parsed)) return parsed;
  }
  return Date.now();
}

function asSegmentMetrics(value: unknown): Record<string, SegmentMetrics> {
  return isRecord(value) ? value as Record<string, SegmentMetrics> : {};
}

function asAdvancedMonitoring(value: unknown): SegmentData['advancedMonitoring'] {
  return isRecord(value) ? value as SegmentData['advancedMonitoring'] : null;
}

function asPermissions(value: unknown): Permissions {
  return isRecord(value) ? value as Permissions : null;
}

function stableHash(value: string): string {
  let hash = 5381;
  for (let i = 0; i < value.length; i += 1) {
    hash = ((hash << 5) + hash) ^ value.charCodeAt(i);
  }
  return (hash >>> 0).toString(36);
}

function inferZone(port: number): string {
  if ([443, 80, 8080, 8443].includes(port)) return 'DMZ';
  if ([22, 3389].includes(port)) return 'Remote Access';
  if ([445, 139].includes(port)) return 'Internal';
  if ([3306, 5432, 1433, 1521].includes(port)) return 'Data Core';
  return 'System';
}

function mapNetworkToConnections(network: RawRecord[]): Connection[] {
  return network.map((c: RawRecord) => {
    const local = asString(c.local, 'Unknown');
    const foreign = asString(c.foreign, 'Unknown');
    const state = asString(c.state, 'UNKNOWN');
    const localParts = local.split(':');
    const port = parseInt(localParts[localParts.length - 1]) || 0;

    let risk = 0;
    if (state === 'LISTENING') risk = 30;
    else if (state === 'ESTABLISHED') risk = 10;
    if (SUSPICIOUS_PORTS[port]) risk = Math.max(risk, SUSPICIOUS_PORTS[port]);
    if (state === 'LISTENING' && SUSPICIOUS_PORTS[port] && SUSPICIOUS_PORTS[port] >= 30) {
      risk = Math.min(100, risk + 20);
    }

    return {
      id: `real-conn-${stableHash(`${local}|${foreign}|${state}|${port}`)}`,
      srcIp: local,
      dstIp: foreign,
      dstHost: foreign,
      protocol: 'SYSTEM' as const,
      port,
      pps: state === 'ESTABLISHED' ? 25 : state === 'LISTENING' ? 0 : 5,
      latency: state === 'ESTABLISHED' ? 20 : 0,
      risk,
      status: state === 'LISTENING' ? 'observing' as const : state === 'ESTABLISHED' ? 'active' as const : 'observing' as const,
      zone: inferZone(port),
      geo: 'Local',
      bytes: state === 'ESTABLISHED' ? 250000 : 0,
      lastSeen: Date.now(),
    };
  });
}

function mapLogsToAlerts(logs: RawRecord[]): Alert[] {
  return logs.map((l: RawRecord) => {
    const mitre = isRecord(l.Mitre) ? l.Mitre : null;
    const suspicious = Boolean(l.Suspicious);
    const ts = asTimestamp(l.Date);
    const srcIp = asString(l.Computer, 'Local');
    const dstHost = asString(l.ProviderName, asString(l.Source, 'System'));
    const signature = asString(l.Description, asString(l.description, asString(l.Message, 'No description')));
    const mitreId = asString(mitre?.id, 'N/A');

    return {
      id: `real-alert-${stableHash(`${ts}|${srcIp}|${dstHost}|${signature}`)}`,
      ts,
      srcIp,
      dstHost,
      protocol: 'SYSTEM' as const,
      category: 'Threat Detection',
      severity: suspicious ? 'high' as const : 'low' as const,
      mitreId,
      mitreName: asString(mitre?.name, 'System Event'),
      signature,
      score: suspicious ? 80 : 10,
      action: 'Logged',
      status: 'investigating' as const,
      malicious: suspicious,
      zone: asString(l.Zone, asString(l.zone, 'System')),
      killed: false,
    };
  });
}

export function useWebSocket() {
  const store = useSOCStore;
  const isAuthenticated = useSOCStore((s) => s.isAuthenticated);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeout = useRef<number>(1000);
  const lastPingRef = useRef<number>(0);
  const maxReconnectTimeout = 30000;

  useEffect(() => {
    if (!isAuthenticated || !Token.getAccess()) return;

    let isActive = true;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      if (!isActive) return;
      store.getState().setWsStatus('connecting');

      const ws = new WebSocket(WS_BASE);
      wsRef.current = ws;

      ws.onopen = () => {
        store.getState().setWsStatus('connected');
        reconnectTimeout.current = 1000;
        ws.send(JSON.stringify({ event: 'auth', token: Token.getAccess() }));

        // Heartbeat
        const hb = setInterval(() => {
          if (ws.readyState === 1) {
            lastPingRef.current = performance.now();
            ws.send(JSON.stringify({ event: 'ping', ts: Date.now() }));
          }
        }, 15000);
        ws.addEventListener('close', () => clearInterval(hb));
      };

      ws.onclose = () => {
        store.getState().setWsStatus('disconnected');
        wsRef.current = null;
        if (!isActive) return;
        reconnectTimer = setTimeout(() => {
          reconnectTimeout.current = Math.min(reconnectTimeout.current * 1.5, maxReconnectTimeout);
          connect();
        }, reconnectTimeout.current);
      };

      ws.onerror = () => { /* triggers onclose */ };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(String(event.data)) as WsMessage;
          if (!isRecord(msg) || typeof msg.event !== 'string') {
            throw new Error('Malformed WebSocket message');
          }
          const { getState } = store;

          if (msg.event === 'auth_ok') {
            getState().markTelemetryAuthenticated(asNumber(msg.ts, Date.now()));
          }

          // Heartbeat pong
          if (msg.event === 'pong' && lastPingRef.current > 0) {
            getState().setWsLatency(Math.round(performance.now() - lastPingRef.current));
            getState().recordTelemetryEvent('pong');
          }

          if (msg.event === 'new_logs') {
            const logRows = asRecordArray(msg.data);
            getState().recordTelemetryEvent('new_logs', { logs: logRows.length });
            getState().pushResponseLog(
              `${clock(asNumber(msg.ts, Date.now()))} Host log stored (${asString(logRows[0]?.id, 'event')})`
            );
          }

          if (msg.event === 'process_killed') {
            const data = isRecord(msg.data) ? msg.data : {};
            getState().recordTelemetryEvent('process_killed');
            getState().pushResponseLog(
              `${clock(asNumber(msg.ts, Date.now()))} Admin action: process ${asString(data.pid, 'unknown')} terminated`
            );
          }

          if (msg.event === 'segment_alert') {
            const data = isRecord(msg.data) ? msg.data : {};
            getState().recordTelemetryEvent('segment_alert', { segmentAlerts: getState().telemetryMeta.sourceCounts.segmentAlerts + 1 });
            getState().pushResponseLog(
              `${clock(asNumber(msg.ts, Date.now()))} SEGMENT ALERT: ${asString(data.segment, 'unknown')}/${asString(data.zone, 'unknown')} - ${asString(data.message, 'No message')}`
            );
          }

          if (msg.event === 'segment_alerts') {
            const rows = Array.isArray(msg.data) ? msg.data : [];
            getState().recordTelemetryEvent('segment_alerts', { segmentAlerts: rows.length });
            getState().updateSegmentData({ alerts: rows });
          }

          if (msg.event === 'permission_status') {
            getState().recordTelemetryEvent('permission_status', { permissions: 1 });
            getState().setPermissions(asPermissions(msg.data));
          }

          if (msg.event === 'telemetry_update') {
            const data = isRecord(msg.data) ? msg.data : {};

            // Segment data
            if (isRecord(data.segments)) {
              const segments = data.segments;
              getState().updateSegmentData({
                health: Array.isArray(segments.segmentHealth) ? segments.segmentHealth : [],
                summary: Array.isArray(segments.segmentSummary) ? segments.segmentSummary : [],
                metrics: asSegmentMetrics(segments.segmentMetrics),
                advancedMonitoring: asAdvancedMonitoring(segments.advancedMonitoring),
              });
            }

            // Connections
            const networkRows = asRecordArray(data.network);
            const realConns = mapNetworkToConnections(networkRows);
            getState().setConnections(realConns);

            // Alerts
            const logRows = asRecordArray(data.logs);
            const realAlerts = mapLogsToAlerts(logRows);
            getState().setAlerts(realAlerts);
            getState().recordTelemetryEvent('telemetry_update', {
              network: networkRows.length,
              logs: logRows.length,
              systemStats: isRecord(data.system) ? 1 : 0,
            });

            // Traffic timeline
            const ts = Date.now();
            const threatCount = realAlerts.filter((a) => a.malicious).length;
            const blockedCount = realAlerts.filter((a) => a.killed || a.status === 'auto-contained').length;
            const activeConns = realConns.filter((c) => c.status === 'active' || c.status === 'observing').length;
            const totalConns = realConns.length;
            const trafficPct = totalConns > 0 ? Math.min(100, Math.round((activeConns / totalConns) * 100)) : 0;

            const point: TrafficPoint = {
              ts,
              t: timelineLabel(ts),
              traffic: trafficPct,
              threats: threatCount,
              blocked: blockedCount,
              analysis: isRecord(data.analysis) ? asString(data.analysis.summary, 'Analyzing system telemetry...') : 'Analyzing system telemetry...',
            };
            getState().pushTrafficPoint(point);
          }
        } catch {
          store.getState().recordMalformedTelemetry();
        }
      };
    };

    connect();

    return () => {
      isActive = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, [isAuthenticated]);
}
