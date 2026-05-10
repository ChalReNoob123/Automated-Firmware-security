import { broadcast } from '../utils/websocket.js';
import * as telemetryService from '../services/telemetryService.js';
import logger from '../utils/logger.js';

// Configurable interval (ms)
const INTERVAL_MS = Number(process.env.TELEMETRY_BROADCAST_INTERVAL) || 5000;

let intervalId = null;
let isRunning = false;

export const startTelemetryBroadcaster = () => {
  if (isRunning) return; // already running
  isRunning = true;
  logger.info(`Starting telemetry broadcaster (every ${INTERVAL_MS} ms)`);
  intervalId = setInterval(async () => {
    try {
      // Fetch logs from all platforms concurrently with individual error boundaries
      const [winLogs, linuxLogs, androidLogs, files, analysis] = await Promise.allSettled([
        telemetryService.getWindowsLogs(50),
        telemetryService.getLinuxLogs(50),
        telemetryService.getAndroidLogs(50),
        telemetryService.getFileChanges(),
        telemetryService.analyzeTelemetry()
      ]);

      const allLogs = [
        ...(winLogs.status === 'fulfilled' ? winLogs.value : []),
        ...(linuxLogs.status === 'fulfilled' ? linuxLogs.value : []),
        ...(androidLogs.status === 'fulfilled' ? androidLogs.value : [])
      ];

      // Sort by timestamp descending for newest-first display
      allLogs.sort((a, b) => {
        const ta = a.TimeCreated ? new Date(a.TimeCreated).getTime() : 0;
        const tb = b.TimeCreated ? new Date(b.TimeCreated).getTime() : 0;
        return tb - ta;
      });

      // Enrich logs with suspicious flag and mitre mapping
      const enrichedLogs = allLogs.map(log => {
        const eventId = String(log.Id || '0');
        const isSuspicious = telemetryService.SUSPICIOUS_IDS?.has?.(eventId) || false;
        const mitre = telemetryService.MITRE_MAP?.[eventId] || null;
        return { ...log, Suspicious: isSuspicious, Mitre: mitre };
      });

      broadcast('telemetry_update', {
        logs: enrichedLogs.slice(0, 100),
        files: files.status === 'fulfilled' ? files.value : [],
        analysis: analysis.status === 'fulfilled' ? analysis.value : { score: 0, threats: [] }
      });

      // Also send new_logs event for backward compatibility with older clients
      if (enrichedLogs.length > 0) {
        broadcast('new_logs', enrichedLogs.slice(0, 10));
      }
    } catch (err) {
      logger.error({ err }, 'Telemetry broadcast error');
    }
  }, INTERVAL_MS);
};

export const stopTelemetryBroadcaster = () => {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
    isRunning = false;
    logger.info('Telemetry broadcaster stopped');
  }
};
