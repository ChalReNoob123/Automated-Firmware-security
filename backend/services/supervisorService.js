import logger from '../utils/logger.js';
import * as telemetryService from './telemetryService.js';
import { broadcast } from '../utils/websocket.js';

let supervisorInterval = null;
let telemetryLoopInterval = null;
let currentPollingRate = 5000;
let consecutiveFailures = 0;

export const startSupervisor = () => {
  logger.info('Supervisor Service started. Monitoring system resilience...');
  
  supervisorInterval = setInterval(async () => {
    try {
      // 1. Health Check
      const health = {
        uptime: process.uptime(),
        memory: process.memoryUsage().rss,
        timestamp: Date.now()
      };
      
      if (health.memory > 500 * 1024 * 1024) { // 500MB threshold
        logger.warn({ memory: health.memory }, 'High memory usage detected in SOC backend');
        // Potential logic for graceful restart or cache clearing
      }

      // 2. Self-Manage Polling Parameters
      // If many failures, slow down polling. If stable, speed up.
      if (consecutiveFailures > 3) {
        adjustPollingRate(10000); // Slow down to 10s
      } else if (consecutiveFailures === 0 && currentPollingRate > 5000) {
        adjustPollingRate(5000); // Return to normal
      }

    } catch (err) {
      logger.error(err, 'Supervisor health check failed');
    }
  }, 10000);

  startTelemetryLoop();
};

const startTelemetryLoop = () => {
  if (telemetryLoopInterval) clearInterval(telemetryLoopInterval);
  
  telemetryLoopInterval = setInterval(async () => {
    try {
      const snapshot = await telemetryService.collectSnapshot();
      broadcast('telemetry_update', snapshot);
      consecutiveFailures = 0;
    } catch (err) {
      consecutiveFailures++;
      logger.error({ err: err.message, consecutiveFailures }, 'Telemetry loop failure');
      
      // Auto-recovery mechanism
      if (consecutiveFailures >= 5) {
        logger.fatal('Critical telemetry failure threshold reached. Attempting service recovery...');
        restartTelemetryLoop();
      }
    }
  }, currentPollingRate);
};

const adjustPollingRate = (newRate) => {
  if (newRate === currentPollingRate) return;
  logger.info({ oldRate: currentPollingRate, newRate }, 'Adjusting telemetry polling rate for resilience');
  currentPollingRate = newRate;
  startTelemetryLoop();
};

const restartTelemetryLoop = () => {
  consecutiveFailures = 0;
  startTelemetryLoop();
};

export const getSystemHealth = () => ({
  status: consecutiveFailures > 0 ? 'degraded' : 'healthy',
  pollingRate: currentPollingRate,
  consecutiveFailures,
  uptime: process.uptime()
});
