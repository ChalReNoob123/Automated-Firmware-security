import http from 'http';
import { WebSocketServer } from 'ws';
import { spawn } from 'child_process';
import app from './app.js';
import logger from './utils/logger.js';
import { verifyJWT, isAccessTokenRevoked } from './utils/auth.js';
import { seedDatabase } from './config/seed.js';
import { startSupervisor } from './services/supervisorService.js';
import { initAIModel } from './services/aiService.js';
import { loadPlugins } from './services/pluginService.js';
import { initWebSocket } from './utils/websocket.js';
import { startTelemetryBroadcaster } from './tasks/telemetryBroadcaster.js';

const PORT = parseInt(process.env.PORT || '3001', 10);

app.post('/api/log-error', (req, res) => {
  console.error('\n\n--- UI ERROR REPORT ---');
  console.error(req.body.stack);
  console.error(req.body.info);
  console.error('-----------------------\n\n');
  res.sendStatus(200);
});

const server = http.createServer(app);

// WebSocket setup
const wss = new WebSocketServer({ server });
initWebSocket(wss);

// Inject auth logic into WebSocket
wss.on('connection', (ws) => {
  ws.onAuth = (token, cb) => {
    try {
      const payload = verifyJWT(token);
      if (isAccessTokenRevoked(payload.jti)) return cb(new Error('Revoked'));
      cb(null);
    } catch (err) {
      cb(err);
    }
  };
});

server.listen(PORT, async () => {
  await seedDatabase();
  await initAIModel();
  await loadPlugins();
  startSupervisor();
  await startTelemetryBroadcaster(); // start broadcasting after server is up
  logger.info(`Modular Server running on port ${PORT}`);

  // Spawn the Python Virtualization Server (FastAPI on Port 3002)
  logger.info('Launching Python Virtualization Orchestrator (port 3002)...');
  const pyProc = spawn('python', ['backend/virtualization_server.py'], {
    stdio: 'inherit',
    shell: true
  });
  pyProc.on('error', (err) => {
    logger.error(`CRITICAL: Failed to launch Python Virtualization Server: ${err.message}`);
  });
  pyProc.on('close', (code) => {
    logger.warn(`Python Virtualization Server closed with exit code ${code}`);
  });
});
