import http from 'http';
import { WebSocketServer } from 'ws';
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
});
