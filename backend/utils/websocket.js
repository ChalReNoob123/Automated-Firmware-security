import logger from './logger.js';
import { spawn } from 'child_process';
import os from 'os';

let wsClients = new Set();
const MAX_WS_MESSAGE_BYTES = 40960; // Increased for terminal output
const MAX_WS_MESSAGES_PER_MINUTE = 900; // Increased for terminal typing

const isRateLimited = (ws) => {
  const now = Date.now();
  if (!ws.rateWindowStart || now - ws.rateWindowStart > 60_000) {
    ws.rateWindowStart = now;
    ws.rateWindowCount = 0;
  }
  ws.rateWindowCount += 1;
  return ws.rateWindowCount > MAX_WS_MESSAGES_PER_MINUTE;
};

export const initWebSocket = (wss) => {
  wss.on('connection', (ws) => {
    ws.isAuthed = false;
    ws.rateWindowStart = Date.now();
    ws.rateWindowCount = 0;
    ws.shellProcess = null;
    
    const authTimeout = setTimeout(() => {
      if (!ws.isAuthed) ws.close(4001, 'Unauthorized');
    }, 8000);

    ws.on('message', (raw) => {
      try {
        const payload = String(raw);
        if (Buffer.byteLength(payload, 'utf8') > MAX_WS_MESSAGE_BYTES) {
          ws.close(1009, 'Message too large');
          return;
        }
        if (isRateLimited(ws)) {
          ws.close(1008, 'Rate limit exceeded');
          return;
        }

        const msg = JSON.parse(payload);
        if (!msg || typeof msg.event !== 'string') {
          ws.close(1008, 'Malformed event');
          return;
        }

        if (msg.event === 'auth' && msg.token) {
          if (ws.onAuth) ws.onAuth(msg.token, (err) => {
            if (err) {
               ws.close(4001, 'Unauthorized');
            } else {
               ws.isAuthed = true;
               clearTimeout(authTimeout);
               wsClients.add(ws);
               ws.send(JSON.stringify({ event: 'auth_ok', ts: Date.now() }));
               logger.info('WS Client Authenticated');
            }
          });
          return;
        }

        if (msg.event === 'ping' && ws.isAuthed) {
          ws.send(JSON.stringify({ event: 'pong', ts: Date.now() }));
          return;
        }

        // Terminal logic for TryHackMe VM equivalent
        if (msg.event === 'terminal_start' && ws.isAuthed) {
          if (ws.shellProcess) return; // already running
          const shellPath = os.platform() === 'win32' ? 'powershell.exe' : 'bash';
          logger.info(`Starting interactive VM shell: ${shellPath}`);
          ws.shellProcess = spawn(shellPath, [], {
            cwd: process.cwd(),
            env: process.env
          });

          ws.shellProcess.stdout.on('data', (data) => {
            if (ws.readyState === 1) {
              ws.send(JSON.stringify({ event: 'terminal_output', data: data.toString() }));
            }
          });

          ws.shellProcess.stderr.on('data', (data) => {
            if (ws.readyState === 1) {
              ws.send(JSON.stringify({ event: 'terminal_output', data: data.toString() }));
            }
          });

          ws.shellProcess.on('close', (code) => {
            logger.info(`VM shell exited with code ${code}`);
            ws.shellProcess = null;
            if (ws.readyState === 1) {
               ws.send(JSON.stringify({ event: 'terminal_exit', code }));
            }
          });
          return;
        }

        if (msg.event === 'terminal_input' && ws.isAuthed && ws.shellProcess) {
          ws.shellProcess.stdin.write(msg.data);
          return;
        }

        if (msg.event === 'terminal_stop' && ws.isAuthed && ws.shellProcess) {
          ws.shellProcess.kill();
          return;
        }

        ws.close(1008, 'Unsupported event');
      } catch (err) {
        logger.warn({ err }, 'Rejected malformed WebSocket message');
        ws.close(4001, 'Unauthorized');
      }
    });

    ws.on('close', () => {
      clearTimeout(authTimeout);
      wsClients.delete(ws);
      if (ws.shellProcess) {
        ws.shellProcess.kill();
      }
    });
  });
};

export const broadcast = (event, data) => {
  const msg = JSON.stringify({ event, data, ts: Date.now() });
  wsClients.forEach(ws => {
    if (ws.readyState === 1 && ws.isAuthed) ws.send(msg);
  });
};
