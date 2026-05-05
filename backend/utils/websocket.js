import logger from './logger.js';

let wsClients = new Set();

export const initWebSocket = (wss) => {
  wss.on('connection', (ws) => {
    ws.isAuthed = false;
    
    const authTimeout = setTimeout(() => {
      if (!ws.isAuthed) ws.close(4001, 'Unauthorized');
    }, 8000);

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(String(raw));
        // Note: we can't import verifyJWT here easily due to circular deps, 
        // so we'll pass a verify function or handle it in server.js
        if (msg.event === 'auth' && msg.token) {
          // This will be handled in server.js by setting a callback
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
        }
      } catch (err) {
        ws.close(4001, 'Unauthorized');
      }
    });

    ws.on('close', () => {
      wsClients.delete(ws);
    });
  });
};

export const broadcast = (event, data) => {
  const msg = JSON.stringify({ event, data, ts: Date.now() });
  wsClients.forEach(ws => {
    if (ws.readyState === 1 && ws.isAuthed) ws.send(msg);
  });
};
