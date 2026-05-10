import { parentPort, workerData } from 'worker_threads';
import fs from 'fs';
import path from 'path';

// Read-only DB proxy stub for worker
const db = {
  prepare: (sql) => {
    const normalised = sql.trim().toUpperCase();
    if (!normalised.startsWith('SELECT')) {
      throw new Error('Plugin DB access is read-only. Only SELECT queries are permitted.');
    }
    // We can't pass the actual sqlite DB instance to the worker. 
    // In a real isolated environment, we would use postMessage to query the main thread.
    // For now, we stub it to prevent arbitrary execution while allowing the plugin to load.
    return {
      all: () => [],
      get: () => null,
    };
  },
};

const logger = {
  info: (msg) => parentPort.postMessage({ type: 'log', level: 'info', msg }),
  error: (msg) => parentPort.postMessage({ type: 'log', level: 'error', msg }),
  warn: (msg) => parentPort.postMessage({ type: 'log', level: 'warn', msg })
};

const pluginPath = workerData.pluginPath;
const code = fs.readFileSync(pluginPath, 'utf8');

// Isolate context by evaluating inside a new Function
const exports = {};
const module = { exports };

try {
  const wrapper = new Function('exports', 'require', 'module', '__filename', '__dirname', 'db', 'logger', code);
  wrapper(exports, require, module, pluginPath, path.dirname(pluginPath), db, logger);
  
  const instance = module.exports || exports;
  
  (async () => {
    if (instance.init) {
      await instance.init({ db, logger });
    }
    parentPort.postMessage({ type: 'ready', name: instance.name || path.basename(pluginPath) });
    
    parentPort.on('message', async (msg) => {
      if (msg.type === 'analyze' && typeof instance.analyze === 'function') {
        try {
          // Pass copies of objects
          instance.analyze(msg.analysis, msg.logs, msg.network, msg.files);
          parentPort.postMessage({ type: 'analyze_done', id: msg.id, analysis: msg.analysis });
        } catch (e) {
          parentPort.postMessage({ type: 'error', error: e.message });
        }
      }
    });
  })();
} catch (err) {
  parentPort.postMessage({ type: 'error', error: err.message });
}
