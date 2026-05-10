import fs from 'fs';
import path from 'path';
import { Worker } from 'worker_threads';
import logger from '../utils/logger.js';

const PLUGINS_DIR = path.join(process.cwd(), 'plugins');
const activePlugins = [];

export const loadPlugins = async () => {
  if (!fs.existsSync(PLUGINS_DIR)) fs.mkdirSync(PLUGINS_DIR, { recursive: true });
  const files = fs.readdirSync(PLUGINS_DIR);
  
  for (const file of files) {
    if ((file.endsWith('.js') || file.endsWith('.mjs')) && file !== 'worker_runner.js' && file !== 'advanced_analysis.js') {
      try {
        const pluginPath = path.join(PLUGINS_DIR, file);
        const runnerPath = path.join(PLUGINS_DIR, 'worker_runner.js');
        if (!fs.existsSync(runnerPath)) continue;
        
        const worker = new Worker(runnerPath, { workerData: { pluginPath } });
        
        worker.on('message', (msg) => {
          if (msg.type === 'log') {
            if (msg.level === 'info') logger.info(msg.msg);
            else if (msg.level === 'warn') logger.warn(msg.msg);
            else logger.error(msg.msg);
          } else if (msg.type === 'ready') {
            activePlugins.push({ name: msg.name, worker });
            logger.info(`Loaded plugin (Worker sandboxed): ${msg.name}`);
          } else if (msg.type === 'error') {
            logger.error(`Plugin error (${file}): ${msg.error}`);
          }
        });
        
        worker.on('error', err => logger.error(`Plugin worker error ${file}: ${err.message}`));
      } catch (err) {
         logger.error(`Failed to load sandboxed plugin ${file}: ${err.message}`);
      }
    }
  }
};

export const getActivePlugins = () => {
  return activePlugins.map(p => ({
    name: p.name,
    hasInit: true,
    hasAnalyze: true
  }));
};

export const runPluginAnalysis = (analysis, logs, network, files) => {
  for (const plugin of activePlugins) {
    if (plugin.worker) {
      try { 
        plugin.worker.postMessage({ type: 'analyze', id: Date.now(), analysis, logs, network, files }); 
      } catch (e) { 
        logger.error(e, `Plugin analysis error in ${plugin.name}`); 
      }
    }
  }
};
