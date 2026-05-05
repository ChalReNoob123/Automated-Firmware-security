import fs from 'fs';
import path from 'path';
import vm from 'vm';
import logger from '../utils/logger.js';
import db from '../config/db.js';
import * as tf from '@tensorflow/tfjs';
import '@tensorflow/tfjs-backend-cpu';

const PLUGINS_DIR = path.join(process.cwd(), 'plugins');
const activePlugins = [];

export const loadPlugins = async () => {
  if (!fs.existsSync(PLUGINS_DIR)) fs.mkdirSync(PLUGINS_DIR, { recursive: true });
  const files = fs.readdirSync(PLUGINS_DIR);
  
  for (const file of files) {
    if (file.endsWith('.js') || file.endsWith('.mjs')) {
      try {
        const pluginPath = path.join(PLUGINS_DIR, file);
        const code = fs.readFileSync(pluginPath, 'utf8');
        
        const sandbox = { 
          db, logger, tf, console, 
          Buffer, setTimeout, setInterval,
          process: { env: { NODE_ENV: process.env.NODE_ENV } },
          exports: {} 
        };
        vm.createContext(sandbox);
        
        const script = new vm.Script(code);
        script.runInContext(sandbox);
        
        const instance = sandbox.exports || sandbox;
        if (instance.init) await instance.init({ db, logger });
        activePlugins.push({ name: instance.name || file, instance });
        logger.info(`Loaded plugin (sandboxed): ${instance.name || file}`);
      } catch (err) {
         logger.error(`Failed to load sandboxed plugin ${file}: ${err.message}`);
      }
    }
  }
};

export const getActivePlugins = () => {
  return activePlugins.map(p => ({
    name: p.name,
    hasInit: typeof p.instance.init === 'function',
    hasAnalyze: typeof p.instance.analyze === 'function'
  }));
};

export const runPluginAnalysis = (analysis, logs, network, files) => {
  for (const plugin of activePlugins) {
    if (typeof plugin.instance.analyze === 'function') {
      try { 
        plugin.instance.analyze(analysis, logs, network, files); 
      } catch (e) { 
        logger.error(e, `Plugin analysis error in ${plugin.name}`); 
      }
    }
  }
};
