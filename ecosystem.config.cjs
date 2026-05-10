// PM2 Ecosystem Config — Gap #9: Process manager for fault tolerance
// Usage:
//   npm install -g pm2
//   pm2 start ecosystem.config.cjs
//   pm2 save && pm2 startup   ← auto-restart on reboot

const fs = require('fs');
if (!fs.existsSync('./logs')) fs.mkdirSync('./logs', { recursive: true });

module.exports = {
  apps: [
    {
      name:         'sentinelgrid-backend',
      script:       'backend/server.js',
      interpreter:  'node',
      instances:    'max',              // scale to 'max' for cluster mode
      exec_mode:    'cluster',
      watch:        false,
      max_memory_restart: '512M',
      restart_delay: 3000,
      max_restarts:  10,
      env: {
        NODE_ENV: 'development',
        PORT:     3001,
      },
      env_production: {
        NODE_ENV: 'production',
        PORT:     3001,
      },
      // Structured log output (pino writes to stdout)
      out_file:  './logs/backend-out.log',
      error_file: './logs/backend-err.log',
      merge_logs: true,
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    },
  ],
};
