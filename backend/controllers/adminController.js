import { execFileSync } from 'child_process';
import os from 'os';
import logger from '../utils/logger.js';
import db from '../config/db.js';

export const killProcess = (req, res) => {
  const { pid } = req.body;
  if (!pid || !/^\d+$/.test(pid.toString())) {
    return res.status(400).json({ error: 'Valid PID required' });
  }

  try {
    if (os.platform() === 'win32') {
      execFileSync('taskkill', ['/F', '/PID', String(pid)], { timeout: 5000 });
    } else {
      execFileSync('kill', ['-9', String(pid)], { timeout: 5000 });
    }
    logger.warn({ pid, by: req.user.username }, 'Process killed');
    res.json({ success: true, message: `Process ${pid} terminated.` });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: err.message });
  }
};

export const resetTOTP = (req, res) => {
  const { targetUsername } = req.body;
  if (!targetUsername) return res.status(400).json({ error: 'Target username required' });

  try {
    db.prepare('UPDATE users SET totp_enrolled=0, totp_secret=NULL WHERE username=?').run(targetUsername);
    logger.info({ admin: req.user.username, target: targetUsername }, 'TOTP reset');
    res.json({ success: true, message: `TOTP reset for ${targetUsername}` });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Failed to reset TOTP' });
  }
};
