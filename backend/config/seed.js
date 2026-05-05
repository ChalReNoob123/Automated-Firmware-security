import db from './db.js';
import { hashPassword } from '../utils/auth.js';
import logger from '../utils/logger.js';
import dotenv from 'dotenv';

dotenv.config();

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

export const seedDatabase = async () => {
  try {
    const exists = db.prepare('SELECT id FROM users WHERE username=?').get(ADMIN_USER);
    if (!exists) {
      const hashed = await hashPassword(ADMIN_PASS);
      db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)')
        .run(ADMIN_USER, `${ADMIN_USER}@sentinelgrid.local`, hashed, 'admin');
      logger.info({ username: ADMIN_USER }, 'Default admin user created');
    }
    
    // Seed patterns
    const ip = db.prepare('INSERT OR IGNORE INTO known_patterns (patternId, name, regex, mitre_tactic) VALUES (?, ?, ?, ?)');
    ip.run('T1110', 'Brute Force', '4625|Failed password', 'Credential Access');
    ip.run('T1070', 'Indicator Removal', '1102|Log clear', 'Defense Evasion');
    ip.run('T1059', 'Command Execution', '4688|/bin/sh|/bin/bash', 'Execution');
    
  } catch (err) {
    logger.error(err, 'Database seeding failed');
  }
};
