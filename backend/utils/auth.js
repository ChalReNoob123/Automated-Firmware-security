import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import db from '../config/db.js';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret-change-me';

export const hashPassword = async (pw) => {
  return await bcrypt.hash(pw, 12);
};

export const verifyPassword = async (pw, hashed) => {
  return await bcrypt.compare(pw, hashed);
};

export const signAccessToken = (user) => {
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { sub: user.id, username: user.username, role: user.role, jti },
    JWT_SECRET,
    { expiresIn: '15m', issuer: 'sentinelgrid' }
  );
  return { token, jti };
};

export const signRefreshToken = (user, days = 7) => {
  const jti = crypto.randomUUID();
  const expiresAt = Date.now() + days * 24 * 60 * 60 * 1000;
  const token = jwt.sign(
    { sub: user.id, username: user.username, jti },
    JWT_REFRESH_SECRET,
    { expiresIn: `${days}d` }
  );
  
  db.prepare('INSERT INTO refresh_tokens (jti, user_id, username, expires_at) VALUES (?, ?, ?, ?)')
    .run(jti, user.id, user.username, expiresAt);
    
  return { token, jti, expiresAt };
};

export const verifyJWT = (token) => {
  return jwt.verify(token, JWT_SECRET, { issuer: 'sentinelgrid' });
};

export const verifyRefreshToken = (token) => {
  return jwt.verify(token, JWT_REFRESH_SECRET);
};

export const signTempToken = (userId) => {
  return jwt.sign({ sub: userId, type: 'temp' }, JWT_SECRET, { expiresIn: '5m' });
};

export const verifyTempToken = (token) => {
  const p = jwt.verify(token, JWT_SECRET);
  if (p.type !== 'temp') throw new Error('Not a temp token');
  return p;
};

export const isAccessTokenRevoked = (jti) => {
  return !!db.prepare('SELECT 1 FROM revoked_access_tokens WHERE jti=?').get(jti);
};

export const revokeRefreshToken = (jti) => {
  db.prepare('UPDATE refresh_tokens SET revoked=1 WHERE jti=?').run(jti);
};

export const revokeAccessToken = (jti, exp) => {
  db.prepare('INSERT OR IGNORE INTO revoked_access_tokens (jti, expires_at) VALUES (?, ?)').run(jti, exp * 1000);
};
