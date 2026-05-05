import db from '../config/db.js';
import logger from '../utils/logger.js';
import { 
  hashPassword, 
  verifyPassword, 
  signAccessToken, 
  signRefreshToken, 
  signTempToken, 
  verifyTempToken,
  revokeRefreshToken,
  revokeAccessToken,
  verifyRefreshToken
} from '../utils/auth.js';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

const LOCKOUT_ATTEMPTS = 5;
const LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes

export const signup = async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });

  try {
    const existing = db.prepare('SELECT id FROM users WHERE username=? OR email=?').get(username, email);
    if (existing) return res.status(400).json({ error: 'Username or email already exists' });

    const passwordHash = await hashPassword(password);
    db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)')
      .run(username, email, passwordHash, 'analyst');

    logger.info({ username }, 'User signed up');
    res.status(201).json({ success: true, message: 'User created' });
  } catch (err) {
    logger.error(err, 'Signup error');
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const login = async (req, res) => {
  const { identifier, password, rememberMe } = req.body;
  
  try {
    const user = db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(identifier, identifier);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (user.locked_until && user.locked_until > Date.now()) {
      const remaining = Math.ceil((user.locked_until - Date.now()) / 60000);
      return res.status(403).json({ 
        error: `Account locked due to multiple failed attempts. Try again in ${remaining} minute(s).`,
        lockedUntil: user.locked_until
      });
    }

    if (!(await verifyPassword(password, user.password_hash))) {
      const now = Date.now();
      let attempts = user.failed_attempts + 1;
      let lockedUntil = 0;
      
      if (attempts >= LOCKOUT_ATTEMPTS) {
        lockedUntil = now + LOCKOUT_DURATION;
        logger.warn({ username: user.username }, 'Account locked due to brute force protection');
      }
      
      db.prepare('UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?')
        .run(attempts, lockedUntil, user.id);

      const msg = lockedUntil > 0 
        ? `Too many attempts. Account locked for 30 minutes.`
        : `Invalid credentials. ${LOCKOUT_ATTEMPTS - attempts} attempts remaining.`;

      return res.status(401).json({ 
        error: msg,
        attemptsRemaining: Math.max(0, LOCKOUT_ATTEMPTS - attempts),
        lockedUntil
      });
    }

    // Success: Reset failed attempts
    db.prepare("UPDATE users SET last_login=datetime('now'), failed_attempts=0, locked_until=0 WHERE id=?").run(user.id);

    if (!user.totp_enrolled) {
      const secret = speakeasy.generateSecret({ name: `SentinelGrid (${user.username})`, length: 20 });
      db.prepare('UPDATE users SET totp_secret=? WHERE id=?').run(secret.base32, user.id);
      const qrCode = await QRCode.toDataURL(secret.otpauth_url);
      const tempToken = signTempToken(user.id);
      return res.json({ step: 'enroll', qrCode, tempToken, rememberMe });
    }

    const tempToken = signTempToken(user.id);
    res.json({ step: '2fa', tempToken, rememberMe });
  } catch (err) {
    logger.error(err, 'Login error');
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const verify2FA = async (req, res) => {
  const { tempToken, code, rememberMe } = req.body;
  try {
    const payload = verifyTempToken(tempToken);
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(payload.sub);
    if (!user) return res.status(401).json({ error: 'User not found' });

    const valid = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (!valid) return res.status(401).json({ error: 'Invalid 2FA code' });

    if (!user.totp_enrolled) {
      db.prepare('UPDATE users SET totp_enrolled=1 WHERE id=?').run(user.id);
    }

    const { token: accessToken } = signAccessToken(user);
    const days = rememberMe ? 30 : 7;
    const { token: refreshToken } = signRefreshToken(user, days);

    res.cookie('sg_refresh_token', refreshToken, {
      httpOnly: true,
      path: '/',
      maxAge: days * 24 * 60 * 60 * 1000,
      sameSite: 'Strict',
      secure: process.env.NODE_ENV === 'production'
    });

    res.json({
      success: true,
      accessToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        lastLogin: user.last_login,
        createdAt: user.created_at
      }
    });
  } catch (err) {
    logger.error(err, '2FA verification error');
    res.status(401).json({ error: 'Verification failed' });
  }
};

export const refresh = async (req, res) => {
  const refreshToken = req.cookies.sg_refresh_token;
  if (!refreshToken) return res.status(401).json({ error: 'No refresh token' });

  try {
    const payload = verifyRefreshToken(refreshToken);
    const rec = db.prepare('SELECT * FROM refresh_tokens WHERE jti=?').get(payload.jti);
    
    if (!rec || rec.revoked || rec.expires_at < Date.now()) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id=?').get(payload.sub);
    if (!user) return res.status(401).json({ error: 'User not found' });

    revokeRefreshToken(payload.jti);
    const { token: newAccessToken } = signAccessToken(user);
    const { token: newRefreshToken } = signRefreshToken(user);

    res.cookie('sg_refresh_token', newRefreshToken, {
      httpOnly: true,
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'Strict',
      secure: process.env.NODE_ENV === 'production'
    });

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(401).json({ error: 'Refresh failed' });
  }
};

export const logout = (req, res) => {
  const refreshToken = req.cookies.sg_refresh_token;
  if (refreshToken) {
    try {
      const p = verifyRefreshToken(refreshToken);
      revokeRefreshToken(p.jti);
    } catch (e) {}
  }

  const auth = req.headers.authorization;
  if (auth?.startsWith('Bearer ')) {
    try {
      const p = verifyJWT(auth.slice(7));
      revokeAccessToken(p.jti, p.exp);
    } catch (e) {}
  }

  res.clearCookie('sg_refresh_token');
  res.json({ success: true });
};

export const me = (req, res) => {
  const user = db.prepare('SELECT id, username, email, role, last_login, created_at FROM users WHERE id=?').get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  res.json({
    authenticated: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      lastLogin: user.last_login,
      createdAt: user.created_at
    }
  });
};
