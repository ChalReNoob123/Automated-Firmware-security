import { verifyJWT, isAccessTokenRevoked } from '../utils/auth.js';
import logger from '../utils/logger.js';

export const authenticate = (req, res, next) => {
  try {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = auth.slice(7);
    const payload = verifyJWT(token);
    
    if (isAccessTokenRevoked(payload.jti)) {
      return res.status(401).json({ error: 'Token revoked' });
    }
    
    req.user = payload;
    next();
  } catch (err) {
    logger.warn({ err: err.message }, 'Authentication failed');
    return res.status(401).json({ error: 'Unauthorized: ' + err.message });
  }
};

export const authorize = (permissions = []) => {
  const requiredPermissions = Array.isArray(permissions) ? permissions : [permissions];
  
  const ROLE_PERMISSIONS = {
    admin: ['read:all', 'write:all', 'exec:kill', 'manage:users'],
    analyst: ['read:all', 'write:logs'],
    viewer: ['read:telemetry']
  };

  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    
    // Special case for role-based check if the "permission" matches a role
    if (requiredPermissions.length === 1 && ROLE_PERMISSIONS[requiredPermissions[0]]) {
      if (req.user.role === requiredPermissions[0]) return next();
    }

    const userPermissions = ROLE_PERMISSIONS[req.user.role] || [];
    const hasPermission = requiredPermissions.every(p => userPermissions.includes(p));
    
    if (!hasPermission) {
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
    }
    next();
  };
};
