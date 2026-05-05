import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../backend/app.js';
import db from '../backend/config/db.js';

describe('Auth API', () => {
  beforeAll(() => {
    // Reset admin user state for consistent testing
    db.prepare('UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?').run('admin');
  });

  it('should return 401 for unauthorized /me', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  it('should return 404 for non-existent route', async () => {
    const res = await request(app).get('/non-existent');
    expect(res.status).toBe(404);
  });
  
  it('should return 200 for health check with supervisor data', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.supervisor).toBeDefined();
    expect(res.body.supervisor.status).toBe('healthy');
  });

  it('should lockout user after 5 failed attempts', async () => {
    const identifier = 'admin';
    const password = 'wrong-password';
    
    // First 4 attempts
    for(let i = 0; i < 4; i++) {
      const res = await request(app).post('/api/auth/login').send({ identifier, password });
      expect(res.status).toBe(401);
      expect(res.body.attemptsRemaining).toBe(4 - i);
    }
    
    // 5th attempt - should lockout
    const res5 = await request(app).post('/api/auth/login').send({ identifier, password });
    expect(res5.status).toBe(401);
    expect(res5.body.error).toContain('Account locked');
    
    // 6th attempt - should return 403 Forbidden with lockout message
    const res6 = await request(app).post('/api/auth/login').send({ identifier, password });
    expect(res6.status).toBe(403);
    expect(res6.body.error).toContain('Account locked');
  });
});
