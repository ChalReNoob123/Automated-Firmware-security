import { describe, it, expect } from 'vitest';
import request from 'supertest';
import app from '../backend/app.js';

describe('Scanner API Endpoints', () => {
  it('should reject unauthenticated requests to /api/scanner/status', async () => {
    const res = await request(app).get('/api/scanner/status');
    expect(res.status).toBe(401);
  });

  it('should reject unauthenticated requests to /api/scanner/targets', async () => {
    const res = await request(app).get('/api/scanner/targets');
    expect(res.status).toBe(401);
  });

  it('should reject unauthenticated requests to /api/scanner/start', async () => {
    const res = await request(app).post('/api/scanner/start').send({ targets: ['C:\\'] });
    expect(res.status).toBe(401);
  });
});
