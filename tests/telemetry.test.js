import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../backend/app.js';
import db from '../backend/config/db.js';

describe('Telemetry API Endpoints', () => {
  let authToken;

  beforeAll(async () => {
    // Generate a token or bypass auth for testing if possible,
    // For this test we will assume unauthenticated access fails.
  });

  it('should reject unauthenticated requests to /api/stats', async () => {
    const res = await request(app).get('/api/stats');
    expect(res.status).toBe(401);
  });

  it('should return 401 for /api/analyze', async () => {
    const res = await request(app).get('/api/analyze');
    expect(res.status).toBe(401);
  });

  it('should return 401 for /api/logs', async () => {
    const res = await request(app).get('/api/logs');
    expect(res.status).toBe(401);
  });
});
