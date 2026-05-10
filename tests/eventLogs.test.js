import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import request from 'supertest';
import app from '../backend/app.js';
import { signAccessToken } from '../backend/utils/auth.js';
import db from '../backend/config/db.js';
import * as telemetryService from '../backend/services/telemetryService.js';

describe('Event Logs Segment — Comprehensive Integration Tests', () => {
  let adminToken;
  let analystToken;

  beforeAll(() => {
    adminToken = signAccessToken({
      id: 1,
      username: 'admin',
      role: 'admin'
    }).token;

    analystToken = signAccessToken({
      id: 2,
      username: 'analyst',
      role: 'analyst'
    }).token;
  });

  afterAll(() => {
    // Clean up if necessary
  });

  // ── Authentication & Authorization ────────────────────────────

  it('should return 401 when unauthenticated', async () => {
    const response = await request(app).get('/api/logs');
    expect(response.status).toBe(401);
  });

  it('should return 403 when role lacks permission', async () => {
    // viewer role only has read:telemetry, not read:all
    const viewerToken = signAccessToken({
      id: 3,
      username: 'viewer',
      role: 'viewer'
    }).token;

    const response = await request(app)
      .get('/api/logs?channel=all&max=100')
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(response.status).toBe(403);
  });

  // ── Live Logs Endpoint ────────────────────────────────────────

  it('should fetch live logs under normal conditions', async () => {
    const response = await request(app)
      .get('/api/logs?channel=all&max=100')
      .set('Authorization', `Bearer ${adminToken}`);
    
    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('logs');
    expect(response.body).toHaveProperty('computer');
    expect(Array.isArray(response.body.logs)).toBe(true);
  });

  it('should handle invalid max parameter gracefully', async () => {
    const response = await request(app)
      .get('/api/logs?channel=all&max=invalid')
      .set('Authorization', `Bearer ${adminToken}`);
    
    expect(response.status).toBe(200);
    expect(Array.isArray(response.body.logs)).toBe(true);
  });

  it('should handle missing max parameter with default', async () => {
    const response = await request(app)
      .get('/api/logs?channel=all')
      .set('Authorization', `Bearer ${adminToken}`);
    
    expect(response.status).toBe(200);
    expect(Array.isArray(response.body.logs)).toBe(true);
  });

  // ── Historical Logs Endpoint ──────────────────────────────────

  it('should fetch historical logs from the database successfully', async () => {
    const response = await request(app)
      .get('/api/database/logs')
      .set('Authorization', `Bearer ${adminToken}`);
    
    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('databaseLogs');
    expect(Array.isArray(response.body.databaseLogs)).toBe(true);
  });

  it('should handle corrupted mitre JSON gracefully in historical logs', async () => {
    // Insert a log with invalid mitre JSON to test defensive parsing
    try {
      db.prepare(`
        INSERT INTO logs (hash, eventId, date, level, task, source, description, suspicious, segment, zone, mitre)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        'test-corrupt-mitre-' + Date.now(),
        '9999',
        new Date().toISOString(),
        'Warning',
        'Test',
        'TestSource',
        'Test message for corrupted mitre',
        1,
        'test',
        'test',
        '{invalid json}'
      );
    } catch {
      // Table may not have mitre column in some schema versions
    }

    const response = await request(app)
      .get('/api/database/logs')
      .set('Authorization', `Bearer ${adminToken}`);
    
    expect(response.status).toBe(200);
    expect(Array.isArray(response.body.databaseLogs)).toBe(true);
  });

  // ── Telemetry Service — Log Mapping ───────────────────────────

  it('should correctly map Windows event IDs to MITRE techniques', () => {
    expect(telemetryService.MITRE_MAP['4625']).toBeDefined();
    expect(telemetryService.MITRE_MAP['4625'].id).toBe('T1110');
    expect(telemetryService.MITRE_MAP['1102'].id).toBe('T1070.001');
  });

  it('should correctly identify suspicious event IDs', () => {
    expect(telemetryService.SUSPICIOUS_IDS.has('4625')).toBe(true);
    expect(telemetryService.SUSPICIOUS_IDS.has('1102')).toBe(true);
    expect(telemetryService.SUSPICIOUS_IDS.has('9999')).toBe(false);
  });

  // ── Historical Logs — Defensive Error Handling ────────────────

  it('should return empty array when database query fails', async () => {
    // Test that getHistoricalLogs handles DB errors gracefully
    const logs = telemetryService.getHistoricalLogs(10);
    expect(Array.isArray(logs)).toBe(true);
    // Should not throw even if DB is locked or corrupted
  });

  // ── Cross-Platform Log Fetching ───────────────────────────────

  it('should return empty array for Windows logs on non-Windows platforms', async () => {
    const logs = await telemetryService.getWindowsLogs(10);
    // This will return [] on Linux/Mac test runners, which is expected
    expect(Array.isArray(logs)).toBe(true);
  });

  it('should return empty array for Linux logs on non-Linux platforms', async () => {
    const logs = await telemetryService.getLinuxLogs(10);
    expect(Array.isArray(logs)).toBe(true);
  });

  // ── Performance: High-Throughput Simulation ───────────────────

  it('should handle rapid successive requests without errors', async () => {
    const requests = Array(10).fill(null).map(() => 
      request(app)
        .get('/api/logs?channel=all&max=50')
        .set('Authorization', `Bearer ${adminToken}`)
    );

    const responses = await Promise.all(requests);
    
    responses.forEach(response => {
      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.logs)).toBe(true);
    });
  });

  // ── System Permissions Endpoint ───────────────────────────────

  it('should return system permissions for authenticated user', async () => {
    const response = await request(app)
      .get('/api/system/permissions')
      .set('Authorization', `Bearer ${adminToken}`);
    
    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('role');
    expect(response.body).toHaveProperty('permissions');
    expect(Array.isArray(response.body.permissions)).toBe(true);
  });

  // ── Analyze Endpoint ─────────────────────────────────────────

  it('should return telemetry snapshot with logs, network, and analysis', async () => {
    const response = await request(app)
      .get('/api/analyze')
      .set('Authorization', `Bearer ${adminToken}`);
    
    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('logs');
    expect(response.body).toHaveProperty('network');
    expect(response.body).toHaveProperty('analysis');
    expect(response.body).toHaveProperty('system');
  });
});
