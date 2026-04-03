// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Health Route Tests
// ═══════════════════════════════════════════════════════════════════════
import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';

// Mock database before importing route
vi.mock('../services/database', () => ({
  getDb: () => ({
    $queryRaw: vi.fn().mockResolvedValue([{ result: 1 }]),
  }),
}));

vi.mock('../services/redis', () => ({
  getRedis: () => null,
}));

import healthRoutes from '../routes/health';

const app = express();
app.use(express.json());
app.use('/', healthRoutes);

describe('GET /health', () => {
  it('returns 200 with status ok', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.timestamp).toBeDefined();
    expect(res.body.version).toBeDefined();
  });
});

describe('GET /health/ready', () => {
  it('returns 200 with database connected', async () => {
    const res = await request(app).get('/health/ready');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ready');
    expect(res.body.database).toBe('connected');
  });
});
