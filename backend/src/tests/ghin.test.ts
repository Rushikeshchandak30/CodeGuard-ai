// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — GHIN Route Tests
// ═══════════════════════════════════════════════════════════════════════
import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';

const mockGhinPackage = {
  id: 'test-id',
  packageName: 'faker-colors-js',
  ecosystem: 'NPM',
  reportCount: 3,
  status: 'CONFIRMED',
  firstSeenAt: new Date(),
  lastSeenAt: new Date(),
  verifiedAt: new Date(),
  metadata: null,
};

vi.mock('../services/database', () => ({
  getDb: () => ({
    ghinPackage: {
      findUnique: vi.fn().mockResolvedValue(mockGhinPackage),
      findMany: vi.fn().mockResolvedValue([mockGhinPackage]),
      count: vi.fn().mockResolvedValue(1),
      groupBy: vi.fn().mockResolvedValue([{ ecosystem: 'NPM', _count: { ecosystem: 1 } }]),
    },
    ghinReport: {
      count: vi.fn().mockResolvedValue(5),
    },
  }),
}));

vi.mock('../services/redis', () => ({
  cacheGet: vi.fn().mockResolvedValue(null),
  cacheSet: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../middleware/auth', () => ({
  optionalAuth: (_req: any, _res: any, next: any) => next(),
  requireAuth: (_req: any, _res: any, next: any) => {
    _req.user = { id: 'user-1', email: 'test@test.com', role: 'USER' };
    next();
  },
}));

import ghinRoutes from '../routes/ghin';

const app = express();
app.use(express.json());
app.use('/api/ghin', ghinRoutes);

describe('GET /api/ghin/check/:ecosystem/:packageName', () => {
  it('returns package info for known hallucination', async () => {
    const res = await request(app).get('/api/ghin/check/NPM/faker-colors-js');
    expect(res.status).toBe(200);
    expect(res.body.packageName).toBe('faker-colors-js');
    expect(res.body.ecosystem).toBe('NPM');
    expect(res.body.known).toBe(true);
    expect(res.body.status).toBe('CONFIRMED');
  });

  it('returns known=false for unknown package', async () => {
    const { getDb } = await import('../services/database');
    (getDb as any)().ghinPackage.findUnique.mockResolvedValueOnce(null);

    const res = await request(app).get('/api/ghin/check/NPM/lodash');
    expect(res.status).toBe(200);
    expect(res.body.known).toBe(false);
    expect(res.body.status).toBeNull();
  });
});

describe('GET /api/ghin/stats', () => {
  it('returns network statistics', async () => {
    const res = await request(app).get('/api/ghin/stats');
    expect(res.status).toBe(200);
    expect(res.body.totalPackages).toBeDefined();
    expect(res.body.confirmedHallucinations).toBeDefined();
    expect(res.body.totalReports).toBeDefined();
    expect(res.body.ecosystems).toBeInstanceOf(Array);
  });
});

describe('POST /api/ghin/check-bulk', () => {
  it('returns results for multiple packages', async () => {
    const res = await request(app)
      .post('/api/ghin/check-bulk')
      .send({
        packages: [
          { name: 'faker-colors-js', ecosystem: 'NPM' },
          { name: 'lodash', ecosystem: 'NPM' },
        ],
      });
    expect(res.status).toBe(200);
    expect(res.body.results).toBeInstanceOf(Array);
    expect(res.body.results).toHaveLength(2);
  });

  it('rejects empty packages array', async () => {
    const res = await request(app)
      .post('/api/ghin/check-bulk')
      .send({ packages: [] });
    expect(res.status).toBe(400);
  });

  it('rejects more than 100 packages', async () => {
    const res = await request(app)
      .post('/api/ghin/check-bulk')
      .send({
        packages: Array.from({ length: 101 }, (_, i) => ({ name: `pkg-${i}`, ecosystem: 'NPM' })),
      });
    expect(res.status).toBe(400);
  });
});
