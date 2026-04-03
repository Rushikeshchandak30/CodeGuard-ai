// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Health Check Routes
// ═══════════════════════════════════════════════════════════════════════

import { Router, Request, Response } from 'express';
import { getDb } from '../services/database';
import { getRedis } from '../services/redis';
import { logger } from '../utils/logger';

const router = Router();

/**
 * GET /health
 * Basic health check — always returns 200 if server is running.
 */
router.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    version: '7.0.0',
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /health/ready
 * Readiness check — verifies database and cache connectivity.
 */
router.get('/health/ready', async (_req: Request, res: Response) => {
  const checks: Record<string, { status: string; latencyMs?: number; error?: string }> = {};

  // Check database
  try {
    const start = Date.now();
    const db = getDb();
    await db.$queryRaw`SELECT 1`;
    checks.database = { status: 'ok', latencyMs: Date.now() - start };
  } catch (err) {
    checks.database = { status: 'error', error: (err as Error).message };
    logger.error('Health check: database failed', err);
  }

  // Check Redis
  try {
    const redis = getRedis();
    if (redis) {
      const start = Date.now();
      await redis.ping();
      checks.redis = { status: 'ok', latencyMs: Date.now() - start };
    } else {
      checks.redis = { status: 'not_configured' };
    }
  } catch (err) {
    checks.redis = { status: 'error', error: (err as Error).message };
    logger.error('Health check: redis failed', err);
  }

  const allOk = Object.values(checks).every(c => c.status === 'ok' || c.status === 'not_configured');

  res.status(allOk ? 200 : 503).json({
    status: allOk ? 'ready' : 'degraded',
    version: '7.0.0',
    checks,
    timestamp: new Date().toISOString(),
  });
});

export default router;
