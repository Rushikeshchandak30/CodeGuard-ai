// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Admin Routes
// ═══════════════════════════════════════════════════════════════════════
// Protected admin endpoints for feature flags, system stats,
// GHIN consolidation triggers, and memory verification.
// ═══════════════════════════════════════════════════════════════════════

import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth';
import { getDb } from '../services/database';
import { getFlags, setFlagOverride, clearOverrides, isEnabled } from '../services/feature-flags';
import { runConsolidation } from '../services/ghin-consolidator';
import { verifyGhinEntries, applyConfidenceDecay } from '../services/memory-verifier';
import { ForbiddenError } from '../utils/errors';
import { logger } from '../utils/logger';

import type { FeatureFlags } from '../services/feature-flags';

const router = Router();

// ─── Admin guard middleware ─────────────────────────────────────────

function requireAdmin(req: Request, _res: Response, next: Function): void {
  if (req.user?.role !== 'ADMIN') {
    throw new ForbiddenError('Admin access required');
  }
  next();
}

// ─── Feature Flags ──────────────────────────────────────────────────

/**
 * GET /api/admin/flags
 * List all feature flags and their current state.
 */
router.get('/flags', requireAuth, requireAdmin, async (_req: Request, res: Response) => {
  const flags = getFlags();
  res.json({ flags });
});

const setFlagSchema = z.object({
  flag: z.string(),
  value: z.boolean(),
});

/**
 * POST /api/admin/flags
 * Set a runtime feature flag override.
 */
router.post('/flags', requireAuth, requireAdmin, async (req: Request, res: Response) => {
  const body = setFlagSchema.parse(req.body);
  const flags = getFlags();

  // Validate flag name exists
  if (!(body.flag in flags)) {
    res.status(400).json({
      error: { code: 'INVALID_FLAG', message: `Unknown feature flag: ${body.flag}` },
    });
    return;
  }

  setFlagOverride(body.flag as keyof FeatureFlags, body.value);
  logger.info('Admin set feature flag', { flag: body.flag, value: body.value, admin: req.user!.email });

  res.json({
    message: `Feature flag '${body.flag}' set to ${body.value}`,
    flags: getFlags(),
  });
});

/**
 * DELETE /api/admin/flags
 * Clear all runtime flag overrides (reset to defaults).
 */
router.delete('/flags', requireAuth, requireAdmin, async (req: Request, res: Response) => {
  clearOverrides();
  logger.info('Admin cleared all feature flag overrides', { admin: req.user!.email });
  res.json({ message: 'All flag overrides cleared', flags: getFlags() });
});

// ─── GHIN Consolidation ─────────────────────────────────────────────

/**
 * POST /api/admin/ghin/consolidate
 * Manually trigger GHIN consolidation cycle.
 */
router.post('/ghin/consolidate', requireAuth, requireAdmin, async (req: Request, res: Response) => {
  logger.info('Admin triggered GHIN consolidation', { admin: req.user!.email });
  const result = await runConsolidation();
  res.json({ message: 'Consolidation complete', result });
});

/**
 * POST /api/admin/ghin/verify
 * Trigger GHIN memory verification against live registries.
 */
router.post('/ghin/verify', requireAuth, requireAdmin, async (req: Request, res: Response) => {
  const limit = parseInt(req.query.limit as string) || 50;
  logger.info('Admin triggered GHIN verification', { admin: req.user!.email, limit });

  const result = await verifyGhinEntries({ limit, ecosystems: ['NPM', 'PYPI'] });
  res.json({ message: 'Verification complete', result });
});

/**
 * POST /api/admin/ghin/decay
 * Apply confidence decay to stale GHIN entries.
 */
router.post('/ghin/decay', requireAuth, requireAdmin, async (req: Request, res: Response) => {
  logger.info('Admin triggered confidence decay', { admin: req.user!.email });
  const downgraded = await applyConfidenceDecay();
  res.json({ message: 'Confidence decay applied', downgraded });
});

// ─── System Stats ───────────────────────────────────────────────────

/**
 * GET /api/admin/stats
 * Get comprehensive system statistics.
 */
router.get('/stats', requireAuth, requireAdmin, async (_req: Request, res: Response) => {
  const db = getDb();

  const [
    userCount,
    teamCount,
    scanCount,
    ghinPackageCount,
    ghinReportCount,
    apiKeyCount,
    recentScans,
    topPackages,
  ] = await Promise.all([
    db.user.count(),
    db.team.count(),
    db.scan.count(),
    db.ghinPackage.count(),
    db.ghinReport.count(),
    db.apiKey.count({ where: { revokedAt: null } }),
    db.scan.count({
      where: { startedAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
    }),
    db.ghinPackage.findMany({
      orderBy: { reportCount: 'desc' },
      take: 10,
      select: {
        packageName: true,
        ecosystem: true,
        status: true,
        reportCount: true,
      },
    }),
  ]);

  res.json({
    system: {
      users: userCount,
      teams: teamCount,
      scans: scanCount,
      scansLast24h: recentScans,
      activeApiKeys: apiKeyCount,
    },
    ghin: {
      totalPackages: ghinPackageCount,
      totalReports: ghinReportCount,
      topReported: topPackages,
    },
    featureFlags: getFlags(),
    server: {
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      nodeVersion: process.version,
    },
  });
});

export default router;
