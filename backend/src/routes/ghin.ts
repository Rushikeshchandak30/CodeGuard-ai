// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — GHIN (Global Hallucination Intelligence Network) Routes
// ═══════════════════════════════════════════════════════════════════════

import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { Prisma } from '@prisma/client';
import { getDb } from '../services/database';
import { cacheGet, cacheSet } from '../services/redis';
import { requireAuth, optionalAuth } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// ─── Report a hallucinated package ───────────────────────────────────

const reportSchema = z.object({
  packageName: z.string().min(1).max(200),
  ecosystem: z.enum(['NPM', 'PYPI', 'CARGO', 'GEM', 'GO']),
  reportType: z.enum(['HALLUCINATION', 'FALSE_POSITIVE', 'TYPOSQUAT', 'MALICIOUS']),
  confidence: z.number().min(0).max(1).optional().default(0.5),
  metadata: z.record(z.unknown()).optional(),
});

/**
 * POST /api/ghin/report
 * Report a hallucinated or malicious package.
 * Requires authentication (so we can track quality).
 */
router.post('/report', requireAuth, async (req: Request, res: Response) => {
  const body = reportSchema.parse(req.body);
  const db = getDb();

  // Create the report
  const report = await db.ghinReport.create({
    data: {
      userId: req.user!.id,
      packageName: body.packageName.toLowerCase(),
      ecosystem: body.ecosystem,
      reportType: body.reportType,
      confidence: body.confidence,
      metadata: body.metadata ? (body.metadata as unknown as Prisma.InputJsonValue) : Prisma.DbNull,
    },
  });

  // Update or create aggregated package entry
  await db.ghinPackage.upsert({
    where: {
      packageName_ecosystem: {
        packageName: body.packageName.toLowerCase(),
        ecosystem: body.ecosystem,
      },
    },
    update: {
      reportCount: { increment: 1 },
      lastSeenAt: new Date(),
    },
    create: {
      packageName: body.packageName.toLowerCase(),
      ecosystem: body.ecosystem,
      reportCount: 1,
      status: 'SUSPECTED',
    },
  });

  // Auto-confirm packages with 3+ hallucination reports
  const pkg = await db.ghinPackage.findUnique({
    where: {
      packageName_ecosystem: {
        packageName: body.packageName.toLowerCase(),
        ecosystem: body.ecosystem,
      },
    },
  });

  if (pkg && pkg.reportCount >= 3 && pkg.status === 'SUSPECTED' && body.reportType === 'HALLUCINATION') {
    await db.ghinPackage.update({
      where: { id: pkg.id },
      data: { status: 'CONFIRMED', verifiedAt: new Date() },
    });
    logger.info('GHIN package auto-confirmed', { packageName: body.packageName, ecosystem: body.ecosystem });
  }

  // Invalidate cache
  await cacheSet(`ghin:${body.ecosystem}:${body.packageName.toLowerCase()}`, null, 1);

  logger.info('GHIN report submitted', { packageName: body.packageName, type: body.reportType, userId: req.user!.id });

  res.status(201).json({
    report: {
      id: report.id,
      packageName: report.packageName,
      ecosystem: report.ecosystem,
      reportType: report.reportType,
    },
    message: 'Report submitted successfully. Thank you for contributing to GHIN.',
  });
});

// ─── Check a package ─────────────────────────────────────────────────

/**
 * GET /api/ghin/check/:ecosystem/:packageName
 * Check if a package is known to GHIN.
 * Public endpoint (optional auth).
 */
router.get('/check/:ecosystem/:packageName', optionalAuth, async (req: Request, res: Response) => {
  const ecosystem = req.params.ecosystem as string;
  const packageName = req.params.packageName as string;
  const eco = ecosystem.toUpperCase();
  const name = packageName.toLowerCase();

  // Check cache first
  const cacheKey = `ghin:${eco}:${name}`;
  const cached = await cacheGet<any>(cacheKey);
  if (cached) {
    res.json(cached);
    return;
  }

  const db = getDb();
  const pkg = await db.ghinPackage.findUnique({
    where: { packageName_ecosystem: { packageName: name, ecosystem: eco as any } },
  });

  const result = {
    packageName: name,
    ecosystem: eco,
    known: !!pkg,
    status: pkg?.status || null,
    reportCount: pkg?.reportCount || 0,
    firstSeenAt: pkg?.firstSeenAt || null,
    lastSeenAt: pkg?.lastSeenAt || null,
  };

  // Cache for 5 minutes
  await cacheSet(cacheKey, result, 300);

  res.json(result);
});

// ─── Bulk check packages ─────────────────────────────────────────────

const bulkCheckSchema = z.object({
  packages: z.array(z.object({
    name: z.string().min(1),
    ecosystem: z.enum(['NPM', 'PYPI', 'CARGO', 'GEM', 'GO']),
  })).min(1).max(100),
});

/**
 * POST /api/ghin/check-bulk
 * Check multiple packages at once.
 * Public endpoint (optional auth).
 */
router.post('/check-bulk', optionalAuth, async (req: Request, res: Response) => {
  const body = bulkCheckSchema.parse(req.body);
  const db = getDb();

  const conditions = body.packages.map(p => ({
    packageName: p.name.toLowerCase(),
    ecosystem: p.ecosystem,
  }));

  const found = await db.ghinPackage.findMany({
    where: { OR: conditions },
  });

  const foundMap = new Map(found.map(p => [`${p.ecosystem}:${p.packageName}`, p]));

  const results = body.packages.map(p => {
    const key = `${p.ecosystem}:${p.name.toLowerCase()}`;
    const pkg = foundMap.get(key);
    return {
      packageName: p.name.toLowerCase(),
      ecosystem: p.ecosystem,
      known: !!pkg,
      status: pkg?.status || null,
      reportCount: pkg?.reportCount || 0,
    };
  });

  res.json({ results });
});

// ─── List known hallucinations ───────────────────────────────────────

/**
 * GET /api/ghin/packages
 * List known hallucinated packages with pagination.
 * Public endpoint.
 */
router.get('/packages', async (req: Request, res: Response) => {
  const db = getDb();
  const page = Math.max(1, parseInt(req.query.page as string) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 50));
  const status = req.query.status as string | undefined;
  const ecosystem = req.query.ecosystem as string | undefined;

  const where: any = {};
  if (status) where.status = status.toUpperCase();
  if (ecosystem) where.ecosystem = ecosystem.toUpperCase();

  const [packages, total] = await Promise.all([
    db.ghinPackage.findMany({
      where,
      orderBy: { reportCount: 'desc' },
      skip: (page - 1) * limit,
      take: limit,
    }),
    db.ghinPackage.count({ where }),
  ]);

  res.json({
    packages,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit),
    },
  });
});

// ─── GHIN Statistics ─────────────────────────────────────────────────

/**
 * GET /api/ghin/stats
 * Get GHIN network statistics.
 */
router.get('/stats', async (_req: Request, res: Response) => {
  const cacheKey = 'ghin:stats';
  const cached = await cacheGet<any>(cacheKey);
  if (cached) {
    res.json(cached);
    return;
  }

  const db = getDb();
  const [totalPackages, confirmedCount, reportCount, ecosystemBreakdown] = await Promise.all([
    db.ghinPackage.count(),
    db.ghinPackage.count({ where: { status: 'CONFIRMED' } }),
    db.ghinReport.count(),
    db.ghinPackage.groupBy({
      by: ['ecosystem'],
      _count: { ecosystem: true },
    }),
  ]);

  const stats = {
    totalPackages,
    confirmedHallucinations: confirmedCount,
    totalReports: reportCount,
    ecosystems: ecosystemBreakdown.map(e => ({ ecosystem: e.ecosystem, count: e._count.ecosystem })),
    lastUpdated: new Date().toISOString(),
  };

  await cacheSet(cacheKey, stats, 300);
  res.json(stats);
});

export default router;
