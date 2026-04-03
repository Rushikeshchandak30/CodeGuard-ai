// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Scan Results Routes
// ═══════════════════════════════════════════════════════════════════════

import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { getDb } from '../services/database';
import { requireAuth } from '../middleware/auth';
import { NotFoundError } from '../utils/errors';

const router = Router();

// ─── Upload scan results ─────────────────────────────────────────────

const uploadScanSchema = z.object({
  source: z.enum(['CLI', 'EXTENSION', 'GITHUB_ACTION', 'PRE_COMMIT', 'API']).default('CLI'),
  projectPath: z.string().min(1),
  branch: z.string().optional(),
  commitHash: z.string().optional(),
  projectName: z.string().optional(),
  summary: z.object({
    totalFindings: z.number().int().min(0),
    critical: z.number().int().min(0).default(0),
    high: z.number().int().min(0).default(0),
    medium: z.number().int().min(0).default(0),
    low: z.number().int().min(0).default(0),
    hallucinatedPackages: z.number().int().min(0).default(0),
    secretsFound: z.number().int().min(0).default(0),
    sastFindings: z.number().int().min(0).default(0),
    mcpIssues: z.number().int().min(0).default(0),
    vulnerabilities: z.number().int().min(0).default(0),
    policyViolations: z.number().int().min(0).default(0),
    scannedFiles: z.number().int().min(0).default(0),
  }),
  findings: z.array(z.record(z.unknown())).optional(),
  packages: z.array(z.record(z.unknown())).optional(),
  sbom: z.record(z.unknown()).optional(),
  aiSbom: z.record(z.unknown()).optional(),
  securityScore: z.number().int().min(0).max(100).optional(),
  durationMs: z.number().int().min(0).optional(),
});

/**
 * POST /api/scans
 * Upload scan results from CLI, extension, or CI/CD.
 */
router.post('/', requireAuth, async (req: Request, res: Response) => {
  const body = uploadScanSchema.parse(req.body);
  const db = getDb();

  const scan = await db.scan.create({
    data: {
      userId: req.user!.id,
      scanType: body.source,
      status: 'COMPLETED',
      findings: (body.findings ?? []) as any,
      metadata: {
        projectPath: body.projectPath,
        branch: body.branch,
        commitHash: body.commitHash,
        projectName: body.projectName,
        summary: body.summary,
        securityScore: body.securityScore,
        durationMs: body.durationMs,
        packages: body.packages,
        sbom: body.sbom,
        aiSbom: body.aiSbom,
      } as any,
      completedAt: new Date(),
    },
  });

  res.status(201).json({
    scan: {
      id: scan.id,
      scanType: scan.scanType,
      status: scan.status,
      startedAt: scan.startedAt,
    },
    message: 'Scan results uploaded successfully.',
  });
});

// ─── List scans ──────────────────────────────────────────────────────

/**
 * GET /api/scans
 * List scan history for the authenticated user.
 */
router.get('/', requireAuth, async (req: Request, res: Response) => {
  const db = getDb();
  const page = Math.max(1, parseInt(req.query.page as string) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit as string) || 20));
  const projectId = req.query.projectId as string | undefined;

  const where: any = { userId: req.user!.id };
  if (projectId) where.projectId = projectId;

  const [scans, total] = await Promise.all([
    db.scan.findMany({
      where,
      select: {
        id: true,
        scanType: true,
        status: true,
        metadata: true,
        startedAt: true,
        completedAt: true,
      },
      orderBy: { startedAt: 'desc' },
      skip: (page - 1) * limit,
      take: limit,
    }),
    db.scan.count({ where }),
  ]);

  res.json({
    scans,
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
});

// ─── Get single scan ─────────────────────────────────────────────────

/**
 * GET /api/scans/:id
 * Get full scan details including findings JSON.
 */
router.get('/:id', requireAuth, async (req: Request, res: Response) => {
  const db = getDb();
  const scanId = req.params.id as string;
  const scan = await db.scan.findFirst({
    where: { id: scanId, userId: req.user!.id },
  });

  if (!scan) throw new NotFoundError('Scan');

  res.json({ scan });
});

// ─── Scan trends ─────────────────────────────────────────────────────

/**
 * GET /api/scans/trends/summary
 * Get scan trend data for the last 30 days.
 */
router.get('/trends/summary', requireAuth, async (req: Request, res: Response) => {
  const db = getDb();
  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const scans = await db.scan.findMany({
    where: {
      userId: req.user!.id,
      startedAt: { gte: since },
    },
    select: {
      metadata: true,
      startedAt: true,
    },
    orderBy: { startedAt: 'asc' },
  });

  const totalScans = scans.length;
  const latestMeta = scans.length > 0 ? (scans[scans.length - 1].metadata as any) : null;
  const avgFindings = totalScans > 0
    ? Math.round(scans.reduce((acc: number, s) => acc + ((s.metadata as any)?.summary?.totalFindings || 0), 0) / totalScans)
    : 0;

  res.json({
    period: '30d',
    totalScans,
    latestSecurityScore: latestMeta?.securityScore ?? null,
    averageFindings: avgFindings,
    trend: scans.map((s) => ({
      date: s.startedAt,
      findings: (s.metadata as any)?.summary?.totalFindings ?? 0,
      critical: (s.metadata as any)?.summary?.critical ?? 0,
      score: (s.metadata as any)?.securityScore ?? null,
    })),
  });
});

export default router;
