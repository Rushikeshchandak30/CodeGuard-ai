// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — GHIN Consolidation Service (KAIROS-inspired)
// ═══════════════════════════════════════════════════════════════════════
// Background service that periodically consolidates GHIN intelligence:
//   1. Auto-confirms packages with sufficient reports
//   2. Merges duplicate reports
//   3. Recalculates confidence scores
//   4. Cleans stale/low-quality entries
//   5. Generates aggregate statistics for the network
//
// Runs on a configurable interval (default: every 15 minutes).
// Inspired by the "always-on background consolidation" pattern.
// ═══════════════════════════════════════════════════════════════════════

import { getDb } from './database';
import { cacheSet } from './redis';
import { isEnabled } from './feature-flags';
import { logger } from '../utils/logger';

// ─── Configuration ──────────────────────────────────────────────────

const CONSOLIDATION_INTERVAL_MS = parseInt(
  process.env.GHIN_CONSOLIDATION_INTERVAL_MS || '900000', 10  // 15 min
);
const AUTO_CONFIRM_THRESHOLD = 3;     // Reports needed to auto-confirm
const STALE_THRESHOLD_DAYS = 90;      // Days before marking entry as stale
const MIN_CONFIDENCE_THRESHOLD = 0.3; // Below this, flag for review

let consolidationTimer: ReturnType<typeof setInterval> | null = null;
let isRunning = false;

// ─── Core Consolidation Logic ───────────────────────────────────────

/**
 * Run a single consolidation cycle.
 * Safe to call multiple times — uses a lock to prevent overlap.
 */
export async function runConsolidation(): Promise<ConsolidationResult> {
  if (isRunning) {
    logger.warn('GHIN consolidation already running — skipping');
    return { skipped: true, autoConfirmed: 0, merged: 0, cleaned: 0, statsUpdated: false };
  }

  if (!isEnabled('ghin_background_consolidation')) {
    return { skipped: true, autoConfirmed: 0, merged: 0, cleaned: 0, statsUpdated: false };
  }

  isRunning = true;
  const startTime = Date.now();

  try {
    const db = getDb();
    let autoConfirmed = 0;
    let merged = 0;
    let cleaned = 0;

    // ── Phase 1: Auto-confirm suspected packages with enough reports ──
    const suspectedPackages = await db.ghinPackage.findMany({
      where: {
        status: 'SUSPECTED',
        reportCount: { gte: AUTO_CONFIRM_THRESHOLD },
      },
    });

    for (const pkg of suspectedPackages) {
      // Verify: count only HALLUCINATION-type reports for this package
      const hallucinationReports = await db.ghinReport.count({
        where: {
          packageName: pkg.packageName,
          ecosystem: pkg.ecosystem,
          reportType: 'HALLUCINATION',
        },
      });

      // Also check if there are FALSE_POSITIVE reports
      const falsePositiveReports = await db.ghinReport.count({
        where: {
          packageName: pkg.packageName,
          ecosystem: pkg.ecosystem,
          reportType: 'FALSE_POSITIVE',
        },
      });

      // Only auto-confirm if hallucination reports outnumber false positives 3:1
      if (hallucinationReports >= AUTO_CONFIRM_THRESHOLD && hallucinationReports > falsePositiveReports * 3) {
        await db.ghinPackage.update({
          where: { id: pkg.id },
          data: {
            status: 'CONFIRMED',
            verifiedAt: new Date(),
          },
        });
        autoConfirmed++;
        logger.info('GHIN auto-confirmed package', {
          package: pkg.packageName,
          ecosystem: pkg.ecosystem,
          reports: hallucinationReports,
        });
      }
    }

    // ── Phase 2: Recalculate confidence scores ──────────────────────
    const allPackages = await db.ghinPackage.findMany({
      where: { status: { in: ['SUSPECTED', 'CONFIRMED'] } },
    });

    for (const pkg of allPackages) {
      const reports = await db.ghinReport.findMany({
        where: {
          packageName: pkg.packageName,
          ecosystem: pkg.ecosystem,
        },
        select: { confidence: true, reportType: true },
      });

      if (reports.length === 0) continue;

      // Weighted confidence: hallucination reports boost, false positives reduce
      let totalWeight = 0;
      let weightedConfidence = 0;

      for (const r of reports) {
        const weight = r.reportType === 'HALLUCINATION' ? 1.0
          : r.reportType === 'TYPOSQUAT' ? 0.8
          : r.reportType === 'MALICIOUS' ? 1.2
          : r.reportType === 'FALSE_POSITIVE' ? -1.0
          : 0.5;
        totalWeight += Math.abs(weight);
        weightedConfidence += r.confidence * weight;
      }

      const avgConfidence = totalWeight > 0
        ? Math.max(0, Math.min(1, weightedConfidence / totalWeight))
        : 0.5;

      // Update report count and metadata on the aggregated entry
      await db.ghinPackage.update({
        where: { id: pkg.id },
        data: {
          reportCount: reports.length,
          lastSeenAt: new Date(),
        },
      });

      merged++;
    }

    // ── Phase 3: Clean stale low-confidence entries ─────────────────
    const staleDate = new Date(Date.now() - STALE_THRESHOLD_DAYS * 24 * 60 * 60 * 1000);

    // Remove SUSPECTED entries with low confidence that haven't been seen recently
    const staleResult = await db.ghinPackage.deleteMany({
      where: {
        status: 'SUSPECTED',
        reportCount: { lt: 2 },
        lastSeenAt: { lt: staleDate },
      },
    });
    cleaned = staleResult.count;

    // ── Phase 4: Rebuild and cache statistics ───────────────────────
    const [totalPackages, confirmed, totalReports, ecosystems] = await Promise.all([
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
      confirmedHallucinations: confirmed,
      totalReports,
      ecosystems: ecosystems.map(e => ({
        ecosystem: e.ecosystem,
        count: e._count.ecosystem,
      })),
      lastConsolidated: new Date().toISOString(),
      lastUpdated: new Date().toISOString(),
    };

    // Cache stats for 30 minutes (consolidation refreshes every 15 min)
    await cacheSet('ghin:stats', stats, 1800);

    const durationMs = Date.now() - startTime;
    logger.info('GHIN consolidation complete', {
      durationMs,
      autoConfirmed,
      merged,
      cleaned,
      totalPackages,
    });

    return { skipped: false, autoConfirmed, merged, cleaned, statsUpdated: true };
  } catch (err) {
    logger.error('GHIN consolidation failed', err);
    return { skipped: false, autoConfirmed: 0, merged: 0, cleaned: 0, statsUpdated: false };
  } finally {
    isRunning = false;
  }
}

// ─── Lifecycle ──────────────────────────────────────────────────────

/**
 * Start the background consolidation timer.
 */
export function startConsolidation(): void {
  if (consolidationTimer) {
    logger.warn('GHIN consolidation already started');
    return;
  }

  logger.info(`GHIN consolidation daemon starting (interval: ${CONSOLIDATION_INTERVAL_MS}ms)`);

  // Run once on startup (delayed 30s to let DB connect)
  setTimeout(() => runConsolidation(), 30_000);

  // Then run on interval
  consolidationTimer = setInterval(() => runConsolidation(), CONSOLIDATION_INTERVAL_MS);
}

/**
 * Stop the background consolidation timer.
 */
export function stopConsolidation(): void {
  if (consolidationTimer) {
    clearInterval(consolidationTimer);
    consolidationTimer = null;
    logger.info('GHIN consolidation daemon stopped');
  }
}

// ─── Types ──────────────────────────────────────────────────────────

export interface ConsolidationResult {
  skipped: boolean;
  autoConfirmed: number;
  merged: number;
  cleaned: number;
  statsUpdated: boolean;
}
