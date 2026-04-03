// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Memory Verification Service
// ═══════════════════════════════════════════════════════════════════════
// Implements a "skeptical memory" approach: before trusting any GHIN
// intelligence data, verify it against live registry sources.
//
// Key principles:
//   1. Never trust a single data source — cross-reference
//   2. Failed lookups are NOT re-inserted as truth
//   3. Confidence decays over time without re-verification
//   4. Anomalous data is quarantined, not deleted
//
// Inspired by the self-healing memory architecture pattern.
// ═══════════════════════════════════════════════════════════════════════

import { getDb } from './database';
import { cacheGet, cacheSet } from './redis';
import { isEnabled } from './feature-flags';
import { logger } from '../utils/logger';

// ─── Registry verification ──────────────────────────────────────────

const REGISTRY_URLS: Record<string, string> = {
  NPM: 'https://registry.npmjs.org',
  PYPI: 'https://pypi.org/pypi',
};

const VERIFICATION_CACHE_TTL = 3600; // 1 hour

/**
 * Verify a package against its live registry.
 * Returns true if the package does NOT exist (i.e., is a hallucination).
 * Returns false if the package exists (false positive).
 * Returns null if verification is inconclusive (network error, etc.).
 */
export async function verifyPackageHallucination(
  packageName: string,
  ecosystem: string
): Promise<VerificationResult> {
  const cacheKey = `verify:${ecosystem}:${packageName}`;

  // Check cache first
  const cached = await cacheGet<VerificationResult>(cacheKey);
  if (cached) return cached;

  const registryUrl = REGISTRY_URLS[ecosystem];
  if (!registryUrl) {
    return {
      verified: false,
      exists: null,
      source: 'unsupported_ecosystem',
      checkedAt: new Date().toISOString(),
    };
  }

  try {
    let url: string;
    if (ecosystem === 'NPM') {
      url = `${registryUrl}/${encodeURIComponent(packageName)}`;
    } else if (ecosystem === 'PYPI') {
      url = `${registryUrl}/${encodeURIComponent(packageName)}/json`;
    } else {
      return {
        verified: false,
        exists: null,
        source: 'unsupported',
        checkedAt: new Date().toISOString(),
      };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const exists = response.status === 200;
    const result: VerificationResult = {
      verified: true,
      exists,
      source: ecosystem === 'NPM' ? 'npmjs.org' : 'pypi.org',
      httpStatus: response.status,
      checkedAt: new Date().toISOString(),
    };

    // Cache the result
    await cacheSet(cacheKey, result, VERIFICATION_CACHE_TTL);

    return result;
  } catch (err) {
    logger.warn('Registry verification failed', { packageName, ecosystem, error: String(err) });
    return {
      verified: false,
      exists: null,
      source: 'error',
      error: String(err),
      checkedAt: new Date().toISOString(),
    };
  }
}

// ─── GHIN Data Integrity Check ──────────────────────────────────────

/**
 * Verify a batch of GHIN entries against live registries.
 * Used by the consolidation service and on-demand verification.
 */
export async function verifyGhinEntries(options: {
  limit?: number;
  status?: string;
  ecosystems?: string[];
}): Promise<BatchVerificationResult> {
  if (!isEnabled('memory_verification')) {
    return { checked: 0, confirmed: 0, falsePositives: 0, errors: 0, skipped: true };
  }

  const db = getDb();
  const limit = options.limit || 50;

  // Find entries that haven't been verified recently (or ever)
  const staleThreshold = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours

  const where: any = {};
  if (options.status) where.status = options.status;
  if (options.ecosystems) where.ecosystem = { in: options.ecosystems };

  const entries = await db.ghinPackage.findMany({
    where: {
      ...where,
      // Only verify NPM and PyPI (we have registry URLs for them)
      ecosystem: { in: options.ecosystems || ['NPM', 'PYPI'] },
      // Prioritize unverified or stale entries
      OR: [
        { verifiedAt: null },
        { verifiedAt: { lt: staleThreshold } },
      ],
    },
    orderBy: { reportCount: 'desc' }, // Verify most-reported first
    take: limit,
  });

  let confirmed = 0;
  let falsePositives = 0;
  let errors = 0;

  for (const entry of entries) {
    const result = await verifyPackageHallucination(entry.packageName, entry.ecosystem);

    if (!result.verified) {
      errors++;
      continue;
    }

    if (result.exists === false) {
      // Package doesn't exist — confirmed hallucination
      if (entry.status === 'SUSPECTED') {
        await db.ghinPackage.update({
          where: { id: entry.id },
          data: {
            status: 'CONFIRMED',
            verifiedAt: new Date(),
          },
        });
        confirmed++;
      }
    } else if (result.exists === true) {
      // Package exists — false positive!
      await db.ghinPackage.update({
        where: { id: entry.id },
        data: {
          status: 'FALSE_POSITIVE',
          verifiedAt: new Date(),
        },
      });
      falsePositives++;

      logger.warn('GHIN false positive detected', {
        package: entry.packageName,
        ecosystem: entry.ecosystem,
        previousStatus: entry.status,
        reportCount: entry.reportCount,
      });
    }

    // Rate limit: 200ms between registry calls to be respectful
    await new Promise(resolve => setTimeout(resolve, 200));
  }

  logger.info('GHIN batch verification complete', {
    checked: entries.length,
    confirmed,
    falsePositives,
    errors,
  });

  return {
    checked: entries.length,
    confirmed,
    falsePositives,
    errors,
    skipped: false,
  };
}

// ─── Confidence Decay ───────────────────────────────────────────────

/**
 * Apply confidence decay to GHIN entries that haven't been
 * re-verified in a long time. This prevents stale data from
 * being trusted indefinitely.
 *
 * Decay formula: entries not verified in >30 days get status
 * downgraded from CONFIRMED → SUSPECTED if report count is low.
 */
export async function applyConfidenceDecay(): Promise<number> {
  const db = getDb();
  const decayThreshold = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days

  // Downgrade confirmed entries with few reports that haven't been re-verified
  const result = await db.ghinPackage.updateMany({
    where: {
      status: 'CONFIRMED',
      reportCount: { lt: 3 },
      verifiedAt: { lt: decayThreshold },
    },
    data: {
      status: 'SUSPECTED',
    },
  });

  if (result.count > 0) {
    logger.info('Confidence decay applied', { downgraded: result.count });
  }

  return result.count;
}

// ─── Types ──────────────────────────────────────────────────────────

export interface VerificationResult {
  verified: boolean;
  exists: boolean | null;
  source: string;
  httpStatus?: number;
  error?: string;
  checkedAt: string;
}

export interface BatchVerificationResult {
  checked: number;
  confirmed: number;
  falsePositives: number;
  errors: number;
  skipped: boolean;
}
