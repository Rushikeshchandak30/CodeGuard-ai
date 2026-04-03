// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Rate Limiting Middleware (Upstash Redis)
// ═══════════════════════════════════════════════════════════════════════

import { Request, Response, NextFunction } from 'express';
import { getRateLimiter } from '../services/redis';
import { RateLimitError } from '../utils/errors';
import { logger } from '../utils/logger';

/**
 * Rate limiting middleware using Upstash Redis sliding window.
 * Falls back to no-op if Redis is not configured.
 * Uses user ID for authenticated requests, IP for anonymous.
 */
export async function rateLimit(req: Request, res: Response, next: NextFunction): Promise<void> {
  const limiter = getRateLimiter();
  if (!limiter) {
    // No Redis configured — skip rate limiting
    return next();
  }

  try {
    const identifier = req.user?.id || req.ip || 'anonymous';
    const result = await limiter.limit(identifier);

    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', result.limit);
    res.setHeader('X-RateLimit-Remaining', result.remaining);
    res.setHeader('X-RateLimit-Reset', result.reset);

    if (!result.success) {
      logger.warn('Rate limit exceeded', { identifier, limit: result.limit });
      throw new RateLimitError();
    }

    next();
  } catch (err) {
    if (err instanceof RateLimitError) {
      return next(err);
    }
    // If rate limiter fails, allow the request through
    logger.error('Rate limiter error, allowing request', err);
    next();
  }
}
