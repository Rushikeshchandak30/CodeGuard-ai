// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Redis Service (Upstash)
// ═══════════════════════════════════════════════════════════════════════

import { Redis } from '@upstash/redis';
import { Ratelimit } from '@upstash/ratelimit';
import { config } from '../config';
import { logger } from '../utils/logger';

let redis: Redis | null = null;
let rateLimiter: Ratelimit | null = null;

/**
 * Get the Redis client (Upstash REST-based).
 * Returns null if Redis is not configured.
 */
export function getRedis(): Redis | null {
  if (redis) return redis;
  if (!config.redis.url || !config.redis.token) {
    logger.warn('Redis not configured — rate limiting and caching disabled');
    return null;
  }

  try {
    redis = new Redis({
      url: config.redis.url,
      token: config.redis.token,
    });
    logger.info('Upstash Redis client initialized');
    return redis;
  } catch (err) {
    logger.error('Failed to initialize Redis', err);
    return null;
  }
}

/**
 * Get the rate limiter instance.
 * Falls back to no-op if Redis is not available.
 */
export function getRateLimiter(): Ratelimit | null {
  if (rateLimiter) return rateLimiter;

  const r = getRedis();
  if (!r) return null;

  rateLimiter = new Ratelimit({
    redis: r,
    limiter: Ratelimit.slidingWindow(config.rateLimit.maxRequests, `${config.rateLimit.windowMs}ms`),
    analytics: true,
    prefix: 'codeguard:ratelimit',
  });

  return rateLimiter;
}

/**
 * Cache a value with TTL (seconds).
 */
export async function cacheSet(key: string, value: unknown, ttlSeconds: number): Promise<void> {
  const r = getRedis();
  if (!r) return;
  try {
    await r.set(`codeguard:cache:${key}`, JSON.stringify(value), { ex: ttlSeconds });
  } catch (err) {
    logger.error('Redis cache set failed', err);
  }
}

/**
 * Get a cached value.
 */
export async function cacheGet<T>(key: string): Promise<T | null> {
  const r = getRedis();
  if (!r) return null;
  try {
    const raw = await r.get<string>(`codeguard:cache:${key}`);
    if (!raw) return null;
    return typeof raw === 'string' ? JSON.parse(raw) : raw as T;
  } catch (err) {
    logger.error('Redis cache get failed', err);
    return null;
  }
}
