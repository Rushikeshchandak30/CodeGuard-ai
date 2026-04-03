// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Authentication Middleware
// ═══════════════════════════════════════════════════════════════════════
// Supports 3 auth methods:
//   1. Supabase JWT (from browser/extension login)
//   2. API Key (cg_xxx — for CLI and CI/CD)
//   3. Anonymous (limited endpoints only)
// ═══════════════════════════════════════════════════════════════════════

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { getDb } from '../services/database';
import { getSupabaseAdmin } from '../services/supabase';
import { hashApiKey } from '../utils/crypto';
import { UnauthorizedError } from '../utils/errors';
import { logger } from '../utils/logger';

// Extend Express Request with authenticated user info
export interface AuthUser {
  id: string;
  email: string;
  role: string;
  authMethod: 'supabase' | 'apikey' | 'jwt';
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

/**
 * Required authentication middleware.
 * Rejects requests without valid auth.
 */
export async function requireAuth(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    const user = await extractUser(req);
    if (!user) {
      throw new UnauthorizedError('Valid authentication required. Use Bearer token or API key.');
    }
    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Optional authentication middleware.
 * Attaches user if auth is present, but allows anonymous access.
 */
export async function optionalAuth(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    req.user = await extractUser(req) || undefined;
    next();
  } catch (err) {
    // Don't fail on auth errors for optional auth — just proceed anonymously
    logger.debug('Optional auth failed, proceeding anonymously', { error: (err as Error).message });
    next();
  }
}

/**
 * Require admin role.
 */
export async function requireAdmin(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    const user = await extractUser(req);
    if (!user) {
      throw new UnauthorizedError();
    }
    if (user.role !== 'ADMIN' && user.role !== 'ENTERPRISE') {
      throw new UnauthorizedError('Admin access required');
    }
    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

// ─── Internal helpers ────────────────────────────────────────────────

async function extractUser(req: Request): Promise<AuthUser | null> {
  const authHeader = req.headers.authorization;
  const apiKeyHeader = req.headers['x-api-key'] as string | undefined;

  // Method 1: API Key (x-api-key header or query param)
  const apiKey = apiKeyHeader || (req.query.api_key as string | undefined);
  if (apiKey && apiKey.startsWith('cg_')) {
    return authenticateApiKey(apiKey);
  }

  // Method 2: Bearer token (Supabase JWT or custom JWT)
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    return authenticateToken(token);
  }

  return null;
}

async function authenticateApiKey(key: string): Promise<AuthUser | null> {
  const db = getDb();
  const keyHash = hashApiKey(key);

  const apiKey = await db.apiKey.findUnique({
    where: { keyHash },
    include: { user: true },
  });

  if (!apiKey || apiKey.revokedAt) {
    throw new UnauthorizedError('Invalid or revoked API key');
  }

  // Update last used timestamp (fire-and-forget)
  db.apiKey.update({
    where: { id: apiKey.id },
    data: { lastUsedAt: new Date() },
  }).catch(() => { /* ignore errors on usage tracking */ });

  return {
    id: apiKey.user.id,
    email: apiKey.user.email,
    role: apiKey.user.role,
    authMethod: 'apikey',
  };
}

async function authenticateToken(token: string): Promise<AuthUser | null> {
  // Try Supabase JWT first
  try {
    const supabase = getSupabaseAdmin();
    const { data, error } = await supabase.auth.getUser(token);

    if (!error && data.user) {
      const db = getDb();
      // Find or create user in our DB
      let user = await db.user.findUnique({ where: { email: data.user.email! } });

      if (!user) {
        user = await db.user.create({
          data: {
            email: data.user.email!,
            name: data.user.user_metadata?.full_name || data.user.user_metadata?.name,
            avatarUrl: data.user.user_metadata?.avatar_url,
            githubId: data.user.user_metadata?.provider_id,
            githubUsername: data.user.user_metadata?.user_name,
          },
        });
        logger.info('New user created from Supabase auth', { email: user.email });
      }

      return {
        id: user.id,
        email: user.email,
        role: user.role,
        authMethod: 'supabase',
      };
    }
  } catch {
    // Supabase auth failed — try custom JWT
  }

  // Try custom JWT
  try {
    const decoded = jwt.verify(token, config.jwt.secret) as { userId: string; email: string; role: string };
    return {
      id: decoded.userId,
      email: decoded.email,
      role: decoded.role,
      authMethod: 'jwt',
    };
  } catch {
    throw new UnauthorizedError('Invalid token');
  }
}
