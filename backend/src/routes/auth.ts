// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Auth Routes
// ═══════════════════════════════════════════════════════════════════════

import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { config } from '../config';
import { getDb } from '../services/database';
import { getSupabaseAdmin } from '../services/supabase';
import { requireAuth } from '../middleware/auth';
import { generateApiKey } from '../utils/crypto';
import { logger } from '../utils/logger';

const router = Router();

// ─── GitHub OAuth via Supabase ───────────────────────────────────────

/**
 * GET /api/auth/github
 * Redirect to GitHub OAuth via Supabase.
 */
router.get('/github', async (_req: Request, res: Response) => {
  const supabase = getSupabaseAdmin();
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'github',
    options: {
      redirectTo: `${config.apiBaseUrl}/api/auth/callback/github`,
    },
  });

  const url = (data as any)?.url;
  if (error || !url) {
    res.status(500).json({ error: { code: 'OAUTH_ERROR', message: 'Failed to initiate GitHub OAuth' } });
    return;
  }

  res.redirect(url);
});

/**
 * GET /api/auth/callback/github
 * Handle GitHub OAuth callback from Supabase.
 */
router.get('/callback/github', async (req: Request, res: Response) => {
  const code = req.query.code as string;
  const accessToken = req.query.access_token as string;
  const refreshToken = req.query.refresh_token as string;
  
  // Check for PKCE code or direct tokens
  if (!code && !accessToken) {
    logger.error('OAuth callback missing parameters', { query: req.query });
    res.status(400).json({ error: { code: 'MISSING_CODE', message: 'OAuth code missing' } });
    return;
  }

  try {
    const supabase = getSupabaseAdmin();
    let session;

    // If we have direct tokens (implicit flow), use them
    if (accessToken) {
      const { data, error } = await supabase.auth.getUser(accessToken);
      if (error || !data.user) {
        res.status(401).json({ error: { code: 'AUTH_FAILED', message: 'GitHub authentication failed' } });
        return;
      }
      session = { user: data.user, access_token: accessToken, refresh_token: refreshToken };
    } else {
      // Otherwise exchange code for session
      const { data, error } = await supabase.auth.exchangeCodeForSession(code);
      if (error || !data.session) {
        logger.error('Code exchange failed', { error });
        res.status(401).json({ error: { code: 'AUTH_FAILED', message: 'GitHub authentication failed' } });
        return;
      }
      session = data.session;
    }

    const supaUser = session.user;
    const db = getDb();

    // Upsert user in our database
    const user = await db.user.upsert({
      where: { email: supaUser.email! },
      update: {
        name: supaUser.user_metadata?.full_name || supaUser.user_metadata?.name,
        avatarUrl: supaUser.user_metadata?.avatar_url,
        githubId: supaUser.user_metadata?.provider_id,
        githubUsername: supaUser.user_metadata?.user_name,
      },
      create: {
        email: supaUser.email!,
        name: supaUser.user_metadata?.full_name || supaUser.user_metadata?.name,
        avatarUrl: supaUser.user_metadata?.avatar_url,
        githubId: supaUser.user_metadata?.provider_id,
        githubUsername: supaUser.user_metadata?.user_name,
      },
    });

    // Issue our own JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      config.jwt.secret,
      { expiresIn: '7d' }
    );

    logger.info('User authenticated via GitHub', { email: user.email });

    // Redirect to frontend with token
    const frontendUrl = config.corsOrigins[1] || 'http://localhost:5173';
    res.redirect(`${frontendUrl}/auth/callback?token=${token}`);
  } catch (err) {
    logger.error('GitHub OAuth callback failed', err);
    res.status(500).json({ error: { code: 'CALLBACK_FAILED', message: 'Authentication processing failed' } });
  }
});

// ─── Session Exchange (Frontend OAuth callback) ──────────────────────

/**
 * POST /api/auth/session
 * Accept a Supabase access token and return our own JWT.
 * Called by the frontend after GitHub OAuth completes.
 */
router.post('/session', async (req: Request, res: Response) => {
  const { supabaseToken } = req.body;
  if (!supabaseToken) {
    res.status(400).json({ error: { code: 'MISSING_TOKEN', message: 'Supabase token required' } });
    return;
  }

  try {
    const supabase = getSupabaseAdmin();
    const { data, error } = await supabase.auth.getUser(supabaseToken);

    if (error || !data.user) {
      res.status(401).json({ error: { code: 'INVALID_TOKEN', message: 'Invalid Supabase token' } });
      return;
    }

    const supaUser = data.user;
    const db = getDb();

    const user = await db.user.upsert({
      where: { email: supaUser.email! },
      update: {
        name: supaUser.user_metadata?.full_name || supaUser.user_metadata?.name,
        avatarUrl: supaUser.user_metadata?.avatar_url,
        githubId: String(supaUser.user_metadata?.provider_id || supaUser.user_metadata?.sub || ''),
        githubUsername: supaUser.user_metadata?.user_name,
      },
      create: {
        email: supaUser.email!,
        name: supaUser.user_metadata?.full_name || supaUser.user_metadata?.name,
        avatarUrl: supaUser.user_metadata?.avatar_url,
        githubId: String(supaUser.user_metadata?.provider_id || supaUser.user_metadata?.sub || ''),
        githubUsername: supaUser.user_metadata?.user_name,
      },
    });

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      config.jwt.secret,
      { expiresIn: '7d' }
    );

    logger.info('User session created via Supabase token', { email: user.email });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
        githubUsername: user.githubUsername,
        role: user.role,
      },
    });
  } catch (err) {
    logger.error('Session creation failed', err);
    res.status(500).json({ error: { code: 'SESSION_FAILED', message: 'Session creation failed' } });
  }
});

// ─── API Key Management ──────────────────────────────────────────────

const createApiKeySchema = z.object({
  name: z.string().min(1).max(100),
  expiresInDays: z.number().int().positive().optional(),
});

/**
 * POST /api/auth/api-keys
 * Create a new API key for the authenticated user.
 */
router.post('/api-keys', requireAuth, async (req: Request, res: Response) => {
  const body = createApiKeySchema.parse(req.body);
  const db = getDb();

  const { key, hash, prefix } = generateApiKey();
  const expiresAt = body.expiresInDays
    ? new Date(Date.now() + body.expiresInDays * 24 * 60 * 60 * 1000)
    : null;

  await db.apiKey.create({
    data: {
      userId: req.user!.id,
      name: body.name,
      keyHash: hash,
      keyPrefix: prefix,
    },
  });

  logger.info('API key created', { userId: req.user!.id, name: body.name });

  // Return the full key ONCE — it cannot be retrieved again
  res.status(201).json({
    key,
    name: body.name,
    prefix,
    expiresAt,
    message: 'Save this key — it will not be shown again.',
  });
});

/**
 * GET /api/auth/api-keys
 * List all API keys for the authenticated user.
 */
router.get('/api-keys', requireAuth, async (req: Request, res: Response) => {
  const db = getDb();
  const keys = await db.apiKey.findMany({
    where: { userId: req.user!.id },
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      lastUsedAt: true,
      revokedAt: true,
      createdAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });

  res.json({ keys });
});

/**
 * DELETE /api/auth/api-keys/:id
 * Revoke an API key.
 */
router.delete('/api-keys/:id', requireAuth, async (req: Request, res: Response) => {
  const db = getDb();
  const keyId = req.params.id as string;
  await db.apiKey.updateMany({
    where: { id: keyId, userId: req.user!.id },
    data: { revokedAt: new Date() },
  });

  logger.info('API key revoked', { userId: req.user!.id, keyId });
  res.json({ message: 'API key revoked' });
});

// ─── Profile ─────────────────────────────────────────────────────────

/**
 * GET /api/auth/me
 * Get current user profile.
 */
router.get('/me', requireAuth, async (req: Request, res: Response) => {
  const db = getDb();
  const user = await db.user.findUnique({
    where: { id: req.user!.id },
    include: {
      teamMembers: {
        include: { team: { select: { id: true, name: true, slug: true } } },
      },
      _count: { select: { scans: true, apiKeys: true, ghinReports: true } },
    },
  });

  res.json({ user });
});

export default router;
