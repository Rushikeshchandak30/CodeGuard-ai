// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Team & Organization Routes
// ═══════════════════════════════════════════════════════════════════════

import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { getDb } from '../services/database';
import { requireAuth } from '../middleware/auth';
import { NotFoundError, ForbiddenError, ConflictError } from '../utils/errors';
import { logger } from '../utils/logger';

const router = Router();

// ─── Create Team ─────────────────────────────────────────────────────

const createTeamSchema = z.object({
  name: z.string().min(2).max(100),
  slug: z.string().min(2).max(50).regex(/^[a-z0-9-]+$/),
});

/**
 * POST /api/teams
 * Create a new team. The creator becomes the owner.
 */
router.post('/', requireAuth, async (req: Request, res: Response) => {
  const body = createTeamSchema.parse(req.body);
  const db = getDb();

  // Check slug uniqueness
  const existing = await db.team.findUnique({ where: { slug: body.slug } });
  if (existing) throw new ConflictError('Team slug already taken');

  const team = await db.team.create({
    data: {
      name: body.name,
      slug: body.slug,
      ownerId: req.user!.id,
      members: {
        create: {
          userId: req.user!.id,
          role: 'OWNER',
        },
      },
    },
    include: { members: { include: { user: { select: { id: true, email: true, name: true } } } } },
  });

  logger.info('Team created', { teamId: team.id, slug: team.slug, userId: req.user!.id });
  res.status(201).json({ team });
});

// ─── List user's teams ───────────────────────────────────────────────

/**
 * GET /api/teams
 * List all teams the user belongs to.
 */
router.get('/', requireAuth, async (req: Request, res: Response) => {
  const db = getDb();
  const memberships = await db.teamMember.findMany({
    where: { userId: req.user!.id },
    include: {
      team: {
        include: {
          _count: { select: { members: true, projects: true } },
        },
      },
    },
  });

  const teams = memberships.map(m => ({
    ...m.team,
    role: m.role,
    joinedAt: m.joinedAt,
  }));

  res.json({ teams });
});

// ─── Get team details ────────────────────────────────────────────────

/**
 * GET /api/teams/:slug
 * Get team details with members and projects.
 */
router.get('/:slug', requireAuth, async (req: Request, res: Response) => {
  const db = getDb();
  const slug = req.params.slug as string;
  const team = await db.team.findUnique({
    where: { slug },
    include: {
      members: {
        include: { user: { select: { id: true, email: true, name: true, avatarUrl: true } } },
      },
      projects: {
        select: { id: true, name: true, repositoryUrl: true },
        orderBy: { createdAt: 'desc' },
      },
    },
  });

  if (!team) throw new NotFoundError('Team');

  // Verify user is a member
  const isMember = team.members.some((m: { userId: string }) => m.userId === req.user!.id);
  if (!isMember) throw new ForbiddenError('You are not a member of this team');

  res.json({ team });
});

// ─── Invite member ───────────────────────────────────────────────────

const inviteMemberSchema = z.object({
  email: z.string().email(),
  role: z.enum(['ADMIN', 'MEMBER', 'VIEWER']).default('MEMBER'),
});

/**
 * POST /api/teams/:slug/members
 * Invite a user to the team by email.
 */
router.post('/:slug/members', requireAuth, async (req: Request, res: Response) => {
  const body = inviteMemberSchema.parse(req.body);
  const db = getDb();
  const slug = req.params.slug as string;

  const team = await db.team.findUnique({
    where: { slug },
    include: { members: true },
  });

  if (!team) throw new NotFoundError('Team');

  // Verify requester is owner or admin
  const requesterMember = team.members.find((m: { userId: string; role: string }) => m.userId === req.user!.id);
  if (!requesterMember || !['OWNER', 'ADMIN'].includes(requesterMember.role)) {
    throw new ForbiddenError('Only owners and admins can invite members');
  }

  // Find user by email
  const invitee = await db.user.findUnique({ where: { email: body.email } });
  if (!invitee) {
    // User doesn't exist yet — in production, send an invite email
    res.status(404).json({
      error: { code: 'USER_NOT_FOUND', message: 'User must sign up first before being invited' },
    });
    return;
  }

  // Check if already a member
  const existingMember = team.members.find((m: { userId: string }) => m.userId === invitee.id);
  if (existingMember) throw new ConflictError('User is already a team member');

  const member = await db.teamMember.create({
    data: {
      teamId: team.id,
      userId: invitee.id,
      role: body.role,
    },
    include: { user: { select: { id: true, email: true, name: true } } },
  });

  logger.info('Team member added', { teamId: team.id, inviteeEmail: body.email, role: body.role });
  res.status(201).json({ member });
});

// ─── Team scan stats ─────────────────────────────────────────────────

/**
 * GET /api/teams/:slug/stats
 * Get aggregate scan statistics for the team.
 */
router.get('/:slug/stats', requireAuth, async (req: Request, res: Response) => {
  const db = getDb();
  const slug = req.params.slug as string;
  const team = await db.team.findUnique({
    where: { slug },
    include: { members: true, projects: true },
  });

  if (!team) throw new NotFoundError('Team');
  const isMember = team.members.some((m: { userId: string }) => m.userId === req.user!.id);
  if (!isMember) throw new ForbiddenError('You are not a member of this team');

  const projectIds = team.projects.map((p: { id: string }) => p.id);

  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const recentScans = projectIds.length > 0
    ? await db.scan.findMany({
        where: {
          projectId: { in: projectIds },
          startedAt: { gte: since },
        },
        select: {
          id: true,
          scanType: true,
          status: true,
          metadata: true,
          startedAt: true,
          completedAt: true,
        },
        orderBy: { startedAt: 'desc' },
      })
    : [];

  res.json({
    team: { id: team.id, name: team.name, slug: team.slug },
    period: '30d',
    totalScans: recentScans.length,
    totalProjects: team.projects.length,
    totalMembers: team.members.length,
    latestScans: recentScans.slice(0, 10),
  });
});

export default router;
