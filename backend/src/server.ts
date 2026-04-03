// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Express Server Entry Point
// ═══════════════════════════════════════════════════════════════════════

import 'express-async-errors';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { config } from './config';
import { logger } from './utils/logger';
import { getDb, disconnectDb } from './services/database';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { rateLimit } from './middleware/rateLimit';
import { optionalAuth } from './middleware/auth';

// Routes
import healthRoutes from './routes/health';
import authRoutes from './routes/auth';
import ghinRoutes from './routes/ghin';
import scanRoutes from './routes/scans';
import teamRoutes from './routes/teams';
import adminRoutes from './routes/admin';

// Services
import { startConsolidation, stopConsolidation } from './services/ghin-consolidator';
import { getFlags } from './services/feature-flags';

// ─── Initialize Sentry (if configured) ──────────────────────────────

if (config.sentry.dsn) {
  try {
    const Sentry = require('@sentry/node');
    Sentry.init({
      dsn: config.sentry.dsn,
      environment: config.nodeEnv,
      tracesSampleRate: config.isProd ? 0.1 : 1.0,
    });
    logger.info('Sentry initialized');
  } catch {
    logger.warn('Sentry initialization failed — continuing without error monitoring');
  }
}

// ─── Create Express App ──────────────────────────────────────────────

const app = express();

// Security headers
app.use(helmet({
  contentSecurityPolicy: false, // Allow API usage from any origin
}));

// CORS
app.use(cors({
  origin: config.corsOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging
if (config.isDev) {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Rate limiting (applied globally)
app.use(rateLimit);

// ─── Routes ──────────────────────────────────────────────────────────

// Public routes (no auth required)
app.use('/', healthRoutes);

// Auth routes
app.use('/api/auth', authRoutes);

// GHIN routes (mix of public and authenticated)
app.use('/api/ghin', ghinRoutes);

// Protected routes (auth required — enforced inside route handlers)
app.use('/api/scans', scanRoutes);
app.use('/api/teams', teamRoutes);

// Admin routes (ADMIN role required — enforced inside route handlers)
app.use('/api/admin', adminRoutes);

// ─── API info route ──────────────────────────────────────────────────

app.get('/api', optionalAuth, (_req: express.Request, res: express.Response) => {
  res.json({
    name: 'CodeGuard AI API',
    version: '7.2.0',
    description: 'Backend API for CodeGuard AI — GHIN Intelligence, Scan History, Team Management, Agentic Security',
    endpoints: {
      health: '/health',
      healthReady: '/health/ready',
      auth: '/api/auth',
      ghin: '/api/ghin',
      scans: '/api/scans',
      teams: '/api/teams',
      admin: '/api/admin',
    },
    features: getFlags(),
    docs: 'https://github.com/codeguard-ai/codeguard-ai#api-reference',
  });
});

// ─── Error handling ──────────────────────────────────────────────────

app.use(notFoundHandler);
app.use(errorHandler);

// ─── Start server ────────────────────────────────────────────────────

async function start(): Promise<void> {
  try {
    // Initialize database connection
    const db = getDb();
    try {
      await db.$connect();
      logger.info('Database connected');
    } catch (dbErr) {
      logger.warn('Database connection failed, starting server anyway', { error: String(dbErr) });
    }

    // Start GHIN background consolidation daemon
    startConsolidation();
    logger.info('GHIN consolidation daemon started');

    app.listen(config.port, () => {
      logger.info(`CodeGuard AI Backend running on port ${config.port}`, {
        env: config.nodeEnv,
        url: config.apiBaseUrl,
      });
      logger.info('Routes registered:', {
        health: '/health, /health/ready',
        api: '/api',
        auth: '/api/auth/*',
        ghin: '/api/ghin/*',
        scans: '/api/scans/*',
        teams: '/api/teams/*',
        admin: '/api/admin/*',
      });
      logger.info('Feature flags:', { ...getFlags() });
    });
  } catch (err) {
    logger.error('Failed to start server', err);
    process.exit(1);
  }
}

// ─── Graceful shutdown ───────────────────────────────────────────────

async function shutdown(signal: string): Promise<void> {
  logger.info(`${signal} received — shutting down gracefully`);
  stopConsolidation();
  await disconnectDb();
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', reason);
});

// Start the server
start();

export { app };
