// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Global Error Handler Middleware
// ═══════════════════════════════════════════════════════════════════════

import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/errors';
import { logger } from '../utils/logger';
import { config } from '../config';

/**
 * Global error handler — catches all thrown errors and returns JSON.
 */
export function errorHandler(err: Error, req: Request, res: Response, _next: NextFunction): void {
  // AppError (expected operational errors)
  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      error: {
        code: err.code,
        message: err.message,
        ...(config.isDev && { stack: err.stack }),
      },
    });
    return;
  }

  // Zod validation errors
  if (err.name === 'ZodError') {
    res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed',
        details: (err as any).issues,
      },
    });
    return;
  }

  // Prisma known errors
  if (err.name === 'PrismaClientKnownRequestError') {
    const prismaErr = err as any;
    if (prismaErr.code === 'P2002') {
      res.status(409).json({
        error: {
          code: 'CONFLICT',
          message: `A record with that value already exists`,
        },
      });
      return;
    }
    if (prismaErr.code === 'P2025') {
      res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'Record not found',
        },
      });
      return;
    }
  }

  // Unexpected errors
  logger.error('Unhandled error', err, {
    method: req.method,
    path: req.path,
    ip: req.ip,
  });

  // Report to Sentry in production
  if (config.isProd && config.sentry.dsn) {
    try {
      const Sentry = require('@sentry/node');
      Sentry.captureException(err);
    } catch {
      // Sentry not available
    }
  }

  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: config.isProd ? 'An internal error occurred' : err.message,
      ...(config.isDev && { stack: err.stack }),
    },
  });
}

/**
 * 404 handler for unknown routes.
 */
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    error: {
      code: 'NOT_FOUND',
      message: `Route ${req.method} ${req.path} not found`,
    },
  });
}
