// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Database Service (Prisma Client Singleton)
// ═══════════════════════════════════════════════════════════════════════

import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';

let prisma: PrismaClient;

/**
 * Get the singleton Prisma client instance.
 * In development, reuse across hot-reloads via globalThis.
 */
export function getDb(): PrismaClient {
  if (prisma) return prisma;

  const globalForPrisma = globalThis as unknown as { __prisma?: PrismaClient };

  if (globalForPrisma.__prisma) {
    prisma = globalForPrisma.__prisma;
    return prisma;
  }

  prisma = new PrismaClient({
    log: process.env.NODE_ENV === 'development'
      ? ['query', 'warn', 'error']
      : ['warn', 'error'],
  });

  globalForPrisma.__prisma = prisma;
  logger.info('Prisma client initialized');

  return prisma;
}

/**
 * Gracefully disconnect from the database.
 */
export async function disconnectDb(): Promise<void> {
  if (prisma) {
    await prisma.$disconnect();
    logger.info('Prisma client disconnected');
  }
}
