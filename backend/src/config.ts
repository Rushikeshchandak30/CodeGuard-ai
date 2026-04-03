// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Configuration
// ═══════════════════════════════════════════════════════════════════════

import dotenv from 'dotenv';
import path from 'path';

// Load .env from backend directory
dotenv.config({ path: path.resolve(__dirname, '../.env') });

function required(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

function optional(key: string, fallback: string): string {
  return process.env[key] || fallback;
}

export const config = {
  // Server
  port: parseInt(optional('PORT', '3000'), 10),
  nodeEnv: optional('NODE_ENV', 'development'),
  apiBaseUrl: optional('API_BASE_URL', 'http://localhost:3000'),
  corsOrigins: optional('CORS_ORIGINS', 'http://localhost:3000,http://localhost:5173').split(','),

  // Supabase
  supabase: {
    url: required('SUPABASE_URL'),
    anonKey: required('SUPABASE_ANON_KEY'),
    serviceRoleKey: required('SUPABASE_SERVICE_ROLE_KEY'),
  },

  // Upstash Redis
  redis: {
    url: optional('UPSTASH_REDIS_REST_URL', ''),
    token: optional('UPSTASH_REDIS_REST_TOKEN', ''),
  },

  // GitHub OAuth
  github: {
    clientId: optional('GITHUB_CLIENT_ID', ''),
    clientSecret: optional('GITHUB_CLIENT_SECRET', ''),
  },

  // Sentry
  sentry: {
    dsn: optional('SENTRY_DSN', ''),
  },

  // Resend (Email)
  resend: {
    apiKey: optional('RESEND_API_KEY', ''),
  },

  // Auth
  jwt: {
    secret: required('JWT_SECRET'),
    expiresIn: '7d',
  },

  // Rate limiting
  rateLimit: {
    windowMs: parseInt(optional('RATE_LIMIT_WINDOW_MS', '60000'), 10),
    maxRequests: parseInt(optional('RATE_LIMIT_MAX_REQUESTS', '100'), 10),
  },

  // OSV
  osv: {
    apiUrl: optional('OSV_API_URL', 'https://api.osv.dev'),
  },

  // Feature flags
  isDev: optional('NODE_ENV', 'development') === 'development',
  isProd: optional('NODE_ENV', 'development') === 'production',
};
