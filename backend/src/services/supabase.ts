// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Supabase Client Service
// ═══════════════════════════════════════════════════════════════════════

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { config } from '../config';
import { logger } from '../utils/logger';

let supabaseAdmin: SupabaseClient;

/**
 * Get the Supabase admin client (service role — full access).
 * Used for server-side operations like user creation, token verification.
 */
export function getSupabaseAdmin(): SupabaseClient {
  if (supabaseAdmin) return supabaseAdmin;

  supabaseAdmin = createClient(config.supabase.url, config.supabase.serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });

  logger.info('Supabase admin client initialized');
  return supabaseAdmin;
}

/**
 * Create a Supabase client scoped to a user's JWT token.
 * Used for row-level security (RLS) operations.
 */
export function getSupabaseForUser(accessToken: string): SupabaseClient {
  return createClient(config.supabase.url, config.supabase.anonKey, {
    global: {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  });
}
