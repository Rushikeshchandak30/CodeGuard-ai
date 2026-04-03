// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Feature Flags Service
// ═══════════════════════════════════════════════════════════════════════
// Dynamic feature flag system for gating experimental features.
// Flags can be overridden per-user, per-team, or globally via DB/Redis.
// ═══════════════════════════════════════════════════════════════════════

import { cacheGet, cacheSet } from './redis';
import { logger } from '../utils/logger';

// ─── Default Feature Flags ──────────────────────────────────────────

export interface FeatureFlags {
  // Core features
  ghin_crowdsource_reports: boolean;      // Accept community hallucination reports
  ghin_auto_confirm: boolean;             // Auto-confirm packages with 3+ reports
  ghin_background_consolidation: boolean; // KAIROS-inspired background data merging
  scan_history_storage: boolean;          // Store scan results in DB
  scan_trend_analytics: boolean;          // 30-day trend calculations

  // Security & validation
  strict_tool_gating: boolean;            // Enforce tool/command allowlists
  memory_verification: boolean;           // Verify GHIN data integrity before trusting
  api_key_rotation_reminder: boolean;     // Warn users about aging API keys

  // Team features
  team_management: boolean;               // Enable team creation and management
  team_policy_sync: boolean;              // Sync policies from backend to CLI/extension
  webhook_delivery: boolean;              // Fire webhooks on scan events

  // Experimental
  ai_triage_assistant: boolean;           // LLM-powered scan result triage
  continuous_monitoring: boolean;          // Background re-scan on dependency changes
  threat_intelligence_feed: boolean;      // Live threat intel from OSV/NVD
  mcp_server_registry: boolean;           // Community MCP server trust registry
  agent_orchestration: boolean;           // Multi-agent scan pipeline coordination
}

// ─── Default values (production-safe) ───────────────────────────────

const DEFAULT_FLAGS: FeatureFlags = {
  // Core — enabled
  ghin_crowdsource_reports: true,
  ghin_auto_confirm: true,
  ghin_background_consolidation: true,
  scan_history_storage: true,
  scan_trend_analytics: true,

  // Security — enabled
  strict_tool_gating: true,
  memory_verification: true,
  api_key_rotation_reminder: true,

  // Team — enabled
  team_management: true,
  team_policy_sync: false,          // Not yet implemented
  webhook_delivery: false,          // Not yet implemented

  // Experimental — disabled by default
  ai_triage_assistant: false,
  continuous_monitoring: false,
  threat_intelligence_feed: false,
  mcp_server_registry: false,
  agent_orchestration: false,
};

// ─── Environment overrides ──────────────────────────────────────────
// Flags can be overridden via env: FEATURE_FLAG_<NAME>=true|false

function loadEnvOverrides(): Partial<FeatureFlags> {
  const overrides: Partial<FeatureFlags> = {};
  for (const key of Object.keys(DEFAULT_FLAGS)) {
    const envKey = `FEATURE_FLAG_${key.toUpperCase()}`;
    const envVal = process.env[envKey];
    if (envVal !== undefined) {
      (overrides as any)[key] = envVal === 'true' || envVal === '1';
    }
  }
  return overrides;
}

// ─── Merged flags (defaults + env overrides + runtime overrides) ────

let runtimeOverrides: Partial<FeatureFlags> = {};

/**
 * Get the current state of all feature flags.
 * Priority: runtime overrides > env overrides > defaults
 */
export function getFlags(): FeatureFlags {
  const envOverrides = loadEnvOverrides();
  return { ...DEFAULT_FLAGS, ...envOverrides, ...runtimeOverrides };
}

/**
 * Check if a specific feature flag is enabled.
 */
export function isEnabled(flag: keyof FeatureFlags): boolean {
  return getFlags()[flag];
}

/**
 * Set a runtime override for a feature flag.
 * Used by admin API or background services.
 */
export function setFlagOverride(flag: keyof FeatureFlags, value: boolean): void {
  runtimeOverrides[flag] = value;
  logger.info(`Feature flag override set: ${flag} = ${value}`);
}

/**
 * Clear all runtime overrides (reset to defaults + env).
 */
export function clearOverrides(): void {
  runtimeOverrides = {};
  logger.info('Feature flag overrides cleared');
}

/**
 * Get flags for a specific user/team from cache.
 * Allows per-user flag overrides stored in Redis.
 */
export async function getUserFlags(userId: string): Promise<FeatureFlags> {
  const baseFlags = getFlags();

  try {
    const userOverrides = await cacheGet<Partial<FeatureFlags>>(`flags:user:${userId}`);
    if (userOverrides) {
      return { ...baseFlags, ...userOverrides };
    }
  } catch (err) {
    logger.error('Failed to load user feature flags', err);
  }

  return baseFlags;
}

/**
 * Set per-user flag overrides (stored in Redis with 24h TTL).
 */
export async function setUserFlags(userId: string, overrides: Partial<FeatureFlags>): Promise<void> {
  try {
    await cacheSet(`flags:user:${userId}`, overrides, 86400); // 24h TTL
    logger.info('User feature flags updated', { userId, flags: Object.keys(overrides) });
  } catch (err) {
    logger.error('Failed to save user feature flags', err);
  }
}
