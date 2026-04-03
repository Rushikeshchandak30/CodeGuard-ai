/**
 * GHIN Production Client
 *
 * Client for the GHIN (Global Hallucination Intelligence Network) production API.
 * Supports:
 * - POST /api/v1/report          — report hallucination/signal with IDE + agent context
 * - POST /api/v1/bulk-check      — batch check packages
 * - GET  /api/v1/package/:eco/:name — single package full intelligence
 * - GET  /api/v1/stats/agents     — hallucination & block stats by AI agent + IDE
 *
 * Falls back to local GHIN DB when the API is unreachable.
 */

import * as vscode from 'vscode';
import { detectIde, detectAiAgent } from '../utils/ide-detect';

// ---------------------------------------------------------------------------
// API Types
// ---------------------------------------------------------------------------

export interface GhinReportPayload {
  event_type: string;
  ide: string;
  ide_version: string;
  extension_version: string;
  ai_agent: string;
  ai_agent_version?: string;
  ai_model?: string;
  ai_interaction_type?: string;
  package_name: string;
  ecosystem: string;
  package_version?: string;
  action_taken: string;
  severity?: string;
  os_platform: string;
  anonymous_client_id: string;
}

export interface GhinPackageIntelligence {
  exists: boolean;
  trust_score: number;
  hallucination: boolean;
  vulnerable: boolean;
  highest_severity: string | null;
  patched_versions: string[];
  provenance: 'verified' | 'partial' | 'none';
  signals: {
    publisher_age_days?: number;
    has_install_scripts?: boolean;
    download_velocity?: string;
    weekly_downloads?: number;
  };
  hallucination_context?: {
    top_ai_sources: string[];
    top_ides: string[];
    report_count: number;
  };
}

export interface GhinBulkCheckRequest {
  packages: Array<{ name: string; ecosystem: string }>;
}

export interface GhinBulkCheckResponse {
  results: Record<string, GhinPackageIntelligence>;
}

export interface GhinAgentStats {
  agents: Array<{
    agent: string;
    hallucinations_reported: number;
    installs_blocked: number;
    top_ecosystem: string;
  }>;
  ides: Array<{
    ide: string;
    total_events: number;
    blocked: number;
  }>;
}

// ---------------------------------------------------------------------------
// Client Configuration
// ---------------------------------------------------------------------------

const DEFAULT_API_BASE = 'https://ghin-api.codeguard.dev';
const REQUEST_TIMEOUT_MS = 5000;
const MAX_RETRIES = 2;

// ---------------------------------------------------------------------------
// GhinClient
// ---------------------------------------------------------------------------

export class GhinClient {
  private apiBase: string;
  private clientId: string;
  private extensionVersion: string;
  private available: boolean = true;
  private lastFailure: number = 0;
  private cooldownMs: number = 60_000; // 1 min cooldown after failure

  constructor(apiBase?: string, extensionVersion?: string) {
    this.apiBase = apiBase ?? DEFAULT_API_BASE;
    this.extensionVersion = extensionVersion ?? '0.4.0';
    this.clientId = this.getOrCreateClientId();
  }

  /**
   * Check if the GHIN API is currently available (not in cooldown).
   */
  isAvailable(): boolean {
    if (!this.available && Date.now() - this.lastFailure > this.cooldownMs) {
      this.available = true; // Reset cooldown
    }
    return this.available;
  }

  /**
   * Report a security event to GHIN.
   */
  async report(payload: Partial<GhinReportPayload>): Promise<boolean> {
    if (!this.isAvailable()) { return false; }

    const fullPayload: GhinReportPayload = {
      event_type: payload.event_type ?? 'unknown',
      ide: detectIde().ide,
      ide_version: vscode.version,
      extension_version: this.extensionVersion,
      ai_agent: payload.ai_agent ?? detectAiAgent().aiAgent,
      ai_agent_version: payload.ai_agent_version,
      ai_model: payload.ai_model,
      ai_interaction_type: payload.ai_interaction_type,
      package_name: payload.package_name ?? '',
      ecosystem: payload.ecosystem ?? 'npm',
      package_version: payload.package_version,
      action_taken: payload.action_taken ?? 'reported',
      severity: payload.severity,
      os_platform: process.platform,
      anonymous_client_id: this.clientId,
    };

    try {
      const resp = await this.fetch(`${this.apiBase}/api/v1/report`, {
        method: 'POST',
        body: JSON.stringify(fullPayload),
      });
      return resp.ok;
    } catch {
      this.markUnavailable();
      return false;
    }
  }

  /**
   * Get full intelligence for a single package.
   */
  async getPackageIntelligence(ecosystem: string, packageName: string): Promise<GhinPackageIntelligence | null> {
    if (!this.isAvailable()) { return null; }

    try {
      const resp = await this.fetch(
        `${this.apiBase}/api/v1/package/${encodeURIComponent(ecosystem)}/${encodeURIComponent(packageName)}`
      );
      if (!resp.ok) { return null; }
      return await resp.json() as GhinPackageIntelligence;
    } catch {
      this.markUnavailable();
      return null;
    }
  }

  /**
   * Batch check multiple packages.
   */
  async bulkCheck(packages: Array<{ name: string; ecosystem: string }>): Promise<GhinBulkCheckResponse | null> {
    if (!this.isAvailable() || packages.length === 0) { return null; }

    try {
      const body: GhinBulkCheckRequest = { packages };
      const resp = await this.fetch(`${this.apiBase}/api/v1/bulk-check`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      if (!resp.ok) { return null; }
      return await resp.json() as GhinBulkCheckResponse;
    } catch {
      this.markUnavailable();
      return null;
    }
  }

  /**
   * Get agent hallucination & block stats.
   */
  async getAgentStats(): Promise<GhinAgentStats | null> {
    if (!this.isAvailable()) { return null; }

    try {
      const resp = await this.fetch(`${this.apiBase}/api/v1/stats/agents`);
      if (!resp.ok) { return null; }
      return await resp.json() as GhinAgentStats;
    } catch {
      this.markUnavailable();
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private async fetch(url: string, init?: { method?: string; body?: string }): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    let lastError: Error | null = null;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        const resp = await globalThis.fetch(url, {
          method: init?.method ?? 'GET',
          headers: {
            'Content-Type': 'application/json',
            'X-CodeGuard-Version': this.extensionVersion,
            'X-CodeGuard-IDE': detectIde().ide,
          },
          body: init?.body,
          signal: controller.signal,
        });
        clearTimeout(timeout);
        return resp;
      } catch (e) {
        lastError = e instanceof Error ? e : new Error(String(e));
        if (attempt < MAX_RETRIES) {
          await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
        }
      }
    }
    clearTimeout(timeout);
    throw lastError ?? new Error('GHIN API request failed');
  }

  private markUnavailable(): void {
    this.available = false;
    this.lastFailure = Date.now();
    console.warn('[CodeGuard] GHIN API unavailable, entering cooldown');
  }


  private getOrCreateClientId(): string {
    // Use VS Code machine ID (already anonymized/hashed by VS Code)
    return vscode.env.machineId ?? 'unknown';
  }
}
