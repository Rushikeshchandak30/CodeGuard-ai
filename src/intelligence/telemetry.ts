/**
 * Telemetry Reporter
 *
 * Sends anonymized security events to the GHIN API with full IDE + AI agent context.
 * Opt-in only — requires codeguard.enableGhinCloudSync = true.
 *
 * Detects:
 * - IDE: VS Code, Cursor, Windsurf, Codespaces
 * - AI Agent: Copilot, Cascade, Cursor AI, etc.
 *
 * Events are queued and batch-sent (max 10 events/minute).
 */

import * as vscode from 'vscode';
import { GhinClient, GhinReportPayload } from './ghin-client';

// ---------------------------------------------------------------------------
// Event Types
// ---------------------------------------------------------------------------

export type SecurityEventType =
  | 'hallucination_detected'
  | 'install_blocked'
  | 'vuln_found'
  | 'fix_applied'
  | 'prompt_injection_detected'
  | 'sbom_generated'
  | 'secret_found'
  | 'sast_finding';

export interface SecurityEvent {
  type: SecurityEventType;
  packageName?: string;
  ecosystem?: string;
  packageVersion?: string;
  severity?: string;
  actionTaken: string;
  aiAgent?: string;
  aiModel?: string;
  aiInteractionType?: string;
}

// ---------------------------------------------------------------------------
// TelemetryReporter
// ---------------------------------------------------------------------------

export class TelemetryReporter {
  private queue: SecurityEvent[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private client: GhinClient;
  private enabled: boolean = false;
  private readonly MAX_QUEUE_SIZE = 50;
  private readonly FLUSH_INTERVAL_MS = 60_000; // 1 minute
  private readonly MAX_EVENTS_PER_FLUSH = 10;

  constructor(client: GhinClient) {
    this.client = client;
    this.enabled = this.checkEnabled();

    // Watch for config changes
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('codeguard.enableGhinCloudSync')) {
        this.enabled = this.checkEnabled();
        if (!this.enabled) { this.queue = []; }
      }
    });

    // Start flush timer
    this.flushTimer = setInterval(() => this.flush(), this.FLUSH_INTERVAL_MS);
  }

  /**
   * Queue a security event for reporting.
   */
  report(event: SecurityEvent): void {
    if (!this.enabled) { return; }

    this.queue.push(event);

    // Prevent unbounded growth
    if (this.queue.length > this.MAX_QUEUE_SIZE) {
      this.queue = this.queue.slice(-this.MAX_QUEUE_SIZE);
    }
  }

  /**
   * Flush queued events to the GHIN API.
   */
  async flush(): Promise<void> {
    if (!this.enabled || this.queue.length === 0 || !this.client.isAvailable()) {
      return;
    }

    const batch = this.queue.splice(0, this.MAX_EVENTS_PER_FLUSH);

    for (const event of batch) {
      const payload: Partial<GhinReportPayload> = {
        event_type: event.type,
        package_name: event.packageName ?? '',
        ecosystem: event.ecosystem ?? 'npm',
        package_version: event.packageVersion,
        action_taken: event.actionTaken,
        severity: event.severity,
        ai_agent: event.aiAgent ?? this.detectAiAgent(),
        ai_model: event.aiModel,
        ai_interaction_type: event.aiInteractionType,
      };

      // Fire-and-forget — don't block on failures
      this.client.report(payload).catch(() => { /* silent */ });
    }
  }

  /**
   * Detect which AI agent is active in the current IDE.
   */
  private detectAiAgent(): string {
    const extensions = vscode.extensions.all.map(e => e.id.toLowerCase());

    if (extensions.some(id => id.includes('github.copilot'))) { return 'copilot'; }
    if (extensions.some(id => id.includes('codeium'))) { return 'windsurf-cascade'; }
    if (extensions.some(id => id.includes('cursor'))) { return 'cursor-ai'; }
    if (extensions.some(id => id.includes('sourcegraph.cody'))) { return 'cody'; }
    if (extensions.some(id => id.includes('tabnine'))) { return 'tabnine'; }
    if (extensions.some(id => id.includes('amazonwebservices') || id.includes('codewhisperer'))) { return 'codewhisperer'; }

    return 'unknown';
  }

  private checkEnabled(): boolean {
    return vscode.workspace.getConfiguration('codeguard').get<boolean>('enableGhinCloudSync', false);
  }

  dispose(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    // Final flush on dispose
    this.flush().catch(() => { /* silent */ });
  }
}
