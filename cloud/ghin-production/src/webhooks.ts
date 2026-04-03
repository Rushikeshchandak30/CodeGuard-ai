/**
 * Webhook Delivery Service
 *
 * Sends real-time security event notifications to external services:
 *   - Slack (incoming webhooks)
 *   - Microsoft Teams (connector webhooks)
 *   - Jira (REST API)
 *   - Generic HTTP webhooks (any endpoint)
 *
 * Events:
 *   - critical_vulnerability — Critical/high vuln detected in dependency
 *   - hallucination_detected — AI hallucinated a package
 *   - install_blocked — Package install was blocked by the gate
 *   - policy_violation — Security policy was violated
 *   - trust_score_drop — Package trust score dropped below threshold
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type WebhookType = 'slack' | 'teams' | 'jira' | 'generic';

export interface WebhookConfig {
  id: string;
  type: WebhookType;
  url: string;
  /** Events to subscribe to (empty = all) */
  events: string[];
  /** Whether this webhook is active */
  enabled: boolean;
  /** Optional auth header for generic webhooks */
  authHeader?: string;
  /** Jira-specific config */
  jira?: {
    projectKey: string;
    issueType: string;
    priority?: string;
  };
}

export interface WebhookEvent {
  event_type: string;
  severity: string;
  package_name?: string;
  ecosystem?: string;
  message: string;
  details?: Record<string, unknown>;
  timestamp: string;
}

export interface DeliveryResult {
  webhookId: string;
  success: boolean;
  statusCode?: number;
  error?: string;
  deliveredAt: string;
}

// ---------------------------------------------------------------------------
// Payload Formatters
// ---------------------------------------------------------------------------

function severityEmoji(severity: string): string {
  switch (severity) {
    case 'critical': return '\u{1F534}';
    case 'high': return '\u{1F7E0}';
    case 'medium': return '\u{1F7E1}';
    case 'low': return '\u{1F7E2}';
    default: return '\u{26AA}';
  }
}

function formatSlackPayload(event: WebhookEvent): object {
  return {
    blocks: [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `${severityEmoji(event.severity)} CodeGuard AI: ${event.event_type.replace(/_/g, ' ')}`,
          emoji: true,
        },
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: event.message,
        },
      },
      ...(event.package_name ? [{
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Package:*\n\`${event.package_name}\`` },
          { type: 'mrkdwn', text: `*Ecosystem:*\n${event.ecosystem || 'unknown'}` },
          { type: 'mrkdwn', text: `*Severity:*\n${event.severity}` },
          { type: 'mrkdwn', text: `*Time:*\n${new Date(event.timestamp).toLocaleString()}` },
        ],
      }] : []),
      {
        type: 'context',
        elements: [
          { type: 'mrkdwn', text: 'Sent by *CodeGuard AI* | <https://codeguard.dev|Dashboard>' },
        ],
      },
    ],
  };
}

function formatTeamsPayload(event: WebhookEvent): object {
  return {
    '@type': 'MessageCard',
    '@context': 'http://schema.org/extensions',
    themeColor: event.severity === 'critical' ? 'FF0000' : event.severity === 'high' ? 'FF8C00' : 'FFD700',
    summary: `CodeGuard AI: ${event.event_type}`,
    sections: [
      {
        activityTitle: `${severityEmoji(event.severity)} CodeGuard AI: ${event.event_type.replace(/_/g, ' ')}`,
        activitySubtitle: event.message,
        facts: [
          ...(event.package_name ? [{ name: 'Package', value: event.package_name }] : []),
          ...(event.ecosystem ? [{ name: 'Ecosystem', value: event.ecosystem }] : []),
          { name: 'Severity', value: event.severity },
          { name: 'Time', value: new Date(event.timestamp).toLocaleString() },
        ],
        markdown: true,
      },
    ],
    potentialAction: [
      {
        '@type': 'OpenUri',
        name: 'Open Dashboard',
        targets: [{ os: 'default', uri: 'https://codeguard.dev' }],
      },
    ],
  };
}

function formatJiraPayload(event: WebhookEvent, config: WebhookConfig): object {
  const jira = config.jira!;
  return {
    fields: {
      project: { key: jira.projectKey },
      summary: `[CodeGuard] ${event.severity.toUpperCase()}: ${event.event_type.replace(/_/g, ' ')}${event.package_name ? ` — ${event.package_name}` : ''}`,
      description: {
        type: 'doc',
        version: 1,
        content: [
          {
            type: 'paragraph',
            content: [
              { type: 'text', text: event.message },
            ],
          },
          ...(event.package_name ? [{
            type: 'paragraph',
            content: [
              { type: 'text', text: `Package: ${event.package_name} (${event.ecosystem || 'unknown'})`, marks: [{ type: 'strong' }] },
            ],
          }] : []),
          {
            type: 'paragraph',
            content: [
              { type: 'text', text: `Severity: ${event.severity} | Detected at: ${event.timestamp}` },
            ],
          },
        ],
      },
      issuetype: { name: jira.issueType || 'Bug' },
      priority: { name: jira.priority || (event.severity === 'critical' ? 'Highest' : event.severity === 'high' ? 'High' : 'Medium') },
      labels: ['codeguard', 'security', event.severity],
    },
  };
}

function formatGenericPayload(event: WebhookEvent): object {
  return {
    source: 'codeguard-ai',
    version: '5.2.0',
    ...event,
  };
}

// ---------------------------------------------------------------------------
// WebhookService Class
// ---------------------------------------------------------------------------

export class WebhookService {
  private configs: WebhookConfig[] = [];
  private deliveryLog: DeliveryResult[] = [];
  private static readonly MAX_LOG = 500;

  constructor(configs?: WebhookConfig[]) {
    if (configs) { this.configs = configs; }
  }

  addWebhook(config: WebhookConfig): void {
    this.configs.push(config);
  }

  removeWebhook(id: string): void {
    this.configs = this.configs.filter(c => c.id !== id);
  }

  getWebhooks(): WebhookConfig[] {
    return [...this.configs];
  }

  getDeliveryLog(): DeliveryResult[] {
    return [...this.deliveryLog];
  }

  /**
   * Deliver an event to all matching webhooks.
   */
  async deliver(event: WebhookEvent): Promise<DeliveryResult[]> {
    const results: DeliveryResult[] = [];

    const matching = this.configs.filter(c =>
      c.enabled && (c.events.length === 0 || c.events.includes(event.event_type))
    );

    for (const config of matching) {
      const result = await this.deliverToWebhook(config, event);
      results.push(result);
      this.deliveryLog.push(result);
    }

    // Trim log
    if (this.deliveryLog.length > WebhookService.MAX_LOG) {
      this.deliveryLog = this.deliveryLog.slice(-WebhookService.MAX_LOG);
    }

    return results;
  }

  /**
   * Test a specific webhook with a sample event.
   */
  async test(webhookId: string): Promise<DeliveryResult> {
    const config = this.configs.find(c => c.id === webhookId);
    if (!config) {
      return { webhookId, success: false, error: 'Webhook not found', deliveredAt: new Date().toISOString() };
    }

    const testEvent: WebhookEvent = {
      event_type: 'test',
      severity: 'low',
      message: 'This is a test notification from CodeGuard AI.',
      timestamp: new Date().toISOString(),
    };

    return this.deliverToWebhook(config, testEvent);
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  private async deliverToWebhook(config: WebhookConfig, event: WebhookEvent): Promise<DeliveryResult> {
    try {
      let payload: object;
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };

      switch (config.type) {
        case 'slack':
          payload = formatSlackPayload(event);
          break;
        case 'teams':
          payload = formatTeamsPayload(event);
          break;
        case 'jira':
          payload = formatJiraPayload(event, config);
          break;
        case 'generic':
        default:
          payload = formatGenericPayload(event);
          break;
      }

      if (config.authHeader) {
        headers['Authorization'] = config.authHeader;
      }

      const response = await fetch(config.url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10000),
      });

      return {
        webhookId: config.id,
        success: response.ok,
        statusCode: response.status,
        deliveredAt: new Date().toISOString(),
      };
    } catch (err) {
      return {
        webhookId: config.id,
        success: false,
        error: err instanceof Error ? err.message : String(err),
        deliveredAt: new Date().toISOString(),
      };
    }
  }
}
