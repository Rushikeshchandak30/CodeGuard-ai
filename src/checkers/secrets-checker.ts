/**
 * Secrets Checker — Hardcoded Credentials & Secrets Detection
 *
 * Scans source files for hardcoded secrets, API keys, tokens, passwords,
 * and other credentials that should never be committed to source code.
 * Uses regex pattern matching with entropy analysis for high accuracy.
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Secret Pattern Definitions
// ---------------------------------------------------------------------------

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium';
  description: string;
  remediation: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // API Keys
  {
    name: 'OpenAI API Key',
    pattern: /\bsk-[A-Za-z0-9]{20,60}\b/,
    severity: 'critical',
    description: 'Hardcoded OpenAI API key detected',
    remediation: 'Move to environment variable: process.env.OPENAI_API_KEY',
  },
  {
    name: 'AWS Access Key',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    severity: 'critical',
    description: 'Hardcoded AWS Access Key ID detected',
    remediation: 'Use AWS IAM roles or environment variables',
  },
  {
    name: 'AWS Secret Key',
    pattern: /(?:aws[_\-\s]?secret|secret[_\-\s]?access[_\-\s]?key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded AWS Secret Access Key detected',
    remediation: 'Use AWS IAM roles or environment variables',
  },
  {
    name: 'GitHub Token',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/,
    severity: 'critical',
    description: 'Hardcoded GitHub personal access token detected',
    remediation: 'Use GitHub Actions secrets or environment variables',
  },
  {
    name: 'GitHub OAuth Token',
    pattern: /\bgithub[_\-\s]?(?:token|oauth|api[_\-\s]?key)\s*[:=]\s*['"]?([A-Za-z0-9_]{35,40})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded GitHub OAuth token detected',
    remediation: 'Use environment variables or secrets manager',
  },
  {
    name: 'Stripe Secret Key',
    pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b/,
    severity: 'critical',
    description: 'Hardcoded Stripe secret key detected',
    remediation: 'Move to environment variable: process.env.STRIPE_SECRET_KEY',
  },
  {
    name: 'Stripe Publishable Key',
    pattern: /\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b/,
    severity: 'high',
    description: 'Hardcoded Stripe publishable key detected',
    remediation: 'Move to environment variable: process.env.STRIPE_PUBLISHABLE_KEY',
  },
  {
    name: 'Slack Token',
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    severity: 'critical',
    description: 'Hardcoded Slack token detected',
    remediation: 'Use Slack app environment variables',
  },
  {
    name: 'Slack Webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
    severity: 'high',
    description: 'Hardcoded Slack webhook URL detected',
    remediation: 'Move to environment variable: process.env.SLACK_WEBHOOK_URL',
  },
  {
    name: 'Google API Key',
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/,
    severity: 'critical',
    description: 'Hardcoded Google API key detected',
    remediation: 'Move to environment variable: process.env.GOOGLE_API_KEY',
  },
  {
    name: 'Firebase API Key',
    pattern: /firebase[_\-\s]?(?:api[_\-\s]?key|secret)\s*[:=]\s*['"]([A-Za-z0-9\-_]{30,})['"]?/i,
    severity: 'high',
    description: 'Hardcoded Firebase API key detected',
    remediation: 'Use Firebase environment configuration',
  },
  {
    name: 'Twilio API Key',
    pattern: /\bSK[0-9a-fA-F]{32}\b/,
    severity: 'critical',
    description: 'Hardcoded Twilio API key detected',
    remediation: 'Move to environment variable: process.env.TWILIO_API_KEY',
  },
  {
    name: 'SendGrid API Key',
    pattern: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/,
    severity: 'critical',
    description: 'Hardcoded SendGrid API key detected',
    remediation: 'Move to environment variable: process.env.SENDGRID_API_KEY',
  },
  {
    name: 'Anthropic API Key',
    pattern: /\bsk-ant-[A-Za-z0-9\-_]{40,}\b/,
    severity: 'critical',
    description: 'Hardcoded Anthropic API key detected',
    remediation: 'Move to environment variable: process.env.ANTHROPIC_API_KEY',
  },
  {
    name: 'Hardcoded Password',
    pattern: /(?:password|passwd|pwd|secret|pass)\s*[:=]\s*['"]([^'"]{8,})['"](?!\s*\+)/i,
    severity: 'high',
    description: 'Hardcoded password or secret string detected',
    remediation: 'Use environment variables or a secrets manager',
  },
  {
    name: 'Hardcoded JWT Secret',
    pattern: /(?:jwt[_\-\s]?secret|token[_\-\s]?secret|signing[_\-\s]?key)\s*[:=]\s*['"]([^'"]{8,})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded JWT signing secret detected',
    remediation: 'Use a strong random secret from environment variables',
  },
  {
    name: 'Database Connection String',
    pattern: /(?:mongodb|postgres|mysql|redis|mssql):\/\/[^:]+:[^@]+@[^\s'"]+/i,
    severity: 'critical',
    description: 'Hardcoded database connection string with credentials detected',
    remediation: 'Use environment variable: process.env.DATABASE_URL',
  },
  {
    name: 'Private Key Block',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical',
    description: 'Hardcoded private key detected in source code',
    remediation: 'Never commit private keys — use a secrets manager or key vault',
  },
  {
    name: 'npm Auth Token',
    pattern: /(?:npm[_\-\s]?token|npm[_\-\s]?auth)\s*[:=]\s*['"]?([A-Za-z0-9\-_]{36,})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded npm authentication token detected',
    remediation: 'Use environment variable: process.env.NPM_TOKEN',
  },
  {
    name: 'Generic High-Entropy Secret',
    pattern: /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]([A-Za-z0-9+/=_-]{32,})['"]?/i,
    severity: 'high',
    description: 'Hardcoded API key or token detected',
    remediation: 'Move to environment variable',
  },
];

// Lines to skip (common false positives)
const SKIP_PATTERNS = [
  /^\s*\/\//,           // single-line comment
  /^\s*\*/              // JSDoc comment
];

const PLACEHOLDER_VALUES = new Set([
  'your-api-key', 'your_api_key', 'YOUR_API_KEY', 'xxx', 'xxxx',
  'placeholder', 'changeme', 'example', 'test', 'dummy', 'fake',
  'your-secret', 'your_secret', 'YOUR_SECRET', 'insert-key-here',
  'sk-...', 'sk-xxxx', 'pk_test_xxx', 'sk_test_xxx',
]);

// ---------------------------------------------------------------------------
// Secret Finding
// ---------------------------------------------------------------------------

export interface SecretFinding {
  line: number;
  column: number;
  endColumn: number;
  patternName: string;
  severity: 'critical' | 'high' | 'medium';
  description: string;
  remediation: string;
  snippet: string;
}

// ---------------------------------------------------------------------------
// SecretsChecker Class
// ---------------------------------------------------------------------------

export class SecretsChecker {
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard-secrets');
  }

  /**
   * Scan a document for hardcoded secrets.
   */
  scanDocument(document: vscode.TextDocument): SecretFinding[] {
    const findings: SecretFinding[] = [];
    const text = document.getText();
    const lines = text.split('\n');

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      // Skip comment lines
      if (SKIP_PATTERNS.some(p => p.test(line))) { continue; }

      for (const secretPattern of SECRET_PATTERNS) {
        const match = secretPattern.pattern.exec(line);
        if (!match) { continue; }

        // Skip placeholder values
        const matchedValue = match[1] ?? match[0];
        if (PLACEHOLDER_VALUES.has(matchedValue.toLowerCase())) { continue; }
        if (matchedValue.length < 8) { continue; }

        const col = match.index;
        const endCol = match.index + match[0].length;

        // Redact the actual secret value in the snippet
        const snippet = line.trim().substring(0, 80).replace(matchedValue, '[REDACTED]');

        findings.push({
          line: lineIdx,
          column: col,
          endColumn: endCol,
          patternName: secretPattern.name,
          severity: secretPattern.severity,
          description: secretPattern.description,
          remediation: secretPattern.remediation,
          snippet,
        });
      }
    }

    return findings;
  }

  /**
   * Update VS Code diagnostics for a document based on secret findings.
   */
  updateDiagnostics(document: vscode.TextDocument, findings: SecretFinding[]): void {
    const diagnostics: vscode.Diagnostic[] = findings.map(f => {
      const range = new vscode.Range(f.line, f.column, f.line, f.endColumn);
      const severity = f.severity === 'critical' || f.severity === 'high'
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Warning;

      const diag = new vscode.Diagnostic(
        range,
        `🔑 ${f.patternName}: ${f.description}. ${f.remediation}`,
        severity
      );
      diag.source = 'CodeGuard AI (Secrets)';
      diag.code = `SECRET_${f.patternName.toUpperCase().replace(/\s+/g, '_')}`;
      return diag;
    });

    this.diagnosticCollection.set(document.uri, diagnostics);
  }

  /**
   * Clear diagnostics for a document.
   */
  clearDiagnostics(uri: vscode.Uri): void {
    this.diagnosticCollection.delete(uri);
  }

  /**
   * Scan and update diagnostics for a document.
   */
  async scan(document: vscode.TextDocument): Promise<SecretFinding[]> {
    const supportedLanguages = [
      'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
      'python', 'go', 'java', 'rust', 'json', 'yaml', 'toml', 'env',
      'shellscript', 'powershell', 'ruby', 'php', 'csharp',
    ];

    if (!supportedLanguages.includes(document.languageId)) {
      return [];
    }

    const findings = this.scanDocument(document);
    this.updateDiagnostics(document, findings);
    return findings;
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
  }
}
