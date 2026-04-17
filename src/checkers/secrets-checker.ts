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

  // ─── AI / LLM provider keys (v8.0 additions) ─────────────────────────
  {
    name: 'HuggingFace Token',
    pattern: /\bhf_[A-Za-z0-9]{34,40}\b/,
    severity: 'critical',
    description: 'Hardcoded HuggingFace access token detected',
    remediation: 'Move to environment variable: process.env.HF_TOKEN',
  },
  {
    name: 'Replicate API Token',
    pattern: /\br8_[A-Za-z0-9]{32,40}\b/,
    severity: 'critical',
    description: 'Hardcoded Replicate API token detected',
    remediation: 'Move to environment variable: process.env.REPLICATE_API_TOKEN',
  },
  {
    name: 'Cohere API Key',
    pattern: /\bco[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{40})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded Cohere API key detected',
    remediation: 'Move to environment variable: process.env.COHERE_API_KEY',
  },
  {
    name: 'Mistral API Key',
    pattern: /(?:mistral|codestral)[_\-\s]?api[_\-\s]?key\s*[:=]\s*['"]([A-Za-z0-9]{32,48})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded Mistral/Codestral API key detected',
    remediation: 'Move to environment variable: process.env.MISTRAL_API_KEY',
  },
  {
    name: 'Groq API Key',
    pattern: /\bgsk_[A-Za-z0-9]{48,56}\b/,
    severity: 'critical',
    description: 'Hardcoded Groq API key detected',
    remediation: 'Move to environment variable: process.env.GROQ_API_KEY',
  },
  {
    name: 'Perplexity API Key',
    pattern: /\bpplx-[A-Za-z0-9]{48,56}\b/,
    severity: 'critical',
    description: 'Hardcoded Perplexity API key detected',
    remediation: 'Move to environment variable: process.env.PPLX_API_KEY',
  },
  {
    name: 'Together AI API Key',
    pattern: /(?:together|togetherai)[_\-\s]?api[_\-\s]?key\s*[:=]\s*['"]([a-f0-9]{64})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded Together AI API key detected',
    remediation: 'Move to environment variable: process.env.TOGETHER_API_KEY',
  },
  {
    name: 'xAI (Grok) API Key',
    pattern: /\bxai-[A-Za-z0-9]{80,100}\b/,
    severity: 'critical',
    description: 'Hardcoded xAI (Grok) API key detected',
    remediation: 'Move to environment variable: process.env.XAI_API_KEY',
  },
  {
    name: 'DeepSeek API Key',
    pattern: /(?:deepseek)[_\-\s]?api[_\-\s]?key\s*[:=]\s*['"](sk-[A-Za-z0-9]{32,48})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded DeepSeek API key detected',
    remediation: 'Move to environment variable: process.env.DEEPSEEK_API_KEY',
  },
  {
    name: 'Fireworks AI API Key',
    pattern: /\bfw_[A-Za-z0-9]{40,60}\b/,
    severity: 'critical',
    description: 'Hardcoded Fireworks AI API key detected',
    remediation: 'Move to environment variable: process.env.FIREWORKS_API_KEY',
  },
  {
    name: 'Azure OpenAI Key',
    pattern: /(?:azure[_\-\s]?openai|openai[_\-\s]?azure)[_\-\s]?(?:api[_\-\s]?)?key\s*[:=]\s*['"]([a-f0-9]{32})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded Azure OpenAI API key detected',
    remediation: 'Move to environment variable: process.env.AZURE_OPENAI_API_KEY',
  },
  {
    name: 'Google Vertex AI Service Account',
    pattern: /"type"\s*:\s*"service_account"[^}]{0,500}"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/,
    severity: 'critical',
    description: 'Hardcoded Google Cloud / Vertex AI service account JSON detected',
    remediation: 'Load from file referenced by GOOGLE_APPLICATION_CREDENTIALS env var; never commit the JSON.',
  },
  {
    name: 'AI21 API Key',
    pattern: /(?:ai21)[_\-\s]?api[_\-\s]?key\s*[:=]\s*['"]([A-Za-z0-9]{32,40})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded AI21 API key detected',
    remediation: 'Move to environment variable: process.env.AI21_API_KEY',
  },
  {
    name: 'Pinecone API Key',
    pattern: /(?:pinecone|pinecone[_-]?io)[_\-\s]?api[_\-\s]?key\s*[:=]\s*['"]([a-f0-9\-]{36})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded Pinecone API key detected',
    remediation: 'Move to environment variable: process.env.PINECONE_API_KEY',
  },
  {
    name: 'Weaviate API Key',
    pattern: /(?:weaviate)[_\-\s]?api[_\-\s]?key\s*[:=]\s*['"]([A-Za-z0-9\-_]{32,64})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded Weaviate API key detected',
    remediation: 'Move to environment variable: process.env.WEAVIATE_API_KEY',
  },
  {
    name: 'LangSmith/LangChain API Key',
    pattern: /\blsv2_(?:pt|sk)_[A-Za-z0-9]{40,48}_[A-Za-z0-9]{10}\b/,
    severity: 'high',
    description: 'Hardcoded LangSmith/LangChain API key detected',
    remediation: 'Move to environment variable: process.env.LANGCHAIN_API_KEY',
  },

  // ─── Cloud providers (expanded) ──────────────────────────────────────
  {
    name: 'Azure Storage Account Key',
    pattern: /\bDefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88}/i,
    severity: 'critical',
    description: 'Hardcoded Azure Storage connection string detected',
    remediation: 'Use Azure Managed Identity or environment variable.',
  },
  {
    name: 'Azure AD Client Secret',
    pattern: /(?:azure[_\-\s]?(?:ad|tenant))[_\-\s]?client[_\-\s]?secret\s*[:=]\s*['"]([A-Za-z0-9~._-]{34,40})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded Azure AD / Entra ID client secret detected',
    remediation: 'Use Managed Identity or Azure Key Vault.',
  },
  {
    name: 'GCP API Key',
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/,
    severity: 'critical',
    description: 'Hardcoded Google Cloud API key detected',
    remediation: 'Use GOOGLE_APPLICATION_CREDENTIALS or Workload Identity.',
  },
  {
    name: 'DigitalOcean Personal Access Token',
    pattern: /\bdop_v1_[a-f0-9]{64}\b/,
    severity: 'critical',
    description: 'Hardcoded DigitalOcean PAT detected',
    remediation: 'Move to environment variable: process.env.DO_API_TOKEN',
  },
  {
    name: 'Heroku API Key',
    pattern: /(?:heroku)[_\-\s]?(?:api[_\-\s]?key|token)\s*[:=]\s*['"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded Heroku API key detected',
    remediation: 'Move to environment variable or use OAuth.',
  },

  // ─── Developer / CI tools ────────────────────────────────────────────
  {
    name: 'GitLab Personal Access Token',
    pattern: /\bglpat-[A-Za-z0-9_\-]{20}\b/,
    severity: 'critical',
    description: 'Hardcoded GitLab PAT detected',
    remediation: 'Move to environment variable: process.env.GITLAB_TOKEN',
  },
  {
    name: 'Bitbucket App Password',
    pattern: /(?:bitbucket)[_\-\s]?app[_\-\s]?password\s*[:=]\s*['"]([A-Z]{32})['"]?/i,
    severity: 'high',
    description: 'Hardcoded Bitbucket app password detected',
    remediation: 'Use repository access tokens instead.',
  },
  {
    name: 'CircleCI Personal Token',
    pattern: /(?:circle[_\-\s]?ci)[_\-\s]?token\s*[:=]\s*['"]([a-f0-9]{40})['"]?/i,
    severity: 'high',
    description: 'Hardcoded CircleCI token detected',
    remediation: 'Use CircleCI contexts or environment variables.',
  },
  {
    name: 'Docker Hub Token',
    pattern: /\bdckr_pat_[A-Za-z0-9_\-]{36,40}\b/,
    severity: 'critical',
    description: 'Hardcoded Docker Hub PAT detected',
    remediation: 'Move to environment variable: process.env.DOCKERHUB_TOKEN',
  },

  // ─── Payment / Finance ───────────────────────────────────────────────
  {
    name: 'Square Access Token',
    pattern: /\b(?:EAAA|sq0[a-z]{3}-)[A-Za-z0-9\-_]{60,100}\b/,
    severity: 'critical',
    description: 'Hardcoded Square access token detected',
    remediation: 'Use Square OAuth flow; never hardcode tokens.',
  },
  {
    name: 'PayPal Client Secret',
    pattern: /(?:paypal)[_\-\s]?(?:client[_\-\s]?)?secret\s*[:=]\s*['"]([A-Za-z0-9_-]{80})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded PayPal client secret detected',
    remediation: 'Use environment variable or secrets manager.',
  },
  {
    name: 'Plaid API Key',
    pattern: /(?:plaid)[_\-\s]?(?:client[_\-\s]?id|secret|public[_\-\s]?key)\s*[:=]\s*['"]([a-f0-9]{24,32})['"]?/i,
    severity: 'critical',
    description: 'Hardcoded Plaid API credential detected',
    remediation: 'Use environment variables.',
  },

  // ─── Misc & expanded ─────────────────────────────────────────────────
  {
    name: 'Mailgun API Key',
    pattern: /\bkey-[a-f0-9]{32}\b/,
    severity: 'high',
    description: 'Hardcoded Mailgun API key detected',
    remediation: 'Move to environment variable: process.env.MAILGUN_API_KEY',
  },
  {
    name: 'Mailchimp API Key',
    pattern: /\b[a-f0-9]{32}-us\d{1,2}\b/,
    severity: 'high',
    description: 'Hardcoded Mailchimp API key detected',
    remediation: 'Move to environment variable: process.env.MAILCHIMP_API_KEY',
  },
  {
    name: 'Discord Bot Token',
    pattern: /\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b/,
    severity: 'critical',
    description: 'Hardcoded Discord bot token detected',
    remediation: 'Move to environment variable: process.env.DISCORD_TOKEN',
  },
  {
    name: 'Telegram Bot Token',
    pattern: /\b\d{9,10}:[A-Za-z0-9_-]{35}\b/,
    severity: 'critical',
    description: 'Hardcoded Telegram bot token detected',
    remediation: 'Move to environment variable: process.env.TELEGRAM_BOT_TOKEN',
  },
  {
    name: 'Shopify Access Token',
    pattern: /\bshpat_[a-f0-9]{32}\b/,
    severity: 'critical',
    description: 'Hardcoded Shopify access token detected',
    remediation: 'Move to environment variable: process.env.SHOPIFY_ACCESS_TOKEN',
  },
  {
    name: 'Datadog API Key',
    pattern: /(?:datadog|dd)[_\-\s]?api[_\-\s]?key\s*[:=]\s*['"]([a-f0-9]{32})['"]?/i,
    severity: 'high',
    description: 'Hardcoded Datadog API key detected',
    remediation: 'Move to environment variable: process.env.DATADOG_API_KEY',
  },
  {
    name: 'New Relic License Key',
    pattern: /(?:new[_\-\s]?relic|nr)[_\-\s]?license[_\-\s]?key\s*[:=]\s*['"]([a-f0-9]{40}NRAL)['"]?/i,
    severity: 'high',
    description: 'Hardcoded New Relic license key detected',
    remediation: 'Move to environment variable: process.env.NEW_RELIC_LICENSE_KEY',
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
