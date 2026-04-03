/**
 * Semantic Intent Verifier
 *
 * Compares what the developer ASKED for vs what the AI GENERATED.
 * Detects when AI output includes unexpected:
 * - Network calls not related to the task
 * - File system operations outside the project
 * - Environment variable access
 * - Obfuscated code blocks
 * - Imports of packages unrelated to the request
 * - External script tags (Rules File Backdoor attack)
 *
 * This catches poisoned .cursorrules / copilot-instructions attacks in real-time.
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface IntentVerificationResult {
  /** Is the generated code semantically aligned with the intent? */
  aligned: boolean;
  /** Confidence score 0-1 */
  confidence: number;
  /** List of suspicious elements found */
  suspiciousElements: SuspiciousElement[];
  /** Summary message */
  summary: string;
}

export interface SuspiciousElement {
  type: 'network' | 'filesystem' | 'env-access' | 'obfuscation' | 'unrelated-import' | 'external-script' | 'crypto' | 'process';
  severity: 'critical' | 'high' | 'medium' | 'low';
  evidence: string;
  line: number | null;
  explanation: string;
}

export interface CodeContext {
  /** The user's prompt/comment/request */
  userIntent: string;
  /** The generated code */
  generatedCode: string;
  /** Language of the code */
  language: string;
  /** File path */
  filePath: string;
}

// ---------------------------------------------------------------------------
// Suspicious Pattern Definitions
// ---------------------------------------------------------------------------

const SUSPICIOUS_PATTERNS: Array<{
  pattern: RegExp;
  type: SuspiciousElement['type'];
  severity: SuspiciousElement['severity'];
  explanation: string;
}> = [
  // External scripts (Rules File Backdoor attack vector)
  {
    pattern: /<script[^>]+src\s*=\s*["']https?:\/\/(?!(?:cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|code\.jquery\.com))[^"']+["'][^>]*>/gi,
    type: 'external-script',
    severity: 'critical',
    explanation: 'External script tag from non-CDN domain — potential Rules File Backdoor attack',
  },
  {
    pattern: /<iframe[^>]+src\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gi,
    type: 'external-script',
    severity: 'critical',
    explanation: 'Iframe embedding external content — potential clickjacking or data exfiltration',
  },

  // Network calls to suspicious domains
  {
    pattern: /(?:fetch|axios|http\.get|https\.get|request|got)\s*\(\s*["'`]https?:\/\/(?!(?:api\.|localhost|127\.0\.0\.1))[^"'`]+["'`]/gi,
    type: 'network',
    severity: 'high',
    explanation: 'Network request to external URL — verify this is expected',
  },
  {
    pattern: /new\s+WebSocket\s*\(\s*["'`]wss?:\/\/[^"'`]+["'`]/gi,
    type: 'network',
    severity: 'high',
    explanation: 'WebSocket connection to external server',
  },

  // Environment variable access (credential theft)
  {
    pattern: /process\.env\s*[[.]\s*["']?(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AWS_|GITHUB_TOKEN|NPM_TOKEN|DATABASE_URL)/gi,
    type: 'env-access',
    severity: 'critical',
    explanation: 'Accesses sensitive environment variable — potential credential theft',
  },

  // File system operations outside project
  {
    pattern: /(?:fs\.(?:readFile|writeFile|appendFile|unlink|rmdir)|readFileSync|writeFileSync)\s*\(\s*["'`](?:\/etc\/|\/usr\/|\/tmp\/|~\/|%APPDATA%|%USERPROFILE%|C:\\Windows)/gi,
    type: 'filesystem',
    severity: 'critical',
    explanation: 'File operation outside project directory — potential persistence or data theft',
  },
  {
    pattern: /(?:fs\.(?:readFile|readFileSync))\s*\(\s*["'`](?:~\/\.ssh|~\/\.aws|~\/\.npmrc|~\/\.env|~\/\.gitconfig)/gi,
    type: 'filesystem',
    severity: 'critical',
    explanation: 'Reading sensitive config file — credential theft attempt',
  },

  // Obfuscation patterns
  {
    pattern: /eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(/gi,
    type: 'obfuscation',
    severity: 'critical',
    explanation: 'Executing decoded/obfuscated code — hidden payload',
  },
  {
    pattern: /new\s+Function\s*\(\s*["'`][^"'`]{50,}/gi,
    type: 'obfuscation',
    severity: 'critical',
    explanation: 'Dynamic function creation with long string — obfuscated code',
  },
  {
    pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/gi,
    type: 'obfuscation',
    severity: 'high',
    explanation: 'Hex-encoded string — potentially obfuscated payload',
  },
  {
    pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){10,}/gi,
    type: 'obfuscation',
    severity: 'high',
    explanation: 'String built from char codes — obfuscation pattern',
  },

  // Process spawning
  {
    pattern: /(?:child_process|exec|execSync|spawn|spawnSync)\s*\(\s*["'`](?:curl|wget|powershell|cmd|bash|sh)\s/gi,
    type: 'process',
    severity: 'critical',
    explanation: 'Spawning shell process — arbitrary command execution',
  },

  // Cryptocurrency operations (unexpected in most contexts)
  {
    pattern: /(?:bitcoin|ethereum|crypto|wallet|miner|blockchain|web3\.eth|ethers\.)/gi,
    type: 'crypto',
    severity: 'medium',
    explanation: 'Cryptocurrency-related code — verify this is expected',
  },
];

// Keywords that indicate specific intents
const INTENT_KEYWORDS: Record<string, string[]> = {
  'http-server': ['http', 'server', 'express', 'fastify', 'koa', 'api', 'rest', 'endpoint'],
  'file-io': ['file', 'read', 'write', 'fs', 'path', 'directory', 'folder'],
  'database': ['database', 'db', 'sql', 'mongo', 'postgres', 'mysql', 'redis', 'query'],
  'auth': ['auth', 'login', 'password', 'token', 'jwt', 'session', 'oauth'],
  'ui': ['button', 'form', 'input', 'component', 'render', 'display', 'ui', 'frontend'],
  'test': ['test', 'spec', 'mock', 'assert', 'expect', 'jest', 'mocha'],
  'crypto': ['encrypt', 'decrypt', 'hash', 'crypto', 'cipher', 'sign', 'verify'],
};

// ---------------------------------------------------------------------------
// Intent Verifier Class
// ---------------------------------------------------------------------------

export class IntentVerifier {
  private llmEnabled: boolean = false;

  constructor() {
    this.llmEnabled = typeof vscode.lm !== 'undefined';
  }

  /**
   * Verify that generated code aligns with the user's intent.
   */
  async verify(context: CodeContext): Promise<IntentVerificationResult> {
    const suspiciousElements: SuspiciousElement[] = [];

    // Step 1: Pattern-based detection (fast, deterministic)
    const patternResults = this.detectSuspiciousPatterns(context.generatedCode);
    suspiciousElements.push(...patternResults);

    // Step 2: Intent mismatch detection
    const intentMismatches = this.detectIntentMismatches(context);
    suspiciousElements.push(...intentMismatches);

    // Step 3: Unrelated import detection
    const unrelatedImports = this.detectUnrelatedImports(context);
    suspiciousElements.push(...unrelatedImports);

    // Step 4: Optional LLM-based semantic analysis (if available and needed)
    if (this.llmEnabled && suspiciousElements.length > 0) {
      // LLM can provide better explanations, but we don't rely on it for detection
      // Detection is deterministic; LLM is advisory
    }

    // Calculate alignment score
    const criticalCount = suspiciousElements.filter(e => e.severity === 'critical').length;
    const highCount = suspiciousElements.filter(e => e.severity === 'high').length;
    const mediumCount = suspiciousElements.filter(e => e.severity === 'medium').length;

    const aligned = criticalCount === 0 && highCount === 0;
    const confidence = Math.max(0, 1 - (criticalCount * 0.3 + highCount * 0.15 + mediumCount * 0.05));

    let summary = '';
    if (aligned) {
      summary = 'Generated code appears aligned with intent.';
    } else if (criticalCount > 0) {
      summary = `⚠️ CRITICAL: Generated code contains ${criticalCount} suspicious element(s) that may indicate a Rules File Backdoor attack or compromised AI output.`;
    } else {
      summary = `Generated code contains ${highCount + mediumCount} element(s) that may not align with your request. Please review.`;
    }

    return {
      aligned,
      confidence,
      suspiciousElements,
      summary,
    };
  }

  /**
   * Quick check for obvious attacks (fast path).
   */
  quickCheck(code: string): { suspicious: boolean; reason: string | null } {
    // Check for the most critical patterns only
    const criticalPatterns = SUSPICIOUS_PATTERNS.filter(p => p.severity === 'critical');

    for (const { pattern, explanation } of criticalPatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(code)) {
        return { suspicious: true, reason: explanation };
      }
    }

    return { suspicious: false, reason: null };
  }

  // -------------------------------------------------------------------------
  // Private detection methods
  // -------------------------------------------------------------------------

  private detectSuspiciousPatterns(code: string): SuspiciousElement[] {
    const elements: SuspiciousElement[] = [];
    const lines = code.split('\n');

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      for (const { pattern, type, severity, explanation } of SUSPICIOUS_PATTERNS) {
        pattern.lastIndex = 0;
        const match = pattern.exec(line);
        if (match) {
          elements.push({
            type,
            severity,
            evidence: match[0].substring(0, 100),
            line: lineIdx + 1,
            explanation,
          });
        }
      }
    }

    return elements;
  }

  private detectIntentMismatches(context: CodeContext): SuspiciousElement[] {
    const elements: SuspiciousElement[] = [];
    const intentLower = context.userIntent.toLowerCase();
    const codeLower = context.generatedCode.toLowerCase();

    // Detect if code contains crypto operations when intent doesn't mention crypto
    const intentCategories = this.categorizeIntent(intentLower);

    if (!intentCategories.includes('crypto') && /(?:bitcoin|ethereum|web3|miner|blockchain)/i.test(codeLower)) {
      elements.push({
        type: 'crypto',
        severity: 'high',
        evidence: 'Cryptocurrency-related code',
        line: null,
        explanation: 'Generated code contains cryptocurrency operations not mentioned in your request',
      });
    }

    // Detect network calls when intent is purely UI/local
    if (intentCategories.includes('ui') && !intentCategories.includes('http-server') && !intentCategories.includes('database')) {
      if (/(?:fetch|axios|http\.get|https\.get)\s*\(/i.test(codeLower)) {
        elements.push({
          type: 'network',
          severity: 'medium',
          evidence: 'Network request in UI code',
          line: null,
          explanation: 'Generated code makes network requests, but your request appeared to be UI-only',
        });
      }
    }

    return elements;
  }

  private detectUnrelatedImports(context: CodeContext): SuspiciousElement[] {
    const elements: SuspiciousElement[] = [];
    const intentLower = context.userIntent.toLowerCase();

    // Extract imports from code
    const importPattern = /(?:import\s+.*?from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))/gi;
    const imports: string[] = [];
    let match;

    while ((match = importPattern.exec(context.generatedCode)) !== null) {
      imports.push(match[1] || match[2]);
    }

    // Check for suspicious imports
    const suspiciousImportPatterns = [
      { pattern: /^https?:\/\//, reason: 'Remote URL import' },
      { pattern: /crypto-?miner|coinhive|cryptonight/i, reason: 'Cryptocurrency miner' },
      { pattern: /keylogger|spyware|trojan/i, reason: 'Malware-related package name' },
    ];

    for (const imp of imports) {
      for (const { pattern, reason } of suspiciousImportPatterns) {
        if (pattern.test(imp)) {
          elements.push({
            type: 'unrelated-import',
            severity: 'critical',
            evidence: imp,
            line: null,
            explanation: `Suspicious import: ${reason}`,
          });
        }
      }
    }

    return elements;
  }

  private categorizeIntent(intent: string): string[] {
    const categories: string[] = [];

    for (const [category, keywords] of Object.entries(INTENT_KEYWORDS)) {
      if (keywords.some(kw => intent.includes(kw))) {
        categories.push(category);
      }
    }

    return categories;
  }
}

// ---------------------------------------------------------------------------
// Integration with VS Code inline completions
// ---------------------------------------------------------------------------

export class IntentVerifierCompletionMiddleware {
  private verifier: IntentVerifier;
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.verifier = new IntentVerifier();
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard-intent');
  }

  /**
   * Analyze a code change and report if it looks suspicious.
   */
  async analyzeChange(
    document: vscode.TextDocument,
    change: vscode.TextDocumentContentChangeEvent,
    recentComment: string | null,
  ): Promise<void> {
    // Only analyze substantial changes (likely AI-generated)
    if (change.text.length < 50) {
      return;
    }

    // Quick check first
    const quick = this.verifier.quickCheck(change.text);
    if (!quick.suspicious) {
      return;
    }

    // Full verification
    const result = await this.verifier.verify({
      userIntent: recentComment || 'unknown',
      generatedCode: change.text,
      language: document.languageId,
      filePath: document.uri.fsPath,
    });

    if (!result.aligned) {
      // Show warning
      const diagnostics: vscode.Diagnostic[] = [];

      for (const element of result.suspiciousElements) {
        const range = element.line
          ? new vscode.Range(change.range.start.line + element.line - 1, 0, change.range.start.line + element.line - 1, 100)
          : change.range;

        const severity = element.severity === 'critical'
          ? vscode.DiagnosticSeverity.Error
          : element.severity === 'high'
            ? vscode.DiagnosticSeverity.Warning
            : vscode.DiagnosticSeverity.Information;

        diagnostics.push(new vscode.Diagnostic(
          range,
          `[CodeGuard Intent] ${element.explanation}`,
          severity,
        ));
      }

      this.diagnosticCollection.set(document.uri, diagnostics);

      // Show notification for critical issues
      if (result.suspiciousElements.some(e => e.severity === 'critical')) {
        vscode.window.showWarningMessage(
          `⚠️ CodeGuard: Generated code may contain malicious elements. ${result.summary}`,
          'Show Details',
        ).then(action => {
          if (action === 'Show Details') {
            vscode.commands.executeCommand('workbench.action.problems.focus');
          }
        });
      }
    }
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
  }
}
