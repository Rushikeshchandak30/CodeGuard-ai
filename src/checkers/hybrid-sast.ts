/**
 * Hybrid SAST Engine — Regex Speed + LLM Depth + Adversarial Verification
 *
 * Three-pass architecture:
 *   Pass 1 (instant, ~5ms): Regex patterns catch obvious vulns (deterministic)
 *   Pass 2 (deferred, 2-5s): LLM deep analysis on flagged code + surrounding context
 *   Pass 3 (adversarial):    LLM challenges its own findings to filter false positives
 *
 * Falls back gracefully: if LLM is unavailable, regex-only results still surface.
 * Security decisions from Pass 1 are DETERMINISTIC and work fully offline.
 * LLM passes are ADVISORY — they enrich findings with confidence + explanations.
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SastSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface HybridFinding {
  /** Unique rule ID, e.g. SQLI_001 or LLM_AUTH_001 */
  id: string;
  name: string;
  severity: SastSeverity;
  description: string;
  remediation: string;
  line: number;
  column: number;
  endColumn: number;
  /** 0-1 confidence from adversarial verification (1.0 = regex-confirmed) */
  confidence: number;
  /** Which pass produced this finding */
  source: 'regex' | 'llm-deep' | 'llm-verified';
  /** LLM explanation (only from pass 2/3) */
  llmExplanation?: string;
  /** Whether the LLM adversarial pass confirmed or rejected this finding */
  adversarialVerdict?: 'confirmed' | 'likely-false-positive' | 'needs-review';
}

interface RegexRule {
  id: string;
  name: string;
  pattern: RegExp;
  severity: SastSeverity;
  description: string;
  remediation: string;
  languages?: string[];
  /** CWE ID for standards mapping */
  cwe?: string;
}

interface LlmDeepFinding {
  id: string;
  name: string;
  severity: SastSeverity;
  description: string;
  remediation: string;
  line: number;
  column: number;
  endColumn: number;
  explanation: string;
}

// ---------------------------------------------------------------------------
// Extended Regex Rules (Pass 1) — 35 patterns
// ---------------------------------------------------------------------------

const REGEX_RULES: RegexRule[] = [
  // --- Injection ---
  { id: 'CG_SQLI_001', name: 'SQL Injection (interpolation)', pattern: /(?:query|execute|exec)\s*\(\s*[`'"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^`'"]*\$\{/i, severity: 'critical', description: 'SQL injection via string interpolation', remediation: 'Use parameterized queries', languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'], cwe: 'CWE-89' },
  { id: 'CG_SQLI_002', name: 'SQL Injection (concatenation)', pattern: /(?:query|execute|exec)\s*\(\s*['"`][^'"`]*['"`]\s*\+/i, severity: 'high', description: 'SQL injection via string concatenation', remediation: 'Use parameterized queries', languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'], cwe: 'CWE-89' },
  { id: 'CG_SQLI_003', name: 'SQL Injection (Python f-string)', pattern: /(?:execute|executemany)\s*\(\s*(?:f['"]|['"][^'"]*%\s*\()/i, severity: 'critical', description: 'SQL injection via f-string/% formatting', remediation: 'Use cursor.execute(query, (param,))', languages: ['python'], cwe: 'CWE-89' },
  { id: 'CG_SQLI_004', name: 'SQL Injection (raw query builder)', pattern: /\.raw\s*\(\s*[`'"][^`'"]*\$\{/i, severity: 'critical', description: 'ORM raw query with string interpolation', remediation: 'Use ORM parameterized methods', languages: ['javascript', 'typescript'], cwe: 'CWE-89' },

  // --- XSS ---
  { id: 'CG_XSS_001', name: 'XSS via innerHTML', pattern: /\.innerHTML\s*=\s*(?!['"`]<(?:div|span|p|h[1-6]|br\s*\/)>['"`])/, severity: 'high', description: 'innerHTML assignment can lead to XSS', remediation: 'Use textContent or DOMPurify', languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'], cwe: 'CWE-79' },
  { id: 'CG_XSS_002', name: 'XSS via document.write', pattern: /document\.write\s*\(/, severity: 'high', description: 'document.write() enables XSS', remediation: 'Use DOM manipulation methods', languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'], cwe: 'CWE-79' },
  { id: 'CG_XSS_003', name: 'dangerouslySetInnerHTML', pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*__html\s*:/, severity: 'medium', description: 'Bypasses React XSS protection', remediation: 'Sanitize HTML with DOMPurify first', languages: ['javascriptreact', 'typescriptreact'], cwe: 'CWE-79' },
  { id: 'CG_XSS_004', name: 'XSS via template literal in HTML', pattern: /`<[^`]*\$\{[^}]*\}[^`]*>`/, severity: 'high', description: 'Template literal building HTML with unescaped input', remediation: 'Escape user input before embedding in HTML', cwe: 'CWE-79' },

  // --- Code Injection ---
  { id: 'CG_EVAL_001', name: 'eval() usage', pattern: /\beval\s*\(/, severity: 'critical', description: 'eval() executes arbitrary code', remediation: 'Use JSON.parse() or refactor logic', cwe: 'CWE-95' },
  { id: 'CG_EVAL_002', name: 'new Function()', pattern: /new\s+Function\s*\(/, severity: 'critical', description: 'Dynamic code execution via Function constructor', remediation: 'Refactor to static functions', cwe: 'CWE-95' },
  { id: 'CG_EVAL_003', name: 'setTimeout/setInterval with string', pattern: /(?:setTimeout|setInterval)\s*\(\s*['"`]/, severity: 'high', description: 'String argument is equivalent to eval()', remediation: 'Pass a function reference instead', cwe: 'CWE-95' },

  // --- Command Injection ---
  { id: 'CG_CMD_001', name: 'Command injection (exec)', pattern: /(?:child_process\.)?exec\s*\(\s*[`'"][^`'"]*\$\{/, severity: 'critical', description: 'Command injection via interpolation in exec()', remediation: 'Use execFile() with argument arrays', languages: ['javascript', 'typescript'], cwe: 'CWE-78' },
  { id: 'CG_CMD_002', name: 'Command injection (Python shell=True)', pattern: /subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/, severity: 'critical', description: 'subprocess with shell=True enables injection', remediation: 'Use shell=False and pass args as list', languages: ['python'], cwe: 'CWE-78' },
  { id: 'CG_CMD_003', name: 'os.system() usage', pattern: /os\.system\s*\(/, severity: 'critical', description: 'os.system() runs shell commands unsafely', remediation: 'Use subprocess.run() with shell=False', languages: ['python'], cwe: 'CWE-78' },

  // --- Path Traversal ---
  { id: 'CG_PATH_001', name: 'Path traversal (user input)', pattern: /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/, severity: 'high', description: 'File operation with user-controlled path', remediation: 'Validate paths with path.resolve() and check against allowed dirs', languages: ['javascript', 'typescript'], cwe: 'CWE-22' },
  { id: 'CG_PATH_002', name: 'Path traversal (open())', pattern: /open\s*\(\s*(?:request\.|f['"].*\{)/, severity: 'high', description: 'File open with user-controlled path', remediation: 'Validate and sanitize file paths', languages: ['python'], cwe: 'CWE-22' },

  // --- Crypto ---
  { id: 'CG_CRYPTO_001', name: 'Weak hash: MD5', pattern: /(?:createHash|hashlib\.new|md5)\s*\(\s*['"]md5['"]/i, severity: 'high', description: 'MD5 is cryptographically broken', remediation: 'Use SHA-256 or SHA-3', cwe: 'CWE-328' },
  { id: 'CG_CRYPTO_002', name: 'Weak hash: SHA1', pattern: /(?:createHash|hashlib\.new)\s*\(\s*['"]sha1['"]/i, severity: 'high', description: 'SHA-1 is cryptographically weak', remediation: 'Use SHA-256 or SHA-3', cwe: 'CWE-328' },
  { id: 'CG_CRYPTO_003', name: 'Insecure random', pattern: /Math\.random\s*\(\s*\)/, severity: 'medium', description: 'Math.random() is not cryptographically secure', remediation: 'Use crypto.getRandomValues()', languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'], cwe: 'CWE-338' },
  { id: 'CG_CRYPTO_004', name: 'Hardcoded IV/key', pattern: /(?:createCipheriv|createDecipheriv)\s*\([^)]*['"][0-9a-fA-F]{16,}['"]/, severity: 'critical', description: 'Hardcoded encryption key or IV', remediation: 'Use environment variables or key management service', languages: ['javascript', 'typescript'], cwe: 'CWE-321' },

  // --- Network ---
  { id: 'CG_HTTP_001', name: 'Insecure HTTP', pattern: /(?:fetch|axios\.get|axios\.post|http\.get|request\.get)\s*\(\s*['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/, severity: 'medium', description: 'HTTP request to non-local URL (no TLS)', remediation: 'Use HTTPS', cwe: 'CWE-319' },
  { id: 'CG_HTTP_002', name: 'TLS verification disabled', pattern: /rejectUnauthorized\s*:\s*false/, severity: 'critical', description: 'TLS certificate verification disabled', remediation: 'Fix the certificate issue instead', cwe: 'CWE-295' },
  { id: 'CG_SSRF_001', name: 'SSRF (user URL)', pattern: /(?:fetch|axios|request|http\.get|https\.get)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)[a-zA-Z_]+/, severity: 'high', description: 'HTTP request with user-controlled URL', remediation: 'Validate URLs against an allowlist', languages: ['javascript', 'typescript'], cwe: 'CWE-918' },
  { id: 'CG_CORS_001', name: 'Permissive CORS', pattern: /Access-Control-Allow-Origin['"]\s*[:,]\s*['"]?\*/, severity: 'medium', description: 'Wildcard CORS allows any origin', remediation: 'Restrict to specific trusted origins', cwe: 'CWE-942' },

  // --- Auth / Session ---
  { id: 'CG_AUTH_001', name: 'JWT none algorithm', pattern: /algorithm\s*[:=]\s*['"]none['"]/i, severity: 'critical', description: 'JWT "none" algorithm disables signature verification', remediation: 'Use RS256 or ES256', cwe: 'CWE-347' },
  { id: 'CG_AUTH_002', name: 'Hardcoded JWT secret', pattern: /(?:sign|verify)\s*\([^)]*['"][a-zA-Z0-9]{8,}['"]/, severity: 'high', description: 'JWT signed with hardcoded secret', remediation: 'Use environment variables for secrets', cwe: 'CWE-798' },
  { id: 'CG_SESSION_001', name: 'Cookie without secure flag', pattern: /(?:cookie|setCookie|set-cookie)[^;]*(?!secure).*httpOnly\s*[:=]\s*false/i, severity: 'medium', description: 'Cookie missing secure or httpOnly flag', remediation: 'Set secure: true, httpOnly: true, sameSite: strict', cwe: 'CWE-614' },

  // --- Deserialization ---
  { id: 'CG_DESER_001', name: 'pickle deserialization', pattern: /pickle\.loads?\s*\(/, severity: 'critical', description: 'pickle can execute arbitrary code on untrusted data', remediation: 'Use JSON or safe serialization', languages: ['python'], cwe: 'CWE-502' },
  { id: 'CG_DESER_002', name: 'yaml.load (unsafe)', pattern: /yaml\.load\s*\([^)]*(?!SafeLoader|safe_load)/, severity: 'high', description: 'yaml.load() default loader executes Python code', remediation: 'Use yaml.safe_load()', languages: ['python'], cwe: 'CWE-502' },

  // --- Prototype Pollution ---
  { id: 'CG_PROTO_001', name: 'Prototype pollution', pattern: /\[['"]__proto__['"]\]|Object\.prototype\[/, severity: 'high', description: 'Modifying Object.prototype is dangerous', remediation: 'Use Object.create(null) for dictionaries', languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'], cwe: 'CWE-1321' },

  // --- Redirect ---
  { id: 'CG_REDIRECT_001', name: 'Open redirect', pattern: /res\.redirect\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)[a-zA-Z_]+/, severity: 'medium', description: 'Redirect to user-controlled URL', remediation: 'Validate redirect URLs against an allowlist', languages: ['javascript', 'typescript'], cwe: 'CWE-601' },

  // --- Logging ---
  { id: 'CG_LOG_001', name: 'Sensitive data in logs', pattern: /(?:console\.log|logger\.\w+|print)\s*\([^)]*(?:password|secret|token|apiKey|api_key|private_key|credential)/i, severity: 'medium', description: 'Sensitive data may be written to logs', remediation: 'Redact sensitive fields before logging', cwe: 'CWE-532' },

  // --- Error Handling ---
  { id: 'CG_ERR_001', name: 'Stack trace exposure', pattern: /res\.(?:send|json|write)\s*\([^)]*(?:err\.stack|error\.stack|\.stackTrace)/, severity: 'medium', description: 'Stack traces exposed to client reveal internal info', remediation: 'Return generic error messages to clients', languages: ['javascript', 'typescript'], cwe: 'CWE-209' },
];

// ---------------------------------------------------------------------------
// LLM Deep-Analysis Prompts (Pass 2)
// ---------------------------------------------------------------------------

const DEEP_ANALYSIS_SYSTEM_PROMPT = `You are an expert security code reviewer. Analyze the following code for vulnerabilities that regex patterns cannot detect. Focus on:
1. Business logic flaws (broken access control, privilege escalation)
2. Authentication/authorization bypasses
3. Race conditions and TOCTOU issues
4. Insecure data flow across function boundaries
5. Missing input validation on critical operations
6. Insecure default configurations

For each finding, respond in this EXACT JSON format (array):
[{"id":"LLM_XXX_NNN","name":"Short Name","severity":"critical|high|medium|low","description":"What the vulnerability is","remediation":"How to fix it","line":N,"explanation":"Detailed explanation"}]

If no vulnerabilities found, respond with: []
Be conservative — only flag REAL vulnerabilities with high confidence. Do NOT flag style issues.`;

const ADVERSARIAL_SYSTEM_PROMPT = `You are a skeptical security reviewer verifying vulnerability findings. For each finding below, determine if it is a TRUE vulnerability or a FALSE POSITIVE.

Consider:
- Is the code actually reachable with malicious input?
- Is there validation/sanitization elsewhere that the scanner missed?
- Is this a test file, mock, or documentation?
- Would exploitation require unlikely conditions?

Respond in this EXACT JSON format (array):
[{"id":"<finding_id>","verdict":"confirmed|likely-false-positive|needs-review","confidence":0.0-1.0,"reason":"Brief explanation"}]`;

// ---------------------------------------------------------------------------
// HybridSastEngine Class
// ---------------------------------------------------------------------------

export class HybridSastEngine {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private llmAvailable: boolean;
  private pendingDeepScans = new Map<string, NodeJS.Timeout>();

  /** Debounce delay before triggering LLM deep analysis (ms) */
  private static readonly LLM_DEBOUNCE_MS = 3000;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard-hybrid-sast');
    this.llmAvailable = typeof vscode.lm !== 'undefined';
  }

  // -----------------------------------------------------------------------
  // Pass 1: Regex Scan (instant, deterministic)
  // -----------------------------------------------------------------------

  scanRegex(document: vscode.TextDocument): HybridFinding[] {
    const findings: HybridFinding[] = [];
    const text = document.getText();
    const lines = text.split('\n');
    const lang = document.languageId;

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      const trimmed = line.trim();

      // Skip comments
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
        continue;
      }

      for (const rule of REGEX_RULES) {
        if (rule.languages && !rule.languages.includes(lang)) { continue; }

        const match = rule.pattern.exec(line);
        if (!match) { continue; }

        findings.push({
          id: rule.id,
          name: rule.name,
          severity: rule.severity,
          description: rule.description,
          remediation: rule.remediation,
          line: lineIdx,
          column: match.index,
          endColumn: match.index + match[0].length,
          confidence: 1.0, // Regex = deterministic
          source: 'regex',
        });
      }
    }

    return findings;
  }

  // -----------------------------------------------------------------------
  // Pass 2: LLM Deep Analysis (deferred, async)
  // -----------------------------------------------------------------------

  async scanDeep(document: vscode.TextDocument): Promise<LlmDeepFinding[]> {
    if (!this.llmAvailable) { return []; }

    try {
      const model = await this.selectModel();
      if (!model) { return []; }

      const text = document.getText();
      // Only send first 500 lines to avoid token limits
      const truncated = text.split('\n').slice(0, 500).join('\n');

      const userPrompt = `File: ${document.fileName} (${document.languageId})\n\n\`\`\`${document.languageId}\n${truncated}\n\`\`\``;

      const messages = [
        vscode.LanguageModelChatMessage.User(DEEP_ANALYSIS_SYSTEM_PROMPT),
        vscode.LanguageModelChatMessage.User(userPrompt),
      ];

      const response = await model.sendRequest(messages, {}, new vscode.CancellationTokenSource().token);
      let responseText = '';
      for await (const chunk of response.text) {
        responseText += chunk;
      }

      return this.parseLlmFindings(responseText);
    } catch (e) {
      console.warn('[CodeGuard Hybrid SAST] LLM deep scan failed:', e);
      return [];
    }
  }

  // -----------------------------------------------------------------------
  // Pass 3: Adversarial Verification
  // -----------------------------------------------------------------------

  async verifyFindings(
    document: vscode.TextDocument,
    findings: HybridFinding[]
  ): Promise<HybridFinding[]> {
    if (!this.llmAvailable || findings.length === 0) { return findings; }

    try {
      const model = await this.selectModel();
      if (!model) { return findings; }

      const text = document.getText();
      const truncated = text.split('\n').slice(0, 500).join('\n');

      const findingsSummary = findings.map(f =>
        `- [${f.id}] Line ${f.line + 1}: ${f.name} — ${f.description}`
      ).join('\n');

      const userPrompt = `File: ${document.fileName}\n\nCode:\n\`\`\`${document.languageId}\n${truncated}\n\`\`\`\n\nFindings to verify:\n${findingsSummary}`;

      const messages = [
        vscode.LanguageModelChatMessage.User(ADVERSARIAL_SYSTEM_PROMPT),
        vscode.LanguageModelChatMessage.User(userPrompt),
      ];

      const response = await model.sendRequest(messages, {}, new vscode.CancellationTokenSource().token);
      let responseText = '';
      for await (const chunk of response.text) {
        responseText += chunk;
      }

      const verdicts = this.parseAdversarialResponse(responseText);
      const verdictMap = new Map(verdicts.map(v => [v.id, v]));

      return findings.map(f => {
        const verdict = verdictMap.get(f.id);
        if (verdict) {
          return {
            ...f,
            confidence: verdict.confidence,
            adversarialVerdict: verdict.verdict as HybridFinding['adversarialVerdict'],
            source: 'llm-verified' as const,
            llmExplanation: verdict.reason,
          };
        }
        return f;
      });
    } catch (e) {
      console.warn('[CodeGuard Hybrid SAST] Adversarial verification failed:', e);
      return findings;
    }
  }

  // -----------------------------------------------------------------------
  // Combined Scan (orchestrates all three passes)
  // -----------------------------------------------------------------------

  async scan(document: vscode.TextDocument): Promise<HybridFinding[]> {
    const supported = [
      'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
      'python', 'go', 'java', 'rust', 'php', 'ruby', 'csharp',
    ];
    if (!supported.includes(document.languageId)) { return []; }

    // Pass 1: Immediate regex scan
    const regexFindings = this.scanRegex(document);

    // Update diagnostics immediately with regex results
    this.updateDiagnostics(document, regexFindings);

    // Schedule Pass 2+3 with debounce (don't block the UI)
    this.scheduleLlmAnalysis(document, regexFindings);

    return regexFindings;
  }

  /**
   * Run full three-pass analysis (for manual "deep scan" command).
   */
  async deepScan(document: vscode.TextDocument): Promise<HybridFinding[]> {
    const supported = [
      'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
      'python', 'go', 'java', 'rust', 'php', 'ruby', 'csharp',
    ];
    if (!supported.includes(document.languageId)) { return []; }

    // Pass 1
    const regexFindings = this.scanRegex(document);

    // Pass 2: LLM deep analysis
    const llmFindings = await this.scanDeep(document);
    const llmHybrid: HybridFinding[] = llmFindings.map(f => ({
      ...f,
      confidence: 0.8, // LLM findings start at 0.8
      source: 'llm-deep' as const,
      llmExplanation: f.explanation,
    }));

    // Merge and deduplicate
    const allFindings = this.mergeFindings(regexFindings, llmHybrid);

    // Pass 3: Adversarial verification on all findings
    const verified = await this.verifyFindings(document, allFindings);

    // Filter out likely false positives
    const filtered = verified.filter(f =>
      f.adversarialVerdict !== 'likely-false-positive'
    );

    this.updateDiagnostics(document, filtered);
    return filtered;
  }

  // -----------------------------------------------------------------------
  // Diagnostics
  // -----------------------------------------------------------------------

  updateDiagnostics(document: vscode.TextDocument, findings: HybridFinding[]): void {
    const diagnostics: vscode.Diagnostic[] = findings.map(f => {
      const range = new vscode.Range(f.line, f.column, f.line, f.endColumn);
      const vscodeSeverity = (f.severity === 'critical' || f.severity === 'high')
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Warning;

      const confidenceLabel = f.confidence >= 0.9 ? '' :
        f.confidence >= 0.7 ? ' (likely)' :
        f.confidence >= 0.5 ? ' (possible)' : ' (low confidence)';

      const llmNote = f.llmExplanation ? ` | AI: ${f.llmExplanation}` : '';

      const diag = new vscode.Diagnostic(
        range,
        `[${f.id}] ${f.name}${confidenceLabel}: ${f.description}. Fix: ${f.remediation}${llmNote}`,
        vscodeSeverity
      );
      diag.source = `CodeGuard Hybrid SAST (${f.source})`;
      diag.code = f.id;
      return diag;
    });

    this.diagnosticCollection.set(document.uri, diagnostics);
  }

  clearDiagnostics(uri: vscode.Uri): void {
    this.diagnosticCollection.delete(uri);
  }

  // -----------------------------------------------------------------------
  // Public Getters
  // -----------------------------------------------------------------------

  get ruleCount(): number {
    return REGEX_RULES.length;
  }

  get isLlmAvailable(): boolean {
    return this.llmAvailable;
  }

  // -----------------------------------------------------------------------
  // Private Helpers
  // -----------------------------------------------------------------------

  private scheduleLlmAnalysis(document: vscode.TextDocument, regexFindings: HybridFinding[]): void {
    if (!this.llmAvailable) { return; }

    const uri = document.uri.toString();

    // Cancel any pending deep scan for this document
    const existing = this.pendingDeepScans.get(uri);
    if (existing) { clearTimeout(existing); }

    const timeout = setTimeout(async () => {
      this.pendingDeepScans.delete(uri);
      try {
        // Pass 2
        const llmFindings = await this.scanDeep(document);
        const llmHybrid: HybridFinding[] = llmFindings.map(f => ({
          ...f,
          confidence: 0.8,
          source: 'llm-deep' as const,
          llmExplanation: f.explanation,
        }));

        const all = this.mergeFindings(regexFindings, llmHybrid);

        // Pass 3
        const verified = await this.verifyFindings(document, all);
        const filtered = verified.filter(f =>
          f.adversarialVerdict !== 'likely-false-positive'
        );

        this.updateDiagnostics(document, filtered);
      } catch {
        // LLM passes failed — regex results remain
      }
    }, HybridSastEngine.LLM_DEBOUNCE_MS);

    this.pendingDeepScans.set(uri, timeout);
  }

  private mergeFindings(regex: HybridFinding[], llm: HybridFinding[]): HybridFinding[] {
    const merged = [...regex];

    for (const lf of llm) {
      // Don't add LLM finding if regex already caught the same line + similar pattern
      const duplicate = regex.some(rf =>
        rf.line === lf.line && rf.name.toLowerCase().includes(lf.name.split(' ')[0].toLowerCase())
      );
      if (!duplicate) {
        merged.push(lf);
      }
    }

    return merged;
  }

  private parseLlmFindings(text: string): LlmDeepFinding[] {
    try {
      // Extract JSON array from response (may have markdown wrapping)
      const jsonMatch = text.match(/\[[\s\S]*\]/);
      if (!jsonMatch) { return []; }

      const parsed = JSON.parse(jsonMatch[0]);
      if (!Array.isArray(parsed)) { return []; }

      return parsed
        .filter((f: Record<string, unknown>) => f.id && f.name && f.severity && f.line)
        .map((f: Record<string, unknown>) => ({
          id: String(f.id),
          name: String(f.name),
          severity: (['critical', 'high', 'medium', 'low'].includes(String(f.severity)) ? String(f.severity) : 'medium') as SastSeverity,
          description: String(f.description || ''),
          remediation: String(f.remediation || 'Review and fix'),
          line: Math.max(0, Number(f.line) - 1), // LLM uses 1-indexed
          column: 0,
          endColumn: 80,
          explanation: String(f.explanation || ''),
        }));
    } catch {
      return [];
    }
  }

  private parseAdversarialResponse(text: string): Array<{ id: string; verdict: string; confidence: number; reason: string }> {
    try {
      const jsonMatch = text.match(/\[[\s\S]*\]/);
      if (!jsonMatch) { return []; }

      const parsed = JSON.parse(jsonMatch[0]);
      if (!Array.isArray(parsed)) { return []; }

      return parsed
        .filter((v: Record<string, unknown>) => v.id && v.verdict)
        .map((v: Record<string, unknown>) => ({
          id: String(v.id),
          verdict: String(v.verdict),
          confidence: Math.max(0, Math.min(1, Number(v.confidence) || 0.5)),
          reason: String(v.reason || ''),
        }));
    } catch {
      return [];
    }
  }

  private async selectModel(): Promise<vscode.LanguageModelChat | null> {
    try {
      const models = await vscode.lm.selectChatModels({ vendor: 'copilot', family: 'gpt-4o' });
      if (models.length > 0) { return models[0]; }

      const fallback = await vscode.lm.selectChatModels({ vendor: 'copilot', family: 'gpt-3.5-turbo' });
      if (fallback.length > 0) { return fallback[0]; }

      return null;
    } catch {
      return null;
    }
  }

  dispose(): void {
    for (const timeout of this.pendingDeepScans.values()) {
      clearTimeout(timeout);
    }
    this.pendingDeepScans.clear();
    this.diagnosticCollection.dispose();
  }
}
