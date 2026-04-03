/**
 * Code Vulnerability Checker — AST-based SAST Pattern Detection
 *
 * Scans source code for common vulnerability patterns:
 * - SQL injection
 * - XSS via unsafe DOM manipulation
 * - eval/exec injection
 * - Path traversal
 * - Insecure crypto (MD5, SHA1)
 * - Hardcoded HTTP (no TLS)
 * - SSRF via unvalidated URLs
 * - Unsafe deserialization
 * - Prototype pollution
 * - Command injection
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Vulnerability Pattern Definitions
// ---------------------------------------------------------------------------

interface VulnPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
  languages?: string[];  // if undefined, applies to all
}

const VULN_PATTERNS: VulnPattern[] = [
  // SQL Injection
  {
    id: 'SQLI_001',
    name: 'SQL Injection',
    pattern: /(?:query|execute|exec)\s*\(\s*[`'"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^`'"]*\$\{/i,
    severity: 'critical',
    description: 'Possible SQL injection via string interpolation in query',
    remediation: 'Use parameterized queries or prepared statements',
    languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'],
  },
  {
    id: 'SQLI_002',
    name: 'SQL Injection (concatenation)',
    pattern: /(?:query|execute|exec)\s*\(\s*['"`][^'"`]*['"`]\s*\+/i,
    severity: 'high',
    description: 'Possible SQL injection via string concatenation in query',
    remediation: 'Use parameterized queries or prepared statements',
    languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'],
  },
  {
    id: 'SQLI_003',
    name: 'SQL Injection (Python)',
    pattern: /(?:execute|executemany)\s*\(\s*(?:f['"]|['"][^'"]*%\s*\()/i,
    severity: 'critical',
    description: 'Possible SQL injection via f-string or % formatting in query',
    remediation: 'Use parameterized queries: cursor.execute(query, (param,))',
    languages: ['python'],
  },

  // XSS
  {
    id: 'XSS_001',
    name: 'XSS via innerHTML',
    pattern: /\.innerHTML\s*=\s*(?!['"`]<(?:div|span|p|h[1-6]|br\s*\/)>['"`])/,
    severity: 'high',
    description: 'Assigning to innerHTML can lead to XSS if value contains user input',
    remediation: 'Use textContent instead, or sanitize with DOMPurify',
    languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'],
  },
  {
    id: 'XSS_002',
    name: 'XSS via outerHTML',
    pattern: /\.outerHTML\s*=/,
    severity: 'high',
    description: 'Assigning to outerHTML can lead to XSS',
    remediation: 'Use safe DOM manipulation methods or DOMPurify',
    languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'],
  },
  {
    id: 'XSS_003',
    name: 'XSS via document.write',
    pattern: /document\.write\s*\(/,
    severity: 'high',
    description: 'document.write() can lead to XSS and blocks page rendering',
    remediation: 'Use DOM manipulation methods instead',
    languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'],
  },
  {
    id: 'XSS_004',
    name: 'Dangerous dangerouslySetInnerHTML',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{[^}]*__html\s*:/,
    severity: 'medium',
    description: 'dangerouslySetInnerHTML bypasses React XSS protection',
    remediation: 'Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML',
    languages: ['javascriptreact', 'typescriptreact'],
  },

  // eval / exec injection
  {
    id: 'EVAL_001',
    name: 'eval() usage',
    pattern: /\beval\s*\(/,
    severity: 'critical',
    description: 'eval() executes arbitrary code and is a major security risk',
    remediation: 'Avoid eval(). Use JSON.parse() for JSON, or refactor logic',
  },
  {
    id: 'EVAL_002',
    name: 'new Function() usage',
    pattern: /new\s+Function\s*\(/,
    severity: 'critical',
    description: 'new Function() is equivalent to eval() and executes arbitrary code',
    remediation: 'Avoid dynamic code execution. Refactor to use static functions',
  },
  {
    id: 'EVAL_003',
    name: 'setTimeout/setInterval with string',
    pattern: /(?:setTimeout|setInterval)\s*\(\s*['"`]/,
    severity: 'high',
    description: 'Passing a string to setTimeout/setInterval is equivalent to eval()',
    remediation: 'Pass a function reference instead: setTimeout(() => {...}, delay)',
  },

  // Command Injection
  {
    id: 'CMD_001',
    name: 'Command Injection via exec',
    pattern: /(?:child_process\.)?exec\s*\(\s*[`'"][^`'"]*\$\{/,
    severity: 'critical',
    description: 'Possible command injection via string interpolation in exec()',
    remediation: 'Use execFile() with argument arrays, or validate/sanitize input',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CMD_002',
    name: 'Command Injection via execSync',
    pattern: /execSync\s*\(\s*[`'"][^`'"]*\$\{/,
    severity: 'critical',
    description: 'Possible command injection via string interpolation in execSync()',
    remediation: 'Use execFileSync() with argument arrays',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CMD_003',
    name: 'Command Injection (Python subprocess)',
    pattern: /subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/,
    severity: 'critical',
    description: 'subprocess with shell=True enables command injection',
    remediation: 'Use shell=False and pass arguments as a list',
    languages: ['python'],
  },

  // Path Traversal
  {
    id: 'PATH_001',
    name: 'Path Traversal',
    pattern: /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/,
    severity: 'high',
    description: 'File system operation with user-controlled path — possible path traversal',
    remediation: 'Validate and sanitize file paths. Use path.resolve() and check against allowed directories',
    languages: ['javascript', 'typescript'],
  },

  // Insecure Crypto
  {
    id: 'CRYPTO_001',
    name: 'Weak Hash: MD5',
    pattern: /(?:createHash|hashlib\.new|md5)\s*\(\s*['"]md5['"]/i,
    severity: 'high',
    description: 'MD5 is cryptographically broken and should not be used for security',
    remediation: 'Use SHA-256 or SHA-3 for security purposes',
  },
  {
    id: 'CRYPTO_002',
    name: 'Weak Hash: SHA1',
    pattern: /(?:createHash|hashlib\.new)\s*\(\s*['"]sha1['"]/i,
    severity: 'high',
    description: 'SHA-1 is cryptographically weak and should not be used for security',
    remediation: 'Use SHA-256 or SHA-3 for security purposes',
  },
  {
    id: 'CRYPTO_003',
    name: 'Insecure Random',
    pattern: /Math\.random\s*\(\s*\)/,
    severity: 'medium',
    description: 'Math.random() is not cryptographically secure',
    remediation: 'Use crypto.getRandomValues() or crypto.randomBytes() for security-sensitive randomness',
    languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'],
  },

  // Insecure HTTP
  {
    id: 'HTTP_001',
    name: 'Insecure HTTP URL',
    pattern: /(?:fetch|axios\.get|axios\.post|http\.get|request\.get)\s*\(\s*['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/,
    severity: 'medium',
    description: 'HTTP request to non-local URL — data transmitted in plaintext',
    remediation: 'Use HTTPS for all external requests',
  },
  {
    id: 'HTTP_002',
    name: 'TLS Verification Disabled',
    pattern: /rejectUnauthorized\s*:\s*false/,
    severity: 'critical',
    description: 'TLS certificate verification is disabled — vulnerable to MITM attacks',
    remediation: 'Remove rejectUnauthorized: false. Fix the certificate issue instead',
  },

  // Prototype Pollution
  {
    id: 'PROTO_001',
    name: 'Prototype Pollution',
    pattern: /\[['"]__proto__['"]\]|Object\.prototype\[/,
    severity: 'high',
    description: 'Possible prototype pollution — modifying Object.prototype is dangerous',
    remediation: 'Use Object.create(null) for safe dictionaries, validate merge inputs',
    languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'],
  },

  // Unsafe Deserialization
  {
    id: 'DESER_001',
    name: 'Unsafe Deserialization (pickle)',
    pattern: /pickle\.loads?\s*\(/,
    severity: 'critical',
    description: 'pickle.load() can execute arbitrary code when deserializing untrusted data',
    remediation: 'Use JSON or other safe serialization formats for untrusted data',
    languages: ['python'],
  },
  {
    id: 'DESER_002',
    name: 'Unsafe Deserialization (yaml.load)',
    pattern: /yaml\.load\s*\([^)]*(?!\bSafeLoader\b|\bsafe_load\b)/,
    severity: 'high',
    description: 'yaml.load() with default loader can execute arbitrary Python code',
    remediation: 'Use yaml.safe_load() instead',
    languages: ['python'],
  },

  // SSRF
  {
    id: 'SSRF_001',
    name: 'Possible SSRF',
    pattern: /(?:fetch|axios|request|http\.get|https\.get)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)[a-zA-Z_]+/,
    severity: 'high',
    description: 'HTTP request with user-controlled URL — possible Server-Side Request Forgery',
    remediation: 'Validate URLs against an allowlist before making requests',
    languages: ['javascript', 'typescript'],
  },

  // Open Redirect
  {
    id: 'REDIRECT_001',
    name: 'Open Redirect',
    pattern: /res\.redirect\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)[a-zA-Z_]+/,
    severity: 'medium',
    description: 'Redirect to user-controlled URL — possible open redirect vulnerability',
    remediation: 'Validate redirect URLs against an allowlist',
    languages: ['javascript', 'typescript'],
  },
];

// ---------------------------------------------------------------------------
// Vulnerability Finding
// ---------------------------------------------------------------------------

export interface VulnFinding {
  line: number;
  column: number;
  endColumn: number;
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
}

// ---------------------------------------------------------------------------
// CodeVulnChecker Class
// ---------------------------------------------------------------------------

export class CodeVulnChecker {
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard-codevuln');
  }

  /**
   * Scan a document for code vulnerability patterns.
   */
  scanDocument(document: vscode.TextDocument): VulnFinding[] {
    const findings: VulnFinding[] = [];
    const text = document.getText();
    const lines = text.split('\n');
    const lang = document.languageId;

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      // Skip pure comment lines
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
        continue;
      }

      for (const vuln of VULN_PATTERNS) {
        // Check language filter
        if (vuln.languages && !vuln.languages.includes(lang)) { continue; }

        const match = vuln.pattern.exec(line);
        if (!match) { continue; }

        findings.push({
          line: lineIdx,
          column: match.index,
          endColumn: match.index + match[0].length,
          id: vuln.id,
          name: vuln.name,
          severity: vuln.severity,
          description: vuln.description,
          remediation: vuln.remediation,
        });
      }
    }

    return findings;
  }

  /**
   * Update VS Code diagnostics for a document.
   */
  updateDiagnostics(document: vscode.TextDocument, findings: VulnFinding[]): void {
    const diagnostics: vscode.Diagnostic[] = findings.map(f => {
      const range = new vscode.Range(f.line, f.column, f.line, f.endColumn);
      const severity = f.severity === 'critical' || f.severity === 'high'
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Warning;

      const diag = new vscode.Diagnostic(
        range,
        `🔒 [${f.id}] ${f.name}: ${f.description}. Fix: ${f.remediation}`,
        severity
      );
      diag.source = 'CodeGuard AI (SAST)';
      diag.code = f.id;
      return diag;
    });

    this.diagnosticCollection.set(document.uri, diagnostics);
  }

  /**
   * Scan and update diagnostics.
   */
  async scan(document: vscode.TextDocument): Promise<VulnFinding[]> {
    const supported = [
      'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
      'python', 'go', 'java', 'rust', 'php', 'ruby', 'csharp',
    ];
    if (!supported.includes(document.languageId)) { return []; }

    const findings = this.scanDocument(document);
    this.updateDiagnostics(document, findings);
    return findings;
  }

  clearDiagnostics(uri: vscode.Uri): void {
    this.diagnosticCollection.delete(uri);
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
  }
}
