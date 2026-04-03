/**
 * Git Security Regression Detector
 *
 * Detects security-relevant regressions in code changes by comparing
 * the current file against its last committed version via `git diff`.
 *
 * Detects:
 *   - Removed input validation / sanitization
 *   - Removed authentication / authorization checks
 *   - Dependency downgrades (lower version in package.json)
 *   - Weakened crypto (SHA-256 → MD5, removed TLS checks)
 *   - Removed error handling (try/catch blocks removed)
 *   - Disabled security features (flags set to false)
 *   - New unsafe patterns introduced in the diff
 *
 * Uses VS Code's built-in Git extension API when available,
 * falls back to spawning `git diff` directly.
 */

import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RegressionSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface SecurityRegression {
  id: string;
  name: string;
  severity: RegressionSeverity;
  description: string;
  file: string;
  line: number;
  /** The removed/changed code */
  removedCode?: string;
  /** The replacement code (if any) */
  addedCode?: string;
  /** Category of regression */
  category: RegressionCategory;
}

export type RegressionCategory =
  | 'removed-validation'
  | 'removed-auth'
  | 'weakened-crypto'
  | 'removed-error-handling'
  | 'disabled-security'
  | 'dependency-downgrade'
  | 'new-unsafe-pattern'
  | 'removed-sanitization';

export interface RegressionReport {
  file: string;
  regressions: SecurityRegression[];
  linesAdded: number;
  linesRemoved: number;
  timestamp: number;
}

// ---------------------------------------------------------------------------
// Regression Detection Patterns
// ---------------------------------------------------------------------------

interface RegressionRule {
  id: string;
  name: string;
  category: RegressionCategory;
  severity: RegressionSeverity;
  /** Pattern that, if REMOVED, indicates a regression */
  removedPattern: RegExp;
  description: string;
}

interface NewUnsafeRule {
  id: string;
  name: string;
  severity: RegressionSeverity;
  /** Pattern that, if ADDED, indicates a new unsafe practice */
  addedPattern: RegExp;
  description: string;
}

const REMOVED_PATTERNS: RegressionRule[] = [
  // Validation removal
  { id: 'REG_VAL_001', name: 'Removed input validation', category: 'removed-validation', severity: 'high', removedPattern: /(?:validate|sanitize|escape|encode|purify|DOMPurify|xss|validator)\s*\(/, description: 'Input validation/sanitization function call was removed' },
  { id: 'REG_VAL_002', name: 'Removed type check', category: 'removed-validation', severity: 'medium', removedPattern: /(?:typeof|instanceof)\s+\w+\s*[!=]==?\s*['"]/, description: 'Type checking guard was removed' },
  { id: 'REG_VAL_003', name: 'Removed bounds check', category: 'removed-validation', severity: 'medium', removedPattern: /(?:\.length|\.size)\s*(?:>|<|>=|<=|===|!==)\s*\d+/, description: 'Bounds/length check was removed' },

  // Auth removal
  { id: 'REG_AUTH_001', name: 'Removed auth check', category: 'removed-auth', severity: 'critical', removedPattern: /(?:isAuthenticated|requireAuth|checkAuth|verifyToken|isAuthorized|requireRole|checkPermission)\s*\(/, description: 'Authentication/authorization check was removed' },
  { id: 'REG_AUTH_002', name: 'Removed middleware', category: 'removed-auth', severity: 'high', removedPattern: /(?:authenticate|authorize|requireLogin|ensureAuth|passport\.authenticate)\s*\(/, description: 'Auth middleware was removed from route' },
  { id: 'REG_AUTH_003', name: 'Removed CSRF protection', category: 'removed-auth', severity: 'high', removedPattern: /(?:csrf|csrfProtection|csurf|csrfToken)\b/, description: 'CSRF protection was removed' },

  // Crypto weakening
  { id: 'REG_CRYPTO_001', name: 'Removed TLS verification', category: 'weakened-crypto', severity: 'critical', removedPattern: /rejectUnauthorized\s*:\s*true/, description: 'TLS certificate verification was disabled' },
  { id: 'REG_CRYPTO_002', name: 'Removed secure hash', category: 'weakened-crypto', severity: 'high', removedPattern: /(?:sha256|sha384|sha512|sha-256|sha-384|sha-512|SHA256|SHA512)\b/, description: 'Strong hash algorithm was removed (possible downgrade)' },
  { id: 'REG_CRYPTO_003', name: 'Removed HTTPS enforcement', category: 'weakened-crypto', severity: 'high', removedPattern: /(?:https|secure\s*:\s*true|forceSSL|requireHTTPS)\b/, description: 'HTTPS enforcement was removed' },

  // Error handling removal
  { id: 'REG_ERR_001', name: 'Removed try-catch', category: 'removed-error-handling', severity: 'medium', removedPattern: /\btry\s*\{/, description: 'Error handling (try-catch) was removed' },
  { id: 'REG_ERR_002', name: 'Removed error handler', category: 'removed-error-handling', severity: 'medium', removedPattern: /\.catch\s*\(/, description: 'Promise error handler (.catch) was removed' },

  // Sanitization removal
  { id: 'REG_SAN_001', name: 'Removed SQL parameterization', category: 'removed-sanitization', severity: 'critical', removedPattern: /(?:parameterized|prepared|placeholder|\?\s*,|\$\d+)/, description: 'SQL parameterization was removed (possible injection)' },
  { id: 'REG_SAN_002', name: 'Removed HTML encoding', category: 'removed-sanitization', severity: 'high', removedPattern: /(?:escapeHtml|htmlEncode|encodeURIComponent|encodeURI)\s*\(/, description: 'HTML/URL encoding was removed' },
  { id: 'REG_SAN_003', name: 'Removed path validation', category: 'removed-sanitization', severity: 'high', removedPattern: /path\.(?:resolve|normalize|join)\s*\(/, description: 'Path normalization was removed (possible traversal)' },

  // Security flags disabled
  { id: 'REG_FLAG_001', name: 'Security flag disabled', category: 'disabled-security', severity: 'high', removedPattern: /(?:httpOnly|secure|sameSite|strictTransportSecurity|contentSecurityPolicy)\s*[:=]\s*true/, description: 'Security flag was changed from true to false' },
];

const NEW_UNSAFE_PATTERNS: NewUnsafeRule[] = [
  { id: 'REG_NEW_001', name: 'New eval() usage', severity: 'critical', addedPattern: /\beval\s*\(/, description: 'eval() was added — possible code injection' },
  { id: 'REG_NEW_002', name: 'New shell command', severity: 'critical', addedPattern: /(?:child_process\.)?exec\s*\(\s*[`'"]/, description: 'Shell command execution was added' },
  { id: 'REG_NEW_003', name: 'Disabled TLS', severity: 'critical', addedPattern: /rejectUnauthorized\s*:\s*false/, description: 'TLS verification was explicitly disabled' },
  { id: 'REG_NEW_004', name: 'Hardcoded secret', severity: 'high', addedPattern: /(?:password|secret|apiKey|api_key|token)\s*[:=]\s*['"][^'"]{8,}['"]/, description: 'Hardcoded secret/credential was added' },
  { id: 'REG_NEW_005', name: 'Wildcard CORS', severity: 'medium', addedPattern: /Access-Control-Allow-Origin['"]\s*[:,]\s*['"]?\*/, description: 'Wildcard CORS policy was added' },
];

// ---------------------------------------------------------------------------
// GitRegressionDetector Class
// ---------------------------------------------------------------------------

export class GitRegressionDetector {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private disposables: vscode.Disposable[] = [];

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard-git-regression');
  }

  /**
   * Activate — watch for file saves and check for regressions.
   */
  activate(context: vscode.ExtensionContext): void {
    this.disposables.push(
      vscode.workspace.onDidSaveTextDocument(async (doc) => {
        if (this.isSupported(doc)) {
          try {
            const report = await this.detectRegressions(doc);
            if (report.regressions.length > 0) {
              this.updateDiagnostics(doc, report.regressions);
            }
          } catch {
            // Git not available or file not tracked
          }
        }
      })
    );

    context.subscriptions.push({ dispose: () => this.dispose() });
  }

  /**
   * Detect security regressions by diffing current file against last commit.
   */
  async detectRegressions(document: vscode.TextDocument): Promise<RegressionReport> {
    const filePath = document.uri.fsPath;
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (!workspaceFolder) {
      return { file: filePath, regressions: [], linesAdded: 0, linesRemoved: 0, timestamp: Date.now() };
    }

    const cwd = workspaceFolder.uri.fsPath;
    const relativePath = path.relative(cwd, filePath);

    // Get diff from git
    const diff = await this.getGitDiff(cwd, relativePath);
    if (!diff) {
      return { file: filePath, regressions: [], linesAdded: 0, linesRemoved: 0, timestamp: Date.now() };
    }

    const { addedLines, removedLines, linesAdded, linesRemoved } = this.parseDiff(diff);
    const regressions: SecurityRegression[] = [];

    // Check removed lines for security regressions
    for (const rl of removedLines) {
      for (const rule of REMOVED_PATTERNS) {
        if (rule.removedPattern.test(rl.text)) {
          // Check if the pattern still exists in added lines nearby
          const stillPresent = addedLines.some(al =>
            Math.abs(al.lineNumber - rl.lineNumber) < 5 && rule.removedPattern.test(al.text)
          );

          if (!stillPresent) {
            regressions.push({
              id: rule.id,
              name: rule.name,
              severity: rule.severity,
              description: rule.description,
              file: filePath,
              line: rl.lineNumber,
              removedCode: rl.text.trim(),
              category: rule.category,
            });
          }
        }
      }
    }

    // Check added lines for new unsafe patterns
    for (const al of addedLines) {
      for (const rule of NEW_UNSAFE_PATTERNS) {
        if (rule.addedPattern.test(al.text)) {
          regressions.push({
            id: rule.id,
            name: rule.name,
            severity: rule.severity,
            description: rule.description,
            file: filePath,
            line: al.lineNumber,
            addedCode: al.text.trim(),
            category: 'new-unsafe-pattern',
          });
        }
      }
    }

    // Check for dependency downgrades in package.json
    if (filePath.endsWith('package.json')) {
      regressions.push(...this.detectDependencyDowngrades(addedLines, removedLines, filePath));
    }

    return {
      file: filePath,
      regressions,
      linesAdded,
      linesRemoved,
      timestamp: Date.now(),
    };
  }

  /**
   * Run regression check on all modified files in the workspace.
   */
  async scanWorkspace(): Promise<RegressionReport[]> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) { return []; }

    const cwd = workspaceFolders[0].uri.fsPath;
    const modifiedFiles = await this.getModifiedFiles(cwd);
    const reports: RegressionReport[] = [];

    for (const file of modifiedFiles) {
      try {
        const uri = vscode.Uri.file(path.join(cwd, file));
        const doc = await vscode.workspace.openTextDocument(uri);
        const report = await this.detectRegressions(doc);
        if (report.regressions.length > 0) {
          reports.push(report);
        }
      } catch {
        // skip files that can't be opened
      }
    }

    return reports;
  }

  /**
   * Format regression report as markdown.
   */
  toMarkdown(reports: RegressionReport[]): string {
    const allRegressions = reports.flatMap(r => r.regressions);
    const lines: string[] = [
      '# Git Security Regression Report',
      '',
      `**Files scanned:** ${reports.length} | **Regressions found:** ${allRegressions.length}`,
      '',
    ];

    if (allRegressions.length === 0) {
      lines.push('No security regressions detected in recent changes.');
      return lines.join('\n');
    }

    // Group by severity
    const bySeverity = new Map<RegressionSeverity, SecurityRegression[]>();
    for (const r of allRegressions) {
      if (!bySeverity.has(r.severity)) { bySeverity.set(r.severity, []); }
      bySeverity.get(r.severity)!.push(r);
    }

    for (const sev of ['critical', 'high', 'medium', 'low'] as RegressionSeverity[]) {
      const regs = bySeverity.get(sev);
      if (!regs || regs.length === 0) { continue; }

      const emoji = sev === 'critical' ? '🔴' : sev === 'high' ? '🟠' : sev === 'medium' ? '🟡' : '🟢';
      lines.push(`## ${emoji} ${sev.toUpperCase()} (${regs.length})`);
      lines.push('');

      for (const r of regs) {
        lines.push(`### ${r.name}`);
        lines.push(`- **File:** \`${path.basename(r.file)}:${r.line + 1}\``);
        lines.push(`- **Category:** ${r.category}`);
        lines.push(`- **Description:** ${r.description}`);
        if (r.removedCode) { lines.push(`- **Removed:** \`${r.removedCode}\``); }
        if (r.addedCode) { lines.push(`- **Added:** \`${r.addedCode}\``); }
        lines.push('');
      }
    }

    return lines.join('\n');
  }

  // -----------------------------------------------------------------------
  // Diagnostics
  // -----------------------------------------------------------------------

  updateDiagnostics(document: vscode.TextDocument, regressions: SecurityRegression[]): void {
    const diagnostics: vscode.Diagnostic[] = regressions.map(r => {
      const range = new vscode.Range(
        Math.max(0, r.line), 0,
        Math.max(0, r.line), 200
      );
      const severity = (r.severity === 'critical' || r.severity === 'high')
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Warning;

      const detail = r.removedCode ? ` (removed: "${r.removedCode}")` : '';
      const diag = new vscode.Diagnostic(
        range,
        `[${r.id}] Security regression: ${r.description}${detail}`,
        severity
      );
      diag.source = 'CodeGuard Git Regression';
      diag.code = r.id;
      return diag;
    });

    this.diagnosticCollection.set(document.uri, diagnostics);
  }

  clearDiagnostics(uri: vscode.Uri): void {
    this.diagnosticCollection.delete(uri);
  }

  // -----------------------------------------------------------------------
  // Private: Git Operations
  // -----------------------------------------------------------------------

  private getGitDiff(cwd: string, relativePath: string): Promise<string | null> {
    return new Promise((resolve) => {
      cp.exec(
        `git diff HEAD -- "${relativePath}"`,
        { cwd, maxBuffer: 1024 * 1024, timeout: 10000 },
        (err, stdout) => {
          if (err || !stdout) { resolve(null); }
          else { resolve(stdout); }
        }
      );
    });
  }

  private getModifiedFiles(cwd: string): Promise<string[]> {
    return new Promise((resolve) => {
      cp.exec(
        'git diff --name-only HEAD',
        { cwd, maxBuffer: 256 * 1024, timeout: 10000 },
        (err, stdout) => {
          if (err || !stdout) { resolve([]); }
          else { resolve(stdout.trim().split('\n').filter(Boolean)); }
        }
      );
    });
  }

  private parseDiff(diff: string): {
    addedLines: Array<{ text: string; lineNumber: number }>;
    removedLines: Array<{ text: string; lineNumber: number }>;
    linesAdded: number;
    linesRemoved: number;
  } {
    const addedLines: Array<{ text: string; lineNumber: number }> = [];
    const removedLines: Array<{ text: string; lineNumber: number }> = [];
    let currentLine = 0;

    for (const line of diff.split('\n')) {
      // Parse hunk header: @@ -a,b +c,d @@
      const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (hunkMatch) {
        currentLine = parseInt(hunkMatch[1], 10) - 1;
        continue;
      }

      if (line.startsWith('+') && !line.startsWith('+++')) {
        addedLines.push({ text: line.substring(1), lineNumber: currentLine });
        currentLine++;
      } else if (line.startsWith('-') && !line.startsWith('---')) {
        removedLines.push({ text: line.substring(1), lineNumber: currentLine });
        // Don't increment currentLine for removed lines
      } else if (!line.startsWith('\\')) {
        currentLine++;
      }
    }

    return {
      addedLines,
      removedLines,
      linesAdded: addedLines.length,
      linesRemoved: removedLines.length,
    };
  }

  // -----------------------------------------------------------------------
  // Private: Dependency Downgrade Detection
  // -----------------------------------------------------------------------

  private detectDependencyDowngrades(
    addedLines: Array<{ text: string; lineNumber: number }>,
    removedLines: Array<{ text: string; lineNumber: number }>,
    filePath: string
  ): SecurityRegression[] {
    const regressions: SecurityRegression[] = [];
    const depPattern = /["']([^"']+)["']\s*:\s*["']([^"']+)["']/;

    const removedDeps = new Map<string, { version: string; line: number }>();
    for (const rl of removedLines) {
      const match = depPattern.exec(rl.text);
      if (match) {
        removedDeps.set(match[1], { version: match[2], line: rl.lineNumber });
      }
    }

    for (const al of addedLines) {
      const match = depPattern.exec(al.text);
      if (match) {
        const pkg = match[1];
        const newVersion = match[2];
        const old = removedDeps.get(pkg);

        if (old && this.isDowngrade(old.version, newVersion)) {
          regressions.push({
            id: 'REG_DEP_001',
            name: 'Dependency downgrade',
            severity: 'high',
            description: `Package "${pkg}" was downgraded from ${old.version} to ${newVersion}`,
            file: filePath,
            line: al.lineNumber,
            removedCode: `"${pkg}": "${old.version}"`,
            addedCode: `"${pkg}": "${newVersion}"`,
            category: 'dependency-downgrade',
          });
        }
      }
    }

    return regressions;
  }

  /**
   * Very simple semver comparison — checks if newVer < oldVer.
   * Strips ^ ~ >= prefixes before comparing.
   */
  private isDowngrade(oldVersion: string, newVersion: string): boolean {
    const strip = (v: string) => v.replace(/^[\^~>=<]+/, '');
    const oldParts = strip(oldVersion).split('.').map(Number);
    const newParts = strip(newVersion).split('.').map(Number);

    for (let i = 0; i < Math.max(oldParts.length, newParts.length); i++) {
      const o = oldParts[i] || 0;
      const n = newParts[i] || 0;
      if (n < o) { return true; }
      if (n > o) { return false; }
    }

    return false;
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private isSupported(doc: vscode.TextDocument): boolean {
    return ['javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'python', 'json'].includes(doc.languageId);
  }

  dispose(): void {
    for (const d of this.disposables) { d.dispose(); }
    this.diagnosticCollection.dispose();
  }
}
