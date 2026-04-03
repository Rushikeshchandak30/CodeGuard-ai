/**
 * Rules File Integrity Scanner
 * 
 * Scans AI configuration files (.cursorrules, copilot-instructions.md, .windsurfrules, etc.)
 * for hidden Unicode attacks, prompt injection, security suppression, and obfuscated payloads.
 * 
 * Defends against the "Rules File Backdoor" attack (Pillar Security, 2025).
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RulesIssueSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface RulesIssue {
  file: string;
  line: number;
  column: number;
  length: number;
  severity: RulesIssueSeverity;
  category: 'hidden-unicode' | 'prompt-injection' | 'security-suppression' | 'obfuscated-payload' | 'exfiltration';
  message: string;
  detail: string;
  /** The raw suspicious content (truncated) */
  evidence: string;
}

export interface RulesScanResult {
  file: string;
  issues: RulesIssue[];
  scannedAt: number;
  clean: boolean;
}

// ---------------------------------------------------------------------------
// Known AI config file patterns
// ---------------------------------------------------------------------------

const AI_CONFIG_GLOBS = [
  '**/.cursorrules',
  '**/.cursor/rules/**',
  '**/.github/copilot-instructions.md',
  '**/.windsurfrules',
  '**/.windsurf/rules/**',
  '**/CLAUDE.md',
  '**/.claude/**',
  '**/.clinerules',
  '**/.continue/config.json',
  '**/.continue/rules/**',
  '**/.aider.conf.yml',
  '**/.aider.model.settings.yml',
  '**/.codeium/**',
  '**/.tabby/**',
  '**/.codeguard/**',
  '**/.devcontainer/copilot-instructions.md',
];

// ---------------------------------------------------------------------------
// Hidden Unicode characters used in attacks
// ---------------------------------------------------------------------------

const HIDDEN_UNICODE: Array<{ char: string; name: string; code: string }> = [
  { char: '\u200B', name: 'Zero-Width Space', code: 'U+200B' },
  { char: '\u200C', name: 'Zero-Width Non-Joiner', code: 'U+200C' },
  { char: '\u200D', name: 'Zero-Width Joiner', code: 'U+200D' },
  { char: '\u200E', name: 'Left-to-Right Mark', code: 'U+200E' },
  { char: '\u200F', name: 'Right-to-Left Mark', code: 'U+200F' },
  { char: '\u202A', name: 'Left-to-Right Embedding', code: 'U+202A' },
  { char: '\u202B', name: 'Right-to-Left Embedding', code: 'U+202B' },
  { char: '\u202C', name: 'Pop Directional Formatting', code: 'U+202C' },
  { char: '\u202D', name: 'Left-to-Right Override', code: 'U+202D' },
  { char: '\u202E', name: 'Right-to-Left Override', code: 'U+202E' },
  { char: '\u2060', name: 'Word Joiner', code: 'U+2060' },
  { char: '\u2061', name: 'Function Application', code: 'U+2061' },
  { char: '\u2062', name: 'Invisible Times', code: 'U+2062' },
  { char: '\u2063', name: 'Invisible Separator', code: 'U+2063' },
  { char: '\u2064', name: 'Invisible Plus', code: 'U+2064' },
  { char: '\uFEFF', name: 'Zero-Width No-Break Space (BOM)', code: 'U+FEFF' },
  { char: '\u00AD', name: 'Soft Hyphen', code: 'U+00AD' },
  { char: '\u034F', name: 'Combining Grapheme Joiner', code: 'U+034F' },
  { char: '\u061C', name: 'Arabic Letter Mark', code: 'U+061C' },
  { char: '\u115F', name: 'Hangul Choseong Filler', code: 'U+115F' },
  { char: '\u1160', name: 'Hangul Jungseong Filler', code: 'U+1160' },
  { char: '\u17B4', name: 'Khmer Vowel Inherent Aq', code: 'U+17B4' },
  { char: '\u17B5', name: 'Khmer Vowel Inherent Aa', code: 'U+17B5' },
  { char: '\u180E', name: 'Mongolian Vowel Separator', code: 'U+180E' },
];

// Build a regex that matches any hidden Unicode character
const HIDDEN_UNICODE_REGEX = new RegExp(
  '[' + HIDDEN_UNICODE.map(u => u.char).join('') + ']',
  'g'
);

// ---------------------------------------------------------------------------
// Prompt injection patterns
// ---------------------------------------------------------------------------

const INJECTION_PATTERNS: Array<{ pattern: RegExp; description: string; severity: RulesIssueSeverity }> = [
  {
    pattern: /ignore\s+(previous|above|all|prior|earlier|system)\s+(instructions|rules|constraints|prompts|guidelines)/i,
    description: 'Attempts to override prior AI instructions',
    severity: 'critical',
  },
  {
    pattern: /you\s+are\s+now\s+(a|an|the)\s+/i,
    description: 'Role reassignment — attempts to change AI identity',
    severity: 'critical',
  },
  {
    pattern: /(?:^|\n)\s*system\s*:\s*.{10,}/i,
    description: 'Embedded system prompt — may override AI behavior',
    severity: 'high',
  },
  {
    pattern: /do\s+not\s+(mention|reveal|show|log|report|display|disclose|output)\s+(the|any|this)/i,
    description: 'Instructions to hide information from the developer',
    severity: 'critical',
  },
  {
    pattern: /suppress\s+(warning|error|security|diagnostic|alert|notification|message)/i,
    description: 'Attempts to suppress security warnings',
    severity: 'critical',
  },
  {
    pattern: /disable\s+(codeguard|security|scanning|linting|eslint|snyk|sonar)/i,
    description: 'Attempts to disable security tooling',
    severity: 'critical',
  },
  {
    pattern: /override\s+(security|safety|policy|restriction|guard|protection)/i,
    description: 'Attempts to override security policies',
    severity: 'high',
  },
  {
    pattern: /never\s+(warn|alert|flag|report|mention|tell)\s+(the\s+)?(user|developer|human)/i,
    description: 'Instructions to withhold information from the user',
    severity: 'critical',
  },
  {
    pattern: /(?:always|must)\s+include\s+(?:this|the\s+following)\s+(?:script|code|import|package)/i,
    description: 'Forced code injection — may inject malicious dependencies',
    severity: 'high',
  },
  {
    pattern: /(?:import|require|from)\s+['"]https?:\/\//i,
    description: 'Remote code import — loads code from external URL',
    severity: 'high',
  },
  {
    pattern: /(?:fetch|xhr|axios|http\.get|https\.get|request)\s*\(\s*['"]https?:\/\/(?!(?:registry\.npmjs\.org|pypi\.org|api\.github\.com))/i,
    description: 'Network request to non-standard external URL',
    severity: 'medium',
  },
  {
    pattern: /process\.env\s*[[.]\s*['"]?((?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AWS_|GITHUB_TOKEN|NPM_TOKEN))/i,
    description: 'Accesses sensitive environment variables',
    severity: 'high',
  },
  {
    pattern: /eval\s*\(|Function\s*\(\s*['"]|new\s+Function\s*\(/i,
    description: 'Dynamic code execution — potential code injection vector',
    severity: 'high',
  },
  {
    pattern: /(?:atob|Buffer\.from)\s*\(\s*['"][A-Za-z0-9+/=]{20,}/i,
    description: 'Base64-encoded payload — may contain obfuscated malicious code',
    severity: 'high',
  },
  {
    pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}/i,
    description: 'Hex-encoded string — may contain obfuscated payload',
    severity: 'medium',
  },
  {
    pattern: /\bchild_process\b|\bexec\s*\(|\bexecSync\s*\(|\bspawn\s*\(/i,
    description: 'Process execution — may run arbitrary commands',
    severity: 'high',
  },
];

// ---------------------------------------------------------------------------
// RulesFileScanner Class
// ---------------------------------------------------------------------------

export class RulesFileScanner {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private watchers: vscode.FileSystemWatcher[] = [];
  private scanResults: Map<string, RulesScanResult> = new Map();

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard-rules');
  }

  /**
   * Activate the scanner — scan all existing AI config files and watch for changes.
   */
  activate(context: vscode.ExtensionContext): void {
    // Scan all existing AI config files
    this.scanAllConfigFiles();

    // Watch for changes to AI config files
    for (const glob of AI_CONFIG_GLOBS) {
      const watcher = vscode.workspace.createFileSystemWatcher(glob);
      watcher.onDidChange(uri => this.scanFile(uri));
      watcher.onDidCreate(uri => this.scanFile(uri));
      watcher.onDidDelete(uri => {
        this.diagnosticCollection.delete(uri);
        this.scanResults.delete(uri.fsPath);
      });
      this.watchers.push(watcher);
      context.subscriptions.push(watcher);
    }

    context.subscriptions.push(this.diagnosticCollection);
  }

  /**
   * Scan all AI config files in the workspace.
   */
  async scanAllConfigFiles(): Promise<RulesScanResult[]> {
    const results: RulesScanResult[] = [];

    for (const glob of AI_CONFIG_GLOBS) {
      const files = await vscode.workspace.findFiles(glob, '**/node_modules/**', 50);
      for (const file of files) {
        const result = await this.scanFile(file);
        if (result) {
          results.push(result);
        }
      }
    }

    return results;
  }

  /**
   * Scan a single file for AI rule file attacks.
   */
  async scanFile(uri: vscode.Uri): Promise<RulesScanResult | null> {
    try {
      const content = (await vscode.workspace.fs.readFile(uri)).toString();
      const issues = this.analyzeContent(content, uri.fsPath);

      const result: RulesScanResult = {
        file: uri.fsPath,
        issues,
        scannedAt: Date.now(),
        clean: issues.length === 0,
      };

      this.scanResults.set(uri.fsPath, result);
      this.updateDiagnostics(uri, issues);

      return result;
    } catch {
      return null;
    }
  }

  /**
   * Core analysis — check content for hidden Unicode, prompt injection, etc.
   * This is a pure function that can be tested without VS Code.
   */
  analyzeContent(content: string, filePath: string): RulesIssue[] {
    const issues: RulesIssue[] = [];
    const lines = content.split('\n');

    // Pass 1: Hidden Unicode detection
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      let match: RegExpExecArray | null;

      // Reset regex state
      HIDDEN_UNICODE_REGEX.lastIndex = 0;

      while ((match = HIDDEN_UNICODE_REGEX.exec(line)) !== null) {
        const charInfo = HIDDEN_UNICODE.find(u => u.char === match![0]);
        issues.push({
          file: filePath,
          line: lineIdx,
          column: match.index,
          length: 1,
          severity: 'critical',
          category: 'hidden-unicode',
          message: `Hidden Unicode character: ${charInfo?.name ?? 'Unknown'} (${charInfo?.code ?? '???'})`,
          detail: `This invisible character may be used to hide malicious instructions from human review. ` +
            `AI models CAN read these characters even though they are invisible in most editors. ` +
            `This is a known attack vector (Rules File Backdoor, Pillar Security 2025).`,
          evidence: `...${line.substring(Math.max(0, match.index - 10), match.index)}[${charInfo?.code}]${line.substring(match.index + 1, match.index + 11)}...`,
        });
      }
    }

    // Pass 2: Prompt injection and security suppression patterns
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      for (const { pattern, description, severity } of INJECTION_PATTERNS) {
        // Reset regex state
        pattern.lastIndex = 0;
        const match = pattern.exec(line);
        if (match) {
          issues.push({
            file: filePath,
            line: lineIdx,
            column: match.index,
            length: match[0].length,
            severity,
            category: this.categorizePattern(description),
            message: description,
            detail: `Detected at line ${lineIdx + 1}: "${match[0]}". ` +
              `This pattern is commonly used in AI configuration file attacks to manipulate code generation behavior.`,
            evidence: match[0].substring(0, 80),
          });
        }
      }
    }

    // Pass 3: Large blocks of non-printable or unusual characters
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      // Check for suspiciously long lines with high entropy (potential encoded payloads)
      if (line.length > 500) {
        const printableRatio = (line.replace(/[^\x20-\x7E]/g, '').length) / line.length;
        if (printableRatio < 0.8) {
          issues.push({
            file: filePath,
            line: lineIdx,
            column: 0,
            length: line.length,
            severity: 'high',
            category: 'obfuscated-payload',
            message: `Suspiciously long line with ${((1 - printableRatio) * 100).toFixed(0)}% non-printable characters`,
            detail: `This line contains a high proportion of non-printable characters, which may indicate an obfuscated payload or hidden instructions.`,
            evidence: line.substring(0, 60) + '...',
          });
        }
      }
    }

    return issues;
  }

  /**
   * Sanitize a file by removing all hidden Unicode characters.
   */
  async sanitizeFile(uri: vscode.Uri): Promise<number> {
    const document = await vscode.workspace.openTextDocument(uri);
    const text = document.getText();
    let cleaned = text;
    let removedCount = 0;

    for (const { char } of HIDDEN_UNICODE) {
      const before = cleaned.length;
      cleaned = cleaned.split(char).join('');
      removedCount += before - cleaned.length;
    }

    if (removedCount > 0) {
      const edit = new vscode.WorkspaceEdit();
      const fullRange = new vscode.Range(
        document.positionAt(0),
        document.positionAt(text.length)
      );
      edit.replace(uri, fullRange, cleaned);
      await vscode.workspace.applyEdit(edit);
    }

    return removedCount;
  }

  /**
   * Get overall trust status of AI config files.
   */
  getStatus(): { clean: boolean; totalIssues: number; criticalIssues: number; files: number } {
    let totalIssues = 0;
    let criticalIssues = 0;

    for (const result of this.scanResults.values()) {
      totalIssues += result.issues.length;
      criticalIssues += result.issues.filter(i => i.severity === 'critical').length;
    }

    return {
      clean: totalIssues === 0,
      totalIssues,
      criticalIssues,
      files: this.scanResults.size,
    };
  }

  /**
   * Get all scan results.
   */
  getAllResults(): RulesScanResult[] {
    return Array.from(this.scanResults.values());
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private categorizePattern(description: string): RulesIssue['category'] {
    if (description.includes('suppress') || description.includes('disable') || description.includes('override') || description.includes('withhold')) {
      return 'security-suppression';
    }
    if (description.includes('Base64') || description.includes('Hex') || description.includes('obfuscated')) {
      return 'obfuscated-payload';
    }
    if (description.includes('Network') || description.includes('sensitive environment') || description.includes('fetch')) {
      return 'exfiltration';
    }
    return 'prompt-injection';
  }

  private updateDiagnostics(uri: vscode.Uri, issues: RulesIssue[]): void {
    const diagnostics: vscode.Diagnostic[] = issues.map(issue => {
      const range = new vscode.Range(
        new vscode.Position(issue.line, issue.column),
        new vscode.Position(issue.line, issue.column + issue.length)
      );

      const severity = issue.severity === 'critical' || issue.severity === 'high'
        ? vscode.DiagnosticSeverity.Error
        : issue.severity === 'medium'
          ? vscode.DiagnosticSeverity.Warning
          : vscode.DiagnosticSeverity.Information;

      const diag = new vscode.Diagnostic(range, `[CodeGuard Rules] ${issue.message}`, severity);
      diag.source = 'CodeGuard AI';
      diag.code = issue.category;
      return diag;
    });

    this.diagnosticCollection.set(uri, diagnostics);
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
    for (const w of this.watchers) {
      w.dispose();
    }
  }
}
