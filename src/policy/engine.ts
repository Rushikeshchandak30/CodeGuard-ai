/**
 * Policy-as-Code Engine
 *
 * Reads `.codeguard/policy.yaml` (or `.json`) and enforces security rules
 * in real-time inside the IDE. Policies can run in three modes:
 *   - audit:   log violations only (output channel)
 *   - warn:    show VS Code warnings
 *   - enforce: show VS Code errors (blocks in strict mode)
 *
 * Supports:
 *   - Package blocklists / allowlists
 *   - Minimum provenance level
 *   - Maximum allowed vulnerability severity
 *   - Required SBOM baseline
 *   - AI code ratio limits
 *   - Custom regex ban patterns
 *   - Pre-commit hook mode
 */

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type PolicyMode = 'audit' | 'warn' | 'enforce';
export type ProvenanceLevel = 'verified' | 'partial' | 'none';

export interface PolicyConfig {
  /** Policy schema version */
  version: 1;
  /** Global enforcement mode */
  mode: PolicyMode;
  rules: PolicyRules;
}

export interface PolicyRules {
  /** Block packages that lack provenance attestation */
  block_unprovenanced_packages?: boolean;
  /** Minimum provenance level required */
  required_provenance_level?: ProvenanceLevel;
  /** Maximum vulnerability severity allowed (e.g. 'medium' blocks high/critical) */
  max_allowed_severity?: 'critical' | 'high' | 'medium' | 'low' | 'none';
  /** Require an SBOM baseline to exist */
  require_sbom_baseline?: boolean;
  /** Packages explicitly forbidden (name or name@version) */
  forbidden_packages?: string[];
  /** Packages explicitly allowed (bypass all other checks) */
  allowed_packages?: string[];
  /** Maximum AI code ratio (0-1, e.g. 0.7 = 70%) */
  max_ai_code_ratio?: number;
  /** Forbidden code patterns (regex strings) */
  forbidden_patterns?: Array<{
    pattern: string;
    message: string;
    severity?: 'error' | 'warning';
  }>;
  /** Require secrets scanner to be enabled */
  require_secrets_scanner?: boolean;
  /** Require SAST scanner to be enabled */
  require_sast_scanner?: boolean;
  /** Maximum number of critical findings allowed */
  max_critical_findings?: number;
  /** Maximum number of high findings allowed */
  max_high_findings?: number;
  // --- Agentic Supply Chain Rules (v7) ---
  /** Block MCP servers that use npx/bunx (rug-pull risk) */
  block_npx_mcp_servers?: boolean;
  /** Block MCP servers connecting over plain HTTP */
  block_unencrypted_mcp?: boolean;
  /** Allowed MCP server names (all others flagged as unapproved) */
  allowed_mcp_servers?: string[];
  /** Block hardcoded credentials in MCP server env */
  block_mcp_hardcoded_credentials?: boolean;
  /** Maximum number of MCP security issues allowed */
  max_mcp_issues?: number;
  /** Require AI-SBOM to be generated */
  require_ai_sbom?: boolean;
  /** Allowed AI SDKs (all others flagged as unapproved shadow AI) */
  allowed_ai_sdks?: string[];
}

export interface PolicyViolation {
  rule: string;
  message: string;
  severity: 'error' | 'warning' | 'info';
  file?: string;
  line?: number;
  /** The policy mode at time of violation */
  mode: PolicyMode;
}

export interface PolicyEvaluation {
  /** Whether all policy rules passed */
  passed: boolean;
  violations: PolicyViolation[];
  /** Number of rules checked */
  rulesChecked: number;
  /** Active policy mode */
  mode: PolicyMode;
  timestamp: number;
}

// ---------------------------------------------------------------------------
// Default Policy
// ---------------------------------------------------------------------------

const DEFAULT_POLICY: PolicyConfig = {
  version: 1,
  mode: 'warn',
  rules: {
    block_unprovenanced_packages: false,
    required_provenance_level: 'none',
    max_allowed_severity: 'critical',
    require_sbom_baseline: false,
    forbidden_packages: [],
    allowed_packages: [],
    max_ai_code_ratio: 1.0,
    forbidden_patterns: [],
    require_secrets_scanner: true,
    require_sast_scanner: true,
    max_critical_findings: 999,
    max_high_findings: 999,
    block_npx_mcp_servers: false,
    block_unencrypted_mcp: true,
    allowed_mcp_servers: [],
    block_mcp_hardcoded_credentials: true,
    max_mcp_issues: 999,
    require_ai_sbom: false,
    allowed_ai_sdks: [],
  },
};

// ---------------------------------------------------------------------------
// PolicyEngine Class
// ---------------------------------------------------------------------------

export class PolicyEngine {
  private policy: PolicyConfig = DEFAULT_POLICY;
  private diagnosticCollection: vscode.DiagnosticCollection;
  private outputChannel: vscode.OutputChannel;
  private policyFilePath: string | undefined;
  private fileWatcher: vscode.FileSystemWatcher | undefined;
  private disposables: vscode.Disposable[] = [];

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard-policy');
    this.outputChannel = vscode.window.createOutputChannel('CodeGuard Policy');
  }

  /**
   * Activate policy engine — load policy file and watch for changes.
   */
  activate(context: vscode.ExtensionContext): void {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) { return; }

    const rootPath = workspaceFolders[0].uri.fsPath;

    // Try loading policy from multiple locations
    const candidates = [
      path.join(rootPath, '.codeguard', 'policy.yaml'),
      path.join(rootPath, '.codeguard', 'policy.json'),
      path.join(rootPath, '.codeguard-policy.yaml'),
      path.join(rootPath, '.codeguard-policy.json'),
    ];

    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        this.policyFilePath = candidate;
        this.loadPolicy(candidate);
        break;
      }
    }

    // Watch for policy file changes
    this.fileWatcher = vscode.workspace.createFileSystemWatcher('**/.codeguard/policy.{yaml,json}');
    this.fileWatcher.onDidChange((uri) => this.loadPolicy(uri.fsPath));
    this.fileWatcher.onDidCreate((uri) => {
      this.policyFilePath = uri.fsPath;
      this.loadPolicy(uri.fsPath);
    });
    this.fileWatcher.onDidDelete(() => {
      this.policy = DEFAULT_POLICY;
      this.policyFilePath = undefined;
      this.outputChannel.appendLine('[Policy] Policy file deleted — using defaults.');
    });

    this.disposables.push(this.fileWatcher);
    context.subscriptions.push({ dispose: () => this.dispose() });
  }

  /**
   * Get the current active policy.
   */
  getPolicy(): PolicyConfig {
    return this.policy;
  }

  /**
   * Check if a policy file exists.
   */
  hasPolicyFile(): boolean {
    return this.policyFilePath !== undefined;
  }

  /**
   * Evaluate a package against the policy.
   */
  evaluatePackage(
    packageName: string,
    version: string | null,
    provenance: ProvenanceLevel,
    maxVulnSeverity: string | null,
  ): PolicyViolation[] {
    const violations: PolicyViolation[] = [];
    const rules = this.policy.rules;
    const mode = this.policy.mode;

    // Check allowlist first (bypass all other checks)
    if (rules.allowed_packages?.includes(packageName)) {
      return [];
    }

    // Forbidden packages
    if (rules.forbidden_packages) {
      const pkgWithVersion = version ? `${packageName}@${version}` : packageName;
      for (const forbidden of rules.forbidden_packages) {
        if (forbidden === packageName || forbidden === pkgWithVersion) {
          violations.push({
            rule: 'forbidden_packages',
            message: `Package "${pkgWithVersion}" is forbidden by policy`,
            severity: mode === 'enforce' ? 'error' : 'warning',
            mode,
          });
        }
      }
    }

    // Provenance requirements
    if (rules.block_unprovenanced_packages && provenance === 'none') {
      violations.push({
        rule: 'block_unprovenanced_packages',
        message: `Package "${packageName}" has no provenance attestation`,
        severity: mode === 'enforce' ? 'error' : 'warning',
        mode,
      });
    }

    if (rules.required_provenance_level) {
      const levels: ProvenanceLevel[] = ['verified', 'partial', 'none'];
      const requiredIdx = levels.indexOf(rules.required_provenance_level);
      const actualIdx = levels.indexOf(provenance);
      if (actualIdx > requiredIdx) {
        violations.push({
          rule: 'required_provenance_level',
          message: `Package "${packageName}" provenance "${provenance}" below required "${rules.required_provenance_level}"`,
          severity: mode === 'enforce' ? 'error' : 'warning',
          mode,
        });
      }
    }

    // Vulnerability severity
    if (rules.max_allowed_severity && maxVulnSeverity) {
      const severityOrder = ['none', 'low', 'medium', 'high', 'critical'];
      const maxAllowed = severityOrder.indexOf(rules.max_allowed_severity);
      const actual = severityOrder.indexOf(maxVulnSeverity.toLowerCase());
      if (actual > maxAllowed) {
        violations.push({
          rule: 'max_allowed_severity',
          message: `Package "${packageName}" has ${maxVulnSeverity} vulnerability (policy allows max: ${rules.max_allowed_severity})`,
          severity: mode === 'enforce' ? 'error' : 'warning',
          mode,
        });
      }
    }

    return violations;
  }

  /**
   * Evaluate a document against custom forbidden patterns.
   */
  evaluateDocument(document: vscode.TextDocument): PolicyViolation[] {
    const violations: PolicyViolation[] = [];
    const rules = this.policy.rules;
    const mode = this.policy.mode;

    if (!rules.forbidden_patterns || rules.forbidden_patterns.length === 0) {
      return [];
    }

    const text = document.getText();
    const lines = text.split('\n');

    for (const fp of rules.forbidden_patterns) {
      try {
        const regex = new RegExp(fp.pattern, 'gi');
        for (let i = 0; i < lines.length; i++) {
          if (regex.test(lines[i])) {
            violations.push({
              rule: 'forbidden_patterns',
              message: fp.message || `Forbidden pattern found: ${fp.pattern}`,
              severity: fp.severity || (mode === 'enforce' ? 'error' : 'warning'),
              file: document.uri.fsPath,
              line: i,
              mode,
            });
          }
          regex.lastIndex = 0; // reset for global regex
        }
      } catch {
        // Invalid regex in policy file — skip
      }
    }

    return violations;
  }

  /**
   * Run a full policy evaluation (for command/pre-commit).
   */
  evaluateFull(context: {
    criticalFindings: number;
    highFindings: number;
    aiCodeRatio: number;
    sbomBaselineExists: boolean;
    secretsScannerEnabled: boolean;
    sastScannerEnabled: boolean;
    mcpIssueCount?: number;
    aiSbomExists?: boolean;
    detectedAiSdks?: string[];
  }): PolicyEvaluation {
    const violations: PolicyViolation[] = [];
    const rules = this.policy.rules;
    const mode = this.policy.mode;
    let rulesChecked = 0;

    // Max critical findings
    if (rules.max_critical_findings !== undefined) {
      rulesChecked++;
      if (context.criticalFindings > rules.max_critical_findings) {
        violations.push({
          rule: 'max_critical_findings',
          message: `${context.criticalFindings} critical findings exceed policy limit of ${rules.max_critical_findings}`,
          severity: mode === 'enforce' ? 'error' : 'warning',
          mode,
        });
      }
    }

    // Max high findings
    if (rules.max_high_findings !== undefined) {
      rulesChecked++;
      if (context.highFindings > rules.max_high_findings) {
        violations.push({
          rule: 'max_high_findings',
          message: `${context.highFindings} high findings exceed policy limit of ${rules.max_high_findings}`,
          severity: mode === 'enforce' ? 'error' : 'warning',
          mode,
        });
      }
    }

    // AI code ratio
    if (rules.max_ai_code_ratio !== undefined) {
      rulesChecked++;
      if (context.aiCodeRatio > rules.max_ai_code_ratio) {
        violations.push({
          rule: 'max_ai_code_ratio',
          message: `AI code ratio ${(context.aiCodeRatio * 100).toFixed(1)}% exceeds policy limit of ${(rules.max_ai_code_ratio * 100).toFixed(1)}%`,
          severity: mode === 'enforce' ? 'error' : 'warning',
          mode,
        });
      }
    }

    // SBOM baseline
    if (rules.require_sbom_baseline) {
      rulesChecked++;
      if (!context.sbomBaselineExists) {
        violations.push({
          rule: 'require_sbom_baseline',
          message: 'SBOM baseline required by policy but not found. Run "CodeGuard: Save SBOM Baseline"',
          severity: mode === 'enforce' ? 'error' : 'warning',
          mode,
        });
      }
    }

    // Required scanners
    if (rules.require_secrets_scanner) {
      rulesChecked++;
      if (!context.secretsScannerEnabled) {
        violations.push({
          rule: 'require_secrets_scanner',
          message: 'Secrets scanner required by policy but disabled',
          severity: 'warning',
          mode,
        });
      }
    }

    if (rules.require_sast_scanner) {
      rulesChecked++;
      if (!context.sastScannerEnabled) {
        violations.push({
          rule: 'require_sast_scanner',
          message: 'SAST scanner required by policy but disabled',
          severity: 'warning',
          mode,
        });
      }
    }

    // Agentic Supply Chain Rules (v7)
    if (rules.max_mcp_issues !== undefined && context.mcpIssueCount !== undefined) {
      rulesChecked++;
      if (context.mcpIssueCount > rules.max_mcp_issues) {
        violations.push({
          rule: 'max_mcp_issues',
          message: `${context.mcpIssueCount} MCP security issue(s) exceed policy limit of ${rules.max_mcp_issues}`,
          severity: mode === 'enforce' ? 'error' : 'warning',
          mode,
        });
      }
    }

    if (rules.require_ai_sbom && context.aiSbomExists !== undefined) {
      rulesChecked++;
      if (!context.aiSbomExists) {
        violations.push({
          rule: 'require_ai_sbom',
          message: 'AI-SBOM required by policy but not found. Run "CodeGuard: Export AI-SBOM (JSON)"',
          severity: mode === 'enforce' ? 'error' : 'warning',
          mode,
        });
      }
    }

    if (rules.allowed_ai_sdks && rules.allowed_ai_sdks.length > 0 && context.detectedAiSdks) {
      rulesChecked++;
      const unapproved = context.detectedAiSdks.filter(sdk => !rules.allowed_ai_sdks!.includes(sdk));
      if (unapproved.length > 0) {
        violations.push({
          rule: 'allowed_ai_sdks',
          message: `Unapproved AI SDK(s) detected: ${unapproved.join(', ')}. Add to allowed_ai_sdks or remove from project.`,
          severity: mode === 'enforce' ? 'error' : 'warning',
          mode,
        });
      }
    }

    return {
      passed: violations.filter(v => v.severity === 'error').length === 0,
      violations,
      rulesChecked,
      mode,
      timestamp: Date.now(),
    };
  }

  /**
   * Update diagnostics for a document based on policy violations.
   */
  updateDiagnostics(document: vscode.TextDocument, violations: PolicyViolation[]): void {
    if (this.policy.mode === 'audit') {
      // In audit mode, log to output channel only
      for (const v of violations) {
        this.outputChannel.appendLine(`[${v.severity.toUpperCase()}] ${v.rule}: ${v.message}`);
      }
      this.diagnosticCollection.delete(document.uri);
      return;
    }

    const diagnostics: vscode.Diagnostic[] = violations
      .filter(v => v.file === document.uri.fsPath && v.line !== undefined)
      .map(v => {
        const range = new vscode.Range(v.line!, 0, v.line!, 200);
        const severity = v.severity === 'error'
          ? vscode.DiagnosticSeverity.Error
          : vscode.DiagnosticSeverity.Warning;

        const diag = new vscode.Diagnostic(range, `[Policy] ${v.message}`, severity);
        diag.source = 'CodeGuard Policy';
        diag.code = v.rule;
        return diag;
      });

    this.diagnosticCollection.set(document.uri, diagnostics);
  }

  /**
   * Format policy evaluation as markdown.
   */
  toMarkdown(evaluation: PolicyEvaluation): string {
    const lines: string[] = [
      '# Policy Evaluation Report',
      '',
      `**Mode:** ${evaluation.mode} | **Rules checked:** ${evaluation.rulesChecked} | **Result:** ${evaluation.passed ? 'PASSED' : 'FAILED'}`,
      '',
    ];

    if (evaluation.violations.length === 0) {
      lines.push('All policy rules passed.');
    } else {
      lines.push(`### Violations (${evaluation.violations.length})`);
      lines.push('');
      for (const v of evaluation.violations) {
        const emoji = v.severity === 'error' ? '🔴' : v.severity === 'warning' ? '🟡' : 'ℹ️';
        lines.push(`- ${emoji} **${v.rule}:** ${v.message}`);
      }
    }

    return lines.join('\n');
  }

  /**
   * Create a default policy file in the workspace.
   */
  async createDefaultPolicy(): Promise<string | null> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) { return null; }

    const dir = path.join(workspaceFolders[0].uri.fsPath, '.codeguard');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const policyPath = path.join(dir, 'policy.json');
    const defaultContent: PolicyConfig = {
      version: 1,
      mode: 'warn',
      rules: {
        block_unprovenanced_packages: false,
        required_provenance_level: 'none',
        max_allowed_severity: 'critical',
        require_sbom_baseline: false,
        forbidden_packages: [],
        allowed_packages: [],
        max_ai_code_ratio: 0.8,
        forbidden_patterns: [
          { pattern: 'TODO:\\s*HACK', message: 'Hack TODO found — review before shipping', severity: 'warning' },
        ],
        require_secrets_scanner: true,
        require_sast_scanner: true,
        max_critical_findings: 0,
        max_high_findings: 5,
        block_npx_mcp_servers: true,
        block_unencrypted_mcp: true,
        block_mcp_hardcoded_credentials: true,
        max_mcp_issues: 0,
        require_ai_sbom: false,
        allowed_ai_sdks: [],
      },
    };

    fs.writeFileSync(policyPath, JSON.stringify(defaultContent, null, 2));
    this.policyFilePath = policyPath;
    this.policy = defaultContent;

    return policyPath;
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  private loadPolicy(filePath: string): void {
    try {
      const raw = fs.readFileSync(filePath, 'utf-8');
      let parsed: PolicyConfig;

      if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
        // Simple YAML parsing (key: value) — no external dependency
        parsed = this.parseSimpleYaml(raw);
      } else {
        parsed = JSON.parse(raw);
      }

      // Validate and merge with defaults
      this.policy = {
        version: 1,
        mode: parsed.mode || DEFAULT_POLICY.mode,
        rules: { ...DEFAULT_POLICY.rules, ...parsed.rules },
      };

      this.outputChannel.appendLine(`[Policy] Loaded policy from ${filePath} (mode: ${this.policy.mode})`);
    } catch (e) {
      this.outputChannel.appendLine(`[Policy] Failed to load policy from ${filePath}: ${e}`);
      this.policy = DEFAULT_POLICY;
    }
  }

  /**
   * Very simple YAML parser for flat key-value policy files.
   * For complex YAML, users should use .json instead.
   */
  private parseSimpleYaml(raw: string): PolicyConfig {
    const result: Record<string, unknown> = {};
    const rules: Record<string, unknown> = {};
    let inRules = false;

    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (trimmed.startsWith('#') || trimmed.length === 0) { continue; }

      if (trimmed === 'rules:') {
        inRules = true;
        continue;
      }

      const match = trimmed.match(/^(\w+)\s*:\s*(.+)$/);
      if (!match) { continue; }

      const key = match[1];
      let value: unknown = match[2].trim();

      // Parse value types
      if (value === 'true') { value = true; }
      else if (value === 'false') { value = false; }
      else if (/^\d+(\.\d+)?$/.test(value as string)) { value = parseFloat(value as string); }
      else if ((value as string).startsWith('[') && (value as string).endsWith(']')) {
        try { value = JSON.parse(value as string); } catch { /* keep as string */ }
      }

      if (inRules && line.startsWith('  ')) {
        rules[key] = value;
      } else {
        result[key] = value;
        inRules = false;
      }
    }

    return {
      version: 1,
      mode: (result['mode'] as PolicyMode) || 'warn',
      rules: rules as unknown as PolicyRules,
    };
  }

  clearDiagnostics(uri: vscode.Uri): void {
    this.diagnosticCollection.delete(uri);
  }

  dispose(): void {
    for (const d of this.disposables) { d.dispose(); }
    this.diagnosticCollection.dispose();
    this.outputChannel.dispose();
    this.fileWatcher?.dispose();
  }
}
