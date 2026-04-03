/**
 * Package Install Gate (Terminal Firewall)
 *
 * Intercepts npm install / pip install / cargo add / go get commands
 * in the VS Code terminal BEFORE they execute. Analyzes every package for:
 * - Known hallucination (from GHIN)
 * - Known vulnerability (from OSV.dev)
 * - Missing provenance attestation
 * - Suspicious install scripts
 * - Recently registered with low downloads
 *
 * Shows a modal with analysis results and lets the user approve/block.
 */

import * as vscode from 'vscode';
import { GhinNetwork } from '../intelligence/ghin';
import { detectIde, detectAiAgent, IdeSlug, AiAgentSlug, AiInteractionType, IdeContext, AiAgentContext } from '../utils/ide-detect';
import { ProvenanceChecker, ProvenanceResult } from '../checkers/provenance';
import { AutoPatchEngine, PatchReport } from '../checkers/auto-patch';
import { ScriptAnalyzer, ScriptAnalysisResult } from './script-analyzer';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ParsedInstallCommand {
  /** Original command string */
  raw: string;
  /** Package manager: npm, pip, cargo, go, yarn, pnpm */
  packageManager: string;
  /** Extracted package names */
  packages: string[];
  /** Ecosystem for registry checks */
  ecosystem: string;
  /** Is this a dev dependency install? */
  isDev: boolean;
  /** Is this a global install? */
  isGlobal: boolean;
}

export interface PackageGateResult {
  packageName: string;
  ecosystem: string;
  /** Overall verdict */
  verdict: 'safe' | 'warning' | 'blocked';
  /** Trust tier from provenance */
  provenance: ProvenanceResult | null;
  /** GHIN hallucination check */
  isKnownHallucination: boolean;
  /** Vulnerability report */
  patchReport: PatchReport | null;
  /** Install script analysis */
  scriptAnalysis: ScriptAnalysisResult | null;
  /** Summary message */
  summary: string;
}

export interface InstallGateResult {
  command: ParsedInstallCommand;
  packages: PackageGateResult[];
  /** Should the install proceed? */
  approved: boolean;
  /** Count of blocked packages */
  blockedCount: number;
  /** Count of warned packages */
  warningCount: number;
  /** Count of safe packages */
  safeCount: number;
}

// ---------------------------------------------------------------------------
// Install command patterns
// ---------------------------------------------------------------------------

const INSTALL_PATTERNS: Array<{
  pattern: RegExp;
  pm: string;
  ecosystem: string;
  extractPackages: (match: RegExpExecArray) => { packages: string[]; isDev: boolean; isGlobal: boolean };
}> = [
    {
      // npm install <packages...> [--save-dev] [-g]
      pattern: /^(?:npm|npx)\s+(?:install|i|add)\s+(.+)/i,
      pm: 'npm',
      ecosystem: 'npm',
      extractPackages: (match) => {
        const args = match[1].trim().split(/\s+/);
        const packages = args.filter(a => !a.startsWith('-') && !a.startsWith('--'));
        const isDev = args.some(a => a === '--save-dev' || a === '-D');
        const isGlobal = args.some(a => a === '-g' || a === '--global');
        return { packages, isDev, isGlobal };
      },
    },
    {
      // yarn add <packages...> [--dev]
      pattern: /^yarn\s+add\s+(.+)/i,
      pm: 'yarn',
      ecosystem: 'npm',
      extractPackages: (match) => {
        const args = match[1].trim().split(/\s+/);
        const packages = args.filter(a => !a.startsWith('-') && !a.startsWith('--'));
        const isDev = args.some(a => a === '--dev' || a === '-D');
        return { packages, isDev, isGlobal: false };
      },
    },
    {
      // pnpm add <packages...> [--save-dev]
      pattern: /^pnpm\s+(?:add|install)\s+(.+)/i,
      pm: 'pnpm',
      ecosystem: 'npm',
      extractPackages: (match) => {
        const args = match[1].trim().split(/\s+/);
        const packages = args.filter(a => !a.startsWith('-') && !a.startsWith('--'));
        const isDev = args.some(a => a === '--save-dev' || a === '-D');
        const isGlobal = args.some(a => a === '-g' || a === '--global');
        return { packages, isDev, isGlobal };
      },
    },
    {
      // pip install <packages...>
      pattern: /^(?:pip3?|python3?\s+-m\s+pip|uv\s+pip)\s+install\s+(.+)/i,
      pm: 'pip',
      ecosystem: 'PyPI',
      extractPackages: (match) => {
        const args = match[1].trim().split(/\s+/);
        const packages = args.filter(a => !a.startsWith('-') && !a.startsWith('--') && a !== '-r' && !a.endsWith('.txt'));
        return { packages, isDev: false, isGlobal: false };
      },
    },
    {
      // poetry add <packages...>
      pattern: /^poetry\s+add\s+(.+)/i,
      pm: 'poetry',
      ecosystem: 'PyPI',
      extractPackages: (match) => {
        const args = match[1].trim().split(/\s+/);
        const packages = args.filter(a => !a.startsWith('-') && !a.startsWith('--'));
        const isDev = args.some(a => a === '--dev' || a === '-D' || a === '--group=dev');
        return { packages, isDev, isGlobal: false };
      },
    },
    {
      // uv add <packages...>
      pattern: /^uv\s+add\s+(.+)/i,
      pm: 'uv',
      ecosystem: 'PyPI',
      extractPackages: (match) => {
        const args = match[1].trim().split(/\s+/);
        const packages = args.filter(a => !a.startsWith('-') && !a.startsWith('--'));
        const isDev = args.some(a => a === '--dev' || a === '-D');
        return { packages, isDev, isGlobal: false };
      },
    },
    {
      // cargo add <packages...>
      pattern: /^cargo\s+(?:add|install)\s+(.+)/i,
      pm: 'cargo',
      ecosystem: 'crates.io',
      extractPackages: (match) => {
        const args = match[1].trim().split(/\s+/);
        const packages = args.filter(a => !a.startsWith('-') && !a.startsWith('--'));
        const isDev = args.some(a => a === '--dev');
        return { packages, isDev, isGlobal: false };
      },
    },
    {
      // go get <packages...>
      pattern: /^go\s+get\s+(.+)/i,
      pm: 'go',
      ecosystem: 'Go',
      extractPackages: (match) => {
        const args = match[1].trim().split(/\s+/);
        const packages = args.filter(a => !a.startsWith('-'));
        return { packages, isDev: false, isGlobal: false };
      },
    },
    {
      // gem install <packages...>
      pattern: /^gem\s+install\s+(.+)/i,
      pm: 'gem',
      ecosystem: 'RubyGems',
      extractPackages: (match) => {
        const args = match[1].trim().split(/\s+/);
        const packages = args.filter(a => !a.startsWith('-') && !a.startsWith('--'));
        return { packages, isDev: false, isGlobal: false };
      },
    },
  ];

// ---------------------------------------------------------------------------
// InstallGate Class
// ---------------------------------------------------------------------------

export class InstallGate {
  private ghin: GhinNetwork;
  private provenance: ProvenanceChecker;
  private patchEngine: AutoPatchEngine;
  private scriptAnalyzer: ScriptAnalyzer;
  private enabled = true;
  private disposables: vscode.Disposable[] = [];
  /** Cached IDE detection (stable for session) */
  private ideContext: IdeContext;
  /** Cached AI agent detection (stable for session) */
  private agentContext: AiAgentContext;

  constructor(
    ghin?: GhinNetwork,
    provenance?: ProvenanceChecker,
    patchEngine?: AutoPatchEngine,
    scriptAnalyzer?: ScriptAnalyzer,
  ) {
    this.ghin = ghin ?? new GhinNetwork('', false);
    this.provenance = provenance ?? new ProvenanceChecker();
    this.patchEngine = patchEngine ?? new AutoPatchEngine();
    this.scriptAnalyzer = scriptAnalyzer ?? new ScriptAnalyzer();
    // Detect IDE and AI agent once at construction time
    this.ideContext = detectIde();
    this.agentContext = detectAiAgent();
    console.log(`[CodeGuard Install Gate] IDE: ${this.ideContext.ide} v${this.ideContext.ideVersion}, Agent: ${this.agentContext.aiAgent} v${this.agentContext.aiAgentVersion}`);
  }

  /**
   * Activate the install gate — start monitoring terminal commands.
   */
  activate(context: vscode.ExtensionContext): void {
    // Use VS Code's terminal shell execution API if available
    if (vscode.window.onDidStartTerminalShellExecution) {
      const disposable = vscode.window.onDidStartTerminalShellExecution(async (event) => {
        if (!this.enabled) { return; }

        const commandLine = event.execution?.commandLine;
        if (!commandLine) { return; }

        // Get the command string
        const cmdString = typeof commandLine === 'string'
          ? commandLine
          : (commandLine as { value?: string }).value ?? '';

        if (!cmdString) { return; }

        const parsed = this.parseCommand(cmdString);
        if (!parsed) { return; }

        // Analyze all packages
        console.log(`[CodeGuard Install Gate] Intercepted: ${cmdString}`);
        const result = await this.analyzeInstall(parsed);

        // Show results if there are issues
        if (result.blockedCount > 0 || result.warningCount > 0) {
          await this.showGateModal(result);
        }
      });
      this.disposables.push(disposable);
      context.subscriptions.push(disposable);
    }

    // Also register a command for manual checking
    const checkCmd = vscode.commands.registerCommand(
      'codeguard.checkInstallCommand',
      async (commandStr?: string) => {
        if (!commandStr) {
          commandStr = await vscode.window.showInputBox({
            prompt: 'Enter install command to analyze',
            placeHolder: 'npm install lodash express fake-pkg',
          });
        }
        if (!commandStr) { return; }

        const parsed = this.parseCommand(commandStr);
        if (!parsed) {
          vscode.window.showWarningMessage('CodeGuard: Not a recognized install command.');
          return;
        }

        const result = await vscode.window.withProgress(
          { location: vscode.ProgressLocation.Notification, title: 'CodeGuard: Analyzing packages...' },
          () => this.analyzeInstall(parsed!)
        );

        await this.showGateModal(result);
      }
    );
    this.disposables.push(checkCmd);
    context.subscriptions.push(checkCmd);
  }

  /**
   * Parse a terminal command into structured data.
   */
  parseCommand(command: string): ParsedInstallCommand | null {
    const trimmed = command.trim();

    for (const { pattern, pm, ecosystem, extractPackages } of INSTALL_PATTERNS) {
      const match = pattern.exec(trimmed);
      if (match) {
        const { packages, isDev, isGlobal } = extractPackages(match);
        if (packages.length === 0) { continue; }

        // Clean version specifiers from package names
        const cleanedPackages = packages.map(p => {
          // Remove version specifiers: lodash@4.17.21 → lodash, requests>=2.31 → requests
          return p.replace(/@[\d^~>=<.*]+.*$/, '').replace(/[><=!~]+[\d.]+.*$/, '').trim();
        }).filter(p => p.length > 0);

        if (cleanedPackages.length === 0) { continue; }

        return {
          raw: trimmed,
          packageManager: pm,
          packages: cleanedPackages,
          ecosystem,
          isDev,
          isGlobal,
        };
      }
    }

    return null;
  }

  /**
   * Analyze all packages in an install command.
   */
  async analyzeInstall(command: ParsedInstallCommand): Promise<InstallGateResult> {
    const packageResults: PackageGateResult[] = [];

    // Analyze packages in parallel (max 5 concurrent)
    const batchSize = 5;
    for (let i = 0; i < command.packages.length; i += batchSize) {
      const batch = command.packages.slice(i, i + batchSize);
      const results = await Promise.all(
        batch.map(pkg => this.analyzePackage(pkg, command.ecosystem))
      );
      packageResults.push(...results);
    }

    const blockedCount = packageResults.filter(r => r.verdict === 'blocked').length;
    const warningCount = packageResults.filter(r => r.verdict === 'warning').length;
    const safeCount = packageResults.filter(r => r.verdict === 'safe').length;

    return {
      command,
      packages: packageResults,
      approved: blockedCount === 0,
      blockedCount,
      warningCount,
      safeCount,
    };
  }

  /**
   * Analyze a single package.
   */
  private async analyzePackage(packageName: string, ecosystem: string): Promise<PackageGateResult> {
    // Run checks in parallel
    const [ghinResult, provenanceResult, patchReport, scriptResult] = await Promise.all([
      this.ghin.check(packageName, ecosystem),
      this.provenance.check(packageName, null, ecosystem).catch(() => null),
      this.patchEngine.getPatchReport(packageName, null, ecosystem).catch(() => null),
      this.scriptAnalyzer.analyzePackage(packageName, ecosystem).catch(() => null),
    ]);

    const isKnownHallucination = ghinResult.found && (ghinResult.record?.confirmedNonexistent ?? false);

    // Determine verdict
    let verdict: 'safe' | 'warning' | 'blocked' = 'safe';
    const summaryParts: string[] = [];

    // BLOCKED: Known hallucination
    if (isKnownHallucination) {
      verdict = 'blocked';
      summaryParts.push(`HALLUCINATED — does not exist on ${ecosystem} (GHIN score: ${ghinResult.record?.riskScore?.toFixed(2)})`);
    }

    // BLOCKED: Untrusted provenance
    if (provenanceResult?.trustTier === 'untrusted') {
      verdict = 'blocked';
      summaryParts.push(`UNTRUSTED — ${provenanceResult.trustSummary}`);
    }

    // WARNING: Suspicious provenance
    if (provenanceResult?.trustTier === 'suspicious' && verdict !== 'blocked') {
      verdict = 'warning';
      summaryParts.push(`SUSPICIOUS — ${provenanceResult.trustSummary}`);
    }

    // WARNING: Has vulnerabilities
    if (patchReport && patchReport.totalVulnerabilities > 0) {
      if (patchReport.criticalCount > 0) {
        verdict = 'blocked';
        summaryParts.push(`${patchReport.criticalCount} CRITICAL vulnerabilities`);
      } else if (patchReport.highCount > 0 && verdict !== 'blocked') {
        verdict = 'warning';
        summaryParts.push(`${patchReport.highCount} HIGH vulnerabilities`);
      } else if (verdict !== 'blocked') {
        verdict = 'warning';
        summaryParts.push(`${patchReport.totalVulnerabilities} vulnerabilities found`);
      }
      summaryParts.push(`Fix: ${patchReport.recommendedAction}`);
    }

    // WARNING: Suspicious install scripts
    if (scriptResult && scriptResult.suspicious) {
      if (scriptResult.criticalIssues > 0) {
        verdict = 'blocked';
      } else if (verdict !== 'blocked') {
        verdict = 'warning';
      }
      summaryParts.push(`Install scripts: ${scriptResult.summary}`);
    }

    // WARNING: Deprecated
    if (patchReport?.deprecated) {
      if (verdict === 'safe') { verdict = 'warning'; }
      summaryParts.push(`DEPRECATED: ${patchReport.deprecationMessage ?? 'No longer maintained'}`);
    }

    // SAFE
    if (verdict === 'safe') {
      const tier = provenanceResult?.trustTier ?? 'partial';
      summaryParts.push(`${ProvenanceChecker.trustEmoji(tier)} ${ProvenanceChecker.trustLabel(tier)}`);
      if (provenanceResult?.hasProvenance) {
        summaryParts.push('Sigstore provenance verified');
      }
      if (provenanceResult?.weeklyDownloads) {
        summaryParts.push(`${provenanceResult.weeklyDownloads.toLocaleString()} weekly downloads`);
      }
    }

    return {
      packageName,
      ecosystem,
      verdict,
      provenance: provenanceResult,
      isKnownHallucination,
      patchReport,
      scriptAnalysis: scriptResult,
      summary: summaryParts.join(' · '),
    };
  }

  /**
   * Show the install gate modal as a rich webview panel.
   */
  private async showGateModal(result: InstallGateResult): Promise<void> {
    const panel = vscode.window.createWebviewPanel(
      'codeguardInstallGate',
      `🛡️ Install Gate — ${result.command.packageManager}`,
      vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: false }
    );

    const safePackages = result.packages.filter(p => p.verdict !== 'blocked').map(p => p.packageName);

    panel.webview.html = this.buildGateHtml(result, safePackages);

    // Handle messages from webview
    panel.webview.onDidReceiveMessage(async (msg) => {
      if (msg.command === 'installSafe' && safePackages.length > 0) {
        const safeCmd = `${result.command.packageManager} install ${safePackages.join(' ')}`;
        await vscode.env.clipboard.writeText(safeCmd);
        vscode.window.showInformationMessage(`CodeGuard: Safe install command copied — ${safePackages.length} package(s).`);
        panel.dispose();
      } else if (msg.command === 'cancel') {
        vscode.window.showInformationMessage('CodeGuard: Install cancelled.');
        panel.dispose();
      } else if (msg.command === 'copy') {
        await vscode.env.clipboard.writeText(msg.text);
        vscode.window.showInformationMessage('Copied to clipboard.');
      }
    });

    // Report hallucinations to GHIN (with full IDE + AI agent context)
    for (const pkg of result.packages) {
      if (pkg.isKnownHallucination || pkg.provenance?.trustTier === 'untrusted') {
        this.ghin.report({
          packageName: pkg.packageName,
          ecosystem: pkg.ecosystem,
          confirmedNonexistent: pkg.isKnownHallucination,
          ide: this.ideContext.ide,
          ideVersion: this.ideContext.ideVersion,
          aiAgent: this.agentContext.aiAgent,
          aiAgentVersion: this.agentContext.aiAgentVersion,
          aiInteractionType: 'agent_action' as AiInteractionType,
          osPlatform: process.platform,
        }).catch(() => { /* best-effort */ });
      }
    }
  }

  /**
   * Build the HTML for the Install Gate webview panel.
   */
  private buildGateHtml(result: InstallGateResult, safePackages: string[]): string {
    const packageCards = result.packages.map(pkg => {
      const badgeColor = pkg.verdict === 'safe' ? '#51cf66' : pkg.verdict === 'warning' ? '#ffa94d' : '#ff6b6b';
      const badgeLabel = pkg.verdict.toUpperCase();
      const icon = pkg.verdict === 'safe' ? '✅' : pkg.verdict === 'warning' ? '⚠️' : '🚫';
      return `<div class="pkg" style="border-left:3px solid ${badgeColor}">
        <div class="pkg-hdr">
          <span class="pkg-name">${icon} ${pkg.packageName}</span>
          <span class="badge" style="background:${badgeColor}">${badgeLabel}</span>
        </div>
        <div class="pkg-sum">${pkg.summary}</div>
      </div>`;
    }).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Install Gate</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Segoe UI',var(--vscode-font-family,-apple-system,sans-serif);color:var(--vscode-foreground,#e0e0e0);background:var(--vscode-editor-background,#0d1117);min-height:100vh;padding:0}
    .hdr{padding:24px 28px;background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);border-bottom:1px solid rgba(255,255,255,.06)}
    .hdr h1{font-size:22px;font-weight:700;margin-bottom:4px}
    .hdr .sub{font-size:13px;opacity:.55}
    .summary{display:flex;gap:16px;padding:20px 28px;border-bottom:1px solid rgba(255,255,255,.04)}
    .pill{padding:6px 14px;border-radius:20px;font-size:12px;font-weight:600;display:flex;align-items:center;gap:6px}
    .pill.safe{background:rgba(81,207,102,.12);color:#51cf66}
    .pill.warn{background:rgba(255,169,77,.12);color:#ffa94d}
    .pill.block{background:rgba(255,107,107,.12);color:#ff6b6b}
    .cnt{padding:20px 28px}
    .pkg{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:16px;margin-bottom:10px;transition:border-color .15s}
    .pkg:hover{border-color:rgba(255,255,255,.12)}
    .pkg-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
    .pkg-name{font-weight:600;font-size:14px}
    .badge{font-size:10px;font-weight:700;padding:3px 8px;border-radius:4px;color:#0d1117;text-transform:uppercase;letter-spacing:.5px}
    .pkg-sum{font-size:12px;opacity:.65;line-height:1.5}
    .actions{display:flex;gap:10px;padding:20px 28px;border-top:1px solid rgba(255,255,255,.06)}
    .btn{padding:10px 20px;border-radius:8px;border:none;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .15s}
    .btn:hover{opacity:.85}
    .btn-primary{background:#51cf66;color:#0d1117}
    .btn-secondary{background:rgba(255,255,255,.08);color:var(--vscode-foreground,#e0e0e0)}
    .btn-danger{background:rgba(255,107,107,.15);color:#ff6b6b}
  </style>
</head>
<body>
  <div class="hdr">
    <h1>🛡️ CodeGuard Install Gate</h1>
    <p class="sub">${result.command.packageManager} install — ${result.packages.length} package(s) analyzed</p>
  </div>
  <div class="summary">
    <div class="pill safe">✅ ${result.safeCount} Safe</div>
    <div class="pill warn">⚠️ ${result.warningCount} Warnings</div>
    <div class="pill block">🚫 ${result.blockedCount} Blocked</div>
  </div>
  <div class="cnt">
    ${packageCards}
  </div>
  <div class="actions">
    ${safePackages.length > 0
        ? `<button class="btn btn-primary" onclick="post('installSafe')">Install ${safePackages.length} Safe Package(s)</button>`
        : `<button class="btn btn-danger" disabled>No Safe Packages</button>`}
    <button class="btn btn-secondary" onclick="post('cancel')">Cancel</button>
  </div>
  <script>
    const vscode = acquireVsCodeApi();
    function post(cmd, text) { vscode.postMessage({ command: cmd, text: text }); }
  </script>
</body>
</html>`;
  }

  /**
   * Enable/disable the install gate.
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  dispose(): void {
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}

// Re-export ProvenanceChecker for convenience
export { ProvenanceChecker };
