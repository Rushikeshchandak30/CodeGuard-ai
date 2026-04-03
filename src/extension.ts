import * as vscode from 'vscode';
import * as fs from 'fs';
import { SecurityChecker } from './checkers/index';
import { Cache } from './cache/cache';
import { DiagnosticsProvider } from './diagnostics/provider';
import { CodeGuardCodeActionProvider } from './diagnostics/codeactions';
import { StatusBar } from './ui/statusbar';
import { HoverProvider } from './ui/hover';
import { DocumentWatcher } from './watcher';
import { Config } from './config';
import { SecurityCodeLensProvider } from './ai/feedback';
import { SecurityContextProvider } from './ai/context';
import { CodeGuardChatParticipant } from './ai/chat-participant';
// v3 imports
import { RulesFileScanner } from './shield/rules-scanner';
import { GhinNetwork } from './intelligence/ghin';
import { ProvenanceChecker } from './checkers/provenance';
import { AutoPatchEngine } from './checkers/auto-patch';
import { ScriptAnalyzer } from './shield/script-analyzer';
import { InstallGate } from './shield/install-gate';
import { LlmAdvisor } from './ai/llm-advisor';
import { IntentVerifierCompletionMiddleware } from './ai/intent-verifier';
import { PatchAgent } from './ai/patch-agent';
import { SbomGenerator } from './sbom/generator';
import { registerTrustTreeView, TrustTreeProvider } from './ui/trust-tree';
import { SecretsChecker } from './checkers/secrets-checker';
import { CodeVulnChecker } from './checkers/code-vuln-checker';
import { SecurityScoreEngine } from './scoring/security-score';
import { SbomDriftDetector } from './sbom/drift';
// v4 imports
import { PermissionModel } from './shield/permission-model';
import { TrustScoreEngine } from './intelligence/trust-score';
import { GhinClient } from './intelligence/ghin-client';
import { registerFindingsTreeView, FindingsTreeProvider } from './ui/findings-tree';
import { TelemetryReporter } from './intelligence/telemetry';
import { ScoreHistory } from './scoring/score-history';
// v5 imports
import { HybridSastEngine } from './checkers/hybrid-sast';
import { TaintTracker } from './analysis/taint-tracker';
import { CodeAttributionEngine } from './ai/code-attribution';
import { PolicyEngine } from './policy/engine';
import { GitRegressionDetector } from './analysis/git-regression';
import { SandboxRunner } from './shield/sandbox-runner';
import { ComplianceReportGenerator } from './reports/compliance';
// v6 imports
import { McpServerScanner } from './shield/mcp-scanner';
import { ShadowAiDiscovery } from './shield/shadow-ai-discovery';

let watcher: DocumentWatcher | undefined;
let cache: Cache | undefined;
let diagnosticsProvider: DiagnosticsProvider | undefined;
let statusBar: StatusBar | undefined;
let hoverProvider: HoverProvider | undefined;
let codeLensProvider: SecurityCodeLensProvider | undefined;
let contextProvider: SecurityContextProvider | undefined;
let chatParticipant: CodeGuardChatParticipant | undefined;
// v3 module instances
let rulesScanner: RulesFileScanner | undefined;
let ghin: GhinNetwork | undefined;
let provenanceChecker: ProvenanceChecker | undefined;
let autoPatchEngine: AutoPatchEngine | undefined;
let scriptAnalyzer: ScriptAnalyzer | undefined;
let installGate: InstallGate | undefined;
let llmAdvisor: LlmAdvisor | undefined;
let intentVerifier: IntentVerifierCompletionMiddleware | undefined;
let patchAgent: PatchAgent | undefined;
let sbomGenerator: SbomGenerator | undefined;
let trustTreeProvider: TrustTreeProvider | undefined;
let secretsChecker: SecretsChecker | undefined;
let codeVulnChecker: CodeVulnChecker | undefined;
let securityScore: SecurityScoreEngine | undefined;
let sbomDrift: SbomDriftDetector | undefined;
// v4 module instances
let permissionModel: PermissionModel | undefined;
let trustScoreEngine: TrustScoreEngine | undefined;
let ghinClient: GhinClient | undefined;
let findingsProvider: FindingsTreeProvider | undefined;
let telemetryReporter: TelemetryReporter | undefined;
let scoreHistory: ScoreHistory | undefined;
// v5 module instances
let hybridSast: HybridSastEngine | undefined;
let taintTracker: TaintTracker | undefined;
let codeAttribution: CodeAttributionEngine | undefined;
let policyEngine: PolicyEngine | undefined;
let gitRegression: GitRegressionDetector | undefined;
let sandboxRunner: SandboxRunner | undefined;
let complianceReport: ComplianceReportGenerator | undefined;
// v6 module instances
let mcpScanner: McpServerScanner | undefined;
let shadowAiDiscovery: ShadowAiDiscovery | undefined;

/**
 * Extension entry point â€” called when VS Code activates the extension.
 */
export function activate(context: vscode.ExtensionContext) {
  console.log('[CodeGuard AI] v5 Activating — Security Immune System...');

  try {
    activateCore(context);
  } catch (err) {
    console.error('[CodeGuard AI] FATAL activation error:', err);
    vscode.window.showErrorMessage(`CodeGuard AI failed to activate: ${err}. Check the Output panel for details.`);
  }
}

function activateCore(context: vscode.ExtensionContext) {
  // Initialize cache with persistence in extension storage
  const cachePath = context.globalStorageUri.fsPath;
  cache = new Cache(Config.cacheTtlMinutes, cachePath);

  // Initialize core components
  diagnosticsProvider = new DiagnosticsProvider();
  statusBar = new StatusBar();
  hoverProvider = new HoverProvider();

  // Initialize v2 components
  codeLensProvider = new SecurityCodeLensProvider();
  contextProvider = new SecurityContextProvider();

  // Initialize v3 components (each wrapped so one failure doesn't crash the rest)
  try {
    ghin = new GhinNetwork(cachePath, Config.enableGhinCloudSync);
  } catch (e) { console.error('[CodeGuard] GHIN init failed:', e); }

  try {
    provenanceChecker = new ProvenanceChecker();
    autoPatchEngine = new AutoPatchEngine();
    scriptAnalyzer = new ScriptAnalyzer();
  } catch (e) { console.error('[CodeGuard] Checker init failed:', e); }

  // Rules File Integrity Scanner
  try {
    if (Config.enableRulesScanner) {
      rulesScanner = new RulesFileScanner();
      rulesScanner.activate(context);
      console.log('[CodeGuard AI] Rules File Scanner activated.');
    }
  } catch (e) { console.error('[CodeGuard] Rules Scanner init failed:', e); }

  // Install Gate (Terminal Firewall)
  try {
    if (Config.enableInstallGate) {
      installGate = new InstallGate(ghin, provenanceChecker, autoPatchEngine, scriptAnalyzer);
      installGate.activate(context);
      console.log('[CodeGuard AI] Install Gate activated.');
    }
  } catch (e) { console.error('[CodeGuard] Install Gate init failed:', e); }

  // LLM Advisory Layer
  try {
    llmAdvisor = new LlmAdvisor();
    if (llmAdvisor.isAvailable()) {
      console.log('[CodeGuard AI] LLM Advisory Layer available.');
    }
  } catch (e) { console.error('[CodeGuard] LLM Advisor init failed:', e); }

  // Semantic Intent Verifier
  try {
    intentVerifier = new IntentVerifierCompletionMiddleware();
    context.subscriptions.push({ dispose: () => intentVerifier?.dispose() });
  } catch (e) { console.error('[CodeGuard] Intent Verifier init failed:', e); }

  // Agentic Patch Assistant
  try {
    patchAgent = new PatchAgent(autoPatchEngine);
  } catch (e) { console.error('[CodeGuard] Patch Agent init failed:', e); }

  // SBOM Generator
  try {
    sbomGenerator = new SbomGenerator();
    sbomGenerator.activate(context);
    console.log('[CodeGuard AI] SBOM Generator activated.');
  } catch (e) { console.error('[CodeGuard] SBOM Generator init failed:', e); }

  // Trust Tier Tree View (sidebar)
  try {
    trustTreeProvider = registerTrustTreeView(context, provenanceChecker);
  } catch (e) { console.error('[CodeGuard] Trust Tree View init failed:', e); }

  // Secrets Checker (hardcoded credentials)
  try {
    secretsChecker = new SecretsChecker();
    console.log('[CodeGuard AI] Secrets Checker activated.');
  } catch (e) { console.error('[CodeGuard] Secrets Checker init failed:', e); }

  // Code Vulnerability Checker (SAST patterns)
  try {
    codeVulnChecker = new CodeVulnChecker();
    console.log('[CodeGuard AI] Code Vulnerability Checker (SAST) activated.');
  } catch (e) { console.error('[CodeGuard] Code Vuln Checker init failed:', e); }

  // Security Score Engine
  try {
    securityScore = new SecurityScoreEngine();
    securityScore.show();
    console.log('[CodeGuard AI] Security Score Engine activated.');
  } catch (e) { console.error('[CodeGuard] Security Score init failed:', e); }

  // SBOM Drift Detector
  try {
    sbomDrift = new SbomDriftDetector();
    console.log('[CodeGuard AI] SBOM Drift Detector activated.');
  } catch (e) { console.error('[CodeGuard] SBOM Drift init failed:', e); }

  // v4: Dependency Permission Model
  try {
    permissionModel = new PermissionModel();
    console.log('[CodeGuard AI] Permission Model activated.');
  } catch (e) { console.error('[CodeGuard] Permission Model init failed:', e); }

  // v4: Composite Trust Score Engine
  try {
    trustScoreEngine = new TrustScoreEngine();
    console.log('[CodeGuard AI] Trust Score Engine activated.');
  } catch (e) { console.error('[CodeGuard] Trust Score Engine init failed:', e); }

  // v4: GHIN Production Client
  try {
    ghinClient = new GhinClient(Config.ghinApiUrl);
    console.log('[CodeGuard AI] GHIN Client activated.');
  } catch (e) { console.error('[CodeGuard] GHIN Client init failed:', e); }

  // v4: Findings TreeView (sidebar â€” severity-grouped)
  try {
    findingsProvider = registerFindingsTreeView(context);
    console.log('[CodeGuard AI] Findings TreeView activated.');
  } catch (e) { console.error('[CodeGuard] Findings TreeView init failed:', e); }

  // v4: Telemetry Reporter (opt-in)
  try {
    if (ghinClient) {
      telemetryReporter = new TelemetryReporter(ghinClient);
      context.subscriptions.push({ dispose: () => telemetryReporter?.dispose() });
    }
    console.log('[CodeGuard AI] Telemetry Reporter activated.');
  } catch (e) { console.error('[CodeGuard] Telemetry Reporter init failed:', e); }

  // v4: Score History
  try {
    scoreHistory = new ScoreHistory();
    console.log('[CodeGuard AI] Score History activated.');
  } catch (e) { console.error('[CodeGuard] Score History init failed:', e); }

  // v5: Hybrid SAST Engine (regex + LLM deep + adversarial verification)
  try {
    hybridSast = new HybridSastEngine();
    console.log(`[CodeGuard AI] Hybrid SAST activated (${hybridSast.ruleCount} rules, LLM: ${hybridSast.isLlmAvailable ? 'ON' : 'OFF'}).`);
  } catch (e) { console.error('[CodeGuard] Hybrid SAST init failed:', e); }

  // v5: Cross-File Taint Tracker
  try {
    taintTracker = new TaintTracker();
    taintTracker.activate(context);
    console.log('[CodeGuard AI] Taint Tracker activated.');
  } catch (e) { console.error('[CodeGuard] Taint Tracker init failed:', e); }

  // v5: AI Code Attribution Engine
  try {
    codeAttribution = new CodeAttributionEngine();
    codeAttribution.activate(context);
    console.log('[CodeGuard AI] Code Attribution Engine activated.');
  } catch (e) { console.error('[CodeGuard] Code Attribution init failed:', e); }

  // v5: Policy-as-Code Engine
  try {
    policyEngine = new PolicyEngine();
    policyEngine.activate(context);
    console.log(`[CodeGuard AI] Policy Engine activated (policy file: ${policyEngine.hasPolicyFile() ? 'found' : 'using defaults'}).`);
  } catch (e) { console.error('[CodeGuard] Policy Engine init failed:', e); }

  // v5: Git Security Regression Detector
  try {
    gitRegression = new GitRegressionDetector();
    gitRegression.activate(context);
    console.log('[CodeGuard AI] Git Regression Detector activated.');
  } catch (e) { console.error('[CodeGuard] Git Regression init failed:', e); }

  // v5: Sandbox Runner (used by Install Gate)
  try {
    sandboxRunner = new SandboxRunner();
    console.log('[CodeGuard AI] Sandbox Runner activated.');
  } catch (e) { console.error('[CodeGuard] Sandbox Runner init failed:', e); }

  // v5.2: Compliance Report Generator
  try {
    complianceReport = new ComplianceReportGenerator();
    console.log('[CodeGuard AI] Compliance Report Generator activated.');
  } catch (e) { console.error('[CodeGuard] Compliance Report init failed:', e); }

  // v6: MCP Server Scanner (Agentic Supply Chain Security)
  try {
    mcpScanner = new McpServerScanner();
    mcpScanner.activate(context);
    console.log('[CodeGuard AI] MCP Server Scanner activated.');
  } catch (e) { console.error('[CodeGuard] MCP Scanner init failed:', e); }

  // v6: Shadow AI Discovery
  try {
    shadowAiDiscovery = new ShadowAiDiscovery();
    console.log('[CodeGuard AI] Shadow AI Discovery activated.');
  } catch (e) { console.error('[CodeGuard] Shadow AI Discovery init failed:', e); }

  const checker = new SecurityChecker(cache, Config.enableHallucinationDetection);

  // Initialize document watcher (the core real-time engine, now with AI detection)
  watcher = new DocumentWatcher(
    checker, diagnosticsProvider, statusBar, hoverProvider,
    codeLensProvider, contextProvider
  );
  watcher.activate();

  // Wire Secrets + SAST + v5 checkers into document change events
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(async (doc) => {
      try { await secretsChecker?.scan(doc); } catch { /* silent */ }
      try { await codeVulnChecker?.scan(doc); } catch { /* silent */ }
      try { await hybridSast?.scan(doc); } catch { /* silent */ }
      try { policyEngine?.evaluateDocument(doc); } catch { /* silent */ }
    }),
    vscode.workspace.onDidChangeTextDocument(async (e) => {
      try { await secretsChecker?.scan(e.document); } catch { /* silent */ }
      try { await codeVulnChecker?.scan(e.document); } catch { /* silent */ }
      try { await hybridSast?.scan(e.document); } catch { /* silent */ }
      try { policyEngine?.evaluateDocument(e.document); } catch { /* silent */ }
    }),
    vscode.workspace.onDidCloseTextDocument((doc) => {
      secretsChecker?.clearDiagnostics(doc.uri);
      codeVulnChecker?.clearDiagnostics(doc.uri);
      hybridSast?.clearDiagnostics(doc.uri);
      policyEngine?.clearDiagnostics(doc.uri);
    })
  );

  // Scan already-open documents on activation
  for (const doc of vscode.workspace.textDocuments) {
    secretsChecker?.scan(doc).catch(() => { /* silent */ });
    codeVulnChecker?.scan(doc).catch(() => { /* silent */ });
    hybridSast?.scan(doc).catch(() => { /* silent */ });
  }

  // Register hover provider for all supported languages
  const supportedLanguages = [
    'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
    'python', 'go', 'java', 'rust', 'json',
  ];
  for (const lang of supportedLanguages) {
    context.subscriptions.push(
      vscode.languages.registerHoverProvider({ language: lang }, hoverProvider)
    );
  }

  // Register CodeAction provider (quick-fixes)
  const codeActionLanguages = supportedLanguages.map(lang => ({ language: lang }));
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      codeActionLanguages,
      new CodeGuardCodeActionProvider(),
      { providedCodeActionKinds: CodeGuardCodeActionProvider.providedCodeActionKinds }
    )
  );

  // Register CodeLens provider (Ask AI to Fix buttons)
  if (Config.enableCodeLens) {
    for (const lang of supportedLanguages) {
      context.subscriptions.push(
        vscode.languages.registerCodeLensProvider({ language: lang }, codeLensProvider)
      );
    }
  }

  // Register Chat Participant (@codeguard in Copilot Chat)
  if (Config.enableChatParticipant) {
    chatParticipant = new CodeGuardChatParticipant(contextProvider);
    chatParticipant.register(context);
  }

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.scanCurrentFile', () => {
      watcher?.scanCurrentFile();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.scanWorkspace', () => {
      watcher?.scanWorkspace();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.clearCache', () => {
      cache?.clear();
      vscode.window.showInformationMessage('CodeGuard: Vulnerability cache cleared.');
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.showDashboard', () => {
      showDashboard(context);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.ignorePackage', (packageName: string) => {
      const config = vscode.workspace.getConfiguration('codeguard');
      const current = config.get<string[]>('ignoredPackages', []);
      if (!current.includes(packageName)) {
        current.push(packageName);
        config.update('ignoredPackages', current, vscode.ConfigurationTarget.Workspace);
        vscode.window.showInformationMessage(`CodeGuard: "${packageName}" added to ignore list.`);
      }
    })
  );

  // "Ask AI to Fix" command â€” opens Copilot Chat with pre-filled prompt
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.askAiToFix', async (
      prompt: string,
      documentUri: vscode.Uri,
      line: number
    ) => {
      // Try to use Copilot Chat API
      try {
        await vscode.commands.executeCommand(
          'workbench.action.chat.open',
          { query: `@codeguard fix\n\n${prompt}` }
        );
      } catch {
        // Fallback: copy prompt to clipboard and show message
        await vscode.env.clipboard.writeText(prompt);
        vscode.window.showInformationMessage(
          'CodeGuard: Fix prompt copied to clipboard. Paste it in your AI assistant chat.',
          'Open Chat'
        ).then(selection => {
          if (selection === 'Open Chat') {
            vscode.commands.executeCommand('workbench.action.chat.open');
          }
        });
      }
    })
  );

  // "Show Issue Details" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.showIssueDetails', (items: unknown[]) => {
      // Show a quick pick with all issue details
      const picks = (items as Array<{ message: string; fixSuggestion: string; packageName: string }>).map(item => ({
        label: `$(warning) ${item.packageName}`,
        description: item.message,
        detail: item.fixSuggestion,
      }));
      vscode.window.showQuickPick(picks, { title: 'CodeGuard AI â€” Security Issues' });
    })
  );

  // "Get Security Context" command (for other extensions to call)
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.getSecurityContext', () => {
      return contextProvider?.getContext();
    })
  );

  // "Get AI Prompt Context" command (security context formatted for AI prompts)
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.getAiPromptContext', () => {
      return contextProvider?.getAiPromptContext();
    })
  );

  // v3 Commands

  // "Scan Rules Files" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.scanRulesFiles', async () => {
      if (!rulesScanner) {
        vscode.window.showWarningMessage('CodeGuard: Rules File Scanner is disabled.');
        return;
      }
      const results = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'CodeGuard: Scanning AI config files...' },
        () => rulesScanner!.scanAllConfigFiles()
      );
      const status = rulesScanner.getStatus();
      if (status.clean) {
        vscode.window.showInformationMessage(`CodeGuard: ${status.files} AI config files scanned â€” all clean. âœ…`);
      } else {
        // eslint-disable-next-line no-irregular-whitespace
        vscode.window.showWarningMessage(
          `CodeGuard: ${status.totalIssues} issues found in AI config files (${status.criticalIssues} critical). âš ï¸`,
          'Show Issues'
        ).then(action => {
          if (action === 'Show Issues') {
            vscode.commands.executeCommand('workbench.action.problems.focus');
          }
        });
      }
    })
  );

  // "Sanitize Rules File" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.sanitizeRulesFile', async (uri?: vscode.Uri) => {
      if (!rulesScanner) { return; }
      const targetUri = uri ?? vscode.window.activeTextEditor?.document.uri;
      if (!targetUri) { return; }
      const removed = await rulesScanner.sanitizeFile(targetUri);
      if (removed > 0) {
        vscode.window.showInformationMessage(`CodeGuard: Removed ${removed} hidden Unicode characters from ${targetUri.fsPath}.`);
      } else {
        vscode.window.showInformationMessage('CodeGuard: No hidden Unicode characters found.');
      }
    })
  );

  // "GHIN Stats" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.ghinStats', () => {
      if (!ghin) { return; }
      const stats = ghin.getStats();
      const lines = [
        `GHIN Database: ${stats.totalRecords} known hallucinations`,
        '',
        'Ecosystem breakdown:',
        ...Object.entries(stats.ecosystemBreakdown).map(([eco, count]) => `  ${eco}: ${count}`),
        '',
        'Top hallucinated packages:',
        ...stats.topHallucinations.slice(0, 10).map((h, i) => `  ${i + 1}. ${h.ecosystem}/${h.name} (${h.reportCount} reports)`),
      ];
      vscode.window.showInformationMessage(lines.join('\n'), { modal: true });
    })
  );

  // "Check Package Provenance" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.checkProvenance', async (packageName?: string) => {
      if (!provenanceChecker) { return; }
      if (!packageName) {
        packageName = await vscode.window.showInputBox({
          prompt: 'Enter package name to check provenance',
          placeHolder: 'e.g., express, lodash, requests',
        });
      }
      if (!packageName) { return; }

      const result = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: `CodeGuard: Checking provenance for ${packageName}...` },
        () => provenanceChecker!.check(packageName!, null, 'npm')
      );

      const emoji = ProvenanceChecker.trustEmoji(result.trustTier);
      const label = ProvenanceChecker.trustLabel(result.trustTier);
      vscode.window.showInformationMessage(
        `${emoji} ${packageName}: ${label} â€” ${result.trustSummary}`,
        { modal: false }
      );
    })
  );

  // "Get Patch Report" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.getPatchReport', async (packageName?: string, version?: string) => {
      if (!autoPatchEngine) { return; }
      if (!packageName) {
        packageName = await vscode.window.showInputBox({
          prompt: 'Enter package name (optionally @version)',
          placeHolder: 'e.g., lodash@4.17.15',
        });
      }
      if (!packageName) { return; }

      // Parse version from input
      if (packageName.includes('@') && !packageName.startsWith('@')) {
        const parts = packageName.split('@');
        packageName = parts[0];
        version = parts[1];
      }

      const report = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: `CodeGuard: Fetching patch report for ${packageName}...` },
        () => autoPatchEngine!.getPatchReport(packageName!, version ?? null, 'npm')
      );

      const md = autoPatchEngine.formatReportAsMarkdown(report);

      // Show in a webview panel
      const panel = vscode.window.createWebviewPanel(
        'codeguardPatch',
        `CodeGuard: ${packageName} Patch Report`,
        vscode.ViewColumn.Beside,
        { enableScripts: false }
      );
      panel.webview.html = `<!DOCTYPE html><html><head><style>
        body { font-family: var(--vscode-font-family); padding: 16px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
        pre { background: var(--vscode-textCodeBlock-background); padding: 8px; border-radius: 4px; overflow-x: auto; }
        code { font-family: var(--vscode-editor-font-family); }
        h2,h3 { margin-top: 16px; }
        </style></head><body>${simpleMarkdownToHtml(md)}</body></html>`;
    })
  );

  // "Run Patch Agent" command â€” agentic workflow to fix all vulnerabilities
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.runPatchAgent', async () => {
      if (!patchAgent) { return; }

      const result = await patchAgent.runWorkflow(false);

      if (result.patchesApplied > 0) {
        vscode.window.showInformationMessage(
          `âœ… CodeGuard Patch Agent: ${result.summary}`,
          'Run npm install'
        ).then(action => {
          if (action === 'Run npm install') {
            const terminal = vscode.window.createTerminal('CodeGuard');
            terminal.sendText('npm install');
            terminal.show();
          }
        });
      } else {
        vscode.window.showInformationMessage(`CodeGuard Patch Agent: ${result.summary}`);
      }
    })
  );

  // "Generate SBOM" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.generateSbom', async () => {
      if (!sbomGenerator) { return; }

      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'CodeGuard: Generating SBOM...' },
        () => sbomGenerator!.regenerate()
      );

      const bom = sbomGenerator.getBom();
      vscode.window.showInformationMessage(
        `âœ… SBOM generated: ${bom?.components.length ?? 0} components in .codeguard/sbom.cdx.json`,
        'Open SBOM'
      ).then(async action => {
        if (action === 'Open SBOM') {
          const workspaceFolders = vscode.workspace.workspaceFolders;
          if (workspaceFolders) {
            const sbomPath = vscode.Uri.joinPath(workspaceFolders[0].uri, '.codeguard', 'sbom.cdx.json');
            const doc = await vscode.workspace.openTextDocument(sbomPath);
            await vscode.window.showTextDocument(doc);
          }
        }
      });
    })
  );

  // "Explain with LLM" command â€” get AI explanation for a security issue
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.explainWithLlm', async (packageName?: string) => {
      if (!llmAdvisor || !autoPatchEngine) { return; }

      if (!packageName) {
        packageName = await vscode.window.showInputBox({
          prompt: 'Enter package name to explain',
          placeHolder: 'e.g., lodash',
        });
      }
      if (!packageName) { return; }

      const report = await autoPatchEngine.getPatchReport(packageName, null, 'npm');

      if (report.totalVulnerabilities === 0 && !report.deprecated) {
        vscode.window.showInformationMessage(`${packageName} has no known issues.`);
        return;
      }

      const explanation = await patchAgent?.explainPatch(report);
      if (explanation) {
        const panel = vscode.window.createWebviewPanel(
          'codeguardExplain',
          `CodeGuard: ${packageName} Explanation`,
          vscode.ViewColumn.Beside,
          { enableScripts: false }
        );
        panel.webview.html = `<!DOCTYPE html><html><head><style>
          body { font-family: var(--vscode-font-family); padding: 16px; color: var(--vscode-foreground); background: var(--vscode-editor-background); }
          pre { background: var(--vscode-textCodeBlock-background); padding: 8px; border-radius: 4px; }
          code { font-family: var(--vscode-editor-font-family); }
          </style></head><body>${simpleMarkdownToHtml(explanation)}</body></html>`;
      }
    })
  );

  // "Show Security Score" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.showSecurityScore', () => {
      if (!securityScore) { return; }
      const md = securityScore.toMarkdown();
      const panel = vscode.window.createWebviewPanel(
        'codeguardScore', 'CodeGuard: Security Score', vscode.ViewColumn.Beside,
        { enableScripts: false }
      );
      panel.webview.html = `<!DOCTYPE html><html><head><style>
        body{font-family:var(--vscode-font-family);padding:16px;color:var(--vscode-foreground);background:var(--vscode-editor-background);}
        table{border-collapse:collapse;width:100%;}td,th{border:1px solid var(--vscode-panel-border);padding:6px 10px;}
        h1,h2,h3{margin-top:16px;}pre{background:var(--vscode-textCodeBlock-background);padding:8px;border-radius:4px;}
        </style></head><body>${simpleMarkdownToHtml(md)}</body></html>`;
    })
  );

  // "Detect SBOM Drift" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.detectSbomDrift', async () => {
      if (!sbomDrift || !sbomGenerator) {
        vscode.window.showWarningMessage('CodeGuard: SBOM Generator or Drift Detector not available.');
        return;
      }
      const bom = sbomGenerator.getBom();
      if (!bom) {
        vscode.window.showWarningMessage('CodeGuard: No SBOM available. Run "Generate SBOM" first.');
        return;
      }
      const report = sbomDrift.detectDrift(bom);
      const md = sbomDrift.toMarkdown(report);
      const panel = vscode.window.createWebviewPanel(
        'codeguardDrift', 'CodeGuard: SBOM Drift Report', vscode.ViewColumn.Beside,
        { enableScripts: false }
      );
      panel.webview.html = `<!DOCTYPE html><html><head><style>
        body{font-family:var(--vscode-font-family);padding:16px;color:var(--vscode-foreground);background:var(--vscode-editor-background);}
        h1,h2,h3{margin-top:16px;}pre{background:var(--vscode-textCodeBlock-background);padding:8px;border-radius:4px;}
        </style></head><body>${simpleMarkdownToHtml(md)}</body></html>`;
      if (report.hasHighRiskChanges) {
        // eslint-disable-next-line no-irregular-whitespace
        vscode.window.showWarningMessage(`âš ï¸ CodeGuard: High-risk dependency changes detected! ${report.summary}`);
      }
    })
  );

  // "Save SBOM Baseline" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.saveSbomBaseline', async () => {
      if (!sbomDrift || !sbomGenerator) { return; }
      const bom = sbomGenerator.getBom();
      if (!bom) {
        vscode.window.showWarningMessage('CodeGuard: No SBOM available. Run "Generate SBOM" first.');
        return;
      }
      sbomDrift.saveBaseline(bom);
      vscode.window.showInformationMessage(`âœ… CodeGuard: SBOM baseline saved (${bom.components.length} components).`);
    })
  );

  // "Scan for Secrets" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.scanSecrets', async () => {
      if (!secretsChecker) { return; }
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('CodeGuard: Open a file to scan for secrets.');
        return;
      }
      const findings = await secretsChecker.scan(editor.document);
      if (findings.length === 0) {
        vscode.window.showInformationMessage('âœ… CodeGuard: No hardcoded secrets found in this file.');
      } else {
        vscode.window.showWarningMessage(`ðŸ”‘ CodeGuard: ${findings.length} secret(s) found! Check the Problems panel.`);
      }
    })
  );

  // "Scan for Code Vulnerabilities" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.scanCodeVulns', async () => {
      if (!codeVulnChecker) { return; }
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('CodeGuard: Open a file to scan for vulnerabilities.');
        return;
      }
      const findings = await codeVulnChecker.scan(editor.document);
      if (findings.length === 0) {
        vscode.window.showInformationMessage('âœ… CodeGuard: No code vulnerability patterns found.');
      } else {
        vscode.window.showWarningMessage(`ðŸ”’ CodeGuard: ${findings.length} vulnerability pattern(s) found! Check the Problems panel.`);
      }
    })
  );

  // v5 Commands

  // "Deep SAST Scan" command — runs all 3 passes (regex + LLM + adversarial)
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.deepSastScan', async () => {
      if (!hybridSast) { return; }
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('CodeGuard: Open a file to run deep SAST scan.');
        return;
      }
      const findings = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'CodeGuard: Running deep SAST analysis (LLM + adversarial verify)...' },
        () => hybridSast!.deepScan(editor.document)
      );
      if (findings.length === 0) {
        vscode.window.showInformationMessage('CodeGuard: Deep SAST scan complete — no vulnerabilities found.');
      } else {
        const confirmed = findings.filter(f => f.adversarialVerdict === 'confirmed' || !f.adversarialVerdict).length;
        vscode.window.showWarningMessage(
          `CodeGuard: ${findings.length} finding(s) from deep SAST (${confirmed} confirmed). Check the Problems panel.`
        );
      }
    })
  );

  // "Taint Analysis" command — workspace-wide cross-file taint tracking
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.taintAnalysis', async () => {
      if (!taintTracker) { return; }
      const report = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'CodeGuard: Running cross-file taint analysis...' },
        () => taintTracker!.scanWorkspace()
      );
      const md = taintTracker.toMarkdown(report);
      const panel = vscode.window.createWebviewPanel(
        'codeguardTaint', 'CodeGuard: Taint Analysis', vscode.ViewColumn.Beside,
        { enableScripts: false }
      );
      panel.webview.html = `<!DOCTYPE html><html><head><style>
        body{font-family:var(--vscode-font-family);padding:16px;color:var(--vscode-foreground);background:var(--vscode-editor-background);}
        h1,h2,h3{margin-top:16px;}pre{background:var(--vscode-textCodeBlock-background);padding:8px;border-radius:4px;}
        code{font-family:var(--vscode-editor-font-family);}
        </style></head><body>${simpleMarkdownToHtml(md)}</body></html>`;
      if (report.flows.length > 0) {
        vscode.window.showWarningMessage(`CodeGuard: ${report.flows.length} tainted data flow(s) found across ${report.scannedFiles} files.`);
      } else {
        vscode.window.showInformationMessage(`CodeGuard: No tainted data flows found (scanned ${report.scannedFiles} files).`);
      }
    })
  );

  // "AI Code Attribution Report" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.aiAttribution', () => {
      if (!codeAttribution) { return; }
      const md = codeAttribution.toMarkdown();
      const panel = vscode.window.createWebviewPanel(
        'codeguardAttribution', 'CodeGuard: AI Code Attribution', vscode.ViewColumn.Beside,
        { enableScripts: false }
      );
      panel.webview.html = `<!DOCTYPE html><html><head><style>
        body{font-family:var(--vscode-font-family);padding:16px;color:var(--vscode-foreground);background:var(--vscode-editor-background);}
        h1,h2,h3{margin-top:16px;}table{border-collapse:collapse;width:100%;}td,th{border:1px solid var(--vscode-panel-border);padding:6px 10px;}
        blockquote{border-left:3px solid var(--vscode-panel-border);padding-left:12px;margin-left:0;opacity:0.8;}
        </style></head><body>${simpleMarkdownToHtml(md)}</body></html>`;
    })
  );

  // "Evaluate Policy" command — full policy check
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.evaluatePolicy', async () => {
      if (!policyEngine) { return; }
      const evaluation = policyEngine.evaluateFull({
        criticalFindings: 0,
        highFindings: 0,
        aiCodeRatio: codeAttribution?.getStats().aiRatio ?? 0,
        sbomBaselineExists: false,
        secretsScannerEnabled: Config.enableSecretsScanner,
        sastScannerEnabled: Config.enableCodeVulnScanner,
      });
      const md = policyEngine.toMarkdown(evaluation);
      const panel = vscode.window.createWebviewPanel(
        'codeguardPolicy', 'CodeGuard: Policy Evaluation', vscode.ViewColumn.Beside,
        { enableScripts: false }
      );
      panel.webview.html = `<!DOCTYPE html><html><head><style>
        body{font-family:var(--vscode-font-family);padding:16px;color:var(--vscode-foreground);background:var(--vscode-editor-background);}
        h1,h2,h3{margin-top:16px;}
        </style></head><body>${simpleMarkdownToHtml(md)}</body></html>`;
      if (evaluation.passed) {
        vscode.window.showInformationMessage('CodeGuard: All policy rules passed.');
      } else {
        vscode.window.showWarningMessage(`CodeGuard: Policy evaluation FAILED — ${evaluation.violations.length} violation(s).`);
      }
    })
  );

  // "Create Policy File" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.createPolicy', async () => {
      if (!policyEngine) { return; }
      const filePath = await policyEngine.createDefaultPolicy();
      if (filePath) {
        const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
        await vscode.window.showTextDocument(doc);
        vscode.window.showInformationMessage('CodeGuard: Default policy file created at .codeguard/policy.json');
      }
    })
  );

  // "Git Regression Scan" command — scan workspace for security regressions
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.gitRegressionScan', async () => {
      if (!gitRegression) { return; }
      const reports = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'CodeGuard: Scanning git changes for security regressions...' },
        () => gitRegression!.scanWorkspace()
      );
      const md = gitRegression.toMarkdown(reports);
      const panel = vscode.window.createWebviewPanel(
        'codeguardGitRegression', 'CodeGuard: Git Security Regressions', vscode.ViewColumn.Beside,
        { enableScripts: false }
      );
      panel.webview.html = `<!DOCTYPE html><html><head><style>
        body{font-family:var(--vscode-font-family);padding:16px;color:var(--vscode-foreground);background:var(--vscode-editor-background);}
        h1,h2,h3{margin-top:16px;}code{font-family:var(--vscode-editor-font-family);}
        </style></head><body>${simpleMarkdownToHtml(md)}</body></html>`;
      const totalRegs = reports.reduce((sum, r) => sum + r.regressions.length, 0);
      if (totalRegs > 0) {
        vscode.window.showWarningMessage(`CodeGuard: ${totalRegs} security regression(s) found in ${reports.length} file(s).`);
      } else {
        vscode.window.showInformationMessage('CodeGuard: No security regressions detected in recent changes.');
      }
    })
  );

  // "Export Compliance Report" command — generates CSV/Markdown/JSON report
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.exportComplianceReport', async () => {
      if (!complianceReport) { return; }
      const format = await vscode.window.showQuickPick(
        [
          { label: 'Markdown', description: 'Human-readable report (.md)', value: 'markdown' as const },
          { label: 'CSV', description: 'Spreadsheet-compatible (.csv)', value: 'csv' as const },
          { label: 'JSON', description: 'Programmatic consumption (.json)', value: 'json' as const },
        ],
        { placeHolder: 'Select report format' }
      );
      if (!format) { return; }

      const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
      if (!workspaceFolder) {
        vscode.window.showWarningMessage('CodeGuard: Open a workspace to generate a compliance report.');
        return;
      }

      const projectName = workspaceFolder.name;
      const outputDir = vscode.Uri.joinPath(workspaceFolder.uri, '.codeguard', 'reports').fsPath;

      const attrStats = codeAttribution?.getStats();
      const data = complianceReport.collectData({
        projectName,
        aiAttribution: attrStats ? {
          totalFiles: attrStats.filesTracked,
          aiGeneratedLines: attrStats.aiLines,
          humanWrittenLines: attrStats.humanLines,
          aiRatio: attrStats.aiRatio,
          aiVulnRate: attrStats.aiVulnRate,
          humanVulnRate: attrStats.humanVulnRate,
        } : undefined,
        policy: policyEngine ? {
          policyFile: policyEngine.hasPolicyFile() ? '.codeguard/policy.json' : null,
          ruleCount: 0, passed: 0, failed: 0, violations: [],
        } : undefined,
      });

      const filePath = await complianceReport.generate(data, format.value, outputDir);
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
      await vscode.window.showTextDocument(doc);
      vscode.window.showInformationMessage(`CodeGuard: Compliance report exported to ${filePath}`);
    })
  );

  // "Scan MCP Servers" command — scan all MCP configs for security issues
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.scanMcpServers', async () => {
      if (!mcpScanner) { return; }
      const results = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'CodeGuard: Scanning MCP server configurations...' },
        () => mcpScanner!.scanWorkspace()
      );
      const summary = mcpScanner.getSummary(results);
      if (summary.totalIssues === 0) {
        vscode.window.showInformationMessage(`CodeGuard: ${summary.totalServers} MCP server(s) scanned — all clean.`);
      } else {
        vscode.window.showWarningMessage(
          `CodeGuard: ${summary.totalIssues} issue(s) in ${summary.totalServers} MCP server(s) (${summary.critical} critical, ${summary.high} high).`,
          'Show Issues'
        ).then(action => {
          if (action === 'Show Issues') {
            vscode.commands.executeCommand('workbench.action.problems.focus');
          }
        });
      }
    })
  );

  // "Discover Shadow AI" command — find all AI tools, SDKs, and configs
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.discoverShadowAi', async () => {
      if (!shadowAiDiscovery) { return; }
      const sbom = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'CodeGuard: Discovering AI components in workspace...' },
        () => shadowAiDiscovery!.discover()
      );
      const s = sbom.summary;
      const panel = vscode.window.createWebviewPanel(
        'codeguardAiSbom', 'CodeGuard: AI-SBOM (Shadow AI Discovery)', vscode.ViewColumn.Beside,
        { enableScripts: false }
      );
      const componentsHtml = sbom.components.map(c =>
        `<tr><td><b>${escapeHtml(c.name)}</b></td><td>${c.type}</td><td>${c.risk}</td><td>${escapeHtml(c.file)}${c.line ? ':' + c.line : ''}</td><td>${escapeHtml(c.description)}</td></tr>`
      ).join('\n');
      panel.webview.html = `<!DOCTYPE html><html><head><style>
        body{font-family:var(--vscode-font-family);padding:16px;color:var(--vscode-foreground);background:var(--vscode-editor-background);}
        h1,h2{margin-top:16px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid var(--vscode-panel-border);padding:6px 10px;text-align:left;}
        th{background:var(--vscode-editor-selectionBackground);}
        </style></head><body>
        <h1>AI-SBOM — Shadow AI Discovery</h1>
        <p>Generated: ${sbom.generatedAt}</p>
        <h2>Summary</h2>
        <ul>
          <li><b>Total AI Components:</b> ${s.totalComponents}</li>
          <li><b>Coding Tool Configs:</b> ${s.codingToolConfigs}</li>
          <li><b>MCP Servers:</b> ${s.mcpServers}</li>
          <li><b>AI SDKs:</b> ${s.aiSdks}</li>
          <li><b>Agent Frameworks:</b> ${s.agentFrameworks}</li>
          <li><b>Model Files:</b> ${s.modelFiles}</li>
          <li><b>High Risk:</b> ${s.highRisk}</li>
        </ul>
        <h2>Components</h2>
        <table><tr><th>Name</th><th>Type</th><th>Risk</th><th>File</th><th>Description</th></tr>
        ${componentsHtml}
        </table>
        </body></html>`;
      vscode.window.showInformationMessage(`CodeGuard: Discovered ${s.totalComponents} AI component(s) — ${s.highRisk} high-risk.`);
    })
  );

  // "Export AI-SBOM" command — export AI-SBOM as JSON
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.exportAiSbom', async () => {
      if (!shadowAiDiscovery) { return; }
      const sbom = await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'CodeGuard: Generating AI-SBOM...' },
        () => shadowAiDiscovery!.discover()
      );
      const json = shadowAiDiscovery.exportJson(sbom);
      const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
      if (!workspaceFolder) { return; }
      const outputPath = vscode.Uri.joinPath(workspaceFolder.uri, '.codeguard', 'ai-sbom.json').fsPath;
      const dir = vscode.Uri.joinPath(workspaceFolder.uri, '.codeguard').fsPath;
      if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }
      fs.writeFileSync(outputPath, json, 'utf-8');
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(outputPath));
      await vscode.window.showTextDocument(doc);
      vscode.window.showInformationMessage(`CodeGuard: AI-SBOM exported to ${outputPath}`);
    })
  );

  // Listen for configuration changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration('codeguard')) {
        if (!Config.enabled) {
          statusBar?.showDisabled();
          diagnosticsProvider?.clearAll();
          codeLensProvider?.clearAll();
        } else {
          // Re-scan active document with new settings
          if (vscode.window.activeTextEditor) {
            watcher?.scanDocument(vscode.window.activeTextEditor.document);
          }
        }
      }
    })
  );

  // Register disposables
  context.subscriptions.push({
    dispose: () => {
      watcher?.dispose();
      diagnosticsProvider?.dispose();
      statusBar?.dispose();
      rulesScanner?.dispose();
      installGate?.dispose();
      ghin?.saveToDisk();
      cache?.saveToDisk();
    },
  });

  console.log(`[CodeGuard AI] v5 Activated â€” GHIN: ${ghin?.size ?? 0} known hallucinations, Rules Scanner: ${Config.enableRulesScanner ? 'ON' : 'OFF'}, Install Gate: ${Config.enableInstallGate ? 'ON' : 'OFF'}`);
}

/**
 * Extension deactivation â€” called when VS Code shuts down or disables the extension.
 */
export function deactivate() {
  console.log('[CodeGuard AI] Deactivating...');
  ghin?.saveToDisk();
  cache?.saveToDisk();
  watcher?.dispose();
  diagnosticsProvider?.dispose();
  statusBar?.dispose();
  rulesScanner?.dispose();
  installGate?.dispose();
}

/**
 * Escape HTML special characters to prevent XSS in webview panels.
 */
function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/**
 * Simple markdown to HTML converter (for webview panels).
 */
function simpleMarkdownToHtml(md: string): string {
  return md
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
    .replace(/^> (.+)$/gm, '<blockquote>$1</blockquote>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/\n/g, '<br>');
}

/**
 * Show the security dashboard in a webview panel.
 */
function showDashboard(context: vscode.ExtensionContext): void {
  const panel = vscode.window.createWebviewPanel(
    'codeguardDashboard',
    'CodeGuard AI â€” Security Dashboard',
    vscode.ViewColumn.One,
    { enableScripts: false }
  );

  const counts = diagnosticsProvider?.getCount() || { errors: 0, warnings: 0, total: 0 };
  const cacheStats = cache?.stats() || { size: 0, ttlMinutes: 60 };

  panel.webview.html = getDashboardHtml(counts, cacheStats);
}

function getDashboardHtml(
  counts: { errors: number; warnings: number; total: number },
  cacheStats: { size: number; ttlMinutes: number }
): string {
  const score = counts.total === 0 ? 100 : Math.max(0, 100 - counts.errors * 15 - counts.warnings * 5);
  const scoreColor = score >= 80 ? '#51cf66' : score >= 50 ? '#ffa94d' : '#ff6b6b';
  const scoreLabel = score >= 80 ? 'Excellent' : score >= 60 ? 'Good' : score >= 40 ? 'Fair' : 'Critical';
  const circ = 2 * Math.PI * 54;
  const dashOffset = circ - (score / 100) * circ;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CodeGuard AI Dashboard</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Inter',var(--vscode-font-family,-apple-system,BlinkMacSystemFont,sans-serif);color:var(--vscode-foreground,#e0e0e0);background:var(--vscode-editor-background,#0d1117);min-height:100vh}
    .hdr{position:relative;padding:32px 32px 40px;background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);background-size:200% 200%;animation:gs 8s ease infinite;border-bottom:1px solid rgba(255,255,255,.06)}
    .hdr::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 20% 50%,rgba(81,207,102,.08) 0%,transparent 60%),radial-gradient(ellipse at 80% 50%,rgba(102,126,234,.08) 0%,transparent 60%)}
    @keyframes gs{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
    .hdr h1{position:relative;font-size:26px;font-weight:700;letter-spacing:-.5px;margin-bottom:4px}
    .hdr .sub{position:relative;font-size:13px;opacity:.55;letter-spacing:.3px}
    .cnt{padding:24px 32px 48px}
    .hero{display:flex;gap:20px;margin-bottom:28px;align-items:stretch}
    .sc{flex:0 0 180px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:24px;display:flex;flex-direction:column;align-items:center;justify-content:center;backdrop-filter:blur(12px)}
    .sr{position:relative;width:120px;height:120px}
    .sr svg{transform:rotate(-90deg)}
    .sr .bg{fill:none;stroke:rgba(255,255,255,.06);stroke-width:8}
    .sr .fg{fill:none;stroke:${scoreColor};stroke-width:8;stroke-linecap:round;stroke-dasharray:${circ};stroke-dashoffset:${dashOffset}}
    .sv{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:32px;font-weight:700;color:${scoreColor}}
    .sl{margin-top:10px;font-size:12px;font-weight:500;text-transform:uppercase;letter-spacing:1.5px;opacity:.5}
    .sg{flex:1;display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
    .stc{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:20px;backdrop-filter:blur(12px);transition:transform .15s,border-color .15s}
    .stc:hover{transform:translateY(-2px);border-color:rgba(255,255,255,.12)}
    .stc .n{font-size:36px;font-weight:700;line-height:1;margin-bottom:6px}
    .stc .l{font-size:11px;font-weight:500;text-transform:uppercase;letter-spacing:1px;opacity:.45}
    .cr{color:#ff6b6b}.co{color:#ffa94d}.cg{color:#51cf66}.cb{color:#74c0fc}
    .st{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:1.5px;opacity:.4;margin-bottom:14px}
    .mg{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px;margin-bottom:28px}
    .mr{display:flex;align-items:center;gap:10px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.04);border-radius:10px;padding:12px 14px;font-size:13px}
    .md{width:8px;height:8px;border-radius:50%;flex-shrink:0;background:#51cf66;box-shadow:0 0 6px rgba(81,207,102,.4)}
    .mn{flex:1;font-weight:500}
    .it{width:100%;border-collapse:collapse;margin-bottom:28px}
    .it td{padding:10px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:13px}
    .it td:first-child{opacity:.5;width:180px}
    .it a{color:#74c0fc;text-decoration:none}
    .it a:hover{text-decoration:underline}
    .ft{text-align:center;font-size:11px;opacity:.3;padding-top:16px;border-top:1px solid rgba(255,255,255,.04)}
  </style>
</head>
<body>
  <div class="hdr">
    <h1>ðŸ›¡ï¸ CodeGuard AI</h1>
    <p class="sub">Security Co-Pilot for AI-Generated Code</p>
  </div>
  <div class="cnt">
    <div class="hero">
      <div class="sc">
        <div class="sr">
          <svg viewBox="0 0 120 120"><circle class="bg" cx="60" cy="60" r="54"/><circle class="fg" cx="60" cy="60" r="54"/></svg>
          <span class="sv">${score}</span>
        </div>
        <span class="sl">${scoreLabel}</span>
      </div>
      <div class="sg">
        <div class="stc"><div class="n cr">${counts.errors}</div><div class="l">Critical</div></div>
        <div class="stc"><div class="n co">${counts.warnings}</div><div class="l">Warnings</div></div>
        <div class="stc"><div class="n cb">${cacheStats.size}</div><div class="l">Scanned</div></div>
      </div>
    </div>

    <div class="st">Active Modules</div>
    <div class="mg">
      <div class="mr"><span class="md"></span><span class="mn">Install Gate</span></div>
      <div class="mr"><span class="md"></span><span class="mn">Hallucination Detection</span></div>
      <div class="mr"><span class="md"></span><span class="mn">Rules File Scanner</span></div>
      <div class="mr"><span class="md"></span><span class="mn">Provenance Checker</span></div>
      <div class="mr"><span class="md"></span><span class="mn">Secrets Scanner</span></div>
      <div class="mr"><span class="md"></span><span class="mn">Code Vuln Scanner</span></div>
      <div class="mr"><span class="md"></span><span class="mn">SBOM Generator</span></div>
      <div class="mr"><span class="md"></span><span class="mn">Trust Score Engine</span></div>
      <div class="mr"><span class="md"></span><span class="mn">LLM Advisor</span></div>
      <div class="mr"><span class="md"></span><span class="mn">Permission Model</span></div>
    </div>

    <div class="st">Configuration</div>
    <table class="it">
      <tr><td>Severity Threshold</td><td>${counts.total === 0 ? 'All Clean' : 'Active'}</td></tr>
      <tr><td>Cache TTL</td><td>${cacheStats.ttlMinutes} minutes</td></tr>
      <tr><td>Cached Packages</td><td>${cacheStats.size}</td></tr>
    </table>

    <div class="st">Data Sources</div>
    <table class="it">
      <tr><td>CVE Database</td><td><a href="https://osv.dev">OSV.dev</a> &middot; <a href="https://github.com/advisories">GitHub Advisory</a></td></tr>
      <tr><td>Registries</td><td>npm &middot; PyPI &middot; crates.io &middot; Go proxy &middot; Maven Central</td></tr>
      <tr><td>GHIN Network</td><td>Global Hallucination Intelligence (crowdsourced)</td></tr>
      <tr><td>Provenance</td><td>Sigstore (npm) &middot; PEP 740 (PyPI)</td></tr>
    </table>

    <div class="ft">CodeGuard AI v5.2.0</div>
  </div>
</body>
</html>`;
}
