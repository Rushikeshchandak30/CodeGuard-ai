import * as vscode from 'vscode';
import { ParserRegistry, ParsedDependency } from './parsers/index';
import { SecurityChecker, ScanResult } from './checkers/index';
import { DiagnosticsProvider } from './diagnostics/provider';
import { StatusBar } from './ui/statusbar';
import { HoverProvider } from './ui/hover';
import { Config } from './config';
import { AiGenerationDetector, ChangeAnalysis } from './ai/detector';
import { VersionResolver } from './checkers/version-resolver';
import { HallucinationDetector, HallucinationAnalysis } from './checkers/hallucination';
import {
  CommentInjector,
  SecurityCodeLensProvider,
  SecurityDecorationProvider,
  FeedbackItem,
  buildFeedbackItems,
} from './ai/feedback';
import { SecurityContextProvider } from './ai/context';

/**
 * Core document watcher — monitors editor changes in real-time,
 * detects AI-generated code, parses imports, runs security checks,
 * and communicates issues back to both the human AND the AI.
 */
export class DocumentWatcher {
  private parser: ParserRegistry;
  private checker: SecurityChecker;
  private diagnostics: DiagnosticsProvider;
  private statusBar: StatusBar;
  private hoverProvider: HoverProvider;
  private debounceTimers = new Map<string, NodeJS.Timeout>();
  private disposables: vscode.Disposable[] = [];

  // v2 modules
  private aiDetector: AiGenerationDetector;
  private versionResolver: VersionResolver;
  private hallucinationDetector: HallucinationDetector;
  private commentInjector: CommentInjector;
  private codeLensProvider: SecurityCodeLensProvider;
  private decorationProvider: SecurityDecorationProvider;
  private contextProvider: SecurityContextProvider;

  // Track last scan results for diff-based rescanning
  private lastDependencies = new Map<string, Set<string>>();
  // Track hallucination analysis results
  private hallucinationResults = new Map<string, HallucinationAnalysis>();

  constructor(
    checker: SecurityChecker,
    diagnostics: DiagnosticsProvider,
    statusBar: StatusBar,
    hoverProvider: HoverProvider,
    codeLensProvider: SecurityCodeLensProvider,
    contextProvider: SecurityContextProvider
  ) {
    this.parser = new ParserRegistry();
    this.checker = checker;
    this.diagnostics = diagnostics;
    this.statusBar = statusBar;
    this.hoverProvider = hoverProvider;

    // v2 modules
    this.aiDetector = new AiGenerationDetector();
    this.versionResolver = new VersionResolver();
    this.hallucinationDetector = new HallucinationDetector();
    this.commentInjector = new CommentInjector();
    this.codeLensProvider = codeLensProvider;
    this.decorationProvider = new SecurityDecorationProvider();
    this.contextProvider = contextProvider;
  }

  /**
   * Start watching document changes.
   */
  activate(): void {
    // Watch text document changes (real-time typing + AI generation)
    this.disposables.push(
      vscode.workspace.onDidChangeTextDocument((event) => {
        this.onDocumentChange(event);
      })
    );

    // Scan when a new document is opened
    this.disposables.push(
      vscode.workspace.onDidOpenTextDocument((document) => {
        this.scanDocument(document);
      })
    );

    // Scan when active editor changes
    this.disposables.push(
      vscode.window.onDidChangeActiveTextEditor((editor) => {
        if (editor) {
          this.scanDocument(editor.document);
        }
      })
    );

    // Clear diagnostics when document closes
    this.disposables.push(
      vscode.workspace.onDidCloseTextDocument((document) => {
        this.diagnostics.clear(document);
        this.aiDetector.clearDocument(document.uri.toString());
        this.lastDependencies.delete(document.uri.toString());
      })
    );

    // Invalidate manifest cache when package.json changes
    this.disposables.push(
      vscode.workspace.onDidSaveTextDocument((document) => {
        if (document.fileName.endsWith('package.json') || document.fileName.endsWith('requirements.txt')) {
          this.versionResolver.invalidateManifestCache();
        }
      })
    );

    // Scan already-open document
    if (vscode.window.activeTextEditor) {
      this.scanDocument(vscode.window.activeTextEditor.document);
    }
  }

  /**
   * Handle document change events with AI-aware debouncing.
   * AI-generated code gets scanned immediately; human typing gets debounced.
   */
  private onDocumentChange(event: vscode.TextDocumentChangeEvent): void {
    if (!Config.enabled) { return; }

    const document = event.document;
    if (!this.parser.supports(document.languageId)) { return; }

    // Ignore lockfiles and node_modules
    if (this.shouldIgnoreFile(document.fileName)) { return; }

    // Run AI generation detection
    const analysis = this.aiDetector.analyze(event);

    const uri = document.uri.toString();
    const existing = this.debounceTimers.get(uri);
    if (existing) {
      clearTimeout(existing);
    }

    // AI-generated code: use shorter debounce (or immediate)
    // Human typing: use normal debounce
    const delay = analysis.isAiGenerated ? Config.aiDebounceMs : Config.debounceMs;

    if (analysis.isAiGenerated) {
      console.log(
        `[CodeGuard] AI generation detected (confidence: ${analysis.confidence.toFixed(2)}, ` +
        `signals: ${analysis.signals.join(', ')})`
      );
    }

    const timer = setTimeout(() => {
      this.debounceTimers.delete(uri);
      this.scanDocument(document, analysis);
    }, delay);

    this.debounceTimers.set(uri, timer);
  }

  /**
   * Scan a document for vulnerable dependencies.
   * When AI-generated code is detected, runs enhanced checks and all feedback channels.
   */
  async scanDocument(
    document: vscode.TextDocument,
    aiAnalysis?: ChangeAnalysis
  ): Promise<void> {
    if (!Config.enabled) { return; }

    const languageId = document.languageId;

    // For JSON files, only scan package.json
    if (languageId === 'json' && !document.fileName.endsWith('package.json')) {
      return;
    }

    if (!this.parser.supports(languageId)) { return; }

    const text = document.getText();
    const dependencies = this.parser.parse(text, languageId);

    if (dependencies.length === 0) {
      this.diagnostics.clear(document);
      this.codeLensProvider.updateItems(document.uri.toString(), []);
      this.clearDecorations(document);
      this.updateStatusBar();
      return;
    }

    // Filter out ignored packages and private registry packages
    const ignored = new Set(Config.ignoredPackages.map(p => p.toLowerCase()));
    const privateScopes = Config.privateRegistries.map(p => p.toLowerCase());
    const filtered = dependencies.filter(d => {
      const nameLower = d.name.toLowerCase();
      if (ignored.has(nameLower)) { return false; }
      // Skip private registry scoped packages (e.g., @mycompany/*)
      if (privateScopes.some(scope => nameLower.startsWith(scope))) { return false; }
      return true;
    });

    if (filtered.length === 0) {
      this.diagnostics.clear(document);
      this.codeLensProvider.updateItems(document.uri.toString(), []);
      this.clearDecorations(document);
      this.updateStatusBar();
      return;
    }

    // Diff-based optimization: only re-check changed packages
    const currentPackages = new Set(filtered.map(d => d.name));
    const previousPackages = this.lastDependencies.get(document.uri.toString());
    this.lastDependencies.set(document.uri.toString(), currentPackages);

    // Resolve versions for packages that have no version
    await this.resolveVersions(filtered);

    this.statusBar.showScanning();

    try {
      const results = await this.checker.scan(filtered);

      // Run enhanced hallucination analysis
      const hallucinationResults = new Map<string, HallucinationAnalysis>();
      if (Config.enableHallucinationDetection) {
        await this.runHallucinationAnalysis(filtered, results, hallucinationResults);
      }
      this.hallucinationResults = hallucinationResults;

      // Filter by severity threshold
      const thresholdResults = this.filterBySeverity(results);

      // Update core diagnostics (squiggly underlines)
      this.diagnostics.update(document, filtered, thresholdResults);

      // Update hover provider
      this.hoverProvider.updateResults(thresholdResults);

      // Update security context (for Chat Participant and other AI tools)
      this.contextProvider.update(thresholdResults, hallucinationResults);

      // Build feedback items for all AI feedback channels
      const feedbackItems = buildFeedbackItems(filtered, thresholdResults, hallucinationResults);

      // Apply all feedback channels
      await this.applyFeedback(document, feedbackItems, aiAnalysis);

      // Update status bar
      this.updateStatusBar();
    } catch (error) {
      console.error('[CodeGuard] Scan error:', error);
      this.statusBar.showError('Scan failed — check connection');
    }
  }

  /**
   * Resolve versions for dependencies that don't have one.
   */
  private async resolveVersions(dependencies: ParsedDependency[]): Promise<void> {
    for (const dep of dependencies) {
      if (!dep.version) {
        try {
          const resolved = await this.versionResolver.resolve(dep.name, dep.ecosystem);
          if (resolved.version) {
            dep.version = resolved.version;
          }
        } catch {
          // Skip resolution errors
        }
      }
    }
  }

  /**
   * Run enhanced hallucination analysis on packages.
   */
  private async runHallucinationAnalysis(
    dependencies: ParsedDependency[],
    scanResults: Map<string, ScanResult>,
    output: Map<string, HallucinationAnalysis>
  ): Promise<void> {
    for (const dep of dependencies) {
      const result = scanResults.get(dep.name);
      if (!result) { continue; }

      try {
        const analysis = await this.hallucinationDetector.analyze(
          dep.name,
          dep.ecosystem,
          result.packageExists
        );
        output.set(dep.name, analysis);
      } catch {
        // Skip analysis errors
      }
    }
  }

  /**
   * Apply all feedback channels: diagnostics, comments, CodeLens, decorations.
   */
  private async applyFeedback(
    document: vscode.TextDocument,
    items: FeedbackItem[],
    aiAnalysis?: ChangeAnalysis
  ): Promise<void> {
    const hasIssues = items.some(i =>
      i.type === 'vulnerability' || i.type === 'hallucination' || i.type === 'typosquat'
    );

    if (!hasIssues) {
      this.codeLensProvider.updateItems(document.uri.toString(), []);
      this.clearDecorations(document);
      return;
    }

    // CodeLens "Ask AI to Fix" buttons
    if (Config.enableCodeLens) {
      this.codeLensProvider.updateItems(document.uri.toString(), items);
    }

    // Editor decorations (visual-only overlays)
    if (Config.enableDecorations) {
      const editor = vscode.window.visibleTextEditors.find(
        e => e.document.uri.toString() === document.uri.toString()
      );
      if (editor) {
        this.decorationProvider.apply(editor, items);
      }
    }

    // Inline comment injection (AI reads these)
    // Only inject for AI-generated code to avoid polluting human-written files
    if (Config.enableCommentInjection && aiAnalysis?.isAiGenerated) {
      const importantItems = items.filter(i =>
        i.type === 'hallucination' || i.severity === 'error'
      );
      if (importantItems.length > 0) {
        await this.commentInjector.inject(document, importantItems);
      }
    }
  }

  /**
   * Force scan the current active document (manual command).
   */
  async scanCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage('CodeGuard: No active file to scan.');
      return;
    }
    await this.scanDocument(editor.document);
  }

  /**
   * Scan all open documents in the workspace.
   */
  async scanWorkspace(): Promise<void> {
    this.statusBar.showScanning();

    // Scan all open text documents
    const documents = vscode.workspace.textDocuments.filter(d =>
      this.parser.supports(d.languageId) || d.fileName.endsWith('package.json')
    );

    for (const doc of documents) {
      await this.scanDocument(doc);
    }

    // Also find and scan package.json / requirements.txt in workspace
    const packageFiles = await vscode.workspace.findFiles(
      '{**/package.json,**/requirements.txt,**/requirements*.txt}',
      '**/node_modules/**',
      20
    );

    for (const uri of packageFiles) {
      try {
        const doc = await vscode.workspace.openTextDocument(uri);
        await this.scanDocument(doc);
      } catch {
        // Skip files that can't be opened
      }
    }

    this.updateStatusBar();
    const counts = this.diagnostics.getCount();
    vscode.window.showInformationMessage(
      `CodeGuard: Workspace scan complete. Found ${counts.total} issue${counts.total !== 1 ? 's' : ''}.`
    );
  }

  /**
   * Get the CodeLens provider for registration in extension.ts.
   */
  getCodeLensProvider(): SecurityCodeLensProvider {
    return this.codeLensProvider;
  }

  dispose(): void {
    for (const timer of this.debounceTimers.values()) {
      clearTimeout(timer);
    }
    this.debounceTimers.clear();
    for (const d of this.disposables) {
      d.dispose();
    }
    this.aiDetector.dispose();
    this.decorationProvider.dispose();
    this.codeLensProvider.dispose();
  }

  private filterBySeverity(results: Map<string, ScanResult>): Map<string, ScanResult> {
    const filtered = new Map<string, ScanResult>();
    for (const [name, result] of results) {
      // Always include hallucinated packages
      if (!result.packageExists) {
        filtered.set(name, result);
        continue;
      }
      // Filter vulnerabilities by threshold
      const filteredVulns = result.vulnerabilities.filter(v =>
        Config.meetsThreshold(v.severity)
      );
      if (filteredVulns.length > 0) {
        filtered.set(name, { ...result, vulnerabilities: filteredVulns });
      } else {
        // Include clean result for hover
        filtered.set(name, { ...result, vulnerabilities: [] });
      }
    }
    return filtered;
  }

  private updateStatusBar(): void {
    const counts = this.diagnostics.getCount();
    if (counts.total > 0) {
      this.statusBar.showIssues(counts.errors, counts.warnings);
    } else {
      this.statusBar.showClean();
    }
  }

  private shouldIgnoreFile(fileName: string): boolean {
    const ignoredPatterns = [
      'node_modules',
      'package-lock.json',
      'yarn.lock',
      'pnpm-lock.yaml',
      'poetry.lock',
      '.git',
    ];
    return ignoredPatterns.some(p => fileName.includes(p));
  }

  private clearDecorations(document: vscode.TextDocument): void {
    const editor = vscode.window.visibleTextEditors.find(
      e => e.document.uri.toString() === document.uri.toString()
    );
    if (editor) {
      this.decorationProvider.clear(editor);
    }
  }
}
