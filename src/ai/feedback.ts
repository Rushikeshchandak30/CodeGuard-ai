import * as vscode from 'vscode';
import { ScanResult } from '../checkers/types';
import { ParsedDependency } from '../parsers/types';
import { HallucinationAnalysis } from '../checkers/hallucination';

/**
 * AI Feedback Engine — communicates security issues back to AI assistants.
 * 
 * Strategies:
 * 1. Inline comment injection (AI reads surrounding context)
 * 2. CodeLens "Ask AI to Fix" buttons
 * 3. Editor decorations (visual-only overlays)
 * 4. VS Code Language Model API (direct AI communication)
 */

export interface FeedbackItem {
  packageName: string;
  line: number;
  type: 'vulnerability' | 'hallucination' | 'typosquat' | 'deprecated' | 'low-popularity';
  message: string;
  fixSuggestion: string;
  severity: 'error' | 'warning' | 'info';
}

// ───────────────────────────────────────────────
// Inline Comment Injection
// ───────────────────────────────────────────────

/**
 * Injects temporary security warning comments into the source file.
 * AI assistants (Copilot, Cursor, Windsurf) read surrounding code context,
 * so they will see these comments and can self-correct.
 */
export class CommentInjector {
  private injectedComments = new Map<string, Set<number>>(); // uri -> set of line numbers
  private static readonly COMMENT_PREFIX = '⚠️ CodeGuard:';
  private static readonly AUTO_REMOVE_DELAY_MS = 60000; // 1 minute

  /**
   * Inject security warning comments for all issues found in a document.
   */
  async inject(
    document: vscode.TextDocument,
    items: FeedbackItem[]
  ): Promise<void> {
    const editor = vscode.window.visibleTextEditors.find(
      e => e.document.uri.toString() === document.uri.toString()
    );
    if (!editor) { return; }

    const uri = document.uri.toString();
    const existingComments = this.injectedComments.get(uri) || new Set<number>();

    // Remove old injected comments first
    await this.removeInjectedComments(document);

    const edit = new vscode.WorkspaceEdit();
    const commentStyle = this.getCommentStyle(document.languageId);
    const newCommentLines = new Set<number>();

    // Sort by line descending so insertions don't shift line numbers
    const sorted = [...items].sort((a, b) => b.line - a.line);

    for (const item of sorted) {
      // Don't duplicate comments on the same line
      if (newCommentLines.has(item.line)) { continue; }

      const commentText = `${commentStyle.start} ${CommentInjector.COMMENT_PREFIX} ${item.message} ${commentStyle.end}\n`;
      const position = new vscode.Position(item.line, 0);
      edit.insert(document.uri, position, commentText);
      newCommentLines.add(item.line);
    }

    if (newCommentLines.size > 0) {
      await vscode.workspace.applyEdit(edit);
      this.injectedComments.set(uri, newCommentLines);

      // Schedule auto-removal
      setTimeout(() => {
        this.removeInjectedComments(document);
      }, CommentInjector.AUTO_REMOVE_DELAY_MS);
    }
  }

  /**
   * Remove all CodeGuard-injected comments from a document.
   */
  async removeInjectedComments(document: vscode.TextDocument): Promise<void> {
    const edit = new vscode.WorkspaceEdit();
    const text = document.getText();
    const lines = text.split('\n');
    let removed = false;

    // Scan from bottom to top to preserve line numbers
    for (let i = lines.length - 1; i >= 0; i--) {
      if (lines[i].includes(CommentInjector.COMMENT_PREFIX)) {
        const range = new vscode.Range(i, 0, i + 1, 0);
        edit.delete(document.uri, range);
        removed = true;
      }
    }

    if (removed) {
      await vscode.workspace.applyEdit(edit);
      this.injectedComments.delete(document.uri.toString());
    }
  }

  /**
   * Check if a document has injected comments.
   */
  hasInjectedComments(uri: string): boolean {
    const comments = this.injectedComments.get(uri);
    return comments !== undefined && comments.size > 0;
  }

  private getCommentStyle(languageId: string): { start: string; end: string } {
    switch (languageId) {
      case 'python':
        return { start: '#', end: '' };
      case 'html':
      case 'xml':
        return { start: '<!--', end: '-->' };
      case 'css':
      case 'scss':
      case 'less':
        return { start: '/*', end: '*/' };
      default:
        return { start: '//', end: '' };
    }
  }
}

// ───────────────────────────────────────────────
// CodeLens Provider — "Ask AI to Fix" buttons
// ───────────────────────────────────────────────

export class SecurityCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  private feedbackItems = new Map<string, FeedbackItem[]>(); // uri -> items

  /**
   * Update the feedback items for a document.
   */
  updateItems(uri: string, items: FeedbackItem[]): void {
    if (items.length > 0) {
      this.feedbackItems.set(uri, items);
    } else {
      this.feedbackItems.delete(uri);
    }
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(
    document: vscode.TextDocument,
    _token: vscode.CancellationToken
  ): vscode.CodeLens[] {
    const uri = document.uri.toString();
    const items = this.feedbackItems.get(uri);
    if (!items || items.length === 0) { return []; }

    const lenses: vscode.CodeLens[] = [];

    // Group by line
    const byLine = new Map<number, FeedbackItem[]>();
    for (const item of items) {
      const line = item.line;
      if (!byLine.has(line)) { byLine.set(line, []); }
      byLine.get(line)!.push(item);
    }

    for (const [line, lineItems] of byLine) {
      const range = new vscode.Range(line, 0, line, 0);
      const issueCount = lineItems.length;
      const topItem = lineItems[0];

      // Lens 1: Issue summary
      const summaryTitle = issueCount === 1
        ? `🛡️ CodeGuard: ${topItem.message.substring(0, 80)}`
        : `🛡️ CodeGuard: ${issueCount} security issues found`;

      lenses.push(new vscode.CodeLens(range, {
        title: summaryTitle,
        command: 'codeguard.showIssueDetails',
        arguments: [lineItems],
      }));

      // Lens 2: "Ask AI to Fix" — opens Copilot Chat with pre-filled prompt
      const fixPrompt = this.buildFixPrompt(lineItems);
      lenses.push(new vscode.CodeLens(range, {
        title: '$(sparkle) Ask AI to Fix',
        command: 'codeguard.askAiToFix',
        arguments: [fixPrompt, document.uri, line],
      }));

      // Lens 3: "Ignore" button
      lenses.push(new vscode.CodeLens(range, {
        title: '$(eye-closed) Ignore',
        command: 'codeguard.ignorePackage',
        arguments: [topItem.packageName],
      }));
    }

    return lenses;
  }

  /**
   * Build a prompt string for AI assistants to fix the issue.
   */
  private buildFixPrompt(items: FeedbackItem[]): string {
    const parts: string[] = ['Please fix the following security issues in my code:\n'];

    for (const item of items) {
      parts.push(`- Package "${item.packageName}": ${item.message}`);
      if (item.fixSuggestion) {
        parts.push(`  Suggested fix: ${item.fixSuggestion}`);
      }
    }

    parts.push('\nPlease provide the corrected code with safe package versions or alternatives.');
    return parts.join('\n');
  }

  clearAll(): void {
    this.feedbackItems.clear();
    this._onDidChangeCodeLenses.fire();
  }

  dispose(): void {
    this._onDidChangeCodeLenses.dispose();
  }
}

// ───────────────────────────────────────────────
// Editor Decorations — Visual overlays (don't modify source)
// ───────────────────────────────────────────────

export class SecurityDecorationProvider {
  private vulnDecorationType: vscode.TextEditorDecorationType;
  private hallucinationDecorationType: vscode.TextEditorDecorationType;
  private warningDecorationType: vscode.TextEditorDecorationType;

  constructor() {
    this.vulnDecorationType = vscode.window.createTextEditorDecorationType({
      after: {
        margin: '0 0 0 1em',
        color: new vscode.ThemeColor('editorWarning.foreground'),
        fontStyle: 'italic',
      },
      backgroundColor: new vscode.ThemeColor('editorWarning.background'),
      isWholeLine: false,
    });

    this.hallucinationDecorationType = vscode.window.createTextEditorDecorationType({
      after: {
        margin: '0 0 0 1em',
        color: new vscode.ThemeColor('editorError.foreground'),
        fontStyle: 'italic',
      },
      backgroundColor: new vscode.ThemeColor('editorError.background'),
      isWholeLine: false,
    });

    this.warningDecorationType = vscode.window.createTextEditorDecorationType({
      after: {
        margin: '0 0 0 1em',
        color: new vscode.ThemeColor('editorInfo.foreground'),
        fontStyle: 'italic',
      },
    });
  }

  /**
   * Apply visual decorations to the editor.
   */
  apply(editor: vscode.TextEditor, items: FeedbackItem[]): void {
    const vulnDecorations: vscode.DecorationOptions[] = [];
    const hallucinationDecorations: vscode.DecorationOptions[] = [];
    const warningDecorations: vscode.DecorationOptions[] = [];

    for (const item of items) {
      const line = editor.document.lineAt(item.line);
      const range = new vscode.Range(line.range.end, line.range.end);

      const decoration: vscode.DecorationOptions = {
        range,
        renderOptions: {
          after: {
            contentText: ` ⚠️ ${item.message.substring(0, 80)}`,
          },
        },
        hoverMessage: new vscode.MarkdownString(this.buildHoverMarkdown(item)),
      };

      switch (item.severity) {
        case 'error':
          hallucinationDecorations.push(decoration);
          break;
        case 'warning':
          vulnDecorations.push(decoration);
          break;
        default:
          warningDecorations.push(decoration);
          break;
      }
    }

    editor.setDecorations(this.vulnDecorationType, vulnDecorations);
    editor.setDecorations(this.hallucinationDecorationType, hallucinationDecorations);
    editor.setDecorations(this.warningDecorationType, warningDecorations);
  }

  /**
   * Clear all decorations for an editor.
   */
  clear(editor: vscode.TextEditor): void {
    editor.setDecorations(this.vulnDecorationType, []);
    editor.setDecorations(this.hallucinationDecorationType, []);
    editor.setDecorations(this.warningDecorationType, []);
  }

  private buildHoverMarkdown(item: FeedbackItem): string {
    const icon = item.severity === 'error' ? '🔴' : item.severity === 'warning' ? '🟡' : 'ℹ️';
    let md = `${icon} **CodeGuard AI** — ${item.type.toUpperCase()}\n\n`;
    md += `${item.message}\n\n`;
    if (item.fixSuggestion) {
      md += `**Fix:** ${item.fixSuggestion}\n`;
    }
    return md;
  }

  dispose(): void {
    this.vulnDecorationType.dispose();
    this.hallucinationDecorationType.dispose();
    this.warningDecorationType.dispose();
  }
}

// ───────────────────────────────────────────────
// Feedback Item Builder — converts scan results to FeedbackItems
// ───────────────────────────────────────────────

export function buildFeedbackItems(
  dependencies: ParsedDependency[],
  scanResults: Map<string, ScanResult>,
  hallucinationResults?: Map<string, HallucinationAnalysis>
): FeedbackItem[] {
  const items: FeedbackItem[] = [];

  for (const dep of dependencies) {
    const scan = scanResults.get(dep.name);
    if (!scan) { continue; }

    const hallucination = hallucinationResults?.get(dep.name);

    // Hallucinated package
    if (!scan.packageExists) {
      let message = `"${dep.name}" does not exist on ${dep.ecosystem} — AI hallucination detected`;
      let fix = 'Remove this import or replace with a real package';

      if (hallucination?.typosquatSuggestion) {
        message += `. Did you mean "${hallucination.typosquatSuggestion}"?`;
        fix = `Replace with "${hallucination.typosquatSuggestion}"`;
      }

      items.push({
        packageName: dep.name,
        line: dep.line,
        type: 'hallucination',
        message,
        fixSuggestion: fix,
        severity: 'error',
      });
      continue;
    }

    // Typosquatting (exists but suspiciously similar to popular package)
    if (hallucination?.typosquatSuggestion && hallucination.typosquatDistance !== null) {
      items.push({
        packageName: dep.name,
        line: dep.line,
        type: 'typosquat',
        message: `"${dep.name}" looks similar to "${hallucination.typosquatSuggestion}" — possible typosquatting`,
        fixSuggestion: `Verify you meant "${dep.name}" and not "${hallucination.typosquatSuggestion}"`,
        severity: 'warning',
      });
    }

    // Low popularity + recently registered = suspicious
    if (hallucination?.recentlyRegistered && hallucination?.lowPopularity) {
      items.push({
        packageName: dep.name,
        line: dep.line,
        type: 'low-popularity',
        message: `"${dep.name}" was registered recently with very low downloads — possible malicious package`,
        fixSuggestion: 'Verify this package is legitimate before using',
        severity: 'warning',
      });
    }

    // Vulnerabilities
    if (scan.vulnerabilities.length > 0) {
      const topVuln = scan.vulnerabilities[0];
      const count = scan.vulnerabilities.length;
      let message = `${count} vulnerability${count > 1 ? 'ies' : ''} in "${dep.name}"`;
      if (dep.version) { message += `@${dep.version}`; }
      message += ` [${scan.highestSeverity}]`;
      if (topVuln.summary) { message += ` — ${topVuln.summary.substring(0, 60)}`; }

      const fix = topVuln.fixedVersion
        ? `Update to ${dep.name}@${topVuln.fixedVersion}`
        : 'Check for alternative packages';

      items.push({
        packageName: dep.name,
        line: dep.line,
        type: 'vulnerability',
        message,
        fixSuggestion: fix,
        severity: scan.highestSeverity === 'CRITICAL' || scan.highestSeverity === 'HIGH' ? 'error' : 'warning',
      });
    }
  }

  return items;
}
