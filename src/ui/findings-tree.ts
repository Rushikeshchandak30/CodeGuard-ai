/**
 * Findings TreeView
 *
 * Sidebar panel that aggregates all security findings from every checker
 * (dependencies, secrets, SAST, hallucinations, provenance) and organizes
 * them by severity: Critical → High → Medium → Low → Info.
 *
 * Each finding shows file, line, description, and provides quick actions
 * (Fix, Ignore, Details).
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Finding Types
// ---------------------------------------------------------------------------

export interface SecurityFinding {
  id: string;
  source: 'dependency' | 'secret' | 'sast' | 'hallucination' | 'provenance' | 'rules' | 'install-script';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  filePath?: string;
  line?: number;
  packageName?: string;
  fixAvailable?: boolean;
  fixCommand?: string;
}

// ---------------------------------------------------------------------------
// Tree Items
// ---------------------------------------------------------------------------

class SeverityGroupItem extends vscode.TreeItem {
  constructor(
    public readonly severityLabel: string,
    public readonly findings: SecurityFinding[],
    iconId: string,
    iconColor: string,
  ) {
    super(
      `${severityLabel} (${findings.length})`,
      findings.length > 0 ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed
    );
    this.contextValue = 'severityGroup';
    this.iconPath = new vscode.ThemeIcon(iconId, new vscode.ThemeColor(iconColor));
    this.tooltip = new vscode.MarkdownString(
      `**${findings.length}** ${severityLabel.toLowerCase()} finding(s)`
    );
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(public readonly finding: SecurityFinding) {
    super(finding.title, vscode.TreeItemCollapsibleState.None);

    this.description = FindingItem.sourceLabel(finding.source);
    this.tooltip = new vscode.MarkdownString(FindingItem.buildTooltip(finding));

    // Icon based on source type
    this.iconPath = new vscode.ThemeIcon(
      FindingItem.sourceIcon(finding.source),
      finding.severity === 'critical' ? new vscode.ThemeColor('errorForeground') :
        finding.severity === 'high' ? new vscode.ThemeColor('editorWarning.foreground') :
          finding.severity === 'medium' ? new vscode.ThemeColor('editorWarning.foreground') :
            undefined
    );

    // Show file path as resource URI when available
    if (finding.filePath) {
      this.resourceUri = vscode.Uri.file(finding.filePath);
    }

    // Click to navigate to the finding location
    if (finding.filePath && finding.line !== undefined) {
      this.command = {
        command: 'codeguard.goToFinding',
        title: 'Go to Finding',
        arguments: [finding],
      };
    }

    this.contextValue = finding.fixAvailable ? 'findingWithFix' : 'finding';
  }

  private static buildTooltip(f: SecurityFinding): string {
    const sevEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️' };
    let md = `**${f.title}**\n\n`;
    md += `${sevEmoji[f.severity] ?? ''} **Severity:** ${f.severity.toUpperCase()}\n\n`;
    md += `- **Source:** ${FindingItem.sourceLabel(f.source)}\n`;
    if (f.packageName) { md += `- **Package:** \`${f.packageName}\`\n`; }
    if (f.filePath) { md += `- **File:** \`${f.filePath}${f.line !== undefined ? `:${f.line + 1}` : ''}\`\n`; }
    md += `\n${f.description}`;
    if (f.fixAvailable) { md += `\n\n✅ **Fix available** — ${f.fixCommand ?? 'auto-fix'}`; }
    return md;
  }

  private static sourceIcon(source: SecurityFinding['source']): string {
    const icons: Record<string, string> = {
      dependency: 'package',
      secret: 'key',
      sast: 'code',
      hallucination: 'sparkle',
      provenance: 'verified',
      rules: 'note',
      'install-script': 'terminal',
    };
    return icons[source] ?? 'circle-outline';
  }

  private static sourceLabel(source: SecurityFinding['source']): string {
    const labels: Record<string, string> = {
      dependency: 'Dependency',
      secret: 'Secret',
      sast: 'SAST',
      hallucination: 'Hallucination',
      provenance: 'Provenance',
      rules: 'Rules File',
      'install-script': 'Install Script',
    };
    return labels[source] ?? source;
  }
}

type TreeNode = SeverityGroupItem | FindingItem;

// ---------------------------------------------------------------------------
// FindingsTreeProvider
// ---------------------------------------------------------------------------

export class FindingsTreeProvider implements vscode.TreeDataProvider<TreeNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: SecurityFinding[] = [];

  getTreeItem(element: TreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    if (!element) {
      // Root — return severity groups
      return this.buildSeverityGroups();
    }

    if (element instanceof SeverityGroupItem) {
      return element.findings.map(f => new FindingItem(f));
    }

    return [];
  }

  /**
   * Replace all findings and refresh the tree.
   */
  setFindings(findings: SecurityFinding[]): void {
    this.findings = findings;
    this._onDidChangeTreeData.fire();
  }

  /**
   * Add findings (merge, deduplicate by id).
   */
  addFindings(newFindings: SecurityFinding[]): void {
    const existingIds = new Set(this.findings.map(f => f.id));
    for (const f of newFindings) {
      if (!existingIds.has(f.id)) {
        this.findings.push(f);
        existingIds.add(f.id);
      }
    }
    this._onDidChangeTreeData.fire();
  }

  /**
   * Remove findings by source (e.g., clear all 'secret' findings before re-scan).
   */
  clearBySource(source: SecurityFinding['source']): void {
    this.findings = this.findings.filter(f => f.source !== source);
    this._onDidChangeTreeData.fire();
  }

  /**
   * Clear all findings.
   */
  clearAll(): void {
    this.findings = [];
    this._onDidChangeTreeData.fire();
  }

  /**
   * Get total finding count.
   */
  getCount(): number {
    return this.findings.length;
  }

  /**
   * Get counts by severity.
   */
  getCounts(): Record<string, number> {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of this.findings) {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }
    return counts;
  }

  /**
   * Refresh the tree display.
   */
  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  private buildSeverityGroups(): SeverityGroupItem[] {
    const groups: { label: string; iconId: string; color: string; severity: string }[] = [
      { label: 'Critical', iconId: 'error', color: 'errorForeground', severity: 'critical' },
      { label: 'High', iconId: 'warning', color: 'editorWarning.foreground', severity: 'high' },
      { label: 'Medium', iconId: 'warning', color: 'editorWarning.foreground', severity: 'medium' },
      { label: 'Low', iconId: 'info', color: 'editorInfo.foreground', severity: 'low' },
      { label: 'Info', iconId: 'info', color: 'descriptionForeground', severity: 'info' },
    ];

    return groups
      .map(g => {
        const findings = this.findings.filter(f => f.severity === g.severity);
        return new SeverityGroupItem(g.label, findings, g.iconId, g.color);
      })
      .filter(g => g.findings.length > 0); // Only show groups with findings
  }

  dispose(): void {
    this._onDidChangeTreeData.dispose();
  }
}

// ---------------------------------------------------------------------------
// Registration Helper
// ---------------------------------------------------------------------------

export function registerFindingsTreeView(
  context: vscode.ExtensionContext
): FindingsTreeProvider {
  const provider = new FindingsTreeProvider();

  const treeView = vscode.window.createTreeView('codeguardFindings', {
    treeDataProvider: provider,
    showCollapseAll: true,
  });

  // Badge: show finding count on sidebar icon
  const updateBadge = () => {
    const count = provider.getCount();
    treeView.badge = count > 0
      ? { value: count, tooltip: `${count} security finding(s)` }
      : undefined;
  };
  provider.onDidChangeTreeData(() => updateBadge());

  // Welcome message when no findings
  treeView.message = 'No security findings. Run a scan to get started.';
  provider.onDidChangeTreeData(() => {
    treeView.message = provider.getCount() === 0
      ? 'No security findings. Run a scan to get started.'
      : undefined;
  });

  // "Go to Finding" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.goToFinding', async (finding: SecurityFinding) => {
      if (!finding.filePath) { return; }
      const uri = vscode.Uri.file(finding.filePath);
      const doc = await vscode.workspace.openTextDocument(uri);
      const line = finding.line ?? 0;
      const editor = await vscode.window.showTextDocument(doc, {
        selection: new vscode.Range(line, 0, line, 0),
        preserveFocus: false,
      });
      editor.revealRange(new vscode.Range(line, 0, line, 0), vscode.TextEditorRevealType.InCenter);
    })
  );

  // "Refresh Findings" command
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.refreshFindings', () => {
      provider.refresh();
    })
  );

  context.subscriptions.push(treeView);

  return provider;
}
