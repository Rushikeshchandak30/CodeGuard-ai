/**
 * Trust Tier Tree View
 *
 * VS Code sidebar panel showing all dependencies organized by trust tier:
 * - 🟢 VERIFIED — Sigstore provenance + verified publisher + high downloads
 * - 🟡 PARTIAL — Exists on registry, no provenance, decent downloads
 * - 🟠 SUSPICIOUS — No provenance, low downloads, recently registered
 * - 🔴 UNTRUSTED — Not on registry / known hallucination / malware flagged
 *
 * Provides quick access to:
 * - Package provenance details
 * - Vulnerability status
 * - One-click patch actions
 */

import * as vscode from 'vscode';
import { ProvenanceChecker, TrustTier } from '../checkers/provenance';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DependencyInfo {
  name: string;
  version: string;
  ecosystem: string;
  trustTier: TrustTier;
  hasProvenance: boolean;
  vulnerabilityCount: number;
  deprecated: boolean;
  filePath: string;
}

// ---------------------------------------------------------------------------
// Tree Item Classes
// ---------------------------------------------------------------------------

class TrustTierItem extends vscode.TreeItem {
  constructor(
    public readonly tier: TrustTier,
    public readonly count: number,
  ) {
    super(
      `${TrustTierItem.getEmoji(tier)} ${TrustTierItem.getLabel(tier)} (${count})`,
      count > 0 ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.None,
    );

    this.contextValue = 'trustTier';
    this.tooltip = TrustTierItem.getTooltip(tier);
  }

  static getEmoji(tier: TrustTier): string {
    switch (tier) {
      case 'verified': return '🟢';
      case 'partial': return '🟡';
      case 'suspicious': return '🟠';
      case 'untrusted': return '🔴';
    }
  }

  static getLabel(tier: TrustTier): string {
    switch (tier) {
      case 'verified': return 'Verified';
      case 'partial': return 'Partial Trust';
      case 'suspicious': return 'Suspicious';
      case 'untrusted': return 'Untrusted';
    }
  }

  static getTooltip(tier: TrustTier): string {
    switch (tier) {
      case 'verified': return 'Packages with Sigstore provenance, verified publisher, and high download counts';
      case 'partial': return 'Packages that exist on registry but lack provenance attestation';
      case 'suspicious': return 'Packages with low downloads, no provenance, or recently registered';
      case 'untrusted': return 'Packages that do not exist, are known hallucinations, or flagged as malware';
    }
  }
}

class DependencyItem extends vscode.TreeItem {
  constructor(
    public readonly dep: DependencyInfo,
  ) {
    super(dep.name, vscode.TreeItemCollapsibleState.None);

    this.description = dep.version;
    this.contextValue = 'dependency';

    // Build tooltip
    const parts: string[] = [
      `${dep.name}@${dep.version}`,
      `Ecosystem: ${dep.ecosystem}`,
      `Trust: ${TrustTierItem.getLabel(dep.trustTier)}`,
      `Provenance: ${dep.hasProvenance ? 'Yes ✓' : 'No'}`,
    ];

    if (dep.vulnerabilityCount > 0) {
      parts.push(`Vulnerabilities: ${dep.vulnerabilityCount}`);
    }

    if (dep.deprecated) {
      parts.push('⚠️ DEPRECATED');
    }

    this.tooltip = parts.join('\n');

    // Set icon based on status
    if (dep.vulnerabilityCount > 0) {
      this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
    } else if (dep.deprecated) {
      this.iconPath = new vscode.ThemeIcon('circle-slash', new vscode.ThemeColor('editorWarning.foreground'));
    } else if (dep.hasProvenance) {
      this.iconPath = new vscode.ThemeIcon('verified', new vscode.ThemeColor('charts.green'));
    } else {
      this.iconPath = new vscode.ThemeIcon('package');
    }

    // Command to show details
    this.command = {
      command: 'codeguard.showDependencyDetails',
      title: 'Show Details',
      arguments: [dep],
    };
  }
}

// ---------------------------------------------------------------------------
// Tree Data Provider
// ---------------------------------------------------------------------------

export class TrustTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined | null | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private dependencies: DependencyInfo[] = [];
  private provenanceChecker: ProvenanceChecker;
  private isLoading: boolean = false;

  constructor(provenanceChecker?: ProvenanceChecker) {
    this.provenanceChecker = provenanceChecker ?? new ProvenanceChecker();
  }

  /**
   * Refresh the tree view.
   */
  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  /**
   * Reload all dependencies from workspace.
   */
  async reload(): Promise<void> {
    if (this.isLoading) { return; }
    this.isLoading = true;

    try {
      this.dependencies = await this.loadDependencies();
      this.refresh();
    } finally {
      this.isLoading = false;
    }
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  async getChildren(element?: vscode.TreeItem): Promise<vscode.TreeItem[]> {
    if (!element) {
      // Root level: show trust tiers
      const tiers: TrustTier[] = ['verified', 'partial', 'suspicious', 'untrusted'];
      return tiers.map(tier => {
        const count = this.dependencies.filter(d => d.trustTier === tier).length;
        return new TrustTierItem(tier, count);
      });
    }

    if (element instanceof TrustTierItem) {
      // Show dependencies for this tier
      const deps = this.dependencies.filter(d => d.trustTier === element.tier);
      return deps.map(d => new DependencyItem(d));
    }

    return [];
  }

  /**
   * Get summary statistics.
   */
  getStats(): { total: number; verified: number; partial: number; suspicious: number; untrusted: number; vulnerable: number } {
    return {
      total: this.dependencies.length,
      verified: this.dependencies.filter(d => d.trustTier === 'verified').length,
      partial: this.dependencies.filter(d => d.trustTier === 'partial').length,
      suspicious: this.dependencies.filter(d => d.trustTier === 'suspicious').length,
      untrusted: this.dependencies.filter(d => d.trustTier === 'untrusted').length,
      vulnerable: this.dependencies.filter(d => d.vulnerabilityCount > 0).length,
    };
  }

  // -------------------------------------------------------------------------
  // Private methods
  // -------------------------------------------------------------------------

  private async loadDependencies(): Promise<DependencyInfo[]> {
    const deps: DependencyInfo[] = [];

    // Find package.json files
    const packageJsonFiles = await vscode.workspace.findFiles('**/package.json', '**/node_modules/**', 10);

    for (const file of packageJsonFiles) {
      try {
        const content = await vscode.workspace.fs.readFile(file);
        const pkg = JSON.parse(content.toString());

        const allDeps = {
          ...pkg.dependencies,
          ...pkg.devDependencies,
        };

        // Limit to first 50 deps to avoid slowdown
        const entries = Object.entries(allDeps).slice(0, 50);

        for (const [name, versionSpec] of entries) {
          const version = this.cleanVersion(versionSpec as string);

          // Check provenance (with timeout)
          let trustTier: TrustTier = 'partial';
          let hasProvenance = false;

          try {
            const result = await Promise.race([
              this.provenanceChecker.check(name, version, 'npm'),
              new Promise<null>((resolve) => setTimeout(() => resolve(null), 3000)),
            ]);

            if (result) {
              trustTier = result.trustTier;
              hasProvenance = result.hasProvenance;
            }
          } catch {
            // Default to partial on error
          }

          deps.push({
            name,
            version,
            ecosystem: 'npm',
            trustTier,
            hasProvenance,
            vulnerabilityCount: 0, // Would need OSV integration
            deprecated: false,
            filePath: file.fsPath,
          });
        }
      } catch {
        // Skip invalid files
      }
    }

    // Sort by trust tier (untrusted first)
    const tierOrder: Record<TrustTier, number> = {
      'untrusted': 0,
      'suspicious': 1,
      'partial': 2,
      'verified': 3,
    };

    deps.sort((a, b) => tierOrder[a.trustTier] - tierOrder[b.trustTier]);

    return deps;
  }

  private cleanVersion(version: string): string {
    return version.replace(/^[\^~>=<]+/, '').split(' ')[0];
  }
}

// ---------------------------------------------------------------------------
// Register Tree View
// ---------------------------------------------------------------------------

export function registerTrustTreeView(context: vscode.ExtensionContext, provenanceChecker?: ProvenanceChecker): TrustTreeProvider {
  const provider = new TrustTreeProvider(provenanceChecker);

  const treeView = vscode.window.createTreeView('codeguardTrustTree', {
    treeDataProvider: provider,
    showCollapseAll: true,
  });

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.refreshTrustTree', () => {
      provider.reload();
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('codeguard.showDependencyDetails', async (dep: DependencyInfo) => {
      const result = await vscode.window.showQuickPick([
        { label: '$(search) Check Provenance', action: 'provenance' },
        { label: '$(shield) Check Vulnerabilities', action: 'vulnerabilities' },
        { label: '$(file) Go to Definition', action: 'goto' },
      ], {
        title: `${dep.name}@${dep.version}`,
        placeHolder: 'Select an action',
      });

      if (result?.action === 'provenance') {
        vscode.commands.executeCommand('codeguard.checkProvenance', dep.name);
      } else if (result?.action === 'vulnerabilities') {
        vscode.commands.executeCommand('codeguard.getPatchReport', dep.name, dep.version);
      } else if (result?.action === 'goto') {
        const doc = await vscode.workspace.openTextDocument(dep.filePath);
        await vscode.window.showTextDocument(doc);
      }
    }),
  );

  context.subscriptions.push(treeView);

  // Initial load
  provider.reload();

  return provider;
}
