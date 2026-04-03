/**
 * Agentic Patch Assistant
 *
 * Automated workflow for fixing vulnerable dependencies:
 * 1. Detect vulnerable package
 * 2. Query GHIN + OSV for fix information
 * 3. Generate patch (edit package.json / requirements.txt)
 * 4. Optionally create PR or apply directly
 *
 * This is the "self-healing dependency network" feature.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { AutoPatchEngine, PatchReport } from '../checkers/auto-patch';
import { LlmAdvisor } from './llm-advisor';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PatchAction {
  type: 'update' | 'replace' | 'remove';
  packageName: string;
  ecosystem: string;
  currentVersion: string | null;
  targetVersion: string | null;
  replacement: string | null;
  filePath: string;
  lineNumber: number | null;
}

export interface PatchResult {
  success: boolean;
  action: PatchAction;
  message: string;
  diff: string | null;
}

export interface AgentWorkflowResult {
  packagesAnalyzed: number;
  patchesAvailable: number;
  patchesApplied: number;
  errors: string[];
  summary: string;
}

// ---------------------------------------------------------------------------
// Patch Agent Class
// ---------------------------------------------------------------------------

export class PatchAgent {
  private patchEngine: AutoPatchEngine;
  private llmAdvisor: LlmAdvisor;

  constructor(patchEngine?: AutoPatchEngine) {
    this.patchEngine = patchEngine ?? new AutoPatchEngine();
    this.llmAdvisor = new LlmAdvisor();
  }

  /**
   * Analyze a workspace and suggest patches for all vulnerable dependencies.
   */
  async analyzeWorkspace(): Promise<Map<string, PatchReport>> {
    const reports = new Map<string, PatchReport>();

    // Find package.json files
    const packageJsonFiles = await vscode.workspace.findFiles('**/package.json', '**/node_modules/**');

    for (const file of packageJsonFiles) {
      try {
        const content = await vscode.workspace.fs.readFile(file);
        const pkg = JSON.parse(content.toString());

        const allDeps = {
          ...pkg.dependencies,
          ...pkg.devDependencies,
        };

        for (const [name, version] of Object.entries(allDeps)) {
          const cleanVersion = this.cleanVersion(version as string);
          const report = await this.patchEngine.getPatchReport(name, cleanVersion, 'npm');

          if (report.totalVulnerabilities > 0 || report.deprecated) {
            reports.set(`npm:${name}`, report);
          }
        }
      } catch {
        // Skip invalid package.json files
      }
    }

    // Find requirements.txt files
    const requirementsFiles = await vscode.workspace.findFiles('**/requirements.txt', '**/venv/**');

    for (const file of requirementsFiles) {
      try {
        const content = await vscode.workspace.fs.readFile(file);
        const lines = content.toString().split('\n');

        for (const line of lines) {
          const match = /^([a-zA-Z0-9_-]+)(?:[=<>!~]+(.+))?/.exec(line.trim());
          if (match) {
            const name = match[1];
            const version = match[2] || null;
            const report = await this.patchEngine.getPatchReport(name, version, 'PyPI');

            if (report.totalVulnerabilities > 0 || report.deprecated) {
              reports.set(`PyPI:${name}`, report);
            }
          }
        }
      } catch {
        // Skip invalid requirements files
      }
    }

    return reports;
  }

  /**
   * Generate patch actions for a specific package.
   */
  async generatePatchActions(report: PatchReport): Promise<PatchAction[]> {
    const actions: PatchAction[] = [];

    // Find the file containing this dependency
    const filePath = await this.findDependencyFile(report.packageName, report.ecosystem);
    if (!filePath) {
      return actions;
    }

    // Determine the best action
    if (report.patches.length > 0) {
      // Find the best patch (highest safe version)
      const bestPatch = report.patches.find(p => p.safeVersion !== null);

      if (bestPatch?.safeVersion) {
        actions.push({
          type: 'update',
          packageName: report.packageName,
          ecosystem: report.ecosystem,
          currentVersion: report.currentVersion,
          targetVersion: bestPatch.safeVersion,
          replacement: null,
          filePath,
          lineNumber: null,
        });
      }
    }

    // If deprecated, suggest replacement (get alternatives from first patch or KNOWN_ALTERNATIVES)
    const alternatives = report.patches[0]?.alternatives ?? [];
    if (report.deprecated && alternatives.length > 0) {
      actions.push({
        type: 'replace',
        packageName: report.packageName,
        ecosystem: report.ecosystem,
        currentVersion: report.currentVersion,
        targetVersion: null,
        replacement: alternatives[0],
        filePath,
        lineNumber: null,
      });
    }

    return actions;
  }

  /**
   * Apply a patch action to the workspace.
   */
  async applyPatch(action: PatchAction): Promise<PatchResult> {
    try {
      const document = await vscode.workspace.openTextDocument(action.filePath);
      const text = document.getText();

      let newText: string;
      let diff: string;

      if (action.ecosystem === 'npm') {
        const result = this.patchPackageJson(text, action);
        newText = result.newText;
        diff = result.diff;
      } else if (action.ecosystem === 'PyPI') {
        const result = this.patchRequirementsTxt(text, action);
        newText = result.newText;
        diff = result.diff;
      } else {
        return {
          success: false,
          action,
          message: `Unsupported ecosystem: ${action.ecosystem}`,
          diff: null,
        };
      }

      // Apply the edit
      const edit = new vscode.WorkspaceEdit();
      edit.replace(
        document.uri,
        new vscode.Range(0, 0, document.lineCount, 0),
        newText,
      );

      const success = await vscode.workspace.applyEdit(edit);

      if (success) {
        await document.save();
        return {
          success: true,
          action,
          message: `Successfully ${action.type === 'update' ? 'updated' : 'replaced'} ${action.packageName}`,
          diff,
        };
      } else {
        return {
          success: false,
          action,
          message: 'Failed to apply edit',
          diff: null,
        };
      }
    } catch (err) {
      return {
        success: false,
        action,
        message: `Error: ${err}`,
        diff: null,
      };
    }
  }

  /**
   * Run the full agentic workflow: analyze → suggest → apply (with user approval).
   */
  async runWorkflow(autoApply: boolean = false): Promise<AgentWorkflowResult> {
    const result: AgentWorkflowResult = {
      packagesAnalyzed: 0,
      patchesAvailable: 0,
      patchesApplied: 0,
      errors: [],
      summary: '',
    };

    // Step 1: Analyze workspace
    const reports = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: 'CodeGuard: Analyzing dependencies...' },
      () => this.analyzeWorkspace(),
    );

    result.packagesAnalyzed = reports.size;

    if (reports.size === 0) {
      result.summary = 'No vulnerable or deprecated packages found.';
      return result;
    }

    // Step 2: Generate patch actions
    const allActions: PatchAction[] = [];
    for (const report of reports.values()) {
      const actions = await this.generatePatchActions(report);
      allActions.push(...actions);
    }

    result.patchesAvailable = allActions.length;

    if (allActions.length === 0) {
      result.summary = `Found ${reports.size} issues but no automatic patches available.`;
      return result;
    }

    // Step 3: Show user the patches and get approval
    if (!autoApply) {
      const items = allActions.map(a => ({
        label: `${a.type === 'update' ? '⬆️' : '🔄'} ${a.packageName}`,
        description: a.type === 'update'
          ? `${a.currentVersion ?? 'unknown'} → ${a.targetVersion}`
          : `Replace with ${a.replacement}`,
        picked: true,
        action: a,
      }));

      const selected = await vscode.window.showQuickPick(items, {
        canPickMany: true,
        title: 'CodeGuard Patch Agent — Select patches to apply',
        placeHolder: 'Select the patches you want to apply',
      });

      if (!selected || selected.length === 0) {
        result.summary = 'Patch workflow cancelled by user.';
        return result;
      }

      // Apply selected patches
      for (const item of selected) {
        const patchResult = await this.applyPatch(item.action);
        if (patchResult.success) {
          result.patchesApplied++;
        } else {
          result.errors.push(patchResult.message);
        }
      }
    } else {
      // Auto-apply all patches
      for (const action of allActions) {
        const patchResult = await this.applyPatch(action);
        if (patchResult.success) {
          result.patchesApplied++;
        } else {
          result.errors.push(patchResult.message);
        }
      }
    }

    result.summary = `Applied ${result.patchesApplied}/${result.patchesAvailable} patches. ${result.errors.length > 0 ? `${result.errors.length} errors.` : ''}`;

    return result;
  }

  /**
   * Generate an LLM-powered explanation for a patch.
   */
  async explainPatch(report: PatchReport): Promise<string> {
    const alternatives = report.patches[0]?.alternatives ?? [];
    const explanation = await this.llmAdvisor.explainPatch({
      packageName: report.packageName,
      ecosystem: report.ecosystem,
      currentVersion: report.currentVersion,
      vulnerabilities: report.patches.map(p => ({
        id: p.vulnerabilityId,
        severity: p.severity,
        summary: p.fixDescription,
      })),
      fixedVersion: report.patches.find(p => p.safeVersion)?.safeVersion ?? null,
      alternatives,
    });

    return `## ${report.packageName}

**Summary:** ${explanation.summary}

**Risk:** ${explanation.riskExplanation}

**Action:** ${explanation.recommendedAction}

${explanation.codeSnippet ? `\`\`\`bash\n${explanation.codeSnippet}\n\`\`\`` : ''}`;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private cleanVersion(version: string): string {
    return version.replace(/^[\^~>=<]+/, '').split(' ')[0];
  }

  private async findDependencyFile(packageName: string, ecosystem: string): Promise<string | null> {
    if (ecosystem === 'npm') {
      const files = await vscode.workspace.findFiles('**/package.json', '**/node_modules/**');
      for (const file of files) {
        try {
          const content = await vscode.workspace.fs.readFile(file);
          const pkg = JSON.parse(content.toString());
          if (pkg.dependencies?.[packageName] || pkg.devDependencies?.[packageName]) {
            return file.fsPath;
          }
        } catch {
          continue;
        }
      }
    } else if (ecosystem === 'PyPI') {
      const files = await vscode.workspace.findFiles('**/requirements.txt', '**/venv/**');
      for (const file of files) {
        try {
          const content = await vscode.workspace.fs.readFile(file);
          if (content.toString().includes(packageName)) {
            return file.fsPath;
          }
        } catch {
          continue;
        }
      }
    }
    return null;
  }

  private patchPackageJson(text: string, action: PatchAction): { newText: string; diff: string } {
    const pkg = JSON.parse(text);
    let diff = '';

    if (action.type === 'update' && action.targetVersion) {
      if (pkg.dependencies?.[action.packageName]) {
        const old = pkg.dependencies[action.packageName];
        pkg.dependencies[action.packageName] = `^${action.targetVersion}`;
        diff = `- "${action.packageName}": "${old}"\n+ "${action.packageName}": "^${action.targetVersion}"`;
      } else if (pkg.devDependencies?.[action.packageName]) {
        const old = pkg.devDependencies[action.packageName];
        pkg.devDependencies[action.packageName] = `^${action.targetVersion}`;
        diff = `- "${action.packageName}": "${old}"\n+ "${action.packageName}": "^${action.targetVersion}"`;
      }
    } else if (action.type === 'replace' && action.replacement) {
      // Remove old, add new
      if (pkg.dependencies?.[action.packageName]) {
        const old = pkg.dependencies[action.packageName];
        delete pkg.dependencies[action.packageName];
        pkg.dependencies[action.replacement] = 'latest';
        diff = `- "${action.packageName}": "${old}"\n+ "${action.replacement}": "latest"`;
      } else if (pkg.devDependencies?.[action.packageName]) {
        const old = pkg.devDependencies[action.packageName];
        delete pkg.devDependencies[action.packageName];
        pkg.devDependencies[action.replacement] = 'latest';
        diff = `- "${action.packageName}": "${old}"\n+ "${action.replacement}": "latest"`;
      }
    }

    return { newText: JSON.stringify(pkg, null, 2) + '\n', diff };
  }

  private patchRequirementsTxt(text: string, action: PatchAction): { newText: string; diff: string } {
    const lines = text.split('\n');
    let diff = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith(action.packageName) || line.startsWith(`${action.packageName}=`) || line.startsWith(`${action.packageName}>`)) {
        if (action.type === 'update' && action.targetVersion) {
          const oldLine = lines[i];
          lines[i] = `${action.packageName}>=${action.targetVersion}`;
          diff = `- ${oldLine}\n+ ${lines[i]}`;
        } else if (action.type === 'replace' && action.replacement) {
          const oldLine = lines[i];
          lines[i] = action.replacement;
          diff = `- ${oldLine}\n+ ${lines[i]}`;
        }
        break;
      }
    }

    return { newText: lines.join('\n'), diff };
  }
}
