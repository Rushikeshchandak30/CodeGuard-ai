import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { ScanResult } from '../checkers/types';
import { HallucinationAnalysis } from '../checkers/hallucination';

/**
 * Maintains a live security context that AI tools can access.
 * Written to .codeguard/security-context.json in the workspace
 * and available via VS Code command and Chat Participant API.
 */

export interface SecurityContext {
  timestamp: string;
  securityScore: number;
  totalScanned: number;
  vulnerablePackages: VulnerablePackageInfo[];
  hallucinatedPackages: HallucinatedPackageInfo[];
  safeAlternatives: Record<string, string>;
}

export interface VulnerablePackageInfo {
  name: string;
  version: string | null;
  ecosystem: string;
  cves: string[];
  severity: string;
  fixVersion: string | null;
  alternatives: string[];
}

export interface HallucinatedPackageInfo {
  name: string;
  ecosystem: string;
  suggestion: string | null;
  riskLevel: string;
}

export class SecurityContextProvider {
  private context: SecurityContext;
  private workspaceRoot: string | undefined;

  constructor() {
    this.context = this.emptyContext();
    const folders = vscode.workspace.workspaceFolders;
    if (folders && folders.length > 0) {
      this.workspaceRoot = folders[0].uri.fsPath;
    }
  }

  /**
   * Update the security context with new scan results.
   */
  update(
    scanResults: Map<string, ScanResult>,
    hallucinationResults?: Map<string, HallucinationAnalysis>
  ): void {
    const vulnerablePackages: VulnerablePackageInfo[] = [];
    const hallucinatedPackages: HallucinatedPackageInfo[] = [];
    const safeAlternatives: Record<string, string> = {};
    let totalScanned = 0;

    for (const [name, result] of scanResults) {
      totalScanned++;

      if (!result.packageExists) {
        const hallucination = hallucinationResults?.get(name);
        hallucinatedPackages.push({
          name,
          ecosystem: result.ecosystem,
          suggestion: hallucination?.typosquatSuggestion || null,
          riskLevel: hallucination?.riskLevel || 'critical',
        });

        if (hallucination?.typosquatSuggestion) {
          safeAlternatives[name] = `Use "${hallucination.typosquatSuggestion}" instead`;
        }
        continue;
      }

      if (result.vulnerabilities.length > 0) {
        const topVuln = result.vulnerabilities[0];
        vulnerablePackages.push({
          name,
          version: null, // Will be populated by version resolver
          ecosystem: result.ecosystem,
          cves: result.vulnerabilities.map(v => v.id),
          severity: result.highestSeverity || 'UNKNOWN',
          fixVersion: topVuln.fixedVersion,
          alternatives: [],
        });

        if (topVuln.fixedVersion) {
          safeAlternatives[name] = `Update to ${name}@${topVuln.fixedVersion}`;
        }
      }
    }

    // Calculate security score
    const issueCount = vulnerablePackages.length + hallucinatedPackages.length;
    const criticalCount = vulnerablePackages.filter(p =>
      p.severity === 'CRITICAL' || p.severity === 'HIGH'
    ).length + hallucinatedPackages.length;
    const score = totalScanned === 0 ? 100 : Math.max(0, 100 - criticalCount * 15 - (issueCount - criticalCount) * 5);

    this.context = {
      timestamp: new Date().toISOString(),
      securityScore: score,
      totalScanned,
      vulnerablePackages,
      hallucinatedPackages,
      safeAlternatives,
    };

    // Write to disk for other tools to read
    this.writeToDisk();
  }

  /**
   * Get the current security context.
   */
  getContext(): SecurityContext {
    return this.context;
  }

  /**
   * Get a formatted string for AI prompt injection.
   */
  getAiPromptContext(): string {
    if (this.context.vulnerablePackages.length === 0 && this.context.hallucinatedPackages.length === 0) {
      return ''; // No issues, no context needed
    }

    const parts: string[] = [
      '[SECURITY CONTEXT from CodeGuard AI]',
      `Security Score: ${this.context.securityScore}/100`,
    ];

    if (this.context.vulnerablePackages.length > 0) {
      parts.push(`\nVulnerable packages (DO NOT use these versions):`);
      for (const pkg of this.context.vulnerablePackages) {
        let line = `  - ${pkg.name}${pkg.version ? '@' + pkg.version : ''}: ${pkg.cves.join(', ')} [${pkg.severity}]`;
        if (pkg.fixVersion) {
          line += ` → Use ${pkg.name}@${pkg.fixVersion} instead`;
        }
        parts.push(line);
      }
    }

    if (this.context.hallucinatedPackages.length > 0) {
      parts.push(`\nHallucinated packages (THESE DO NOT EXIST — remove them):`);
      for (const pkg of this.context.hallucinatedPackages) {
        let line = `  - ${pkg.name} (not on ${pkg.ecosystem})`;
        if (pkg.suggestion) {
          line += ` → Did you mean "${pkg.suggestion}"?`;
        }
        parts.push(line);
      }
    }

    parts.push('[END SECURITY CONTEXT]');
    return parts.join('\n');
  }

  /**
   * Write security context to .codeguard/security-context.json in workspace.
   */
  private writeToDisk(): void {
    if (!this.workspaceRoot) { return; }

    try {
      const dir = path.join(this.workspaceRoot, '.codeguard');
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const filePath = path.join(dir, 'security-context.json');
      fs.writeFileSync(filePath, JSON.stringify(this.context, null, 2), 'utf8');
    } catch {
      // Ignore write errors (read-only workspace, etc.)
    }
  }

  private emptyContext(): SecurityContext {
    return {
      timestamp: new Date().toISOString(),
      securityScore: 100,
      totalScanned: 0,
      vulnerablePackages: [],
      hallucinatedPackages: [],
      safeAlternatives: {},
    };
  }
}
