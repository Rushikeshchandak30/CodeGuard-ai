import * as vscode from 'vscode';
import { ParsedDependency } from '../parsers/types';
import { ScanResult } from '../checkers/types';

/**
 * Manages VS Code diagnostics (the squiggly underlines) for security issues.
 * Maps scan results to inline warnings in the editor.
 */
export class DiagnosticsProvider {
  private collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('codeguard');
  }

  /**
   * Update diagnostics for a document based on scan results.
   */
  update(
    document: vscode.TextDocument,
    dependencies: ParsedDependency[],
    results: Map<string, ScanResult>
  ): void {
    const diagnostics: vscode.Diagnostic[] = [];

    for (const dep of dependencies) {
      const result = results.get(dep.name);
      if (!result) { continue; }

      // Hallucinated / non-existent package — highest priority
      if (!result.packageExists) {
        const range = new vscode.Range(dep.line, dep.columnStart, dep.line, dep.columnEnd);
        const diag = new vscode.Diagnostic(
          range,
          `🚨 HALLUCINATED PACKAGE: "${dep.name}" does not exist on ${dep.ecosystem}! ` +
          `This may be an AI hallucination (slopsquatting risk). An attacker could register this name with malware.`,
          vscode.DiagnosticSeverity.Error
        );
        diag.code = 'codeguard-hallucinated';
        diag.source = 'CodeGuard AI';
        diagnostics.push(diag);
        continue;
      }

      // Vulnerabilities
      if (result.vulnerabilities.length > 0) {
        const range = new vscode.Range(dep.line, dep.columnStart, dep.line, dep.columnEnd);
        const vulnCount = result.vulnerabilities.length;
        const highest = result.highestSeverity || 'UNKNOWN';
        const topVuln = result.vulnerabilities[0];

        const severity = this.mapSeverity(highest);

        let message = `⚠️ ${vulnCount} vulnerability${vulnCount > 1 ? 'ies' : ''} found in "${dep.name}"`;
        if (dep.version) {
          message += `@${dep.version}`;
        }
        message += ` [${highest}]`;

        // Add top vulnerability details
        message += `\n${topVuln.id}: ${topVuln.summary}`;
        if (topVuln.fixedVersion) {
          message += `\n✅ Fix: update to ${topVuln.fixedVersion}`;
        }
        if (vulnCount > 1) {
          message += `\n... and ${vulnCount - 1} more`;
        }

        const diag = new vscode.Diagnostic(range, message, severity);
        diag.code = {
          value: topVuln.id,
          target: vscode.Uri.parse(topVuln.referenceUrl),
        };
        diag.source = 'CodeGuard AI';
        diagnostics.push(diag);
      }
    }

    this.collection.set(document.uri, diagnostics);
  }

  /**
   * Clear diagnostics for a document.
   */
  clear(document: vscode.TextDocument): void {
    this.collection.delete(document.uri);
  }

  /**
   * Clear all diagnostics.
   */
  clearAll(): void {
    this.collection.clear();
  }

  /**
   * Get current diagnostic count across all documents.
   */
  getCount(): { errors: number; warnings: number; total: number } {
    let errors = 0;
    let warnings = 0;
    this.collection.forEach((uri, diags) => {
      for (const d of diags) {
        if (d.severity === vscode.DiagnosticSeverity.Error) { errors++; }
        else { warnings++; }
      }
    });
    return { errors, warnings, total: errors + warnings };
  }

  dispose(): void {
    this.collection.dispose();
  }

  private mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return vscode.DiagnosticSeverity.Error;
      case 'MEDIUM':
        return vscode.DiagnosticSeverity.Warning;
      case 'LOW':
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Warning;
    }
  }
}
