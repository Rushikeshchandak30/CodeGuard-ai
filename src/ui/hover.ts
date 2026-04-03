import * as vscode from 'vscode';
import { ScanResult } from '../checkers/types';

/**
 * Provides rich hover tooltips over imports showing CVE details.
 */
export class HoverProvider implements vscode.HoverProvider {
  private results: Map<string, ScanResult> = new Map();

  /**
   * Update the results used for hover display.
   */
  updateResults(results: Map<string, ScanResult>): void {
    for (const [key, val] of results) {
      this.results.set(key, val);
    }
  }

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken
  ): vscode.Hover | null {
    // Get the word at the hover position
    const wordRange = document.getWordRangeAtPosition(position, /[a-zA-Z0-9@/_.-]+/);
    if (!wordRange) { return null; }

    const word = document.getText(wordRange);

    // Check if this word matches a scanned package
    const result = this.findResult(word);
    if (!result) { return null; }

    const md = new vscode.MarkdownString('', true);
    md.isTrusted = true;
    md.supportHtml = true;

    if (!result.packageExists) {
      md.appendMarkdown(`### $(error) Hallucinated Package Detected\n\n`);
      md.appendMarkdown(`**\`${result.packageName}\`** does not exist on **${result.ecosystem}**.\n\n`);
      md.appendMarkdown(`> **Slopsquatting Risk:** AI may have hallucinated this package name. `);
      md.appendMarkdown(`An attacker could register this name with malicious code.\n\n`);
      md.appendMarkdown(`---\n`);
      md.appendMarkdown(`[Search npm](https://www.npmjs.com/search?q=${encodeURIComponent(result.packageName)}) | `);
      md.appendMarkdown(`[Search PyPI](https://pypi.org/search/?q=${encodeURIComponent(result.packageName)})\n`);
      return new vscode.Hover(md, wordRange);
    }

    if (result.vulnerabilities.length === 0) {
      md.appendMarkdown(`### $(shield) ${result.packageName}\n\n`);
      md.appendMarkdown(`No known vulnerabilities found. $(check)\n`);
      return new vscode.Hover(md, wordRange);
    }

    // Show vulnerability details
    md.appendMarkdown(`### $(warning) ${result.packageName} — ${result.vulnerabilities.length} Vulnerabilit${result.vulnerabilities.length > 1 ? 'ies' : 'y'}\n\n`);

    const maxDisplay = 3;
    for (let i = 0; i < Math.min(result.vulnerabilities.length, maxDisplay); i++) {
      const vuln = result.vulnerabilities[i];
      const severityIcon = this.severityIcon(vuln.severity);

      md.appendMarkdown(`#### ${severityIcon} ${vuln.id} — ${vuln.severity}`);
      if (vuln.cvssScore !== null) {
        md.appendMarkdown(` (CVSS ${vuln.cvssScore})`);
      }
      md.appendMarkdown(`\n\n`);
      md.appendMarkdown(`${vuln.summary}\n\n`);

      if (vuln.affectedVersions !== 'Unknown') {
        md.appendMarkdown(`**Affected:** \`${vuln.affectedVersions}\`\n\n`);
      }
      if (vuln.fixedVersion) {
        md.appendMarkdown(`**Fix:** Update to \`${vuln.fixedVersion}\`\n\n`);
      }

      md.appendMarkdown(`[View Details](${vuln.referenceUrl})\n\n`);

      if (i < Math.min(result.vulnerabilities.length, maxDisplay) - 1) {
        md.appendMarkdown(`---\n\n`);
      }
    }

    if (result.vulnerabilities.length > maxDisplay) {
      md.appendMarkdown(`\n*...and ${result.vulnerabilities.length - maxDisplay} more vulnerabilities*\n`);
    }

    return new vscode.Hover(md, wordRange);
  }

  private findResult(word: string): ScanResult | null {
    // Direct match
    if (this.results.has(word)) {
      return this.results.get(word)!;
    }
    // Try matching scoped packages or partial names
    for (const [name, result] of this.results) {
      if (word.includes(name) || name.includes(word)) {
        return result;
      }
    }
    return null;
  }

  private severityIcon(severity: string): string {
    switch (severity) {
      case 'CRITICAL': return '🔴';
      case 'HIGH': return '🟠';
      case 'MEDIUM': return '🟡';
      case 'LOW': return '🟢';
      default: return '⚪';
    }
  }
}
