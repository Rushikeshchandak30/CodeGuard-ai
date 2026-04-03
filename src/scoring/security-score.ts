/**
 * Developer Security Score — Project Security Posture (0-100)
 *
 * Computes a composite security score for the current workspace based on:
 * - Vulnerable dependencies (OSV/CVE data)
 * - Hallucinated packages (GHIN)
 * - Hardcoded secrets found
 * - Code vulnerability patterns (SAST)
 * - Unverified provenance (trust tiers)
 * - Deprecated packages in use
 * - SBOM freshness
 *
 * Score displayed in status bar and security dashboard.
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Score Signal Types
// ---------------------------------------------------------------------------

export interface ScoreSignal {
  category: 'dependency' | 'secret' | 'code' | 'provenance' | 'hallucination' | 'sbom';
  severity: 'critical' | 'high' | 'medium' | 'low';
  count: number;
  description: string;
}

export interface SecurityScoreResult {
  score: number;               // 0-100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  label: string;               // "Excellent" | "Good" | "Fair" | "Poor" | "Critical"
  signals: ScoreSignal[];
  breakdown: {
    dependencies: number;      // 0-100 sub-score
    secrets: number;
    code: number;
    provenance: number;
  };
  computedAt: Date;
}

// ---------------------------------------------------------------------------
// Score Weights
// ---------------------------------------------------------------------------

const DEDUCTIONS: Record<string, Record<string, number>> = {
  dependency: { critical: 20, high: 10, medium: 5, low: 2 },
  secret:     { critical: 25, high: 15, medium: 8, low: 3 },
  code:       { critical: 15, high: 8,  medium: 4, low: 1 },
  provenance: { critical: 10, high: 5,  medium: 2, low: 1 },
  hallucination: { critical: 20, high: 12, medium: 6, low: 2 },
  sbom:       { critical: 5,  high: 3,  medium: 1, low: 0 },
};

// ---------------------------------------------------------------------------
// SecurityScoreEngine
// ---------------------------------------------------------------------------

export class SecurityScoreEngine {
  private signals: ScoreSignal[] = [];
  private lastResult: SecurityScoreResult | null = null;
  private statusBarItem: vscode.StatusBarItem;
  private onScoreChangeEmitter = new vscode.EventEmitter<SecurityScoreResult>();

  readonly onScoreChange = this.onScoreChangeEmitter.event;

  constructor() {
    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      90  // priority — appears left of CodeGuard main status
    );
    this.statusBarItem.command = 'codeguard.showDashboard';
    this.statusBarItem.tooltip = 'CodeGuard AI — Security Score. Click to open dashboard.';
  }

  /**
   * Reset all signals and recompute.
   */
  reset(): void {
    this.signals = [];
  }

  /**
   * Add a signal to the score engine.
   */
  addSignal(signal: ScoreSignal): void {
    this.signals.push(signal);
  }

  /**
   * Report vulnerable dependency findings.
   */
  reportVulnerableDependencies(critical: number, high: number, medium: number, low: number): void {
    if (critical > 0) { this.signals.push({ category: 'dependency', severity: 'critical', count: critical, description: `${critical} critical CVE(s)` }); }
    if (high > 0)     { this.signals.push({ category: 'dependency', severity: 'high',     count: high,     description: `${high} high CVE(s)` }); }
    if (medium > 0)   { this.signals.push({ category: 'dependency', severity: 'medium',   count: medium,   description: `${medium} medium CVE(s)` }); }
    if (low > 0)      { this.signals.push({ category: 'dependency', severity: 'low',      count: low,      description: `${low} low CVE(s)` }); }
  }

  /**
   * Report hardcoded secret findings.
   */
  reportSecrets(critical: number, high: number, medium: number): void {
    if (critical > 0) { this.signals.push({ category: 'secret', severity: 'critical', count: critical, description: `${critical} critical secret(s) exposed` }); }
    if (high > 0)     { this.signals.push({ category: 'secret', severity: 'high',     count: high,     description: `${high} high-risk secret(s) exposed` }); }
    if (medium > 0)   { this.signals.push({ category: 'secret', severity: 'medium',   count: medium,   description: `${medium} medium-risk secret(s) exposed` }); }
  }

  /**
   * Report SAST code vulnerability findings.
   */
  reportCodeVulns(critical: number, high: number, medium: number, low: number): void {
    if (critical > 0) { this.signals.push({ category: 'code', severity: 'critical', count: critical, description: `${critical} critical code vuln(s)` }); }
    if (high > 0)     { this.signals.push({ category: 'code', severity: 'high',     count: high,     description: `${high} high code vuln(s)` }); }
    if (medium > 0)   { this.signals.push({ category: 'code', severity: 'medium',   count: medium,   description: `${medium} medium code vuln(s)` }); }
    if (low > 0)      { this.signals.push({ category: 'code', severity: 'low',      count: low,      description: `${low} low code vuln(s)` }); }
  }

  /**
   * Report hallucinated package findings.
   */
  reportHallucinations(count: number): void {
    if (count > 0) {
      this.signals.push({ category: 'hallucination', severity: 'critical', count, description: `${count} hallucinated package(s)` });
    }
  }

  /**
   * Report untrusted/suspicious provenance.
   */
  reportProvenanceIssues(untrusted: number, suspicious: number): void {
    if (untrusted > 0)   { this.signals.push({ category: 'provenance', severity: 'high',   count: untrusted,   description: `${untrusted} untrusted package(s)` }); }
    if (suspicious > 0)  { this.signals.push({ category: 'provenance', severity: 'medium', count: suspicious,  description: `${suspicious} suspicious package(s)` }); }
  }

  /**
   * Compute the security score from current signals.
   */
  compute(): SecurityScoreResult {
    let score = 100;
    let depScore = 100;
    let secretScore = 100;
    let codeScore = 100;
    let provScore = 100;

    for (const signal of this.signals) {
      const deduction = (DEDUCTIONS[signal.category]?.[signal.severity] ?? 0) * Math.min(signal.count, 5);
      score = Math.max(0, score - deduction);

      switch (signal.category) {
        case 'dependency':
        case 'hallucination':
          depScore = Math.max(0, depScore - deduction * 1.5);
          break;
        case 'secret':
          secretScore = Math.max(0, secretScore - deduction * 2);
          break;
        case 'code':
          codeScore = Math.max(0, codeScore - deduction * 1.2);
          break;
        case 'provenance':
          provScore = Math.max(0, provScore - deduction);
          break;
      }
    }

    score = Math.round(Math.max(0, Math.min(100, score)));

    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
    const label = score >= 90 ? 'Excellent' : score >= 75 ? 'Good' : score >= 60 ? 'Fair' : score >= 40 ? 'Poor' : 'Critical';

    const result: SecurityScoreResult = {
      score,
      grade,
      label,
      signals: [...this.signals],
      breakdown: {
        dependencies: Math.round(depScore),
        secrets: Math.round(secretScore),
        code: Math.round(codeScore),
        provenance: Math.round(provScore),
      },
      computedAt: new Date(),
    };

    this.lastResult = result;
    this.updateStatusBar(result);
    this.onScoreChangeEmitter.fire(result);
    return result;
  }

  /**
   * Get the last computed score result.
   */
  getLastResult(): SecurityScoreResult | null {
    return this.lastResult;
  }

  /**
   * Update the status bar with the current score.
   */
  private updateStatusBar(result: SecurityScoreResult): void {
    const icon = result.score >= 90 ? '$(shield)' :
                 result.score >= 75 ? '$(shield)' :
                 result.score >= 60 ? '$(warning)' :
                 result.score >= 40 ? '$(error)' : '$(error)';

    const color = result.score >= 75 ? undefined :
                  result.score >= 60 ? new vscode.ThemeColor('statusBarItem.warningBackground') :
                  new vscode.ThemeColor('statusBarItem.errorBackground');

    this.statusBarItem.text = `${icon} Security: ${result.score}/100 (${result.grade})`;
    this.statusBarItem.backgroundColor = color;
    this.statusBarItem.show();
  }

  /**
   * Show the status bar item.
   */
  show(): void {
    if (this.lastResult) {
      this.updateStatusBar(this.lastResult);
    } else {
      this.statusBarItem.text = '$(shield) Security: --';
      this.statusBarItem.show();
    }
  }

  /**
   * Hide the status bar item.
   */
  hide(): void {
    this.statusBarItem.hide();
  }

  /**
   * Generate a markdown summary of the security score.
   */
  toMarkdown(): string {
    const r = this.lastResult;
    if (!r) { return '# Security Score\n\nNo scan results yet.'; }

    const emoji = r.score >= 90 ? '🟢' : r.score >= 75 ? '🟡' : r.score >= 60 ? '🟠' : '🔴';

    let md = `# ${emoji} Security Score: ${r.score}/100 — ${r.label} (${r.grade})\n\n`;
    md += `*Computed at ${r.computedAt.toLocaleTimeString()}*\n\n`;
    md += `## Score Breakdown\n\n`;
    md += `| Category | Score |\n|----------|-------|\n`;
    md += `| Dependencies & Hallucinations | ${r.breakdown.dependencies}/100 |\n`;
    md += `| Secrets & Credentials | ${r.breakdown.secrets}/100 |\n`;
    md += `| Code Vulnerabilities (SAST) | ${r.breakdown.code}/100 |\n`;
    md += `| Package Provenance | ${r.breakdown.provenance}/100 |\n\n`;

    if (r.signals.length > 0) {
      md += `## Issues Found\n\n`;
      for (const s of r.signals) {
        const sev = s.severity === 'critical' ? '🔴' : s.severity === 'high' ? '🟠' : s.severity === 'medium' ? '🟡' : '🔵';
        md += `- ${sev} **${s.description}** (${s.category})\n`;
      }
    } else {
      md += `## ✅ No Issues Found\n\nYour project has no detected security issues.\n`;
    }

    return md;
  }

  dispose(): void {
    this.statusBarItem.dispose();
    this.onScoreChangeEmitter.dispose();
  }
}
