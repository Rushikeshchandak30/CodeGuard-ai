import * as vscode from 'vscode';

/**
 * Manages the status bar item that shows real-time security status.
 * Displays: security score, scanning state, issue count, and clean status.
 */
export class StatusBar {
  private item: vscode.StatusBarItem;
  private currentScore: number = 100;

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100
    );
    this.item.command = 'codeguard.showDashboard';
    this.showClean();
    this.item.show();
  }

  /**
   * Show scanning indicator with animation.
   */
  showScanning(): void {
    this.item.text = '$(loading~spin) CodeGuard: Scanning...';
    this.item.tooltip = new vscode.MarkdownString(
      '$(shield) **CodeGuard AI** is scanning dependencies for vulnerabilities...'
    );
    this.item.backgroundColor = undefined;
    this.item.color = undefined;
  }

  /**
   * Show the security score (0-100).
   * Color-coded: 80-100 green, 50-79 orange, 0-49 red.
   */
  showScore(score: number): void {
    this.currentScore = Math.max(0, Math.min(100, Math.round(score)));
    const emoji = this.currentScore >= 80 ? '🛡️' : this.currentScore >= 50 ? '⚠️' : '🚨';

    this.item.text = `${emoji} CodeGuard: ${this.currentScore}`;

    const tier = this.currentScore >= 80 ? 'Excellent'
      : this.currentScore >= 60 ? 'Good'
        : this.currentScore >= 40 ? 'Fair'
          : 'Critical';

    this.item.tooltip = new vscode.MarkdownString(
      `**CodeGuard AI — Security Score: ${this.currentScore}/100**\n\n` +
      `Rating: **${tier}**\n\n` +
      `Click for full security dashboard`
    );

    if (this.currentScore >= 80) {
      this.item.backgroundColor = undefined;
      this.item.color = '#51cf66';
    } else if (this.currentScore >= 50) {
      this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
      this.item.color = undefined;
    } else {
      this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
      this.item.color = undefined;
    }
  }

  /**
   * Show clean status (no issues found).
   */
  showClean(): void {
    this.item.text = '🛡️ CodeGuard: 100';
    this.item.tooltip = new vscode.MarkdownString(
      '**CodeGuard AI — Security Score: 100/100**\n\n' +
      'No vulnerabilities or hallucinated packages detected.\n\n' +
      'Click for full security dashboard'
    );
    this.item.backgroundColor = undefined;
    this.item.color = '#51cf66';
    this.currentScore = 100;
  }

  /**
   * Show issues found with count breakdown.
   */
  showIssues(errors: number, warnings: number): void {
    const total = errors + warnings;
    if (total === 0) {
      this.showClean();
      return;
    }

    // Approximate score reduction: errors = -15 each, warnings = -5 each
    const approxScore = Math.max(0, 100 - (errors * 15) - (warnings * 5));
    this.showScore(approxScore);

    // Override tooltip with specific counts
    const parts: string[] = [];
    if (errors > 0) { parts.push(`🔴 ${errors} critical`); }
    if (warnings > 0) { parts.push(`🟡 ${warnings} warning${warnings > 1 ? 's' : ''}`); }

    this.item.tooltip = new vscode.MarkdownString(
      `**CodeGuard AI — ${total} issue${total > 1 ? 's' : ''} found**\n\n` +
      parts.join('  ·  ') + '\n\n' +
      'Click for full security dashboard'
    );
  }

  /**
   * Show disabled status.
   */
  showDisabled(): void {
    this.item.text = '$(shield) CodeGuard: Off';
    this.item.tooltip = new vscode.MarkdownString(
      '**CodeGuard AI** is disabled.\n\nClick to enable.'
    );
    this.item.backgroundColor = undefined;
    this.item.color = undefined;
  }

  /**
   * Show error status (e.g., API failure).
   */
  showError(message: string): void {
    this.item.text = '$(error) CodeGuard: Error';
    this.item.tooltip = new vscode.MarkdownString(
      `**CodeGuard AI Error**\n\n${message}`
    );
    this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    this.item.color = undefined;
  }

  /**
   * Get the current score.
   */
  getScore(): number {
    return this.currentScore;
  }

  dispose(): void {
    this.item.dispose();
  }
}
