/**
 * Score History
 *
 * Tracks security score over time per project.
 * Stores snapshots in .codeguard/score-history.json.
 * Keeps last 100 entries for trend analysis.
 */

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { SecurityScoreResult } from './security-score';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScoreSnapshot {
  timestamp: string;
  score: number;
  grade: string;
  signalCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  breakdown: {
    dependencies: number;
    secrets: number;
    code: number;
    provenance: number;
  };
}

export type ScoreTrend = 'improving' | 'stable' | 'declining';

// ---------------------------------------------------------------------------
// ScoreHistory
// ---------------------------------------------------------------------------

export class ScoreHistory {
  private snapshots: ScoreSnapshot[] = [];
  private filePath: string | null = null;
  private readonly MAX_SNAPSHOTS = 100;

  constructor() {
    this.load();
  }

  /**
   * Record a new score snapshot.
   */
  record(result: SecurityScoreResult): void {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const s of result.signals) {
      if (s.severity in counts) {
        counts[s.severity as keyof typeof counts] += s.count;
      }
    }

    const snapshot: ScoreSnapshot = {
      timestamp: new Date().toISOString(),
      score: result.score,
      grade: result.grade,
      signalCounts: counts,
      breakdown: { ...result.breakdown },
    };

    this.snapshots.push(snapshot);

    // Keep only last N
    if (this.snapshots.length > this.MAX_SNAPSHOTS) {
      this.snapshots = this.snapshots.slice(-this.MAX_SNAPSHOTS);
    }

    this.save();
  }

  /**
   * Get the score trend (comparing last 5 vs previous 5).
   */
  getTrend(): ScoreTrend {
    if (this.snapshots.length < 2) { return 'stable'; }

    const recent = this.snapshots.slice(-5);
    const previous = this.snapshots.slice(-10, -5);

    if (previous.length === 0) { return 'stable'; }

    const avgRecent = recent.reduce((s, e) => s + e.score, 0) / recent.length;
    const avgPrevious = previous.reduce((s, e) => s + e.score, 0) / previous.length;

    const diff = avgRecent - avgPrevious;
    if (diff > 3) { return 'improving'; }
    if (diff < -3) { return 'declining'; }
    return 'stable';
  }

  /**
   * Get all snapshots.
   */
  getSnapshots(): ScoreSnapshot[] {
    return [...this.snapshots];
  }

  /**
   * Get the latest snapshot.
   */
  getLatest(): ScoreSnapshot | null {
    return this.snapshots.length > 0 ? this.snapshots[this.snapshots.length - 1] : null;
  }

  /**
   * Format history as markdown for dashboard display.
   */
  toMarkdown(): string {
    const trend = this.getTrend();
    const trendEmoji = trend === 'improving' ? '📈' : trend === 'declining' ? '📉' : '➡️';

    let md = `## ${trendEmoji} Score History (${trend})\n\n`;

    if (this.snapshots.length === 0) {
      md += 'No history yet. Run a scan to start tracking.\n';
      return md;
    }

    md += `| Date | Score | Grade | Critical | High | Medium |\n`;
    md += `|------|-------|-------|----------|------|--------|\n`;

    const display = this.snapshots.slice(-20).reverse();
    for (const s of display) {
      const date = new Date(s.timestamp).toLocaleDateString();
      md += `| ${date} | ${s.score} | ${s.grade} | ${s.signalCounts.critical} | ${s.signalCounts.high} | ${s.signalCounts.medium} |\n`;
    }

    return md;
  }

  // ---------------------------------------------------------------------------
  // Persistence
  // ---------------------------------------------------------------------------

  private getFilePath(): string | null {
    if (this.filePath) { return this.filePath; }
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) { return null; }
    const dir = path.join(folders[0].uri.fsPath, '.codeguard');
    if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }
    this.filePath = path.join(dir, 'score-history.json');
    return this.filePath;
  }

  private load(): void {
    const fp = this.getFilePath();
    if (!fp || !fs.existsSync(fp)) { return; }
    try {
      const content = fs.readFileSync(fp, 'utf-8');
      this.snapshots = JSON.parse(content);
    } catch {
      this.snapshots = [];
    }
  }

  private save(): void {
    const fp = this.getFilePath();
    if (!fp) { return; }
    try {
      fs.writeFileSync(fp, JSON.stringify(this.snapshots, null, 2), 'utf-8');
    } catch { /* silent */ }
  }
}
