/**
 * AI Code Attribution Engine
 *
 * Tracks which code blocks were AI-generated vs human-written and correlates
 * with vulnerability findings. No other security tool does this.
 *
 * Features:
 *   - Uses AiGenerationDetector signals to tag code regions
 *   - Maintains per-file attribution map (line ranges → source)
 *   - Correlates SAST/taint findings with attribution
 *   - Computes AI vs human vulnerability rates
 *   - Persists attribution data in .codeguard/attribution.json
 *
 * Privacy: All data stays local. No code content is stored — only line ranges
 * and metadata.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { AiGenerationDetector, ChangeAnalysis, AiSignal } from './detector';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CodeSource = 'ai' | 'human' | 'unknown';

export interface AttributedRegion {
  /** 0-indexed start line */
  startLine: number;
  /** 0-indexed end line (inclusive) */
  endLine: number;
  source: CodeSource;
  /** Confidence 0-1 */
  confidence: number;
  /** Which AI detection signals fired */
  signals: AiSignal[];
  /** Timestamp of attribution */
  timestamp: number;
}

export interface FileAttribution {
  filePath: string;
  regions: AttributedRegion[];
  /** Summary stats */
  totalLines: number;
  aiLines: number;
  humanLines: number;
  unknownLines: number;
}

export interface AttributionStats {
  /** Total files tracked */
  filesTracked: number;
  /** Total lines across all files */
  totalLines: number;
  /** Lines attributed to AI */
  aiLines: number;
  /** Lines attributed to humans */
  humanLines: number;
  /** AI code ratio (0-1) */
  aiRatio: number;
  /** Vulnerabilities in AI code */
  aiVulnCount: number;
  /** Vulnerabilities in human code */
  humanVulnCount: number;
  /** AI vulnerability rate (vulns per 1000 lines) */
  aiVulnRate: number;
  /** Human vulnerability rate (vulns per 1000 lines) */
  humanVulnRate: number;
}

export interface VulnAttribution {
  findingId: string;
  line: number;
  file: string;
  source: CodeSource;
  confidence: number;
}

// ---------------------------------------------------------------------------
// Persistence Format
// ---------------------------------------------------------------------------

interface PersistedAttribution {
  version: 1;
  files: Record<string, {
    regions: Array<{
      startLine: number;
      endLine: number;
      source: CodeSource;
      confidence: number;
      signals: AiSignal[];
      timestamp: number;
    }>;
  }>;
  vulnAttributions: VulnAttribution[];
  lastUpdated: number;
}

// ---------------------------------------------------------------------------
// CodeAttributionEngine Class
// ---------------------------------------------------------------------------

export class CodeAttributionEngine {
  private detector: AiGenerationDetector;
  private fileAttributions = new Map<string, FileAttribution>();
  private vulnAttributions: VulnAttribution[] = [];
  private disposables: vscode.Disposable[] = [];
  private storagePath: string | undefined;
  private dirty = false;

  constructor() {
    this.detector = new AiGenerationDetector();
  }

  /**
   * Activate — start watching for document changes to detect AI-generated code.
   */
  activate(context: vscode.ExtensionContext): void {
    // Set storage path
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders) {
      this.storagePath = path.join(workspaceFolders[0].uri.fsPath, '.codeguard', 'attribution.json');
      this.loadFromDisk();
    }

    // Watch document changes for AI detection
    this.disposables.push(
      vscode.workspace.onDidChangeTextDocument((event) => {
        if (this.isSupported(event.document)) {
          this.onDocumentChange(event);
        }
      })
    );

    // Periodic save
    const saveInterval = setInterval(() => {
      if (this.dirty) {
        this.saveToDisk();
        this.dirty = false;
      }
    }, 30000); // every 30 seconds

    this.disposables.push({ dispose: () => clearInterval(saveInterval) });
    context.subscriptions.push({ dispose: () => this.dispose() });
  }

  /**
   * Attribute a vulnerability finding to AI or human code.
   */
  attributeFinding(findingId: string, file: string, line: number): VulnAttribution {
    const attribution = this.getLineAttribution(file, line);

    const va: VulnAttribution = {
      findingId,
      line,
      file,
      source: attribution.source,
      confidence: attribution.confidence,
    };

    // Update or add
    const existing = this.vulnAttributions.findIndex(v => v.findingId === findingId);
    if (existing >= 0) {
      this.vulnAttributions[existing] = va;
    } else {
      this.vulnAttributions.push(va);
    }

    this.dirty = true;
    return va;
  }

  /**
   * Get attribution for a specific line in a file.
   */
  getLineAttribution(file: string, line: number): { source: CodeSource; confidence: number } {
    const fa = this.fileAttributions.get(file);
    if (!fa) { return { source: 'unknown', confidence: 0 }; }

    for (const region of fa.regions) {
      if (line >= region.startLine && line <= region.endLine) {
        return { source: region.source, confidence: region.confidence };
      }
    }

    return { source: 'unknown', confidence: 0 };
  }

  /**
   * Get overall attribution statistics.
   */
  getStats(): AttributionStats {
    let totalLines = 0;
    let aiLines = 0;
    let humanLines = 0;

    for (const fa of this.fileAttributions.values()) {
      totalLines += fa.totalLines;
      aiLines += fa.aiLines;
      humanLines += fa.humanLines;
    }

    const aiVulns = this.vulnAttributions.filter(v => v.source === 'ai');
    const humanVulns = this.vulnAttributions.filter(v => v.source === 'human');

    const aiVulnRate = aiLines > 0 ? (aiVulns.length / aiLines) * 1000 : 0;
    const humanVulnRate = humanLines > 0 ? (humanVulns.length / humanLines) * 1000 : 0;

    return {
      filesTracked: this.fileAttributions.size,
      totalLines,
      aiLines,
      humanLines,
      aiRatio: totalLines > 0 ? aiLines / totalLines : 0,
      aiVulnCount: aiVulns.length,
      humanVulnCount: humanVulns.length,
      aiVulnRate: Math.round(aiVulnRate * 100) / 100,
      humanVulnRate: Math.round(humanVulnRate * 100) / 100,
    };
  }

  /**
   * Get file-level attribution.
   */
  getFileAttribution(file: string): FileAttribution | undefined {
    return this.fileAttributions.get(file);
  }

  /**
   * Format stats as markdown for dashboard.
   */
  toMarkdown(): string {
    const stats = this.getStats();
    const lines: string[] = [
      '# AI Code Attribution Report',
      '',
      '## Overview',
      `- **Files tracked:** ${stats.filesTracked}`,
      `- **Total lines:** ${stats.totalLines.toLocaleString()}`,
      `- **AI-generated:** ${stats.aiLines.toLocaleString()} lines (${(stats.aiRatio * 100).toFixed(1)}%)`,
      `- **Human-written:** ${stats.humanLines.toLocaleString()} lines (${((1 - stats.aiRatio) * 100).toFixed(1)}%)`,
      '',
      '## Vulnerability Correlation',
      `| Metric | AI Code | Human Code |`,
      `|--------|---------|------------|`,
      `| Vulnerabilities | ${stats.aiVulnCount} | ${stats.humanVulnCount} |`,
      `| Rate (per 1K lines) | ${stats.aiVulnRate} | ${stats.humanVulnRate} |`,
      '',
    ];

    if (stats.aiVulnRate > 0 && stats.humanVulnRate > 0) {
      const ratio = stats.aiVulnRate / stats.humanVulnRate;
      if (ratio > 1.5) {
        lines.push(`> **Warning:** AI-generated code has **${ratio.toFixed(1)}x** the vulnerability rate of human code.`);
      } else if (ratio < 0.7) {
        lines.push(`> AI-generated code has a **lower** vulnerability rate than human code (${ratio.toFixed(1)}x).`);
      } else {
        lines.push(`> AI and human code have similar vulnerability rates.`);
      }
    }

    // Top files by AI ratio
    const fileStats = Array.from(this.fileAttributions.values())
      .filter(f => f.totalLines > 10)
      .map(f => ({
        file: path.basename(f.filePath),
        aiRatio: f.totalLines > 0 ? f.aiLines / f.totalLines : 0,
        totalLines: f.totalLines,
      }))
      .sort((a, b) => b.aiRatio - a.aiRatio)
      .slice(0, 10);

    if (fileStats.length > 0) {
      lines.push('', '## Top Files by AI Code Ratio', '');
      lines.push('| File | AI % | Lines |');
      lines.push('|------|------|-------|');
      for (const f of fileStats) {
        const bar = '█'.repeat(Math.round(f.aiRatio * 10)) + '░'.repeat(10 - Math.round(f.aiRatio * 10));
        lines.push(`| ${f.file} | ${bar} ${(f.aiRatio * 100).toFixed(0)}% | ${f.totalLines} |`);
      }
    }

    return lines.join('\n');
  }

  // -----------------------------------------------------------------------
  // Private: Change Detection
  // -----------------------------------------------------------------------

  private onDocumentChange(event: vscode.TextDocumentChangeEvent): void {
    const analysis = this.detector.analyze(event);
    const filePath = event.document.uri.fsPath;

    if (event.contentChanges.length === 0) { return; }

    // Get or create file attribution
    let fa = this.fileAttributions.get(filePath);
    if (!fa) {
      fa = {
        filePath,
        regions: [],
        totalLines: event.document.lineCount,
        aiLines: 0,
        humanLines: event.document.lineCount,
        unknownLines: 0,
      };
      this.fileAttributions.set(filePath, fa);
    }

    // Process each content change
    for (const change of event.contentChanges) {
      if (change.text.length === 0) { continue; } // deletion, not insertion

      const startLine = change.range.start.line;
      const insertedLineCount = change.text.split('\n').length - 1;
      const endLine = startLine + Math.max(0, insertedLineCount);

      if (insertedLineCount === 0 && change.text.length < 5) {
        // Small edits (1-4 chars) are almost always human typing
        continue;
      }

      const region: AttributedRegion = {
        startLine,
        endLine,
        source: analysis.isAiGenerated ? 'ai' : 'human',
        confidence: analysis.confidence,
        signals: analysis.signals,
        timestamp: Date.now(),
      };

      // Merge with existing regions or add new
      this.mergeRegion(fa, region);
    }

    // Recalculate stats
    this.recalculateFileStats(fa, event.document.lineCount);
    this.dirty = true;
  }

  private mergeRegion(fa: FileAttribution, newRegion: AttributedRegion): void {
    // Remove overlapping regions
    fa.regions = fa.regions.filter(r =>
      r.endLine < newRegion.startLine || r.startLine > newRegion.endLine
    );

    // Add new region
    fa.regions.push(newRegion);

    // Sort by start line
    fa.regions.sort((a, b) => a.startLine - b.startLine);

    // Merge adjacent regions with same source
    const merged: AttributedRegion[] = [];
    for (const region of fa.regions) {
      const last = merged[merged.length - 1];
      if (last && last.source === region.source && last.endLine >= region.startLine - 1) {
        last.endLine = Math.max(last.endLine, region.endLine);
        last.confidence = Math.max(last.confidence, region.confidence);
        last.signals = [...new Set([...last.signals, ...region.signals])];
      } else {
        merged.push({ ...region });
      }
    }

    fa.regions = merged;
  }

  private recalculateFileStats(fa: FileAttribution, totalLines: number): void {
    fa.totalLines = totalLines;
    fa.aiLines = 0;
    fa.humanLines = 0;

    const covered = new Set<number>();

    for (const region of fa.regions) {
      for (let line = region.startLine; line <= Math.min(region.endLine, totalLines - 1); line++) {
        covered.add(line);
        if (region.source === 'ai') {
          fa.aiLines++;
        } else if (region.source === 'human') {
          fa.humanLines++;
        }
      }
    }

    fa.unknownLines = totalLines - covered.size;
    // Uncovered lines default to human
    fa.humanLines += fa.unknownLines;
    fa.unknownLines = 0;
  }

  // -----------------------------------------------------------------------
  // Private: Persistence
  // -----------------------------------------------------------------------

  private loadFromDisk(): void {
    if (!this.storagePath) { return; }
    try {
      if (!fs.existsSync(this.storagePath)) { return; }
      const raw = fs.readFileSync(this.storagePath, 'utf-8');
      const data: PersistedAttribution = JSON.parse(raw);
      if (data.version !== 1) { return; }

      for (const [filePath, fileData] of Object.entries(data.files)) {
        const regions = fileData.regions.map(r => ({
          ...r,
          signals: r.signals || [],
        }));

        const fa: FileAttribution = {
          filePath,
          regions,
          totalLines: 0,
          aiLines: 0,
          humanLines: 0,
          unknownLines: 0,
        };

        // Recalculate stats from regions
        let maxLine = 0;
        for (const r of regions) {
          maxLine = Math.max(maxLine, r.endLine);
          const lineCount = r.endLine - r.startLine + 1;
          if (r.source === 'ai') { fa.aiLines += lineCount; }
          else { fa.humanLines += lineCount; }
        }
        fa.totalLines = maxLine + 1;

        this.fileAttributions.set(filePath, fa);
      }

      this.vulnAttributions = data.vulnAttributions || [];
    } catch {
      // Corrupted file, start fresh
    }
  }

  saveToDisk(): void {
    if (!this.storagePath) { return; }

    try {
      const dir = path.dirname(this.storagePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const data: PersistedAttribution = {
        version: 1,
        files: {},
        vulnAttributions: this.vulnAttributions,
        lastUpdated: Date.now(),
      };

      for (const [filePath, fa] of this.fileAttributions) {
        data.files[filePath] = {
          regions: fa.regions.map(r => ({
            startLine: r.startLine,
            endLine: r.endLine,
            source: r.source,
            confidence: r.confidence,
            signals: r.signals,
            timestamp: r.timestamp,
          })),
        };
      }

      fs.writeFileSync(this.storagePath, JSON.stringify(data, null, 2));
    } catch {
      // Silent failure — don't crash extension for persistence issues
    }
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private isSupported(doc: vscode.TextDocument): boolean {
    return ['javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'python', 'go', 'java', 'rust'].includes(doc.languageId);
  }

  dispose(): void {
    this.saveToDisk();
    this.detector.dispose();
    for (const d of this.disposables) { d.dispose(); }
    this.fileAttributions.clear();
    this.vulnAttributions = [];
  }
}
