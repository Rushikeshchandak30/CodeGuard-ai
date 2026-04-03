import * as vscode from 'vscode';

/**
 * Detects whether code changes are AI-generated vs human-typed.
 * Uses multiple heuristics: burst insertion, paste detection, typing speed,
 * and import-heavy content patterns.
 */

export interface ChangeAnalysis {
  /** Whether this change appears to be AI-generated */
  isAiGenerated: boolean;
  /** Confidence score 0-1 */
  confidence: number;
  /** Which signals triggered */
  signals: AiSignal[];
  /** Number of new import lines in this change */
  newImportCount: number;
}

export type AiSignal =
  | 'burst-insertion'
  | 'paste-detected'
  | 'high-speed-typing'
  | 'import-heavy'
  | 'multi-line-single-event'
  | 'inline-completion';

/**
 * Tracks per-document typing velocity for speed-based detection.
 */
interface TypingTracker {
  lastChangeTime: number;
  charsSinceLastCheck: number;
  recentBursts: number;        // count of burst events in last 5 seconds
  lastBurstReset: number;
}

// Regex patterns for import detection across languages
const IMPORT_PATTERNS = [
  /^\s*import\s+/,                         // ES import / Python import
  /^\s*from\s+\S+\s+import\s+/,           // Python from-import
  /\brequire\s*\(/,                        // CommonJS require
  /^\s*using\s+/,                          // C# using
  /^\s*use\s+/,                            // Rust use
  /^\s*#include\s+/,                       // C/C++ include
  /^\s*package\s+/,                        // Go package
];

export class AiGenerationDetector {
  private trackers = new Map<string, TypingTracker>();
  private disposables: vscode.Disposable[] = [];

  // Thresholds (tuned for detecting AI tools)
  private static readonly BURST_LINE_THRESHOLD = 3;       // >=3 lines in one event = burst
  private static readonly SPEED_CHARS_THRESHOLD = 150;     // >150 chars in <200ms = not human
  private static readonly SPEED_TIME_WINDOW_MS = 200;
  private static readonly IMPORT_HEAVY_THRESHOLD = 2;      // >=2 import lines in one change
  private static readonly CONFIDENCE_THRESHOLD = 0.5;      // Above this = classified as AI
  private static readonly BURST_WINDOW_MS = 5000;          // 5-second window for burst counting

  /**
   * Analyze a text document change event and determine if it's AI-generated.
   */
  analyze(event: vscode.TextDocumentChangeEvent): ChangeAnalysis {
    const signals: AiSignal[] = [];
    let totalWeight = 0;
    let maxWeight = 0;
    let newImportCount = 0;

    const uri = event.document.uri.toString();
    const now = Date.now();
    const tracker = this.getTracker(uri, now);

    for (const change of event.contentChanges) {
      const insertedText = change.text;
      const insertedLines = insertedText.split('\n');
      const lineCount = insertedLines.length;
      const charCount = insertedText.length;

      // Signal 1: Burst insertion (multiple lines in one event)
      if (lineCount >= AiGenerationDetector.BURST_LINE_THRESHOLD) {
        signals.push('burst-insertion');
        totalWeight += 0.4;
        tracker.recentBursts++;
      }

      // Signal 2: Multi-line single event (even 2 lines is unusual for human typing)
      if (lineCount >= 2 && charCount > 50) {
        signals.push('multi-line-single-event');
        totalWeight += 0.2;
      }

      // Signal 3: High-speed typing (>150 chars in <200ms)
      const timeSinceLastChange = now - tracker.lastChangeTime;
      tracker.charsSinceLastCheck += charCount;
      if (
        timeSinceLastChange < AiGenerationDetector.SPEED_TIME_WINDOW_MS &&
        tracker.charsSinceLastCheck > AiGenerationDetector.SPEED_CHARS_THRESHOLD
      ) {
        signals.push('high-speed-typing');
        totalWeight += 0.3;
      }

      // Signal 4: Paste detection (large single insertion, not a newline)
      if (charCount > 100 && lineCount >= 2 && !this.isJustNewlines(insertedText)) {
        signals.push('paste-detected');
        totalWeight += 0.35;
      }

      // Signal 5: Import-heavy content
      const importLines = insertedLines.filter(line => this.isImportLine(line));
      newImportCount += importLines.length;
      if (importLines.length >= AiGenerationDetector.IMPORT_HEAVY_THRESHOLD) {
        signals.push('import-heavy');
        totalWeight += 0.25;
      }

      maxWeight += 1.5; // Theoretical max per change
    }

    // Update tracker
    tracker.lastChangeTime = now;
    if (now - tracker.lastBurstReset > AiGenerationDetector.BURST_WINDOW_MS) {
      tracker.recentBursts = 0;
      tracker.lastBurstReset = now;
      tracker.charsSinceLastCheck = 0;
    }

    // Calculate confidence
    const confidence = maxWeight > 0 ? Math.min(1, totalWeight / 1.0) : 0;
    const isAiGenerated = confidence >= AiGenerationDetector.CONFIDENCE_THRESHOLD;

    // Deduplicate signals
    const uniqueSignals = [...new Set(signals)];

    return {
      isAiGenerated,
      confidence,
      signals: uniqueSignals,
      newImportCount,
    };
  }

  /**
   * Check if a single line looks like an import statement.
   */
  private isImportLine(line: string): boolean {
    const trimmed = line.trim();
    if (trimmed.length === 0) { return false; }
    return IMPORT_PATTERNS.some(re => re.test(trimmed));
  }

  private isJustNewlines(text: string): boolean {
    return /^\s*$/.test(text);
  }

  private getTracker(uri: string, now: number): TypingTracker {
    let tracker = this.trackers.get(uri);
    if (!tracker) {
      tracker = {
        lastChangeTime: now,
        charsSinceLastCheck: 0,
        recentBursts: 0,
        lastBurstReset: now,
      };
      this.trackers.set(uri, tracker);
    }
    return tracker;
  }

  /**
   * Clear tracking state for a closed document.
   */
  clearDocument(uri: string): void {
    this.trackers.delete(uri);
  }

  dispose(): void {
    this.trackers.clear();
    for (const d of this.disposables) { d.dispose(); }
  }
}
