import * as assert from 'assert';
import { AiGenerationDetector } from '../../ai/detector';

/**
 * Mock TextDocumentChangeEvent for testing the AI generation detector.
 * We simulate VS Code events without requiring the actual VS Code API.
 */
function createMockChangeEvent(changes: Array<{ text: string; rangeLength?: number }>): any {
  return {
    document: {
      uri: { toString: () => 'file:///test/mock.ts' },
    },
    contentChanges: changes.map(c => ({
      text: c.text,
      range: { start: { line: 0, character: 0 }, end: { line: 0, character: c.rangeLength ?? 0 } },
      rangeLength: c.rangeLength ?? 0,
      rangeOffset: 0,
    })),
    reason: undefined,
  };
}

suite('AiGenerationDetector', () => {
  let detector: AiGenerationDetector;

  setup(() => {
    detector = new AiGenerationDetector();
  });

  teardown(() => {
    detector.dispose();
  });

  // ─── Burst Insertion Detection ─────────────────────────────────────

  suite('Burst Insertion', () => {
    test('detects multi-line burst insertion (>=3 lines)', () => {
      const event = createMockChangeEvent([{
        text: 'import express from "express";\nimport cors from "cors";\nimport helmet from "helmet";\nimport morgan from "morgan";',
      }]);
      const result = detector.analyze(event);
      assert.strictEqual(result.isAiGenerated, true, 'Should detect as AI-generated');
      assert.ok(result.signals.includes('burst-insertion'), 'Should include burst-insertion signal');
    });

    test('single character typing is not AI', () => {
      const event = createMockChangeEvent([{ text: 'a' }]);
      const result = detector.analyze(event);
      assert.strictEqual(result.isAiGenerated, false, 'Single char should not be AI');
      assert.strictEqual(result.signals.length, 0, 'No signals for single char');
    });

    test('single line insertion is not burst', () => {
      const event = createMockChangeEvent([{ text: 'const x = 1;' }]);
      const result = detector.analyze(event);
      assert.ok(!result.signals.includes('burst-insertion'), 'Single line should not trigger burst');
    });
  });

  // ─── Paste Detection ───────────────────────────────────────────────

  suite('Paste Detection', () => {
    test('detects large multi-line paste (>100 chars, >=2 lines)', () => {
      const longCode = 'import { useState, useEffect, useCallback, useMemo, useRef } from "react";\n' +
        'import { BrowserRouter, Routes, Route, Link, useParams } from "react-router-dom";\n' +
        'import axios from "axios";\n';
      const event = createMockChangeEvent([{ text: longCode }]);
      const result = detector.analyze(event);
      assert.strictEqual(result.isAiGenerated, true, 'Large paste should be detected as AI');
      assert.ok(result.signals.includes('paste-detected'), 'Should include paste-detected signal');
    });

    test('small paste is not flagged', () => {
      const event = createMockChangeEvent([{ text: 'hello world' }]);
      const result = detector.analyze(event);
      assert.ok(!result.signals.includes('paste-detected'));
    });
  });

  // ─── Import-Heavy Content ──────────────────────────────────────────

  suite('Import-Heavy Content', () => {
    test('detects multiple import lines in one change', () => {
      const event = createMockChangeEvent([{
        text: 'import React from "react";\nimport ReactDOM from "react-dom";\nimport App from "./App";',
      }]);
      const result = detector.analyze(event);
      assert.ok(result.newImportCount >= 2, 'Should count multiple imports');
      assert.ok(result.signals.includes('import-heavy'), 'Should flag as import-heavy');
    });

    test('counts Python imports correctly', () => {
      const event = createMockChangeEvent([{
        text: 'import numpy as np\nfrom pandas import DataFrame\nimport matplotlib.pyplot as plt',
      }]);
      const result = detector.analyze(event);
      assert.ok(result.newImportCount >= 2, 'Should count Python imports');
    });

    test('single import line is not flagged as import-heavy', () => {
      const event = createMockChangeEvent([{ text: 'import lodash from "lodash";' }]);
      const result = detector.analyze(event);
      assert.ok(!result.signals.includes('import-heavy'));
      assert.strictEqual(result.newImportCount, 1);
    });
  });

  // ─── Confidence Calculation ────────────────────────────────────────

  suite('Confidence', () => {
    test('confidence is between 0 and 1', () => {
      const event = createMockChangeEvent([{
        text: 'import a from "a";\nimport b from "b";\nimport c from "c";\nimport d from "d";',
      }]);
      const result = detector.analyze(event);
      assert.ok(result.confidence >= 0, 'Confidence should be >= 0');
      assert.ok(result.confidence <= 1, 'Confidence should be <= 1');
    });

    test('empty change has zero confidence', () => {
      const event = createMockChangeEvent([{ text: '' }]);
      const result = detector.analyze(event);
      assert.strictEqual(result.confidence, 0);
      assert.strictEqual(result.isAiGenerated, false);
    });
  });

  // ─── Signal Deduplication ──────────────────────────────────────────

  suite('Signal Deduplication', () => {
    test('signals are unique (no duplicates)', () => {
      const event = createMockChangeEvent([{
        text: 'import express from "express";\nimport cors from "cors";\nimport helmet from "helmet";\nimport morgan from "morgan";\nimport bodyParser from "body-parser";',
      }]);
      const result = detector.analyze(event);
      const uniqueSignals = new Set(result.signals);
      assert.strictEqual(result.signals.length, uniqueSignals.size, 'Signals should be deduplicated');
    });
  });

  // ─── Document Tracking ─────────────────────────────────────────────

  suite('Document Tracking', () => {
    test('clearDocument removes tracking state', () => {
      const event = createMockChangeEvent([{ text: 'const x = 1;' }]);
      detector.analyze(event);
      // Should not throw
      detector.clearDocument('file:///test/mock.ts');
      // Second analyze should work fresh
      const result2 = detector.analyze(event);
      assert.ok(result2 !== undefined);
    });
  });
});
