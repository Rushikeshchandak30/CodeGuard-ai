import * as assert from 'assert';
import { AiGenerationDetector } from '../../ai/detector';
import { HallucinationDetector } from '../../checkers/hallucination';

/**
 * Integration test — validates the end-to-end pipeline:
 *   AI Detector → Hallucination Checker → Risk Assessment
 *
 * Simulates the real flow: AI generates code with imports → detector flags it →
 * hallucination checker analyzes each package → risk levels computed.
 */

// Helper to create a mock change event
function createMockChangeEvent(text: string): any {
  return {
    document: {
      uri: { toString: () => 'file:///test/integration-mock.ts' },
    },
    contentChanges: [{
      text,
      range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } },
      rangeLength: 0,
      rangeOffset: 0,
    }],
    reason: undefined,
  };
}

// Helper: extract package names from a code snippet (simplified parser)
function extractImportedPackages(code: string): string[] {
  const packages: string[] = [];
  const lines = code.split('\n');
  for (const line of lines) {
    // ES import: import X from 'package'
    const esMatch = line.match(/import\s+.*\s+from\s+['"]([^'"./][^'"]*)['"]/);
    if (esMatch) {
      // Strip subpath: 'lodash/merge' → 'lodash'
      const pkg = esMatch[1].split('/')[0];
      // Handle scoped: '@scope/pkg/sub' → '@scope/pkg'
      if (esMatch[1].startsWith('@')) {
        const parts = esMatch[1].split('/');
        packages.push(parts.slice(0, 2).join('/'));
      } else {
        packages.push(pkg);
      }
      continue;
    }
    // Python import: import package / from package import X
    const pyImport = line.match(/^import\s+([a-zA-Z_][a-zA-Z0-9_]*)/);
    if (pyImport) {
      packages.push(pyImport[1]);
      continue;
    }
    const pyFrom = line.match(/^from\s+([a-zA-Z_][a-zA-Z0-9_]*)/);
    if (pyFrom) {
      packages.push(pyFrom[1]);
    }
  }
  return [...new Set(packages)];
}

suite('Integration: AI Detection → Hallucination Analysis Pipeline', () => {
  let aiDetector: AiGenerationDetector;
  let hallucinationDetector: HallucinationDetector;

  setup(() => {
    aiDetector = new AiGenerationDetector();
    hallucinationDetector = new HallucinationDetector();
  });

  teardown(() => {
    aiDetector.dispose();
  });

  test('AI-generated npm imports with hallucinated package are caught', async () => {
    // Simulate AI dumping multiple import lines at once
    const aiCode = [
      'import express from "express";',
      'import cors from "cors";',
      'import reactAiComponents from "react-ai-components";',
      'import helmet from "helmet";',
    ].join('\n');

    // Step 1: AI detector flags this as AI-generated
    const event = createMockChangeEvent(aiCode);
    const detection = aiDetector.analyze(event);
    assert.strictEqual(detection.isAiGenerated, true, 'Multi-line imports should be detected as AI');
    assert.ok(detection.newImportCount >= 3, 'Should count multiple imports');

    // Step 2: Extract packages
    const packages = extractImportedPackages(aiCode);
    assert.ok(packages.includes('express'));
    assert.ok(packages.includes('react-ai-components'));

    // Step 3: Run hallucination analysis on each
    const results = await Promise.all(
      packages.map(pkg => {
        // Simulate: express exists, react-ai-components doesn't
        const exists = ['express', 'cors', 'helmet'].includes(pkg);
        return hallucinationDetector.analyze(pkg, 'npm', exists);
      })
    );

    // Step 4: Verify results
    const expressResult = results[packages.indexOf('express')];
    assert.strictEqual(expressResult.riskLevel, 'none', 'express should be safe');
    assert.strictEqual(expressResult.knownHallucination, false);

    const fakeResult = results[packages.indexOf('react-ai-components')];
    assert.strictEqual(fakeResult.exists, false);
    assert.strictEqual(fakeResult.riskLevel, 'critical');
    assert.strictEqual(fakeResult.knownHallucination, true, 'Should be in known hallucination DB');
  });

  test('AI-generated Python imports with hallucinated package are caught', async () => {
    const aiCode = [
      'import numpy as np',
      'import pandas as pd',
      'import flask_ai_guard',
      'from sklearn import metrics',
    ].join('\n');

    // Step 1: AI detector
    const event = createMockChangeEvent(aiCode);
    const detection = aiDetector.analyze(event);
    assert.strictEqual(detection.isAiGenerated, true);

    // Step 2: Extract packages
    const packages = extractImportedPackages(aiCode);
    assert.ok(packages.includes('numpy'));
    assert.ok(packages.includes('flask_ai_guard'));

    // Step 3: Hallucination analysis
    const results = new Map<string, any>();
    for (const pkg of packages) {
      const normalizedName = pkg.replace(/_/g, '-');
      const exists = ['numpy', 'pandas', 'sklearn'].includes(pkg);
      const result = await hallucinationDetector.analyze(normalizedName, 'PyPI', exists);
      results.set(pkg, result);
    }

    // Step 4: Verify
    const numpyResult = results.get('numpy');
    assert.strictEqual(numpyResult.riskLevel, 'none');

    const fakeResult = results.get('flask_ai_guard');
    assert.strictEqual(fakeResult.exists, false);
    assert.strictEqual(fakeResult.riskLevel, 'critical');
    assert.strictEqual(fakeResult.knownHallucination, true);
  });

  test('Human typing is not flagged as AI-generated', async () => {
    // Single character typing
    const events = ['i', 'm', 'p', 'o', 'r', 't'].map(ch => createMockChangeEvent(ch));
    for (const event of events) {
      const result = aiDetector.analyze(event);
      assert.strictEqual(result.isAiGenerated, false, 'Single chars should not be AI');
    }
  });

  test('Namespace confusion is detected in cross-ecosystem usage', async () => {
    // AI suggests a Python package in a JavaScript file
    const result = await hallucinationDetector.analyze('numpy', 'npm', true);
    assert.strictEqual(result.namespaceConfusion, true);
    assert.strictEqual(result.correctEcosystem, 'PyPI');
  });

  test('Typosquat near popular package is flagged', async () => {
    // "expresss" is 1 edit from "express"
    const result = await hallucinationDetector.analyze('expresss', 'npm', false);
    assert.strictEqual(result.riskLevel, 'critical');
    assert.ok(result.typosquatSuggestion !== null);
    assert.ok(result.riskSummary.includes('Did you mean'));
  });

  test('Full pipeline: detect AI code → parse imports → check all → aggregate risks', async () => {
    // Simulate a realistic AI code dump
    const aiCode = [
      'import express from "express";',
      'import { createServer } from "http";',
      'import nodeAiUtils from "node-ai-utils";',
      'import cors from "cors";',
      'import expressAiRouter from "express-ai-router";',
    ].join('\n');

    // Detection
    const event = createMockChangeEvent(aiCode);
    const detection = aiDetector.analyze(event);
    assert.strictEqual(detection.isAiGenerated, true);

    // Parse
    const packages = extractImportedPackages(aiCode);

    // Check each package
    const safePackages: string[] = [];
    const dangerousPackages: string[] = [];

    for (const pkg of packages) {
      if (pkg === 'http') { continue; } // Skip Node.js built-in
      const exists = ['express', 'cors'].includes(pkg);
      const analysis = await hallucinationDetector.analyze(pkg, 'npm', exists);

      if (analysis.riskLevel === 'none' || analysis.riskLevel === 'low') {
        safePackages.push(pkg);
      } else {
        dangerousPackages.push(pkg);
      }
    }

    // Validate results
    assert.ok(safePackages.includes('express'), 'express should be safe');
    assert.ok(safePackages.includes('cors'), 'cors should be safe');
    assert.ok(dangerousPackages.includes('node-ai-utils'), 'node-ai-utils should be dangerous');
    assert.ok(dangerousPackages.includes('express-ai-router'), 'express-ai-router should be dangerous');
    assert.ok(dangerousPackages.length >= 2, 'Should catch at least 2 hallucinated packages');
  });
});
