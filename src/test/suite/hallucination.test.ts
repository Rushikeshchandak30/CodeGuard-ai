import * as assert from 'assert';
import { HallucinationDetector } from '../../checkers/hallucination';

suite('HallucinationDetector', () => {
  let detector: HallucinationDetector;

  setup(() => {
    detector = new HallucinationDetector();
  });

  // ─── Known Hallucination DB ────────────────────────────────────────

  suite('Known Hallucination DB', () => {
    test('flags known npm hallucinated package', async () => {
      const result = await detector.analyze('react-ai-components', 'npm', false);
      assert.strictEqual(result.knownHallucination, true);
      assert.strictEqual(result.riskLevel, 'critical');
      assert.ok(result.riskSummary.includes('KNOWN AI hallucination'));
    });

    test('flags known PyPI hallucinated package', async () => {
      const result = await detector.analyze('flask-ai-guard', 'PyPI', false);
      assert.strictEqual(result.knownHallucination, true);
      assert.strictEqual(result.riskLevel, 'critical');
    });

    test('does not flag real npm package as hallucination', async () => {
      const result = await detector.analyze('express', 'npm', true);
      assert.strictEqual(result.knownHallucination, false);
    });

    test('does not flag real PyPI package as hallucination', async () => {
      const result = await detector.analyze('requests', 'PyPI', true);
      assert.strictEqual(result.knownHallucination, false);
    });

    test('known hallucination check is case-insensitive', async () => {
      const result = await detector.analyze('React-AI-Components', 'npm', false);
      assert.strictEqual(result.knownHallucination, true);
    });
  });

  // ─── Typosquatting Detection ───────────────────────────────────────

  suite('Typosquatting Detection', () => {
    test('detects single-char typo of popular npm package', async () => {
      // "requets" is 1 edit distance from "request"
      const result = await detector.analyze('requets', 'npm', true);
      assert.ok(result.typosquatSuggestion !== null, 'Should suggest a similar package');
      assert.ok(
        result.typosquatDistance !== null && result.typosquatDistance <= 2,
        'Distance should be <= 2'
      );
    });

    test('detects single-char typo of popular PyPI package', async () => {
      // "reqeusts" is 2 edit distance from "requests"
      const result = await detector.analyze('reqeusts', 'PyPI', true);
      assert.ok(result.typosquatSuggestion !== null, 'Should suggest requests');
    });

    test('does not flag exact match as typosquat', async () => {
      const result = await detector.analyze('express', 'npm', true);
      assert.strictEqual(result.typosquatSuggestion, null);
    });

    test('does not flag completely different name', async () => {
      const result = await detector.analyze('my-unique-company-pkg-xyz', 'npm', true);
      assert.strictEqual(result.typosquatSuggestion, null);
    });
  });

  // ─── Namespace Confusion ───────────────────────────────────────────

  suite('Namespace Confusion', () => {
    test('detects Python package used in npm context', async () => {
      const result = await detector.analyze('numpy', 'npm', true);
      assert.strictEqual(result.namespaceConfusion, true);
      assert.strictEqual(result.correctEcosystem, 'PyPI');
    });

    test('detects npm package used in PyPI context', async () => {
      const result = await detector.analyze('react', 'PyPI', true);
      assert.strictEqual(result.namespaceConfusion, true);
      assert.strictEqual(result.correctEcosystem, 'npm');
    });

    test('no confusion when package is in correct ecosystem', async () => {
      const result = await detector.analyze('numpy', 'PyPI', true);
      assert.strictEqual(result.namespaceConfusion, false);
      assert.strictEqual(result.correctEcosystem, null);
    });

    test('no confusion for unknown packages', async () => {
      const result = await detector.analyze('some-random-pkg', 'npm', true);
      assert.strictEqual(result.namespaceConfusion, false);
    });
  });

  // ─── Non-Existent Packages ─────────────────────────────────────────

  suite('Non-Existent Packages', () => {
    test('non-existent package gets critical risk', async () => {
      const result = await detector.analyze('this-pkg-definitely-does-not-exist-xyz', 'npm', false);
      assert.strictEqual(result.exists, false);
      assert.strictEqual(result.riskLevel, 'critical');
      assert.ok(result.riskSummary.includes('does not exist'));
    });

    test('non-existent package with typosquat gets typo message', async () => {
      // "expresss" is 1 edit from "express"
      const result = await detector.analyze('expresss', 'npm', false);
      assert.strictEqual(result.riskLevel, 'critical');
      if (result.typosquatSuggestion) {
        assert.ok(result.riskSummary.includes('Did you mean'));
      }
    });
  });

  // ─── Risk Level Computation ────────────────────────────────────────

  suite('Risk Level Computation', () => {
    test('existing popular package has no risk', async () => {
      const result = await detector.analyze('lodash', 'npm', true);
      assert.strictEqual(result.riskLevel, 'none');
      assert.ok(result.riskSummary.includes('No hallucination risk'));
    });

    test('result contains all required fields', async () => {
      const result = await detector.analyze('test-pkg', 'npm', true);
      assert.ok('exists' in result);
      assert.ok('typosquatSuggestion' in result);
      assert.ok('typosquatDistance' in result);
      assert.ok('lowPopularity' in result);
      assert.ok('weeklyDownloads' in result);
      assert.ok('namespaceConfusion' in result);
      assert.ok('correctEcosystem' in result);
      assert.ok('recentlyRegistered' in result);
      assert.ok('registeredDate' in result);
      assert.ok('riskLevel' in result);
      assert.ok('riskSummary' in result);
      assert.ok('knownHallucination' in result);
    });
  });
});
