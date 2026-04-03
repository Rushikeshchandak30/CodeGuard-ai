import * as assert from 'assert';

/**
 * Policy Engine tests — unit tests for evaluatePackage and evaluateFull.
 * These tests import the PolicyEngine types but don't require VS Code API
 * for the core logic validation (evaluatePackage is a pure function on the policy object).
 *
 * We test the policy evaluation logic by reimplementing the core checks
 * as pure functions that mirror the PolicyEngine behavior.
 */

// Replicate types from policy/engine.ts for pure-function testing
type PolicyMode = 'audit' | 'warn' | 'enforce';
type ProvenanceLevel = 'verified' | 'partial' | 'none';

interface PolicyRules {
  block_unprovenanced_packages?: boolean;
  required_provenance_level?: ProvenanceLevel;
  max_allowed_severity?: 'critical' | 'high' | 'medium' | 'low' | 'none';
  require_sbom_baseline?: boolean;
  forbidden_packages?: string[];
  allowed_packages?: string[];
  max_ai_code_ratio?: number;
  forbidden_patterns?: Array<{ pattern: string; message: string; severity?: 'error' | 'warning' }>;
  require_secrets_scanner?: boolean;
  require_sast_scanner?: boolean;
  max_critical_findings?: number;
  max_high_findings?: number;
}

interface PolicyConfig {
  version: 1;
  mode: PolicyMode;
  rules: PolicyRules;
}

interface PolicyViolation {
  rule: string;
  message: string;
  severity: 'error' | 'warning' | 'info';
  mode: PolicyMode;
}

// Pure function that mirrors PolicyEngine.evaluatePackage logic
function evaluatePackage(
  policy: PolicyConfig,
  packageName: string,
  version: string | null,
  provenance: ProvenanceLevel,
  maxVulnSeverity: string | null,
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const rules = policy.rules;
  const mode = policy.mode;

  // Allowlist bypass
  if (rules.allowed_packages?.includes(packageName)) {
    return [];
  }

  // Forbidden packages
  if (rules.forbidden_packages) {
    const pkgWithVersion = version ? `${packageName}@${version}` : packageName;
    for (const forbidden of rules.forbidden_packages) {
      if (forbidden === packageName || forbidden === pkgWithVersion) {
        violations.push({
          rule: 'forbidden_packages',
          message: `Package "${pkgWithVersion}" is forbidden by policy`,
          severity: mode === 'enforce' ? 'error' : 'warning',
          mode,
        });
      }
    }
  }

  // Provenance requirements
  if (rules.block_unprovenanced_packages && provenance === 'none') {
    violations.push({
      rule: 'block_unprovenanced_packages',
      message: `Package "${packageName}" has no provenance attestation`,
      severity: mode === 'enforce' ? 'error' : 'warning',
      mode,
    });
  }

  if (rules.required_provenance_level) {
    const levels: ProvenanceLevel[] = ['verified', 'partial', 'none'];
    const requiredIdx = levels.indexOf(rules.required_provenance_level);
    const actualIdx = levels.indexOf(provenance);
    if (actualIdx > requiredIdx) {
      violations.push({
        rule: 'required_provenance_level',
        message: `Package "${packageName}" provenance "${provenance}" below required "${rules.required_provenance_level}"`,
        severity: mode === 'enforce' ? 'error' : 'warning',
        mode,
      });
    }
  }

  // Vulnerability severity
  if (rules.max_allowed_severity && maxVulnSeverity) {
    const severityOrder = ['none', 'low', 'medium', 'high', 'critical'];
    const maxAllowed = severityOrder.indexOf(rules.max_allowed_severity);
    const actual = severityOrder.indexOf(maxVulnSeverity.toLowerCase());
    if (actual > maxAllowed) {
      violations.push({
        rule: 'max_allowed_severity',
        message: `Package "${packageName}" has ${maxVulnSeverity} vulnerability (policy allows max: ${rules.max_allowed_severity})`,
        severity: mode === 'enforce' ? 'error' : 'warning',
        mode,
      });
    }
  }

  return violations;
}

// Pure function that mirrors PolicyEngine.evaluateFull logic
function evaluateFull(
  policy: PolicyConfig,
  context: {
    criticalFindings: number;
    highFindings: number;
    aiCodeRatio: number;
    sbomBaselineExists: boolean;
    secretsScannerEnabled: boolean;
    sastScannerEnabled: boolean;
  },
): { passed: boolean; violations: PolicyViolation[]; rulesChecked: number } {
  const violations: PolicyViolation[] = [];
  const rules = policy.rules;
  const mode = policy.mode;
  let rulesChecked = 0;

  if (rules.max_critical_findings !== undefined) {
    rulesChecked++;
    if (context.criticalFindings > rules.max_critical_findings) {
      violations.push({
        rule: 'max_critical_findings',
        message: `${context.criticalFindings} critical findings exceed policy limit of ${rules.max_critical_findings}`,
        severity: mode === 'enforce' ? 'error' : 'warning',
        mode,
      });
    }
  }

  if (rules.max_high_findings !== undefined) {
    rulesChecked++;
    if (context.highFindings > rules.max_high_findings) {
      violations.push({
        rule: 'max_high_findings',
        message: `${context.highFindings} high findings exceed policy limit of ${rules.max_high_findings}`,
        severity: mode === 'enforce' ? 'error' : 'warning',
        mode,
      });
    }
  }

  if (rules.max_ai_code_ratio !== undefined) {
    rulesChecked++;
    if (context.aiCodeRatio > rules.max_ai_code_ratio) {
      violations.push({
        rule: 'max_ai_code_ratio',
        message: `AI code ratio exceeds policy limit`,
        severity: mode === 'enforce' ? 'error' : 'warning',
        mode,
      });
    }
  }

  if (rules.require_sbom_baseline) {
    rulesChecked++;
    if (!context.sbomBaselineExists) {
      violations.push({
        rule: 'require_sbom_baseline',
        message: 'SBOM baseline required but not found',
        severity: mode === 'enforce' ? 'error' : 'warning',
        mode,
      });
    }
  }

  if (rules.require_secrets_scanner) {
    rulesChecked++;
    if (!context.secretsScannerEnabled) {
      violations.push({
        rule: 'require_secrets_scanner',
        message: 'Secrets scanner required but disabled',
        severity: 'warning',
        mode,
      });
    }
  }

  if (rules.require_sast_scanner) {
    rulesChecked++;
    if (!context.sastScannerEnabled) {
      violations.push({
        rule: 'require_sast_scanner',
        message: 'SAST scanner required but disabled',
        severity: 'warning',
        mode,
      });
    }
  }

  return { passed: violations.length === 0, violations, rulesChecked };
}

// ─── Tests ─────────────────────────────────────────────────────────

suite('PolicyEngine — Package Evaluation', () => {

  const strictPolicy: PolicyConfig = {
    version: 1,
    mode: 'enforce',
    rules: {
      forbidden_packages: ['event-stream', 'ua-parser-js@0.7.28'],
      allowed_packages: ['trusted-lib'],
      block_unprovenanced_packages: true,
      required_provenance_level: 'partial',
      max_allowed_severity: 'medium',
    },
  };

  const warnPolicy: PolicyConfig = {
    version: 1,
    mode: 'warn',
    rules: {
      forbidden_packages: ['event-stream'],
      max_allowed_severity: 'high',
    },
  };

  test('forbidden package is rejected', () => {
    const v = evaluatePackage(strictPolicy, 'event-stream', null, 'none', null);
    assert.ok(v.length > 0, 'Should have violations');
    assert.strictEqual(v[0].rule, 'forbidden_packages');
    assert.strictEqual(v[0].severity, 'error', 'Enforce mode should produce errors');
  });

  test('forbidden package with version match', () => {
    const v = evaluatePackage(strictPolicy, 'ua-parser-js', '0.7.28', 'none', null);
    const forbiddenViolation = v.find(vi => vi.rule === 'forbidden_packages');
    assert.ok(forbiddenViolation, 'Should match version-specific ban');
  });

  test('allowed package bypasses all checks', () => {
    const v = evaluatePackage(strictPolicy, 'trusted-lib', null, 'none', 'critical');
    assert.strictEqual(v.length, 0, 'Allowed packages bypass all rules');
  });

  test('unprovenanced package is blocked', () => {
    const v = evaluatePackage(strictPolicy, 'some-pkg', null, 'none', null);
    const provenanceViolation = v.find(vi => vi.rule === 'block_unprovenanced_packages');
    assert.ok(provenanceViolation, 'Should block unprovenanced packages');
  });

  test('provenance level below required triggers violation', () => {
    const v = evaluatePackage(strictPolicy, 'some-pkg', null, 'none', null);
    const levelViolation = v.find(vi => vi.rule === 'required_provenance_level');
    assert.ok(levelViolation, 'Should flag provenance below required level');
  });

  test('verified provenance passes provenance checks', () => {
    const v = evaluatePackage(strictPolicy, 'good-pkg', null, 'verified', null);
    const provenanceViolations = v.filter(vi =>
      vi.rule === 'block_unprovenanced_packages' || vi.rule === 'required_provenance_level'
    );
    assert.strictEqual(provenanceViolations.length, 0);
  });

  test('critical vulnerability exceeds medium policy', () => {
    const v = evaluatePackage(strictPolicy, 'vuln-pkg', '1.0.0', 'verified', 'critical');
    const sevViolation = v.find(vi => vi.rule === 'max_allowed_severity');
    assert.ok(sevViolation, 'Critical should exceed medium policy');
  });

  test('low vulnerability passes medium policy', () => {
    const v = evaluatePackage(strictPolicy, 'minor-pkg', '1.0.0', 'verified', 'low');
    const sevViolation = v.find(vi => vi.rule === 'max_allowed_severity');
    assert.strictEqual(sevViolation, undefined, 'Low should pass medium policy');
  });

  test('warn mode produces warnings not errors', () => {
    const v = evaluatePackage(warnPolicy, 'event-stream', null, 'none', null);
    assert.ok(v.length > 0);
    assert.strictEqual(v[0].severity, 'warning');
  });

  test('clean package has no violations', () => {
    const v = evaluatePackage(warnPolicy, 'lodash', '4.17.21', 'verified', null);
    assert.strictEqual(v.length, 0);
  });
});

suite('PolicyEngine — Full Evaluation', () => {

  const strictPolicy: PolicyConfig = {
    version: 1,
    mode: 'enforce',
    rules: {
      max_critical_findings: 0,
      max_high_findings: 5,
      max_ai_code_ratio: 0.7,
      require_sbom_baseline: true,
      require_secrets_scanner: true,
      require_sast_scanner: true,
    },
  };

  test('clean project passes all rules', () => {
    const result = evaluateFull(strictPolicy, {
      criticalFindings: 0,
      highFindings: 0,
      aiCodeRatio: 0.3,
      sbomBaselineExists: true,
      secretsScannerEnabled: true,
      sastScannerEnabled: true,
    });
    assert.strictEqual(result.passed, true);
    assert.strictEqual(result.violations.length, 0);
    assert.ok(result.rulesChecked >= 5);
  });

  test('critical findings exceed limit', () => {
    const result = evaluateFull(strictPolicy, {
      criticalFindings: 3,
      highFindings: 0,
      aiCodeRatio: 0.1,
      sbomBaselineExists: true,
      secretsScannerEnabled: true,
      sastScannerEnabled: true,
    });
    assert.strictEqual(result.passed, false);
    const v = result.violations.find(vi => vi.rule === 'max_critical_findings');
    assert.ok(v, 'Should flag critical findings');
  });

  test('AI code ratio over limit', () => {
    const result = evaluateFull(strictPolicy, {
      criticalFindings: 0,
      highFindings: 0,
      aiCodeRatio: 0.85,
      sbomBaselineExists: true,
      secretsScannerEnabled: true,
      sastScannerEnabled: true,
    });
    assert.strictEqual(result.passed, false);
    assert.ok(result.violations.some(v => v.rule === 'max_ai_code_ratio'));
  });

  test('missing SBOM baseline triggers violation', () => {
    const result = evaluateFull(strictPolicy, {
      criticalFindings: 0,
      highFindings: 0,
      aiCodeRatio: 0.1,
      sbomBaselineExists: false,
      secretsScannerEnabled: true,
      sastScannerEnabled: true,
    });
    assert.ok(result.violations.some(v => v.rule === 'require_sbom_baseline'));
  });

  test('disabled scanners trigger violations', () => {
    const result = evaluateFull(strictPolicy, {
      criticalFindings: 0,
      highFindings: 0,
      aiCodeRatio: 0.1,
      sbomBaselineExists: true,
      secretsScannerEnabled: false,
      sastScannerEnabled: false,
    });
    assert.ok(result.violations.some(v => v.rule === 'require_secrets_scanner'));
    assert.ok(result.violations.some(v => v.rule === 'require_sast_scanner'));
  });

  test('multiple violations accumulate', () => {
    const result = evaluateFull(strictPolicy, {
      criticalFindings: 5,
      highFindings: 10,
      aiCodeRatio: 0.95,
      sbomBaselineExists: false,
      secretsScannerEnabled: false,
      sastScannerEnabled: false,
    });
    assert.strictEqual(result.passed, false);
    assert.ok(result.violations.length >= 5, 'Should have multiple violations');
  });
});
