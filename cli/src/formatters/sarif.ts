/**
 * SARIF (Static Analysis Results Interchange Format) v2.1.0 output formatter.
 * Compatible with GitHub Code Scanning, Azure DevOps, and other SARIF consumers.
 */

import { ScanResult, ScanFinding, Severity } from '../scanner';

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
  invocations: SarifInvocation[];
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  fixes?: SarifFix[];
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region: { startLine: number; startColumn: number };
  };
}

interface SarifFix {
  description: { text: string };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  endTimeUtc: string;
}

function severityToSarifLevel(severity: Severity): string {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'error';
    case 'medium': return 'warning';
    case 'low': return 'note';
    case 'info': return 'note';
    default: return 'warning';
  }
}

/**
 * Convert a ScanResult to SARIF v2.1.0 format.
 */
export function toSarif(result: ScanResult): string {
  // Collect unique rules
  const rulesMap = new Map<string, SarifRule>();
  for (const f of result.findings) {
    const ruleId = f.ruleId ?? f.id;
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: f.message.split(':')[0] || f.message,
        shortDescription: { text: f.message },
        defaultConfiguration: { level: severityToSarifLevel(f.severity) },
      });
    }
  }

  const sarifResults: SarifResult[] = result.findings.map(f => {
    const sarifResult: SarifResult = {
      ruleId: f.ruleId ?? f.id,
      level: severityToSarifLevel(f.severity),
      message: { text: f.message },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: f.file.replace(/\\/g, '/') },
          region: { startLine: f.line, startColumn: f.column || 1 },
        },
      }],
    };
    if (f.fix) {
      sarifResult.fixes = [{ description: { text: f.fix } }];
    }
    return sarifResult;
  });

  const sarif: SarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'CodeGuard AI',
          version: '5.2.0',
          informationUri: 'https://github.com/codeguard-ai/codeguard-ai',
          rules: Array.from(rulesMap.values()),
        },
      },
      results: sarifResults,
      invocations: [{
        executionSuccessful: true,
        endTimeUtc: result.timestamp,
      }],
    }],
  };

  return JSON.stringify(sarif, null, 2);
}
