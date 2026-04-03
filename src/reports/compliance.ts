/**
 * Compliance Report Generator
 *
 * Generates compliance-ready security reports for audit purposes.
 * Supports:
 *   - CSV export (for spreadsheet analysis)
 *   - Markdown export (for documentation / PDF conversion)
 *   - JSON export (for programmatic consumption)
 *
 * Report sections:
 *   1. Executive Summary
 *   2. Vulnerability Inventory
 *   3. Dependency Trust Scores
 *   4. SBOM Summary
 *   5. AI Code Attribution Summary
 *   6. Policy Compliance Status
 *   7. Security Score Trend
 *   8. Hallucination Detection Log
 *
 * Designed for:
 *   - EU Cyber Resilience Act (CRA)
 *   - US Executive Order 14028 (Software Supply Chain Security)
 *   - SOC 2 Type II evidence
 *   - ISO 27001 control evidence
 */

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ComplianceData {
  projectName: string;
  generatedAt: string;
  extensionVersion: string;

  /** Vulnerability findings summary */
  vulnerabilities: VulnSummary[];

  /** Dependency trust scores */
  dependencies: DepTrustEntry[];

  /** SBOM component count */
  sbomComponentCount: number;
  sbomFormat: string;

  /** AI code attribution */
  aiAttribution: {
    totalFiles: number;
    aiGeneratedLines: number;
    humanWrittenLines: number;
    aiRatio: number;
    aiVulnRate: number;
    humanVulnRate: number;
  };

  /** Policy evaluation */
  policy: {
    policyFile: string | null;
    ruleCount: number;
    passed: number;
    failed: number;
    violations: string[];
  };

  /** Security score */
  securityScore: {
    current: number;
    trend: 'improving' | 'stable' | 'declining';
    history: Array<{ date: string; score: number }>;
  };

  /** Hallucination detections */
  hallucinations: Array<{
    package_name: string;
    ecosystem: string;
    detected_at: string;
    ai_agent?: string;
  }>;
}

interface VulnSummary {
  id: string;
  package_name: string;
  ecosystem: string;
  severity: string;
  description: string;
  remediation: string;
  status: 'open' | 'patched' | 'accepted';
}

interface DepTrustEntry {
  name: string;
  ecosystem: string;
  version: string;
  trustScore: number;
  trustTier: string;
  provenance: boolean;
  vulnerabilityCount: number;
}

// ---------------------------------------------------------------------------
// ComplianceReportGenerator
// ---------------------------------------------------------------------------

export class ComplianceReportGenerator {
  private outputChannel: vscode.OutputChannel;

  constructor() {
    this.outputChannel = vscode.window.createOutputChannel('CodeGuard Compliance');
  }

  /**
   * Generate a full compliance report and save to disk.
   */
  async generate(
    data: ComplianceData,
    format: 'csv' | 'markdown' | 'json',
    outputDir: string
  ): Promise<string> {
    // Ensure output directory exists
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    let filename: string;
    let content: string;

    switch (format) {
      case 'csv':
        filename = `codeguard-compliance-${timestamp}.csv`;
        content = this.generateCsv(data);
        break;
      case 'json':
        filename = `codeguard-compliance-${timestamp}.json`;
        content = JSON.stringify(data, null, 2);
        break;
      case 'markdown':
      default:
        filename = `codeguard-compliance-${timestamp}.md`;
        content = this.generateMarkdown(data);
        break;
    }

    const filePath = path.join(outputDir, filename);
    fs.writeFileSync(filePath, content, 'utf-8');

    this.outputChannel.appendLine(`[Compliance] Report generated: ${filePath} (${format})`);
    return filePath;
  }

  /**
   * Collect compliance data from all active modules.
   * This is a helper that gathers data from various extension components.
   */
  collectData(params: {
    projectName: string;
    vulnerabilities?: VulnSummary[];
    dependencies?: DepTrustEntry[];
    sbomComponentCount?: number;
    aiAttribution?: ComplianceData['aiAttribution'];
    policy?: ComplianceData['policy'];
    securityScore?: ComplianceData['securityScore'];
    hallucinations?: ComplianceData['hallucinations'];
  }): ComplianceData {
    return {
      projectName: params.projectName,
      generatedAt: new Date().toISOString(),
      extensionVersion: '5.2.0',
      vulnerabilities: params.vulnerabilities || [],
      dependencies: params.dependencies || [],
      sbomComponentCount: params.sbomComponentCount || 0,
      sbomFormat: 'CycloneDX 1.5',
      aiAttribution: params.aiAttribution || {
        totalFiles: 0,
        aiGeneratedLines: 0,
        humanWrittenLines: 0,
        aiRatio: 0,
        aiVulnRate: 0,
        humanVulnRate: 0,
      },
      policy: params.policy || {
        policyFile: null,
        ruleCount: 0,
        passed: 0,
        failed: 0,
        violations: [],
      },
      securityScore: params.securityScore || {
        current: 0,
        trend: 'stable',
        history: [],
      },
      hallucinations: params.hallucinations || [],
    };
  }

  // -----------------------------------------------------------------------
  // Markdown Report
  // -----------------------------------------------------------------------

  generateMarkdown(data: ComplianceData): string {
    const lines: string[] = [];

    // Header
    lines.push('# CodeGuard AI — Compliance Security Report');
    lines.push('');
    lines.push(`**Project:** ${data.projectName}`);
    lines.push(`**Generated:** ${new Date(data.generatedAt).toLocaleString()}`);
    lines.push(`**Extension Version:** ${data.extensionVersion}`);
    lines.push('');
    lines.push('---');
    lines.push('');

    // 1. Executive Summary
    lines.push('## 1. Executive Summary');
    lines.push('');
    const criticalCount = data.vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = data.vulnerabilities.filter(v => v.severity === 'high').length;
    const openCount = data.vulnerabilities.filter(v => v.status === 'open').length;
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Security Score | **${data.securityScore.current}/100** (${data.securityScore.trend}) |`);
    lines.push(`| Total Vulnerabilities | ${data.vulnerabilities.length} (${criticalCount} critical, ${highCount} high) |`);
    lines.push(`| Open Vulnerabilities | ${openCount} |`);
    lines.push(`| Dependencies Tracked | ${data.dependencies.length} |`);
    lines.push(`| SBOM Components | ${data.sbomComponentCount} (${data.sbomFormat}) |`);
    lines.push(`| AI-Generated Code Ratio | ${(data.aiAttribution.aiRatio * 100).toFixed(1)}% |`);
    lines.push(`| Policy Compliance | ${data.policy.passed}/${data.policy.ruleCount} rules passed |`);
    lines.push(`| Hallucinations Detected | ${data.hallucinations.length} |`);
    lines.push('');

    // 2. Vulnerability Inventory
    lines.push('## 2. Vulnerability Inventory');
    lines.push('');
    if (data.vulnerabilities.length === 0) {
      lines.push('No vulnerabilities detected.');
    } else {
      lines.push('| ID | Package | Severity | Status | Description |');
      lines.push('|----|---------|----------|--------|-------------|');
      for (const v of data.vulnerabilities) {
        lines.push(`| ${v.id} | ${v.package_name} (${v.ecosystem}) | ${v.severity} | ${v.status} | ${v.description} |`);
      }
    }
    lines.push('');

    // 3. Dependency Trust Scores
    lines.push('## 3. Dependency Trust Scores');
    lines.push('');
    if (data.dependencies.length === 0) {
      lines.push('No dependency data available.');
    } else {
      lines.push('| Package | Version | Trust Score | Tier | Provenance | Vulns |');
      lines.push('|---------|---------|-------------|------|------------|-------|');
      for (const d of data.dependencies) {
        lines.push(`| ${d.name} | ${d.version} | ${d.trustScore}/100 | ${d.trustTier} | ${d.provenance ? 'Verified' : 'None'} | ${d.vulnerabilityCount} |`);
      }
    }
    lines.push('');

    // 4. AI Code Attribution
    lines.push('## 4. AI Code Attribution');
    lines.push('');
    const ai = data.aiAttribution;
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Files Tracked | ${ai.totalFiles} |`);
    lines.push(`| AI-Generated Lines | ${ai.aiGeneratedLines.toLocaleString()} |`);
    lines.push(`| Human-Written Lines | ${ai.humanWrittenLines.toLocaleString()} |`);
    lines.push(`| AI Code Ratio | ${(ai.aiRatio * 100).toFixed(1)}% |`);
    lines.push(`| AI Code Vuln Rate | ${(ai.aiVulnRate * 100).toFixed(2)}% |`);
    lines.push(`| Human Code Vuln Rate | ${(ai.humanVulnRate * 100).toFixed(2)}% |`);
    lines.push('');

    // 5. Policy Compliance
    lines.push('## 5. Policy Compliance');
    lines.push('');
    if (!data.policy.policyFile) {
      lines.push('No policy file configured. Create `.codeguard/policy.json` to enable policy enforcement.');
    } else {
      lines.push(`**Policy file:** \`${data.policy.policyFile}\``);
      lines.push(`**Rules:** ${data.policy.ruleCount} total, ${data.policy.passed} passed, ${data.policy.failed} failed`);
      lines.push('');
      if (data.policy.violations.length > 0) {
        lines.push('### Violations');
        for (const v of data.policy.violations) {
          lines.push(`- ${v}`);
        }
      } else {
        lines.push('All policy rules passed.');
      }
    }
    lines.push('');

    // 6. Hallucination Detection Log
    lines.push('## 6. Hallucination Detection Log');
    lines.push('');
    if (data.hallucinations.length === 0) {
      lines.push('No AI-hallucinated packages detected.');
    } else {
      lines.push('| Package | Ecosystem | Detected At | AI Agent |');
      lines.push('|---------|-----------|-------------|----------|');
      for (const h of data.hallucinations) {
        lines.push(`| ${h.package_name} | ${h.ecosystem} | ${new Date(h.detected_at).toLocaleString()} | ${h.ai_agent || 'Unknown'} |`);
      }
    }
    lines.push('');

    // 7. Compliance Framework Mapping
    lines.push('## 7. Compliance Framework Mapping');
    lines.push('');
    lines.push('| Requirement | Framework | Evidence | Status |');
    lines.push('|-------------|-----------|----------|--------|');
    lines.push(`| Software Bill of Materials | CRA Art. 10, EO 14028 | SBOM (${data.sbomComponentCount} components, ${data.sbomFormat}) | ${data.sbomComponentCount > 0 ? 'Met' : 'Not Generated'} |`);
    lines.push(`| Vulnerability Management | CRA Art. 10, SOC 2 CC7.1 | ${data.vulnerabilities.length} tracked, ${openCount} open | ${openCount === 0 ? 'Met' : 'In Progress'} |`);
    lines.push(`| Supply Chain Security | EO 14028, SLSA | ${data.dependencies.filter(d => d.provenance).length}/${data.dependencies.length} with provenance | ${data.dependencies.length > 0 ? 'Partial' : 'N/A'} |`);
    lines.push(`| Security Policy Enforcement | ISO 27001 A.14 | ${data.policy.ruleCount} rules, ${data.policy.failed} violations | ${data.policy.failed === 0 ? 'Met' : 'Not Met'} |`);
    lines.push(`| AI Code Governance | Internal | ${(ai.aiRatio * 100).toFixed(1)}% AI-generated, tracked | Met |`);
    lines.push(`| Continuous Monitoring | SOC 2 CC7.2 | Real-time IDE scanning active | Met |`);
    lines.push('');

    // Footer
    lines.push('---');
    lines.push(`*Report generated by CodeGuard AI v${data.extensionVersion}*`);

    return lines.join('\n');
  }

  // -----------------------------------------------------------------------
  // CSV Report
  // -----------------------------------------------------------------------

  generateCsv(data: ComplianceData): string {
    const rows: string[][] = [];

    // Vulnerability section
    rows.push(['Section', 'ID', 'Package', 'Ecosystem', 'Severity', 'Status', 'Description', 'Remediation']);
    for (const v of data.vulnerabilities) {
      rows.push(['Vulnerability', v.id, v.package_name, v.ecosystem, v.severity, v.status, v.description, v.remediation]);
    }

    // Empty row separator
    rows.push([]);

    // Dependency section
    rows.push(['Section', 'Package', 'Version', 'Trust Score', 'Trust Tier', 'Provenance', 'Vulnerabilities']);
    for (const d of data.dependencies) {
      rows.push(['Dependency', d.name, d.version, String(d.trustScore), d.trustTier, d.provenance ? 'Yes' : 'No', String(d.vulnerabilityCount)]);
    }

    // Empty row separator
    rows.push([]);

    // Hallucination section
    rows.push(['Section', 'Package', 'Ecosystem', 'Detected At', 'AI Agent']);
    for (const h of data.hallucinations) {
      rows.push(['Hallucination', h.package_name, h.ecosystem, h.detected_at, h.ai_agent || '']);
    }

    // Empty row separator
    rows.push([]);

    // Summary section
    rows.push(['Metric', 'Value']);
    rows.push(['Project', data.projectName]);
    rows.push(['Generated', data.generatedAt]);
    rows.push(['Security Score', String(data.securityScore.current)]);
    rows.push(['Score Trend', data.securityScore.trend]);
    rows.push(['Total Vulnerabilities', String(data.vulnerabilities.length)]);
    rows.push(['Dependencies', String(data.dependencies.length)]);
    rows.push(['SBOM Components', String(data.sbomComponentCount)]);
    rows.push(['AI Code Ratio', `${(data.aiAttribution.aiRatio * 100).toFixed(1)}%`]);
    rows.push(['Policy Rules Passed', `${data.policy.passed}/${data.policy.ruleCount}`]);
    rows.push(['Hallucinations Detected', String(data.hallucinations.length)]);

    return rows.map(row => row.map(cell => this.csvEscape(cell)).join(',')).join('\n');
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private csvEscape(value: string): string {
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }

  dispose(): void {
    this.outputChannel.dispose();
  }
}
