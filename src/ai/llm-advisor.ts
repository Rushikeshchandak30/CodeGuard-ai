/**
 * LLM Advisory Layer
 *
 * Uses VS Code Language Model API (vscode.lm) to provide:
 * - Patch explanation generation
 * - Risk summary in plain language
 * - Fix suggestion formatting for AI assistants
 * - Semantic risk analysis
 *
 * LLMs are ADVISORY only — security decisions remain deterministic.
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PatchExplanationRequest {
  packageName: string;
  ecosystem: string;
  currentVersion: string | null;
  vulnerabilities: Array<{
    id: string;
    severity: string;
    summary: string;
  }>;
  fixedVersion: string | null;
  alternatives: string[];
}

export interface PatchExplanation {
  summary: string;
  riskExplanation: string;
  recommendedAction: string;
  codeSnippet: string | null;
  generatedByLlm: boolean;
}

export interface RiskSummaryRequest {
  packageName: string;
  ecosystem: string;
  issues: Array<{
    type: 'vulnerability' | 'hallucination' | 'provenance' | 'script' | 'deprecated';
    severity: string;
    detail: string;
  }>;
}

export interface ScriptRiskRequest {
  packageName: string;
  scriptContent: string;
  suspiciousPatterns: Array<{
    category: string;
    evidence: string;
    line: number | null;
  }>;
}

// ---------------------------------------------------------------------------
// LLM Advisor Class
// ---------------------------------------------------------------------------

export class LlmAdvisor {
  private modelSelector: vscode.LanguageModelChatSelector = {
    vendor: 'copilot',
    family: 'gpt-4o',
  };

  private fallbackModelSelector: vscode.LanguageModelChatSelector = {
    vendor: 'copilot',
    family: 'gpt-3.5-turbo',
  };

  private enabled: boolean = true;

  constructor() {
    // Check if LM API is available
    this.enabled = typeof vscode.lm !== 'undefined';
  }

  /**
   * Check if LLM advisory is available.
   */
  isAvailable(): boolean {
    return this.enabled;
  }

  /**
   * Generate a human-readable patch explanation.
   */
  async explainPatch(request: PatchExplanationRequest): Promise<PatchExplanation> {
    // Fallback if LLM not available
    if (!this.enabled) {
      return this.generateFallbackPatchExplanation(request);
    }

    try {
      const model = await this.selectModel();
      if (!model) {
        return this.generateFallbackPatchExplanation(request);
      }

      const prompt = this.buildPatchPrompt(request);
      const messages = [vscode.LanguageModelChatMessage.User(prompt)];

      const response = await model.sendRequest(messages, {}, new vscode.CancellationTokenSource().token);

      let text = '';
      for await (const chunk of response.text) {
        text += chunk;
      }

      return this.parsePatchResponse(text, request);
    } catch {
      return this.generateFallbackPatchExplanation(request);
    }
  }

  /**
   * Generate a plain-language risk summary.
   */
  async summarizeRisk(request: RiskSummaryRequest): Promise<string> {
    if (!this.enabled) {
      return this.generateFallbackRiskSummary(request);
    }

    try {
      const model = await this.selectModel();
      if (!model) {
        return this.generateFallbackRiskSummary(request);
      }

      const prompt = `You are a security advisor. Summarize the following security issues for the package "${request.packageName}" (${request.ecosystem}) in 2-3 sentences that a developer can quickly understand. Be concise and actionable.

Issues:
${request.issues.map(i => `- [${i.severity.toUpperCase()}] ${i.type}: ${i.detail}`).join('\n')}

Respond with ONLY the summary, no preamble.`;

      const messages = [vscode.LanguageModelChatMessage.User(prompt)];
      const response = await model.sendRequest(messages, {}, new vscode.CancellationTokenSource().token);

      let text = '';
      for await (const chunk of response.text) {
        text += chunk;
      }

      return text.trim() || this.generateFallbackRiskSummary(request);
    } catch {
      return this.generateFallbackRiskSummary(request);
    }
  }

  /**
   * Explain why an install script is risky.
   */
  async explainScriptRisk(request: ScriptRiskRequest): Promise<string> {
    if (!this.enabled) {
      return this.generateFallbackScriptExplanation(request);
    }

    try {
      const model = await this.selectModel();
      if (!model) {
        return this.generateFallbackScriptExplanation(request);
      }

      const prompt = `You are a security analyst. The npm package "${request.packageName}" has an install script with the following suspicious patterns:

${request.suspiciousPatterns.map(p => `- ${p.category}: "${p.evidence}" (line ${p.line ?? 'unknown'})`).join('\n')}

Explain in 2-3 sentences what these patterns could do and why they're concerning. Be specific but concise.`;

      const messages = [vscode.LanguageModelChatMessage.User(prompt)];
      const response = await model.sendRequest(messages, {}, new vscode.CancellationTokenSource().token);

      let text = '';
      for await (const chunk of response.text) {
        text += chunk;
      }

      return text.trim() || this.generateFallbackScriptExplanation(request);
    } catch {
      return this.generateFallbackScriptExplanation(request);
    }
  }

  /**
   * Generate a fix suggestion formatted for AI assistants to read.
   */
  async generateAiFixPrompt(
    packageName: string,
    ecosystem: string,
    issue: string,
    fixVersion: string | null,
    alternatives: string[],
  ): Promise<string> {
    const parts: string[] = [
      `## Security Issue: ${packageName} (${ecosystem})`,
      '',
      `**Problem:** ${issue}`,
      '',
    ];

    if (fixVersion) {
      parts.push(`**Recommended Fix:** Update to ${packageName}@${fixVersion}`);
      parts.push('');
      if (ecosystem === 'npm') {
        parts.push('```bash');
        parts.push(`npm install ${packageName}@${fixVersion}`);
        parts.push('```');
      } else if (ecosystem === 'PyPI') {
        parts.push('```bash');
        parts.push(`pip install "${packageName}>=${fixVersion}"`);
        parts.push('```');
      }
    }

    if (alternatives.length > 0) {
      parts.push('');
      parts.push(`**Alternatives:** Consider using ${alternatives.join(', ')} instead.`);
    }

    return parts.join('\n');
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private async selectModel(): Promise<vscode.LanguageModelChat | null> {
    try {
      const models = await vscode.lm.selectChatModels(this.modelSelector);
      if (models.length > 0) {
        return models[0];
      }

      // Try fallback
      const fallbackModels = await vscode.lm.selectChatModels(this.fallbackModelSelector);
      if (fallbackModels.length > 0) {
        return fallbackModels[0];
      }

      return null;
    } catch {
      return null;
    }
  }

  private buildPatchPrompt(request: PatchExplanationRequest): string {
    const vulnList = request.vulnerabilities
      .map(v => `- ${v.id} (${v.severity}): ${v.summary}`)
      .join('\n');

    return `You are a security advisor helping a developer fix a vulnerable dependency.

Package: ${request.packageName} (${request.ecosystem})
Current Version: ${request.currentVersion ?? 'unknown'}
Vulnerabilities:
${vulnList}

Fixed Version: ${request.fixedVersion ?? 'unknown'}
Alternatives: ${request.alternatives.length > 0 ? request.alternatives.join(', ') : 'none'}

Provide a response in this exact format:
SUMMARY: <one sentence summary of the risk>
RISK: <2-3 sentence explanation of what could happen if not fixed>
ACTION: <specific action the developer should take>
CODE: <optional code snippet to fix, or "none">

Be concise and actionable.`;
  }

  private parsePatchResponse(text: string, request: PatchExplanationRequest): PatchExplanation {
    const lines = text.split('\n');
    let summary = '';
    let riskExplanation = '';
    let recommendedAction = '';
    let codeSnippet: string | null = null;

    for (const line of lines) {
      if (line.startsWith('SUMMARY:')) {
        summary = line.replace('SUMMARY:', '').trim();
      } else if (line.startsWith('RISK:')) {
        riskExplanation = line.replace('RISK:', '').trim();
      } else if (line.startsWith('ACTION:')) {
        recommendedAction = line.replace('ACTION:', '').trim();
      } else if (line.startsWith('CODE:')) {
        const code = line.replace('CODE:', '').trim();
        if (code && code.toLowerCase() !== 'none') {
          codeSnippet = code;
        }
      }
    }

    // If parsing failed, use fallback
    if (!summary && !riskExplanation) {
      return this.generateFallbackPatchExplanation(request);
    }

    return {
      summary: summary || `${request.packageName} has ${request.vulnerabilities.length} known vulnerabilities`,
      riskExplanation: riskExplanation || 'This package contains security vulnerabilities that could be exploited.',
      recommendedAction: recommendedAction || (request.fixedVersion ? `Update to ${request.fixedVersion}` : 'Review and update the package'),
      codeSnippet,
      generatedByLlm: true,
    };
  }

  private generateFallbackPatchExplanation(request: PatchExplanationRequest): PatchExplanation {
    const vulnCount = request.vulnerabilities.length;
    const severities = request.vulnerabilities.map(v => v.severity);
    const hasCritical = severities.includes('CRITICAL');
    const hasHigh = severities.includes('HIGH');

    let summary = `${request.packageName} has ${vulnCount} known ${vulnCount === 1 ? 'vulnerability' : 'vulnerabilities'}`;
    if (hasCritical) {
      summary += ' including CRITICAL severity issues';
    } else if (hasHigh) {
      summary += ' including HIGH severity issues';
    }

    let riskExplanation = 'These vulnerabilities could allow attackers to ';
    if (hasCritical) {
      riskExplanation += 'execute arbitrary code, steal data, or compromise your application.';
    } else if (hasHigh) {
      riskExplanation += 'exploit your application through various attack vectors.';
    } else {
      riskExplanation += 'potentially affect your application security.';
    }

    let recommendedAction = '';
    if (request.fixedVersion) {
      recommendedAction = `Update to ${request.packageName}@${request.fixedVersion}`;
    } else if (request.alternatives.length > 0) {
      recommendedAction = `Consider switching to ${request.alternatives[0]}`;
    } else {
      recommendedAction = 'Review the vulnerabilities and update to the latest version';
    }

    let codeSnippet: string | null = null;
    if (request.fixedVersion) {
      if (request.ecosystem === 'npm') {
        codeSnippet = `npm install ${request.packageName}@${request.fixedVersion}`;
      } else if (request.ecosystem === 'PyPI') {
        codeSnippet = `pip install "${request.packageName}>=${request.fixedVersion}"`;
      }
    }

    return {
      summary,
      riskExplanation,
      recommendedAction,
      codeSnippet,
      generatedByLlm: false,
    };
  }

  private generateFallbackRiskSummary(request: RiskSummaryRequest): string {
    const counts: Record<string, number> = {};
    for (const issue of request.issues) {
      counts[issue.type] = (counts[issue.type] || 0) + 1;
    }

    const parts: string[] = [];
    if (counts['vulnerability']) {
      parts.push(`${counts['vulnerability']} ${counts['vulnerability'] === 1 ? 'vulnerability' : 'vulnerabilities'}`);
    }
    if (counts['hallucination']) {
      parts.push('potential hallucination');
    }
    if (counts['provenance']) {
      parts.push('provenance concerns');
    }
    if (counts['script']) {
      parts.push('suspicious install scripts');
    }
    if (counts['deprecated']) {
      parts.push('deprecation');
    }

    return `${request.packageName} has ${parts.join(', ')}. Review before using.`;
  }

  private generateFallbackScriptExplanation(request: ScriptRiskRequest): string {
    const categories = [...new Set(request.suspiciousPatterns.map(p => p.category))];

    const explanations: Record<string, string> = {
      'network': 'makes network requests that could exfiltrate data',
      'env-access': 'accesses environment variables that may contain secrets',
      'process-spawn': 'executes system commands that could run arbitrary code',
      'obfuscation': 'contains obfuscated code that hides its true behavior',
      'filesystem': 'accesses files outside the project directory',
      'dynamic-require': 'dynamically loads code that could be injected',
    };

    const risks = categories.map(c => explanations[c] || c).join(', ');

    return `The install script for ${request.packageName} ${risks}. This could indicate malicious behavior.`;
  }
}
