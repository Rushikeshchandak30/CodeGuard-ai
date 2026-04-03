import * as vscode from 'vscode';

/**
 * Extension configuration wrapper.
 * Reads settings from VS Code's configuration system.
 */
export class Config {
  private static readonly SECTION = 'codeguard';

  static get enabled(): boolean {
    return this.get<boolean>('enabled', true);
  }

  static get severityThreshold(): string {
    return this.get<string>('severityThreshold', 'MEDIUM');
  }

  static get enableHallucinationDetection(): boolean {
    return this.get<boolean>('enableHallucinationDetection', true);
  }

  static get debounceMs(): number {
    return this.get<number>('debounceMs', 500);
  }

  static get cacheTtlMinutes(): number {
    return this.get<number>('cacheTtlMinutes', 60);
  }

  static get ignoredPackages(): string[] {
    return this.get<string[]>('ignoredPackages', []);
  }

  static get enableAiFeedback(): boolean {
    return this.get<boolean>('enableAiFeedback', true);
  }

  static get enableCommentInjection(): boolean {
    return this.get<boolean>('enableCommentInjection', true);
  }

  static get enableCodeLens(): boolean {
    return this.get<boolean>('enableCodeLens', true);
  }

  static get enableDecorations(): boolean {
    return this.get<boolean>('enableDecorations', true);
  }

  static get enableChatParticipant(): boolean {
    return this.get<boolean>('enableChatParticipant', true);
  }

  static get enableLanguageModelApi(): boolean {
    return this.get<boolean>('enableLanguageModelApi', true);
  }

  static get privateRegistries(): string[] {
    return this.get<string[]>('privateRegistries', []);
  }

  static get enableTyposquatDetection(): boolean {
    return this.get<boolean>('enableTyposquatDetection', true);
  }

  static get enablePopularityCheck(): boolean {
    return this.get<boolean>('enablePopularityCheck', true);
  }

  static get aiDebounceMs(): number {
    return this.get<number>('aiDebounceMs', 100);
  }

  // v3 settings

  static get enableInstallGate(): boolean {
    return this.get<boolean>('enableInstallGate', true);
  }

  static get enableRulesScanner(): boolean {
    return this.get<boolean>('enableRulesScanner', true);
  }

  static get enableGhin(): boolean {
    return this.get<boolean>('enableGhin', true);
  }

  static get enableGhinCloudSync(): boolean {
    return this.get<boolean>('enableGhinCloudSync', false);
  }

  static get enableProvenanceCheck(): boolean {
    return this.get<boolean>('enableProvenanceCheck', true);
  }

  static get enableAutoPatch(): boolean {
    return this.get<boolean>('enableAutoPatch', true);
  }

  static get enableScriptAnalysis(): boolean {
    return this.get<boolean>('enableScriptAnalysis', true);
  }

  static get enableSecretsScanner(): boolean {
    return this.get<boolean>('enableSecretsScanner', true);
  }

  static get enableCodeVulnScanner(): boolean {
    return this.get<boolean>('enableCodeVulnScanner', true);
  }

  static get enableSecurityScore(): boolean {
    return this.get<boolean>('enableSecurityScore', true);
  }

  static get strictnessLevel(): 'audit' | 'warn' | 'enforce' {
    return this.get<'audit' | 'warn' | 'enforce'>('strictnessLevel', 'warn');
  }

  static get ghinApiUrl(): string {
    return this.get<string>('ghinApiUrl', 'https://ghin-api.codeguard.dev');
  }

  /**
   * Check if a given severity meets the configured threshold.
   */
  static meetsThreshold(severity: string): boolean {
    const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const threshold = order.indexOf(this.severityThreshold);
    const actual = order.indexOf(severity);
    if (threshold === -1 || actual === -1) { return true; }
    return actual >= threshold;
  }

  private static get<T>(key: string, defaultValue: T): T {
    const config = vscode.workspace.getConfiguration(this.SECTION);
    return config.get<T>(key, defaultValue);
  }
}
