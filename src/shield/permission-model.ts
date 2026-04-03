/**
 * Dependency Permission Model
 *
 * Analyzes what capabilities a package requires (network, filesystem, env access)
 * and lets the developer approve/deny permissions before install.
 *
 * Persists trust decisions in .codeguard/permissions.json so packages only need
 * to be approved once per workspace.
 *
 * Integrates with Install Gate — called during the install analysis pipeline.
 */

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Permission Types
// ---------------------------------------------------------------------------

export type PermissionKind = 'network' | 'filesystem' | 'env' | 'process' | 'crypto';

export interface PermissionRequest {
  kind: PermissionKind;
  description: string;
  evidence: string;        // code snippet or pattern that triggered it
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface PackagePermissions {
  packageName: string;
  ecosystem: string;
  version?: string;
  permissions: PermissionRequest[];
  hasInstallScripts: boolean;
  totalPermissions: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

export type PermissionDecision = 'allow_all' | 'deny' | 'allow_once';

export interface TrustDecisionRecord {
  packageName: string;
  ecosystem: string;
  decision: PermissionDecision;
  decidedAt: string;         // ISO timestamp
  permissionsAtDecision: PermissionKind[];
  version?: string;
}

// ---------------------------------------------------------------------------
// Permission Detection Patterns
// ---------------------------------------------------------------------------

interface PermissionPattern {
  kind: PermissionKind;
  pattern: RegExp;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

const PERMISSION_PATTERNS: PermissionPattern[] = [
  // Network access
  { kind: 'network', pattern: /\b(?:http|https|net|dgram|tls|dns)\.(?:get|request|createServer|createConnection|connect|lookup)\b/i, description: 'Makes network connections', severity: 'high' },
  { kind: 'network', pattern: /\b(?:fetch|axios|got|request|node-fetch|undici)\s*\(/i, description: 'Uses HTTP client library', severity: 'medium' },
  { kind: 'network', pattern: /\bWebSocket\b/i, description: 'Opens WebSocket connections', severity: 'high' },
  { kind: 'network', pattern: /https?:\/\/[^\s'"]+/i, description: 'Contains hardcoded URLs', severity: 'medium' },
  { kind: 'network', pattern: /\b(?:XMLHttpRequest|ActiveXObject)\b/i, description: 'Uses legacy HTTP APIs', severity: 'medium' },

  // Filesystem access
  { kind: 'filesystem', pattern: /\bfs\.\b(?:readFile|writeFile|unlink|rmdir|mkdir|rename|copyFile|appendFile|chmod|chown|access|stat|readdir|createReadStream|createWriteStream)/i, description: 'Reads/writes filesystem', severity: 'high' },
  { kind: 'filesystem', pattern: /\bfs\.(?:readFileSync|writeFileSync|unlinkSync|rmdirSync|mkdirSync)\b/i, description: 'Synchronous filesystem operations', severity: 'high' },
  { kind: 'filesystem', pattern: /\b(?:fse|fs-extra|graceful-fs)\b/i, description: 'Uses extended filesystem library', severity: 'medium' },
  { kind: 'filesystem', pattern: /(?:\/etc\/|\/usr\/|\/var\/|~\/|%APPDATA%|%USERPROFILE%|os\.homedir)/i, description: 'Accesses system directories', severity: 'critical' },

  // Environment variable access
  { kind: 'env', pattern: /process\.env\b/i, description: 'Reads environment variables', severity: 'high' },
  { kind: 'env', pattern: /\bos\.environ\b/i, description: 'Reads environment (Python)', severity: 'high' },
  { kind: 'env', pattern: /\b(?:dotenv|cross-env)\b/i, description: 'Uses dotenv/environment library', severity: 'low' },

  // Process spawning
  { kind: 'process', pattern: /\b(?:child_process|exec|execSync|spawn|spawnSync|execFile|fork)\b/i, description: 'Spawns child processes', severity: 'critical' },
  { kind: 'process', pattern: /\b(?:shelljs|execa)\b/i, description: 'Uses shell execution library', severity: 'high' },
  { kind: 'process', pattern: /\bprocess\.(?:exit|kill|abort)\b/i, description: 'Can terminate processes', severity: 'high' },

  // Crypto operations (may indicate key/cert handling)
  { kind: 'crypto', pattern: /\b(?:crypto|createHash|createCipheriv|createSign|createVerify|randomBytes|generateKeyPair)\b/i, description: 'Uses cryptographic operations', severity: 'low' },
  { kind: 'crypto', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i, description: 'Contains private key material', severity: 'critical' },
];

// ---------------------------------------------------------------------------
// PermissionModel Class
// ---------------------------------------------------------------------------

export class PermissionModel {
  private trustStore: Map<string, TrustDecisionRecord> = new Map();
  private permissionsFilePath: string | null = null;

  constructor() {
    this.loadTrustStore();
  }

  /**
   * Analyze a package's code/scripts for required permissions.
   */
  analyzePermissions(
    packageName: string,
    ecosystem: string,
    scriptContent: string,
    hasInstallScripts: boolean,
    version?: string
  ): PackagePermissions {
    const permissions: PermissionRequest[] = [];
    const lines = scriptContent.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pp of PERMISSION_PATTERNS) {
        const match = pp.pattern.exec(line);
        if (match) {
          // Avoid duplicate permission kinds from same pattern
          const already = permissions.find(p => p.kind === pp.kind && p.description === pp.description);
          if (!already) {
            permissions.push({
              kind: pp.kind,
              description: pp.description,
              evidence: line.trim().substring(0, 120),
              severity: pp.severity,
            });
          }
        }
      }
    }

    const riskLevel = this.computeRiskLevel(permissions, hasInstallScripts);

    return {
      packageName,
      ecosystem,
      version,
      permissions,
      hasInstallScripts,
      totalPermissions: permissions.length,
      riskLevel,
    };
  }

  /**
   * Check if a package has already been trusted by the user.
   */
  isTrusted(packageName: string, ecosystem: string): boolean {
    const key = `${ecosystem}/${packageName}`;
    const record = this.trustStore.get(key);
    return record?.decision === 'allow_all';
  }

  /**
   * Check if a package has been denied.
   */
  isDenied(packageName: string, ecosystem: string): boolean {
    const key = `${ecosystem}/${packageName}`;
    const record = this.trustStore.get(key);
    return record?.decision === 'deny';
  }

  /**
   * Get existing trust decision for a package.
   */
  getDecision(packageName: string, ecosystem: string): TrustDecisionRecord | undefined {
    const key = `${ecosystem}/${packageName}`;
    return this.trustStore.get(key);
  }

  /**
   * Show the permission request UI and return the user's decision.
   */
  async requestPermission(pkg: PackagePermissions): Promise<PermissionDecision> {
    // Check if already trusted
    if (this.isTrusted(pkg.packageName, pkg.ecosystem)) {
      return 'allow_all';
    }
    if (this.isDenied(pkg.packageName, pkg.ecosystem)) {
      return 'deny';
    }

    // If no permissions needed, auto-allow
    if (pkg.permissions.length === 0 && !pkg.hasInstallScripts) {
      return 'allow_all';
    }

    // Build permission summary
    const permSummary = this.formatPermissionSummary(pkg);

    const riskEmoji = pkg.riskLevel === 'critical' ? '🔴' :
                      pkg.riskLevel === 'high' ? '🟠' :
                      pkg.riskLevel === 'medium' ? '🟡' : '🟢';

    const message = `${riskEmoji} ${pkg.packageName} requests ${pkg.totalPermissions} permission(s):\n${permSummary}`;

    const choice = await vscode.window.showWarningMessage(
      message,
      { modal: true, detail: this.formatDetailedPermissions(pkg) },
      'Allow All',
      'Allow Once',
      'Deny & Remove'
    );

    let decision: PermissionDecision;
    switch (choice) {
      case 'Allow All':
        decision = 'allow_all';
        break;
      case 'Allow Once':
        decision = 'allow_once';
        break;
      default:
        decision = 'deny';
        break;
    }

    // Persist decision (except allow_once)
    if (decision !== 'allow_once') {
      this.saveTrustDecision(pkg.packageName, pkg.ecosystem, decision, pkg.permissions.map(p => p.kind), pkg.version);
    }

    return decision;
  }

  /**
   * Revoke trust for a package.
   */
  revokeTrust(packageName: string, ecosystem: string): void {
    const key = `${ecosystem}/${packageName}`;
    this.trustStore.delete(key);
    this.persistTrustStore();
  }

  /**
   * Get all trust decisions.
   */
  getAllDecisions(): TrustDecisionRecord[] {
    return Array.from(this.trustStore.values());
  }

  // ---------------------------------------------------------------------------
  // Private Helpers
  // ---------------------------------------------------------------------------

  private computeRiskLevel(permissions: PermissionRequest[], hasInstallScripts: boolean): 'safe' | 'low' | 'medium' | 'high' | 'critical' {
    if (permissions.length === 0 && !hasInstallScripts) { return 'safe'; }

    const hasCritical = permissions.some(p => p.severity === 'critical');
    const hasHigh = permissions.some(p => p.severity === 'high');
    const hasProcess = permissions.some(p => p.kind === 'process');
    const hasNetwork = permissions.some(p => p.kind === 'network');
    const hasEnv = permissions.some(p => p.kind === 'env');

    if (hasCritical || (hasProcess && hasNetwork)) { return 'critical'; }
    if (hasHigh || (hasInstallScripts && (hasNetwork || hasEnv))) { return 'high'; }
    if (permissions.length >= 3 || hasInstallScripts) { return 'medium'; }
    return 'low';
  }

  private formatPermissionSummary(pkg: PackagePermissions): string {
    const kinds = new Set(pkg.permissions.map(p => p.kind));
    const icons: Record<PermissionKind, string> = {
      network: '🌐 Network access',
      filesystem: '📁 File system access',
      env: '🔑 Environment variables',
      process: '⚙️ Process spawning',
      crypto: '🔐 Cryptographic operations',
    };
    const parts: string[] = [];
    for (const k of kinds) {
      parts.push(icons[k] ?? k);
    }
    if (pkg.hasInstallScripts) {
      parts.push('📜 Install scripts (preinstall/postinstall)');
    }
    return parts.join('\n');
  }

  private formatDetailedPermissions(pkg: PackagePermissions): string {
    let detail = `Package: ${pkg.packageName}@${pkg.version ?? 'latest'}\n`;
    detail += `Ecosystem: ${pkg.ecosystem}\n`;
    detail += `Risk Level: ${pkg.riskLevel.toUpperCase()}\n\n`;
    detail += `Detected capabilities:\n`;
    for (const p of pkg.permissions) {
      const sev = p.severity === 'critical' ? '🔴' : p.severity === 'high' ? '🟠' : p.severity === 'medium' ? '🟡' : '🔵';
      detail += `  ${sev} [${p.kind}] ${p.description}\n`;
      detail += `    Evidence: ${p.evidence}\n`;
    }
    return detail;
  }

  private saveTrustDecision(
    packageName: string,
    ecosystem: string,
    decision: PermissionDecision,
    permissionKinds: PermissionKind[],
    version?: string
  ): void {
    const key = `${ecosystem}/${packageName}`;
    this.trustStore.set(key, {
      packageName,
      ecosystem,
      decision,
      decidedAt: new Date().toISOString(),
      permissionsAtDecision: permissionKinds,
      version,
    });
    this.persistTrustStore();
  }

  private loadTrustStore(): void {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) { return; }

    const filePath = path.join(workspaceFolders[0].uri.fsPath, '.codeguard', 'permissions.json');
    this.permissionsFilePath = filePath;

    if (fs.existsSync(filePath)) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const records: TrustDecisionRecord[] = JSON.parse(content);
        for (const r of records) {
          this.trustStore.set(`${r.ecosystem}/${r.packageName}`, r);
        }
      } catch {
        // Corrupted file — start fresh
        this.trustStore.clear();
      }
    }
  }

  private persistTrustStore(): void {
    if (!this.permissionsFilePath) {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (!workspaceFolders) { return; }
      const dir = path.join(workspaceFolders[0].uri.fsPath, '.codeguard');
      if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }
      this.permissionsFilePath = path.join(dir, 'permissions.json');
    }

    const records = Array.from(this.trustStore.values());
    fs.writeFileSync(this.permissionsFilePath, JSON.stringify(records, null, 2), 'utf-8');
  }

  dispose(): void {
    // Nothing to dispose
  }
}
