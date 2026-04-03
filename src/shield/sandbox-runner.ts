/**
 * Sandbox Runtime Analysis for Install Gate
 *
 * Before allowing a package install, optionally runs the package's install
 * scripts in a restricted Node.js VM sandbox and observes what they do.
 *
 * Monitors:
 *   - Network calls (http/https/dns)
 *   - File system writes outside the sandbox directory
 *   - Environment variable reads
 *   - Process spawning (child_process)
 *   - Crypto operations (potential mining)
 *   - Dynamic code evaluation (eval, Function)
 *
 * Compares observed behavior against the PermissionModel's declared permissions
 * to flag permission violations BEFORE the package actually installs.
 *
 * Safety: Uses Node.js `vm` module (not full isolation). This is a heuristic
 * analysis layer, not a security boundary. Real sandboxing would require
 * containers or VMs.
 */

import * as vscode from 'vscode';
import * as vm from 'vm';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ObservedBehavior =
  | 'network-call'
  | 'filesystem-write'
  | 'filesystem-read-external'
  | 'env-access'
  | 'process-spawn'
  | 'crypto-operation'
  | 'dynamic-eval'
  | 'timer-usage'
  | 'global-modification';

export interface BehaviorObservation {
  behavior: ObservedBehavior;
  detail: string;
  /** Was this declared in the permission model? */
  permitted: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface SandboxReport {
  packageName: string;
  scriptType: 'preinstall' | 'install' | 'postinstall';
  observations: BehaviorObservation[];
  /** Whether any undeclared behaviors were observed */
  hasViolations: boolean;
  /** Number of violations */
  violationCount: number;
  /** Execution time in ms */
  executionTimeMs: number;
  /** Whether the script errored */
  scriptErrored: boolean;
  errorMessage?: string;
  timestamp: number;
}

export interface DeclaredPermissions {
  network: boolean;
  filesystem: boolean;
  env: boolean;
  process: boolean;
  crypto: boolean;
}

// ---------------------------------------------------------------------------
// Behavior Detection via Static Analysis of Script Content
// ---------------------------------------------------------------------------

interface BehaviorPattern {
  behavior: ObservedBehavior;
  pattern: RegExp;
  detail: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

const BEHAVIOR_PATTERNS: BehaviorPattern[] = [
  // Network
  { behavior: 'network-call', pattern: /require\s*\(\s*['"](?:http|https|net|dgram|dns|tls)['"]\s*\)/, detail: 'Imports network module', severity: 'high' },
  { behavior: 'network-call', pattern: /(?:fetch|XMLHttpRequest|axios|request|got|node-fetch)\s*\(/, detail: 'Makes HTTP request', severity: 'high' },
  { behavior: 'network-call', pattern: /\.(?:get|post|put|delete|request)\s*\(\s*['"]https?:/, detail: 'HTTP request to URL', severity: 'high' },
  { behavior: 'network-call', pattern: /new\s+(?:WebSocket|Socket)\s*\(/, detail: 'Opens socket connection', severity: 'high' },
  { behavior: 'network-call', pattern: /dns\.(?:lookup|resolve|reverse)\s*\(/, detail: 'DNS lookup', severity: 'medium' },

  // Filesystem
  { behavior: 'filesystem-write', pattern: /(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(/, detail: 'Writes to filesystem', severity: 'high' },
  { behavior: 'filesystem-write', pattern: /(?:mkdir|mkdirSync|rmdir|rmdirSync|unlink|unlinkSync|rename|renameSync)\s*\(/, detail: 'Modifies filesystem structure', severity: 'high' },
  { behavior: 'filesystem-write', pattern: /(?:cp|copyFile|copyFileSync)\s*\(/, detail: 'Copies files', severity: 'medium' },
  { behavior: 'filesystem-read-external', pattern: /(?:readFile|readFileSync|createReadStream)\s*\(\s*['"]\/(?:etc|proc|sys|home|Users|root)/, detail: 'Reads sensitive system paths', severity: 'critical' },
  { behavior: 'filesystem-read-external', pattern: /(?:readFile|readFileSync)\s*\([^)]*(?:\.ssh|\.aws|\.env|\.npmrc|\.gitconfig)/, detail: 'Reads credential files', severity: 'critical' },

  // Environment
  { behavior: 'env-access', pattern: /process\.env\b/, detail: 'Reads environment variables', severity: 'medium' },
  { behavior: 'env-access', pattern: /(?:HOME|USER|PATH|SHELL|USERPROFILE|APPDATA|LOCALAPPDATA)\b/, detail: 'Accesses system environment paths', severity: 'medium' },
  { behavior: 'env-access', pattern: /(?:AWS_|AZURE_|GCP_|GOOGLE_|GITHUB_TOKEN|NPM_TOKEN|CI_)\w+/, detail: 'Accesses cloud/CI credential env vars', severity: 'high' },

  // Process
  { behavior: 'process-spawn', pattern: /require\s*\(\s*['"]child_process['"]\s*\)/, detail: 'Imports child_process module', severity: 'critical' },
  { behavior: 'process-spawn', pattern: /(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\(/, detail: 'Spawns child process', severity: 'critical' },
  { behavior: 'process-spawn', pattern: /process\.(?:kill|exit|abort)\s*\(/, detail: 'Terminates process', severity: 'high' },

  // Crypto (potential mining)
  { behavior: 'crypto-operation', pattern: /require\s*\(\s*['"]crypto['"]\s*\)/, detail: 'Imports crypto module', severity: 'low' },
  { behavior: 'crypto-operation', pattern: /(?:createHash|createCipher|createDecipher|pbkdf2|scrypt)\s*\(/, detail: 'Performs crypto operation', severity: 'low' },

  // Dynamic eval
  { behavior: 'dynamic-eval', pattern: /\beval\s*\(/, detail: 'Uses eval() for dynamic code execution', severity: 'critical' },
  { behavior: 'dynamic-eval', pattern: /new\s+Function\s*\(/, detail: 'Creates function from string', severity: 'critical' },
  { behavior: 'dynamic-eval', pattern: /vm\.(?:runInNewContext|runInThisContext|createContext|Script)\b/, detail: 'Uses Node.js VM module', severity: 'high' },

  // Timers (persistence)
  { behavior: 'timer-usage', pattern: /setInterval\s*\(/, detail: 'Sets repeating timer (possible persistence)', severity: 'medium' },

  // Global modification
  { behavior: 'global-modification', pattern: /(?:global|globalThis|window)\.\w+\s*=/, detail: 'Modifies global scope', severity: 'medium' },
  { behavior: 'global-modification', pattern: /Object\.prototype\.\w+\s*=/, detail: 'Modifies Object prototype', severity: 'high' },
];

// ---------------------------------------------------------------------------
// SandboxRunner Class
// ---------------------------------------------------------------------------

export class SandboxRunner {
  private outputChannel: vscode.OutputChannel;

  /** Maximum script execution time (ms) */
  private static readonly TIMEOUT_MS = 5000;

  constructor() {
    this.outputChannel = vscode.window.createOutputChannel('CodeGuard Sandbox');
  }

  /**
   * Analyze a package install script for runtime behaviors.
   *
   * This performs STATIC analysis of the script content (pattern matching)
   * plus a restricted VM execution attempt to catch dynamic behaviors.
   */
  analyzeScript(
    packageName: string,
    scriptContent: string,
    scriptType: 'preinstall' | 'install' | 'postinstall',
    declaredPermissions: DeclaredPermissions
  ): SandboxReport {
    const startTime = Date.now();
    const observations: BehaviorObservation[] = [];

    // Phase 1: Static pattern analysis
    const lines = scriptContent.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      // Skip comments
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) { continue; }

      for (const bp of BEHAVIOR_PATTERNS) {
        if (bp.pattern.test(line)) {
          const permitted = this.isPermitted(bp.behavior, declaredPermissions);
          observations.push({
            behavior: bp.behavior,
            detail: `Line ${i + 1}: ${bp.detail}`,
            permitted,
            severity: permitted ? this.downgradeSeverity(bp.severity) : bp.severity,
          });
        }
      }
    }

    // Phase 2: Restricted VM execution (catch dynamic behaviors)
    let scriptErrored = false;
    let errorMessage: string | undefined;

    try {
      const vmObservations = this.executeInSandbox(scriptContent, declaredPermissions);
      observations.push(...vmObservations);
    } catch (e) {
      scriptErrored = true;
      errorMessage = e instanceof Error ? e.message : String(e);
      // Script errors during sandbox execution are expected — many scripts
      // won't run outside their intended environment
    }

    // Deduplicate observations
    const seen = new Set<string>();
    const unique = observations.filter(o => {
      const key = `${o.behavior}:${o.detail}`;
      if (seen.has(key)) { return false; }
      seen.add(key);
      return true;
    });

    const violations = unique.filter(o => !o.permitted);

    const report: SandboxReport = {
      packageName,
      scriptType,
      observations: unique,
      hasViolations: violations.length > 0,
      violationCount: violations.length,
      executionTimeMs: Date.now() - startTime,
      scriptErrored,
      errorMessage,
      timestamp: Date.now(),
    };

    this.logReport(report);
    return report;
  }

  /**
   * Format sandbox report as markdown.
   */
  toMarkdown(report: SandboxReport): string {
    const lines: string[] = [
      `# Sandbox Analysis: ${report.packageName}`,
      '',
      `**Script:** ${report.scriptType} | **Time:** ${report.executionTimeMs}ms | **Violations:** ${report.violationCount}`,
      '',
    ];

    if (report.scriptErrored) {
      lines.push(`> Script errored during sandbox execution: ${report.errorMessage}`);
      lines.push('');
    }

    if (report.observations.length === 0) {
      lines.push('No notable behaviors detected.');
      return lines.join('\n');
    }

    // Group by behavior type
    const byBehavior = new Map<ObservedBehavior, BehaviorObservation[]>();
    for (const o of report.observations) {
      if (!byBehavior.has(o.behavior)) { byBehavior.set(o.behavior, []); }
      byBehavior.get(o.behavior)!.push(o);
    }

    for (const [behavior, obs] of byBehavior) {
      const anyViolation = obs.some(o => !o.permitted);
      const icon = anyViolation ? '🔴' : '✅';
      lines.push(`## ${icon} ${behavior} (${obs.length})`);
      for (const o of obs) {
        const status = o.permitted ? '✓ permitted' : '✗ VIOLATION';
        lines.push(`- [${status}] ${o.detail}`);
      }
      lines.push('');
    }

    return lines.join('\n');
  }

  // -----------------------------------------------------------------------
  // Private: VM Sandbox Execution
  // -----------------------------------------------------------------------

  private executeInSandbox(scriptContent: string, declaredPermissions: DeclaredPermissions): BehaviorObservation[] {
    const observations: BehaviorObservation[] = [];

    // Create a mock `require` that logs what modules are imported
    const mockRequire = (moduleName: string) => {
      const networkModules = ['http', 'https', 'net', 'dgram', 'dns', 'tls'];
      const fsModules = ['fs', 'fs/promises'];
      const processModules = ['child_process'];
      const cryptoModules = ['crypto'];

      if (networkModules.includes(moduleName)) {
        observations.push({
          behavior: 'network-call',
          detail: `VM: require('${moduleName}')`,
          permitted: declaredPermissions.network,
          severity: declaredPermissions.network ? 'low' : 'high',
        });
      } else if (fsModules.includes(moduleName)) {
        observations.push({
          behavior: 'filesystem-write',
          detail: `VM: require('${moduleName}')`,
          permitted: declaredPermissions.filesystem,
          severity: declaredPermissions.filesystem ? 'low' : 'high',
        });
      } else if (processModules.includes(moduleName)) {
        observations.push({
          behavior: 'process-spawn',
          detail: `VM: require('${moduleName}')`,
          permitted: declaredPermissions.process,
          severity: declaredPermissions.process ? 'medium' : 'critical',
        });
      } else if (cryptoModules.includes(moduleName)) {
        observations.push({
          behavior: 'crypto-operation',
          detail: `VM: require('${moduleName}')`,
          permitted: declaredPermissions.crypto,
          severity: 'low',
        });
      }

      // Return empty mock object
      return new Proxy({}, {
        get: (_target, prop) => {
          if (typeof prop === 'string') {
            return (..._args: unknown[]) => {
              // Log function calls on required modules
            };
          }
          return undefined;
        }
      });
    };

    // Create sandbox context with mocked globals
    const mockProcess = {
      env: new Proxy({}, {
        get: (_target, prop) => {
          if (typeof prop === 'string') {
            observations.push({
              behavior: 'env-access',
              detail: `VM: process.env.${prop}`,
              permitted: declaredPermissions.env,
              severity: declaredPermissions.env ? 'low' : 'medium',
            });
          }
          return undefined;
        }
      }),
      cwd: () => '/sandbox',
      platform: process.platform,
      arch: process.arch,
      version: process.version,
      exit: () => {
        observations.push({
          behavior: 'process-spawn',
          detail: 'VM: process.exit() called',
          permitted: false,
          severity: 'high',
        });
      },
    };

    const sandbox = {
      require: mockRequire,
      process: mockProcess,
      console: {
        log: () => {},
        warn: () => {},
        error: () => {},
        info: () => {},
      },
      setTimeout: () => {},
      setInterval: () => {
        observations.push({
          behavior: 'timer-usage',
          detail: 'VM: setInterval() called',
          permitted: false,
          severity: 'medium',
        });
      },
      Buffer: {
        from: () => Buffer.alloc(0),
        alloc: (size: number) => Buffer.alloc(Math.min(size, 1024)),
      },
      __filename: '/sandbox/script.js',
      __dirname: '/sandbox',
      module: { exports: {} },
      exports: {},
      global: {},
    };

    try {
      const context = vm.createContext(sandbox);
      const script = new vm.Script(scriptContent, {
        filename: 'sandbox-script.js',
      });
      script.runInContext(context, { timeout: SandboxRunner.TIMEOUT_MS });
    } catch (e) {
      // Expected — most install scripts won't run in a sandbox
      // The mock require/process already captured the important signals
      if (e instanceof Error && e.message.includes('timed out')) {
        observations.push({
          behavior: 'timer-usage',
          detail: 'VM: Script execution timed out (possible infinite loop)',
          permitted: false,
          severity: 'high',
        });
      }
    }

    return observations;
  }

  // -----------------------------------------------------------------------
  // Private: Helpers
  // -----------------------------------------------------------------------

  private isPermitted(behavior: ObservedBehavior, perms: DeclaredPermissions): boolean {
    switch (behavior) {
      case 'network-call': return perms.network;
      case 'filesystem-write':
      case 'filesystem-read-external': return perms.filesystem;
      case 'env-access': return perms.env;
      case 'process-spawn': return perms.process;
      case 'crypto-operation': return perms.crypto;
      case 'dynamic-eval': return false; // Never permitted
      case 'timer-usage': return true;   // Generally acceptable
      case 'global-modification': return false; // Never permitted
      default: return false;
    }
  }

  private downgradeSeverity(severity: 'critical' | 'high' | 'medium' | 'low'): 'critical' | 'high' | 'medium' | 'low' {
    // If behavior is permitted, downgrade severity
    switch (severity) {
      case 'critical': return 'medium';
      case 'high': return 'low';
      case 'medium': return 'low';
      case 'low': return 'low';
    }
  }

  private logReport(report: SandboxReport): void {
    this.outputChannel.appendLine(`\n[Sandbox] ${report.packageName} (${report.scriptType})`);
    this.outputChannel.appendLine(`  Observations: ${report.observations.length}, Violations: ${report.violationCount}`);
    for (const o of report.observations) {
      const icon = o.permitted ? '✓' : '✗';
      this.outputChannel.appendLine(`  ${icon} [${o.severity}] ${o.behavior}: ${o.detail}`);
    }
    if (report.scriptErrored) {
      this.outputChannel.appendLine(`  Script error: ${report.errorMessage}`);
    }
  }

  dispose(): void {
    this.outputChannel.dispose();
  }
}
