/**
 * Install Script Static Analyzer
 *
 * Downloads package tarballs and analyzes preinstall/postinstall scripts
 * for suspicious behavior BEFORE they execute:
 * - Network calls to unknown domains
 * - Environment variable exfiltration
 * - File system access outside project
 * - Process spawning / shell execution
 * - Obfuscated code (eval, base64, hex encoding)
 * - Dynamic requires
 */

import * as https from 'https';
import * as zlib from 'zlib';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScriptIssue {
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'network' | 'env-access' | 'filesystem' | 'process-spawn' | 'obfuscation' | 'dynamic-require';
  message: string;
  evidence: string;
  line: number | null;
}

export interface ScriptAnalysisResult {
  packageName: string;
  ecosystem: string;
  /** Does the package have install scripts? */
  hasInstallScripts: boolean;
  /** Script names found (preinstall, postinstall, etc.) */
  scriptNames: string[];
  /** Individual issues found */
  issues: ScriptIssue[];
  /** Is the package suspicious overall? */
  suspicious: boolean;
  /** Critical issue count */
  criticalIssues: number;
  /** Summary message */
  summary: string;
  /** Script content for manual review (truncated) */
  scriptPreview: string | null;
}

// ---------------------------------------------------------------------------
// Suspicious pattern definitions
// ---------------------------------------------------------------------------

const SUSPICIOUS_PATTERNS: Array<{
  pattern: RegExp;
  category: ScriptIssue['category'];
  severity: ScriptIssue['severity'];
  message: string;
}> = [
  // Network calls
  {
    pattern: /https?:\/\/(?!(?:registry\.npmjs\.org|pypi\.org|github\.com|api\.github\.com|nodejs\.org|npmjs\.com))[^\s'")\]]+/gi,
    category: 'network',
    severity: 'high',
    message: 'HTTP request to non-standard external URL',
  },
  {
    pattern: /\b(?:fetch|axios|request|http\.get|https\.get|http\.request|https\.request|XMLHttpRequest|got)\s*\(/gi,
    category: 'network',
    severity: 'medium',
    message: 'Network request function call detected',
  },
  {
    pattern: /\b(?:net\.connect|net\.createConnection|dgram|dns\.resolve|dns\.lookup)\s*\(/gi,
    category: 'network',
    severity: 'high',
    message: 'Low-level network operation detected',
  },
  {
    pattern: /\bWebSocket\s*\(/gi,
    category: 'network',
    severity: 'high',
    message: 'WebSocket connection detected',
  },

  // Environment variable access (credential theft)
  {
    pattern: /process\.env\s*[[.]\s*['"]?(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AWS_ACCESS_KEY|AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|PYPI_TOKEN|SSH_KEY|DATABASE_URL|DB_PASSWORD|REDIS_URL|STRIPE_KEY|SENDGRID)/gi,
    category: 'env-access',
    severity: 'critical',
    message: 'Accesses sensitive environment variable',
  },
  {
    pattern: /process\.env\b/g,
    category: 'env-access',
    severity: 'medium',
    message: 'Accesses process environment variables',
  },
  {
    pattern: /os\.environ/g,
    category: 'env-access',
    severity: 'medium',
    message: 'Accesses OS environment variables (Python)',
  },

  // File system operations (persistence / data theft)
  {
    pattern: /(?:fs\.(?:writeFile|appendFile|createWriteStream|rename|unlink|rmdir|mkdir)|writeFileSync|appendFileSync)\s*\(\s*['"](?:\/etc\/|\/usr\/|\/tmp\/|\/var\/|~\/|%APPDATA%|%USERPROFILE%)/gi,
    category: 'filesystem',
    severity: 'critical',
    message: 'Writes to system directory outside project',
  },
  {
    pattern: /(?:fs\.(?:readFile|createReadStream|readFileSync))\s*\(\s*['"](?:\/etc\/passwd|\/etc\/shadow|~\/\.ssh|~\/\.aws|~\/\.npmrc|~\/\.pypirc|~\/\.gitconfig|~\/\.env)/gi,
    category: 'filesystem',
    severity: 'critical',
    message: 'Reads sensitive system file (credentials/config)',
  },
  {
    pattern: /(?:fs\.(?:readdir|readdirSync))\s*\(\s*['"](?:\/|~\/|C:\\)/gi,
    category: 'filesystem',
    severity: 'high',
    message: 'Enumerates directories outside project root',
  },

  // Process spawning (arbitrary command execution)
  {
    pattern: /\b(?:child_process|exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/gi,
    category: 'process-spawn',
    severity: 'high',
    message: 'Spawns child process / executes system command',
  },
  {
    pattern: /\b(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(/gi,
    category: 'process-spawn',
    severity: 'high',
    message: 'Executes system command (Python)',
  },
  {
    pattern: /\bpowershell\b|\bcmd\s*\/c\b|\bbash\s+-c\b|\bsh\s+-c\b/gi,
    category: 'process-spawn',
    severity: 'critical',
    message: 'Invokes shell interpreter directly',
  },
  {
    pattern: /\bcurl\s+-|wget\s+/gi,
    category: 'process-spawn',
    severity: 'high',
    message: 'Downloads remote content via CLI tool',
  },

  // Obfuscation (hiding malicious code)
  {
    pattern: /\beval\s*\(/gi,
    category: 'obfuscation',
    severity: 'critical',
    message: 'Dynamic code execution via eval()',
  },
  {
    pattern: /\bnew\s+Function\s*\(/gi,
    category: 'obfuscation',
    severity: 'critical',
    message: 'Dynamic code execution via Function constructor',
  },
  {
    pattern: /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{30,}/gi,
    category: 'obfuscation',
    severity: 'critical',
    message: 'Large base64-encoded payload decoded at runtime',
  },
  {
    pattern: /\batob\s*\(\s*['"][A-Za-z0-9+/=]{30,}/gi,
    category: 'obfuscation',
    severity: 'critical',
    message: 'Base64 decoding of large payload',
  },
  {
    pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/gi,
    category: 'obfuscation',
    severity: 'high',
    message: 'Hex-encoded string (potentially obfuscated payload)',
  },
  {
    pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}/gi,
    category: 'obfuscation',
    severity: 'high',
    message: 'String constructed from char codes (obfuscation pattern)',
  },
  {
    pattern: /\['\\x[0-9a-f]{2}[^']*'\]/gi,
    category: 'obfuscation',
    severity: 'high',
    message: 'Property access via hex-encoded string',
  },

  // Dynamic requires (code injection)
  {
    pattern: /require\s*\(\s*(?!['"])[^)]+\)/gi,
    category: 'dynamic-require',
    severity: 'medium',
    message: 'Dynamic require() with variable argument',
  },
  {
    pattern: /import\s*\(\s*(?!['"])[^)]+\)/gi,
    category: 'dynamic-require',
    severity: 'medium',
    message: 'Dynamic import() with variable argument',
  },
];

// ---------------------------------------------------------------------------
// ScriptAnalyzer Class
// ---------------------------------------------------------------------------

export class ScriptAnalyzer {
  private cache: Map<string, ScriptAnalysisResult> = new Map();
  private readonly CACHE_TTL = 60 * 60 * 1000; // 1 hour
  private cacheTimestamps: Map<string, number> = new Map();

  /**
   * Analyze a package's install scripts.
   */
  async analyzePackage(packageName: string, ecosystem: string): Promise<ScriptAnalysisResult> {
    const cacheKey = `${ecosystem}:${packageName}`;
    const cached = this.cache.get(cacheKey);
    const cachedTime = this.cacheTimestamps.get(cacheKey);
    if (cached && cachedTime && Date.now() - cachedTime < this.CACHE_TTL) {
      return cached;
    }

    let result: ScriptAnalysisResult;

    if (ecosystem.toLowerCase() === 'npm') {
      result = await this.analyzeNpmPackage(packageName);
    } else {
      // For non-npm ecosystems, return a basic result
      result = {
        packageName,
        ecosystem,
        hasInstallScripts: false,
        scriptNames: [],
        issues: [],
        suspicious: false,
        criticalIssues: 0,
        summary: `Install script analysis not yet supported for ${ecosystem}`,
        scriptPreview: null,
      };
    }

    this.cache.set(cacheKey, result);
    this.cacheTimestamps.set(cacheKey, Date.now());
    return result;
  }

  /**
   * Analyze raw script content (can be used for testing without network).
   */
  analyzeScriptContent(content: string): ScriptIssue[] {
    const issues: ScriptIssue[] = [];
    const lines = content.split('\n');

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      for (const { pattern, category, severity, message } of SUSPICIOUS_PATTERNS) {
        // Reset regex state for global patterns
        pattern.lastIndex = 0;
        const match = pattern.exec(line);
        if (match) {
          issues.push({
            severity,
            category,
            message,
            evidence: match[0].substring(0, 100),
            line: lineIdx + 1,
          });
        }
      }
    }

    return issues;
  }

  // -------------------------------------------------------------------------
  // npm-specific analysis
  // -------------------------------------------------------------------------

  private async analyzeNpmPackage(packageName: string): Promise<ScriptAnalysisResult> {
    try {
      // Step 1: Fetch package.json from registry to check for install scripts
      const pkgJson = await this.fetchNpmPackageJson(packageName);
      if (!pkgJson) {
        return this.makeResult(packageName, 'npm', false, [], 'Could not fetch package metadata');
      }

      const scripts = pkgJson.scripts ?? {};
      const installScriptNames = ['preinstall', 'install', 'postinstall', 'prepare'];
      const foundScripts: string[] = [];
      const scriptContents: string[] = [];

      for (const name of installScriptNames) {
        if (scripts[name]) {
          foundScripts.push(name);
          scriptContents.push(`# ${name}\n${scripts[name]}`);
        }
      }

      if (foundScripts.length === 0) {
        return this.makeResult(packageName, 'npm', false, [], 'No install scripts');
      }

      // Step 2: Analyze the script commands
      const allContent = scriptContents.join('\n\n');
      const issues = this.analyzeScriptContent(allContent);

      // Step 3: Try to download tarball and analyze actual script files
      const tarballUrl = pkgJson.dist?.tarball;
      if (tarballUrl) {
        const tarballIssues = await this.analyzeTarball(tarballUrl, foundScripts, scripts);
        issues.push(...tarballIssues);
      }

      const criticalIssues = issues.filter(i => i.severity === 'critical').length;
      const suspicious = criticalIssues > 0 || issues.filter(i => i.severity === 'high').length >= 2;

      const summaryParts: string[] = [];
      if (criticalIssues > 0) { summaryParts.push(`${criticalIssues} CRITICAL`); }
      const highCount = issues.filter(i => i.severity === 'high').length;
      if (highCount > 0) { summaryParts.push(`${highCount} HIGH`); }
      const medCount = issues.filter(i => i.severity === 'medium').length;
      if (medCount > 0) { summaryParts.push(`${medCount} MEDIUM`); }

      return {
        packageName,
        ecosystem: 'npm',
        hasInstallScripts: true,
        scriptNames: foundScripts,
        issues,
        suspicious,
        criticalIssues,
        summary: summaryParts.length > 0
          ? `${foundScripts.join(', ')} scripts: ${summaryParts.join(', ')} issues`
          : `${foundScripts.join(', ')} scripts: no suspicious patterns`,
        scriptPreview: allContent.substring(0, 500),
      };
    } catch {
      return this.makeResult(packageName, 'npm', false, [], 'Analysis failed');
    }
  }

  private fetchNpmPackageJson(packageName: string): Promise<NpmPackageJson | null> {
    return new Promise((resolve) => {
      const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;

      const req = https.get(url, { headers: { Accept: 'application/json' } }, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          try {
            if (res.statusCode !== 200) { resolve(null); return; }
            resolve(JSON.parse(body));
          } catch { resolve(null); }
        });
      });
      req.on('error', () => resolve(null));
      req.setTimeout(8000, () => { req.destroy(); resolve(null); });
      req.end();
    });
  }

  private analyzeTarball(
    tarballUrl: string,
    scriptNames: string[],
    scripts: Record<string, string>,
  ): Promise<ScriptIssue[]> {
    return new Promise((resolve) => {
      // Download tarball and look for the script files referenced in package.json
      const req = https.get(tarballUrl, (res) => {
        if (res.statusCode !== 200) { resolve([]); return; }

        const chunks: Buffer[] = [];
        let totalSize = 0;
        const MAX_SIZE = 5 * 1024 * 1024; // 5MB limit

        res.on('data', (chunk: Buffer) => {
          totalSize += chunk.length;
          if (totalSize > MAX_SIZE) {
            req.destroy();
            resolve([]);
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          try {
            const buffer = Buffer.concat(chunks);
            // Decompress gzip
            const decompressed = zlib.gunzipSync(buffer);

            // Simple tar parsing — look for .js files referenced in scripts
            const content = decompressed.toString('utf-8', 0, Math.min(decompressed.length, 2 * 1024 * 1024));

            // Analyze the raw content for patterns
            const issues = this.analyzeScriptContent(content);

            // Filter to only high/critical issues from tarball (to reduce noise)
            resolve(issues.filter(i => i.severity === 'critical' || i.severity === 'high'));
          } catch {
            resolve([]);
          }
        });
      });

      req.on('error', () => resolve([]));
      req.setTimeout(15000, () => { req.destroy(); resolve([]); });
      req.end();
    });
  }

  private makeResult(
    packageName: string,
    ecosystem: string,
    hasScripts: boolean,
    issues: ScriptIssue[],
    summary: string,
  ): ScriptAnalysisResult {
    return {
      packageName,
      ecosystem,
      hasInstallScripts: hasScripts,
      scriptNames: [],
      issues,
      suspicious: false,
      criticalIssues: 0,
      summary,
      scriptPreview: null,
    };
  }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface NpmPackageJson {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  dist?: { tarball?: string };
  deprecated?: string;
}
