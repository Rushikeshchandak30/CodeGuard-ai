/**
 * Core Scanner — standalone scanning engine with NO vscode dependency.
 * Used by the CLI tool and can be imported by CI/CD integrations.
 *
 * Scans a project directory for:
 *   1. Hallucinated package names (from imports + known-hallucination DB)
 *   2. Dependency vulnerabilities (via OSV.dev API)
 *   3. Hardcoded secrets (regex patterns)
 *   4. Code vulnerability patterns (SAST regex)
 *   5. Policy violations (from .codeguard/policy.json)
 */

import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';

// ─── Types ───────────────────────────────────────────────────────────

export type Ecosystem = 'npm' | 'PyPI' | 'Go' | 'Maven' | 'crates.io';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ScanFinding {
  id: string;
  type: 'hallucination' | 'vulnerability' | 'secret' | 'sast' | 'policy' | 'mcp';
  severity: Severity;
  message: string;
  file: string;
  line: number;
  column: number;
  packageName?: string;
  cveId?: string;
  ruleId?: string;
  fix?: string;
}

export interface ScanResult {
  projectPath: string;
  timestamp: string;
  findings: ScanFinding[];
  summary: ScanSummary;
  packages: PackageInfo[];
}

export interface ScanSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  hallucinatedPackages: number;
  vulnerablePackages: number;
  secretsFound: number;
  sastFindings: number;
  policyViolations: number;
  mcpIssues: number;
  scannedFiles: number;
}

export interface PackageInfo {
  name: string;
  version: string | null;
  ecosystem: Ecosystem;
  exists: boolean;
  isHallucination: boolean;
  vulnerabilities: string[];
}

export interface ScanOptions {
  /** Project root directory */
  projectPath: string;
  /** Enable hallucination detection (default: true) */
  hallucination?: boolean;
  /** Enable vulnerability scanning (default: true) */
  vulnerabilities?: boolean;
  /** Enable secrets scanning (default: true) */
  secrets?: boolean;
  /** Enable SAST scanning (default: true) */
  sast?: boolean;
  /** Enable policy evaluation (default: true) */
  policy?: boolean;
  /** Enable MCP server config scanning (default: true) */
  mcp?: boolean;
  /** Severity threshold — only report findings at or above this level */
  severityThreshold?: Severity;
  /** Packages to ignore */
  ignoredPackages?: string[];
  /** Private scoped packages to skip (e.g., '@mycompany/') */
  privateRegistries?: string[];
}

// ─── Known Hallucination DB (bundled subset) ─────────────────────────

// Load from the shared data files if available, or use inline fallback
let KNOWN_NPM_HALLUCINATIONS: Set<string>;
let KNOWN_PYPI_HALLUCINATIONS: Set<string>;
let POPULAR_NPM: string[];
let POPULAR_PYPI: string[];

try {
  const hallucinationsPath = path.resolve(__dirname, '../../src/data/known-hallucinations.json');
  const popularPath = path.resolve(__dirname, '../../src/data/popular-packages.json');
  if (fs.existsSync(hallucinationsPath)) {
    const data = JSON.parse(fs.readFileSync(hallucinationsPath, 'utf-8'));
    KNOWN_NPM_HALLUCINATIONS = new Set((data.npm as string[]).map(n => n.toLowerCase()));
    KNOWN_PYPI_HALLUCINATIONS = new Set((data.pypi as string[]).map(n => n.toLowerCase()));
  } else {
    KNOWN_NPM_HALLUCINATIONS = new Set();
    KNOWN_PYPI_HALLUCINATIONS = new Set();
  }
  if (fs.existsSync(popularPath)) {
    const data = JSON.parse(fs.readFileSync(popularPath, 'utf-8'));
    POPULAR_NPM = data.npm;
    POPULAR_PYPI = data.pypi;
  } else {
    POPULAR_NPM = [];
    POPULAR_PYPI = [];
  }
} catch {
  KNOWN_NPM_HALLUCINATIONS = new Set();
  KNOWN_PYPI_HALLUCINATIONS = new Set();
  POPULAR_NPM = [];
  POPULAR_PYPI = [];
}

// ─── Secret Patterns ─────────────────────────────────────────────────

const SECRET_PATTERNS: Array<{ id: string; name: string; pattern: RegExp; severity: Severity }> = [
  { id: 'SEC_AWS_KEY', name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/, severity: 'critical' },
  { id: 'SEC_AWS_SECRET', name: 'AWS Secret Key', pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}/, severity: 'critical' },
  { id: 'SEC_GITHUB', name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/, severity: 'critical' },
  { id: 'SEC_STRIPE_SK', name: 'Stripe Secret Key', pattern: /sk_live_[A-Za-z0-9]{24,}/, severity: 'critical' },
  { id: 'SEC_STRIPE_PK', name: 'Stripe Publishable Key', pattern: /pk_live_[A-Za-z0-9]{24,}/, severity: 'medium' },
  { id: 'SEC_SLACK_TOKEN', name: 'Slack Token', pattern: /xox[bpors]-[A-Za-z0-9-]{10,}/, severity: 'high' },
  { id: 'SEC_PRIVATE_KEY', name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: 'critical' },
  { id: 'SEC_JWT', name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'high' },
  { id: 'SEC_GENERIC_SECRET', name: 'Generic Secret Assignment', pattern: /(?:secret|password|token|api_key|apikey)\s*[=:]\s*['"][A-Za-z0-9+/=]{16,}['"]/i, severity: 'high' },
  { id: 'SEC_DB_URL', name: 'Database Connection String', pattern: /(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/, severity: 'critical' },
];

// ─── SAST Patterns ───────────────────────────────────────────────────

const SAST_PATTERNS: Array<{ id: string; name: string; pattern: RegExp; severity: Severity; languages?: string[] }> = [
  { id: 'SAST_SQLI_001', name: 'SQL Injection (interpolation)', pattern: /(?:query|execute|exec)\s*\(\s*[`'"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`'"]*\$\{/i, severity: 'critical' },
  { id: 'SAST_SQLI_002', name: 'SQL Injection (concatenation)', pattern: /(?:query|execute|exec)\s*\(\s*['"`][^'"`]*['"`]\s*\+/i, severity: 'high' },
  { id: 'SAST_SQLI_003', name: 'SQL Injection (Python f-string)', pattern: /(?:execute|executemany)\s*\(\s*(?:f['"]|['"][^'"]*%\s*\()/i, severity: 'critical', languages: ['py'] },
  { id: 'SAST_XSS_001', name: 'XSS via innerHTML', pattern: /\.innerHTML\s*=/, severity: 'high', languages: ['js', 'ts', 'jsx', 'tsx'] },
  { id: 'SAST_XSS_002', name: 'XSS via document.write', pattern: /document\.write\s*\(/, severity: 'high', languages: ['js', 'ts'] },
  { id: 'SAST_EVAL_001', name: 'eval() usage', pattern: /\beval\s*\(/, severity: 'high' },
  { id: 'SAST_EXEC_001', name: 'Command injection risk', pattern: /(?:child_process|exec|spawn|execSync|spawnSync)\s*\(.*\$\{/i, severity: 'critical' },
  { id: 'SAST_PATH_001', name: 'Path traversal risk', pattern: /(?:readFile|writeFile|createReadStream|unlink|rmdir)\s*\([^)]*(?:req\.|params\.|query\.|body\.)/i, severity: 'high' },
  { id: 'SAST_CRYPTO_001', name: 'Weak hash (MD5/SHA1)', pattern: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/, severity: 'medium' },
  { id: 'SAST_CRYPTO_002', name: 'Hardcoded IV/Key', pattern: /(?:createCipheriv|createDecipheriv)\s*\([^)]*['"][0-9a-f]{16,}['"]/, severity: 'high' },
  { id: 'SAST_DESERIALIZE', name: 'Unsafe deserialization', pattern: /(?:pickle\.loads?|yaml\.load\s*\([^)]*(?!Loader))/, severity: 'critical', languages: ['py'] },
  { id: 'SAST_CORS', name: 'Wildcard CORS', pattern: /(?:Access-Control-Allow-Origin|cors)\s*[:(]\s*['"]?\*['"]?/, severity: 'medium' },
];

// ─── Import Parsers (standalone, no vscode) ──────────────────────────

interface ParsedImport {
  name: string;
  version: string | null;
  ecosystem: Ecosystem;
  line: number;
  file: string;
}

function parseJsImports(content: string, filePath: string): ParsedImport[] {
  const imports: ParsedImport[] = [];
  const lines = content.split('\n');
  const seen = new Set<string>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // ES import
    const esMatch = line.match(/import\s+.*\s+from\s+['"]([^'"./][^'"]*)['"]/);
    if (esMatch) {
      const pkg = extractPackageName(esMatch[1]);
      if (pkg && !seen.has(pkg)) {
        seen.add(pkg);
        imports.push({ name: pkg, version: null, ecosystem: 'npm', line: i + 1, file: filePath });
      }
      continue;
    }
    // require()
    const reqMatch = line.match(/require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/);
    if (reqMatch) {
      const pkg = extractPackageName(reqMatch[1]);
      if (pkg && !seen.has(pkg)) {
        seen.add(pkg);
        imports.push({ name: pkg, version: null, ecosystem: 'npm', line: i + 1, file: filePath });
      }
    }
  }
  return imports;
}

function parsePyImports(content: string, filePath: string): ParsedImport[] {
  const imports: ParsedImport[] = [];
  const lines = content.split('\n');
  const seen = new Set<string>();
  const PYTHON_STDLIB = new Set([
    'os', 'sys', 'json', 're', 'math', 'datetime', 'collections', 'itertools',
    'functools', 'pathlib', 'typing', 'io', 'subprocess', 'threading', 'multiprocessing',
    'socket', 'http', 'urllib', 'email', 'html', 'xml', 'logging', 'unittest',
    'hashlib', 'hmac', 'secrets', 'csv', 'sqlite3', 'pickle', 'copy', 'pprint',
    'abc', 'enum', 'dataclasses', 'contextlib', 'asyncio', 'concurrent', 'signal',
    'argparse', 'configparser', 'shutil', 'tempfile', 'glob', 'fnmatch', 'stat',
    'struct', 'codecs', 'unicodedata', 'textwrap', 'string', 'difflib',
    'time', 'calendar', 'random', 'statistics', 'decimal', 'fractions',
    'array', 'bisect', 'heapq', 'queue', 'types', 'weakref', 'inspect',
    'traceback', 'warnings', 'atexit', 'gc', 'dis', 'ast', 'compileall',
    'zipfile', 'tarfile', 'gzip', 'bz2', 'lzma', 'zlib',
  ]);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    // import X
    const importMatch = line.match(/^import\s+([a-zA-Z_][a-zA-Z0-9_]*)/);
    if (importMatch) {
      const pkg = importMatch[1].replace(/_/g, '-');
      if (!PYTHON_STDLIB.has(importMatch[1]) && !seen.has(pkg)) {
        seen.add(pkg);
        imports.push({ name: pkg, version: null, ecosystem: 'PyPI', line: i + 1, file: filePath });
      }
      continue;
    }
    // from X import Y
    const fromMatch = line.match(/^from\s+([a-zA-Z_][a-zA-Z0-9_]*)/);
    if (fromMatch) {
      const pkg = fromMatch[1].replace(/_/g, '-');
      if (!PYTHON_STDLIB.has(fromMatch[1]) && !seen.has(pkg)) {
        seen.add(pkg);
        imports.push({ name: pkg, version: null, ecosystem: 'PyPI', line: i + 1, file: filePath });
      }
    }
  }
  return imports;
}

function extractPackageName(raw: string): string | null {
  if (raw.startsWith('@')) {
    // Scoped: @scope/package/sub → @scope/package
    const parts = raw.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  }
  // Regular: package/sub → package
  return raw.split('/')[0] || null;
}

// ─── Package.json / requirements.txt parser ──────────────────────────

function parsePackageJson(projectPath: string): ParsedImport[] {
  const pkgPath = path.join(projectPath, 'package.json');
  if (!fs.existsSync(pkgPath)) { return []; }
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    const allDeps: Record<string, string> = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };
    return Object.entries(allDeps).map(([name, ver], i) => ({
      name,
      version: (ver as string).replace(/^[\^~>=<]*/, ''),
      ecosystem: 'npm' as Ecosystem,
      line: i + 1,
      file: 'package.json',
    }));
  } catch { return []; }
}

function parseRequirementsTxt(projectPath: string): ParsedImport[] {
  const reqPath = path.join(projectPath, 'requirements.txt');
  if (!fs.existsSync(reqPath)) { return []; }
  try {
    const content = fs.readFileSync(reqPath, 'utf-8');
    const imports: ParsedImport[] = [];
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#') || line.startsWith('-')) { continue; }
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*(?:[=<>~!]+\s*(.+))?/);
      if (match) {
        imports.push({
          name: match[1].replace(/_/g, '-'),
          version: match[2]?.split(',')[0]?.trim() ?? null,
          ecosystem: 'PyPI',
          line: i + 1,
          file: 'requirements.txt',
        });
      }
    }
    return imports;
  } catch { return []; }
}

// ─── Registry Existence Check ────────────────────────────────────────

function checkRegistryExists(packageName: string, ecosystem: Ecosystem): Promise<boolean> {
  return new Promise((resolve) => {
    let url: string;
    if (ecosystem === 'npm') {
      url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
    } else if (ecosystem === 'PyPI') {
      url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
    } else {
      resolve(true); // Assume exists for unsupported ecosystems
      return;
    }

    const urlObj = new URL(url);
    const req = https.request({
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'HEAD',
      timeout: 5000,
    }, (res) => {
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(true)); // Assume exists on error
    req.on('timeout', () => { req.destroy(); resolve(true); });
    req.end();
  });
}

// ─── OSV.dev Vulnerability API ───────────────────────────────────────

interface OsvVulnerability {
  id: string;
  summary: string;
  severity: Severity;
  aliases: string[];
  fixedVersion: string | null;
}

/**
 * Map OSV ecosystem name to our Ecosystem type.
 */
function osvEcosystem(eco: Ecosystem): string {
  switch (eco) {
    case 'npm': return 'npm';
    case 'PyPI': return 'PyPI';
    case 'Go': return 'Go';
    case 'Maven': return 'Maven';
    case 'crates.io': return 'crates.io';
    default: return eco;
  }
}

/**
 * Map CVSS score or OSV severity string to our Severity type.
 */
function mapOsvSeverity(vuln: any): Severity {
  // Try database_specific severity first
  const dbSev = vuln.database_specific?.severity?.toLowerCase();
  if (dbSev === 'critical') { return 'critical'; }
  if (dbSev === 'high') { return 'high'; }
  if (dbSev === 'moderate' || dbSev === 'medium') { return 'medium'; }
  if (dbSev === 'low') { return 'low'; }

  // Try CVSS from severity array
  if (vuln.severity && Array.isArray(vuln.severity)) {
    for (const s of vuln.severity) {
      if (s.score) {
        const score = parseFloat(s.score);
        if (score >= 9.0) { return 'critical'; }
        if (score >= 7.0) { return 'high'; }
        if (score >= 4.0) { return 'medium'; }
        return 'low';
      }
    }
  }

  return 'medium'; // Default if unknown
}

/**
 * Query OSV.dev API for vulnerabilities affecting a specific package+version.
 * Uses the batch query endpoint for efficiency.
 */
function queryOsv(packageName: string, version: string, ecosystem: Ecosystem): Promise<OsvVulnerability[]> {
  return new Promise((resolve) => {
    const payload = JSON.stringify({
      package: {
        name: packageName,
        ecosystem: osvEcosystem(ecosystem),
      },
      version: version || undefined,
    });

    const req = https.request({
      hostname: 'api.osv.dev',
      path: '/v1/query',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 8000,
    }, (res) => {
      let body = '';
      res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          if (!data.vulns || !Array.isArray(data.vulns)) {
            resolve([]);
            return;
          }
          const results: OsvVulnerability[] = data.vulns.map((v: any) => {
            // Extract fix version from affected ranges
            let fixedVersion: string | null = null;
            if (v.affected) {
              for (const aff of v.affected) {
                if (aff.ranges) {
                  for (const range of aff.ranges) {
                    if (range.events) {
                      for (const ev of range.events) {
                        if (ev.fixed) { fixedVersion = ev.fixed; }
                      }
                    }
                  }
                }
              }
            }

            return {
              id: v.id,
              summary: v.summary || v.details?.substring(0, 120) || 'No description available',
              severity: mapOsvSeverity(v),
              aliases: v.aliases || [],
              fixedVersion,
            };
          });
          resolve(results);
        } catch {
          resolve([]);
        }
      });
    });

    req.on('error', () => resolve([]));
    req.on('timeout', () => { req.destroy(); resolve([]); });
    req.write(payload);
    req.end();
  });
}

// ─── Levenshtein (for typosquat detection) ───────────────────────────

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) { dp[i][0] = i; }
  for (let j = 0; j <= n; j++) { dp[0][j] = j; }
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

function findTyposquat(name: string, ecosystem: Ecosystem): string | null {
  const popular = ecosystem === 'npm' ? POPULAR_NPM : ecosystem === 'PyPI' ? POPULAR_PYPI : [];
  const lower = name.toLowerCase();
  if (popular.includes(lower)) { return null; } // Exact match — not a typo
  let best: string | null = null;
  let bestDist = Infinity;
  for (const p of popular) {
    const d = levenshtein(lower, p.toLowerCase());
    if (d > 0 && d <= 2 && d < bestDist) {
      bestDist = d;
      best = p;
    }
  }
  return best;
}

// ─── Main Scanner ────────────────────────────────────────────────────

export class CoreScanner {
  private options: ScanOptions;

  constructor(options: ScanOptions) {
    this.options = {
      hallucination: true,
      vulnerabilities: true,
      secrets: true,
      sast: true,
      policy: true,
      severityThreshold: 'low',
      ignoredPackages: [],
      privateRegistries: [],
      ...options,
    };
  }

  /**
   * Run a full scan on the project.
   */
  async scan(): Promise<ScanResult> {
    const findings: ScanFinding[] = [];
    const packages: PackageInfo[] = [];
    let scannedFiles = 0;

    const projectPath = this.options.projectPath;

    // 1. Collect all imports from manifest files
    const manifestImports = [
      ...parsePackageJson(projectPath),
      ...parseRequirementsTxt(projectPath),
    ];

    // 2. Collect imports from source files
    const sourceImports = this.scanSourceFiles(projectPath);
    scannedFiles = sourceImports.scannedFiles;

    // 3. Merge all imports (deduplicate)
    const allImports = [...manifestImports, ...sourceImports.imports];
    const uniqueImports = new Map<string, ParsedImport>();
    for (const imp of allImports) {
      if (!uniqueImports.has(imp.name)) {
        uniqueImports.set(imp.name, imp);
      }
    }

    // 4. Filter ignored and private packages
    const ignored = new Set(this.options.ignoredPackages?.map(p => p.toLowerCase()) ?? []);
    const privateScopes = this.options.privateRegistries ?? [];

    // 5. Check each package for hallucination (or just build package list)
    if (this.options.hallucination) {
      const checkPromises: Promise<void>[] = [];
      for (const [name, imp] of uniqueImports) {
        if (ignored.has(name.toLowerCase())) { continue; }
        if (privateScopes.some(scope => name.startsWith(scope))) { continue; }

        checkPromises.push(
          this.checkPackage(name, imp).then(({ pkgInfo, pkgFindings }) => {
            packages.push(pkgInfo);
            findings.push(...pkgFindings);
          })
        );
      }
      // Run with concurrency limit of 5
      const chunks = this.chunk(checkPromises, 5);
      for (const batch of chunks) {
        await Promise.all(batch);
      }
    } else {
      // Still populate package list for vulnerability + policy checks
      for (const [name, imp] of uniqueImports) {
        if (ignored.has(name.toLowerCase())) { continue; }
        if (privateScopes.some(scope => name.startsWith(scope))) { continue; }
        packages.push({
          name,
          version: imp.version,
          ecosystem: imp.ecosystem,
          exists: true,
          isHallucination: false,
          vulnerabilities: [],
        });
      }
    }

    // 6. Vulnerability scanning via OSV.dev
    if (this.options.vulnerabilities) {
      const vulnPromises: Promise<void>[] = [];
      for (const pkg of packages) {
        if (!pkg.exists || pkg.isHallucination) { continue; }
        if (!pkg.version) { continue; } // Need a version to check vulns

        vulnPromises.push(
          queryOsv(pkg.name, pkg.version, pkg.ecosystem).then((vulns) => {
            for (const v of vulns) {
              const cveAlias = v.aliases.find(a => a.startsWith('CVE-'));
              pkg.vulnerabilities.push(v.id);
              // Find the original import for file/line info
              const imp = uniqueImports.get(pkg.name);
              findings.push({
                id: v.id,
                type: 'vulnerability',
                severity: v.severity,
                message: `${pkg.name}@${pkg.version}: ${v.summary}${cveAlias ? ` (${cveAlias})` : ''}`,
                file: imp?.file ?? 'package.json',
                line: imp?.line ?? 1,
                column: 0,
                packageName: pkg.name,
                cveId: cveAlias ?? v.id,
                fix: v.fixedVersion ? `Upgrade to ${pkg.name}@${v.fixedVersion}` : 'No fix available yet.',
              });
            }
          }).catch(() => { /* Silent fail on network issues */ })
        );
      }
      const vulnChunks = this.chunk(vulnPromises, 5);
      for (const batch of vulnChunks) {
        await Promise.all(batch);
      }
    }

    // 7. Scan for secrets
    if (this.options.secrets) {
      findings.push(...sourceImports.secretFindings);
    }

    // 8. Scan for SAST patterns
    if (this.options.sast) {
      findings.push(...sourceImports.sastFindings);
    }

    // 8.5. MCP Server Config scanning
    if (this.options.mcp !== false) {
      findings.push(...this.scanMcpConfigs(projectPath));
    }

    // 9. Policy evaluation
    if (this.options.policy) {
      findings.push(...this.evaluatePolicy(projectPath, packages, sourceImports.scannedFiles, findings));
    }

    // 10. Filter by severity threshold
    const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const thresholdIdx = severityOrder.indexOf(this.options.severityThreshold ?? 'low');
    const filtered = findings.filter(f => severityOrder.indexOf(f.severity) <= thresholdIdx);

    // 10. Compute summary
    const summary: ScanSummary = {
      totalFindings: filtered.length,
      critical: filtered.filter(f => f.severity === 'critical').length,
      high: filtered.filter(f => f.severity === 'high').length,
      medium: filtered.filter(f => f.severity === 'medium').length,
      low: filtered.filter(f => f.severity === 'low').length,
      info: filtered.filter(f => f.severity === 'info').length,
      hallucinatedPackages: filtered.filter(f => f.type === 'hallucination').length,
      vulnerablePackages: filtered.filter(f => f.type === 'vulnerability').length,
      secretsFound: filtered.filter(f => f.type === 'secret').length,
      sastFindings: filtered.filter(f => f.type === 'sast').length,
      policyViolations: filtered.filter(f => f.type === 'policy').length,
      mcpIssues: filtered.filter(f => f.type === 'mcp').length,
      scannedFiles,
    };

    return {
      projectPath,
      timestamp: new Date().toISOString(),
      findings: filtered,
      summary,
      packages,
    };
  }

  /**
   * Check a single package for hallucination and typosquatting.
   */
  private async checkPackage(
    name: string,
    imp: ParsedImport
  ): Promise<{ pkgInfo: PackageInfo; pkgFindings: ScanFinding[] }> {
    const pkgFindings: ScanFinding[] = [];
    let exists = true;
    let isHallucination = false;

    // Check known hallucination DB first (instant, no network)
    const knownDb = imp.ecosystem === 'npm' ? KNOWN_NPM_HALLUCINATIONS
      : imp.ecosystem === 'PyPI' ? KNOWN_PYPI_HALLUCINATIONS
      : null;

    if (knownDb?.has(name.toLowerCase())) {
      isHallucination = true;
      exists = false;
      pkgFindings.push({
        id: `HALL_KNOWN_${name}`,
        type: 'hallucination',
        severity: 'critical',
        message: `"${name}" is a KNOWN AI-hallucinated package (in CodeGuard seed DB). It does not exist on ${imp.ecosystem}.`,
        file: imp.file,
        line: imp.line,
        column: 0,
        packageName: name,
        fix: 'Remove this import. The AI assistant invented this package name.',
      });
    } else {
      // Network check for existence
      try {
        exists = await checkRegistryExists(name, imp.ecosystem);
      } catch {
        exists = true; // Assume exists if network fails
      }

      if (!exists) {
        isHallucination = true;
        const typo = findTyposquat(name, imp.ecosystem);
        pkgFindings.push({
          id: `HALL_${name}`,
          type: 'hallucination',
          severity: 'critical',
          message: typo
            ? `"${name}" does not exist on ${imp.ecosystem}. Did you mean "${typo}"?`
            : `"${name}" does not exist on ${imp.ecosystem}. Likely an AI hallucination.`,
          file: imp.file,
          line: imp.line,
          column: 0,
          packageName: name,
          fix: typo ? `Replace with "${typo}"` : 'Remove this import or find the correct package name.',
        });
      }
    }

    return {
      pkgInfo: {
        name,
        version: imp.version,
        ecosystem: imp.ecosystem,
        exists,
        isHallucination,
        vulnerabilities: [],
      },
      pkgFindings,
    };
  }

  /**
   * Scan all source files in the project for imports, secrets, and SAST patterns.
   */
  private scanSourceFiles(projectPath: string): {
    imports: ParsedImport[];
    secretFindings: ScanFinding[];
    sastFindings: ScanFinding[];
    scannedFiles: number;
  } {
    const imports: ParsedImport[] = [];
    const secretFindings: ScanFinding[] = [];
    const sastFindings: ScanFinding[] = [];
    let scannedFiles = 0;

    const SCAN_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.py', '.mjs', '.cjs']);
    const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'out', 'build', '__pycache__', '.venv', 'venv', '.codeguard']);

    const walk = (dir: string): void => {
      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory()) {
            if (!IGNORE_DIRS.has(entry.name)) {
              walk(path.join(dir, entry.name));
            }
          } else if (entry.isFile()) {
            const ext = path.extname(entry.name).toLowerCase();
            if (SCAN_EXTENSIONS.has(ext)) {
              const filePath = path.join(dir, entry.name);
              const relPath = path.relative(projectPath, filePath);
              try {
                const content = fs.readFileSync(filePath, 'utf-8');
                scannedFiles++;

                // Parse imports
                if (['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'].includes(ext)) {
                  imports.push(...parseJsImports(content, relPath));
                } else if (ext === '.py') {
                  imports.push(...parsePyImports(content, relPath));
                }

                // Scan for secrets
                const lines = content.split('\n');
                for (let i = 0; i < lines.length; i++) {
                  const line = lines[i];
                  for (const sp of SECRET_PATTERNS) {
                    if (sp.pattern.test(line)) {
                      secretFindings.push({
                        id: sp.id,
                        type: 'secret',
                        severity: sp.severity,
                        message: `${sp.name} detected`,
                        file: relPath,
                        line: i + 1,
                        column: 0,
                        ruleId: sp.id,
                        fix: 'Move to environment variables or a secrets manager.',
                      });
                    }
                  }

                  // Scan for SAST patterns
                  for (const sast of SAST_PATTERNS) {
                    if (sast.languages) {
                      const fileExt = ext.replace('.', '');
                      if (!sast.languages.includes(fileExt)) { continue; }
                    }
                    if (sast.pattern.test(line)) {
                      sastFindings.push({
                        id: sast.id,
                        type: 'sast',
                        severity: sast.severity,
                        message: sast.name,
                        file: relPath,
                        line: i + 1,
                        column: 0,
                        ruleId: sast.id,
                      });
                    }
                  }
                }
              } catch {
                // Skip unreadable files
              }
            }
          }
        }
      } catch {
        // Skip unreadable directories
      }
    };

    walk(projectPath);

    return { imports, secretFindings, sastFindings, scannedFiles };
  }

  /**
   * Evaluate .codeguard/policy.json rules against scan results.
   * Supports: forbidden packages, max vulnerability severity, secrets scanner requirement.
   */
  private evaluatePolicy(
    projectPath: string,
    packages: PackageInfo[],
    _scannedFiles: number,
    currentFindings: ScanFinding[]
  ): ScanFinding[] {
    const policyFindings: ScanFinding[] = [];
    const policyPath = path.join(projectPath, '.codeguard', 'policy.json');

    if (!fs.existsSync(policyPath)) { return []; }

    let policy: any;
    try {
      policy = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
    } catch {
      policyFindings.push({
        id: 'POLICY_PARSE_ERROR',
        type: 'policy',
        severity: 'high',
        message: 'Failed to parse .codeguard/policy.json — policy evaluation skipped.',
        file: '.codeguard/policy.json',
        line: 1,
        column: 0,
      });
      return policyFindings;
    }

    const rules = policy.rules ?? policy;

    // Rule: forbidden packages
    if (rules.forbiddenPackages && Array.isArray(rules.forbiddenPackages)) {
      const forbidden = new Set((rules.forbiddenPackages as string[]).map(p => p.toLowerCase()));
      for (const pkg of packages) {
        if (forbidden.has(pkg.name.toLowerCase())) {
          policyFindings.push({
            id: `POLICY_FORBIDDEN_${pkg.name}`,
            type: 'policy',
            severity: 'high',
            message: `"${pkg.name}" is forbidden by project policy (.codeguard/policy.json).`,
            file: 'package.json',
            line: 1,
            column: 0,
            packageName: pkg.name,
            fix: `Remove "${pkg.name}" or update the policy file.`,
          });
        }
      }
    }

    // Rule: max vulnerability severity
    if (rules.maxVulnerabilitySeverity) {
      const maxSev = rules.maxVulnerabilitySeverity.toLowerCase();
      const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      const maxLevel = sevOrder[maxSev] ?? 2;

      const vulnFindings = currentFindings.filter(f => f.type === 'vulnerability');
      for (const f of vulnFindings) {
        const fLevel = sevOrder[f.severity] ?? 0;
        if (fLevel > maxLevel) {
          policyFindings.push({
            id: `POLICY_VULN_SEV_${f.id}`,
            type: 'policy',
            severity: 'high',
            message: `Vulnerability ${f.id} (${f.severity}) exceeds policy max severity "${maxSev}".`,
            file: f.file,
            line: f.line,
            column: 0,
            packageName: f.packageName,
          });
        }
      }
    }

    // Rule: require secrets scanner (check if secrets were found)
    if (rules.requireScanners && Array.isArray(rules.requireScanners)) {
      if (rules.requireScanners.includes('secrets') && !this.options.secrets) {
        policyFindings.push({
          id: 'POLICY_SCANNER_SECRETS',
          type: 'policy',
          severity: 'medium',
          message: 'Policy requires secrets scanner, but it was disabled (--no-secrets).',
          file: '.codeguard/policy.json',
          line: 1,
          column: 0,
        });
      }
      if (rules.requireScanners.includes('sast') && !this.options.sast) {
        policyFindings.push({
          id: 'POLICY_SCANNER_SAST',
          type: 'policy',
          severity: 'medium',
          message: 'Policy requires SAST scanner, but it was disabled (--no-sast).',
          file: '.codeguard/policy.json',
          line: 1,
          column: 0,
        });
      }
    }

    // Rule: no hallucinated packages allowed
    if (rules.blockHallucinations !== false) {
      const hallFindings = currentFindings.filter(f => f.type === 'hallucination');
      if (hallFindings.length > 0) {
        policyFindings.push({
          id: 'POLICY_HALLUCINATION_BLOCK',
          type: 'policy',
          severity: 'high',
          message: `${hallFindings.length} hallucinated package(s) detected — policy blocks hallucinated dependencies.`,
          file: '.codeguard/policy.json',
          line: 1,
          column: 0,
        });
      }
    }

    return policyFindings;
  }

  /**
   * Scan MCP server configurations for security issues.
   */
  private scanMcpConfigs(projectPath: string): ScanFinding[] {
    const mcpFindings: ScanFinding[] = [];
    const mcpFiles = [
      '.vscode/mcp.json',
      '.cursor/mcp.json',
      'mcp.json',
      '.mcp.json',
      'claude_desktop_config.json',
      'cline_mcp_settings.json',
    ];

    for (const relFile of mcpFiles) {
      const fullPath = path.join(projectPath, relFile);
      if (!fs.existsSync(fullPath)) { continue; }

      let json: any;
      try {
        json = JSON.parse(fs.readFileSync(fullPath, 'utf-8'));
      } catch { continue; }

      // Extract servers from various formats
      const serversObj = json.mcpServers ?? json.servers ?? json.mcp?.servers;
      if (!serversObj || typeof serversObj !== 'object') { continue; }

      for (const [name, config] of Object.entries(serversObj)) {
        if (typeof config !== 'object' || config === null) { continue; }
        const cfg = config as any;
        const fullCmd = [cfg.command ?? '', ...(cfg.args ?? [])].join(' ');

        // Check for npx/bunx rug-pull risk
        if (/\bnpx\b/.test(fullCmd)) {
          mcpFindings.push({
            id: `MCP_RUGPULL_${name}`,
            type: 'mcp',
            severity: 'high',
            message: `MCP server "${name}" uses npx (downloads latest at runtime — rug-pull risk). Pin the version or use a local server.`,
            file: relFile,
            line: 1,
            column: 0,
            fix: 'Replace npx with a locally installed package or pin to a specific version.',
          });
        }

        // Check for pipe-to-shell
        if (/\bcurl\b.*\|.*\b(?:sh|bash|zsh)\b/.test(fullCmd) || /\bwget\b.*-O\s*-\s*\|/.test(fullCmd)) {
          mcpFindings.push({
            id: `MCP_PIPESHELL_${name}`,
            type: 'mcp',
            severity: 'critical',
            message: `MCP server "${name}" pipes downloaded content to shell — critical code execution risk.`,
            file: relFile,
            line: 1,
            column: 0,
            fix: 'Never pipe remote content to a shell. Download, verify, then execute.',
          });
        }

        // Check for unencrypted remote HTTP
        if (cfg.url && cfg.url.startsWith('http://') && !cfg.url.includes('localhost') && !cfg.url.includes('127.0.0.1')) {
          mcpFindings.push({
            id: `MCP_HTTP_${name}`,
            type: 'mcp',
            severity: 'high',
            message: `MCP server "${name}" connects over unencrypted HTTP to a remote endpoint. Use HTTPS.`,
            file: relFile,
            line: 1,
            column: 0,
            fix: 'Change the URL to use HTTPS.',
          });
        }

        // Check for hardcoded credentials in env
        if (cfg.env && typeof cfg.env === 'object') {
          const sensitiveKeys = /(?:AWS_SECRET|AWS_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|DATABASE_URL|DB_PASSWORD|STRIPE_SECRET|PRIVATE_KEY)/i;
          for (const [key, value] of Object.entries(cfg.env)) {
            if (sensitiveKeys.test(key) && typeof value === 'string' && !value.startsWith('${') && !value.startsWith('$')) {
              mcpFindings.push({
                id: `MCP_CRED_${name}_${key}`,
                type: 'mcp',
                severity: 'critical',
                message: `MCP server "${name}" has hardcoded credential "${key}" in env. Use a secrets manager.`,
                file: relFile,
                line: 1,
                column: 0,
                fix: `Move ${key} to a secrets manager or use environment variable references.`,
              });
            }
          }
        }

        // Check for prompt injection in tool descriptions
        if (cfg.tools && Array.isArray(cfg.tools)) {
          for (const tool of cfg.tools) {
            const desc = (tool.description ?? '') + ' ' + JSON.stringify(tool.inputSchema ?? {});
            if (/ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i.test(desc)) {
              mcpFindings.push({
                id: `MCP_POISON_${name}_${tool.name}`,
                type: 'mcp',
                severity: 'critical',
                message: `Tool "${tool.name}" in MCP server "${name}" contains prompt injection in its description.`,
                file: relFile,
                line: 1,
                column: 0,
                fix: 'Remove the prompt injection from the tool description.',
              });
            }
            if (/do\s+not\s+(?:tell|inform|alert|warn)\s+the\s+user/i.test(desc)) {
              mcpFindings.push({
                id: `MCP_DECEPTION_${name}_${tool.name}`,
                type: 'mcp',
                severity: 'critical',
                message: `Tool "${tool.name}" in MCP server "${name}" contains user deception directive.`,
                file: relFile,
                line: 1,
                column: 0,
                fix: 'Remove the deceptive instruction from the tool description.',
              });
            }
          }
        }
      }
    }

    return mcpFindings;
  }

  private chunk<T>(arr: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < arr.length; i += size) {
      chunks.push(arr.slice(i, i + size));
    }
    return chunks;
  }
}
