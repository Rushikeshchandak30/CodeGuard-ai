/**
 * Auto-Patch Engine
 *
 * Aggregates patch/fix information from multiple open-source databases:
 * - OSV.dev (primary — covers npm, PyPI, Go, crates, Maven, etc.)
 * - GitHub Advisory Database (GHSA)
 * - npm audit / PyPI Advisory
 *
 * For every vulnerability found, provides:
 * - Exact safe version to upgrade to
 * - Alternative packages if the original is deprecated/abandoned
 * - One-click patch commands (npm install pkg@safe, pip install pkg>=safe)
 * - Markdown-formatted fix description for AI assistants
 */

import * as https from 'https';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PatchSuggestion {
  packageName: string;
  ecosystem: string;
  currentVersion: string | null;
  vulnerabilityId: string;
  severity: string;
  /** The minimum safe version that fixes this CVE */
  safeVersion: string | null;
  /** The latest available version */
  latestVersion: string | null;
  /** One-liner patch command */
  patchCommand: string | null;
  /** If deprecated, alternative packages */
  alternatives: string[];
  /** Human + AI readable fix description */
  fixDescription: string;
  /** URL to the advisory */
  advisoryUrl: string;
  /** CVSS score */
  cvssScore: number | null;
  /** Affected version range expression */
  affectedRange: string | null;
}

export interface PatchReport {
  packageName: string;
  ecosystem: string;
  currentVersion: string | null;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  patches: PatchSuggestion[];
  /** Best single action to take */
  recommendedAction: string;
  /** Is the package deprecated? */
  deprecated: boolean;
  /** Deprecation message from registry */
  deprecationMessage: string | null;
}

// ---------------------------------------------------------------------------
// Well-known alternatives for deprecated/abandoned packages
// ---------------------------------------------------------------------------

const KNOWN_ALTERNATIVES: Record<string, string[]> = {
  // npm
  'request': ['axios', 'node-fetch', 'got', 'undici'],
  'node-uuid': ['uuid'],
  'querystring': ['qs', 'URLSearchParams (built-in)'],
  'colors': ['chalk', 'picocolors', 'kleur'],
  'moment': ['dayjs', 'date-fns', 'luxon'],
  'underscore': ['lodash', 'ramda'],
  'bower': ['npm', 'pnpm', 'yarn'],
  'left-pad': ['String.prototype.padStart (built-in)'],
  'nomnom': ['commander', 'yargs', 'meow'],
  'optimist': ['yargs', 'minimist', 'commander'],
  'mkdirp': ['fs.mkdirSync with recursive option (built-in Node 10+)'],
  'rimraf': ['fs.rmSync with recursive option (built-in Node 14+)'],
  'node-sass': ['sass (dart-sass)'],
  'tslint': ['eslint with @typescript-eslint'],
  'istanbul': ['nyc', 'c8'],
  'jade': ['pug'],
  'coffee-script': ['TypeScript', 'plain JavaScript'],

  // PyPI
  'pycrypto': ['pycryptodome', 'cryptography'],
  'optparse': ['argparse (stdlib)', 'click', 'typer'],
  'BeautifulSoup': ['beautifulsoup4'],
  'distribute': ['setuptools'],
  'PIL': ['Pillow'],
  'pydns': ['dnspython'],
  'mysql-python': ['mysqlclient', 'PyMySQL'],
  'nose': ['pytest'],
  'fabric': ['fabric2', 'invoke'],
};

// ---------------------------------------------------------------------------
// AutoPatchEngine
// ---------------------------------------------------------------------------

export class AutoPatchEngine {
  private cache: Map<string, PatchReport> = new Map();
  private readonly CACHE_TTL = 15 * 60 * 1000; // 15 minutes
  private cacheTimestamps: Map<string, number> = new Map();

  /**
   * Get a complete patch report for a package, aggregating from all sources.
   */
  async getPatchReport(
    packageName: string,
    currentVersion: string | null,
    ecosystem: string,
  ): Promise<PatchReport> {
    const cacheKey = `${ecosystem}:${packageName}@${currentVersion ?? 'unknown'}`;
    const cached = this.cache.get(cacheKey);
    const cachedTime = this.cacheTimestamps.get(cacheKey);
    if (cached && cachedTime && Date.now() - cachedTime < this.CACHE_TTL) {
      return cached;
    }

    // Fetch vulnerability data from OSV.dev
    const osvVulns = await this.fetchOsvVulnerabilities(packageName, currentVersion, ecosystem);

    // Fetch deprecation info
    const deprecation = await this.checkDeprecation(packageName, ecosystem);

    // Fetch latest version
    const latestVersion = await this.fetchLatestVersion(packageName, ecosystem);

    // Build patch suggestions
    const patches: PatchSuggestion[] = [];
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const vuln of osvVulns) {
      const severity = vuln.severity?.toUpperCase() ?? 'UNKNOWN';
      switch (severity) {
        case 'CRITICAL': criticalCount++; break;
        case 'HIGH': highCount++; break;
        case 'MEDIUM': mediumCount++; break;
        case 'LOW': lowCount++; break;
      }

      const safeVersion = vuln.fixedVersion;
      const alternatives = KNOWN_ALTERNATIVES[packageName] ?? [];

      patches.push({
        packageName,
        ecosystem,
        currentVersion,
        vulnerabilityId: vuln.id,
        severity,
        safeVersion,
        latestVersion,
        patchCommand: this.buildPatchCommand(packageName, safeVersion ?? latestVersion, ecosystem),
        alternatives: deprecation.deprecated ? alternatives : [],
        fixDescription: this.buildFixDescription(packageName, currentVersion, vuln, safeVersion, latestVersion, deprecation, alternatives),
        advisoryUrl: vuln.referenceUrl ?? `https://osv.dev/vulnerability/${vuln.id}`,
        cvssScore: vuln.cvssScore,
        affectedRange: vuln.affectedVersions,
      });
    }

    // Determine best recommended action
    let recommendedAction: string;
    if (deprecation.deprecated && KNOWN_ALTERNATIVES[packageName]) {
      recommendedAction = `Replace ${packageName} with ${KNOWN_ALTERNATIVES[packageName][0]} (deprecated)`;
    } else if (patches.length > 0) {
      const bestSafe = this.findBestSafeVersion(patches);
      if (bestSafe) {
        recommendedAction = `Update to ${packageName}@${bestSafe}`;
      } else if (latestVersion) {
        recommendedAction = `Update to ${packageName}@${latestVersion} (latest)`;
      } else {
        recommendedAction = `Review vulnerabilities and update ${packageName}`;
      }
    } else {
      recommendedAction = deprecation.deprecated
        ? `Consider replacing deprecated package ${packageName}`
        : 'No action needed — no known vulnerabilities';
    }

    const report: PatchReport = {
      packageName,
      ecosystem,
      currentVersion,
      totalVulnerabilities: osvVulns.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      patches,
      recommendedAction,
      deprecated: deprecation.deprecated,
      deprecationMessage: deprecation.message,
    };

    this.cache.set(cacheKey, report);
    this.cacheTimestamps.set(cacheKey, Date.now());

    return report;
  }

  /**
   * Get a one-liner patch command for a package.
   */
  buildPatchCommand(packageName: string, targetVersion: string | null, ecosystem: string): string | null {
    if (!targetVersion) { return null; }

    switch (ecosystem.toLowerCase()) {
      case 'npm':
        return `npm install ${packageName}@${targetVersion}`;
      case 'pypi':
        return `pip install "${packageName}>=${targetVersion}"`;
      case 'go':
        return `go get ${packageName}@v${targetVersion}`;
      case 'crates.io':
        return `cargo update -p ${packageName} --precise ${targetVersion}`;
      case 'maven':
        return `Update ${packageName} version to ${targetVersion} in pom.xml`;
      default:
        return `Update ${packageName} to version ${targetVersion}`;
    }
  }

  /**
   * Build a markdown fix description suitable for both humans and AI assistants.
   */
  buildFixDescription(
    packageName: string,
    currentVersion: string | null,
    vuln: OsvVulnSummary,
    safeVersion: string | null,
    latestVersion: string | null,
    deprecation: { deprecated: boolean; message: string | null },
    alternatives: string[],
  ): string {
    const parts: string[] = [];

    parts.push(`**${vuln.id}** — ${vuln.summary} (${vuln.severity ?? 'Unknown'} severity)`);

    if (vuln.cvssScore) {
      parts.push(`CVSS: ${vuln.cvssScore}/10`);
    }

    if (currentVersion) {
      parts.push(`Current: \`${packageName}@${currentVersion}\` (affected: ${vuln.affectedVersions ?? 'unknown range'})`);
    }

    if (safeVersion) {
      parts.push(`**Fix:** Update to \`${packageName}@${safeVersion}\` or later`);
    } else if (latestVersion) {
      parts.push(`**Fix:** Update to latest \`${packageName}@${latestVersion}\``);
    }

    if (deprecation.deprecated) {
      parts.push(`**Warning:** This package is deprecated. ${deprecation.message ?? ''}`);
      if (alternatives.length > 0) {
        parts.push(`**Alternatives:** ${alternatives.join(', ')}`);
      }
    }

    parts.push(`Advisory: ${vuln.referenceUrl ?? `https://osv.dev/vulnerability/${vuln.id}`}`);

    return parts.join('\n');
  }

  /**
   * Format a full patch report as markdown (for Chat Participant / AI context).
   */
  formatReportAsMarkdown(report: PatchReport): string {
    const lines: string[] = [];

    lines.push(`## Security Report: ${report.packageName}`);
    lines.push('');

    if (report.deprecated) {
      lines.push(`> ⚠️ **DEPRECATED:** ${report.deprecationMessage ?? 'This package is no longer maintained.'}`);
      lines.push('');
    }

    if (report.totalVulnerabilities === 0) {
      lines.push('✅ No known vulnerabilities.');
    } else {
      lines.push(`Found **${report.totalVulnerabilities}** vulnerabilities:`);
      if (report.criticalCount > 0) { lines.push(`- 🔴 ${report.criticalCount} CRITICAL`); }
      if (report.highCount > 0) { lines.push(`- 🟠 ${report.highCount} HIGH`); }
      if (report.mediumCount > 0) { lines.push(`- 🟡 ${report.mediumCount} MEDIUM`); }
      if (report.lowCount > 0) { lines.push(`- ⚪ ${report.lowCount} LOW`); }
    }

    lines.push('');
    lines.push(`**Recommended Action:** ${report.recommendedAction}`);
    lines.push('');

    for (const patch of report.patches) {
      lines.push(`### ${patch.vulnerabilityId}`);
      lines.push(patch.fixDescription);
      if (patch.patchCommand) {
        lines.push(`\`\`\`bash\n${patch.patchCommand}\n\`\`\``);
      }
      lines.push('');
    }

    return lines.join('\n');
  }

  // -------------------------------------------------------------------------
  // Data sources
  // -------------------------------------------------------------------------

  /**
   * Fetch vulnerabilities from OSV.dev (covers all ecosystems).
   */
  private fetchOsvVulnerabilities(
    packageName: string,
    version: string | null,
    ecosystem: string,
  ): Promise<OsvVulnSummary[]> {
    return new Promise((resolve) => {
      const osvEcosystem = this.mapToOsvEcosystem(ecosystem);

      const payload: Record<string, unknown> = {
        package: { name: packageName, ecosystem: osvEcosystem },
      };
      if (version) {
        payload.version = version;
      }

      const body = JSON.stringify(payload);

      const options = {
        hostname: 'api.osv.dev',
        path: '/v1/query',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
        res.on('end', () => {
          try {
            const json = JSON.parse(data);
            const vulns: OsvVulnSummary[] = (json.vulns ?? []).map((v: Record<string, unknown>) => this.parseOsvVuln(v, packageName, osvEcosystem));
            resolve(vulns);
          } catch {
            resolve([]);
          }
        });
      });

      req.on('error', () => resolve([]));
      req.setTimeout(10000, () => { req.destroy(); resolve([]); });
      req.write(body);
      req.end();
    });
  }

  /**
   * Fetch vulnerabilities from GitHub Advisory Database (GHSA).
   * Uses the public GraphQL-free endpoint.
   */
  async fetchGitHubAdvisories(packageName: string, ecosystem: string): Promise<OsvVulnSummary[]> {
    // GitHub Advisory is already included in OSV.dev results (GHSA IDs), so this
    // serves as an enrichment layer for additional detail.
    return new Promise((resolve) => {
      const ghEcosystem = ecosystem.toLowerCase() === 'npm' ? 'npm'
        : ecosystem.toLowerCase() === 'pypi' ? 'pip'
          : ecosystem.toLowerCase();

      const url = `https://api.github.com/advisories?ecosystem=${encodeURIComponent(ghEcosystem)}&package=${encodeURIComponent(packageName)}&per_page=10`;

      const req = https.get(url, {
        headers: {
          'Accept': 'application/vnd.github+json',
          'User-Agent': 'CodeGuard-AI/0.3.0',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      }, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          try {
            if (res.statusCode !== 200) { resolve([]); return; }
            const advisories = JSON.parse(body);
            if (!Array.isArray(advisories)) { resolve([]); return; }

            const vulns: OsvVulnSummary[] = advisories.map((adv: Record<string, unknown>) => ({
              id: (adv.ghsa_id as string) ?? (adv.cve_id as string) ?? 'unknown',
              summary: (adv.summary as string) ?? '',
              severity: ((adv.severity as string) ?? 'UNKNOWN').toUpperCase(),
              cvssScore: (adv.cvss as { score?: number })?.score ?? null,
              affectedVersions: this.extractGhsaAffectedRange(adv, packageName),
              fixedVersion: this.extractGhsaFixedVersion(adv, packageName),
              referenceUrl: (adv.html_url as string) ?? null,
            }));

            resolve(vulns);
          } catch {
            resolve([]);
          }
        });
      });

      req.on('error', () => resolve([]));
      req.setTimeout(8000, () => { req.destroy(); resolve([]); });
      req.end();
    });
  }

  /**
   * Check if a package is deprecated.
   */
  private async checkDeprecation(packageName: string, ecosystem: string): Promise<{ deprecated: boolean; message: string | null }> {
    if (ecosystem.toLowerCase() === 'npm') {
      return this.checkNpmDeprecation(packageName);
    }
    // Add PyPI deprecation check in future
    return { deprecated: KNOWN_ALTERNATIVES[packageName] !== undefined, message: null };
  }

  private checkNpmDeprecation(packageName: string): Promise<{ deprecated: boolean; message: string | null }> {
    return new Promise((resolve) => {
      const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;

      const req = https.get(url, { headers: { Accept: 'application/json' } }, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          try {
            const data = JSON.parse(body);
            if (data.deprecated) {
              resolve({ deprecated: true, message: data.deprecated });
            } else {
              resolve({ deprecated: false, message: null });
            }
          } catch {
            resolve({ deprecated: false, message: null });
          }
        });
      });
      req.on('error', () => resolve({ deprecated: false, message: null }));
      req.setTimeout(5000, () => { req.destroy(); resolve({ deprecated: false, message: null }); });
      req.end();
    });
  }

  /**
   * Fetch the latest version from the registry.
   */
  private async fetchLatestVersion(packageName: string, ecosystem: string): Promise<string | null> {
    if (ecosystem.toLowerCase() === 'npm') {
      return this.fetchNpmLatest(packageName);
    }
    if (ecosystem.toLowerCase() === 'pypi') {
      return this.fetchPyPILatest(packageName);
    }
    return null;
  }

  private fetchNpmLatest(packageName: string): Promise<string | null> {
    return new Promise((resolve) => {
      const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;
      const req = https.get(url, { headers: { Accept: 'application/json' } }, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          try {
            resolve(JSON.parse(body).version ?? null);
          } catch { resolve(null); }
        });
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
      req.end();
    });
  }

  private fetchPyPILatest(packageName: string): Promise<string | null> {
    return new Promise((resolve) => {
      const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
      const req = https.get(url, { headers: { Accept: 'application/json' } }, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          try {
            resolve(JSON.parse(body).info?.version ?? null);
          } catch { resolve(null); }
        });
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
      req.end();
    });
  }

  // -------------------------------------------------------------------------
  // Parsing helpers
  // -------------------------------------------------------------------------

  private parseOsvVuln(raw: Record<string, unknown>, packageName: string, osvEcosystem: string): OsvVulnSummary {
    const id = (raw.id as string) ?? 'unknown';
    const summary = (raw.summary as string) ?? '';

    // Extract severity from database_specific or severity array
    let severity = 'UNKNOWN';
    let cvssScore: number | null = null;

    const severityArr = raw.severity as Array<{ type?: string; score?: string }> | undefined;
    if (severityArr && Array.isArray(severityArr)) {
      for (const s of severityArr) {
        if (s.type === 'CVSS_V3' && s.score) {
          // Parse CVSS vector to get base score
          const scoreMatch = s.score.match(/CVSS:[\d.]+\/AV:\w\/AC:\w\/PR:\w\/UI:\w\/S:\w\/C:\w\/I:\w\/A:\w/);
          if (scoreMatch) {
            // Approximate score from vector (simplified)
            cvssScore = this.approximateCvssScore(s.score);
            severity = this.cvssToSeverity(cvssScore);
          }
        }
      }
    }

    // Also check database_specific.severity
    const dbSpecific = raw.database_specific as { severity?: string } | undefined;
    if (dbSpecific?.severity && severity === 'UNKNOWN') {
      severity = dbSpecific.severity.toUpperCase();
    }

    // Extract affected/fixed versions
    let affectedVersions: string | null = null;
    let fixedVersion: string | null = null;

    const affected = raw.affected as Array<{
      package?: { name?: string; ecosystem?: string };
      ranges?: Array<{ type?: string; events?: Array<{ introduced?: string; fixed?: string }> }>;
    }> | undefined;

    if (affected && Array.isArray(affected)) {
      for (const aff of affected) {
        const pkg = aff.package;
        if (pkg?.name?.toLowerCase() === packageName.toLowerCase() || pkg?.ecosystem === osvEcosystem) {
          const ranges = aff.ranges ?? [];
          for (const range of ranges) {
            const events = range.events ?? [];
            const introduced: string[] = [];
            const fixed: string[] = [];
            for (const evt of events) {
              if (evt.introduced) { introduced.push(evt.introduced); }
              if (evt.fixed) { fixed.push(evt.fixed); }
            }
            if (introduced.length > 0 || fixed.length > 0) {
              affectedVersions = introduced.map(v => `>=${v}`).join(', ');
              if (fixed.length > 0) {
                affectedVersions += `, <${fixed[fixed.length - 1]}`;
                fixedVersion = fixed[fixed.length - 1];
              }
            }
          }
        }
      }
    }

    // Get reference URL
    const references = raw.references as Array<{ type?: string; url?: string }> | undefined;
    const referenceUrl = references?.[0]?.url ?? `https://osv.dev/vulnerability/${id}`;

    return { id, summary, severity, cvssScore, affectedVersions, fixedVersion, referenceUrl };
  }

  private extractGhsaAffectedRange(adv: Record<string, unknown>, packageName: string): string | null {
    const vulnerabilities = adv.vulnerabilities as Array<{
      package?: { name?: string };
      vulnerable_version_range?: string;
    }> | undefined;

    if (vulnerabilities) {
      for (const v of vulnerabilities) {
        if (v.package?.name?.toLowerCase() === packageName.toLowerCase()) {
          return v.vulnerable_version_range ?? null;
        }
      }
    }
    return null;
  }

  private extractGhsaFixedVersion(adv: Record<string, unknown>, packageName: string): string | null {
    const vulnerabilities = adv.vulnerabilities as Array<{
      package?: { name?: string };
      patched_versions?: string;
      first_patched_version?: { identifier?: string };
    }> | undefined;

    if (vulnerabilities) {
      for (const v of vulnerabilities) {
        if (v.package?.name?.toLowerCase() === packageName.toLowerCase()) {
          return v.first_patched_version?.identifier ?? v.patched_versions ?? null;
        }
      }
    }
    return null;
  }

  private mapToOsvEcosystem(ecosystem: string): string {
    switch (ecosystem.toLowerCase()) {
      case 'npm': return 'npm';
      case 'pypi': return 'PyPI';
      case 'go': return 'Go';
      case 'crates.io': return 'crates.io';
      case 'maven': return 'Maven';
      default: return ecosystem;
    }
  }

  private approximateCvssScore(vector: string): number {
    // Simplified CVSS v3 scoring — approximate from attack vector components
    let score = 5.0; // Base
    if (vector.includes('AV:N')) { score += 1.5; } // Network
    if (vector.includes('AC:L')) { score += 0.5; } // Low complexity
    if (vector.includes('PR:N')) { score += 0.5; } // No privileges
    if (vector.includes('UI:N')) { score += 0.5; } // No user interaction
    if (vector.includes('S:C')) { score += 0.5; }  // Changed scope
    if (vector.includes('C:H')) { score += 0.5; }  // High confidentiality
    if (vector.includes('I:H')) { score += 0.5; }  // High integrity
    if (vector.includes('A:H')) { score += 0.5; }  // High availability
    return Math.min(score, 10.0);
  }

  private cvssToSeverity(score: number): string {
    if (score >= 9.0) { return 'CRITICAL'; }
    if (score >= 7.0) { return 'HIGH'; }
    if (score >= 4.0) { return 'MEDIUM'; }
    return 'LOW';
  }

  private findBestSafeVersion(patches: PatchSuggestion[]): string | null {
    // Find the highest safe version that fixes the most vulnerabilities
    const safeVersions = patches
      .map(p => p.safeVersion)
      .filter((v): v is string => v !== null);

    if (safeVersions.length === 0) { return null; }

    // Return the highest version (simple string comparison — works for semver)
    return safeVersions.sort((a, b) => {
      const pa = a.split('.').map(Number);
      const pb = b.split('.').map(Number);
      for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const diff = (pb[i] ?? 0) - (pa[i] ?? 0);
        if (diff !== 0) { return diff; }
      }
      return 0;
    })[0];
  }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface OsvVulnSummary {
  id: string;
  summary: string;
  severity: string;
  cvssScore: number | null;
  affectedVersions: string | null;
  fixedVersion: string | null;
  referenceUrl: string | null;
}
