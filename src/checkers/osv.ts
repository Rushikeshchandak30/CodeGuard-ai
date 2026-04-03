import * as https from 'https';
import { Ecosystem } from '../parsers/types';
import { VulnerabilityInfo, Severity } from './types';

/**
 * OSV.dev API client — free, open vulnerability database.
 * Aggregates GitHub Advisory, PyPA, NVD, RustSec, and more.
 * API docs: https://osv.dev/docs/
 */
export class OsvClient {
  private static readonly API_URL = 'https://api.osv.dev/v1';

  /**
   * Query OSV for vulnerabilities affecting a specific package + version.
   */
  async query(
    packageName: string,
    version: string | null,
    ecosystem: Ecosystem
  ): Promise<VulnerabilityInfo[]> {
    const osvEcosystem = this.mapEcosystem(ecosystem);

    const body: Record<string, unknown> = {
      package: {
        name: packageName,
        ecosystem: osvEcosystem,
      },
    };

    if (version) {
      body.version = version;
    }

    try {
      const response = await this.post(`${OsvClient.API_URL}/query`, body);
      return this.parseResponse(response);
    } catch (error) {
      console.error(`[CodeGuard] OSV query failed for ${packageName}@${version}:`, error);
      return [];
    }
  }

  /**
   * Batch query: check multiple packages at once (OSV supports this).
   */
  async queryBatch(
    packages: Array<{ name: string; version: string | null; ecosystem: Ecosystem }>
  ): Promise<Map<string, VulnerabilityInfo[]>> {
    const queries = packages.map(pkg => ({
      package: {
        name: pkg.name,
        ecosystem: this.mapEcosystem(pkg.ecosystem),
      },
      ...(pkg.version ? { version: pkg.version } : {}),
    }));

    const results = new Map<string, VulnerabilityInfo[]>();

    try {
      const response = await this.post(`${OsvClient.API_URL}/querybatch`, { queries });
      const parsed = JSON.parse(response);

      if (parsed.results && Array.isArray(parsed.results)) {
        for (let i = 0; i < parsed.results.length; i++) {
          const pkg = packages[i];
          const vulns = parsed.results[i].vulns || [];
          results.set(pkg.name, this.parseVulns(vulns));
        }
      }
    } catch (error) {
      console.error('[CodeGuard] OSV batch query failed:', error);
      // Fall back to individual queries
      for (const pkg of packages) {
        const vulns = await this.query(pkg.name, pkg.version, pkg.ecosystem);
        results.set(pkg.name, vulns);
      }
    }

    return results;
  }

  /**
   * Parse raw OSV API response JSON into VulnerabilityInfo[].
   */
  private parseResponse(responseBody: string): VulnerabilityInfo[] {
    const parsed = JSON.parse(responseBody);
    if (!parsed.vulns || !Array.isArray(parsed.vulns)) {
      return [];
    }
    return this.parseVulns(parsed.vulns);
  }

  private parseVulns(vulns: any[]): VulnerabilityInfo[] {
    return vulns.map((vuln: any) => {
      const severity = this.extractSeverity(vuln);
      const cvssScore = this.extractCvssScore(vuln);
      const fixedVersion = this.extractFixedVersion(vuln);
      const affectedVersions = this.extractAffectedVersions(vuln);

      // Build reference URL
      const id: string = vuln.id || 'UNKNOWN';
      let referenceUrl = `https://osv.dev/vulnerability/${id}`;
      if (vuln.references && vuln.references.length > 0) {
        const advisory = vuln.references.find((r: any) => r.type === 'ADVISORY');
        if (advisory) {
          referenceUrl = advisory.url;
        }
      }

      return {
        id,
        summary: vuln.summary || 'No summary available',
        details: vuln.details || '',
        severity,
        cvssScore,
        affectedVersions,
        fixedVersion,
        referenceUrl,
        published: vuln.published || null,
      };
    });
  }

  /**
   * Extract severity from OSV vuln object.
   * Checks database_specific.severity, then CVSS score ranges.
   */
  private extractSeverity(vuln: any): Severity {
    // Check severity array (CVSS v3/v4)
    if (vuln.severity && Array.isArray(vuln.severity)) {
      for (const s of vuln.severity) {
        if (s.score) {
          return this.cvssToSeverity(parseFloat(s.score));
        }
        // Try parsing CVSS vector for score
        if (s.type === 'CVSS_V3' && typeof s.score === 'string') {
          const scoreMatch = s.score.match(/CVSS:\d\.\d\/.*$/);
          if (scoreMatch) {
            // Rough extraction — would need full CVSS parser for accuracy
            return 'MEDIUM';
          }
        }
      }
    }

    // Check database_specific severity
    if (vuln.database_specific?.severity) {
      const sev = vuln.database_specific.severity.toUpperCase();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(sev)) {
        return sev as Severity;
      }
    }

    // Check ecosystem_specific
    if (vuln.ecosystem_specific?.severity) {
      const sev = vuln.ecosystem_specific.severity.toUpperCase();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(sev)) {
        return sev as Severity;
      }
    }

    return 'UNKNOWN';
  }

  private extractCvssScore(vuln: any): number | null {
    if (vuln.severity && Array.isArray(vuln.severity)) {
      for (const s of vuln.severity) {
        if (typeof s.score === 'number') {
          return s.score;
        }
      }
    }
    return null;
  }

  private extractFixedVersion(vuln: any): string | null {
    if (vuln.affected && Array.isArray(vuln.affected)) {
      for (const affected of vuln.affected) {
        if (affected.ranges && Array.isArray(affected.ranges)) {
          for (const range of affected.ranges) {
            if (range.events && Array.isArray(range.events)) {
              const fixedEvent = range.events.find((e: any) => e.fixed);
              if (fixedEvent) {
                return fixedEvent.fixed;
              }
            }
          }
        }
      }
    }
    return null;
  }

  private extractAffectedVersions(vuln: any): string {
    if (vuln.affected && Array.isArray(vuln.affected)) {
      const ranges: string[] = [];
      for (const affected of vuln.affected) {
        if (affected.versions && Array.isArray(affected.versions)) {
          if (affected.versions.length <= 5) {
            ranges.push(affected.versions.join(', '));
          } else {
            ranges.push(`${affected.versions[0]} ... ${affected.versions[affected.versions.length - 1]} (${affected.versions.length} versions)`);
          }
        } else if (affected.ranges) {
          for (const range of affected.ranges) {
            if (range.events) {
              const introduced = range.events.find((e: any) => e.introduced);
              const fixed = range.events.find((e: any) => e.fixed);
              if (introduced && fixed) {
                ranges.push(`>=${introduced.introduced}, <${fixed.fixed}`);
              } else if (introduced) {
                ranges.push(`>=${introduced.introduced}`);
              }
            }
          }
        }
      }
      return ranges.join('; ') || 'Unknown';
    }
    return 'Unknown';
  }

  private cvssToSeverity(score: number): Severity {
    if (score >= 9.0) { return 'CRITICAL'; }
    if (score >= 7.0) { return 'HIGH'; }
    if (score >= 4.0) { return 'MEDIUM'; }
    if (score > 0) { return 'LOW'; }
    return 'UNKNOWN';
  }

  private mapEcosystem(ecosystem: Ecosystem): string {
    const map: Record<Ecosystem, string> = {
      'npm': 'npm',
      'PyPI': 'PyPI',
      'Go': 'Go',
      'Maven': 'Maven',
      'crates.io': 'crates.io',
    };
    return map[ecosystem] || ecosystem;
  }

  /**
   * Simple HTTPS POST helper (no external dependencies needed).
   */
  private post(url: string, body: unknown): Promise<string> {
    return new Promise((resolve, reject) => {
      const data = JSON.stringify(body);
      const urlObj = new URL(url);

      const options: https.RequestOptions = {
        hostname: urlObj.hostname,
        port: 443,
        path: urlObj.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(data),
          'User-Agent': 'CodeGuard-AI-VSCode/0.1.0',
        },
        timeout: 10000,
      };

      const req = https.request(options, (res) => {
        let responseBody = '';
        res.on('data', (chunk) => { responseBody += chunk; });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve(responseBody);
          } else {
            reject(new Error(`OSV API returned ${res.statusCode}: ${responseBody}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('OSV API request timed out'));
      });

      req.write(data);
      req.end();
    });
  }
}
