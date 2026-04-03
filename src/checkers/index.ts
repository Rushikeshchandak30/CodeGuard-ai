import { ParsedDependency } from '../parsers/types';
import { OsvClient } from './osv';
import { RegistryChecker } from './registry';
import { ScanResult, VulnerabilityInfo, Severity } from './types';
import { Cache } from '../cache/cache';

/**
 * Orchestrator that runs all security checks for a set of parsed dependencies.
 * Coordinates OSV vulnerability lookup + registry existence checking + caching.
 */
export class SecurityChecker {
  private osv: OsvClient;
  private registry: RegistryChecker;
  private cache: Cache;
  private enableHallucination: boolean;

  constructor(cache: Cache, enableHallucinationDetection: boolean = true) {
    this.osv = new OsvClient();
    this.registry = new RegistryChecker();
    this.cache = cache;
    this.enableHallucination = enableHallucinationDetection;
  }

  /**
   * Scan a list of parsed dependencies and return results.
   */
  async scan(dependencies: ParsedDependency[]): Promise<Map<string, ScanResult>> {
    const results = new Map<string, ScanResult>();

    // Deduplicate by package name
    const uniqueDeps = new Map<string, ParsedDependency>();
    for (const dep of dependencies) {
      if (!uniqueDeps.has(dep.name)) {
        uniqueDeps.set(dep.name, dep);
      }
    }

    // Check cache first, collect uncached
    const uncached: ParsedDependency[] = [];
    for (const [name, dep] of uniqueDeps) {
      const cached = this.cache.get(name);
      if (cached) {
        results.set(name, { ...cached, fromCache: true });
      } else {
        uncached.push(dep);
      }
    }

    if (uncached.length === 0) {
      return results;
    }

    // Run vulnerability checks and registry checks in parallel
    const [vulnResults, existenceResults] = await Promise.all([
      this.checkVulnerabilities(uncached),
      this.enableHallucination ? this.checkExistence(uncached) : Promise.resolve(new Map<string, boolean>()),
    ]);

    // Merge results
    for (const dep of uncached) {
      const vulns = vulnResults.get(dep.name) || [];
      const exists = existenceResults.get(dep.name) ?? true;
      const highestSeverity = this.getHighestSeverity(vulns);

      const result: ScanResult = {
        packageName: dep.name,
        ecosystem: dep.ecosystem,
        packageExists: exists,
        vulnerabilities: vulns,
        highestSeverity,
        fromCache: false,
      };

      results.set(dep.name, result);
      this.cache.set(dep.name, result);
    }

    return results;
  }

  /**
   * Batch vulnerability check via OSV.
   */
  private async checkVulnerabilities(
    deps: ParsedDependency[]
  ): Promise<Map<string, VulnerabilityInfo[]>> {
    const packages = deps.map(d => ({
      name: d.name,
      version: d.version,
      ecosystem: d.ecosystem,
    }));

    return this.osv.queryBatch(packages);
  }

  /**
   * Check if packages exist on their registries.
   */
  private async checkExistence(deps: ParsedDependency[]): Promise<Map<string, boolean>> {
    const results = new Map<string, boolean>();

    // Run checks in parallel with concurrency limit of 5
    const chunks = this.chunk(deps, 5);
    for (const batch of chunks) {
      const checks = batch.map(async (dep) => {
        const exists = await this.registry.exists(dep.name, dep.ecosystem);
        results.set(dep.name, exists);
      });
      await Promise.all(checks);
    }

    return results;
  }

  /**
   * Get the highest severity from a list of vulnerabilities.
   */
  private getHighestSeverity(vulns: VulnerabilityInfo[]): Severity | null {
    if (vulns.length === 0) { return null; }

    const order: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
    for (const level of order) {
      if (vulns.some(v => v.severity === level)) {
        return level;
      }
    }
    return 'UNKNOWN';
  }

  /**
   * Split array into chunks of given size.
   */
  private chunk<T>(arr: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < arr.length; i += size) {
      chunks.push(arr.slice(i, i + size));
    }
    return chunks;
  }
}

export { ScanResult, VulnerabilityInfo, Severity } from './types';
