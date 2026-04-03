import * as https from 'https';
import { Ecosystem } from '../parsers/types';
import popularPackagesData from '../data/popular-packages.json';
import knownHallucinationsData from '../data/known-hallucinations.json';

/**
 * Enhanced hallucination detection — goes beyond simple existence checks.
 * Detects typosquatting, namespace confusion, popularity concerns, and age-based risks.
 */

export interface HallucinationAnalysis {
  /** Package exists on registry */
  exists: boolean;
  /** Typosquatting: similar to a known popular package */
  typosquatSuggestion: string | null;
  /** Levenshtein distance to the suggested real package */
  typosquatDistance: number | null;
  /** Package is suspiciously low-popularity */
  lowPopularity: boolean;
  /** Weekly download count (if available) */
  weeklyDownloads: number | null;
  /** Namespace confusion: wrong ecosystem for this package */
  namespaceConfusion: boolean;
  /** The correct ecosystem if namespace confusion detected */
  correctEcosystem: Ecosystem | null;
  /** Package was registered very recently (possible malicious claim) */
  recentlyRegistered: boolean;
  /** Registration date (if available) */
  registeredDate: string | null;
  /** Overall risk level */
  riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  /** Human-readable risk summary */
  riskSummary: string;
  /** Package is in the known-hallucination database */
  knownHallucination: boolean;
}

// Popular packages loaded from bundled JSON data file for typosquatting detection
const TOP_NPM_PACKAGES: string[] = popularPackagesData.npm;
const TOP_PYPI_PACKAGES: string[] = popularPackagesData.pypi;

// Known AI-hallucinated package names loaded from bundled seed DB
const KNOWN_HALLUCINATED_NPM = new Set<string>(knownHallucinationsData.npm.map((n: string) => n.toLowerCase()));
const KNOWN_HALLUCINATED_PYPI = new Set<string>(knownHallucinationsData.pypi.map((n: string) => n.toLowerCase()));

// Known cross-ecosystem packages (exist in one ecosystem, not the other)
const CROSS_ECOSYSTEM_MAP: Record<string, Ecosystem> = {
  // Python packages that don't exist on npm
  'beautifulsoup4': 'PyPI',
  'scikit-learn': 'PyPI',
  'sklearn': 'PyPI',
  'numpy': 'PyPI',
  'pandas': 'PyPI',
  'scipy': 'PyPI',
  'matplotlib': 'PyPI',
  'tensorflow': 'PyPI',
  'pytorch': 'PyPI',
  'flask': 'PyPI',
  'django': 'PyPI',
  'fastapi': 'PyPI',
  'uvicorn': 'PyPI',
  'gunicorn': 'PyPI',
  'celery': 'PyPI',
  'sqlalchemy': 'PyPI',
  'pydantic': 'PyPI',
  'pytest': 'PyPI',
  // npm packages that don't exist on PyPI
  'react': 'npm',
  'react-dom': 'npm',
  'next': 'npm',
  'vue': 'npm',
  'angular': 'npm',
  'svelte': 'npm',
  'express': 'npm',
  'webpack': 'npm',
  'vite': 'npm',
  'tailwindcss': 'npm',
  'jquery': 'npm',
  'electron': 'npm',
};

export class HallucinationDetector {

  /**
   * Run full hallucination analysis on a package.
   */
  async analyze(
    packageName: string,
    ecosystem: Ecosystem,
    exists: boolean
  ): Promise<HallucinationAnalysis> {
    const result: HallucinationAnalysis = {
      exists,
      typosquatSuggestion: null,
      typosquatDistance: null,
      lowPopularity: false,
      weeklyDownloads: null,
      namespaceConfusion: false,
      correctEcosystem: null,
      recentlyRegistered: false,
      registeredDate: null,
      riskLevel: 'none',
      riskSummary: '',
      knownHallucination: false,
    };

    // Check 0: Known hallucination DB (fast, local, no network)
    this.checkKnownHallucination(packageName, ecosystem, result);

    // Check 1: Namespace confusion
    this.checkNamespaceConfusion(packageName, ecosystem, result);

    // Check 2: Typosquatting (always check, even if package exists)
    this.checkTyposquatting(packageName, ecosystem, result);

    // If package doesn't exist, it's at minimum high risk
    if (!exists) {
      result.riskLevel = 'critical';
      if (result.knownHallucination) {
        result.riskSummary = `Package "${packageName}" is a KNOWN AI hallucination ` +
          `(in CodeGuard seed DB). It does not exist on ${ecosystem}.`;
      } else if (result.typosquatSuggestion) {
        result.riskSummary = `Package "${packageName}" does not exist on ${ecosystem}. ` +
          `Did you mean "${result.typosquatSuggestion}"? (typosquatting risk)`;
      } else {
        result.riskSummary = `Package "${packageName}" does not exist on ${ecosystem}. ` +
          `This appears to be an AI hallucination (slopsquatting risk).`;
      }
      return result;
    }

    // Check 3: Popularity (only for packages that exist)
    if (ecosystem === 'npm' || ecosystem === 'PyPI') {
      await this.checkPopularity(packageName, ecosystem, result);
    }

    // Check 4: Recent registration (only for packages that exist)
    if (ecosystem === 'npm') {
      await this.checkRegistrationAge(packageName, result);
    }

    // Determine overall risk level
    this.computeRiskLevel(result);

    return result;
  }

  /**
   * Check if the package name is in the known-hallucination seed database.
   */
  private checkKnownHallucination(
    packageName: string,
    ecosystem: Ecosystem,
    result: HallucinationAnalysis
  ): void {
    const lower = packageName.toLowerCase();
    const db = ecosystem === 'npm' ? KNOWN_HALLUCINATED_NPM
      : ecosystem === 'PyPI' ? KNOWN_HALLUCINATED_PYPI
      : null;
    if (db && db.has(lower)) {
      result.knownHallucination = true;
    }
  }

  /**
   * Check if the package name belongs to a different ecosystem.
   */
  private checkNamespaceConfusion(
    packageName: string,
    ecosystem: Ecosystem,
    result: HallucinationAnalysis
  ): void {
    const correctEcosystem = CROSS_ECOSYSTEM_MAP[packageName.toLowerCase()];
    if (correctEcosystem && correctEcosystem !== ecosystem) {
      result.namespaceConfusion = true;
      result.correctEcosystem = correctEcosystem;
    }
  }

  /**
   * Check if the package name is suspiciously similar to a popular package.
   */
  private checkTyposquatting(
    packageName: string,
    ecosystem: Ecosystem,
    result: HallucinationAnalysis
  ): void {
    const popularList = ecosystem === 'npm' ? TOP_NPM_PACKAGES
      : ecosystem === 'PyPI' ? TOP_PYPI_PACKAGES
      : [];

    // Skip if the package IS in the popular list
    if (popularList.includes(packageName.toLowerCase())) { return; }

    let bestMatch: string | null = null;
    let bestDistance = Infinity;

    for (const popular of popularList) {
      const distance = this.levenshtein(packageName.toLowerCase(), popular.toLowerCase());
      // Only flag if distance is 1-2 (very close but not exact)
      if (distance > 0 && distance <= 2 && distance < bestDistance) {
        bestDistance = distance;
        bestMatch = popular;
      }
    }

    if (bestMatch) {
      result.typosquatSuggestion = bestMatch;
      result.typosquatDistance = bestDistance;
    }
  }

  /**
   * Check package download count for suspiciously low popularity.
   */
  private async checkPopularity(
    packageName: string,
    ecosystem: Ecosystem,
    result: HallucinationAnalysis
  ): Promise<void> {
    try {
      if (ecosystem === 'npm') {
        const downloads = await this.getNpmWeeklyDownloads(packageName);
        result.weeklyDownloads = downloads;
        if (downloads !== null && downloads < 100) {
          result.lowPopularity = true;
        }
      }
      // PyPI download stats require BigQuery — skip for now
    } catch {
      // Ignore errors
    }
  }

  /**
   * Check if an npm package was registered very recently.
   */
  private async checkRegistrationAge(
    packageName: string,
    result: HallucinationAnalysis
  ): Promise<void> {
    try {
      const body = await this.httpsGet(
        `https://registry.npmjs.org/${encodeURIComponent(packageName)}`
      );
      const parsed = JSON.parse(body);
      const created = parsed.time?.created;
      if (created) {
        result.registeredDate = created;
        const createdDate = new Date(created);
        const daysSinceCreation = (Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceCreation < 30) {
          result.recentlyRegistered = true;
        }
      }
    } catch {
      // Ignore errors
    }
  }

  /**
   * Get npm weekly download count.
   */
  private async getNpmWeeklyDownloads(packageName: string): Promise<number | null> {
    try {
      const encoded = encodeURIComponent(packageName);
      const body = await this.httpsGet(
        `https://api.npmjs.org/downloads/point/last-week/${encoded}`
      );
      const parsed = JSON.parse(body);
      return parsed.downloads ?? null;
    } catch {
      return null;
    }
  }

  /**
   * Compute overall risk level from individual signals.
   */
  private computeRiskLevel(result: HallucinationAnalysis): void {
    const risks: string[] = [];

    if (!result.exists) {
      result.riskLevel = 'critical';
      return;
    }

    if (result.recentlyRegistered && result.lowPopularity) {
      // New + unpopular = very suspicious (possible malicious claim)
      result.riskLevel = 'high';
      risks.push('Recently registered with very low downloads — possible malicious package');
    } else if (result.recentlyRegistered) {
      result.riskLevel = 'medium';
      risks.push('Package registered less than 30 days ago');
    } else if (result.lowPopularity) {
      result.riskLevel = 'low';
      risks.push(`Very low download count (${result.weeklyDownloads} weekly)`);
    }

    if (result.typosquatSuggestion && result.exists) {
      // Exists but looks like a typo of a popular package
      if (result.riskLevel === 'none') { result.riskLevel = 'medium'; }
      risks.push(`Name is very similar to popular package "${result.typosquatSuggestion}" — possible typosquatting`);
    }

    if (result.namespaceConfusion) {
      if (result.riskLevel === 'none') { result.riskLevel = 'low'; }
      risks.push(`This is typically a ${result.correctEcosystem} package, not ${result.exists ? 'expected here' : 'available on this registry'}`);
    }

    result.riskSummary = risks.length > 0 ? risks.join('. ') + '.' : 'No hallucination risk detected.';
  }

  /**
   * Levenshtein distance between two strings.
   */
  private levenshtein(a: string, b: string): number {
    const m = a.length;
    const n = b.length;
    const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) { dp[i][0] = i; }
    for (let j = 0; j <= n; j++) { dp[0][j] = j; }

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,       // deletion
          dp[i][j - 1] + 1,       // insertion
          dp[i - 1][j - 1] + cost // substitution
        );
      }
    }

    return dp[m][n];
  }

  private httpsGet(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const options: https.RequestOptions = {
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        method: 'GET',
        headers: {
          'User-Agent': 'CodeGuard-AI-VSCode/0.2.0',
          'Accept': 'application/json',
        },
        timeout: 8000,
      };

      const req = https.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve(body);
          } else {
            reject(new Error(`HTTP ${res.statusCode}`));
          }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.end();
    });
  }
}
