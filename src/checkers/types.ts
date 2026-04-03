import { Ecosystem } from '../parsers/types';

/**
 * Severity levels aligned with CVSS qualitative ratings.
 */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

/**
 * Result of a vulnerability check for a single package.
 */
export interface VulnerabilityResult {
  /** Package name */
  packageName: string;
  /** Package ecosystem */
  ecosystem: Ecosystem;
  /** Version that was checked */
  versionChecked: string | null;
  /** Whether the package exists on its registry */
  exists: boolean;
  /** List of vulnerabilities found */
  vulnerabilities: VulnerabilityInfo[];
  /** Timestamp of the check */
  checkedAt: number;
}

/**
 * Details about a single vulnerability (CVE).
 */
export interface VulnerabilityInfo {
  /** Vulnerability ID (e.g. "CVE-2020-8203", "GHSA-xxxx") */
  id: string;
  /** Human-readable summary */
  summary: string;
  /** Detailed description */
  details: string;
  /** Severity level */
  severity: Severity;
  /** CVSS score (0-10) if available */
  cvssScore: number | null;
  /** Affected version ranges */
  affectedVersions: string;
  /** First fixed version if known */
  fixedVersion: string | null;
  /** URL for more information */
  referenceUrl: string;
  /** When it was published */
  published: string | null;
}

/**
 * Combined scan result for a single dependency.
 */
export interface ScanResult {
  /** Package name */
  packageName: string;
  /** Ecosystem */
  ecosystem: Ecosystem;
  /** Whether this package actually exists on its registry */
  packageExists: boolean;
  /** Vulnerability results (empty if clean) */
  vulnerabilities: VulnerabilityInfo[];
  /** Highest severity found across all vulns */
  highestSeverity: Severity | null;
  /** Whether this was served from cache */
  fromCache: boolean;
}
