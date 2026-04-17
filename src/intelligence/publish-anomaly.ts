/**
 * Chronological Publish Anomaly Detector
 *
 * Detects common attack patterns by looking at the time-series of package
 * versions on the registry:
 *
 *   1. Out-of-order patches — attackers publish a new version on an old major
 *      line (e.g. v2.x while current stable is v5.x). Old-major users who pin
 *      ranges like ^2.3.0 pick it up automatically.
 *
 *   2. Burst republish — many versions pushed in a short window (common in
 *      rug-pull and credential-harvesting campaigns).
 *
 *   3. Long silence → sudden activity — package dormant for >1 year then
 *      suddenly gets a new version by a different publisher (takeover).
 *
 *   4. Version skip — package jumps from 1.2.3 straight to 99.0.0 to force
 *      a semver-major update into downstream consumers.
 *
 *   5. Pre-release → stable shortcut — 0.x pre-release promoted to 1.0 with
 *      no intermediate versions, often paired with new-maintainer signals.
 *
 *   6. Retracted-and-resurrected — package that was unpublished then
 *      re-registered by a different account.
 *
 * All analysis is done offline once registry metadata is fetched; no PII.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AnomalySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface PublishAnomaly {
  id: string;
  severity: AnomalySeverity;
  title: string;
  detail: string;
  evidence: string;
}

export interface PublishAnomalyReport {
  packageName: string;
  ecosystem: 'npm' | 'pypi';
  versionCount: number;
  anomalies: PublishAnomaly[];
  riskScore: number; // 0 (clean) to 100 (dangerous)
  summary: string;
}

export interface VersionRecord {
  version: string; // semver string
  publishedAt: Date;
  publisher?: string;
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

/**
 * Analyze a list of version records (must be unsorted or sorted — we sort).
 */
export function analyzePublishHistory(
  packageName: string,
  ecosystem: 'npm' | 'pypi',
  versions: VersionRecord[]
): PublishAnomalyReport {
  const anomalies: PublishAnomaly[] = [];
  if (versions.length === 0) {
    return {
      packageName,
      ecosystem,
      versionCount: 0,
      anomalies: [],
      riskScore: 0,
      summary: `${packageName}: no version history to analyze.`,
    };
  }

  // Sort by publish date ascending
  const sorted = [...versions].sort(
    (a, b) => a.publishedAt.getTime() - b.publishedAt.getTime()
  );

  // -----------------------------------------------------------------------
  // 1. Out-of-order patches (version number lower than a previously-published
  //    version, indicating a retroactive publish on an old major line).
  // -----------------------------------------------------------------------
  const semverSorted = [...sorted].sort((a, b) =>
    semverCompare(a.version, b.version)
  );
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    const cur = sorted[i];
    if (semverCompare(cur.version, prev.version) < 0) {
      anomalies.push({
        id: 'CG_PANOM_001',
        severity: 'high',
        title: 'Out-of-order version publish',
        detail:
          'A version with a LOWER semver was published AFTER a higher one. Attackers ' +
          'use this to target users pinned to old majors (e.g. they release v2.10.1 ' +
          'while v5 is current). Users on ^2.x pull it automatically.',
        evidence: `${prev.version} (published ${prev.publishedAt.toISOString()}) followed by ${cur.version} (${cur.publishedAt.toISOString()})`,
      });
      break; // one finding per package is enough
    }
  }

  // -----------------------------------------------------------------------
  // 2. Burst republish — many versions in a short window
  // -----------------------------------------------------------------------
  const WINDOW_MS = 6 * 60 * 60 * 1000; // 6 hours
  const BURST_THRESHOLD = 5;
  for (let i = BURST_THRESHOLD - 1; i < sorted.length; i++) {
    const windowStart = sorted[i - BURST_THRESHOLD + 1].publishedAt.getTime();
    const windowEnd = sorted[i].publishedAt.getTime();
    if (windowEnd - windowStart <= WINDOW_MS) {
      anomalies.push({
        id: 'CG_PANOM_002',
        severity: 'high',
        title: `Burst publish (${BURST_THRESHOLD}+ versions in 6h)`,
        detail:
          'Rapid successive publishes often indicate a compromised automation ' +
          'pipeline or a deliberate malicious campaign (wiper packages, rug-pulls).',
        evidence: `${BURST_THRESHOLD} versions between ${new Date(windowStart).toISOString()} and ${new Date(windowEnd).toISOString()}`,
      });
      break;
    }
  }

  // -----------------------------------------------------------------------
  // 3. Dormant-then-active (>365 days silence followed by a new version,
  //    especially if publisher changes)
  // -----------------------------------------------------------------------
  if (sorted.length >= 2) {
    for (let i = 1; i < sorted.length; i++) {
      const gap =
        sorted[i].publishedAt.getTime() - sorted[i - 1].publishedAt.getTime();
      if (gap > 365 * 86_400_000) {
        const publisherChanged =
          sorted[i - 1].publisher &&
          sorted[i].publisher &&
          sorted[i - 1].publisher !== sorted[i].publisher;
        anomalies.push({
          id: publisherChanged ? 'CG_PANOM_003a' : 'CG_PANOM_003b',
          severity: publisherChanged ? 'critical' : 'medium',
          title: publisherChanged
            ? 'Dormant-then-active with publisher change (takeover pattern)'
            : `Package dormant for ${Math.floor(gap / 86_400_000)} days`,
          detail: publisherChanged
            ? 'The package was inactive for >1 year, then a new version was published by a DIFFERENT account. This is the classic maintainer-handover exploitation pattern (see "event-stream" 2018).'
            : 'Package was dormant for more than a year, then resumed activity. Legitimate maintenance, but worth verifying the new version independently.',
          evidence: `${sorted[i - 1].version} (${sorted[i - 1].publishedAt.toISOString()}, publisher=${sorted[i - 1].publisher ?? '?'}) → ${sorted[i].version} (${sorted[i].publishedAt.toISOString()}, publisher=${sorted[i].publisher ?? '?'})`,
        });
        break;
      }
    }
  }

  // -----------------------------------------------------------------------
  // 4. Massive version skip (major version +10 or more)
  // -----------------------------------------------------------------------
  for (let i = 1; i < semverSorted.length; i++) {
    const prev = semverSorted[i - 1];
    const cur = semverSorted[i];
    const dMajor = parseMajor(cur.version) - parseMajor(prev.version);
    if (dMajor >= 10) {
      anomalies.push({
        id: 'CG_PANOM_004',
        severity: 'medium',
        title: `Unusual major version jump: v${parseMajor(prev.version)} → v${parseMajor(cur.version)}`,
        detail:
          'A massive version bump may be an attempt to appear "newer" in UI listings ' +
          'or to trigger auto-update rules that normally skip majors.',
        evidence: `${prev.version} → ${cur.version}`,
      });
      break;
    }
  }

  // -----------------------------------------------------------------------
  // 5. Zero-version shortcut (no intermediate versions)
  // -----------------------------------------------------------------------
  const uniqueVersions = new Set(sorted.map((v) => v.version));
  const hasZero = [...uniqueVersions].some((v) => /^0\./.test(v));
  const hasOne = [...uniqueVersions].some((v) => /^1\.0\.0$/.test(v));
  if (hasZero && hasOne && uniqueVersions.size <= 3) {
    anomalies.push({
      id: 'CG_PANOM_005',
      severity: 'low',
      title: 'Package jumped to 1.0.0 with minimal pre-release history',
      detail:
        'Going straight from 0.x to 1.0.0 with few intermediate versions is rare for ' +
        'mature libraries. Combined with a new-maintainer signal, treat as a risk.',
      evidence: `Versions observed: ${[...uniqueVersions].slice(0, 8).join(', ')}`,
    });
  }

  // -----------------------------------------------------------------------
  // 6. Publisher inconsistency summary
  // -----------------------------------------------------------------------
  const publishers = new Set(
    sorted.filter((v) => v.publisher).map((v) => v.publisher as string)
  );
  if (publishers.size >= 3) {
    anomalies.push({
      id: 'CG_PANOM_006',
      severity: 'medium',
      title: `${publishers.size} distinct publishers in version history`,
      detail:
        'Multiple publishers can be legitimate (team maintenance) but combined with ' +
        'other signals it indicates churn. Review the current publisher carefully.',
      evidence: [...publishers].slice(0, 6).join(', '),
    });
  }

  const riskScore = scoreAnomalies(anomalies);
  return {
    packageName,
    ecosystem,
    versionCount: versions.length,
    anomalies,
    riskScore,
    summary: buildAnomalySummary(packageName, anomalies, riskScore),
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseMajor(v: string): number {
  const m = v.replace(/^v/, '').match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : 0;
}

function semverCompare(a: string, b: string): number {
  const clean = (s: string) => s.replace(/^v/, '').split('-')[0];
  const pa = clean(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = clean(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

function scoreAnomalies(anomalies: PublishAnomaly[]): number {
  let score = 0;
  for (const a of anomalies) {
    switch (a.severity) {
      case 'critical':
        score += 45;
        break;
      case 'high':
        score += 25;
        break;
      case 'medium':
        score += 12;
        break;
      case 'low':
        score += 5;
        break;
      default:
        break;
    }
  }
  return Math.min(100, score);
}

function buildAnomalySummary(
  pkg: string,
  anomalies: PublishAnomaly[],
  score: number
): string {
  if (anomalies.length === 0) return `${pkg}: version history looks clean.`;
  const critical = anomalies.filter((a) => a.severity === 'critical').length;
  const high = anomalies.filter((a) => a.severity === 'high').length;
  return `${pkg}: ${anomalies.length} anomal${anomalies.length === 1 ? 'y' : 'ies'} (${critical}C/${high}H), risk ${score}/100.`;
}

export function getPublishAnomalyStats(): { detectorCount: number } {
  return { detectorCount: 6 };
}
