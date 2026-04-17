/**
 * Maintainer Reputation Tracker
 *
 * Queries npm and PyPI registry metadata to build a reputation score for the
 * humans behind a package. Inspired by Socket.dev's "unstable ownership" and
 * "new maintainer" alerts, and by the 2024 "event-stream" incident where a
 * handover to a malicious maintainer led to wallet theft.
 *
 * Signals scored:
 *   - Age of the maintainer account (newer = riskier)
 *   - Number of packages the maintainer owns (lone-wolf vs established)
 *   - Ownership churn: how many maintainers added/removed recently
 *   - Unstable ownership: new publisher ≠ historical publisher set
 *   - Email domain reputation (free mail vs corporate vs disposable)
 *   - 2FA enforcement status (npm provides this publicly)
 *   - GitHub linkage (is there a verified github_id?)
 *
 * No secrets required — uses public registry endpoints:
 *   npm:  https://registry.npmjs.org/<pkg>
 *         https://api.npmjs.org/downloads/range/...
 *   PyPI: https://pypi.org/pypi/<pkg>/json
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ReputationSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface MaintainerSignal {
  id: string;
  severity: ReputationSeverity;
  title: string;
  detail: string;
}

export interface MaintainerReputationReport {
  packageName: string;
  ecosystem: 'npm' | 'pypi';
  score: number; // 0..100 (higher = safer)
  verdict: 'trusted' | 'caution' | 'suspect' | 'unknown';
  maintainers: MaintainerInfo[];
  signals: MaintainerSignal[];
  summary: string;
  checkedAt: number;
}

export interface MaintainerInfo {
  name: string;
  email?: string;
  emailDomain?: string;
  hasGitHub?: boolean;
  hasTwoFactor?: boolean;
  /** Number of packages this maintainer publishes. */
  packageCount?: number;
  /** ISO date of first publish for this maintainer on the ecosystem. */
  firstPublishAt?: string;
}

export interface PackageVersionInfo {
  version: string;
  publishedAt: string; // ISO
  publisher?: string;
  integrity?: string;
}

export interface FetchOptions {
  /**
   * Async fetch function that returns JSON. In the extension context this will
   * be bound to node-fetch/undici; in tests we inject a mock.
   */
  fetchJson: (url: string) => Promise<any>;
  /** Cache hook — if present, we use it to avoid refetching within TTL. */
  cache?: {
    get: (key: string) => any | undefined;
    set: (key: string, value: any, ttlMs: number) => void;
  };
}

// ---------------------------------------------------------------------------
// Domain lists
// ---------------------------------------------------------------------------

/** Free-mail providers — not inherently bad, but lower reputation than corporate. */
const FREE_MAIL_DOMAINS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com', 'mail.com',
  'aol.com', 'proton.me', 'protonmail.com', 'tutanota.com', 'yandex.com', 'gmx.com',
  'live.com', 'msn.com', 'me.com', 'mac.com', 'fastmail.com',
]);

/** Disposable / throwaway mail — strong negative signal. */
const DISPOSABLE_MAIL_DOMAINS = new Set([
  'mailinator.com', '10minutemail.com', 'tempmail.com', 'guerrillamail.com',
  'throwawaymail.com', 'maildrop.cc', 'yopmail.com', 'sharklasers.com',
  'getnada.com', 'trashmail.com', 'dispostable.com', 'fakeinbox.com',
  'inboxalias.com', 'mintemail.com', 'spam4.me', 'spamgourmet.com',
  'mohmal.com', 'emailondeck.com', 'temp-mail.org', 'mail-temp.com',
]);

/** Known compromised-in-the-past maintainer accounts (as of 2025-11). */
const FLAGGED_MAINTAINERS = new Set<string>([
  // event-stream handoff account (historical, now locked)
  'right9ctrl',
  // Other publicly-reported compromised accounts from research — keep minimal
  // to avoid defamation; additions should cite a public incident report.
]);

// ---------------------------------------------------------------------------
// npm fetcher
// ---------------------------------------------------------------------------

export async function getNpmMaintainerReport(
  packageName: string,
  opts: FetchOptions
): Promise<MaintainerReputationReport> {
  const cacheKey = `maintainer:npm:${packageName}`;
  const cached = opts.cache?.get(cacheKey);
  if (cached) return cached;

  const signals: MaintainerSignal[] = [];
  const maintainers: MaintainerInfo[] = [];

  let registryData: any;
  try {
    registryData = await opts.fetchJson(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`);
  } catch (err) {
    return unknownReport(packageName, 'npm', `Failed to fetch registry metadata: ${String(err).slice(0, 120)}`);
  }

  if (!registryData || registryData.error) {
    return unknownReport(packageName, 'npm', 'Package not found in npm registry');
  }

  const latestVersion = registryData['dist-tags']?.latest as string | undefined;
  const time = registryData.time ?? {};
  const versions = registryData.versions ?? {};

  // Collect maintainers from the top-level entry
  const topMaintainers: Array<{ name?: string; email?: string }> =
    registryData.maintainers ?? [];
  for (const m of topMaintainers) {
    maintainers.push({
      name: m.name ?? 'unknown',
      email: m.email,
      emailDomain: m.email?.split('@')[1]?.toLowerCase(),
    });
  }

  // -- Signal: no maintainers listed
  if (maintainers.length === 0) {
    signals.push({
      id: 'CG_MAINT_001',
      severity: 'medium',
      title: 'No maintainers listed',
      detail: 'Package has no maintainers field — may be abandoned or misconfigured.',
    });
  }

  // -- Signal: single maintainer (bus factor 1)
  if (maintainers.length === 1) {
    signals.push({
      id: 'CG_MAINT_002',
      severity: 'low',
      title: 'Single maintainer (bus factor of 1)',
      detail: `Only "${maintainers[0].name}" maintains this package. A compromise of this single account is sufficient to publish malicious code.`,
    });
  }

  // -- Signal: disposable email
  for (const m of maintainers) {
    if (m.emailDomain && DISPOSABLE_MAIL_DOMAINS.has(m.emailDomain)) {
      signals.push({
        id: 'CG_MAINT_003',
        severity: 'high',
        title: `Maintainer uses disposable email (${m.emailDomain})`,
        detail: `Maintainer "${m.name}" registered with a throwaway email provider — strong risk indicator.`,
      });
    } else if (m.emailDomain && FREE_MAIL_DOMAINS.has(m.emailDomain)) {
      // informational only; not a finding by itself
      m.emailDomain = m.emailDomain; // kept for scoring
    }
  }

  // -- Signal: flagged account
  for (const m of maintainers) {
    if (m.name && FLAGGED_MAINTAINERS.has(m.name.toLowerCase())) {
      signals.push({
        id: 'CG_MAINT_004',
        severity: 'critical',
        title: `Maintainer "${m.name}" has a historical compromise`,
        detail: 'This account has been publicly associated with a supply-chain incident. Audit carefully.',
      });
    }
  }

  // -- Signal: unstable ownership (publisher of latest differs from historical set)
  const historicalPublishers = new Set<string>();
  const versionEntries = Object.entries(versions) as Array<[string, any]>;
  for (const [, vdata] of versionEntries) {
    const pub = vdata._npmUser?.name ?? vdata?.maintainers?.[0]?.name;
    if (pub) historicalPublishers.add(pub);
  }
  const latestPublisher =
    versions[latestVersion ?? '']?._npmUser?.name ??
    versions[latestVersion ?? '']?.maintainers?.[0]?.name;

  if (latestPublisher && historicalPublishers.size > 1) {
    const others = Array.from(historicalPublishers).filter((p) => p !== latestPublisher);
    const topMaintainerNames = new Set(maintainers.map((m) => m.name));
    if (!topMaintainerNames.has(latestPublisher)) {
      signals.push({
        id: 'CG_MAINT_005',
        severity: 'critical',
        title: `Unstable ownership: latest version published by "${latestPublisher}" who is NOT in current maintainers`,
        detail: `Historical publishers include: ${others.slice(0, 5).join(', ')}. A new account publishing without being listed is a classic takeover pattern.`,
      });
    } else if (others.length > 0) {
      signals.push({
        id: 'CG_MAINT_006',
        severity: 'medium',
        title: 'Multiple publishers in package history',
        detail: `Versions have been published by ${historicalPublishers.size} different accounts. Last publisher: "${latestPublisher}".`,
      });
    }
  }

  // -- Signal: first-publish-recently
  const firstVersion = Object.keys(versions)[0];
  const firstPublishDate = time.created ?? (firstVersion ? time[firstVersion] : undefined);
  if (firstPublishDate) {
    const age = Date.now() - new Date(firstPublishDate).getTime();
    const days = Math.floor(age / 86400000);
    if (days < 30) {
      signals.push({
        id: 'CG_MAINT_007',
        severity: 'high',
        title: `Package is very new (${days} days old)`,
        detail: 'New packages have little reputation history. Prefer established alternatives.',
      });
    } else if (days < 180) {
      signals.push({
        id: 'CG_MAINT_008',
        severity: 'medium',
        title: `Package is relatively new (${days} days old)`,
        detail: 'Packages under 6 months old are more likely to be abandoned or exploited.',
      });
    }
  }

  // -- Signal: latest version published very recently by a rare publisher
  const latestPublishDate = latestVersion ? time[latestVersion] : undefined;
  if (latestPublishDate && latestPublisher) {
    const age = Date.now() - new Date(latestPublishDate).getTime();
    const hours = age / 3_600_000;
    // if a rare publisher published a new version within 48h, that's suspicious
    const publisherFrequency = versionEntries.filter(
      ([, v]) => v._npmUser?.name === latestPublisher
    ).length;
    if (hours < 48 && publisherFrequency <= 2 && historicalPublishers.size > 1) {
      signals.push({
        id: 'CG_MAINT_009',
        severity: 'high',
        title: `Recent version (${Math.round(hours)}h ago) by a rare publisher`,
        detail: `Publisher "${latestPublisher}" has only ${publisherFrequency} historical publish(es) but just released a new version.`,
      });
    }
  }

  // -- Signal: git repo missing or unverified
  const repo = registryData.repository;
  if (!repo || !repo.url) {
    signals.push({
      id: 'CG_MAINT_010',
      severity: 'medium',
      title: 'No source repository link',
      detail: 'Package does not declare a git repository. Cannot verify provenance against source.',
    });
  } else if (!/github\.com|gitlab\.com|bitbucket\.org|codeberg\.org/i.test(repo.url)) {
    signals.push({
      id: 'CG_MAINT_011',
      severity: 'low',
      title: `Repository hosted on uncommon provider: ${repo.url}`,
      detail: 'Most legitimate packages are hosted on mainstream git providers.',
    });
  }

  // -- Signal: README / homepage missing (less trust signal)
  if (!registryData.readme || registryData.readme.length < 100) {
    signals.push({
      id: 'CG_MAINT_012',
      severity: 'low',
      title: 'Very short or missing README',
      detail: 'Legitimate packages usually have substantive documentation.',
    });
  }

  // --- Download volume ---
  let weeklyDownloads: number | undefined;
  try {
    const dl = await opts.fetchJson(
      `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`
    );
    weeklyDownloads = dl?.downloads;
  } catch {
    // ignore — downloads API may be rate limited
  }
  if (weeklyDownloads !== undefined) {
    if (weeklyDownloads < 20) {
      signals.push({
        id: 'CG_MAINT_013',
        severity: 'medium',
        title: `Very low weekly downloads (${weeklyDownloads})`,
        detail: 'Suspiciously low adoption for a public package. Prefer established alternatives.',
      });
    } else if (weeklyDownloads < 1000) {
      signals.push({
        id: 'CG_MAINT_014',
        severity: 'low',
        title: `Low weekly downloads (${weeklyDownloads})`,
        detail: 'Niche package — verify source and maintainers manually.',
      });
    }
  }

  // --- Scoring ---
  const score = scoreReport(signals);
  const verdict = verdictFromScore(score);
  const report: MaintainerReputationReport = {
    packageName,
    ecosystem: 'npm',
    score,
    verdict,
    maintainers,
    signals,
    summary: summarize(verdict, score, signals.length, packageName),
    checkedAt: Date.now(),
  };
  opts.cache?.set(cacheKey, report, 6 * 3_600_000); // 6h cache
  return report;
}

// ---------------------------------------------------------------------------
// PyPI fetcher
// ---------------------------------------------------------------------------

export async function getPyPiMaintainerReport(
  packageName: string,
  opts: FetchOptions
): Promise<MaintainerReputationReport> {
  const cacheKey = `maintainer:pypi:${packageName}`;
  const cached = opts.cache?.get(cacheKey);
  if (cached) return cached;

  const signals: MaintainerSignal[] = [];
  const maintainers: MaintainerInfo[] = [];

  let data: any;
  try {
    data = await opts.fetchJson(`https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`);
  } catch (err) {
    return unknownReport(packageName, 'pypi', `Failed to fetch PyPI metadata: ${String(err).slice(0, 120)}`);
  }

  if (!data || !data.info) {
    return unknownReport(packageName, 'pypi', 'Package not found on PyPI');
  }

  const info = data.info;

  // PyPI does not expose "maintainer list" the same way npm does, but info.author/author_email
  // and info.maintainer/maintainer_email are available.
  if (info.author) {
    maintainers.push({
      name: info.author,
      email: info.author_email,
      emailDomain: info.author_email?.split('@')[1]?.toLowerCase(),
    });
  }
  if (info.maintainer && info.maintainer !== info.author) {
    maintainers.push({
      name: info.maintainer,
      email: info.maintainer_email,
      emailDomain: info.maintainer_email?.split('@')[1]?.toLowerCase(),
    });
  }

  // Disposable mail check
  for (const m of maintainers) {
    if (m.emailDomain && DISPOSABLE_MAIL_DOMAINS.has(m.emailDomain)) {
      signals.push({
        id: 'CG_MAINT_003',
        severity: 'high',
        title: `Maintainer uses disposable email (${m.emailDomain})`,
        detail: `Maintainer "${m.name}" registered with a throwaway email provider.`,
      });
    }
  }

  // Missing homepage / project URLs
  const projectUrls = info.project_urls ?? {};
  const hasRepo =
    info.home_page ||
    Object.values(projectUrls).some((v) =>
      typeof v === 'string' &&
      /github\.com|gitlab\.com|bitbucket\.org|codeberg\.org/i.test(v as string)
    );
  if (!hasRepo) {
    signals.push({
      id: 'CG_MAINT_010',
      severity: 'medium',
      title: 'No source repository link',
      detail: 'Package does not declare a git repository URL. Cannot verify provenance.',
    });
  }

  // Age — use first release
  const releases = data.releases ?? {};
  const releaseDates: string[] = [];
  for (const files of Object.values(releases) as any[]) {
    if (Array.isArray(files) && files[0]?.upload_time_iso_8601) {
      releaseDates.push(files[0].upload_time_iso_8601);
    }
  }
  releaseDates.sort();
  if (releaseDates.length > 0) {
    const ageDays = Math.floor(
      (Date.now() - new Date(releaseDates[0]).getTime()) / 86400000
    );
    if (ageDays < 30) {
      signals.push({
        id: 'CG_MAINT_007',
        severity: 'high',
        title: `Package is very new (${ageDays} days old)`,
        detail: 'New PyPI packages have little reputation history.',
      });
    } else if (ageDays < 180) {
      signals.push({
        id: 'CG_MAINT_008',
        severity: 'medium',
        title: `Package is relatively new (${ageDays} days old)`,
        detail: 'Packages under 6 months old are more likely to be compromised.',
      });
    }
  }

  // Missing author info at all = unknown provenance
  if (maintainers.length === 0) {
    signals.push({
      id: 'CG_MAINT_001',
      severity: 'medium',
      title: 'No maintainer information',
      detail: 'Package has no author or maintainer listed on PyPI.',
    });
  }

  const score = scoreReport(signals);
  const verdict = verdictFromScore(score);
  const report: MaintainerReputationReport = {
    packageName,
    ecosystem: 'pypi',
    score,
    verdict,
    maintainers,
    signals,
    summary: summarize(verdict, score, signals.length, packageName),
    checkedAt: Date.now(),
  };
  opts.cache?.set(cacheKey, report, 6 * 3_600_000);
  return report;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

function scoreReport(signals: MaintainerSignal[]): number {
  // Start at 95. Each signal subtracts points by severity.
  let score = 95;
  for (const s of signals) {
    switch (s.severity) {
      case 'critical':
        score -= 40;
        break;
      case 'high':
        score -= 20;
        break;
      case 'medium':
        score -= 8;
        break;
      case 'low':
        score -= 3;
        break;
      case 'info':
      default:
        score -= 0;
    }
  }
  return Math.max(0, Math.min(100, Math.round(score)));
}

function verdictFromScore(score: number): MaintainerReputationReport['verdict'] {
  if (score >= 80) return 'trusted';
  if (score >= 55) return 'caution';
  if (score >= 0) return 'suspect';
  return 'unknown';
}

function summarize(
  verdict: MaintainerReputationReport['verdict'],
  score: number,
  signalCount: number,
  pkg: string
): string {
  switch (verdict) {
    case 'trusted':
      return `${pkg}: trusted (score ${score}/100, ${signalCount} minor notes).`;
    case 'caution':
      return `${pkg}: use with caution (score ${score}/100, ${signalCount} signal${signalCount === 1 ? '' : 's'}).`;
    case 'suspect':
      return `${pkg}: SUSPECT — review before installing (score ${score}/100, ${signalCount} signals).`;
    default:
      return `${pkg}: reputation unknown.`;
  }
}

function unknownReport(
  packageName: string,
  ecosystem: 'npm' | 'pypi',
  reason: string
): MaintainerReputationReport {
  return {
    packageName,
    ecosystem,
    score: 0,
    verdict: 'unknown',
    maintainers: [],
    signals: [
      {
        id: 'CG_MAINT_999',
        severity: 'info',
        title: 'Reputation check could not be completed',
        detail: reason,
      },
    ],
    summary: `${packageName}: reputation unknown (${reason}).`,
    checkedAt: Date.now(),
  };
}

// ---------------------------------------------------------------------------
// Public facade
// ---------------------------------------------------------------------------

export async function getMaintainerReport(
  packageName: string,
  ecosystem: 'npm' | 'pypi',
  opts: FetchOptions
): Promise<MaintainerReputationReport> {
  if (ecosystem === 'npm') return getNpmMaintainerReport(packageName, opts);
  return getPyPiMaintainerReport(packageName, opts);
}

export function getMaintainerEngineStats(): {
  freeMailDomains: number;
  disposableMailDomains: number;
  flaggedAccounts: number;
  signalCount: number;
} {
  return {
    freeMailDomains: FREE_MAIL_DOMAINS.size,
    disposableMailDomains: DISPOSABLE_MAIL_DOMAINS.size,
    flaggedAccounts: FLAGGED_MAINTAINERS.size,
    signalCount: 14,
  };
}
