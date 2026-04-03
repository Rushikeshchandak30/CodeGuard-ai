/**
 * Composite Trust Score Engine
 *
 * Computes a unified 0-100 trust score per package by combining multiple signals:
 * - Provenance verification (Sigstore, PEP 740)
 * - Download count & velocity
 * - Publisher age (days since first publish)
 * - Install script presence & suspiciousness
 * - Typosquat distance to popular packages
 * - GitHub stars/forks
 * - Known hallucination status (GHIN)
 * - Known vulnerability count
 * - Version spike detection (sudden major version jumps)
 * - Recent ownership change
 *
 * Score replaces ad-hoc trust tier logic with a single deterministic engine.
 */

// ---------------------------------------------------------------------------
// Signal Types
// ---------------------------------------------------------------------------

export interface TrustSignals {
  // Provenance
  provenanceVerified?: boolean;       // Sigstore / PEP 740 attestation found
  slsaLevel?: number;                 // 0-3 SLSA provenance level
  verifiedPublisher?: boolean;        // Publisher identity verified via OIDC

  // Popularity
  weeklyDownloads?: number;
  downloadVelocity?: 'declining' | 'stable' | 'growing' | 'spike';

  // Age & maturity
  publisherAgeDays?: number;          // Days since first publish on registry
  packageAgeDays?: number;            // Days since this specific package first appeared
  totalVersions?: number;             // Number of published versions

  // Install scripts
  hasInstallScripts?: boolean;
  suspiciousScripts?: boolean;        // Script analyzer flagged something

  // Typosquatting
  typosquatDistance?: number;          // Levenshtein distance to closest popular pkg
  closestPopularPkg?: string;         // Name of the popular package it resembles

  // GitHub signals
  githubStars?: number;
  githubForks?: number;
  hasRepository?: boolean;

  // Security
  knownHallucination?: boolean;       // GHIN flagged as hallucinated
  vulnerabilityCount?: number;        // Active CVEs
  highestCveSeverity?: 'critical' | 'high' | 'medium' | 'low' | null;
  malwareFlagged?: boolean;           // Known malware

  // Ownership
  recentOwnershipChange?: boolean;    // npm/PyPI maintainer changed recently
  versionSpike?: boolean;             // Sudden major version jump (e.g., 1.0 → 50.0)

  // Registry
  registryExists?: boolean;           // Package exists on its registry
}

export type TrustTier = 'verified' | 'partial' | 'suspicious' | 'untrusted';

export interface TrustScoreResult {
  score: number;            // 0-100
  tier: TrustTier;
  label: string;            // "Verified", "Partial Trust", "Suspicious", "Untrusted"
  emoji: string;            // 🟢 🟡 🟠 🔴
  signals: TrustSignals;
  breakdown: TrustBreakdown;
  reasons: string[];        // Human-readable reasons for the score
}

export interface TrustBreakdown {
  provenance: number;       // 0-25 points
  popularity: number;       // 0-25 points
  maturity: number;         // 0-20 points
  security: number;         // 0-20 points
  codeQuality: number;      // 0-10 points
}

// ---------------------------------------------------------------------------
// Weight Configuration
// ---------------------------------------------------------------------------

const WEIGHTS = {
  provenance: 25,
  popularity: 25,
  maturity: 20,
  security: 20,
  codeQuality: 10,
};

// ---------------------------------------------------------------------------
// TrustScoreEngine
// ---------------------------------------------------------------------------

export class TrustScoreEngine {

  /**
   * Compute a composite 0-100 trust score from raw signals.
   */
  compute(signals: TrustSignals): TrustScoreResult {
    // Immediate disqualifiers
    if (signals.malwareFlagged) {
      return this.buildResult(0, signals, { provenance: 0, popularity: 0, maturity: 0, security: 0, codeQuality: 0 }, ['Package flagged as malware']);
    }
    if (signals.knownHallucination || signals.registryExists === false) {
      return this.buildResult(0, signals, { provenance: 0, popularity: 0, maturity: 0, security: 0, codeQuality: 0 },
        [signals.knownHallucination ? 'Known hallucinated package (GHIN)' : 'Package does not exist on registry']);
    }

    const reasons: string[] = [];
    const breakdown: TrustBreakdown = {
      provenance: this.scoreProvenance(signals, reasons),
      popularity: this.scorePopularity(signals, reasons),
      maturity: this.scoreMaturity(signals, reasons),
      security: this.scoreSecurity(signals, reasons),
      codeQuality: this.scoreCodeQuality(signals, reasons),
    };

    const raw = breakdown.provenance + breakdown.popularity + breakdown.maturity + breakdown.security + breakdown.codeQuality;
    const score = Math.round(Math.max(0, Math.min(100, raw)));

    return this.buildResult(score, signals, breakdown, reasons);
  }

  // ---------------------------------------------------------------------------
  // Sub-score Computations
  // ---------------------------------------------------------------------------

  private scoreProvenance(s: TrustSignals, reasons: string[]): number {
    let score = 0;
    const max = WEIGHTS.provenance;

    if (s.provenanceVerified) {
      score += 15;
      reasons.push('✅ Sigstore/PEP 740 provenance verified');
    } else {
      reasons.push('⚠️ No provenance attestation');
    }

    if (s.slsaLevel !== undefined) {
      score += Math.min(s.slsaLevel * 3, 6);  // 0-6 points for SLSA 0-3
    }

    if (s.verifiedPublisher) {
      score += 4;
      reasons.push('✅ Publisher identity verified via OIDC');
    }

    return Math.min(score, max);
  }

  private scorePopularity(s: TrustSignals, reasons: string[]): number {
    let score = 0;
    const max = WEIGHTS.popularity;

    if (s.weeklyDownloads !== undefined) {
      if (s.weeklyDownloads >= 1_000_000) {
        score += 15;
      } else if (s.weeklyDownloads >= 100_000) {
        score += 12;
      } else if (s.weeklyDownloads >= 10_000) {
        score += 8;
      } else if (s.weeklyDownloads >= 1_000) {
        score += 5;
      } else if (s.weeklyDownloads >= 100) {
        score += 2;
      } else {
        reasons.push('⚠️ Very low download count');
      }
    }

    if (s.githubStars !== undefined) {
      if (s.githubStars >= 10_000) { score += 5; }
      else if (s.githubStars >= 1_000) { score += 3; }
      else if (s.githubStars >= 100) { score += 1; }
    }

    if (s.hasRepository) { score += 2; }
    else { reasons.push('⚠️ No source repository linked'); }

    if (s.downloadVelocity === 'spike') {
      score -= 3;
      reasons.push('⚠️ Abnormal download spike detected');
    }

    return Math.max(0, Math.min(score, max));
  }

  private scoreMaturity(s: TrustSignals, reasons: string[]): number {
    let score = 0;
    const max = WEIGHTS.maturity;

    if (s.publisherAgeDays !== undefined) {
      if (s.publisherAgeDays >= 365) { score += 8; }
      else if (s.publisherAgeDays >= 90) { score += 5; }
      else if (s.publisherAgeDays >= 30) { score += 2; }
      else {
        reasons.push('⚠️ Publisher registered recently (<30 days)');
      }
    }

    if (s.packageAgeDays !== undefined) {
      if (s.packageAgeDays >= 365) { score += 5; }
      else if (s.packageAgeDays >= 90) { score += 3; }
      else if (s.packageAgeDays < 30) {
        reasons.push('⚠️ Package is very new (<30 days)');
      }
    }

    if (s.totalVersions !== undefined) {
      if (s.totalVersions >= 20) { score += 4; }
      else if (s.totalVersions >= 5) { score += 2; }
      else if (s.totalVersions <= 1) {
        reasons.push('⚠️ Only 1 published version');
      }
    }

    if (s.recentOwnershipChange) {
      score -= 5;
      reasons.push('🔴 Recent ownership/maintainer change');
    }

    if (s.versionSpike) {
      score -= 3;
      reasons.push('⚠️ Suspicious version spike');
    }

    return Math.max(0, Math.min(score, max));
  }

  private scoreSecurity(s: TrustSignals, reasons: string[]): number {
    let score = WEIGHTS.security; // Start at max, deduct

    if (s.vulnerabilityCount !== undefined && s.vulnerabilityCount > 0) {
      if (s.highestCveSeverity === 'critical') {
        score -= 15;
        reasons.push(`🔴 ${s.vulnerabilityCount} vulnerabilities (highest: CRITICAL)`);
      } else if (s.highestCveSeverity === 'high') {
        score -= 10;
        reasons.push(`🟠 ${s.vulnerabilityCount} vulnerabilities (highest: HIGH)`);
      } else {
        score -= 5;
        reasons.push(`🟡 ${s.vulnerabilityCount} vulnerabilities (highest: ${s.highestCveSeverity})`);
      }
    }

    return Math.max(0, score);
  }

  private scoreCodeQuality(s: TrustSignals, reasons: string[]): number {
    let score = WEIGHTS.codeQuality;

    if (s.hasInstallScripts) {
      score -= 3;
      reasons.push('⚠️ Package has install scripts');
    }

    if (s.suspiciousScripts) {
      score -= 7;
      reasons.push('🔴 Suspicious install scripts detected');
    }

    if (s.typosquatDistance !== undefined && s.typosquatDistance <= 2) {
      score -= 5;
      reasons.push(`⚠️ Name similar to popular package "${s.closestPopularPkg}" (distance: ${s.typosquatDistance})`);
    }

    return Math.max(0, score);
  }

  // ---------------------------------------------------------------------------
  // Result Builder
  // ---------------------------------------------------------------------------

  private buildResult(score: number, signals: TrustSignals, breakdown: TrustBreakdown, reasons: string[]): TrustScoreResult {
    let tier: TrustTier;
    let label: string;
    let emoji: string;

    if (score >= 80) {
      tier = 'verified'; label = 'Verified'; emoji = '🟢';
    } else if (score >= 50) {
      tier = 'partial'; label = 'Partial Trust'; emoji = '🟡';
    } else if (score >= 25) {
      tier = 'suspicious'; label = 'Suspicious'; emoji = '🟠';
    } else {
      tier = 'untrusted'; label = 'Untrusted'; emoji = '🔴';
    }

    return { score, tier, label, emoji, signals, breakdown, reasons };
  }

  /**
   * Format a trust score result as a markdown summary.
   */
  toMarkdown(result: TrustScoreResult): string {
    let md = `## ${result.emoji} Trust Score: ${result.score}/100 — ${result.label}\n\n`;
    md += `| Category | Score | Max |\n|----------|-------|-----|\n`;
    md += `| Provenance | ${result.breakdown.provenance} | ${WEIGHTS.provenance} |\n`;
    md += `| Popularity | ${result.breakdown.popularity} | ${WEIGHTS.popularity} |\n`;
    md += `| Maturity | ${result.breakdown.maturity} | ${WEIGHTS.maturity} |\n`;
    md += `| Security | ${result.breakdown.security} | ${WEIGHTS.security} |\n`;
    md += `| Code Quality | ${result.breakdown.codeQuality} | ${WEIGHTS.codeQuality} |\n\n`;

    if (result.reasons.length > 0) {
      md += `### Signals\n\n`;
      for (const r of result.reasons) {
        md += `- ${r}\n`;
      }
    }

    return md;
  }
}
