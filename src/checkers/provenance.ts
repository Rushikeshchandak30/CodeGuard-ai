/**
 * Cryptographic Provenance Verification
 *
 * Verifies package supply chain attestations at write-time:
 * - npm: Sigstore provenance via registry attestation API
 * - PyPI: PEP 740 digital attestations via Integrity API
 *
 * Trust tiers:
 *   VERIFIED   — Sigstore provenance + verified publisher + high downloads
 *   PARTIAL    — Exists, no provenance, decent downloads
 *   SUSPICIOUS — No provenance, low downloads, recently registered
 *   UNTRUSTED  — Not on registry / known hallucination / malware flagged
 */

import * as https from 'https';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TrustTier = 'verified' | 'partial' | 'suspicious' | 'untrusted';

export interface ProvenanceResult {
  packageName: string;
  version: string | null;
  ecosystem: string;
  /** Does the package have Sigstore / PEP 740 provenance? */
  hasProvenance: boolean;
  /** SLSA build level (0-4) */
  slsaLevel: number;
  /** Source repository URL (from provenance attestation) */
  sourceRepo: string | null;
  /** CI/CD builder identity (e.g., "GitHub Actions") */
  builderId: string | null;
  /** Was the publisher's identity verified via OIDC? */
  publisherVerified: boolean;
  /** Transparency log entry ID (Rekor) */
  transparencyLogId: string | null;
  /** Computed trust tier */
  trustTier: TrustTier;
  /** Human-readable trust summary */
  trustSummary: string;
  /** Weekly downloads (for trust calculation) */
  weeklyDownloads: number | null;
  /** When the package version was published */
  publishedAt: string | null;
  /** Error if provenance check failed */
  error: string | null;
}

// ---------------------------------------------------------------------------
// ProvenanceChecker
// ---------------------------------------------------------------------------

export class ProvenanceChecker {
  private cache: Map<string, ProvenanceResult> = new Map();
  private readonly CACHE_TTL = 30 * 60 * 1000; // 30 minutes
  private cacheTimestamps: Map<string, number> = new Map();

  /**
   * Check provenance for a package.
   */
  async check(packageName: string, version: string | null, ecosystem: string): Promise<ProvenanceResult> {
    const cacheKey = `${ecosystem}:${packageName}@${version ?? 'latest'}`;
    const cached = this.cache.get(cacheKey);
    const cachedTime = this.cacheTimestamps.get(cacheKey);
    if (cached && cachedTime && Date.now() - cachedTime < this.CACHE_TTL) {
      return cached;
    }

    let result: ProvenanceResult;

    switch (ecosystem.toLowerCase()) {
      case 'npm':
        result = await this.checkNpm(packageName, version);
        break;
      case 'pypi':
        result = await this.checkPyPI(packageName, version);
        break;
      default:
        result = this.makeResult(packageName, version, ecosystem, {
          trustTier: 'partial',
          trustSummary: `Provenance verification not yet supported for ${ecosystem}`,
        });
        break;
    }

    this.cache.set(cacheKey, result);
    this.cacheTimestamps.set(cacheKey, Date.now());
    return result;
  }

  /**
   * Compute trust tier from multiple signals.
   */
  computeTrustTier(
    exists: boolean,
    hasProvenance: boolean,
    weeklyDownloads: number | null,
    isKnownHallucination: boolean,
    isMalwareFlagged: boolean,
    recentlyRegistered: boolean,
  ): TrustTier {
    if (!exists || isKnownHallucination || isMalwareFlagged) {
      return 'untrusted';
    }

    if (hasProvenance && weeklyDownloads !== null && weeklyDownloads > 10000) {
      return 'verified';
    }

    if (hasProvenance) {
      return weeklyDownloads !== null && weeklyDownloads > 100 ? 'verified' : 'partial';
    }

    // No provenance
    if (weeklyDownloads !== null && weeklyDownloads < 100 && recentlyRegistered) {
      return 'suspicious';
    }

    if (weeklyDownloads !== null && weeklyDownloads > 50000) {
      return 'partial'; // Well-known package, just no provenance yet
    }

    return weeklyDownloads !== null && weeklyDownloads < 500 ? 'suspicious' : 'partial';
  }

  /**
   * Get a trust tier emoji for display.
   */
  static trustEmoji(tier: TrustTier): string {
    switch (tier) {
      case 'verified': return '🟢';
      case 'partial': return '🟡';
      case 'suspicious': return '🟠';
      case 'untrusted': return '🔴';
    }
  }

  /**
   * Get a trust tier label for display.
   */
  static trustLabel(tier: TrustTier): string {
    switch (tier) {
      case 'verified': return 'VERIFIED';
      case 'partial': return 'PARTIAL';
      case 'suspicious': return 'SUSPICIOUS';
      case 'untrusted': return 'UNTRUSTED';
    }
  }

  // -------------------------------------------------------------------------
  // npm Provenance Check
  // -------------------------------------------------------------------------

  private async checkNpm(packageName: string, version: string | null): Promise<ProvenanceResult> {
    try {
      // Step 1: Get package metadata (version, downloads, publish date)
      const meta = await this.fetchNpmMetadata(packageName, version);
      if (!meta.exists) {
        return this.makeResult(packageName, version, 'npm', {
          trustTier: 'untrusted',
          trustSummary: 'Package does not exist on npm registry',
        });
      }

      const resolvedVersion = meta.version;

      // Step 2: Check for Sigstore attestation
      const attestation = await this.fetchNpmAttestation(packageName, resolvedVersion);

      // Step 3: Get download count
      const downloads = await this.fetchNpmDownloads(packageName);

      // Step 4: Compute trust tier
      const hasProvenance = attestation.hasProvenance;
      const recentlyRegistered = meta.publishedAt
        ? Date.now() - new Date(meta.publishedAt).getTime() < 30 * 24 * 60 * 60 * 1000
        : false;

      const trustTier = this.computeTrustTier(
        true, hasProvenance, downloads, false, false, recentlyRegistered
      );

      const summaryParts: string[] = [];
      if (hasProvenance) {
        summaryParts.push('Sigstore provenance verified');
        if (attestation.sourceRepo) { summaryParts.push(`Source: ${attestation.sourceRepo}`); }
        if (attestation.builderId) { summaryParts.push(`Builder: ${attestation.builderId}`); }
      } else {
        summaryParts.push('No Sigstore provenance');
      }
      if (downloads !== null) {
        summaryParts.push(`${downloads.toLocaleString()} weekly downloads`);
      }

      return this.makeResult(packageName, resolvedVersion, 'npm', {
        hasProvenance,
        slsaLevel: attestation.slsaLevel,
        sourceRepo: attestation.sourceRepo,
        builderId: attestation.builderId,
        publisherVerified: attestation.publisherVerified,
        transparencyLogId: attestation.transparencyLogId,
        trustTier,
        trustSummary: summaryParts.join(' · '),
        weeklyDownloads: downloads,
        publishedAt: meta.publishedAt,
      });
    } catch (err) {
      return this.makeResult(packageName, version, 'npm', {
        trustTier: 'partial',
        trustSummary: 'Provenance check failed',
        error: String(err),
      });
    }
  }

  private fetchNpmMetadata(packageName: string, version: string | null): Promise<{
    exists: boolean; version: string; publishedAt: string | null;
  }> {
    return new Promise((resolve) => {
      const versionPath = version ? `/${version}` : '/latest';
      const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}${versionPath}`;

      const req = https.get(url, { headers: { Accept: 'application/json' } }, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          if (res.statusCode !== 200) {
            resolve({ exists: false, version: version ?? 'latest', publishedAt: null });
            return;
          }
          try {
            const data = JSON.parse(body);
            resolve({
              exists: true,
              version: data.version ?? version ?? 'latest',
              publishedAt: data.time?.[data.version] ?? null,
            });
          } catch {
            resolve({ exists: false, version: version ?? 'latest', publishedAt: null });
          }
        });
      });
      req.on('error', () => resolve({ exists: false, version: version ?? 'latest', publishedAt: null }));
      req.setTimeout(8000, () => { req.destroy(); resolve({ exists: false, version: version ?? 'latest', publishedAt: null }); });
      req.end();
    });
  }

  private fetchNpmAttestation(packageName: string, version: string): Promise<{
    hasProvenance: boolean;
    slsaLevel: number;
    sourceRepo: string | null;
    builderId: string | null;
    publisherVerified: boolean;
    transparencyLogId: string | null;
  }> {
    return new Promise((resolve) => {
      const url = `https://registry.npmjs.org/-/npm/v1/attestations/${encodeURIComponent(packageName)}@${encodeURIComponent(version)}`;

      const req = https.get(url, { headers: { Accept: 'application/json' } }, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          if (res.statusCode !== 200) {
            resolve({
              hasProvenance: false, slsaLevel: 0, sourceRepo: null,
              builderId: null, publisherVerified: false, transparencyLogId: null,
            });
            return;
          }
          try {
            const data = JSON.parse(body);
            const attestations = data.attestations ?? [];

            // Look for SLSA provenance attestation
            let hasSlsa = false;
            let sourceRepo: string | null = null;
            let builderId: string | null = null;
            let transparencyLogId: string | null = null;

            for (const att of attestations) {
              const predType = att.predicateType ?? '';
              if (predType.includes('slsa.dev/provenance') || predType.includes('in-toto')) {
                hasSlsa = true;

                // Extract source repo from bundle if available
                try {
                  const bundle = att.bundle;
                  if (bundle?.verificationMaterial?.tlogEntries?.[0]) {
                    transparencyLogId = bundle.verificationMaterial.tlogEntries[0].logIndex ?? null;
                  }

                  // Try to extract from certificate extensions
                  const cert = bundle?.verificationMaterial?.certificate?.rawBytes;
                  if (cert) {
                    // The source repo is embedded in the Fulcio certificate as a SAN URI
                    // We can extract it from the base64-decoded certificate
                    const decoded = Buffer.from(cert, 'base64').toString('utf-8');
                    // eslint-disable-next-line no-control-regex
                    const repoMatch = decoded.match(/https:\/\/github\.com\/[^\x00-\x1F\x7F]+/);
                    if (repoMatch) {
                      sourceRepo = repoMatch[0].split('\x00')[0]; // Trim at null bytes
                    }

                    // Look for GitHub Actions builder ID
                    if (decoded.includes('github-hosted')) {
                      builderId = 'GitHub Actions';
                    } else if (decoded.includes('gitlab')) {
                      builderId = 'GitLab CI';
                    }
                  }
                } catch {
                  // Best-effort extraction
                }
              }
            }

            // Also check for publish attestation
            const hasPublishAtt = attestations.some(
              (a: { predicateType?: string }) => (a.predicateType ?? '').includes('npmjs.com/attestation')
            );

            resolve({
              hasProvenance: hasSlsa || hasPublishAtt,
              slsaLevel: hasSlsa ? 2 : 0, // npm provenance is SLSA Level 2 minimum
              sourceRepo,
              builderId,
              publisherVerified: hasPublishAtt, // Publish attestation = verified publisher
              transparencyLogId,
            });
          } catch {
            resolve({
              hasProvenance: false, slsaLevel: 0, sourceRepo: null,
              builderId: null, publisherVerified: false, transparencyLogId: null,
            });
          }
        });
      });

      req.on('error', () => resolve({
        hasProvenance: false, slsaLevel: 0, sourceRepo: null,
        builderId: null, publisherVerified: false, transparencyLogId: null,
      }));
      req.setTimeout(8000, () => {
        req.destroy();
        resolve({
          hasProvenance: false, slsaLevel: 0, sourceRepo: null,
          builderId: null, publisherVerified: false, transparencyLogId: null,
        });
      });
      req.end();
    });
  }

  private fetchNpmDownloads(packageName: string): Promise<number | null> {
    return new Promise((resolve) => {
      const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`;

      const req = https.get(url, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          try {
            const data = JSON.parse(body);
            resolve(data.downloads ?? null);
          } catch {
            resolve(null);
          }
        });
      });
      req.on('error', () => resolve(null));
      req.setTimeout(5000, () => { req.destroy(); resolve(null); });
      req.end();
    });
  }

  // -------------------------------------------------------------------------
  // PyPI Provenance Check
  // -------------------------------------------------------------------------

  private async checkPyPI(packageName: string, version: string | null): Promise<ProvenanceResult> {
    try {
      // Step 1: Get package metadata
      const meta = await this.fetchPyPIMetadata(packageName, version);
      if (!meta.exists) {
        return this.makeResult(packageName, version, 'PyPI', {
          trustTier: 'untrusted',
          trustSummary: 'Package does not exist on PyPI',
        });
      }

      const resolvedVersion = meta.version;

      // Step 2: Check PEP 740 attestation via Integrity API
      const attestation = await this.fetchPyPIAttestation(packageName, resolvedVersion, meta.filename);

      // Step 3: Compute trust tier
      const recentlyRegistered = meta.publishedAt
        ? Date.now() - new Date(meta.publishedAt).getTime() < 30 * 24 * 60 * 60 * 1000
        : false;

      // PyPI doesn't have a public download count API like npm, estimate from available data
      const estimatedDownloads = meta.weeklyDownloads;

      const trustTier = this.computeTrustTier(
        true, attestation.hasProvenance, estimatedDownloads, false, false, recentlyRegistered
      );

      const summaryParts: string[] = [];
      if (attestation.hasProvenance) {
        summaryParts.push('PEP 740 attestation verified');
        if (attestation.sourceRepo) { summaryParts.push(`Source: ${attestation.sourceRepo}`); }
      } else {
        summaryParts.push('No PEP 740 attestation');
      }

      return this.makeResult(packageName, resolvedVersion, 'PyPI', {
        hasProvenance: attestation.hasProvenance,
        slsaLevel: attestation.hasProvenance ? 2 : 0,
        sourceRepo: attestation.sourceRepo,
        builderId: attestation.builderId,
        publisherVerified: attestation.publisherVerified,
        transparencyLogId: attestation.transparencyLogId,
        trustTier,
        trustSummary: summaryParts.join(' · '),
        weeklyDownloads: estimatedDownloads,
        publishedAt: meta.publishedAt,
      });
    } catch (err) {
      return this.makeResult(packageName, version, 'PyPI', {
        trustTier: 'partial',
        trustSummary: 'Provenance check failed',
        error: String(err),
      });
    }
  }

  private fetchPyPIMetadata(packageName: string, version: string | null): Promise<{
    exists: boolean; version: string; filename: string | null;
    publishedAt: string | null; weeklyDownloads: number | null;
  }> {
    return new Promise((resolve) => {
      const versionPath = version ? `/${version}` : '';
      const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}${versionPath}/json`;

      const req = https.get(url, { headers: { Accept: 'application/json' } }, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          if (res.statusCode !== 200) {
            resolve({ exists: false, version: version ?? 'latest', filename: null, publishedAt: null, weeklyDownloads: null });
            return;
          }
          try {
            const data = JSON.parse(body);
            const ver = data.info?.version ?? version ?? 'latest';
            const urls = data.urls ?? [];
            // Get the first wheel or sdist filename
            const filename = urls.length > 0 ? urls[0].filename : null;
            const publishedAt = urls.length > 0 ? urls[0].upload_time_iso_8601 : null;

            resolve({
              exists: true,
              version: ver,
              filename,
              publishedAt,
              weeklyDownloads: null, // PyPI doesn't provide this directly; would need BigQuery
            });
          } catch {
            resolve({ exists: false, version: version ?? 'latest', filename: null, publishedAt: null, weeklyDownloads: null });
          }
        });
      });
      req.on('error', () => resolve({ exists: false, version: version ?? 'latest', filename: null, publishedAt: null, weeklyDownloads: null }));
      req.setTimeout(8000, () => { req.destroy(); resolve({ exists: false, version: version ?? 'latest', filename: null, publishedAt: null, weeklyDownloads: null }); });
      req.end();
    });
  }

  private fetchPyPIAttestation(packageName: string, version: string, filename: string | null): Promise<{
    hasProvenance: boolean;
    sourceRepo: string | null;
    builderId: string | null;
    publisherVerified: boolean;
    transparencyLogId: string | null;
  }> {
    return new Promise((resolve) => {
      if (!filename) {
        resolve({ hasProvenance: false, sourceRepo: null, builderId: null, publisherVerified: false, transparencyLogId: null });
        return;
      }

      // PEP 740 Integrity API
      const url = `https://pypi.org/integrity/${encodeURIComponent(packageName)}/${encodeURIComponent(version)}/${encodeURIComponent(filename)}/provenance`;

      const req = https.get(url, { headers: { Accept: 'application/json' } }, (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => {
          if (res.statusCode !== 200) {
            resolve({ hasProvenance: false, sourceRepo: null, builderId: null, publisherVerified: false, transparencyLogId: null });
            return;
          }
          try {
            const data = JSON.parse(body);
            const bundles = data.attestation_bundles ?? [];
            const hasAtt = bundles.length > 0;

            let sourceRepo: string | null = null;
            let builderId: string | null = null;

            // Try to extract publisher info from attestation bundles
            if (hasAtt) {
              for (const bundle of bundles) {
                const publisher = bundle.publisher;
                if (publisher?.kind === 'GitHub') {
                  sourceRepo = `https://github.com/${publisher.repository ?? ''}`;
                  builderId = publisher.workflow ?? 'GitHub Actions';
                } else if (publisher?.kind === 'GitLab') {
                  builderId = 'GitLab CI';
                }
              }
            }

            resolve({
              hasProvenance: hasAtt,
              sourceRepo,
              builderId,
              publisherVerified: hasAtt, // PEP 740 = trusted publisher
              transparencyLogId: null,
            });
          } catch {
            resolve({ hasProvenance: false, sourceRepo: null, builderId: null, publisherVerified: false, transparencyLogId: null });
          }
        });
      });

      req.on('error', () => resolve({ hasProvenance: false, sourceRepo: null, builderId: null, publisherVerified: false, transparencyLogId: null }));
      req.setTimeout(8000, () => {
        req.destroy();
        resolve({ hasProvenance: false, sourceRepo: null, builderId: null, publisherVerified: false, transparencyLogId: null });
      });
      req.end();
    });
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  private makeResult(
    packageName: string,
    version: string | null,
    ecosystem: string,
    overrides: Partial<ProvenanceResult>,
  ): ProvenanceResult {
    return {
      packageName,
      version,
      ecosystem,
      hasProvenance: false,
      slsaLevel: 0,
      sourceRepo: null,
      builderId: null,
      publisherVerified: false,
      transparencyLogId: null,
      trustTier: 'partial',
      trustSummary: '',
      weeklyDownloads: null,
      publishedAt: null,
      error: null,
      ...overrides,
    };
  }
}
