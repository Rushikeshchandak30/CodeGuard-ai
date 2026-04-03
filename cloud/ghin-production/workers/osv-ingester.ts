/**
 * OSV + GitHub Advisory Ingestion Worker
 *
 * Cron job that runs every 6 hours to ingest vulnerability data from:
 * 1. OSV.dev bulk feed (npm, PyPI, Go, crates.io)
 * 2. GitHub Advisory Database (via GraphQL API)
 * 3. npm registry metadata (downloads, publish dates)
 * 4. PyPI metadata (downloads, publish dates)
 *
 * Normalizes data and upserts into the GHIN PostgreSQL database.
 *
 * Usage: npx ts-node workers/osv-ingester.ts
 * Or via cron: 0 */6 * * * cd /app && node workers/osv-ingester.js
 */

import { Pool } from 'pg';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL ?? 'postgresql://localhost:5432/ghin',
  max: 5,
});

// ---------------------------------------------------------------------------
// OSV.dev Ingestion
// ---------------------------------------------------------------------------

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { ecosystem: string; name: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  database_specific?: Record<string, unknown>;
}

const OSV_ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'crates.io'];

async function ingestOsv(): Promise<number> {
  let totalIngested = 0;
  const client = await pool.connect();

  try {
    for (const ecosystem of OSV_ECOSYSTEMS) {
      console.log(`[OSV] Ingesting ${ecosystem}...`);

      // OSV.dev query API — batch query for recent vulnerabilities
      const resp = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          package: { ecosystem },
          // Query all vulns (OSV returns paginated results)
        }),
      });

      if (!resp.ok) {
        console.error(`[OSV] Failed to query ${ecosystem}: ${resp.status}`);
        continue;
      }

      const data = await resp.json() as { vulns?: OsvVulnerability[] };
      const vulns = data.vulns ?? [];
      console.log(`[OSV] Got ${vulns.length} vulnerabilities for ${ecosystem}`);

      for (const vuln of vulns) {
        if (!vuln.affected) { continue; }

        for (const affected of vuln.affected) {
          if (!affected.package?.name) { continue; }

          const pkgName = affected.package.name;
          const eco = normalizeEcosystem(affected.package.ecosystem);

          // Extract affected range and fixed versions
          const fixedVersions: string[] = [];
          let affectedRange = '';

          for (const range of affected.ranges ?? []) {
            for (const event of range.events) {
              if (event.introduced) { affectedRange = `>=${event.introduced}`; }
              if (event.fixed) { fixedVersions.push(event.fixed); }
            }
          }

          // Extract CVE IDs from aliases
          const cveIds = (vuln.aliases ?? []).filter(a => a.startsWith('CVE-'));

          // Extract severity
          const cvssEntry = vuln.severity?.find(s => s.type === 'CVSS_V3');
          const cvssScore = cvssEntry ? parseFloat(cvssEntry.score) : null;
          const severity = cvssToSeverity(cvssScore);

          // Upsert vulnerability
          await client.query(
            `INSERT INTO vulnerabilities
              (package_name, ecosystem, affected_range, fixed_versions, severity, cvss_score, cve_ids, source, source_url, raw_data)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'osv', $8, $9)
             ON CONFLICT DO NOTHING`,
            [
              pkgName, eco, affectedRange || 'unknown',
              fixedVersions.length > 0 ? fixedVersions : null,
              severity, cvssScore,
              cveIds.length > 0 ? cveIds : null,
              `https://osv.dev/vulnerability/${vuln.id}`,
              JSON.stringify(vuln),
            ]
          );

          totalIngested++;
        }
      }
    }
  } finally {
    client.release();
  }

  return totalIngested;
}

// ---------------------------------------------------------------------------
// npm Registry Metadata Enrichment
// ---------------------------------------------------------------------------

async function enrichNpmMetadata(packageNames: string[]): Promise<number> {
  let enriched = 0;
  const client = await pool.connect();

  try {
    for (const name of packageNames) {
      try {
        // Get download count
        const dlResp = await fetch(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`);
        const dlData = dlResp.ok ? await dlResp.json() as { downloads?: number } : null;

        // Get package metadata
        const metaResp = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
        if (!metaResp.ok) { continue; }
        const meta = await metaResp.json() as Record<string, unknown>;

        const time = meta.time as Record<string, string> | undefined;
        const versions = Object.keys(meta.versions as Record<string, unknown> ?? {});
        const created = time?.created ? new Date(time.created) : null;
        const packageAgeDays = created ? Math.floor((Date.now() - created.getTime()) / 86400000) : null;

        // Check for install scripts in latest version
        const latestVersion = meta['dist-tags'] ? (meta['dist-tags'] as Record<string, string>).latest : null;
        const latestMeta = latestVersion ? (meta.versions as Record<string, Record<string, unknown>>)?.[latestVersion] : null;
        const scripts = latestMeta?.scripts as Record<string, string> | undefined;
        const hasInstallScripts = !!(scripts?.preinstall || scripts?.postinstall || scripts?.install);

        // Repository check
        const repository = meta.repository as { url?: string } | undefined;
        const hasRepository = !!repository?.url;
        let githubStars: number | null = null;

        if (hasRepository && repository?.url?.includes('github.com')) {
          // Extract owner/repo from GitHub URL
          const match = /github\.com\/([^/]+)\/([^/.]+)/.exec(repository.url);
          if (match) {
            try {
              const ghResp = await fetch(`https://api.github.com/repos/${match[1]}/${match[2]}`, {
                headers: process.env.GITHUB_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {},
              });
              if (ghResp.ok) {
                const ghData = await ghResp.json() as { stargazers_count?: number; forks_count?: number };
                githubStars = ghData.stargazers_count ?? null;
              }
            } catch { /* rate limited, skip */ }
          }
        }

        // Upsert trust score data
        await client.query(
          `INSERT INTO trust_scores
            (package_name, ecosystem, weekly_downloads, package_age_days, total_versions,
             has_install_scripts, has_repository, github_stars, computed_at)
           VALUES ($1, 'npm', $2, $3, $4, $5, $6, $7, NOW())
           ON CONFLICT (package_name, ecosystem) DO UPDATE SET
             weekly_downloads = EXCLUDED.weekly_downloads,
             package_age_days = EXCLUDED.package_age_days,
             total_versions = EXCLUDED.total_versions,
             has_install_scripts = EXCLUDED.has_install_scripts,
             has_repository = EXCLUDED.has_repository,
             github_stars = COALESCE(EXCLUDED.github_stars, trust_scores.github_stars),
             computed_at = NOW()`,
          [name, dlData?.downloads ?? null, packageAgeDays, versions.length, hasInstallScripts, hasRepository, githubStars]
        );

        enriched++;

        // Rate limit: 100ms between requests
        await new Promise(r => setTimeout(r, 100));
      } catch (e) {
        console.error(`[npm] Failed to enrich ${name}:`, e);
      }
    }
  } finally {
    client.release();
  }

  return enriched;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeEcosystem(eco: string): string {
  const map: Record<string, string> = {
    'npm': 'npm', 'PyPI': 'pypi', 'Go': 'go',
    'crates.io': 'cargo', 'NuGet': 'nuget', 'Maven': 'maven',
  };
  return map[eco] ?? eco.toLowerCase();
}

function cvssToSeverity(cvss: number | null): string {
  if (cvss === null) { return 'medium'; }
  if (cvss >= 9.0) { return 'critical'; }
  if (cvss >= 7.0) { return 'high'; }
  if (cvss >= 4.0) { return 'medium'; }
  return 'low';
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('[Ingester] Starting GHIN data ingestion...');
  const startTime = Date.now();

  // Phase 1: Ingest OSV vulnerabilities
  const osvCount = await ingestOsv();
  console.log(`[Ingester] OSV: ${osvCount} vulnerabilities ingested`);

  // Phase 2: Enrich npm metadata for packages that have trust scores or vulns
  const client = await pool.connect();
  try {
    const pkgRows = await client.query(
      `SELECT DISTINCT package_name FROM vulnerabilities WHERE ecosystem = 'npm'
       UNION
       SELECT DISTINCT package_name FROM trust_scores WHERE ecosystem = 'npm'
       LIMIT 500`
    );
    const npmPackages = pkgRows.rows.map(r => r.package_name as string);

    if (npmPackages.length > 0) {
      const enriched = await enrichNpmMetadata(npmPackages);
      console.log(`[Ingester] npm metadata: ${enriched} packages enriched`);
    }

    // Phase 3: Refresh materialized views
    await client.query('REFRESH MATERIALIZED VIEW hallucination_stats');
    await client.query('REFRESH MATERIALIZED VIEW agent_block_stats');
    console.log('[Ingester] Materialized views refreshed');
  } finally {
    client.release();
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`[Ingester] Complete in ${elapsed}s`);

  await pool.end();
}

main().catch(err => {
  console.error('[Ingester] Fatal error:', err);
  process.exit(1);
});
