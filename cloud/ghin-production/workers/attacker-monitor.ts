/**
 * GHIN Attacker Registration Monitor
 *
 * Cron job that runs every hour to detect when previously-hallucinated
 * package names get registered on public registries by attackers.
 *
 * This is the "hallucination → attack pipeline" detector:
 *   1. AI hallucinates "fake-pkg-xyz" → user tries to install it → CodeGuard blocks
 *   2. Attacker sees hallucination trend → registers "fake-pkg-xyz" on npm with malware
 *   3. THIS SCRIPT detects the registration → marks risk_score=100, fires alerts
 *   4. Every CodeGuard user now sees CRITICAL warning for "fake-pkg-xyz"
 *
 * Usage: npx ts-node workers/attacker-monitor.ts
 * Cron:  0 * * * * cd /app && node workers/attacker-monitor.js  (every hour)
 */

import { Pool } from 'pg';

const pool = new Pool({
    connectionString: process.env.DATABASE_URL ?? 'postgresql://localhost:5432/ghin',
    max: 3,
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface HallucinationRow {
    id: number;
    package_name: string;
    ecosystem: string;
    report_count: number;
    risk_score: number;
    is_attacked: boolean;
    last_checked_at: string | null;
}

interface RegistryCheckResult {
    exists: boolean;
    registeredAt: string | null;
    publisher: string | null;
    downloadCount: number | null;
    version: string | null;
    hasInstallScript: boolean;
}

interface AttackEvent {
    packageName: string;
    ecosystem: string;
    registeredAt: string | null;
    publisher: string | null;
    downloadCount: number | null;
    version: string | null;
    hasInstallScript: boolean;
}

// ---------------------------------------------------------------------------
// Registry Checks — one per ecosystem
// ---------------------------------------------------------------------------

async function checkNpm(packageName: string): Promise<RegistryCheckResult> {
    try {
        const res = await fetch(
            `https://registry.npmjs.org/${encodeURIComponent(packageName)}`,
            { signal: AbortSignal.timeout(8000) }
        );
        if (!res.ok) { return { exists: false, registeredAt: null, publisher: null, downloadCount: null, version: null, hasInstallScript: false }; }

        const data = await res.json() as Record<string, unknown>;
        const time = data.time as Record<string, string> | undefined;
        const distTags = data['dist-tags'] as Record<string, string> | undefined;
        const latestVersion = distTags?.latest;
        const latestMeta = latestVersion
            ? (data.versions as Record<string, Record<string, unknown>>)?.[latestVersion]
            : null;
        const scripts = latestMeta?.scripts as Record<string, string> | undefined;
        const hasInstallScript = !!(scripts?.preinstall || scripts?.postinstall || scripts?.install);

        // Fetch weekly downloads
        let downloadCount: number | null = null;
        try {
            const dlRes = await fetch(
                `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`,
                { signal: AbortSignal.timeout(5000) }
            );
            if (dlRes.ok) {
                const dlData = await dlRes.json() as { downloads?: number };
                downloadCount = dlData.downloads ?? null;
            }
        } catch { /* best-effort */ }

        return {
            exists: true,
            registeredAt: time?.created ?? null,
            publisher: (data.maintainers as Array<{ name: string }>)?.[0]?.name ?? null,
            downloadCount,
            version: latestVersion ?? null,
            hasInstallScript,
        };
    } catch {
        return { exists: false, registeredAt: null, publisher: null, downloadCount: null, version: null, hasInstallScript: false };
    }
}

async function checkPypi(packageName: string): Promise<RegistryCheckResult> {
    try {
        const res = await fetch(
            `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`,
            { signal: AbortSignal.timeout(8000) }
        );
        if (!res.ok) { return { exists: false, registeredAt: null, publisher: null, downloadCount: null, version: null, hasInstallScript: false }; }

        const data = await res.json() as { info?: Record<string, unknown>; urls?: Array<{ upload_time?: string }> };
        const info = data.info;
        const uploadTime = data.urls?.[0]?.upload_time ?? null;

        return {
            exists: true,
            registeredAt: uploadTime,
            publisher: info?.author as string ?? null,
            downloadCount: null, // PyPI stats require separate API
            version: info?.version as string ?? null,
            hasInstallScript: false, // Would need tarball analysis
        };
    } catch {
        return { exists: false, registeredAt: null, publisher: null, downloadCount: null, version: null, hasInstallScript: false };
    }
}

async function checkCrates(packageName: string): Promise<RegistryCheckResult> {
    try {
        const res = await fetch(
            `https://crates.io/api/v1/crates/${encodeURIComponent(packageName)}`,
            {
                signal: AbortSignal.timeout(8000),
                headers: { 'User-Agent': 'CodeGuard-GHIN-Monitor/3.0 (security@codeguard.dev)' },
            }
        );
        if (!res.ok) { return { exists: false, registeredAt: null, publisher: null, downloadCount: null, version: null, hasInstallScript: false }; }

        const data = await res.json() as { crate?: { created_at?: string; downloads?: number; max_version?: string } };
        const crate = data.crate;

        return {
            exists: true,
            registeredAt: crate?.created_at ?? null,
            publisher: null,
            downloadCount: crate?.downloads ?? null,
            version: crate?.max_version ?? null,
            hasInstallScript: false,
        };
    } catch {
        return { exists: false, registeredAt: null, publisher: null, downloadCount: null, version: null, hasInstallScript: false };
    }
}

async function checkGoProxy(modulePath: string): Promise<RegistryCheckResult> {
    try {
        const res = await fetch(
            `https://proxy.golang.org/${encodeURIComponent(modulePath)}/@latest`,
            { signal: AbortSignal.timeout(8000) }
        );
        if (!res.ok) { return { exists: false, registeredAt: null, publisher: null, downloadCount: null, version: null, hasInstallScript: false }; }

        const data = await res.json() as { Version?: string; Time?: string };
        return {
            exists: true,
            registeredAt: data.Time ?? null,
            publisher: null,
            downloadCount: null,
            version: data.Version ?? null,
            hasInstallScript: false,
        };
    } catch {
        return { exists: false, registeredAt: null, publisher: null, downloadCount: null, version: null, hasInstallScript: false };
    }
}

async function checkRegistry(packageName: string, ecosystem: string): Promise<RegistryCheckResult> {
    switch (ecosystem.toLowerCase()) {
        case 'npm': return checkNpm(packageName);
        case 'pypi': return checkPypi(packageName);
        case 'crates.io': return checkCrates(packageName);
        case 'go': return checkGoProxy(packageName);
        default:
            return { exists: false, registeredAt: null, publisher: null, downloadCount: null, version: null, hasInstallScript: false };
    }
}

// ---------------------------------------------------------------------------
// Alert Dispatcher
// ---------------------------------------------------------------------------

async function dispatchAlert(event: AttackEvent): Promise<void> {
    console.log('\n🚨 ATTACK DETECTED 🚨');
    console.log(`Package:    ${event.packageName} (${event.ecosystem})`);
    console.log(`Registered: ${event.registeredAt ?? 'unknown'}`);
    console.log(`Publisher:  ${event.publisher ?? 'unknown'}`);
    console.log(`Version:    ${event.version ?? 'unknown'}`);
    console.log(`Downloads:  ${event.downloadCount ?? 'unknown'}`);
    console.log(`Has install script: ${event.hasInstallScript}`);

    // Webhook alert (Slack / PagerDuty / custom)
    const webhookUrl = process.env.ATTACK_ALERT_WEBHOOK;
    if (webhookUrl) {
        try {
            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    text: '🚨 *GHIN Attack Alert* — Hallucinated package now registered by attacker',
                    attachments: [{
                        color: 'danger',
                        fields: [
                            { title: 'Package', value: event.packageName, short: true },
                            { title: 'Ecosystem', value: event.ecosystem, short: true },
                            { title: 'Publisher', value: event.publisher ?? 'unknown', short: true },
                            { title: 'Version', value: event.version ?? 'unknown', short: true },
                            { title: 'Registered', value: event.registeredAt ?? 'unknown', short: true },
                            { title: 'Has Install Script', value: String(event.hasInstallScript), short: true },
                        ],
                    }],
                }),
                signal: AbortSignal.timeout(5000),
            });
            console.log('[Monitor] Alert sent to webhook.');
        } catch (err) {
            console.error('[Monitor] Webhook failed:', (err as Error).message);
        }
    }
}

// ---------------------------------------------------------------------------
// Core Monitor Logic
// ---------------------------------------------------------------------------

/**
 * Add a check-tracking column if it doesn't exist.
 */
async function ensureCheckColumn(): Promise<void> {
    const client = await pool.connect();
    try {
        await client.query(`
      ALTER TABLE hallucinations
        ADD COLUMN IF NOT EXISTS last_registry_check TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS registry_check_count INT DEFAULT 0;
    `);
    } catch { /* already exists */ } finally {
        client.release();
    }
}

/**
 * Fetch all non-attacked hallucinations that haven't been checked in the
 * last 60 minutes, ordered by report_count DESC (most dangerous first).
 */
async function fetchCandidates(limit = 200): Promise<HallucinationRow[]> {
    const client = await pool.connect();
    try {
        const result = await client.query<HallucinationRow>(
            `SELECT id, package_name, ecosystem, report_count, risk_score, is_attacked, last_registry_check AS last_checked_at
       FROM hallucinations
       WHERE is_attacked = FALSE
         AND is_confirmed_hallucination = TRUE
         AND (last_registry_check IS NULL OR last_registry_check < NOW() - INTERVAL '60 minutes')
       ORDER BY report_count DESC, risk_score DESC
       LIMIT $1`,
            [limit]
        );
        return result.rows;
    } finally {
        client.release();
    }
}

/**
 * Mark a package as claimed by an attacker and record the event.
 */
async function markAttacked(row: HallucinationRow, checkResult: RegistryCheckResult): Promise<void> {
    const client = await pool.connect();
    try {
        await client.query(
            `UPDATE hallucinations SET
         is_attacked           = TRUE,
         risk_score            = 100,
         last_registry_check   = NOW(),
         registry_check_count  = registry_check_count + 1,
         last_seen             = NOW()
       WHERE id = $1`,
            [row.id]
        );

        // Log the attack event in telemetry_events
        await client.query(
            `INSERT INTO telemetry_events (event_type, event_data, created_at)
       VALUES ('attack_detected', $1, NOW())`,
            [JSON.stringify({
                package_name: row.package_name,
                ecosystem: row.ecosystem,
                registered_at: checkResult.registeredAt,
                publisher: checkResult.publisher,
                version: checkResult.version,
                download_count: checkResult.downloadCount,
                has_install_script: checkResult.hasInstallScript,
                previous_report_count: row.report_count,
            })]
        );

        console.log(`[Monitor] ✅ Marked attacked: ${row.package_name} (${row.ecosystem})`);
    } finally {
        client.release();
    }
}

/**
 * Update the last_checked_at timestamp without marking as attacked.
 */
async function updateCheckTimestamp(id: number): Promise<void> {
    const client = await pool.connect();
    try {
        await client.query(
            `UPDATE hallucinations SET
         last_registry_check  = NOW(),
         registry_check_count = registry_check_count + 1
       WHERE id = $1`,
            [id]
        );
    } finally {
        client.release();
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
    console.log('\n[Monitor] ═══════════════════════════════════════════════════');
    console.log('[Monitor]  GHIN — Attacker Registration Monitor');
    console.log('[Monitor] ═══════════════════════════════════════════════════\n');

    await ensureCheckColumn();

    const candidates = await fetchCandidates(200);
    console.log(`[Monitor] Checking ${candidates.length} hallucinated packages for registry registration...`);

    const attacks: AttackEvent[] = [];
    let checked = 0;
    let skipped = 0; // ecosystems we can't check yet

    for (const row of candidates) {
        const eco = row.ecosystem.toLowerCase();
        const supportedEcosystems = ['npm', 'pypi', 'crates.io', 'go'];
        if (!supportedEcosystems.includes(eco)) {
            skipped++;
            continue;
        }

        const result = await checkRegistry(row.package_name, eco);
        checked++;

        if (result.exists) {
            // A hallucinated package now exists — classify as attack
            const event: AttackEvent = {
                packageName: row.package_name,
                ecosystem: row.ecosystem,
                registeredAt: result.registeredAt,
                publisher: result.publisher,
                downloadCount: result.downloadCount,
                version: result.version,
                hasInstallScript: result.hasInstallScript,
            };
            attacks.push(event);

            await markAttacked(row, result);
            await dispatchAlert(event);
        } else {
            await updateCheckTimestamp(row.id);
        }

        // Rate limiting: 200ms between checks to avoid registry rate limits
        await new Promise(r => setTimeout(r, 200));
    }

    console.log('\n[Monitor] ── Run Summary ─────────────────────────────────────');
    console.log(`[Monitor]  Candidates checked: ${checked}`);
    console.log(`[Monitor]  Skipped (unsupported ecosystem): ${skipped}`);
    console.log(`[Monitor]  🚨 Attacks detected: ${attacks.length}`);
    if (attacks.length > 0) {
        console.log('[Monitor]  Attacked packages:');
        for (const a of attacks) {
            console.log(`[Monitor]    - ${a.packageName} (${a.ecosystem}) @ v${a.version ?? '?'} by ${a.publisher ?? 'unknown'}`);
        }
    }
    console.log('[Monitor] ──────────────────────────────────────────────────\n');

    await pool.end();
}

main().catch(err => {
    console.error('[Monitor] Fatal error:', err);
    process.exit(1);
});
