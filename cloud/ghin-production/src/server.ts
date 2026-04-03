/**
 * GHIN Production API — Fastify REST Server
 *
 * Endpoints:
 *   POST /api/v1/report          — report hallucination/signal
 *   POST /api/v1/bulk-check      — batch check packages
 *   GET  /api/v1/package/:eco/:name — single package intelligence
 *   GET  /api/v1/stats/agents    — agent hallucination & block stats
 *
 * Stack: Fastify + PostgreSQL (pg) + Redis cache
 */

import Fastify from 'fastify';
import { Pool } from 'pg';

// ---------------------------------------------------------------------------
// Database Connection
// ---------------------------------------------------------------------------

const pool = new Pool({
  connectionString: process.env.DATABASE_URL ?? 'postgresql://localhost:5432/ghin',
  max: 20,
  idleTimeoutMillis: 30_000,
});

// ---------------------------------------------------------------------------
// Fastify App
// ---------------------------------------------------------------------------

const app = Fastify({ logger: true });

// Health check
app.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }));

// ---------------------------------------------------------------------------
// POST /api/v1/report — Report a security event
// ---------------------------------------------------------------------------

app.post('/api/v1/report', async (request, reply) => {
  const body = request.body as Record<string, unknown>;
  const {
    event_type, ide, ide_version, extension_version,
    ai_agent, ai_agent_version, ai_model, ai_interaction_type,
    package_name, ecosystem, package_version,
    action_taken, severity, os_platform, anonymous_client_id,
  } = body;

  if (!event_type || !package_name || !ecosystem) {
    return reply.status(400).send({ error: 'Missing required fields: event_type, package_name, ecosystem' });
  }

  const client = await pool.connect();
  try {
    // Resolve IDE and AI agent IDs
    const ideRow = await client.query('SELECT id FROM ides WHERE slug = $1', [ide]);
    const agentRow = await client.query('SELECT id FROM ai_agents WHERE slug = $1', [ai_agent]);

    const ideId = ideRow.rows[0]?.id ?? null;
    const agentId = agentRow.rows[0]?.id ?? null;

    // Insert telemetry event
    await client.query(
      `INSERT INTO telemetry_events
        (event_type, ide_id, ide_version, extension_version,
         ai_agent_id, ai_agent_version, ai_model_used, ai_interaction_type,
         package_name, ecosystem, package_version,
         action_taken, severity, os_platform, anonymous_client_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [event_type, ideId, ide_version, extension_version,
       agentId, ai_agent_version, ai_model, ai_interaction_type,
       package_name, ecosystem, package_version,
       action_taken, severity, os_platform, anonymous_client_id]
    );

    // If hallucination event, upsert into hallucinations table
    if (event_type === 'hallucination_detected') {
      await client.query(
        `INSERT INTO hallucinations (package_name, ecosystem, ai_agent_id, ide_id, report_count, is_confirmed_hallucination)
         VALUES ($1, $2, $3, $4, 1, TRUE)
         ON CONFLICT (package_name, ecosystem)
         DO UPDATE SET
           report_count = hallucinations.report_count + 1,
           last_seen = NOW(),
           ai_agent_id = COALESCE($3, hallucinations.ai_agent_id),
           ide_id = COALESCE($4, hallucinations.ide_id)`,
        [package_name, ecosystem, agentId, ideId]
      );
    }

    return reply.status(201).send({ success: true });
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// GET /api/v1/package/:eco/:name — Single package intelligence
// ---------------------------------------------------------------------------

app.get('/api/v1/package/:eco/:name', async (request, reply) => {
  const { eco, name } = request.params as { eco: string; name: string };

  const client = await pool.connect();
  try {
    // Check hallucination status
    const hallucRow = await client.query(
      'SELECT * FROM hallucinations WHERE package_name = $1 AND ecosystem = $2',
      [name, eco]
    );

    // Check trust score
    const trustRow = await client.query(
      'SELECT * FROM trust_scores WHERE package_name = $1 AND ecosystem = $2',
      [name, eco]
    );

    // Check vulnerabilities
    const vulnRows = await client.query(
      'SELECT severity, fixed_versions, cve_ids FROM vulnerabilities WHERE package_name = $1 AND ecosystem = $2',
      [name, eco]
    );

    const halluc = hallucRow.rows[0];
    const trust = trustRow.rows[0];
    const vulns = vulnRows.rows;

    const isHallucination = halluc?.is_confirmed_hallucination ?? false;
    const highestSeverity = vulns.length > 0
      ? (['critical', 'high', 'medium', 'low'].find(s => vulns.some(v => v.severity === s)) ?? null)
      : null;

    const patchedVersions: string[] = [];
    for (const v of vulns) {
      if (v.fixed_versions) { patchedVersions.push(...v.fixed_versions); }
    }

    const response = {
      exists: !isHallucination,
      trust_score: trust?.trust_score ?? (isHallucination ? 0 : 50),
      hallucination: isHallucination,
      vulnerable: vulns.length > 0,
      highest_severity: highestSeverity,
      patched_versions: [...new Set(patchedVersions)],
      provenance: trust?.provenance_verified ? 'verified' : (trust ? 'partial' : 'none'),
      signals: {
        publisher_age_days: trust?.publisher_age_days ?? null,
        has_install_scripts: trust?.has_install_scripts ?? false,
        download_velocity: trust?.download_velocity ?? null,
        weekly_downloads: trust?.weekly_downloads ? Number(trust.weekly_downloads) : null,
      },
      hallucination_context: isHallucination ? {
        report_count: halluc?.report_count ?? 0,
        risk_score: halluc?.risk_score ?? 0,
        first_seen: halluc?.first_seen ?? null,
      } : undefined,
    };

    return reply.send(response);
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// POST /api/v1/bulk-check — Batch check packages
// ---------------------------------------------------------------------------

app.post('/api/v1/bulk-check', async (request, reply) => {
  const body = request.body as { packages?: Array<{ name: string; ecosystem: string }> };
  const packages = body.packages;

  if (!packages || !Array.isArray(packages) || packages.length === 0) {
    return reply.status(400).send({ error: 'Missing or empty packages array' });
  }

  // Cap at 100 packages per request
  const batch = packages.slice(0, 100);

  const client = await pool.connect();
  try {
    const results: Record<string, unknown> = {};

    for (const pkg of batch) {
      const key = `${pkg.ecosystem}/${pkg.name}`;

      const halluc = await client.query(
        'SELECT is_confirmed_hallucination, report_count, risk_score FROM hallucinations WHERE package_name = $1 AND ecosystem = $2',
        [pkg.name, pkg.ecosystem]
      );

      const trust = await client.query(
        'SELECT trust_score, trust_tier, vulnerability_count, highest_cve_severity FROM trust_scores WHERE package_name = $1 AND ecosystem = $2',
        [pkg.name, pkg.ecosystem]
      );

      const h = halluc.rows[0];
      const t = trust.rows[0];

      results[key] = {
        exists: !(h?.is_confirmed_hallucination),
        trust_score: t?.trust_score ?? 50,
        trust_tier: t?.trust_tier ?? 'partial',
        hallucination: h?.is_confirmed_hallucination ?? false,
        vulnerable: (t?.vulnerability_count ?? 0) > 0,
        highest_severity: t?.highest_cve_severity ?? null,
      };
    }

    return reply.send({ results });
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// GET /api/v1/stats/agents — Agent hallucination & block stats
// ---------------------------------------------------------------------------

app.get('/api/v1/stats/agents', async (_request, reply) => {
  const client = await pool.connect();
  try {
    // Agent stats from materialized view (or fallback to live query)
    const agentStats = await client.query(`
      SELECT
        a.display_name AS agent,
        COUNT(*) FILTER (WHERE t.event_type = 'hallucination_detected') AS hallucinations_reported,
        COUNT(*) FILTER (WHERE t.action_taken = 'blocked') AS installs_blocked,
        MODE() WITHIN GROUP (ORDER BY t.ecosystem) AS top_ecosystem
      FROM telemetry_events t
      LEFT JOIN ai_agents a ON t.ai_agent_id = a.id
      WHERE a.display_name IS NOT NULL
      GROUP BY a.display_name
      ORDER BY hallucinations_reported DESC
      LIMIT 20
    `);

    const ideStats = await client.query(`
      SELECT
        i.display_name AS ide,
        COUNT(*) AS total_events,
        COUNT(*) FILTER (WHERE t.action_taken = 'blocked') AS blocked
      FROM telemetry_events t
      LEFT JOIN ides i ON t.ide_id = i.id
      WHERE i.display_name IS NOT NULL
      GROUP BY i.display_name
      ORDER BY total_events DESC
    `);

    return reply.send({
      agents: agentStats.rows.map(r => ({
        agent: r.agent,
        hallucinations_reported: Number(r.hallucinations_reported),
        installs_blocked: Number(r.installs_blocked),
        top_ecosystem: r.top_ecosystem ?? 'npm',
      })),
      ides: ideStats.rows.map(r => ({
        ide: r.ide,
        total_events: Number(r.total_events),
        blocked: Number(r.blocked),
      })),
    });
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------------
// Start Server
// ---------------------------------------------------------------------------

const start = async () => {
  try {
    const port = Number(process.env.PORT ?? 3000);
    const host = process.env.HOST ?? '0.0.0.0';
    await app.listen({ port, host });
    console.log(`GHIN API listening on ${host}:${port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();

export { app, pool };
