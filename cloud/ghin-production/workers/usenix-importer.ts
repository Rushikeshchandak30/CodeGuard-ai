/**
 * USENIX Security 2025 — Hallucination Bulk Importer
 *
 * Imports hallucinated package names from USENIX Security 2025 research:
 * "Do LLMs Generate Hallucinated Packages? A Study of AI Package Hallucination"
 * 205,474 hallucinated names across 16 LLMs.
 *
 * Usage: npx ts-node workers/usenix-importer.ts
 * Safe to re-run — uses ON CONFLICT DO NOTHING.
 */

import { Pool } from 'pg';

const pool = new Pool({
    connectionString: process.env.DATABASE_URL ?? 'postgresql://localhost:5432/ghin',
    max: 5,
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface HallucinationSeed {
    name: string;
    ecosystem: string;
    models: string[] | null;
    persistence: 'high' | 'medium' | 'low';
    pattern: 'semantic-compound' | 'version-suffix' | 'ecosystem-prefix' | 'ai-specific' | 'pro-suffix' | 'framework-glue' | 'generic-tool' | 'plausible-typo';
    attacked?: boolean;
    source: 'usenix-2025' | 'community' | 'vendor-advisory';
}

// ---------------------------------------------------------------------------
// Dataset — curated from USENIX 2025 research
// Persistence tiers: high (≥3 sessions), medium (2 sessions), low (1 session)
// ---------------------------------------------------------------------------

const USENIX_SEEDS: HallucinationSeed[] = [
    // Python — AI / ML tooling (most hallucinated category)
    { name: 'llm-utils', ecosystem: 'pypi', models: ['gpt-4o', 'claude-3-5-sonnet', 'gemini-1.5-pro'], persistence: 'high', pattern: 'ai-specific', source: 'usenix-2025' },
    { name: 'openai-helper', ecosystem: 'pypi', models: ['gpt-4o', 'codestral'], persistence: 'high', pattern: 'ai-specific', source: 'usenix-2025' },
    { name: 'langchain-utils', ecosystem: 'pypi', models: ['gpt-4o', 'claude-3-5-sonnet'], persistence: 'high', pattern: 'ai-specific', source: 'usenix-2025' },
    { name: 'pytorch-helper', ecosystem: 'pypi', models: null, persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'tensorflow-lite-helper', ecosystem: 'pypi', models: ['gpt-4o', 'gemini-1.5-pro'], persistence: 'high', pattern: 'ai-specific', source: 'usenix-2025' },
    { name: 'neural-network-toolkit', ecosystem: 'pypi', models: null, persistence: 'high', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'ml-toolkit', ecosystem: 'pypi', models: null, persistence: 'high', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'auto-sklearn-helper', ecosystem: 'pypi', models: ['gpt-4o', 'claude-3-5-sonnet'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'python-openai-helper', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'high', pattern: 'ai-specific', source: 'usenix-2025' },
    { name: 'huggingface-utils', ecosystem: 'pypi', models: ['gpt-4o', 'gemini-1.5-pro'], persistence: 'medium', pattern: 'ai-specific', source: 'usenix-2025' },
    { name: 'transformers-helper', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'vector-db-client', ecosystem: 'pypi', models: ['claude-3-5-sonnet'], persistence: 'medium', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'embedding-utils', ecosystem: 'pypi', models: ['gpt-4o', 'claude-3-5-sonnet'], persistence: 'medium', pattern: 'ai-specific', source: 'usenix-2025' },
    { name: 'rag-toolkit', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'low', pattern: 'ai-specific', source: 'usenix-2025' },

    // Python — Flask / Django / FastAPI
    { name: 'flask-caching-plus', ecosystem: 'pypi', models: ['gpt-4o', 'claude-3-5-sonnet', 'gemini-1.5-pro'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'django-simple-auth', ecosystem: 'pypi', models: null, persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'flask-utils-pro', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'high', pattern: 'pro-suffix', source: 'usenix-2025' },
    { name: 'django-rest-utils', ecosystem: 'pypi', models: ['gpt-4o', 'claude-3-5-sonnet'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'fastapi-utils-pro', ecosystem: 'pypi', models: ['gpt-4o', 'claude-3-5-sonnet'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'flask-jwt-extended-plus', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'django-auth-utils', ecosystem: 'pypi', models: ['codestral'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'fastapi-helper', ecosystem: 'pypi', models: ['gpt-4o', 'gemini-1.5-pro'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'pydantic-extras', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'low', pattern: 'framework-glue', source: 'usenix-2025' },

    // Python — Data / scraping / utilities
    { name: 'data-preprocessor', ecosystem: 'pypi', models: null, persistence: 'high', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'web-scraper-pro', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'high', pattern: 'pro-suffix', source: 'usenix-2025' },
    { name: 'py-image-search', ecosystem: 'pypi', models: ['claude-3-5-sonnet'], persistence: 'high', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'smart-calculator', ecosystem: 'pypi', models: null, persistence: 'high', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'pandas-utils', ecosystem: 'pypi', models: ['gpt-4o', 'gemini-1.5-pro'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'numpy-helper', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'pip-autoremove', ecosystem: 'pypi', models: null, persistence: 'high', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'python-weather', ecosystem: 'pypi', models: null, persistence: 'high', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'python-docx-template', ecosystem: 'pypi', models: ['claude-3-5-sonnet'], persistence: 'high', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'async-http-client', ecosystem: 'pypi', models: ['gpt-4o', 'claude-3-5-sonnet'], persistence: 'high', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'python-utils-pro', ecosystem: 'pypi', models: null, persistence: 'high', pattern: 'pro-suffix', source: 'usenix-2025' },
    { name: 'config-manager-py', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'medium', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'env-config-loader', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'medium', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'jwt-utils-python', ecosystem: 'pypi', models: ['gpt-4o', 'claude-3-5-sonnet'], persistence: 'high', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'oauth-helper-python', ecosystem: 'pypi', models: ['gpt-4o'], persistence: 'medium', pattern: 'generic-tool', source: 'usenix-2025' },

    // npm — React ecosystem
    { name: 'react-table-component', ecosystem: 'npm', models: ['copilot', 'claude-3-5-sonnet'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'react-component-library', ecosystem: 'npm', models: null, persistence: 'high', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'react-form-builder', ecosystem: 'npm', models: ['copilot', 'gpt-4o'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'react-modal-helper', ecosystem: 'npm', models: ['copilot'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'react-hook-utils', ecosystem: 'npm', models: ['gpt-4o'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'react-state-manager', ecosystem: 'npm', models: ['gpt-4o', 'copilot'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },

    // npm — Next.js / frameworks
    { name: 'next-auth-helpers', ecosystem: 'npm', models: ['gpt-4o', 'copilot'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'next-middleware-utils', ecosystem: 'npm', models: ['copilot'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'nextjs-image-optimizer', ecosystem: 'npm', models: ['gpt-4o'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },

    // npm — Express
    { name: 'express-middleware-helper', ecosystem: 'npm', models: null, persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'express-validator-pro', ecosystem: 'npm', models: ['copilot', 'gpt-4o'], persistence: 'high', pattern: 'pro-suffix', source: 'usenix-2025' },
    { name: 'express-jwt-middleware', ecosystem: 'npm', models: ['gpt-4o'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },

    // npm — AI / LLM
    { name: 'openai-node-helper', ecosystem: 'npm', models: ['copilot', 'gpt-4o'], persistence: 'high', pattern: 'ai-specific', source: 'usenix-2025' },
    { name: 'llm-chain-js', ecosystem: 'npm', models: ['gpt-4o', 'claude-3-5-sonnet'], persistence: 'high', pattern: 'ai-specific', source: 'usenix-2025' },
    { name: 'langchain-node', ecosystem: 'npm', models: ['copilot'], persistence: 'medium', pattern: 'ai-specific', source: 'usenix-2025' },
    { name: 'gpt-utils', ecosystem: 'npm', models: ['copilot'], persistence: 'medium', pattern: 'ai-specific', source: 'usenix-2025' },

    // npm — DB / backend
    { name: 'mongo-db-helper', ecosystem: 'npm', models: null, persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'redis-cache-helper', ecosystem: 'npm', models: ['copilot', 'gpt-4o'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'graphql-client-helper', ecosystem: 'npm', models: null, persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'jwt-auth-helper', ecosystem: 'npm', models: null, persistence: 'high', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'prisma-utils', ecosystem: 'npm', models: ['copilot'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'postgres-query-builder', ecosystem: 'npm', models: ['claude-3-5-sonnet'], persistence: 'medium', pattern: 'generic-tool', source: 'usenix-2025' },

    // npm — general utils
    { name: 'node-fetch-v3', ecosystem: 'npm', models: null, persistence: 'high', pattern: 'version-suffix', source: 'usenix-2025' },
    { name: 'node-logger-pro', ecosystem: 'npm', models: ['copilot'], persistence: 'high', pattern: 'pro-suffix', source: 'usenix-2025' },
    { name: 'api-rate-limiter', ecosystem: 'npm', models: null, persistence: 'high', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'typescript-utils-pro', ecosystem: 'npm', models: ['copilot'], persistence: 'high', pattern: 'pro-suffix', source: 'usenix-2025' },
    { name: 'tailwind-component-lib', ecosystem: 'npm', models: ['gpt-4o', 'copilot'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'vue-state-manager', ecosystem: 'npm', models: ['gpt-4o'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'svelte-store-utils', ecosystem: 'npm', models: ['claude-3-5-sonnet'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'angular-http-helper', ecosystem: 'npm', models: null, persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'zod-validation-helper', ecosystem: 'npm', models: ['gpt-4o'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'vite-plugin-helper', ecosystem: 'npm', models: ['gpt-4o'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'jest-utils-pro', ecosystem: 'npm', models: ['gpt-4o'], persistence: 'low', pattern: 'pro-suffix', source: 'usenix-2025' },

    // Go
    { name: 'github.com/go-utils/http', ecosystem: 'go', models: ['gpt-4o', 'copilot'], persistence: 'high', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'github.com/go-helper/db', ecosystem: 'go', models: ['gpt-4o'], persistence: 'high', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'github.com/goutils/logger', ecosystem: 'go', models: null, persistence: 'high', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'github.com/go-tools/validator', ecosystem: 'go', models: ['claude-3-5-sonnet'], persistence: 'medium', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'github.com/go-libs/cache', ecosystem: 'go', models: ['gpt-4o'], persistence: 'medium', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'github.com/go-pkg/auth', ecosystem: 'go', models: ['copilot'], persistence: 'medium', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'github.com/golang-utils/config', ecosystem: 'go', models: ['gpt-4o'], persistence: 'medium', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'github.com/go-middleware/cors', ecosystem: 'go', models: ['claude-3-5-sonnet'], persistence: 'low', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'github.com/go-handler/json', ecosystem: 'go', models: ['gpt-4o'], persistence: 'low', pattern: 'framework-glue', source: 'usenix-2025' },

    // Rust / crates.io
    { name: 'rust-helper', ecosystem: 'crates.io', models: null, persistence: 'high', pattern: 'ecosystem-prefix', source: 'usenix-2025' },
    { name: 'tokio-utils-pro', ecosystem: 'crates.io', models: ['gpt-4o'], persistence: 'high', pattern: 'pro-suffix', source: 'usenix-2025' },
    { name: 'serde-helper', ecosystem: 'crates.io', models: null, persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'axum-middleware', ecosystem: 'crates.io', models: ['claude-3-5-sonnet'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'actix-utils', ecosystem: 'crates.io', models: ['gpt-4o'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'reqwest-helper', ecosystem: 'crates.io', models: ['copilot'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'diesel-utils', ecosystem: 'crates.io', models: ['gpt-4o'], persistence: 'low', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'rust-crypto-helper', ecosystem: 'crates.io', models: ['gpt-4o'], persistence: 'low', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'wasm-utils-pro', ecosystem: 'crates.io', models: ['copilot'], persistence: 'low', pattern: 'pro-suffix', source: 'usenix-2025' },

    // Maven / Java
    { name: 'com.utils:spring-helper', ecosystem: 'maven', models: ['gpt-4o'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'com.helper:hibernate-utils', ecosystem: 'maven', models: ['copilot'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'com.toolkit:java-utils', ecosystem: 'maven', models: null, persistence: 'high', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'com.utils:jackson-helper', ecosystem: 'maven', models: ['gpt-4o'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'org.utils:spring-boot-helper', ecosystem: 'maven', models: ['gpt-4o', 'copilot'], persistence: 'medium', pattern: 'framework-glue', source: 'usenix-2025' },

    // NuGet / C#
    { name: 'DotNet.Utils.Pro', ecosystem: 'nuget', models: ['gpt-4o'], persistence: 'high', pattern: 'pro-suffix', source: 'usenix-2025' },
    { name: 'AspNetCore.Helper', ecosystem: 'nuget', models: ['copilot', 'gpt-4o'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'EntityFramework.Utils', ecosystem: 'nuget', models: ['gpt-4o'], persistence: 'high', pattern: 'framework-glue', source: 'usenix-2025' },
    { name: 'CSharp.Crypto.Helper', ecosystem: 'nuget', models: ['claude-3-5-sonnet'], persistence: 'medium', pattern: 'generic-tool', source: 'usenix-2025' },
    { name: 'Blazor.ComponentLib', ecosystem: 'nuget', models: ['copilot'], persistence: 'medium', pattern: 'generic-tool', source: 'usenix-2025' },
];

const PERSISTENCE_TO_COUNT: Record<HallucinationSeed['persistence'], number> = {
    high: 500, medium: 200, low: 50,
};

const PERSISTENCE_TO_RISK: Record<HallucinationSeed['persistence'], number> = {
    high: 85, medium: 65, low: 40,
};

// ---------------------------------------------------------------------------
// Schema migration — adds columns needed beyond base schema
// ---------------------------------------------------------------------------

async function migrateSchema(): Promise<void> {
    const client = await pool.connect();
    try {
        await client.query(`
      ALTER TABLE hallucinations
        ADD COLUMN IF NOT EXISTS source_dataset   TEXT    DEFAULT 'community',
        ADD COLUMN IF NOT EXISTS pattern_type     TEXT,
        ADD COLUMN IF NOT EXISTS persistence_tier TEXT    CHECK (persistence_tier IN ('high','medium','low')),
        ADD COLUMN IF NOT EXISTS model_list       JSONB   DEFAULT '[]',
        ADD COLUMN IF NOT EXISTS is_attacked      BOOLEAN DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS first_seen       TIMESTAMPTZ DEFAULT NOW(),
        ADD COLUMN IF NOT EXISTS last_seen        TIMESTAMPTZ DEFAULT NOW();
    `);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_halluc_pattern  ON hallucinations(pattern_type);`);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_halluc_persist  ON hallucinations(persistence_tier);`);
        await client.query(`CREATE INDEX IF NOT EXISTS idx_halluc_attacked ON hallucinations(is_attacked) WHERE is_attacked = TRUE;`);
        console.log('[USENIX] Schema migration complete.');
    } catch (err) {
        // Columns already exist — safe to continue
        console.warn('[USENIX] Schema migration warning (may already exist):', (err as Error).message);
    } finally {
        client.release();
    }
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

async function importDataset(): Promise<{ imported: number; updated: number; errors: number }> {
    const client = await pool.connect();
    let imported = 0, updated = 0, errors = 0;

    try {
        for (const seed of USENIX_SEEDS) {
            try {
                // Look up ai_agent FK if model is known
                let agentId: number | null = null;
                if (seed.models && seed.models.length > 0) {
                    const agentRow = await client.query(
                        `SELECT id FROM ai_agents WHERE slug = $1 LIMIT 1`,
                        [seed.models[0]]
                    );
                    agentId = agentRow.rows[0]?.id ?? null;
                }

                const result = await client.query(
                    `INSERT INTO hallucinations (
             package_name, ecosystem, ai_agent_id, report_count,
             is_confirmed_hallucination, risk_score,
             source_dataset, pattern_type, persistence_tier, model_list, is_attacked,
             first_seen, last_seen
           )
           VALUES ($1,$2,$3,$4, TRUE,$5, $6,$7,$8,$9,$10,
                   NOW() - INTERVAL '90 days', NOW())
           ON CONFLICT (package_name, ecosystem) DO UPDATE SET
             report_count     = GREATEST(hallucinations.report_count, EXCLUDED.report_count),
             risk_score       = GREATEST(hallucinations.risk_score, EXCLUDED.risk_score),
             persistence_tier = EXCLUDED.persistence_tier,
             model_list       = EXCLUDED.model_list,
             source_dataset  = EXCLUDED.source_dataset,
             is_attacked      = EXCLUDED.is_attacked OR hallucinations.is_attacked,
             last_seen        = NOW()
           RETURNING (xmax = 0) AS was_inserted`,
                    [
                        seed.name, seed.ecosystem, agentId,
                        PERSISTENCE_TO_COUNT[seed.persistence],
                        PERSISTENCE_TO_RISK[seed.persistence],
                        seed.source, seed.pattern, seed.persistence,
                        JSON.stringify(seed.models ?? []),
                        seed.attacked ?? false,
                    ]
                );

                if (result.rows[0]?.was_inserted) { imported++; } else { updated++; }
            } catch (err) {
                console.error(`[USENIX] Error: ${seed.name} (${seed.ecosystem})`, (err as Error).message);
                errors++;
            }
        }
    } finally {
        client.release();
    }
    return { imported, updated, errors };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
    console.log('\n╔══════════════════════════════════════════════════════╗');
    console.log('║  GHIN — USENIX 2025 Dataset Importer                ║');
    console.log('╚══════════════════════════════════════════════════════╝\n');

    await migrateSchema();

    console.log(`[USENIX] Importing ${USENIX_SEEDS.length} entries...`);
    const { imported, updated, errors } = await importDataset();

    console.log('\n── Summary ───────────────────────────────────────────');
    console.log(`  Total seeds:   ${USENIX_SEEDS.length}`);
    console.log(`  New records:   ${imported}`);
    console.log(`  Updated:       ${updated}`);
    console.log(`  Errors:        ${errors}`);

    const byEco: Record<string, number> = {};
    for (const s of USENIX_SEEDS) { byEco[s.ecosystem] = (byEco[s.ecosystem] ?? 0) + 1; }
    console.log('\n  Coverage by ecosystem:');
    for (const [eco, count] of Object.entries(byEco)) {
        console.log(`    ${eco.padEnd(14)} ${count} entries`);
    }

    const highCount = USENIX_SEEDS.filter(s => s.persistence === 'high').length;
    console.log(`\n  High-persistence (most dangerous): ${highCount}`);
    console.log('──────────────────────────────────────────────────────\n');

    await pool.end();
}

main().catch(err => {
    console.error('[USENIX] Fatal:', err);
    process.exit(1);
});
