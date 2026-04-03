-- ============================================================================
-- GHIN Production Database Schema — PostgreSQL 16
-- Global Hallucination Intelligence Network
--
-- 4 Modules + 2 Lookup Tables + 2 Materialized Views
-- Requires: pg_trgm extension (for typosquat similarity search)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ============================================================================
-- LOOKUP TABLES
-- ============================================================================

-- Canonical list of supported IDEs
CREATE TABLE ides (
    id SERIAL PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    vendor TEXT,
    platform_type TEXT,          -- desktop, web, terminal
    extension_api TEXT,          -- vscode, jetbrains, lsp
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO ides (slug, display_name, vendor, platform_type, extension_api) VALUES
    ('vscode', 'VS Code', 'microsoft', 'desktop', 'vscode'),
    ('cursor', 'Cursor', 'anysphere', 'desktop', 'vscode'),
    ('windsurf', 'Windsurf', 'codeium', 'desktop', 'vscode'),
    ('jetbrains', 'JetBrains IDEs', 'jetbrains', 'desktop', 'jetbrains'),
    ('neovim', 'Neovim', 'community', 'terminal', 'lsp'),
    ('vscode-web', 'VS Code Web', 'microsoft', 'web', 'vscode'),
    ('github-codespaces', 'GitHub Codespaces', 'github', 'web', 'vscode');

-- Canonical list of AI agents/assistants
CREATE TABLE ai_agents (
    id SERIAL PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    vendor TEXT,
    agent_type TEXT,             -- inline_completion, chat, agent, autonomous
    model_family TEXT,           -- gpt, claude, gemini, codellama, starcoder, custom
    supports_tool_use BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO ai_agents (slug, display_name, vendor, agent_type, model_family, supports_tool_use) VALUES
    ('copilot', 'GitHub Copilot', 'github', 'inline_completion', 'gpt', true),
    ('copilot-chat', 'Copilot Chat', 'github', 'chat', 'gpt', true),
    ('chatgpt', 'ChatGPT', 'openai', 'chat', 'gpt', true),
    ('claude', 'Claude', 'anthropic', 'chat', 'claude', true),
    ('cursor-ai', 'Cursor AI', 'anysphere', 'agent', 'custom', true),
    ('windsurf-cascade', 'Windsurf Cascade', 'codeium', 'agent', 'custom', true),
    ('codewhisperer', 'Amazon CodeWhisperer', 'amazon', 'inline_completion', 'custom', false),
    ('cody', 'Sourcegraph Cody', 'sourcegraph', 'chat', 'custom', true),
    ('gemini-code-assist', 'Gemini Code Assist', 'google', 'chat', 'gemini', true),
    ('tabnine', 'Tabnine', 'tabnine', 'inline_completion', 'custom', false),
    ('manual', 'Manual (no AI)', 'none', 'none', 'none', false);

-- ============================================================================
-- MODULE A: Hallucination Intelligence
-- ============================================================================

CREATE TABLE hallucinations (
    id BIGSERIAL PRIMARY KEY,
    package_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,             -- npm, pypi, go, cargo, nuget
    ai_agent_id INT REFERENCES ai_agents(id),
    ide_id INT REFERENCES ides(id),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    report_count INT DEFAULT 1,
    registry_exists BOOLEAN DEFAULT FALSE,
    is_confirmed_hallucination BOOLEAN DEFAULT FALSE,
    claimed_by_attacker BOOLEAN DEFAULT FALSE,
    claimed_at TIMESTAMPTZ,
    risk_score REAL DEFAULT 0.5,
    model_attribution TEXT,
    metadata JSONB,
    UNIQUE(package_name, ecosystem)
);

CREATE INDEX idx_halluc_pkg ON hallucinations USING gin (package_name gin_trgm_ops);
CREATE INDEX idx_halluc_eco ON hallucinations(ecosystem);
CREATE INDEX idx_halluc_ai ON hallucinations(ai_agent_id);
CREATE INDEX idx_halluc_ide ON hallucinations(ide_id);
CREATE INDEX idx_halluc_risk ON hallucinations(risk_score DESC);
CREATE INDEX idx_halluc_confirmed ON hallucinations(is_confirmed_hallucination) WHERE is_confirmed_hallucination = TRUE;

-- ============================================================================
-- MODULE B: Vulnerability + Patch Intelligence
-- ============================================================================

CREATE TABLE vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    package_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    affected_range TEXT NOT NULL,        -- semver range
    fixed_versions TEXT[],
    severity TEXT,                       -- critical, high, medium, low
    cvss_score DECIMAL(3,1),
    cve_ids TEXT[],
    patch_strategy TEXT,                 -- upgrade, replace, workaround
    alternative_packages TEXT[],         -- safe replacement suggestions
    source TEXT,                         -- osv, github_advisory, nvd
    source_url TEXT,
    ingested_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    raw_data JSONB
);

CREATE INDEX idx_vuln_pkg ON vulnerabilities(package_name, ecosystem);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_cve ON vulnerabilities USING gin(cve_ids);

-- ============================================================================
-- MODULE C: Trust Intelligence
-- ============================================================================

CREATE TABLE trust_scores (
    id BIGSERIAL PRIMARY KEY,
    package_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    trust_score INT CHECK (trust_score BETWEEN 0 AND 100),
    trust_tier TEXT,                     -- verified, partial, suspicious, untrusted

    -- Provenance signals
    provenance_verified BOOLEAN DEFAULT FALSE,
    slsa_level INT DEFAULT 0,
    verified_publisher BOOLEAN DEFAULT FALSE,

    -- Popularity signals
    weekly_downloads BIGINT,
    download_velocity TEXT,              -- declining, stable, growing, spike
    github_stars INT,
    github_forks INT,
    has_repository BOOLEAN DEFAULT FALSE,

    -- Maturity signals
    publisher_age_days INT,
    package_age_days INT,
    total_versions INT,
    recent_ownership_change BOOLEAN DEFAULT FALSE,
    version_spike BOOLEAN DEFAULT FALSE,

    -- Security signals
    has_install_scripts BOOLEAN DEFAULT FALSE,
    suspicious_scripts BOOLEAN DEFAULT FALSE,
    vulnerability_count INT DEFAULT 0,
    highest_cve_severity TEXT,

    -- Typosquatting
    typosquat_distance INT,
    closest_popular_pkg TEXT,

    -- Meta
    signals JSONB,
    computed_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(package_name, ecosystem)
);

CREATE INDEX idx_trust_pkg ON trust_scores(package_name, ecosystem);
CREATE INDEX idx_trust_score ON trust_scores(trust_score DESC);
CREATE INDEX idx_trust_tier ON trust_scores(trust_tier);

-- ============================================================================
-- MODULE D: Telemetry & Context Tracking
-- ============================================================================

CREATE TABLE telemetry_events (
    id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,

    -- IDE context
    ide_id INT REFERENCES ides(id),
    ide_version TEXT,
    extension_version TEXT,

    -- AI agent context
    ai_agent_id INT REFERENCES ai_agents(id),
    ai_agent_version TEXT,
    ai_model_used TEXT,
    ai_interaction_type TEXT,

    -- Package context (nullable)
    package_name TEXT,
    ecosystem TEXT,
    package_version TEXT,

    -- Event details
    action_taken TEXT,
    severity TEXT,
    trust_score_at_time INT,

    -- Environment context
    os_platform TEXT,
    anonymous_client_id TEXT,
    is_enterprise BOOLEAN DEFAULT FALSE,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),

    -- Extensible metadata
    metadata JSONB
);

CREATE INDEX idx_telem_event ON telemetry_events(event_type);
CREATE INDEX idx_telem_ide ON telemetry_events(ide_id);
CREATE INDEX idx_telem_agent ON telemetry_events(ai_agent_id);
CREATE INDEX idx_telem_pkg ON telemetry_events(package_name, ecosystem);
CREATE INDEX idx_telem_time ON telemetry_events(created_at);
CREATE INDEX idx_telem_client ON telemetry_events(anonymous_client_id);

-- ============================================================================
-- MATERIALIZED VIEWS (for dashboards)
-- ============================================================================

-- Hallucination stats grouped by AI agent + IDE
CREATE MATERIALIZED VIEW hallucination_stats AS
SELECT
    a.display_name AS ai_agent,
    i.display_name AS ide,
    h.ecosystem,
    COUNT(*) AS total_hallucinations,
    COUNT(*) FILTER (WHERE h.is_confirmed_hallucination) AS confirmed,
    ROUND(AVG(h.report_count)::numeric, 1) AS avg_reports,
    MAX(h.last_seen) AS latest_report
FROM hallucinations h
LEFT JOIN ai_agents a ON h.ai_agent_id = a.id
LEFT JOIN ides i ON h.ide_id = i.id
GROUP BY a.display_name, i.display_name, h.ecosystem;

-- Agent block stats
CREATE MATERIALIZED VIEW agent_block_stats AS
SELECT
    a.display_name AS ai_agent,
    a.vendor AS agent_vendor,
    i.display_name AS ide,
    t.event_type,
    COUNT(*) AS event_count,
    COUNT(*) FILTER (WHERE t.action_taken = 'blocked') AS blocked_count,
    COUNT(*) FILTER (WHERE t.action_taken = 'allowed') AS allowed_count,
    COUNT(*) FILTER (WHERE t.action_taken = 'patched') AS patched_count
FROM telemetry_events t
LEFT JOIN ai_agents a ON t.ai_agent_id = a.id
LEFT JOIN ides i ON t.ide_id = i.id
GROUP BY a.display_name, a.vendor, i.display_name, t.event_type;

-- Refresh views (to be called by cron)
-- REFRESH MATERIALIZED VIEW CONCURRENTLY hallucination_stats;
-- REFRESH MATERIALIZED VIEW CONCURRENTLY agent_block_stats;
