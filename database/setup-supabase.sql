-- ═══════════════════════════════════════════════════════════════════════
-- CodeGuard AI — Supabase Database Setup
-- Run this in: https://supabase.com/dashboard/project/iwjierrgvqwpzphrfwan/sql/new
-- ═══════════════════════════════════════════════════════════════════════

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  avatar_url TEXT,
  github_id TEXT UNIQUE,
  github_username TEXT,
  role TEXT NOT NULL DEFAULT 'USER',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT UNIQUE NOT NULL,
  key_prefix TEXT NOT NULL,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);

-- Teams table
CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  owner_id TEXT NOT NULL REFERENCES users(id),
  settings JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Team Members table
CREATE TABLE IF NOT EXISTS team_members (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'MEMBER',
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(team_id, user_id)
);

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  repository_url TEXT,
  settings JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
  user_id TEXT NOT NULL REFERENCES users(id),
  scan_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  findings JSONB NOT NULL DEFAULT '[]',
  metadata JSONB,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

-- GHIN Reports table
CREATE TABLE IF NOT EXISTS ghin_reports (
  id TEXT PRIMARY KEY,
  package_name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  reporter_id TEXT REFERENCES users(id),
  context TEXT,
  verified BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- GHIN Packages table
CREATE TABLE IF NOT EXISTS ghin_packages (
  id TEXT PRIMARY KEY,
  package_name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'REPORTED',
  report_count INTEGER NOT NULL DEFAULT 1,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  verified_at TIMESTAMPTZ,
  metadata JSONB,
  UNIQUE(package_name, ecosystem)
);

-- Policy Templates table
CREATE TABLE IF NOT EXISTS policy_templates (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  rules JSONB NOT NULL,
  is_default BOOLEAN NOT NULL DEFAULT false,
  created_by TEXT REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Webhooks table
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  events TEXT[] NOT NULL,
  secret TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Webhook Deliveries table
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY,
  webhook_id TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event TEXT NOT NULL,
  payload JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  response_code INTEGER,
  response_body TEXT,
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  delivered_at TIMESTAMPTZ
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_teams_owner_id ON teams(owner_id);
CREATE INDEX IF NOT EXISTS idx_teams_slug ON teams(slug);
CREATE INDEX IF NOT EXISTS idx_team_members_team_id ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user_id ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_projects_team_id ON projects(team_id);
CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_ghin_reports_package ON ghin_reports(package_name, ecosystem);
CREATE INDEX IF NOT EXISTS idx_ghin_packages_ecosystem ON ghin_packages(ecosystem);
CREATE INDEX IF NOT EXISTS idx_ghin_packages_status ON ghin_packages(status);
CREATE INDEX IF NOT EXISTS idx_webhooks_team_id ON webhooks(team_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);

-- Seed admin user
INSERT INTO users (id, email, name, role, created_at, updated_at)
VALUES ('admin-001', 'admin@codeguard.ai', 'CodeGuard Admin', 'ADMIN', NOW(), NOW())
ON CONFLICT (email) DO NOTHING;

-- Seed known hallucinated packages
INSERT INTO ghin_packages (id, package_name, ecosystem, status, report_count, verified_at, metadata)
VALUES
  ('ghin-001', 'faker-colors-js', 'NPM', 'CONFIRMED', 5, NOW(), '{"source": "bundled"}'),
  ('ghin-002', 'react-native-safe-view', 'NPM', 'CONFIRMED', 3, NOW(), '{"source": "bundled"}'),
  ('ghin-003', 'lodash-helpers', 'NPM', 'CONFIRMED', 4, NOW(), '{"source": "bundled"}'),
  ('ghin-004', 'express-middleware-auth', 'NPM', 'CONFIRMED', 2, NOW(), '{"source": "bundled"}'),
  ('ghin-005', 'axios-retry-helper', 'NPM', 'CONFIRMED', 3, NOW(), '{"source": "bundled"}'),
  ('ghin-006', 'moment-timezone-utils', 'NPM', 'CONFIRMED', 2, NOW(), '{"source": "bundled"}'),
  ('ghin-007', 'webpack-bundle-optimizer', 'NPM', 'CONFIRMED', 4, NOW(), '{"source": "bundled"}'),
  ('ghin-008', 'typescript-decorators-extra', 'NPM', 'CONFIRMED', 2, NOW(), '{"source": "bundled"}'),
  ('ghin-009', 'jest-snapshot-utils', 'NPM', 'CONFIRMED', 3, NOW(), '{"source": "bundled"}'),
  ('ghin-010', 'eslint-config-airbnb-pro', 'NPM', 'CONFIRMED', 2, NOW(), '{"source": "bundled"}'),
  ('ghin-011', 'pandas-utils', 'PYPI', 'CONFIRMED', 4, NOW(), '{"source": "bundled"}'),
  ('ghin-012', 'numpy-helpers', 'PYPI', 'CONFIRMED', 3, NOW(), '{"source": "bundled"}'),
  ('ghin-013', 'tensorflow-utils', 'PYPI', 'CONFIRMED', 5, NOW(), '{"source": "bundled"}'),
  ('ghin-014', 'django-rest-helpers', 'PYPI', 'CONFIRMED', 2, NOW(), '{"source": "bundled"}'),
  ('ghin-015', 'flask-middleware-auth', 'PYPI', 'CONFIRMED', 3, NOW(), '{"source": "bundled"}'),
  ('ghin-016', 'requests-retry-helper', 'PYPI', 'CONFIRMED', 2, NOW(), '{"source": "bundled"}'),
  ('ghin-017', 'sqlalchemy-utils-extra', 'PYPI', 'CONFIRMED', 4, NOW(), '{"source": "bundled"}'),
  ('ghin-018', 'pytest-fixtures-utils', 'PYPI', 'CONFIRMED', 3, NOW(), '{"source": "bundled"}')
ON CONFLICT (package_name, ecosystem) DO NOTHING;

-- Seed default policy template
INSERT INTO policy_templates (id, name, description, rules, is_default, created_by)
VALUES (
  'policy-default',
  'Default Security Policy',
  'Recommended security policy for most projects',
  '{"forbiddenPackages":[],"maxVulnerabilitySeverity":"HIGH","requireScanners":["hallucination","secrets","sast"],"blockHallucinations":true}',
  true,
  'admin-001'
)
ON CONFLICT (id) DO NOTHING;

-- Success message
SELECT 'Database setup complete! 🎉' AS message;
