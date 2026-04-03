# Database Schema Reference

> PostgreSQL 15 via Supabase · Prisma 5.22 ORM · 11 tables

---

## Tables

### `users`
| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| email | TEXT UNIQUE | User email |
| name | TEXT | Display name |
| avatar_url | TEXT | Profile picture |
| github_id | TEXT UNIQUE | GitHub user ID |
| github_username | TEXT | GitHub handle |
| role | ENUM | `USER` \| `ADMIN` \| `ENTERPRISE` |
| created_at | TIMESTAMP | Auto |
| updated_at | TIMESTAMP | Auto-updated |

---

### `api_keys`
| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| user_id | CUID FK | → users.id (CASCADE DELETE) |
| name | TEXT | Label e.g. "CI/CD Key" |
| key_hash | TEXT UNIQUE | SHA-256 of actual key |
| key_prefix | TEXT | First 8 chars e.g. `cg_abc123` (safe to display) |
| last_used_at | TIMESTAMP | Updated on use |
| expires_at | TIMESTAMP | NULL = never expires |
| revoked | BOOLEAN | Soft delete |
| created_at | TIMESTAMP | Auto |

**Notes:** Actual key is shown once at creation — never stored. Only the hash is stored.

---

### `teams`
| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| name | TEXT | Display name |
| slug | TEXT UNIQUE | URL-safe identifier |
| avatar_url | TEXT | Team logo |
| plan | ENUM | `FREE` \| `PRO` \| `ENTERPRISE` |
| created_at | TIMESTAMP | Auto |
| updated_at | TIMESTAMP | Auto-updated |

---

### `team_members`
| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| team_id | CUID FK | → teams.id |
| user_id | CUID FK | → users.id |
| role | ENUM | `OWNER` \| `ADMIN` \| `MEMBER` \| `VIEWER` |
| joined_at | TIMESTAMP | Auto |

**Unique constraint:** (team_id, user_id)

---

### `projects`
| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| team_id | CUID FK | → teams.id |
| name | TEXT | Project name |
| repo_url | TEXT | GitHub/GitLab URL |
| default_branch | TEXT | Default: `main` |
| last_scan_at | TIMESTAMP | Updated on scan |
| created_at | TIMESTAMP | Auto |
| updated_at | TIMESTAMP | Auto-updated |

---

### `scans`
| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| user_id | CUID FK | → users.id |
| project_id | CUID FK | → projects.id (nullable) |
| source | ENUM | `CLI` \| `EXTENSION` \| `GITHUB_ACTION` \| `PRE_COMMIT` \| `API` |
| status | ENUM | `PENDING` \| `RUNNING` \| `COMPLETED` \| `FAILED` |
| project_path | TEXT | Scanned directory path |
| branch | TEXT | Git branch |
| commit_hash | TEXT | Git SHA |
| total_findings | INT | Summary count |
| critical_count | INT | Critical severity |
| high_count | INT | High severity |
| medium_count | INT | Medium severity |
| low_count | INT | Low severity |
| hallucinated_pkgs | INT | AI hallucinated packages found |
| secrets_found | INT | Exposed secrets found |
| sast_findings | INT | Static analysis findings |
| mcp_issues | INT | MCP server security issues |
| vulnerabilities | INT | CVE vulnerabilities |
| policy_violations | INT | Policy rule violations |
| scanned_files | INT | Files scanned |
| security_score | INT | 0-100 score |
| findings_json | JSON | Full findings array |
| packages_json | JSON | Package inventory |
| sbom_json | JSON | Software Bill of Materials |
| ai_sbom_json | JSON | AI-specific SBOM |
| duration_ms | INT | Scan duration |
| created_at | TIMESTAMP | Auto |

**Indexes:** (user_id, created_at), (project_id, created_at)

---

### `ghin_reports`
Individual crowdsourced hallucination reports from users.

| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| user_id | CUID FK | → users.id (nullable — anonymous allowed) |
| package_name | TEXT | Package reported |
| ecosystem | ENUM | `NPM` \| `PYPI` \| `CARGO` \| `GEM` \| `GO` |
| report_type | ENUM | `HALLUCINATION` \| `FALSE_POSITIVE` \| `TYPOSQUAT` \| `MALICIOUS` |
| confidence | FLOAT | 0.0–1.0 (reporter's confidence) |
| verified | BOOLEAN | Admin-verified flag |
| metadata | JSON | Registry response, notes |
| created_at | TIMESTAMP | Auto |

---

### `ghin_packages`
Aggregated intelligence — rebuilt from reports by the consolidation daemon.

| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| package_name | TEXT | Package name (lowercase) |
| ecosystem | ENUM | Package ecosystem |
| report_count | INT | Total reports |
| status | ENUM | `SUSPECTED` \| `CONFIRMED` \| `FALSE_POSITIVE` \| `MALICIOUS` |
| first_seen_at | TIMESTAMP | First report |
| last_seen_at | TIMESTAMP | Latest report |
| verified_at | TIMESTAMP | When registry-verified |
| metadata | JSON | Extra data |

**Unique constraint:** (package_name, ecosystem)

---

### `policy_templates`
Shareable security policy configurations.

| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| team_id | CUID FK | → teams.id (nullable = global template) |
| name | TEXT | Template name |
| description | TEXT | What this policy enforces |
| is_public | BOOLEAN | Shared publicly |
| policy_json | JSON | Full `.codeguard/policy.json` content |
| created_at | TIMESTAMP | Auto |
| updated_at | TIMESTAMP | Auto-updated |

---

### `webhooks`
Outbound notification endpoints.

| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| team_id | CUID FK | → teams.id (nullable) |
| name | TEXT | Webhook label |
| url | TEXT | Target URL |
| secret | TEXT | HMAC-SHA256 signing secret |
| events | TEXT[] | e.g. `["scan.completed","critical.found"]` |
| active | BOOLEAN | On/off switch |
| created_at | TIMESTAMP | Auto |
| updated_at | TIMESTAMP | Auto-updated |

---

### `webhook_deliveries`
Delivery log for each webhook fire.

| Column | Type | Notes |
|--------|------|-------|
| id | CUID | Primary key |
| webhook_id | CUID FK | → webhooks.id |
| event | TEXT | Event type |
| payload | JSON | Full payload sent |
| status_code | INT | HTTP response code |
| success | BOOLEAN | Whether delivery succeeded |
| error | TEXT | Error message if failed |
| delivered_at | TIMESTAMP | Auto |

---

## Enums Summary

| Enum | Values |
|------|--------|
| `UserRole` | `USER`, `ADMIN`, `ENTERPRISE` |
| `TeamPlan` | `FREE`, `PRO`, `ENTERPRISE` |
| `MemberRole` | `OWNER`, `ADMIN`, `MEMBER`, `VIEWER` |
| `ScanSource` | `CLI`, `EXTENSION`, `GITHUB_ACTION`, `PRE_COMMIT`, `API` |
| `ScanStatus` | `PENDING`, `RUNNING`, `COMPLETED`, `FAILED` |
| `Ecosystem` | `NPM`, `PYPI`, `CARGO`, `GEM`, `GO` |
| `GhinReportType` | `HALLUCINATION`, `FALSE_POSITIVE`, `TYPOSQUAT`, `MALICIOUS` |
| `GhinStatus` | `SUSPECTED`, `CONFIRMED`, `FALSE_POSITIVE`, `MALICIOUS` |
