# Changelog

## [8.0.0] — The "Best-in-World" Release

Ten brand-new detection engines, positioning CodeGuard AI as the most
complete AI-era security platform.

### Added — AI-Specific Superpowers

#### MCP CVE Database (`src/shield/mcp-cve-db.ts`)
- Curated registry of known MCP CVEs (CVE-2025-6514 `mcp-remote` RCE,
  CVE-2025-53110 path traversal, CVE-2025-49596 Inspector 0-day,
  CVE-2025-52882 Claude Code WebSocket hijack, +3 more)
- **9 known-bad MCP servers** (confirmed malicious, typosquat, abandoned,
  suspicious origin) with provenance dates
- Risky-URL pattern matcher (shortener, tunneling, Tor, pastebin, raw IP)
- Semver-aware version match; extracts candidate package names from
  `command`, `args`, and `url`

#### LLM Jailbreak Scanner (`src/checkers/jailbreak-scanner.ts`)
- **30+ rules** across 8 categories: direct jailbreak (DAN/STAN/AIM/Kevin),
  role override, prompt leak, known payloads, unsafe concatenation, hidden
  Unicode (zero-width, BiDi, Unicode Tags block), system-prompt tag
  injection (ChatML / Llama control tokens), covert-action directives
- Scans `.py`, `.js`, `.ts`, `.md`, `.json`, `.yaml`, `CLAUDE.md`,
  `.cursorrules`, `.windsurfrules`, `copilot-instructions.md`
- OWASP LLM Top 10 mapping (LLM01, LLM02)

#### ML Model File Scanner (`src/checkers/model-file-scanner.ts`)
- **Pickle exploit detection** at the byte level (no Python runtime):
  parses GLOBAL/STACK_GLOBAL opcodes, matches 50+ dangerous callables
  (`os.system`, `subprocess.*`, `builtins.eval`, `runpy.*`, `ctypes.CDLL`)
- Handles both raw pickle and ZIP-wrapped torch models
- **Keras Lambda-layer detection** in `.h5`/`.hdf5`/`.keras`
- **ONNX** external-data exfiltration + custom-op domain scan
- **safetensors** header validation + metadata hidden-Unicode check
- **HuggingFace** `auto_map` / `trust_remote_code` detection
- Source-code rules for `torch.load`, `pickle.load`, `joblib.load`,
  `yaml.load`, `load_model` without `safe_mode=True`, `trust_remote_code=True`

#### Enhanced Typosquat Engine (`src/intelligence/typosquat-enhanced.ts`)
- **10-signal detection:** Levenshtein, Damerau (transposition), keyboard
  adjacency (QWERTY map), homoglyph (Cyrillic/Greek/number-for-letter),
  phonetic (Metaphone-lite), separator tricks, suspicious suffix
  (`-pro`, `-official`, `-tools`, `2`, `-v2`…), prefix tricks, plural
  flips, scope drop, case variants
- **350+ popular npm + PyPI packages** as typosquat targets
- Weighted scoring with severity (critical/high/medium/low) + actionable
  recommendation strings per match

#### Expanded Secrets Patterns (`src/checkers/secrets-checker.ts`)
- **+35 new patterns** covering AI providers (HuggingFace, Replicate,
  Cohere, Mistral/Codestral, Groq, Perplexity, Together AI, xAI Grok,
  DeepSeek, Fireworks AI, Azure OpenAI, Vertex AI SA, AI21, Pinecone,
  Weaviate, LangSmith), cloud (Azure Storage, Azure AD, GCP API,
  DigitalOcean, Heroku), CI/dev (GitLab, Bitbucket, CircleCI, Docker Hub),
  payment (Square, PayPal, Plaid), and more (Mailgun, Mailchimp, Discord,
  Telegram, Shopify, Datadog, New Relic)

### Added — Supply Chain Depth

#### Maintainer Reputation (`src/intelligence/maintainer-reputation.ts`)
- Queries npm & PyPI registry metadata for 14 signals:
  no-maintainer / single-maintainer / disposable-email / flagged-account /
  **unstable-ownership** (latest publisher ∉ maintainers) /
  rare-publisher-recent-release / missing-repo / very-new-package /
  low-downloads / short-README / …
- Pluggable `fetchJson` + cache hooks for integration with the extension's
  existing cache layer

#### Publish Anomaly Detector (`src/intelligence/publish-anomaly.ts`)
- 6 detectors: out-of-order patches (old-major exploit), burst publish
  (5+ versions in 6h), dormant-then-active-with-publisher-change
  (event-stream pattern), massive major-version jump, zero-to-1.0
  shortcut, publisher churn

#### Cryptojacking Scanner (`src/checkers/cryptojacking-scanner.ts`)
- **30 mining pool hostnames** (Monero, BTC, ETH Classic) + **18 in-browser
  miner libs** (Coinhive, CryptoNight, jsecoin, coinimp…) + 12 pattern
  rules (XMR/BTC/ETH wallets, xmrig/minerd/ccminer binaries, mining
  algorithm flags, base64-encoded PE/ELF droppers)
- **Auto-escalates severity** when found in `package.json` install scripts

#### License Compliance Engine (`src/checkers/license-compliance.ts`)
- **40+ SPDX ids** categorized (permissive / weak-copyleft /
  strong-copyleft / network-copyleft / commercial-restricted /
  proprietary / public-domain / unknown)
- SPDX expression parser (OR / AND / WITH)
- Compatibility matrix (Apache+GPL-2, MIT+AGPL, MIT+SSPL/BUSL/Elastic)
- Policy configurable via `.codeguard/policy.json` `licenses` block

### Added — Broader SAST Coverage

#### IaC Scanner (`src/checkers/iac-scanner.ts`)
- **35+ rules** across Dockerfile (13), Kubernetes (12), Terraform (12)
- CIS benchmark mapping (CIS-Docker 4.1/4.9/4.10, CIS-Kubernetes 5.2.*,
  CIS-AWS 1.16/2.1.3/2.3.*/4.1)
- Dockerfile: no USER, :latest, curl|sh, chmod 777, embedded secrets in
  ENV, --insecure
- K8s: privileged/hostNetwork/hostPID, runAsUser:0, NET_ADMIN/SYS_ADMIN,
  hostPath to /etc/proc/sys/docker.sock, automountSA token, secret env
  as plain value
- Terraform: public S3 ACL, 0.0.0.0/0 security groups, publicly_accessible
  DBs, unencrypted storage, wildcard IAM, hardcoded access keys, Azure
  public blob access, GCP allUsers bindings

#### API Security Scanner (`src/checkers/api-security-scanner.ts`)
- **33 rules** unified across JWT, GraphQL, deserialization, and API design
- **JWT:** alg:none, weak/short secret, placeholder secret, missing
  `expiresIn`, `jwt.decode` without verify, PyJWT `verify=False`
- **GraphQL:** introspection in prod, Playground in prod, missing depth
  limits, batching enabled
- **Deserialization:** pickle, YAML unsafe, Java ObjectInputStream,
  PHP unserialize, Ruby Marshal.load, .NET BinaryFormatter, node-serialize
- **API design:** CORS `*`, open redirect, **BOLA/IDOR** patterns (OWASP
  API1:2023), mass assignment (Object.assign/new Model(req.body)),
  permissive rate limits, CSRF cookie `secure:false`
- CWE + OWASP API Top 10 mappings

### New VS Code Commands
- `CodeGuard v8: Scan MCP Servers Against CVE Database`
- `CodeGuard v8: Scan for LLM Jailbreak Patterns`
- `CodeGuard v8: Scan ML Model Files (Pickle/ONNX/Keras)`
- `CodeGuard v8: Check Package for Typosquat Risk`
- `CodeGuard v8: Run All New Detection Engines`

### Changed
- Version bumped to **8.0.0**
- 18 new keywords added to `package.json` (MCP, jailbreak, pickle,
  IaC, terraform, kubernetes, JWT, OWASP, etc.)
- Description rewritten to reflect full AI-era scope

### Removed
- Obsolete build artifacts: `codeguard-ai-5.2.0.vsix`, `codeguard-ai-7.0.0.vsix`
- One-off test script: `smoke-test-v3.js`
- Consolidated/redundant docs: `TEAM_ONBOARDING.md`, `DEPLOYMENT.md`,
  `PROJECT_SUMMARY.md`, `EXTENSION_BUILD.md` (their content is covered
  by `DEPLOYMENT_GUIDE.md` / `QUICKSTART.md` / `README.md`)

### Engine-Level Numbers (v8.0)
- **7 MCP CVEs** + **9 known-bad servers** + **5 risky-URL patterns**
- **30+ jailbreak rules** across 8 categories
- **50+ dangerous pickle globals** + **6 unsafe-load rules**
- **350 popular packages** protected + **26 keyboard keys** mapped +
  **24 homoglyph groups** + **29 suspicious suffixes**
- **60+ secret patterns** (up from 22)
- **14 maintainer reputation signals** + **6 publish-anomaly detectors**
- **30 mining pool hosts** + **18 miner libs** + **12 cryptojack patterns**
- **40+ SPDX license ids** across 8 categories
- **35+ IaC rules** across Dockerfile/K8s/Terraform
- **33 API security rules** (JWT/GraphQL/deserialization/design)

---

## [7.2.0] - 2026-04-01

### Added — Agentic Security Architecture

#### Feature Flags System (`backend/src/services/feature-flags.ts`)
- Dynamic feature flag service with 3-tier priority: runtime overrides > env overrides > defaults
- 16 flags covering core, security, team, and experimental features
- Per-user flag overrides via Redis (24h TTL)
- Environment variable override support (`FEATURE_FLAG_<NAME>=true|false`)

#### GHIN Consolidation Daemon (`backend/src/services/ghin-consolidator.ts`)
- Background service (KAIROS-inspired) that runs every 15 minutes
- **Phase 1:** Auto-confirms suspected packages with 3+ hallucination reports (requires 3:1 hallucination-to-false-positive ratio)
- **Phase 2:** Recalculates weighted confidence scores across all reports
- **Phase 3:** Cleans stale low-confidence entries (>90 days, <2 reports)
- **Phase 4:** Rebuilds and caches GHIN network statistics
- Configurable interval via `GHIN_CONSOLIDATION_INTERVAL_MS`

#### Memory Verification Service (`backend/src/services/memory-verifier.ts`)
- "Skeptical memory" approach: verifies GHIN data against live npm/PyPI registries
- Batch verification of unverified/stale entries (prioritizes most-reported)
- Confidence decay: auto-downgrades CONFIRMED → SUSPECTED after 30 days without re-verification
- Rate-limited registry calls (200ms between requests)

#### Admin API (`backend/src/routes/admin.ts`)
- `GET /api/admin/flags` — View all feature flags
- `POST /api/admin/flags` — Set runtime flag overrides
- `DELETE /api/admin/flags` — Reset all overrides
- `POST /api/admin/ghin/consolidate` — Manually trigger consolidation
- `POST /api/admin/ghin/verify` — Trigger registry verification
- `POST /api/admin/ghin/decay` — Apply confidence decay
- `GET /api/admin/stats` — Comprehensive system statistics
- All endpoints require ADMIN role

#### Deployment Infrastructure
- `DEPLOYMENT_GUIDE.md` — Step-by-step guide (Supabase + Railway/Render)
- `render.yaml` — Render Blueprint for one-click deployment
- `backend/Procfile` — Railway/Heroku process file
- Updated `.env.example` with feature flag and consolidation config

### Changed
- `backend/src/server.ts` — Wired admin routes, GHIN consolidation daemon, feature flags
- API version bumped to 7.2.0
- Backend package version bumped to 7.2.0

## [7.1.0] - 2026-03-21

### Added — Production Backend API

#### Backend Server (`backend/`)
- **Express.js + TypeScript** backend with Prisma ORM and Supabase PostgreSQL
- **3-strategy authentication**: Supabase JWT (browser), API keys `cg_xxx` (CLI/CI), custom JWT
- **GHIN Intelligence API** — report, check, bulk-check (100 packages), list, statistics endpoints
- **Scan History API** — upload results from CLI/extension/CI, list, get, 30-day trend analysis
- **Team Management API** — create teams, invite members, team scan statistics
- **API Key Management** — create/list/revoke API keys with SHA-256 hashing
- **Rate Limiting** — Upstash Redis sliding window (graceful degradation if not configured)
- **Security** — Helmet headers, CORS, Zod request validation, global error handler
- **Error Monitoring** — Sentry integration (optional)
- **Health Checks** — `/health` (basic) and `/health/ready` (DB + Redis connectivity)

#### Database Schema (Prisma, 11 models)
- `users`, `api_keys`, `teams`, `team_members`, `projects`, `scans`
- `ghin_reports`, `ghin_packages` (hallucination intelligence)
- `policy_templates`, `webhooks`, `webhook_deliveries`

#### Infrastructure
- `.env.example` — all required keys with free-tier signup instructions
- `backend/Dockerfile` — multi-stage production Docker build
- `docker-compose.yml` — backend + PostgreSQL for local development
- `.github/workflows/ci.yml` — CI pipeline for extension + CLI + backend
- `.gitignore` updated for `.env`, backend build artifacts, logs

#### Documentation
- `PROGRESS.md` — comprehensive project status, architecture, API reference, setup guide, roadmap
- `CHANGELOG.md` — v7.1.0 entry

### Build Status
- Backend: `npm run build` ✅ 0 errors
- Prisma: `npx prisma generate` ✅ client generated
- Extension: `npm run compile` ✅ clean
- CLI: 15/15 tests passing

## [7.0.0] - 2026-03-20

### Added — Phase 4-5: Agentic Supply Chain Security & Competitive Differentiation

#### MCP Server Scanner (`src/shield/mcp-scanner.ts`)
- Scans `mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`, `cline_mcp_settings.json`, `.vscode/mcp.json`
- 7 detection categories: tool poisoning, rug-pull risk, cross-origin escalation, prompt injection, unverified servers, data exfiltration, credential exposure
- Supports multiple config formats: `mcpServers`, `servers`, `mcp.servers`
- File watchers for real-time MCP config scanning in the IDE
- VS Code diagnostics integration with severity-mapped errors/warnings
- CLI integration: `scanMcpConfigs()` in `cli/src/scanner.ts`

#### Shadow AI Discovery (`src/shield/shadow-ai-discovery.ts`)
- Discovers all AI tools, SDKs, MCP servers, agent frameworks, and model files in workspace
- **AI-SBOM** (AI Software Bill of Materials) — first-of-kind AI component inventory
- 15+ AI SDK detectors: OpenAI, Anthropic, LangChain, CrewAI, AutoGen, Hugging Face, MCP SDK, Google Gemini, Cohere, Ollama, Replicate, PyTorch, TensorFlow, Vercel AI, LlamaIndex
- Model file detection: `.onnx`, `.pt`, `.safetensors`, `.gguf`, `.ggml`, `.h5`, `.tflite`, `.mlmodel`
- AI config file detection: 18+ patterns covering Cursor, Windsurf, Claude, Cline, Continue, Aider, Codeium, Copilot
- JSON export for compliance and audit workflows

#### Agentic Permission Policy (v7 policy rules)
- `block_npx_mcp_servers` — block MCP servers that use npx/bunx (rug-pull risk)
- `block_unencrypted_mcp` — block MCP servers connecting over plain HTTP
- `allowed_mcp_servers` — allowlist for approved MCP server names
- `block_mcp_hardcoded_credentials` — block hardcoded credentials in MCP env
- `max_mcp_issues` — maximum number of MCP security issues allowed
- `require_ai_sbom` — require AI-SBOM to be generated
- `allowed_ai_sdks` — allowlist for approved AI SDKs (shadow AI governance)

#### AI Config Shield Expansion
- Added `CLAUDE.md`, `.claude/**`, `.clinerules`, `.windsurf/rules/**`, `.aider.model.settings.yml`, `.devcontainer/copilot-instructions.md` to Rules File Scanner

#### New VS Code Commands
- `codeguard.scanMcpServers` — Scan MCP Server Configurations
- `codeguard.discoverShadowAi` — Discover Shadow AI (AI-SBOM)
- `codeguard.exportAiSbom` — Export AI-SBOM (JSON)

#### Unit Tests (3 new CLI tests, 15 total)
- MCP npx rug-pull risk detection
- MCP hardcoded credential detection
- MCP scanning disable option

### Changed
- `src/shield/rules-scanner.ts` — expanded `AI_CONFIG_GLOBS` from 11 to 17 patterns
- `src/policy/engine.ts` — added 7 agentic supply chain rules to `PolicyRules` interface, `evaluateFull()`, and `createDefaultPolicy()`
- `src/extension.ts` — integrated MCP Scanner and Shadow AI Discovery modules, added `escapeHtml()` helper, registered 3 new commands
- `cli/src/scanner.ts` — added `mcp` finding type, `mcpIssues` summary field, `mcp` scan option, `scanMcpConfigs()` method
- `package.json` — added 3 new command registrations
- `README.md` — added Layer 8 (Agentic Supply Chain Security)
- Version bumped to 7.0.0

## [6.0.0] - 2026-03-16

### Added — Phase 0-2: Platform Evolution

#### Bundled Hallucination Intelligence Data
- New `src/data/popular-packages.json` — 500 npm + 300 PyPI popular packages for offline typosquatting detection
- New `src/data/known-hallucinations.json` — 520+ known AI-hallucinated package names (seed DB v1)
- `HallucinationDetector` now loads from JSON files instead of inline arrays
- New `knownHallucination` field in `HallucinationAnalysis` — flags packages in the seed DB instantly (no network)
- GHIN `seedFromBundledJson()` — merges 520+ entries on first install, version-tracked for auto-merge on updates

#### CLI Tool (`cli/`)
- New `@codeguard-ai/cli` — standalone security scanner with zero vscode dependency
- `codeguard scan` — scan projects for hallucinations, secrets, SAST patterns
- `codeguard pre-commit` — pre-commit hook mode (exit 1 on critical/high)
- Output formats: `table` (colored terminal), `json`, `sarif` (GitHub Code Scanning compatible)
- Severity filtering, package ignore lists, private scope support
- Core scanner: hallucination check (known DB + registry), secrets (10 patterns), SAST (12 rules)
- **OSV.dev vulnerability scanning** — queries OSV.dev API for known CVEs per package+version, with severity mapping and fix suggestions
- **Policy evaluation** — reads `.codeguard/policy.json` for forbidden packages, max vulnerability severity, required scanners, hallucination blocking
- Package list populated even when hallucination check is disabled (enables vuln + policy checks independently)
- SARIF v2.1.0 formatter with rule definitions, locations, and fix suggestions
- Colored table formatter with severity badges and grouped output

#### GitHub Action (`cli/action.yml`)
- Composite action: setup Node → install → scan → upload SARIF → check threshold
- Inputs: path, format, severity, fail-on, upload-sarif, ignore, private-scopes
- Outputs: findings, critical, high, hallucinations, sarif-file
- Auto-uploads to GitHub Code Scanning when `upload-sarif: true`

#### Unit Tests (5 new test files, 12 CLI tests)
- `hallucination.test.ts` — known DB, typosquatting, namespace confusion, risk levels
- `detector.test.ts` — burst insertion, paste detection, import-heavy, confidence
- `policy.test.ts` — package evaluation, full evaluation, multiple violation scenarios
- `version-resolver.test.ts` — manifest parsing, requirements.txt, semver stripping
- `integration.test.ts` — end-to-end AI detection → hallucination → risk pipeline

### Fixed
- Dashboard version string (v5.0.0 → v5.2.0) in `extension.ts`
- Unused imports in test files (lint cleanup)
- Added `cli/` to main `tsconfig.json` exclude list

### Changed
- `src/checkers/hallucination.ts` — imports from JSON data files, added `checkKnownHallucination()` method
- `src/intelligence/ghin.ts` — imports bundled JSON, added `seedFromBundledJson()` with version tracking
- `README.md` — added CLI reference, GitHub Action section, updated Quick Start
- Version bumped to 6.0.0

---

## [5.2.0] - 2026-02-23

### Added — Phase 3: Team Intelligence

#### Team Dashboard (React SPA)
- New `cloud/dashboard/` — Vite + React 18 + Recharts + TailwindCSS SPA
- 5 tabs: Overview, Trends (30-day charts), Packages (vulnerable/hallucinated/low-trust), AI Agents comparison, Developers (anonymized)
- Connects to GHIN API via `/api/v1/dashboard/*` endpoints
- New GHIN API endpoints: `/dashboard/overview`, `/dashboard/trends`, `/dashboard/top-packages`, `/dashboard/developers`

#### Webhook Integrations
- New `cloud/ghin-production/src/webhooks.ts` — `WebhookService` class
- Slack: formatted Block Kit messages with severity emoji and package details
- Microsoft Teams: MessageCard with color-coded theme and action buttons
- Jira: Creates issues with Atlassian Document Format description, auto-priority from severity
- Generic HTTP: JSON payload to any endpoint with optional auth header
- `POST /api/v1/webhooks/test` endpoint for connection testing

#### Compliance Report Export
- New `src/reports/compliance.ts` — `ComplianceReportGenerator`
- Formats: Markdown (human-readable), CSV (spreadsheet), JSON (programmatic)
- Sections: Executive Summary, Vulnerability Inventory, Dependency Trust Scores, AI Code Attribution, Policy Compliance, Hallucination Log, Compliance Framework Mapping
- Framework mapping: EU Cyber Resilience Act, US EO 14028, SOC 2 Type II, ISO 27001
- New command: `CodeGuard: Export Compliance Report (CSV/Markdown/JSON)`

#### README v5.2
- Full competitive comparison table vs Claude Code Security
- 7 feature layers documented
- 30 commands listed

### Changed
- Version bumped to 5.2.0
- Total commands: 30

---

## [5.0.0] - 2026-02-22

### Added — Phase 1 & 2: Competitive Moat Features

#### Hybrid SAST Engine (`src/checkers/hybrid-sast.ts`)
- 3-pass architecture: instant regex (35 rules) → LLM deep analysis → adversarial self-verification
- Covers: injection, XSS, crypto misuse, path traversal, SSRF, prototype pollution, race conditions, deserialization
- Falls back to regex-only when LLM unavailable (offline mode)
- Wired into real-time document change events

#### Cross-File Taint Tracker (`src/analysis/taint-tracker.ts`)
- Tracks tainted data (user input, env vars, request params) through import graph to dangerous sinks
- Sinks: SQL queries, exec/spawn, innerHTML, eval, file writes, HTTP redirects
- Incremental updates on file save, workspace-wide analysis on demand
- New command: `CodeGuard: Cross-File Taint Analysis`

#### AI Code Attribution Engine (`src/ai/code-attribution.ts`)
- Tags code regions as AI-generated vs human-written using `AiGenerationDetector` signals
- Computes per-file and aggregate AI/human vulnerability rates
- Persists attribution map in `.codeguard/attribution.json`
- New command: `CodeGuard: AI Code Attribution Report`

#### Policy-as-Code Engine (`src/policy/engine.ts`)
- Reads `.codeguard/policy.json` — define blocklists, provenance requirements, AI ratio limits
- Modes: `audit` (log only), `warn` (diagnostics), `enforce` (block + error)
- Real-time enforcement on document open/change
- New commands: `CodeGuard: Evaluate Security Policy`, `CodeGuard: Create Default Policy File`

#### Git Security Regression Detector (`src/analysis/git-regression.ts`)
- Diffs current files against `HEAD` via `git diff`
- Detects: removed input validation, removed auth checks, crypto algorithm downgrade, dependency version rollback, removed sanitization
- New command: `CodeGuard: Git Regression Scan`

#### Sandbox Runtime Analysis (`src/shield/sandbox-runner.ts`)
- Runs package install scripts in a Node.js VM sandbox
- Static analysis + dynamic observation of network calls, fs writes, process spawning, env access
- Compares observed permissions against declared permissions
- Integrated with Install Gate

### Changed
- Version bumped to 5.0.0
- ESLint configuration added (`.eslintrc.json`)
- Total commands: 29

---

## [0.5.0] - 2026-02-20

### Improved — Production Hardening & UI Upgrade

#### UI Modernization
- **Dashboard**: Premium dark glassmorphism design with animated gradient header, circular SVG score gauge, glassmorphic stat cards, active modules grid
- **Status Bar**: Numeric security score (🛡️ 87) with color-coded thresholds (green/orange/red) and rich MarkdownString tooltips
- **Install Gate**: Replaced QuickPick modal with rich webview panel — verdict cards with colored badges, summary pills, Install Safe / Cancel actions
- **Findings TreeView**: ThemeIcon codicons per source type (package, key, code, sparkle, verified, terminal), badge count on sidebar, welcome message for empty state

#### Code Cleanup & Deduplication
- Extracted shared IDE/AI agent detection into `src/utils/ide-detect.ts`
- Removed legacy `cloud/ghin-api/` (Cloudflare Workers, superseded by production Fastify backend)
- Removed old `smoke-test.js` and `smoke-test-v2.js`
- Removed unrelated AD-Simulator test files

#### Deployment & Documentation
- New `DEPLOYMENT.md` — full guide for accounts, hosting, database, .env setup
- New `.env.example` for GHIN production API
- Updated `PUBLISHING.md` to reference production backend
- Updated activation log to v5

---

## [0.4.0] - 2026-02-19

### Added — Enterprise Security Layer

#### Dependency Permission Model
- Capability-based permissions: network, filesystem, subprocess, native, env access
- Auto-detection from package metadata and known package capabilities
- Policy enforcement with allow/deny/prompt actions

#### Composite Trust Score Engine
- Multi-signal trust scoring: provenance, popularity, age, maintenance, security history
- Configurable weighting per signal
- Trust tier assignment (verified → trusted → partial → suspicious → untrusted)

#### GHIN Production Client
- Fastify + PostgreSQL production backend
- Bulk package checks, agent stats, cooldown on API unavailability
- Retry logic with exponential backoff

#### Findings TreeView (Sidebar)
- Severity-grouped findings panel (Critical → High → Medium → Low → Info)
- Source-specific icons, file navigation, fix indicators
- Aggregate findings from all checkers

#### Telemetry Reporter (Opt-in)
- Anonymous usage telemetry to GHIN cloud
- Extension activation, scan events, finding counts
- Fully opt-in with `codeguard.enableTelemetry`

#### Score History
- Tracks security score over time
- Trend detection (improving, declining, stable)

### New Commands
- `CodeGuard: Show Security Score`
- `CodeGuard: Detect SBOM Drift`
- `CodeGuard: Save SBOM Baseline`
- `CodeGuard: Scan for Secrets`
- `CodeGuard: Scan for Code Vulnerabilities`

---

## [0.3.0] - 2026-02-19

### Added — Security Immune System

#### Rules File Integrity Scanner
- Scans `.cursorrules`, `copilot-instructions.md`, `.windsurfrules` for hidden attacks
- Detects 24 hidden Unicode characters (zero-width joiners, bidirectional marks)
- Detects 15+ prompt injection patterns (role override, security suppression)
- "Sanitize File" command to remove hidden Unicode
- First defense against "Rules File Backdoor" attack (Pillar Security 2025)

#### Global Hallucination Intelligence Network (GHIN)
- Crowdsourced hallucination database seeded with 46 known hallucinations
- Based on USENIX Security 2025 research (205K hallucinated package names)
- Local persistence + cloud API ready (opt-in anonymous reporting)
- Risk scoring, model attribution, attacker-claimed tracking

#### Cryptographic Provenance Checker
- npm Sigstore attestation verification
- PyPI PEP 740 attestation support
- Trust tiers: 🟢 Verified, 🟡 Partial, 🟠 Suspicious, 🔴 Untrusted
- SLSA level extraction, source repo verification

#### Auto-Patch Engine
- Aggregates fixes from OSV.dev, GitHub Advisory, npm audit
- 18 deprecated packages mapped to safe alternatives
- One-click patch commands for npm, PyPI, Cargo, Go
- Markdown reports formatted for AI assistants

#### Install Script Static Analyzer
- Analyzes preinstall/postinstall scripts before execution
- Detects 20+ suspicious patterns (network, env theft, process spawn, obfuscation)
- Downloads and inspects package tarballs

#### Package Install Gate (Terminal Firewall)
- Intercepts npm/pip/yarn/pnpm/cargo/go/gem install commands
- Analyzes packages for hallucination, provenance, vulnerabilities, scripts
- Modal UI with approve/block options

#### LLM Advisory Layer
- Uses VS Code Language Model API (Copilot) for explanations
- Patch explanation generation
- Risk summary in plain language
- Fallback to deterministic explanations when LLM unavailable

#### Semantic Intent Verifier
- Compares user intent vs AI-generated code
- Detects external scripts, network calls, env access, obfuscation
- Catches Rules File Backdoor attacks in real-time

#### Agentic Patch Assistant
- Automated workflow: analyze → suggest → apply patches
- Edits package.json / requirements.txt directly
- LLM-powered patch explanations

#### Live SBOM Generator
- Real-time CycloneDX 1.5 format SBOM
- Tracks npm, PyPI, Cargo, Go dependencies
- Auto-updates on dependency changes
- Output: `.codeguard/sbom.cdx.json`

#### Trust Tier Tree View
- Sidebar panel showing dependencies by trust tier
- Quick access to provenance, vulnerabilities, patch actions
- Visual indicators for verified/vulnerable/deprecated packages

### New Commands
- `CodeGuard: Scan AI Config Files for Attacks`
- `CodeGuard: Sanitize Rules File (Remove Hidden Unicode)`
- `CodeGuard: GHIN Hallucination Database Stats`
- `CodeGuard: Check Package Provenance (Sigstore)`
- `CodeGuard: Get Patch Report for Package`
- `CodeGuard: Run Patch Agent (Auto-fix Vulnerabilities)`
- `CodeGuard: Generate SBOM (CycloneDX)`
- `CodeGuard: Explain Security Issue with AI`
- `CodeGuard: Refresh Trust Tier View`

### New Configuration
- `codeguard.enableInstallGate` — Terminal firewall
- `codeguard.enableRulesScanner` — AI config file scanning
- `codeguard.enableGhin` — GHIN local database
- `codeguard.enableGhinCloudSync` — Opt-in cloud sync
- `codeguard.enableProvenanceCheck` — Sigstore verification
- `codeguard.enableAutoPatch` — Auto-patch suggestions
- `codeguard.enableScriptAnalysis` — Install script analysis

---

## [0.2.0] - 2026-02-18

### Added — AI-to-AI Feedback Loop
- AI generation detection (burst insertion, paste patterns, typing speed)
- Comment injection for AI assistants to read security warnings
- CodeLens "Ask AI to Fix" buttons
- @codeguard Chat Participant for Copilot Chat
- Security context provider (`.codeguard/security-context.json`)
- Enhanced hallucination detection (typosquatting, popularity, namespace confusion)
- Version resolver (lockfile → registry fallback)

---

## [0.1.0] - 2026-02-18

### Added
- Real-time document monitoring for AI-generated code
- JavaScript/TypeScript import parser (ES modules, CommonJS, dynamic imports)
- Python import parser (import, from-import, stdlib filtering)
- package.json dependency parser with version extraction
- requirements.txt parser with version extraction
- OSV.dev API integration for vulnerability lookups (batch + single)
- Package registry existence checker (npm, PyPI, Go, Maven, crates.io)
- Hallucinated/slopsquatting package detection
- VS Code Diagnostics with inline warnings (squiggly underlines)
- CodeAction provider with quick-fixes (update version, remove import, view CVE)
- Rich hover tooltips with CVE details, CVSS scores, fix versions
- Status bar indicator (clean/scanning/issues/error states)
- Security dashboard webview panel
- Local cache with configurable TTL and disk persistence
- Configurable severity threshold (LOW/MEDIUM/HIGH/CRITICAL)
- Package allowlist (ignore specific packages)
- Commands: Scan File, Scan Workspace, Clear Cache, Show Dashboard
