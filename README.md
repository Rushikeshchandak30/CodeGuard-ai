# CodeGuard AI — The Immune System for AI-Assisted Development

> **Don't just scan. Shield.** The first AI-aware pre-execution developer security platform.

CodeGuard AI prevents supply chain attacks, AI hallucinations, and insecure code patterns **before they enter your project** — not after. Works with Copilot, Cursor, Windsurf, and all AI coding tools.

---

## CodeGuard AI vs Claude Code Security

| Capability | Claude Code Security | **CodeGuard AI v5.2** |
|:---|:---:|:---:|
| Real-time IDE scanning | - | **YES** |
| LLM-powered deep SAST | YES | **YES** (Hybrid 3-pass) |
| Cross-file data flow tracing | YES | **YES** |
| Adversarial self-verification | YES | **YES** |
| Supply chain analysis | - | **YES** |
| AI hallucination detection | - | **YES** (205K+ DB) |
| Terminal install firewall | - | **YES** |
| Sandbox runtime analysis | - | **YES** |
| Package provenance (Sigstore) | - | **YES** |
| AI config attack scanning | - | **YES** |
| Secrets detection | - | **YES** |
| SBOM generation (CycloneDX) | - | **YES** |
| AI code attribution | - | **YES** |
| Policy-as-Code | - | **YES** |
| Git regression detection | YES | **YES** |
| Compliance report export | - | **YES** |
| Team dashboard | YES | **YES** |
| Webhook integrations | - | **YES** (Slack/Teams/Jira) |
| Crowdsourced intelligence | - | **YES** (GHIN) |
| Offline mode | - | **YES** |
| AI-agent agnostic | - | **YES** |
| Price | Enterprise-only | **Free** |

> Claude finds bugs after they're written. CodeGuard stops them from being written in the first place.

---

## Features

### Layer 1: Pre-Execution Prevention
- **Install Gate** — Intercepts `npm install`, `pip install`, `cargo add` in your terminal.
- **Sandbox Runtime Analysis** — Runs install scripts in a VM sandbox to detect undeclared network/fs/env access before packages execute.
- **Dependency Permission Model** — Shows what a package needs (network, filesystem, env) before you approve it.
- **Install Script Analyzer** — Static analysis of preinstall/postinstall scripts for 20+ malicious patterns.

### Layer 2: Real-Time Code Scanning
- **Hybrid SAST Engine** — 3-pass architecture: instant regex (35 rules) + LLM deep analysis + adversarial self-verification. Falls back to regex-only offline.
- **Cross-File Taint Tracker** — Traces tainted data (user input, env vars) through imports to dangerous sinks (SQL, exec, innerHTML) across your entire project.
- **Hallucination Detection** — Checks if AI-suggested packages exist on npm/PyPI. Backed by GHIN (205K+ known hallucinations).
- **Secrets Scanner** — Detects 20+ patterns: AWS keys, GitHub tokens, Stripe keys, database URLs, private keys.
- **Git Security Regression Detector** — Diffs against HEAD to catch removed validation, auth checks, crypto downgrade, and dependency rollbacks.

### Layer 3: Supply Chain Intelligence
- **Cryptographic Provenance** — Verifies npm Sigstore attestations and PyPI PEP 740. Trust tiers: Verified / Partial / Suspicious / Untrusted.
- **GHIN Network** — Global Hallucination Intelligence Network. Crowdsourced DB that grows with every user.
- **Composite Trust Score** — 0-100 score combining provenance, downloads, age, scripts, typosquatting, GitHub stars.
- **Auto-Patch Engine** — Finds safe versions and generates upgrade commands automatically.

### Layer 4: AI Advisory & Attribution
- **AI Code Attribution Engine** — Tracks AI-generated vs human-written code and correlates with vulnerability rates. No other tool does this.
- **LLM Explanations** — Uses VS Code Language Model API (Copilot GPT-4o) to explain CVEs in plain English.
- **Semantic Intent Verifier** — Compares what you asked the AI for vs. what it generated.
- **Agentic Patch Assistant** — Automated fix workflow: detect, analyze, suggest, apply.

### Layer 5: Policy & Compliance
- **Policy-as-Code Engine** — Define security rules in `.codeguard/policy.json`. Enforce package blocklists, provenance requirements, AI code ratio limits, and more.
- **Compliance Report Export** — Generate audit-ready reports in Markdown, CSV, or JSON. Covers CRA, EO 14028, SOC 2, ISO 27001.
- **Security Score** — Project posture score (0-100, A-F grade) displayed in status bar with trend tracking.
- **Live SBOM** — CycloneDX 1.5 format, auto-updated. SBOM drift detection against baselines.
- **Findings TreeView** — Sidebar panel with all findings grouped by severity.

### Layer 6: Team Intelligence
- **Team Dashboard** — React SPA showing team-wide security scores, AI agent comparison, hallucination trends, top vulnerable packages.
- **Webhook Integrations** — Real-time notifications to Slack, Microsoft Teams, Jira, or any HTTP endpoint.
- **Developer Analytics** — Anonymized per-developer security stats (opt-in).

### Layer 7: Defense Against AI Config Attacks
- **Rules File Scanner** — Scans `.cursorrules`, `.windsurfrules`, `CLAUDE.md`, `.clinerules`, `copilot-instructions.md`, and 16 more config patterns for hidden Unicode attacks and prompt injection.
- **Sanitize Action** — One-click removal of hidden characters from compromised config files.

### Layer 8: Agentic Supply Chain Security (NEW)
- **MCP Server Scanner** — Scans `mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`, `cline_mcp_settings.json` for tool poisoning, rug-pull risks, credential exposure, prompt injection, and suspicious commands.
- **Shadow AI Discovery** — Discovers all AI tools, SDKs, MCP servers, agent frameworks, and model files in your workspace. Generates an **AI-SBOM** (AI Software Bill of Materials).
- **AI-SBOM Export** — JSON export of every AI component in your project — the first AI-specific SBOM format.
- **15+ AI SDK Detectors** — Automatically detects OpenAI, Anthropic, LangChain, CrewAI, AutoGen, Hugging Face, MCP SDK, and more in source code.

---

## Quick Start

### VS Code Extension (Install from VSIX)
```bash
code --install-extension codeguard-ai-5.2.0.vsix
```

### CLI Tool (for CI/CD and command line)
```bash
# From project root
cd cli && npm install && npm run build

# Scan any project
node dist/index.js scan --path /your/project

# Pre-commit hook mode (exits 1 on critical/high)
node dist/index.js pre-commit --path .

# Output SARIF for GitHub Code Scanning
node dist/index.js scan --format sarif --output results.sarif

# JSON output for pipelines
node dist/index.js scan --format json --output report.json
```

### Build from Source
```bash
cd codeguard-ai
npm install
npm run compile
npx @vscode/vsce package --no-dependencies

# Build CLI separately
cd cli && npm install && npm run build
```

### Use It
1. **IDE:** Open any project in VS Code / Cursor / Windsurf — scanning starts automatically
2. **CLI:** Run `codeguard scan` from your terminal or CI pipeline
3. **GitHub Action:** Add the action to your workflow (see below)

---

## Commands (30 total)

| Command | Description |
|---------|-------------|
| `CodeGuard: Scan Current File` | Force scan the active file |
| `CodeGuard: Scan Workspace` | Scan all workspace dependencies |
| `CodeGuard: Show Dashboard` | Open the security dashboard |
| `CodeGuard: Show Security Score` | View project security score breakdown |
| `CodeGuard: Scan for Hardcoded Secrets` | Scan active file for secrets |
| `CodeGuard: Scan for Code Vulnerabilities` | Scan active file for SAST patterns |
| `CodeGuard: Deep SAST Scan` | LLM deep analysis + adversarial verification |
| `CodeGuard: Cross-File Taint Analysis` | Workspace-wide tainted data flow tracing |
| `CodeGuard: AI Code Attribution Report` | View AI vs human code stats |
| `CodeGuard: Evaluate Security Policy` | Run full policy compliance check |
| `CodeGuard: Create Default Policy File` | Generate `.codeguard/policy.json` |
| `CodeGuard: Git Regression Scan` | Detect security regressions in recent changes |
| `CodeGuard: Export Compliance Report` | Generate CSV/Markdown/JSON audit report |
| `CodeGuard: Check Package Provenance` | Verify Sigstore/PEP 740 attestation |
| `CodeGuard: Get Patch Report` | Get CVE + patch info for a package |
| `CodeGuard: Run Patch Agent` | Auto-fix vulnerable dependencies |
| `CodeGuard: Generate SBOM` | Generate CycloneDX 1.5 SBOM |
| `CodeGuard: Detect Dependency Drift` | Compare SBOM to baseline |
| `CodeGuard: Save SBOM Baseline` | Save current SBOM as baseline |
| `CodeGuard: Scan AI Config Files` | Scan .cursorrules etc. for attacks |
| `CodeGuard: Sanitize Rules File` | Remove hidden Unicode from config |
| `CodeGuard: Explain with AI` | LLM explanation of a security issue |
| `CodeGuard: GHIN Stats` | View hallucination database stats |
| `CodeGuard: Analyze Install Command` | Test an install command through the gate |

---

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `codeguard.enabled` | `true` | Master switch |
| `codeguard.severityThreshold` | `MEDIUM` | Minimum severity to display |
| `codeguard.strictnessLevel` | `warn` | `audit` / `warn` / `enforce` |
| `codeguard.enableHallucinationDetection` | `true` | Check package existence |
| `codeguard.enableInstallGate` | `true` | Terminal install interception |
| `codeguard.enableRulesScanner` | `true` | AI config file scanning |
| `codeguard.enableProvenanceCheck` | `true` | Sigstore/PEP 740 verification |
| `codeguard.enableSecretsScanner` | `true` | Hardcoded secrets detection |
| `codeguard.enableCodeVulnScanner` | `true` | SAST pattern detection |
| `codeguard.enableSecurityScore` | `true` | Project security score |
| `codeguard.enableGhinCloudSync` | `false` | Opt-in GHIN cloud telemetry |
| `codeguard.ghinApiUrl` | `https://ghin-api.codeguard.dev` | GHIN API URL (enterprise) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 LAYER 1: VS Code Extension                   │
│  Install Gate · Hybrid SAST · Taint Tracker · Secrets       │
│  Policy Engine · Attribution · Git Regression · Compliance  │
│  Sandbox Runner · Trust Tree · Findings Tree · Score · UI   │
└──────────────────────────▲──────────────────────────────────┘
                           │ local
┌──────────────────────────▼──────────────────────────────────┐
│              LAYER 2: Enforcement Engine (LOCAL)              │
│  35 regex rules · Provenance · Script Analyzer · GHIN       │
│  Terminal interceptor · Permission model · Trust score       │
│  Policy evaluation · Taint analysis · Git diff analysis     │
│  (Runs entirely on developer machine — zero cloud)          │
└──────────────────────────▲──────────────────────────────────┘
                           │ HTTPS (optional, opt-in)
┌──────────────────────────▼──────────────────────────────────┐
│              LAYER 3: GHIN Intelligence API                   │
│  Package validation · CVE lookup · Trust score · Patch      │
│  Hallucination DB · Telemetry · Team Dashboard · Webhooks   │
│  (PostgreSQL + Redis + React SPA)                           │
└──────────────────────────▲──────────────────────────────────┘
                           │ internal
┌──────────────────────────▼──────────────────────────────────┐
│              LAYER 4: Advisory LLM Layer                      │
│  Deep SAST analysis · Adversarial verification              │
│  Risk explanation · Patch generation · Intent verify        │
│  (VS Code Language Model API — Copilot GPT-4o)             │
└─────────────────────────────────────────────────────────────┘
```

**Critical design rule:** All security DECISIONS happen in Layer 2 (local, deterministic). Layers 3-4 provide intelligence only. The extension works fully offline.

---

## Supported Languages

| Language | Import Patterns | Ecosystem |
|----------|----------------|-----------|
| JavaScript | `import`, `require()`, `import()` | npm |
| TypeScript | `import`, `require()` | npm |
| JSX/TSX | `import`, `require()` | npm |
| Python | `import`, `from X import` | PyPI |
| Go | `import "pkg"` | Go modules |
| Rust | `use crate` | crates.io |
| Java | `import pkg` | Maven |
| package.json | `dependencies`, `devDependencies` | npm |
| requirements.txt | `package==version` | PyPI |

---

## CLI Reference

```
codeguard scan [options]          Scan a project for security issues
codeguard pre-commit              Pre-commit hook mode (exit 1 on critical/high)
codeguard --help                  Show help
codeguard --version               Show version
```

| Option | Description |
|--------|-------------|
| `--path, -p <dir>` | Project directory (default: cwd) |
| `--format, -f <fmt>` | Output: `table`, `json`, `sarif` (default: table) |
| `--severity, -s <level>` | Min severity: `critical`, `high`, `medium`, `low` |
| `--output, -o <file>` | Write output to file |
| `--no-color` | Disable colored output |
| `--no-hallucination` | Skip hallucination detection |
| `--no-secrets` | Skip secrets scanning |
| `--no-sast` | Skip SAST scanning |
| `--ignore <pkg1,pkg2>` | Packages to ignore |
| `--private-scopes <@co/>` | Private scoped packages to skip |

---

## GitHub Action

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  codeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./cli
        with:
          path: '.'
          format: sarif
          fail-on: critical
          upload-sarif: true
```

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Project directory to scan |
| `format` | `sarif` | Output format |
| `severity` | `low` | Min severity to report |
| `fail-on` | `critical` | Fail action on: `critical`, `high`, `never` |
| `upload-sarif` | `true` | Upload to GitHub Code Scanning |
| `ignore` | `''` | Comma-separated packages to ignore |
| `private-scopes` | `''` | Private scoped packages to skip |

---

## Backend API (NEW — v7.1)

CodeGuard AI now includes a production backend for GHIN intelligence, scan history, team management, and authentication.

### Quick Start
```bash
# 1. Copy environment file and fill in your keys (see .env.example)
cp .env.example .env

# 2. Install & build
cd backend && npm install && npx prisma generate

# 3. Push database schema to Supabase
npx prisma db push

# 4. Start dev server
npm run dev
```

### Required Accounts (all free tier)

| Service | Free Tier | What You Need |
|---------|-----------|---------------|
| [Supabase](https://supabase.com) | 500 MB, 50K users | `SUPABASE_URL`, keys, `DATABASE_URL` |
| [GitHub OAuth](https://github.com/settings/applications/new) | Free | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` |
| Self-generated | — | `JWT_SECRET` (see `.env.example`) |
| [Upstash](https://upstash.com) *(optional)* | 10K cmds/day | Redis URL + token |
| [Sentry](https://sentry.io) *(optional)* | 5K events/mo | DSN |

### API Endpoints

| Area | Endpoints | Auth |
|------|-----------|------|
| **Health** | `GET /health`, `GET /health/ready` | None |
| **Auth** | `GET /api/auth/github`, `/callback/github`, `/me`, API keys CRUD | Mixed |
| **GHIN** | `POST /api/ghin/report`, `GET /check/:eco/:pkg`, `POST /check-bulk`, `/packages`, `/stats` | Mixed |
| **Scans** | `POST /api/scans`, `GET /api/scans`, `GET /:id`, `GET /trends/summary` | Required |
| **Teams** | `POST /api/teams`, `GET /api/teams`, `GET /:slug`, invite, stats | Required |
| **Admin** | `GET /api/admin/flags`, `POST /api/admin/ghin/consolidate`, `GET /api/admin/stats` | ADMIN role |

**Auth methods:** Supabase JWT (`Authorization: Bearer`), API Key (`X-API-Key: cg_xxx`), or custom JWT.

### Docker
```bash
docker-compose up -d          # Starts backend + PostgreSQL
cd backend && npx prisma db push  # Apply schema
```

> See `DEPLOYMENT_GUIDE.md` for full step-by-step setup, and `PROGRESS.md` for the full API reference.

---

## Data Sources

- **[OSV.dev](https://osv.dev)** — Google's open vulnerability database
- **[GitHub Advisory DB](https://github.com/advisories)** — CVE + patch intelligence
- **npm Registry** — Package existence, provenance, download stats
- **PyPI JSON API** — Package existence, PEP 740 attestations
- **USENIX 2025 Dataset** — 205,474 hallucinated package names from 16 LLMs
- **GHIN Cloud** — Crowdsourced hallucination intelligence (opt-in)

---

## Repository Structure

```
codeguard-ai/
├── src/                 ← VS Code extension source (TypeScript)
├── backend/             ← Express.js API (TypeScript + Prisma)
│   ├── src/routes/      ← API route handlers
│   ├── src/services/    ← Database, Redis, GHIN consolidator, memory verifier
│   ├── src/middleware/  ← Auth, rate limiting, error handling
│   ├── src/utils/       ← Logger, errors, crypto helpers
│   ├── src/tests/       ← Vitest API tests
│   └── prisma/          ← Database schema (11 models)
├── frontend/            ← React dashboard (Vite + TailwindCSS)
│   └── src/             ← Pages, components, store, API layer
├── database/            ← Schema docs, seed scripts, ERD, migration guide
├── cli/                 ← Standalone CLI + GitHub Action
└── .github/workflows/   ← CI/CD pipeline
```

## Documentation

| Document | Description |
|----------|-------------|
| `README.md` | This file — overview, features, quick start |
| `EXTENSION_BUILD.md` | **How to build & install** the extension in VS Code, Windsurf, Cursor |
| `DEPLOYMENT_GUIDE.md` | **Full deployment guide** — Supabase, Railway, Render, step-by-step |
| `PROJECT_SUMMARY.md` | 40-line product brief — what we built and who it helps |
| `PROGRESS.md` | Full project status, API reference, architecture, roadmap |
| `USER_GUIDE.md` | Comprehensive user manual for first-time users |
| `COMPARISON.md` | Competitive analysis vs AI Security Crew |
| `CHANGELOG.md` | Full version history (v0.1 → v7.2) |
| `.env.example` | All required environment variables with signup instructions |
| `database/` | Schema docs, ERD diagram, seed scripts, migration guide |

## License

MIT
