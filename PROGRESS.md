# CodeGuard AI — Project Progress & Implementation Guide

> **Version 7.2.0** — The first AI-aware pre-execution developer security platform.  
> Last updated: April 1, 2026

---

## Table of Contents

1. [What Is CodeGuard AI?](#1-what-is-codeguard-ai)
2. [Architecture Overview](#2-architecture-overview)
3. [Complete Feature Inventory](#3-complete-feature-inventory)
4. [Tech Stack](#4-tech-stack)
5. [Repository Structure](#5-repository-structure)
6. [Backend API Reference](#6-backend-api-reference)
7. [Database Schema](#7-database-schema)
8. [Environment Setup Guide](#8-environment-setup-guide)
9. [Build & Run Instructions](#9-build--run-instructions)
10. [Version History](#10-version-history)
11. [What's Next — Roadmap](#11-whats-next--roadmap)

---

## 1. What Is CodeGuard AI?

CodeGuard AI is a **multi-layer security platform** that protects developers from supply-chain attacks, AI hallucinations, insecure code patterns, and agentic threats **before** they enter your project — not after.

It works as three integrated tools:

| Component | What It Does | Status |
|-----------|-------------|--------|
| **VS Code Extension** | Real-time IDE scanning, diagnostics, Install Gate, dashboards | ✅ Production |
| **CLI Tool** | CI/CD scanning, pre-commit hooks, SARIF output, GitHub Action | ✅ Production |
| **Backend API** | GHIN intelligence, scan history, teams, auth, webhooks | ✅ Built (needs deployment) |

**Supported AI tools:** Copilot, Cursor, Windsurf, Claude Code, Cline, Aider, Continue, and all AI coding assistants.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    VS Code Extension (Layer 1)                   │
│  Install Gate · Hybrid SAST · Taint Tracker · Secrets Scanner   │
│  Policy Engine · Attribution · Git Regression · MCP Scanner     │
│  Shadow AI Discovery · AI-SBOM · Compliance · Score · Dashboard │
└───────────────────────────▲─────────────────────────────────────┘
                            │ local (all decisions happen here)
┌───────────────────────────▼─────────────────────────────────────┐
│                    CLI Tool (Layer 2)                             │
│  codeguard scan · pre-commit · SARIF · JSON · GitHub Action     │
│  Hallucination DB · Secrets (10) · SAST (12) · OSV.dev · Policy │
└───────────────────────────▲─────────────────────────────────────┘
                            │ HTTPS (opt-in)
┌───────────────────────────▼─────────────────────────────────────┐
│                    Backend API (Layer 3)  ← NEW                  │
│  Express.js + Prisma + Supabase PostgreSQL + Upstash Redis      │
│  Auth (GitHub OAuth + JWT + API Keys)                            │
│  GHIN Intelligence API · Scan History · Teams · Webhooks         │
└───────────────────────────▲─────────────────────────────────────┘
                            │ internal
┌───────────────────────────▼─────────────────────────────────────┐
│                    Advisory LLM Layer (Layer 4)                   │
│  Deep SAST · Adversarial Verification · Risk Explanation         │
│  Patch Generation · Intent Verification                          │
│  (VS Code Language Model API — Copilot GPT-4o)                  │
└─────────────────────────────────────────────────────────────────┘
```

**Critical design rule:** All security DECISIONS happen locally (deterministic). The backend provides intelligence and history only. The extension works fully offline.

---

## 3. Complete Feature Inventory

### 3.1 Pre-Execution Prevention
| Feature | Implementation | File(s) |
|---------|---------------|---------|
| Install Gate (terminal firewall) | Intercepts npm/pip/cargo/gem/go install | `src/shield/install-gate.ts` |
| Sandbox Runtime Analysis | VM sandbox for install scripts | `src/shield/sandbox-runner.ts` |
| Dependency Permission Model | Network/fs/env capability tracking | `src/shield/permissions.ts` |
| Install Script Analyzer | 20+ malicious pattern detection | `src/shield/script-analyzer.ts` |

### 3.2 Real-Time Code Scanning
| Feature | Implementation | File(s) |
|---------|---------------|---------|
| Hybrid SAST Engine | 3-pass: 35 regex → LLM → adversarial | `src/checkers/hybrid-sast.ts` |
| Cross-File Taint Tracker | Traces tainted data through imports | `src/analysis/taint-tracker.ts` |
| Hallucination Detection | 520+ DB + npm/PyPI registry check | `src/checkers/hallucination.ts` |
| Secrets Scanner | 20+ regex patterns (AWS, GitHub, etc.) | `src/checkers/secrets-checker.ts` |
| Git Regression Detector | Diffs HEAD for removed security | `src/analysis/git-regression.ts` |

### 3.3 Supply Chain Intelligence
| Feature | Implementation | File(s) |
|---------|---------------|---------|
| Cryptographic Provenance | Sigstore (npm) + PEP 740 (PyPI) | `src/intelligence/provenance.ts` |
| GHIN Network | Crowdsourced hallucination DB | `src/intelligence/ghin.ts` |
| Composite Trust Score | 0-100 multi-signal scoring | `src/intelligence/trust-score.ts` |
| Auto-Patch Engine | CVE fix finder + upgrade commands | `src/intelligence/auto-patch.ts` |
| OSV.dev Vulnerability Scanning | Live CVE lookup per package | `cli/src/scanner.ts` |

### 3.4 AI Advisory & Attribution
| Feature | Implementation | File(s) |
|---------|---------------|---------|
| AI Code Attribution | AI vs human code tracking | `src/ai/code-attribution.ts` |
| LLM Explanations | Copilot GPT-4o risk explanations | `src/ai/llm-advisor.ts` |
| Semantic Intent Verifier | Intent vs generated code comparison | `src/ai/intent-verifier.ts` |
| Agentic Patch Assistant | Auto-fix workflow | `src/ai/patch-assistant.ts` |

### 3.5 Policy & Compliance
| Feature | Implementation | File(s) |
|---------|---------------|---------|
| Policy-as-Code Engine | `.codeguard/policy.json` rules | `src/policy/engine.ts` |
| Compliance Report Export | Markdown/CSV/JSON for CRA, EO 14028, SOC 2, ISO 27001 | `src/reports/compliance.ts` |
| Security Score | 0-100, A-F grade, status bar | `src/scoring/` |
| Live SBOM | CycloneDX 1.5, drift detection | `src/sbom/` |

### 3.6 Agentic Supply Chain Security (v7.0)
| Feature | Implementation | File(s) |
|---------|---------------|---------|
| MCP Server Scanner | 7 detection categories across 5 config formats | `src/shield/mcp-scanner.ts` |
| Shadow AI Discovery | 15+ AI SDK detectors, model files, configs | `src/shield/shadow-ai-discovery.ts` |
| AI-SBOM Export | First AI-specific component inventory | `src/shield/shadow-ai-discovery.ts` |
| AI Config Shield | 17+ config patterns for hidden attacks | `src/shield/rules-scanner.ts` |

### 3.7 Team Intelligence
| Feature | Implementation | File(s) |
|---------|---------------|---------|
| Team Dashboard | React SPA with charts | `cloud/dashboard/` |
| Webhook Integrations | Slack, Teams, Jira, HTTP | `cloud/ghin-production/src/webhooks.ts` |

### 3.8 Backend API (v7.1)
| Feature | Implementation | File(s) |
|---------|---------------|---------|
| Auth (GitHub OAuth + JWT + API Keys) | Supabase Auth + custom JWT | `backend/src/routes/auth.ts` |
| GHIN Intelligence API | Report, check, bulk-check, stats | `backend/src/routes/ghin.ts` |
| Scan History API | Upload, list, get, trends | `backend/src/routes/scans.ts` |
| Team Management API | Create, invite, stats | `backend/src/routes/teams.ts` |
| Rate Limiting | Upstash Redis sliding window | `backend/src/middleware/rateLimit.ts` |
| Error Monitoring | Sentry integration | `backend/src/server.ts` |

### 3.9 Agentic Security Architecture (v7.2 — NEW)
| Feature | Implementation | File(s) |
|---------|---------------|---------|
| Feature Flags System | 16 dynamic flags, 3-tier priority, per-user overrides | `backend/src/services/feature-flags.ts` |
| GHIN Consolidation Daemon | KAIROS-inspired background data merging every 15 min | `backend/src/services/ghin-consolidator.ts` |
| Memory Verification | Skeptical memory — verifies GHIN vs live registries | `backend/src/services/memory-verifier.ts` |
| Confidence Decay | Auto-downgrades stale unverified entries | `backend/src/services/memory-verifier.ts` |
| Admin API | Feature flags, consolidation triggers, system stats | `backend/src/routes/admin.ts` |
| Deployment Infrastructure | Railway, Render, Docker configs | `render.yaml`, `Procfile`, `DEPLOYMENT_GUIDE.md` |

---

## 4. Tech Stack

### Extension
| Layer | Technology |
|-------|-----------|
| Runtime | VS Code Extension API (TypeScript) |
| LLM | VS Code Language Model API (Copilot GPT-4o) |
| Data | JSON bundles (520+ hallucinations, 800 popular packages) |
| UI | Webview panels (Dashboard, Install Gate), TreeView, CodeLens |

### CLI
| Layer | Technology |
|-------|-----------|
| Runtime | Node.js + TypeScript |
| Testing | Mocha (15 tests passing) |
| Output | SARIF v2.1.0, JSON, colored table |
| CI/CD | GitHub Action (composite) |

### Backend (NEW)
| Layer | Technology | Free Tier |
|-------|-----------|-----------|
| Framework | Express.js 4.21 + TypeScript | — |
| ORM | Prisma 5.22 | — |
| Database | Supabase PostgreSQL | 500 MB, 2 projects |
| Auth | Supabase Auth (GitHub OAuth) | 50K monthly users |
| Cache | Upstash Redis (REST) | 10K commands/day |
| Rate Limiting | @upstash/ratelimit | Included |
| Error Monitoring | Sentry | 5K events/month |
| Email | Resend | 100 emails/day |
| Validation | Zod | — |
| Security | Helmet + CORS | — |
| Container | Docker (multi-stage) | — |
| CI/CD | GitHub Actions | Free for public repos |

---

## 5. Repository Structure

```
codeguard-ai/
├── .env.example              # All required environment variables
├── .github/workflows/ci.yml  # CI for extension + CLI + backend
├── .gitignore                # .env, dist/, node_modules/
├── docker-compose.yml        # Backend + PostgreSQL local dev
├── render.yaml               # Render Blueprint for deployment
├── package.json              # Extension package (v7.0.0)
├── README.md                 # Project documentation
├── CHANGELOG.md              # Full version history
├── COMPARISON.md             # Competitive analysis vs AI Security Crew
├── USER_GUIDE.md             # Comprehensive user manual
├── PROGRESS.md               # This file
│
├── src/                      # VS Code Extension source
│   ├── extension.ts          # Entry point (30 commands)
│   ├── ai/                   # LLM advisory layer
│   ├── analysis/             # Taint tracker, git regression
│   ├── checkers/             # Hallucination, secrets, hybrid SAST
│   ├── data/                 # Bundled JSON (hallucinations, packages)
│   ├── intelligence/         # GHIN, provenance, trust score, auto-patch
│   ├── policy/               # Policy-as-Code engine
│   ├── reports/              # Compliance report generator
│   ├── shield/               # Install gate, MCP scanner, shadow AI, rules scanner
│   └── utils/                # Shared utilities
│
├── cli/                      # Standalone CLI tool
│   ├── src/
│   │   ├── index.ts          # CLI entry point
│   │   ├── scanner.ts        # Core scanner (hallucination, secrets, SAST, OSV, MCP, policy)
│   │   ├── formatters/       # SARIF, JSON, table output
│   │   └── __tests__/        # 15 unit tests
│   ├── action.yml            # GitHub Action definition
│   └── bin/pre-commit        # Git pre-commit hook
│
├── backend/                  # Backend API server (NEW)
│   ├── Dockerfile            # Multi-stage Docker build
│   ├── package.json          # Dependencies
│   ├── tsconfig.json         # TypeScript config
│   ├── prisma/
│   │   └── schema.prisma     # Database schema (11 models)
│   └── src/
│       ├── server.ts         # Express app entry point
│       ├── config.ts         # Environment config loader
│       ├── middleware/
│       │   ├── auth.ts       # 3-strategy auth (Supabase JWT, API key, custom JWT)
│       │   ├── rateLimit.ts  # Upstash Redis sliding window
│       │   └── errorHandler.ts # Global error + 404 handler
│       ├── routes/
│       │   ├── auth.ts       # GitHub OAuth, API keys, profile
│       │   ├── ghin.ts       # GHIN intelligence (report, check, bulk, stats)
│       │   ├── health.ts     # Health + readiness checks
│       │   ├── scans.ts      # Scan upload, list, get, trends
│       │   └── teams.ts      # Team CRUD, invite, stats
│       ├── services/
│       │   ├── database.ts   # Prisma singleton
│       │   ├── redis.ts      # Upstash client + cache helpers
│       │   └── supabase.ts   # Supabase admin + per-user clients
│       └── utils/
│           ├── crypto.ts     # API key generation, webhook signing
│           ├── errors.ts     # Custom error classes (6 types)
│           └── logger.ts     # Structured logger
│
├── cloud/                    # Team dashboard + GHIN production
│   ├── dashboard/            # React SPA (Vite + Recharts + TailwindCSS)
│   └── ghin-production/      # Fastify GHIN API (legacy, being replaced by backend/)
│
└── test-samples/             # Test fixtures for scanning
```

---

## 6. Backend API Reference

**Base URL:** `http://localhost:3000` (dev) or `https://your-domain.com` (prod)

### Health
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | None | Basic health check |
| GET | `/health/ready` | None | DB + Redis connectivity check |

### Auth
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/auth/github` | None | Start GitHub OAuth flow |
| GET | `/api/auth/callback/github` | None | OAuth callback handler |
| GET | `/api/auth/me` | Required | Get current user profile |
| POST | `/api/auth/api-keys` | Required | Create API key |
| GET | `/api/auth/api-keys` | Required | List API keys |
| DELETE | `/api/auth/api-keys/:id` | Required | Revoke API key |

### GHIN (Hallucination Intelligence)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/ghin/report` | Required | Report a hallucinated package |
| GET | `/api/ghin/check/:ecosystem/:name` | Optional | Check single package |
| POST | `/api/ghin/check-bulk` | Optional | Check up to 100 packages |
| GET | `/api/ghin/packages` | None | List known hallucinations (paginated) |
| GET | `/api/ghin/stats` | None | GHIN network statistics |

### Scans
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/scans` | Required | Upload scan results |
| GET | `/api/scans` | Required | List scan history (paginated) |
| GET | `/api/scans/:id` | Required | Get full scan details |
| GET | `/api/scans/trends/summary` | Required | 30-day trend data |

### Teams
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/teams` | Required | Create team |
| GET | `/api/teams` | Required | List user's teams |
| GET | `/api/teams/:slug` | Required | Get team details |
| POST | `/api/teams/:slug/members` | Required | Invite member |
| GET | `/api/teams/:slug/stats` | Required | Team scan statistics |

### Authentication Methods
1. **Supabase JWT** — `Authorization: Bearer <supabase-token>` (from browser login)
2. **API Key** — `X-API-Key: cg_xxxx` or `?api_key=cg_xxxx` (for CLI and CI/CD)
3. **Custom JWT** — `Authorization: Bearer <jwt>` (from OAuth callback)

---

## 7. Database Schema

**11 models** in Supabase PostgreSQL via Prisma ORM:

| Model | Table | Purpose |
|-------|-------|---------|
| User | `users` | User accounts (email, GitHub, role) |
| ApiKey | `api_keys` | Hashed API keys with expiry |
| Team | `teams` | Organizations (name, slug, plan) |
| TeamMember | `team_members` | User-team membership + roles |
| Project | `projects` | Team projects linked to repos |
| Scan | `scans` | Scan results with summary counts + full JSON |
| GhinReport | `ghin_reports` | Individual hallucination reports |
| GhinPackage | `ghin_packages` | Aggregated hallucination data |
| PolicyTemplate | `policy_templates` | Shared policy configurations |
| Webhook | `webhooks` | Webhook configurations |
| WebhookDelivery | `webhook_deliveries` | Webhook delivery log |

---

## 8. Environment Setup Guide

### Step 1: Copy `.env.example`
```bash
cp .env.example .env
```

### Step 2: Create Accounts (all free tier)

#### Required: Supabase (Database + Auth)
1. Go to [supabase.com](https://supabase.com) → Create account
2. Create a new project (name: `codeguard-ai`)
3. Go to **Settings → API** → Copy:
   - `SUPABASE_URL` — Project URL
   - `SUPABASE_ANON_KEY` — anon/public key
   - `SUPABASE_SERVICE_ROLE_KEY` — service_role key
4. Go to **Settings → Database → Connection String → URI** → Copy:
   - `DATABASE_URL` — Pooler connection (port 6543, add `?pgbouncer=true`)
   - `DIRECT_URL` — Direct connection (port 5432)
5. Go to **Authentication → Providers → GitHub** → Enable and enter GitHub OAuth credentials

#### Required: GitHub OAuth App
1. Go to [github.com/settings/applications/new](https://github.com/settings/applications/new)
2. Fill in:
   - Application name: `CodeGuard AI`
   - Homepage URL: `http://localhost:3000`
   - Callback URL: `http://localhost:3000/api/auth/callback/github`
3. Copy `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`

#### Required: JWT Secret
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
Put the output as `JWT_SECRET`.

#### Optional: Upstash Redis
1. Go to [upstash.com](https://upstash.com) → Create Redis database
2. Copy `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`
3. If not configured, rate limiting and caching are disabled (app still works)

#### Optional: Sentry
1. Go to [sentry.io](https://sentry.io) → Create Node.js project
2. Copy `SENTRY_DSN`

#### Optional: Resend (for email notifications)
1. Go to [resend.com](https://resend.com) → Create API key
2. Copy `RESEND_API_KEY`

### Step 3: Push Database Schema
```bash
cd backend
npx prisma db push
```

---

## 9. Build & Run Instructions

### Extension (VS Code / Cursor / Windsurf)
```bash
# Install dependencies
npm install

# Build
npm run compile

# Package VSIX
npx @vscode/vsce package --no-dependencies

# Install
code --install-extension codeguard-ai-7.0.0.vsix
```

### CLI
```bash
cd cli
npm install
npm run build

# Scan a project
node dist/index.js scan --path /your/project

# Pre-commit hook
node dist/index.js pre-commit --path .

# SARIF output for GitHub
node dist/index.js scan --format sarif --output results.sarif
```

### Backend
```bash
cd backend
npm install
npx prisma generate
npx prisma db push        # Push schema to Supabase

# Development (hot-reload)
npm run dev

# Production build
npm run build
npm start
```

### Docker (local development)
```bash
# Start backend + PostgreSQL
docker-compose up -d

# Apply database schema
cd backend && npx prisma db push
```

### Run Tests
```bash
# Extension
npm run compile && npm run lint

# CLI (15 tests)
cd cli && npm run build && npx mocha dist/__tests__/scanner.test.js --timeout 30000

# Backend (build check)
cd backend && npm run build
```

### GitHub Actions CI
The `.github/workflows/ci.yml` automatically runs on push/PR to `main`:
- Extension: compile + lint
- CLI: build + 15 unit tests
- Backend: prisma generate + build

---

## 10. Version History

| Version | Date | Highlights |
|---------|------|------------|
| **v7.2.0** | 2026-04-01 | Agentic security: feature flags, GHIN consolidation daemon, memory verification, admin API, deployment guide |
| **v7.1.0** | 2026-03-21 | Backend API (Express + Prisma + Supabase), auth, GHIN API, scan history, teams, Docker, CI/CD |
| **v7.0.0** | 2026-03-20 | MCP Server Scanner (7 categories), Shadow AI Discovery, AI-SBOM, 7 agentic policy rules |
| **v6.0.0** | 2026-03-16 | CLI tool, GitHub Action, SARIF, OSV.dev scanning, policy evaluation, 520+ hallucination DB |
| **v5.2.0** | 2026-02-23 | Team Dashboard (React SPA), Webhook integrations (Slack/Teams/Jira), Compliance reports |
| **v5.0.0** | 2026-02-22 | Hybrid SAST, taint tracker, attribution, policy engine, git regression, sandbox |
| **v0.5.0** | 2026-02-20 | Dashboard UI overhaul, deployment docs, code cleanup |
| **v0.4.0** | 2026-02-19 | Permission model, trust score, GHIN production, findings tree, telemetry |
| **v0.3.0** | 2026-02-19 | Rules scanner, GHIN, provenance, auto-patch, Install Gate, SBOM, LLM advisory |
| **v0.2.0** | 2026-02-18 | AI detection, comment injection, CodeLens, Chat Participant, hallucination enhancement |
| **v0.1.0** | 2026-02-18 | Core: real-time monitoring, import parsing, OSV.dev, diagnostics, dashboard |

---

## 11. What's Next — Roadmap

### Phase 1: Immediate (Deploy & Test) 🎯
- [ ] User creates Supabase + GitHub OAuth accounts, fills `.env`
- [ ] Run `npx prisma db push` to create tables
- [ ] Run `npm run dev` in backend/ to start server
- [ ] Test API endpoints with curl/Postman
- [ ] Connect CLI to backend (add `--upload` flag to scan command)

### Phase 2: CLI ↔ Backend Integration
- [ ] Add `--api-key` and `--upload` flags to CLI scanner
- [ ] Auto-upload scan results after each CLI scan
- [ ] Auto-report hallucinations to GHIN backend
- [ ] CLI `login` command for API key creation

### Phase 3: Extension ↔ Backend Integration
- [ ] Update extension settings to connect to backend API
- [ ] Real-time GHIN queries from extension (with local fallback)
- [ ] Scan result sync from extension to backend
- [ ] Team policy sync (pull policies from backend)

### Phase 4: Feature Gaps (vs AI Security Crew)
- [ ] OWASP knowledge base integration (bundled cheat sheets)
- [ ] Threat modeling (STRIDE framework)
- [ ] Reachability analysis for CVEs
- [ ] Expose CodeGuard as MCP server (so AI agents can call it)

### Phase 5: Production Hardening
- [ ] Backend unit tests (Vitest)
- [ ] API documentation (Swagger/OpenAPI)
- [ ] Admin dashboard for GHIN moderation
- [ ] Webhook delivery for scan.completed events
- [ ] Email notifications via Resend
- [ ] Deploy backend to Railway/Render (free tier)
- [ ] Custom domain + SSL

### Phase 6: Growth
- [ ] Public GHIN API documentation
- [ ] VS Code Marketplace listing
- [ ] npm package for CLI (`npx codeguard-ai scan`)
- [ ] Landing page / website
- [ ] Community hallucination reporting UI

---

## Build Verification Status

| Component | Command | Status |
|-----------|---------|--------|
| Extension | `npm run compile` | ✅ Clean |
| Extension | `npm run lint` | ✅ 0 errors, 22 warnings (pre-existing) |
| CLI | `npm run build` (in cli/) | ✅ Clean |
| CLI Tests | `mocha dist/__tests__/*.js` | ✅ 15/15 passing |
| Backend | `npm run build` (in backend/) | ✅ Clean (0 errors) |
| Backend | `npx prisma generate` | ✅ Client generated |

---

*This document is the single source of truth for CodeGuard AI project status. Update it after each major change.*
