# CodeGuard AI — Project Summary
### What We Built & Who It Helps

---

## 40-Line Product Brief

CodeGuard AI is the world's first **AI-aware, pre-execution developer security platform** — purpose-built for the era where developers ship AI-generated code without knowing if it's safe.

**The problem it solves:** When developers ask AI (ChatGPT, Copilot, Claude, Cursor) to write code, the AI routinely invents package names that don't exist — called "hallucinations." These fake packages are then searched on npm and PyPI by attackers who publish malicious versions to steal secrets, passwords, and cloud credentials. This is called a **slopsquatting attack**. Traditional security tools don't catch this because they scan *after* install — we catch it *before*.

---

### What We Built

**1. VS Code / Windsurf / Cursor Extension** (`src/`)
Real-time scanner that activates the moment you type an import. Detects hallucinated packages (520+ known entries), CVE vulnerabilities via OSV.dev, exposed secrets (10 pattern types), SAST issues (12 rule categories), MCP server attacks (7 threat types), and Shadow AI discovery across your workspace. Displays inline red squiggles, a Dashboard webview, a pre-install Gate that blocks dangerous packages, an AI-SBOM generator, and 30+ security commands.

**2. CLI + GitHub Action** (`cli/`)
Standalone scanner with zero VS Code dependency. Runs in CI/CD pipelines, git pre-commit hooks, and Docker containers. Outputs SARIF v2.1.0 for GitHub Code Scanning, colored terminal tables, and JSON. Detects all the same threats as the extension. Ships as a GitHub Action composite with configurable fail-on-severity gates.

**3. Production Backend API** (`backend/`)
Express.js + TypeScript + Prisma ORM API connecting to Supabase PostgreSQL. Provides 3-strategy authentication (GitHub OAuth, API keys, JWT), the GHIN crowdsourced hallucination intelligence network, scan history storage, team management, feature flags, a KAIROS-inspired background consolidation daemon (auto-confirms hallucinations, recalculates confidence scores, cleans stale data), and a memory verification service that validates GHIN entries against live npm/PyPI registries.

**4. React Dashboard** (`frontend/`)
Dark-theme web dashboard with real-time scan history, GHIN intelligence browser, trend charts, team management, and API key management. Built with Vite + React + TailwindCSS + Recharts.

**5. Database Layer** (`database/`)
PostgreSQL 15 with 11 tables covering users, API keys, teams, projects, scans, GHIN reports, GHIN packages, policy templates, webhooks, and delivery logs. Full schema documentation, ERD diagram, seed scripts, and migration guide.

---

### Who It Helps

| Audience | Pain Point Solved |
|----------|------------------|
| **Developers using AI coding tools** | Catches hallucinated packages and CVEs before they install them |
| **DevSecOps / Security Engineers** | Automates hallucination detection in CI/CD — no manual review needed |
| **SOC Teams** | Reduces supply chain attack surface from AI-generated code |
| **Enterprise Security Teams** | Team-wide policy enforcement, audit trails, cloud sync of scan results |
| **Open Source Maintainers** | Pre-commit hooks block dangerous deps from entering the repo |
| **MSSP / Managed Security Providers** | Multi-tenant backend, API keys, webhook integrations |

---

### Technology Stack

```
Extension:   TypeScript · VS Code API · OSV.dev · Webview (HTML/CSS/JS)
CLI:         Node.js · TypeScript · SARIF · GitHub Actions Composite
Backend:     Express.js · TypeScript · Prisma ORM · Supabase (PostgreSQL)
             Upstash Redis · Supabase Auth · JWT · Sentry · Zod
Frontend:    React 18 · Vite · TailwindCSS · Recharts · React Query
Database:    PostgreSQL 15 · Prisma 5.22 · 11 models · Supabase hosting
Deployment:  Railway / Render · Docker · GitHub Actions CI
```

---

### By the Numbers

- **520+** known hallucinated packages in bundled database
- **800** popular packages tracked for false-positive prevention
- **10** secret detection patterns (API keys, passwords, tokens)
- **12** SAST security rules (eval, SQL injection, XSS, etc.)
- **7** MCP server attack categories
- **15** CLI unit tests passing
- **11** database tables
- **20** API endpoints
- **30+** VS Code commands
- **16** feature flags
- **$0/month** to run on free tiers of all services

---

*v7.2.0 — April 2026*
