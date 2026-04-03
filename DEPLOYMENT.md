# CodeGuard AI — Deployment Guide

Complete guide to deploying CodeGuard AI from development to production.

---

## 1. Accounts Required

| Service | Purpose | Required? | Link |
|---------|---------|-----------|------|
| **VS Code Marketplace** | Publish the extension | ✅ Yes | [marketplace.visualstudio.com/manage](https://marketplace.visualstudio.com/manage) |
| **Railway** or **Render** | Host the GHIN API server | ⚡ For cloud mode | [railway.app](https://railway.app) / [render.com](https://render.com) |
| **Neon** or **Supabase** | Managed PostgreSQL 16 | ⚡ For cloud mode | [neon.tech](https://neon.tech) / [supabase.com](https://supabase.com) |
| **OpenAI** | LLM advisory layer | ❌ Optional | [platform.openai.com](https://platform.openai.com) |

> **Note**: CodeGuard AI works fully offline. The cloud components (GHIN API, PostgreSQL) are only needed for the crowdsourced hallucination database and telemetry features.

---

## 2. Database Setup

### Create PostgreSQL Instance

1. Sign up at [Neon](https://neon.tech) (free tier) or [Supabase](https://supabase.com)
2. Create a new project/database named `ghin`
3. Copy the connection string (format: `postgresql://user:pass@host:5432/ghin`)

### Apply Schema

```bash
psql $DATABASE_URL -f cloud/ghin-production/schema.sql
```

The schema creates:
- `hallucinations` — Known hallucinated package names
- `packages` — Package metadata and trust scores
- `reports` — User-submitted hallucination reports
- `telemetry` — Anonymous usage statistics
- Lookup tables, indexes, and materialized views

---

## 3. GHIN API Deployment

### Option A: Railway (Recommended)

1. Connect your GitHub repo to [Railway](https://railway.app)
2. Set root directory to `cloud/ghin-production`
3. Add environment variables from `.env.example`
4. Deploy — Railway auto-detects the Node.js app

### Option B: Render

1. Create a new Web Service on [Render](https://render.com)
2. Point to `cloud/ghin-production/` directory
3. Build command: `npm install`
4. Start command: `npm start`
5. Add environment variables

### Option C: Self-Hosted

```bash
cd cloud/ghin-production
cp .env.example .env
# Edit .env with your DATABASE_URL
npm install
npm start
```

### Verify Deployment

```bash
curl https://your-api-host/health
# Expected: { "status": "ok" }

curl https://your-api-host/api/v1/check/lodash/npm
# Expected: { "found": false, ... }
```

---

## 4. Extension Configuration

### For Development

```bash
cd codeguard-ai
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

### For Production (VSIX)

```bash
npm run compile
npx vsce package
# Creates codeguard-ai-0.5.0.vsix
code --install-extension codeguard-ai-0.5.0.vsix
```

### VS Code Settings

```json
{
  "codeguard.severityThreshold": "MEDIUM",
  "codeguard.enableInstallGate": true,
  "codeguard.enableRulesScanner": true,
  "codeguard.enableGhin": true,
  "codeguard.enableGhinCloudSync": false,
  "codeguard.enableProvenanceCheck": true,
  "codeguard.enableAutoPatch": true,
  "codeguard.enableScriptAnalysis": true,
  "codeguard.ghinApiUrl": "https://your-api-host"
}
```

---

## 5. How It Works — End-to-End

### Extension Activation Flow

```
VS Code starts → extension activates → 10 security modules initialize:

1. Install Gate        — Hooks terminal to intercept npm/pip/yarn install commands
2. Rules Scanner       — Watches .cursorrules, copilot-instructions.md for attacks
3. GHIN Client         — Loads local hallucination database (46 seed entries)
4. Provenance Checker  — Ready to verify Sigstore/PEP 740 attestations
5. Secrets Scanner     — Watches for hardcoded API keys, tokens, passwords
6. Code Vuln Scanner   — SAST patterns for JS/TS/Python
7. SBOM Generator      — Tracks dependency graph in real-time
8. Trust Score Engine   — Computes composite trust per package
9. LLM Advisor         — Connects to VS Code Language Model API
10. Permission Model   — Enforces capability-based package permissions
```

### Real-Time Scanning

```
Developer writes code → Document change event fires
  → Parser extracts imports (JS/TS/Python)
  → Each import checked against:
      ├── Local hallucination DB (GHIN)
      ├── Package registry (npm/PyPI/etc.)
      ├── OSV.dev vulnerability DB
      ├── Provenance verification
      └── Trust score computation
  → Results shown as:
      ├── Inline diagnostics (squiggly underlines)
      ├── Findings TreeView (sidebar)
      ├── Status bar score (🛡️ 87)
      └── Security context file
```

### Install Gate Flow

```
Developer types: npm install some-package
  → Install Gate intercepts terminal command
  → Analyzes each package in parallel:
      ├── GHIN hallucination check
      ├── Provenance verification
      ├── Vulnerability scan (OSV.dev)
      └── Install script analysis
  → Shows rich webview panel with results:
      ├── ✅ Safe — green badge
      ├── ⚠️ Warning — orange badge
      └── 🚫 Blocked — red badge
  → User clicks "Install Safe" or "Cancel"
```

### Offline vs Connected Mode

| Feature | Offline | Connected |
|---------|---------|-----------|
| Hallucination detection | ✅ Local DB (46 entries) | ✅ Cloud DB (crowdsourced) |
| Vulnerability scanning | ✅ OSV.dev API | ✅ Same |
| Provenance checking | ✅ Direct registry | ✅ Same |
| Telemetry | ❌ Disabled | ✅ Opt-in anonymous |
| Install Gate | ✅ Full | ✅ Full |
| LLM Advisory | ✅ Copilot (if available) | ✅ Same |

---

## 6. Smoke Testing

Run the comprehensive smoke test after deployment:

```bash
node smoke-test-v3.js
```

This validates:
- GHIN hallucination checks
- Provenance verification logic
- Auto-patch report generation
- Script analyzer patterns
- Install Gate command parsing
- Rules file scanner patterns
