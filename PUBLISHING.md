# CodeGuard AI â€” Publishing Guide

## Prerequisites

1. **VS Code Marketplace Publisher Account**
   - Go to https://marketplace.visualstudio.com/manage
   - Sign in with Microsoft account
   - Create a publisher (e.g., `codeguard-ai`)

2. **Personal Access Token (PAT)**
   - Go to https://dev.azure.com
   - User Settings â†’ Personal Access Tokens
   - Create new token with:
     - Organization: All accessible organizations
     - Scopes: Marketplace â†’ Manage
   - Save the token securely

## Publishing Steps

### 1. Install vsce (VS Code Extension CLI)

```bash
npm install -g @vscode/vsce
```

### 2. Login to Publisher

```bash
vsce login codeguard-ai
# Enter your PAT when prompted
```

### 3. Publish the Extension

```bash
# From the codeguard-ai directory
vsce publish
```

Or publish a specific version:

```bash
vsce publish 5.2.0
```

### 4. Verify Publication

- Go to https://marketplace.visualstudio.com/items?itemName=codeguard-ai.codeguard-ai
- Extension should appear within 5-10 minutes

## Alternative: Publish Pre-built VSIX

If you already have the `.vsix` file:

```bash
vsce publish --packagePath codeguard-ai-5.2.0.vsix
```

## Local Installation (Testing)

To install the extension locally without publishing:

```bash
code --install-extension codeguard-ai-5.2.0.vsix
# or in Windsurf:
windsurf --install-extension codeguard-ai-5.2.0.vsix --force
```

Or in VS Code:
1. Open Command Palette (Ctrl+Shift+P)
2. Run "Extensions: Install from VSIX..."
3. Select `codeguard-ai-5.2.0.vsix`

## GHIN Production API Deployment (Optional)

The GHIN production API is in `cloud/ghin-production/`. It uses **Fastify + PostgreSQL**.

### 1. Database Setup

Create a PostgreSQL 16 instance (e.g., [Neon](https://neon.tech) or [Supabase](https://supabase.com)):

```bash
# Apply schema
psql $DATABASE_URL -f cloud/ghin-production/schema.sql
```

### 2. Configure Environment

```bash
cp cloud/ghin-production/.env.example cloud/ghin-production/.env
# Edit .env with your DATABASE_URL and other settings
```

### 3. Deploy to Railway or Render

```bash
cd cloud/ghin-production
npm install
npm start
```

Or deploy via [Railway](https://railway.app) / [Render](https://render.com) â€” connect the `cloud/ghin-production/` directory as the root.

### 4. Verify

```bash
curl https://your-api-host/health
# Should return { "status": "ok" }
```

### 5. Configure Extension

Set the GHIN API URL in VS Code settings:
```json
"codeguard.ghinApiUrl": "https://your-api-host"
```

## Version Bumping

To release a new version:

```bash
# Bump version in package.json
npm version patch  # or minor, major

# Rebuild and package
npm run compile
vsce package

# Publish
vsce publish
```

## Marketplace Listing Optimization

For better discoverability, ensure:

1. **README.md** has:
   - Clear feature list with screenshots
   - Installation instructions
   - Quick start guide
   - Badges (version, installs, rating)

2. **package.json** has:
   - Good `description`
   - Relevant `keywords`
   - `icon` pointing to a 128x128 PNG
   - `galleryBanner` colors

3. **CHANGELOG.md** is up to date

## LLM Model Usage

CodeGuard AI uses the **VS Code Language Model API** (`vscode.lm`) to access AI models:

- **Primary**: Copilot's GPT-4o (via `vscode.lm.selectChatModels`)
- **Fallback**: GPT-3.5-turbo
- **Fallback**: Deterministic explanations (no LLM)

The LLM is used for:
- Patch explanation generation
- Risk summary in plain language
- Install script risk explanation
- Semantic intent verification (advisory only)

**Important**: LLMs are ADVISORY only. All security decisions (vulnerability detection, provenance verification, hallucination detection) are deterministic.

## Architecture Summary

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                    CodeGuard AI v0.5.0                      â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  ENFORCEMENT LAYER (Deterministic)                          â”‚
â”‚  â”œâ”€â”€ Rules File Scanner (hidden Unicode, injection)         â”‚
â”‚  â”œâ”€â”€ Install Gate (terminal firewall + rich webview)        â”‚
â”‚  â”œâ”€â”€ Provenance Checker (Sigstore, PEP 740)                 â”‚
â”‚  â”œâ”€â”€ Script Analyzer (preinstall/postinstall)               â”‚
â”‚  â”œâ”€â”€ Permission Model (capability-based)                    â”‚
â”‚  â””â”€â”€ GHIN (hallucination database)                          â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  INTELLIGENCE LAYER (Data Sources)                          â”‚
â”‚  â”œâ”€â”€ OSV.dev (vulnerabilities)                              â”‚
â”‚  â”œâ”€â”€ GitHub Advisory (GHSA)                                 â”‚
â”‚  â”œâ”€â”€ npm/PyPI registries (existence, metadata)              â”‚
â”‚  â”œâ”€â”€ USENIX 2025 dataset (hallucination seed)               â”‚
â”‚  â”œâ”€â”€ Trust Score Engine (multi-signal)                       â”‚
â”‚  â””â”€â”€ GHIN Production API (Fastify + PostgreSQL)             â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  ADVISORY LAYER (LLM-powered)                               â”‚
â”‚  â”œâ”€â”€ LLM Advisor (explanations)                             â”‚
â”‚  â”œâ”€â”€ Intent Verifier (semantic analysis)                    â”‚
â”‚  â””â”€â”€ Patch Agent (agentic workflow)                         â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  OUTPUT LAYER                                                â”‚
â”‚  â”œâ”€â”€ Diagnostics (inline warnings)                          â”‚
â”‚  â”œâ”€â”€ Findings TreeView (sidebar, severity groups)           â”‚
â”‚  â”œâ”€â”€ Security Dashboard (glassmorphism webview)             â”‚
â”‚  â”œâ”€â”€ SBOM Generator (CycloneDX)                             â”‚
â”‚  â”œâ”€â”€ Chat Participant (@codeguard)                          â”‚
â”‚  â””â”€â”€ Security Context (.codeguard/security-context.json)    â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Support

- GitHub Issues: https://github.com/codeguard-ai/codeguard-ai/issues
- Documentation: https://codeguard.dev/docs


### 1. Install Wrangler
