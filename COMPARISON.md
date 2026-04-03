# Competitive Analysis: CodeGuard AI vs AI Security Crew

> **Summary:** CodeGuard AI and AI Security Crew both address AI-era developer security, but from fundamentally different angles. AI Security Crew is an MCP server that AI agents call for security guidance. CodeGuard AI is an automated scanner that enforces security at the infrastructure level — without requiring agent cooperation. CodeGuard AI covers 23/31 evaluated capabilities; AI Security Crew covers 6/31. They are complementary, but CodeGuard AI is significantly broader in scope.

---

## Table of Contents

1. [What Is AI Security Crew?](#1-what-is-ai-security-crew)
2. [What Is CodeGuard AI?](#2-what-is-codeguard-ai)
3. [Architecture Comparison](#3-architecture-comparison)
4. [Head-to-Head Feature Matrix](#4-head-to-head-feature-matrix)
5. [Key Philosophical Differences](#5-key-philosophical-differences)
6. [Where AI Security Crew Is Stronger](#6-where-ai-security-crew-is-stronger)
7. [Where CodeGuard AI Is Stronger](#7-where-codeguard-ai-is-stronger)
8. [Gaps to Close — Prioritized Roadmap](#8-gaps-to-close)
9. [Market Positioning](#9-market-positioning)

---

## 1. What Is AI Security Crew?

**Repository:** [github.com/Srajangpt1/ai_security_crew](https://github.com/Srajangpt1/ai_security_crew)

AI Security Crew is a **Python-based MCP (Model Context Protocol) server** that injects security context into AI coding agents during "vibe coding." It runs as a **Docker container** and provides security tools that AI agents (Claude, Cursor, etc.) call at different stages of the coding workflow.

### How It Works

```
Developer asks AI to write code
        │
        ▼
┌─────────────────────────┐
│   AI Agent (Claude,     │
│   Cursor, etc.)         │
│                         │
│   1. Before coding:     │──── calls ──→  lightweight_security_review
│   2. Adding packages:   │──── calls ──→  verify_packages + scan_dependencies
│   3. After coding:      │──── calls ──→  verify_code_security
│   4. For big features:  │──── calls ──→  perform_threat_model
│                         │
└─────────────────────────┘
        │
        ▼  (via MCP protocol)
┌─────────────────────────┐
│  AI Security Crew       │
│  (Docker container)     │
│                         │
│  - OSV.dev CVE lookup   │
│  - Reachability analysis│
│  - OWASP guidelines     │
│  - Jira/Confluence APIs │
│  - Threat model persist │
└─────────────────────────┘
```

### Feature Inventory

| Feature | Details |
|---------|---------|
| **Pre-coding security review** | `lightweight_security_review` — agent reviews requirements before generating code |
| **Jira ticket assessment** | `assess_ticket_security` — pulls Jira ticket, identifies security concerns |
| **Threat modeling** | `perform_threat_model` — STRIDE-based threat models, persists to `threat-model.md` |
| **Package verification** | `verify_packages` — checks packages before installation |
| **Dependency scanning** | `scan_dependencies` — queries OSV.dev with **reachability analysis** |
| **Post-code verification** | `verify_code_security` — AI reviews generated code for security issues |
| **Threat model persistence** | `search_previous_threat_models`, `update_threat_model_file` |
| **OWASP guidelines** | 101 OWASP Cheat Sheets loaded into assessments automatically |
| **Custom guidelines** | Add org-specific security guidelines as markdown files |
| **Agent workflow injection** | Auto-injects workflow instructions via MCP `initialize` handshake |
| **Claude Code plugin** | `/sec-review`, `/verify-code`, `/threat-model` slash commands |
| **Reachability analysis** | OSV function-level symbols → keyword matching → AI analysis |
| **Atlassian integration** | Jira Cloud/Server/DC + Confluence via API token, PAT, or OAuth 2.0 |

### Source Structure

```
src/mcp_security_review/
├── servers/             # MCP tool handlers
│   ├── main.py          # Server entry, MCP tool registration
│   ├── sca.py           # Software Composition Analysis (OSV.dev)
│   ├── dependencies.py  # Package verification logic
│   ├── jira.py          # Jira ticket security assessment
│   ├── confluence.py    # Confluence documentation integration
│   ├── threat_model.py  # STRIDE threat modeling + persistence
│   ├── general.py       # General security review tools
│   └── context.py       # Workflow context management
├── security/
│   ├── analyzer.py      # Security analysis engine
│   ├── assessment.py    # Assessment scoring logic
│   ├── code_verifier.py # Post-coding verification
│   ├── guidelines/      # 101 OWASP Cheat Sheets (bundled docs/)
│   └── threat_modeling/  # Threat model templates
├── providers/
│   ├── atlassian/       # Jira + Confluence API clients
│   └── sca/             # OSV.dev SCA provider
├── models/              # Data models (Pydantic)
├── preprocessing/       # Input preprocessing
└── utils/               # Helpers
```

**Tech stack:** Python 3, `uv` package manager, Docker, MCP SDK, httpx, Pydantic

---

## 2. What Is CodeGuard AI?

**Repository:** Local project (`codeguard-ai` v7.0.0)

CodeGuard AI is a **TypeScript VS Code extension + standalone CLI tool** that provides 8 layers of automated security scanning for AI-generated code. It runs **inside VS Code** (real-time diagnostics) and as a **standalone Node.js CLI** (CI/CD, pre-commit hooks).

### How It Works

```
Developer writes/generates code
        │
        ▼  (automatic — no agent needed)
┌─────────────────────────────────────────────┐
│  CodeGuard AI (VS Code Extension)           │
│                                             │
│  File watchers trigger on every save:       │
│  ├── Hallucination Detection (registry API) │
│  ├── Secrets Scanner (20+ regex patterns)   │
│  ├── SAST Engine (35+ rules + LLM)         │
│  ├── Cross-file Taint Tracking              │
│  └── MCP Config Scanner (7 categories)      │
│                                             │
│  Terminal watchers intercept installs:       │
│  ├── Install Gate (npm/pip/cargo/gem/go)    │
│  └── Sandbox Runtime Analysis               │
│                                             │
│  On-demand commands:                        │
│  ├── Shadow AI Discovery + AI-SBOM          │
│  ├── Provenance Verification (Sigstore)     │
│  ├── Policy Evaluation (20+ rules)          │
│  ├── SBOM Generation (CycloneDX 1.5)       │
│  └── Compliance Report Export               │
└─────────────────────────────────────────────┘
        │
        ▼  Also available as:
┌─────────────────────────────────────────────┐
│  CLI Tool (zero VS Code dependency)         │
│  codeguard scan . --format sarif            │
│  ├── GitHub Action (SARIF upload)           │
│  ├── Pre-commit hook                        │
│  └── JSON/Table/SARIF output formats        │
└─────────────────────────────────────────────┘
```

### Feature Summary (8 Layers, 33+ Commands)

| Layer | Features |
|-------|----------|
| **L1: Pre-Execution** | Install Gate, sandbox runtime, install script analyzer, dependency permissions |
| **L2: Real-Time Scanning** | Hybrid SAST (35+ rules + LLM), taint tracking, hallucination detection (520+ DB), secrets (20+), git regression |
| **L3: Supply Chain** | Sigstore/PEP 740 provenance, GHIN network (205K+), trust score (0-100), auto-patch |
| **L4: AI Advisory** | AI code attribution, LLM explanations, semantic intent verifier, agentic patch assistant |
| **L5: Policy & Compliance** | Policy-as-Code (20+ rules), compliance reports (CRA/SOC2/ISO), security score, CycloneDX SBOM |
| **L6: Team Intelligence** | React dashboard, webhook integrations (Slack/Teams/Jira), developer analytics |
| **L7: AI Config Defense** | Rules file scanner (17+ AI config patterns), Unicode attack detection, sanitize action |
| **L8: Agentic Supply Chain** | MCP server scanner (7 categories), Shadow AI discovery, AI-SBOM export, 15+ SDK detectors |

---

## 3. Architecture Comparison

| Dimension | AI Security Crew | CodeGuard AI |
|:---|:---|:---|
| **Language** | Python 3 | TypeScript |
| **Delivery** | Docker container (MCP server) | VS Code extension + standalone CLI |
| **Runtime model** | Service that agents connect to | Runs inside VS Code + Node.js process |
| **Agent dependency** | **Requires** an AI agent to call tools | Works **without** any AI agent |
| **Scanning trigger** | Agent decides when to call tools | Automatic on file save / type / install |
| **Determinism** | AI-driven analysis (`ctx.sample()`) — non-deterministic | Regex + rules (deterministic) + optional LLM layer |
| **Offline mode** | Needs Docker + network for OSV | Full offline mode with bundled DBs |
| **IDE support** | Any MCP-capable IDE (Claude Desktop, Cursor, Cline) | VS Code (extension) + any terminal (CLI) |
| **Package manager** | `uv` (Python) | `npm` (Node.js) |
| **CI/CD story** | Run Docker container | Native CLI + SARIF + GitHub Action + pre-commit |
| **Setup complexity** | Docker build + env vars for Jira/Confluence | `npm install` + `npm run compile` |
| **Transport** | stdio / streamable-http / SSE | In-process (extension) / stdout (CLI) |

---

## 4. Head-to-Head Feature Matrix

| # | Capability | AI Security Crew | CodeGuard AI | Winner |
|---|:---|:---:|:---:|:---:|
| 1 | **Hallucination / Slopsquatting Detection** | ❌ | ✅ 520+ DB + registry | **CodeGuard** |
| 2 | **OSV.dev CVE Scanning** | ✅ | ✅ | Tie |
| 3 | **CVE Reachability Analysis** | ✅ function-level + AI | ❌ | **AI Sec Crew** |
| 4 | **SAST / Code Vulnerability Scanning** | ⚠️ AI-driven only | ✅ 35+ regex + LLM hybrid | **CodeGuard** |
| 5 | **Secrets Detection** | ❌ | ✅ 20+ patterns | **CodeGuard** |
| 6 | **MCP Config Security Scanning** | ❌ | ✅ 7 detection categories | **CodeGuard** |
| 7 | **MCP Server for AI Agents** | ✅ agents call tools | ❌ | **AI Sec Crew** |
| 8 | **Threat Modeling (STRIDE)** | ✅ with persistence | ❌ | **AI Sec Crew** |
| 9 | **Jira Ticket Security Assessment** | ✅ | ❌ (webhook only) | **AI Sec Crew** |
| 10 | **Confluence Integration** | ✅ | ❌ | **AI Sec Crew** |
| 11 | **OWASP Guidelines (101 bundled)** | ✅ | ❌ | **AI Sec Crew** |
| 12 | **Pre-coding Security Injection** | ✅ via MCP initialize | ❌ | **AI Sec Crew** |
| 13 | **Install Gate (terminal firewall)** | ❌ | ✅ npm/pip/cargo/gem/go | **CodeGuard** |
| 14 | **Sandbox Runtime Analysis** | ❌ | ✅ | **CodeGuard** |
| 15 | **SBOM Generation (CycloneDX)** | ❌ | ✅ 1.5 with drift | **CodeGuard** |
| 16 | **AI-SBOM (AI component inventory)** | ❌ | ✅ first-of-kind | **CodeGuard** |
| 17 | **Shadow AI Discovery** | ❌ | ✅ 15+ SDK detectors | **CodeGuard** |
| 18 | **Provenance Verification (Sigstore)** | ❌ | ✅ npm + PyPI | **CodeGuard** |
| 19 | **Trust Score (composite 0-100)** | ❌ | ✅ | **CodeGuard** |
| 20 | **AI Code Attribution** | ❌ | ✅ AI vs human tracking | **CodeGuard** |
| 21 | **Policy-as-Code Engine** | ❌ | ✅ 20+ configurable rules | **CodeGuard** |
| 22 | **Security Score (project grade)** | ❌ | ✅ 0-100, A-F | **CodeGuard** |
| 23 | **Team Dashboard** | ❌ | ✅ React SPA | **CodeGuard** |
| 24 | **CI/CD Integration** | ⚠️ Docker only | ✅ CLI + SARIF + GH Action | **CodeGuard** |
| 25 | **Pre-commit Hook** | ❌ | ✅ | **CodeGuard** |
| 26 | **Compliance Reports** | ❌ | ✅ CRA/SOC2/ISO/EO14028 | **CodeGuard** |
| 27 | **Real-time IDE Diagnostics** | ❌ (agent-triggered) | ✅ on save/type | **CodeGuard** |
| 28 | **Git Regression Detection** | ❌ | ✅ | **CodeGuard** |
| 29 | **AI Config Attack Detection** | ❌ | ✅ 17+ patterns | **CodeGuard** |
| 30 | **Custom Org Security Guidelines** | ✅ markdown files | ❌ | **AI Sec Crew** |
| 31 | **Cross-file Taint Tracking** | ❌ | ✅ | **CodeGuard** |

### Scorecard

| | Count |
|---|---|
| **CodeGuard AI wins** | **23** |
| **AI Security Crew wins** | **6** |
| **Tie** | **2** |

---

## 5. Key Philosophical Differences

### 5.1 Agent-Driven vs Infrastructure-Level

**AI Security Crew** relies on the AI agent to decide when to call security tools. The agent follows workflow instructions injected at MCP `initialize`. If the agent ignores the workflow, chooses not to call tools, or hallucinates a "clean" result — **security checks silently don't run**.

**CodeGuard AI** runs automatically — file watchers trigger on save, terminal watchers intercept installs, diagnostics update in real-time. No agent cooperation is needed. Security is enforced at the infrastructure level, not the agent level.

> **Implication:** CodeGuard AI provides guaranteed coverage. AI Security Crew provides advisory coverage that depends on agent compliance.

### 5.2 MCP Server vs MCP Scanner

**AI Security Crew** IS an MCP server — it *provides* security tools to AI agents.

**CodeGuard AI** SCANS MCP servers — it *detects attacks* in MCP configurations (tool poisoning, rug-pull risks, credential exposure, prompt injection).

These are fundamentally different and complementary. AI Security Crew doesn't protect you from a malicious MCP server in your project; CodeGuard AI does. Conversely, CodeGuard AI doesn't inject security context into agent workflows; AI Security Crew does.

### 5.3 AI-Dependent vs Deterministic

**AI Security Crew's** code verification and reachability analysis use AI analysis via `ctx.sample()` — non-deterministic. The same code can produce different security findings on different runs.

**CodeGuard AI's** SAST uses deterministic regex rules (35+) as the primary engine, with optional LLM deep analysis as a second pass. CI/CD pipelines produce the same results every run — critical for compliance and auditing.

### 5.4 Shift-Left Timing

| Phase | AI Security Crew | CodeGuard AI |
|-------|-----------------|--------------|
| Before coding (requirements) | ✅ `lightweight_security_review` | ❌ |
| During coding (real-time) | ❌ (only if agent calls tools) | ✅ (file watchers, diagnostics) |
| Package installation | ⚠️ (agent must call `verify_packages`) | ✅ (Install Gate intercepts automatically) |
| After coding (review) | ✅ `verify_code_security` | ✅ (Scan commands, CLI) |
| CI/CD pipeline | ⚠️ (Docker container) | ✅ (Native CLI + SARIF + GH Action) |
| Git commit | ❌ | ✅ (Pre-commit hook) |

---

## 6. Where AI Security Crew Is Stronger

### 6.1 CVE Reachability Analysis
Their dependency scanner determines if vulnerable code paths are **actually called** in your application:

```
Reachability levels:
  reachable       → vulnerable function is directly called
  not_reachable   → vulnerable function exists but isn't called
  not_imported    → vulnerable module isn't even imported
  uncertain       → couldn't determine (falls back to AI analysis)
  no_code_provided → no source code available for analysis
```

Uses three tiers: OSV function-level symbols → keyword matching against vuln summary → AI analysis via `ctx.sample()`.

**Why it matters:** Reduces false positives significantly. A project may have 50 CVEs but only 3 are reachable. CodeGuard AI reports all 50 without differentiation.

### 6.2 Threat Modeling
Full STRIDE-based threat modeling with:
- `perform_threat_model` — generates threat model from code/requirements
- `update_threat_model_file` — persists to `threat-model.md`
- `search_previous_threat_models` — searchable history

CodeGuard AI has no threat modeling capability.

### 6.3 Pre-coding Security Injection
Injects security requirements into the agent's context **before** it writes any code. The MCP `initialize` handshake tells the agent:
1. Call `lightweight_security_review` before writing code
2. Call `verify_packages` when adding dependencies
3. Call `verify_code_security` after generating code

This is a genuine shift-left that CodeGuard AI doesn't have — CodeGuard catches issues after code is written.

### 6.4 Jira Ticket Security Assessment
`assess_ticket_security` pulls a Jira ticket and identifies security implications in the requirements before any code is written. This is useful for enterprise teams where work items originate from Jira.

### 6.5 OWASP Knowledge Base
101 OWASP Cheat Sheets are bundled and automatically loaded into security assessments, providing structured security knowledge that improves the quality of AI-generated security advice. Organizations can also add custom guidelines as markdown files.

### 6.6 Claude Code Plugin
Direct integration with Claude Code as a plugin — no Docker or MCP config needed:
```
/plugin install Srajangpt1/ai_security_crew
```
Provides `/sec-review`, `/verify-code`, `/threat-model` as native slash commands.

---

## 7. Where CodeGuard AI Is Stronger

### 7.1 Hallucination / Slopsquatting Detection (CRITICAL GAP in AI Security Crew)
The single biggest differentiator. CodeGuard AI detects AI-hallucinated package names that don't exist on npm or PyPI — the core attack vector in slopsquatting attacks.

- 520+ known hallucinated packages in bundled database
- Live npm/PyPI registry verification
- Typosquatting detection (Levenshtein distance to popular packages)
- GHIN (Global Hallucination Intelligence Network) with 205K+ entries

**AI Security Crew has zero hallucination detection.** Their `verify_packages` checks for CVEs in real packages but doesn't verify that the package itself exists. This is a critical gap — slopsquatting is the #1 AI-specific supply chain threat.

### 7.2 MCP Configuration Security (7 Attack Categories)
CodeGuard AI scans MCP config files for:

| Category | Example | Severity |
|----------|---------|----------|
| Tool Poisoning | `"Ignore previous instructions"` in tool description | Critical |
| Credential Exposure | Hardcoded `AWS_SECRET_KEY` in env | Critical |
| Pipe-to-Shell | `curl ... \| bash` in command | Critical |
| Rug-Pull Risk | `npx` downloads latest at runtime | High |
| Unencrypted Transport | `http://` remote URL | High |
| Prompt Injection | Hidden Unicode in tool descriptions | High |
| Cross-Origin Escalation | Tool accessing filesystem outside workspace | High |

AI Security Crew IS an MCP server but doesn't audit MCP configs — it could itself be a vector if misconfigured.

### 7.3 Install Gate (Terminal Firewall)
Real-time interception of package install commands across 5 package managers:
- `npm install` / `yarn add` / `pnpm add`
- `pip install` / `pip3 install`
- `cargo add`
- `gem install`
- `go get`

Intercepts **before execution**, shows risk analysis, allows approve/deny. AI Security Crew has no terminal-level protection.

### 7.4 Secrets Detection (20+ Patterns)
Dedicated regex-based secrets scanner detecting:
- AWS Access Keys, Secret Keys
- GitHub/GitLab tokens
- Stripe, Slack, Google API keys
- Database connection strings
- Private keys (RSA, SSH, PGP)
- JWT secrets
- Generic password patterns

AI Security Crew has no dedicated secrets scanner.

### 7.5 Policy-as-Code Engine (20+ Rules)
Configurable `.codeguard/policy.json` with rules including:
- `max_critical_findings`, `max_high_findings`
- `forbidden_packages`, `allowed_packages`
- `max_ai_code_ratio`
- `block_npx_mcp_servers`, `block_unencrypted_mcp`
- `block_mcp_hardcoded_credentials`
- `max_mcp_issues`
- `require_ai_sbom`, `allowed_ai_sdks`
- `require_secrets_scanner`, `require_sast_scanner`

Three enforcement modes: `audit` → `warn` → `enforce`. AI Security Crew has no policy engine.

### 7.6 Shadow AI Discovery + AI-SBOM
First-of-kind AI component inventory that discovers:
- 18+ AI config file patterns (`.cursorrules`, `CLAUDE.md`, `.clinerules`, etc.)
- 15+ AI SDKs in source code (OpenAI, Anthropic, LangChain, CrewAI, AutoGen, etc.)
- 10 model file types (`.onnx`, `.pt`, `.safetensors`, `.gguf`, etc.)
- All MCP server configurations

Exports as **AI-SBOM** — no equivalent exists in AI Security Crew or any other tool.

### 7.7 SBOM + Provenance
- **CycloneDX 1.5 SBOM** generation with drift detection against baselines
- **Sigstore provenance** verification for npm packages
- **PEP 740** provenance for PyPI packages
- Trust tiers: Verified → Partial → Suspicious → Untrusted

AI Security Crew generates neither SBOMs nor provenance checks.

### 7.8 CI/CD Native
- Standalone CLI with zero VS Code dependency
- SARIF v2.1.0 output for GitHub Code Scanning
- GitHub Action composite action (`action.yml`)
- Pre-commit git hook
- JSON and colored table output formats
- Exit codes for CI gate enforcement

AI Security Crew requires Docker and is primarily designed for IDE-time agent use, not CI/CD pipelines.

### 7.9 Deterministic Scanning
35+ SAST regex rules, 20+ secrets patterns, and 7 MCP detection categories produce **identical results on every run**. Critical for:
- Compliance auditing (SOC 2, ISO 27001)
- CI/CD gate decisions
- Regression testing

AI Security Crew's AI-driven analysis (`ctx.sample()`) is non-deterministic — same code can produce different results.

### 7.10 Real-Time IDE Feedback
VS Code diagnostics (red underlines, Problems panel), status bar security score, sidebar TreeView — all update **automatically** on file save without any agent involvement.

AI Security Crew only produces results when an agent explicitly calls its tools.

---

## 8. Gaps to Close

Features AI Security Crew has that we should consider adding:

| # | Gap | Effort | Impact | Priority | Notes |
|---|-----|--------|--------|----------|-------|
| 1 | **Expose CodeGuard as an MCP server** | Medium | High | **P1** | Let AI agents call our hallucination, SAST, secrets tools via MCP. This makes us work in BOTH paradigms — automated + agent-driven. |
| 2 | **CVE Reachability Analysis** | High | High | **P1** | Function-level analysis to mark CVEs as reachable/not-reachable. Reduces noise significantly. Could use OSV symbols + import graph analysis. |
| 3 | **Threat Modeling** | Medium | Medium | **P2** | STRIDE-based threat model generation with file persistence. Appeals to security-conscious enterprises. |
| 4 | **OWASP Guidelines Bundle** | Low | Medium | **P2** | Bundle 101 OWASP Cheat Sheets as a searchable knowledge base. Low effort, high perceived value. |
| 5 | **Pre-coding Security Injection** | Medium | Medium | **P2** | If we build the MCP server (P1 #1), we can inject security context via `initialize` handshake — just like AI Security Crew. |
| 6 | **Jira Ticket Assessment** | Medium | Medium | **P3** | Inbound Jira integration (pull tickets, assess security). Currently we only have outbound webhook. |
| 7 | **Custom Org Guidelines** | Low | Low | **P3** | Load custom markdown security guidelines. Low effort add-on once OWASP bundle exists. |
| 8 | **Claude Code Plugin** | Low | Low | **P3** | Package our tools as a Claude Code plugin with slash commands. |

### Recommended Roadmap (v8.0.0)

**Phase 1 (High Priority):**
- Add MCP server mode — expose hallucination, SAST, secrets, MCP scanning as MCP tools
- Add reachability analysis to OSV vulnerability scanning

**Phase 2 (Medium Priority):**
- Bundle OWASP Cheat Sheets
- Add STRIDE threat modeling with `threat-model.md` persistence
- Pre-coding security injection via MCP initialize

**Phase 3 (Low Priority):**
- Jira inbound ticket assessment
- Custom org guidelines (markdown)
- Claude Code plugin packaging

---

## 9. Market Positioning

### One-Line Positioning

> **AI Security Crew** is a security advisor for AI agents. **CodeGuard AI** is a security enforcement platform for AI-era development.

### Positioning Matrix

```
                    Agent-Driven ◄──────────────────► Automated
                         │                              │
                         │  AI Security Crew            │
     Advisory ──────     │  (advisor to agents)         │
         │               │                              │
         │               │                              │
         │               │                    CodeGuard AI
     Enforcement ───     │                    (enforces at infra level)
                         │                              │
```

### Key Messages for Different Audiences

**For developers:**
> "AI Security Crew tells your AI assistant about security. CodeGuard AI catches what your AI assistant missed — hallucinated packages, hardcoded secrets, poisoned MCP configs — automatically, in real-time, without waiting for an AI agent to cooperate."

**For security teams:**
> "AI Security Crew is non-deterministic and agent-dependent — you can't guarantee it ran. CodeGuard AI produces deterministic, reproducible results with SARIF output, policy enforcement, and CI/CD gates. It's auditable."

**For engineering leaders:**
> "AI Security Crew covers pre-coding advisory and threat modeling. CodeGuard AI covers the full lifecycle — from terminal install interception through CI/CD gates to compliance reports. It's the only tool that detects AI-hallucinated packages, scans MCP configs for attacks, and generates AI-SBOMs."

### The Complementary Argument

These tools are not strictly competitors — they address different layers:

| Layer | Best Tool |
|-------|-----------|
| Pre-coding requirements review | AI Security Crew |
| Real-time code scanning | CodeGuard AI |
| Package hallucination detection | CodeGuard AI (only option) |
| CVE scanning with reachability | AI Security Crew |
| CVE scanning without reachability | Both (OSV.dev) |
| Secrets detection | CodeGuard AI (only option) |
| MCP config security | CodeGuard AI (only option) |
| Threat modeling | AI Security Crew (only option) |
| Policy enforcement | CodeGuard AI (only option) |
| CI/CD integration | CodeGuard AI |
| SBOM + AI-SBOM | CodeGuard AI (only option) |

A security-mature team could run both: AI Security Crew for agent-time advisory + CodeGuard AI for automated enforcement. But if you can only choose one, CodeGuard AI covers significantly more ground (23 vs 6 capabilities).

---

*Generated: 2026-03-20 | CodeGuard AI v7.0.0 vs AI Security Crew (37 commits, 2 contributors)*
