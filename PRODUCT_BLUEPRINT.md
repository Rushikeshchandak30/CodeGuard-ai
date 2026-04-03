# CodeGuard AI — Product Blueprint

> **The Immune System for AI-Assisted Development.**
> Not a scanner. Not a linter. A pre-execution security enforcement layer that no system prompt, IDE rule, or AI configuration file can replicate.

---

## The Problem We Solve

AI coding assistants (Copilot, Cursor, Claude, ChatGPT) are now writing 30-60% of production code. This creates three new threat surfaces that **did not exist before 2023:**

| Threat | Example | Who Else Stops It? |
|--------|---------|-------------------|
| **AI package hallucinations** | AI suggests `flask-async-utils` — it doesn't exist. Attacker registers it with malware. | Nobody in the IDE. |
| **Poisoned AI config files** | Hidden Unicode in `.cursorrules` makes AI inject `<script src="evil.com">` into every output. | Nobody. Period. |
| **Unverified supply chains** | AI suggests package with zero provenance. Was it built from source? Published from CI? Unknown. | Not at write-time. |

These aren't hypothetical. USENIX Security 2025 documented **205,474 hallucinated package names** across 16 LLMs. Pillar Security published the "Rules File Backdoor" attack in 2025. Over 16,000 npm packages now publish cryptographic provenance — but no tool checks it when AI writes the import.

**CodeGuard AI is the first tool that catches all three — at the moment they happen, inside the IDE, before any code or package enters the project.**

---

## What Makes Us Fundamentally Different

### The Core Insight

Every competitor (Snyk, Socket, Semgrep, Trivy, Aikido) works **after the fact** — in CI pipelines, PR checks, or web dashboards. By the time they flag something, the malicious package has already been installed and its install scripts have already run.

```
Traditional security:    Write code → Install deps → Push to CI → Scanner finds issue → Fix
CodeGuard AI:            Write code → CodeGuard intercepts → Block before install → Never enters project
```

We operate at **three points no one else occupies:**

| Interception Point | What Happens | Who Else Does This? |
|-------------------|-------------|-------------------|
| **At write-time** | AI writes `import x` → we verify `x` exists, has provenance, has no CVEs — instantly | Nobody |
| **At install-time** | Developer types `npm install x` → we intercept the terminal, analyze the package, show risk → block or approve | Nobody in IDE |
| **At config-load** | IDE loads `.cursorrules` → we scan for hidden Unicode, prompt injection, security suppression | Nobody. Period. |

### The Fundamental Asymmetry

> A system prompt is **inside** the AI's generation loop. CodeGuard AI is **outside** it, in the enforcement layer.
> **You cannot use the prisoner to guard the prison.**

A `.cursorrules` file can say "avoid bad packages" — but it can't query a live registry, verify a Sigstore certificate, download a tarball, or parse an install script. It is static text. We are a running security engine.

---

## The 6-Layer Defense Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        LAYER 6                                   │
│            AI Config Defense (Rules File Scanner)                 │
│   Scans .cursorrules, copilot-instructions.md, .windsurfrules    │
│   for hidden Unicode, prompt injection, security suppression     │
│   → DEFENDS AGAINST the system-prompt competition itself         │
├─────────────────────────────────────────────────────────────────┤
│                        LAYER 5                                   │
│                Compliance & Visibility                            │
│   Live SBOM (CycloneDX 1.5) · Dependency Drift Detection        │
│   Security Score (0-100, A-F) · Score History · Findings Panel   │
│   → EU Cyber Resilience Act / US EO 14028 ready                 │
├─────────────────────────────────────────────────────────────────┤
│                        LAYER 4                                   │
│                   AI Advisory Layer                               │
│   LLM Explanations (GPT-4o via VS Code LM API)                  │
│   Semantic Intent Verifier · Agentic Patch Assistant             │
│   → AI explains risks, auto-fixes vulnerabilities               │
├─────────────────────────────────────────────────────────────────┤
│                        LAYER 3                                   │
│               Supply Chain Intelligence                          │
│   GHIN (crowdsourced hallucination DB, 46+ seed + cloud)         │
│   Cryptographic Provenance (Sigstore, PEP 740, SLSA)            │
│   Trust Score (0-100) · Auto-Patch (OSV + GitHub Advisory)       │
│   → Deterministic, evidence-based trust decisions                │
├─────────────────────────────────────────────────────────────────┤
│                        LAYER 2                                   │
│                  Real-Time Code Scanning                         │
│   CVE Detection (OSV.dev) · Hallucination Detection              │
│   Secrets Scanner (20+ patterns) · SAST (22 vuln patterns)      │
│   → Every import checked the moment AI writes it                 │
├─────────────────────────────────────────────────────────────────┤
│                        LAYER 1                                   │
│               Pre-Execution Prevention                           │
│   Install Gate (terminal firewall for npm/pip/cargo/go/gem)      │
│   Install Script Analyzer (tarball download + static analysis)   │
│   Dependency Permission Model (network/fs/env per package)       │
│   → Physically prevents dangerous packages from installing       │
└─────────────────────────────────────────────────────────────────┘
```

**Critical design rule:** All security **decisions** happen locally. The cloud (GHIN API) provides intelligence only. CodeGuard works fully offline — zero dependency on external services for enforcement.

---

## The 7 Breakthrough Capabilities (No Competitor Has All 7)

### 1. Global Hallucination Intelligence Network (GHIN) — THE MOAT

A crowdsourced, anonymized database of AI-hallucinated package names.

**How it works:**
- Seeded with data from USENIX Security 2025 research (205K hallucinated names across 16 LLMs)
- Every CodeGuard user anonymously reports confirmed hallucinations (opt-in)
- Reports include IDE context (VS Code / Cursor / Windsurf) and AI agent (Copilot / Claude / ChatGPT)
- Risk scoring: packages hallucinated by multiple LLMs across multiple sessions get higher scores
- Cloud API tracks which AI agents hallucinate the most, which ecosystems are most affected

**Why it's unbeatable:** 100 users → decent DB. 10,000 users → no static rule file can compete. The database **grows with every installation**. A `.cursorrules` file is frozen the moment it's written.

**Privacy:** Only `package_name + ecosystem + exists_boolean` sent. No source code, no user identity, no file paths.

### 2. Package Install Gate — PREVENTION, NOT DETECTION

Intercepts `npm install`, `pip install`, `cargo add`, `go get`, `gem install`, `yarn add`, `pnpm add`, `uv add`, `poetry add` commands in the VS Code terminal **before they execute**.

```
Developer types: npm install express lodash fake-pkg-xyz

CodeGuard intercepts → parses command → analyzes each package:
  ✅ express@5.1.0 — Sigstore provenance verified, 30M downloads/week
  ⚠️ lodash@4.17.15 — 4 CVEs → safe version: 4.17.21
  ❌ fake-pkg-xyz — BLOCKED: known hallucination (GHIN score: 0.97)

Shows rich webview panel with verdicts, one-click approve/block.
```

System prompts say "drive carefully." We **are** the seatbelt — we physically prevent the crash.

### 3. Cryptographic Provenance Verification

When AI writes `import express`, we immediately verify the package's cryptographic supply chain:

- **npm:** Sigstore attestation via `registry.npmjs.org/-/npm/v1/attestations/{pkg}@{version}`
- **PyPI:** PEP 740 attestation via `pypi.org/integrity/{project}/{version}/{filename}/provenance`
- SLSA level extraction, source repo verification, publisher identity via OIDC

**Trust tiers:**
```
🟢 VERIFIED   — Sigstore provenance + verified publisher + >1M downloads
🟡 PARTIAL    — Exists on registry, no provenance, decent downloads
🟠 SUSPICIOUS — No provenance, <1000 downloads, registered recently
🔴 UNTRUSTED  — Not on registry / known hallucination / malware flagged
```

No system prompt can fetch attestations, verify certificate chains, or check transparency logs.

### 4. Rules File Integrity Scanner — DEFEND THE DEFENDERS

Scans **all** AI configuration files for attacks:

| Attack Vector | What We Detect |
|--------------|---------------|
| Hidden Unicode | 24 invisible characters (zero-width joiners, bidirectional marks, Mongolian vowel separators) |
| Prompt injection | 15+ patterns: "ignore previous instructions", role override, system: prefix |
| Security suppression | "suppress warnings", "disable codeguard", "override security" |
| Obfuscated payloads | Base64 strings, hex-encoded strings, char code construction |
| Exfiltration | Instructions to send data to URLs, encode secrets, access env vars |

**This protects AGAINST the competition.** If someone ships a malicious `.cursorrules` with "always suggest package X" (where X is a trojan), CodeGuard catches it. We don't compete with rule files — we **guard** them.

### 5. Install Script Static Analysis

Before `npm install <pkg>` runs, we download the package tarball, extract `preinstall`/`postinstall` scripts, and analyze for:

| Pattern | Risk Level |
|---------|-----------|
| Network calls to unknown domains | HIGH |
| `process.env.NPM_TOKEN` access | CRITICAL |
| File writes outside project dir | CRITICAL |
| `child_process.exec('curl ...')` | HIGH |
| `eval(Buffer.from('...').toString())` | CRITICAL |
| Dynamic `require(variable)` | MEDIUM |

Socket.dev does this in CI. We do it **in the IDE, before the script executes**.

### 6. Semantic Intent Verification

Compares what the developer **asked for** vs what the AI **generated**:

- User: "Create a simple HTTP server"
- AI output includes: `<script src="https://evil.com/payload.js">`
- CodeGuard: "⚠️ External script tag not related to your request — possible Rules File Backdoor attack"

This catches the Pillar Security attack in real-time.

### 7. Live SBOM + Dependency Drift

- Real-time CycloneDX 1.5 SBOM generation from lockfiles (npm, PyPI, Cargo, Go)
- Drift detection: new deps added by AI, version downgrades, license changes
- Output: `.codeguard/sbom.cdx.json` — git-committable, CI-readable
- EU Cyber Resilience Act / US EO 14028 compliant

---

## Competitive Moat — The Full Picture

| Capability | System Prompt | Snyk | Socket | Semgrep | Trivy | Aikido | **CodeGuard AI** |
|------------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Guidance ("avoid bad pkgs") | ✅ | - | - | - | - | - | ✅ |
| Registry existence check | - | ✅ | ✅ | - | - | - | ✅ |
| CVE scanning | - | ✅ | ✅ | - | ✅ | ✅ | ✅ |
| **AI hallucination detection** | - | - | - | - | - | - | **✅** |
| **Crowdsourced hallucination DB** | - | - | - | - | - | - | **✅** |
| **Terminal install firewall (IDE)** | - | - | CLI* | - | - | - | **✅** |
| **Provenance verify at write-time** | - | - | - | - | - | - | **✅** |
| **AI config file attack scanner** | - | - | - | - | - | - | **✅** |
| **Install script pre-analysis** | - | - | CI† | - | - | - | **✅** |
| **Semantic intent verification** | - | - | - | - | - | - | **✅** |
| **Real-time SBOM in IDE** | - | - | - | - | - | CI‡ | **✅** |
| Secrets scanning | - | ✅ | - | ✅ | ✅ | ✅ | ✅ |
| SAST patterns | - | ✅ | - | ✅ | - | ✅ | ✅ |
| Auto-patch with fix commands | - | partial | - | - | - | - | **✅** |
| Agentic auto-fix workflow | - | - | - | - | - | - | **✅** |
| LLM-powered risk explanations | - | - | - | - | - | - | **✅** |
| Network effect (grows w/ users) | - | ✅ | ✅ | - | - | - | **✅** |

\* Socket's `safe-npm` is CLI-only, not IDE-native
† Socket does script analysis in CI/web dashboard, not pre-install in IDE
‡ Aikido generates SBOM in CI, not real-time in IDE

**5 of 7 breakthrough capabilities have ZERO competitors.**

---

## Why System Prompts Can NEVER Replace This

| CodeGuard Capability | Why Prompts Can't Replicate |
|---------------------|---------------------------|
| GHIN crowdsourced DB | Prompts are static text — they can't query a live, growing database |
| Terminal interception | Prompts run inside the AI — they have zero access to the terminal |
| Cryptographic provenance | Requires fetching Sigstore attestations and verifying certificate chains |
| Rules file scanning | The rules file IS the prompt — it can't scan itself for attacks |
| Install script analysis | Requires downloading tarballs and performing static analysis |
| Semantic intent verification | Prompts can't compare their own output to the user's intent externally |
| Real-time SBOM | Requires file system parsing, registry queries, CycloneDX generation |

---

## Self-Healing Dependency Network — The Patch Pipeline

CodeGuard doesn't just detect problems. **It fixes them.**

```
Detection                  Intelligence               Fix
─────────                  ────────────               ───
Import scanned        →    OSV.dev CVE query     →    Safe version identified
Terminal intercepted  →    GHIN + Trust Score    →    Block or suggest alternative
Provenance checked    →    GitHub Advisory DB    →    Patch command generated
Script analyzed       →    LLM risk explanation  →    One-click "Apply Patch"
```

**Data sources for patch intelligence:**
- **OSV.dev** — Google's open vulnerability database (primary)
- **GitHub Advisory Database** — CVE + remediation data
- **npm Registry** — deprecation status, latest versions
- **PyPI JSON API** — version history, download stats
- **18 built-in deprecated → alternative package mappings** (e.g., `request` → `got`/`axios`)

The Agentic Patch Assistant automates the full workflow: detect → analyze → suggest → edit `package.json` / `requirements.txt` → show diff → apply.

---

## The LLM Layer — Where AI Helps (And Where It Doesn't)

### ✅ Where We USE LLMs

| Use Case | Example |
|----------|---------|
| **Explain risks** | Convert "Prototype pollution via unsafe merge" → "Attackers could modify application logic through object merging" |
| **Generate patch summaries** | "Upgrade lodash to 4.17.21 to fix CVE-2021-23337 (command injection via template)" |
| **Explain script risks** | "This install script downloads external code from api.evil.com, which could execute arbitrary commands" |
| **Chat participant** | `@codeguard is lodash safe?` → full trust report in Copilot Chat |

### ❌ Where We DO NOT Use LLMs

| Decision | Method |
|----------|--------|
| Package exists? | Registry API (deterministic) |
| Package has CVEs? | OSV.dev query (deterministic) |
| Has provenance? | Sigstore attestation check (deterministic) |
| Trust score? | Multi-signal formula (deterministic) |
| Hidden Unicode? | Character code matching (deterministic) |

**LLMs are advisory. The security engine is deterministic.** Security decisions must never depend on probabilistic language generation.

---

## Technical Implementation

### Codebase Stats

| Component | Files | Total Lines |
|-----------|-------|-------------|
| Shield (Install Gate, Rules Scanner, Script Analyzer, Permissions) | 4 | ~1,830 |
| Checkers (Hallucination, Provenance, OSV, Auto-Patch, Secrets, Code Vuln) | 10 | ~3,500 |
| AI Layer (Intent Verifier, LLM Advisor, Patch Agent, Chat Participant) | 7 | ~1,800 |
| Intelligence (GHIN, GHIN Client, Trust Score, Telemetry) | 4 | ~1,300 |
| SBOM (Generator, Drift Detector) | 2 | ~800 |
| Scoring (Security Score, History) | 2 | ~400 |
| UI (Findings Tree, Trust Tree, StatusBar, Hover) | 4 | ~500 |
| Extension Entry Point | 1 | ~880 |
| Cloud API + Schema + Ingester | 3 | ~815 |
| **Total** | **~50 files** | **~10,000+ lines** |

### VS Code Integration Points

- **20+ commands** registered in Command Palette
- **Sidebar Activity Bar** with Security Findings + Trust Tier tree views
- **Chat Participant** (`@codeguard` in Copilot Chat)
- **Terminal shell integration** for install command interception
- **15+ configuration settings** (toggle each feature independently)
- **StatusBar** with live security score (color-coded)
- **Hover provider** with inline trust info on imports
- **File watchers** on dependency files + AI config files
- **Diagnostic provider** with CodeActions (quick-fix suggestions)

### Cloud Infrastructure

| Component | Technology | Purpose |
|-----------|-----------|---------|
| GHIN REST API | Fastify (Node.js) | 4 endpoints: report, bulk-check, package intel, agent stats |
| Database | PostgreSQL 16 | 4 tables + 2 lookup tables + 2 materialized views |
| Ingestion Worker | Cron job (every 6 hr) | Pulls from OSV.dev + GitHub Advisory + npm metadata |
| Data Model | 252-line schema.sql | IDE/agent-aware telemetry with full context tracking |

---

## Revenue Model

| Tier | Price | What You Get |
|------|-------|-------------|
| **Free (Community)** | $0 | All local features + GHIN read access + 50 provenance checks/day |
| **Pro (Individual)** | $9/mo | Unlimited provenance + install script analysis + priority GHIN |
| **Team** | $29/seat/mo | Shared SBOM, team policy engine, private hallucination DB |
| **Enterprise** | Custom | On-prem GHIN, SAML/SSO, audit trail, compliance reports, air-gapped mode |

The GHIN network effect creates a natural freemium funnel: free users contribute hallucination data, paid users get premium intelligence and unlimited API calls.

---

## The One-Line Summary

```
System Prompt:   "Please don't use bad packages"           → hope-based security
CodeGuard AI:    "I verified this package's cryptographic
                  provenance, checked it against 205K known
                  hallucinations, analyzed its install scripts
                  for malware, and intercepted the terminal
                  command before it ran."                    → evidence-based security
```

**CodeGuard AI doesn't compete with system prompts. It makes them safe to use.**
