# CodeGuard AI — Complete Technical Reference

**Version:** 8.0.0 | **Coverage:** Every module, engine, rule, integration, and configuration

---

## Table of Contents

1. [What Is CodeGuard AI](#1-what-is-codeguard-ai)
2. [System Architecture](#2-system-architecture)
3. [AI-Era Detection Engines v8.0](#3-ai-era-detection-engines-v80)
4. [Core Security Engines](#4-core-security-engines)
5. [Supply Chain Intelligence](#5-supply-chain-intelligence)
6. [AI Shield Layer](#6-ai-shield-layer)
7. [AI Integration Layer](#7-ai-integration-layer)
8. [IDE Integration](#8-ide-integration)
9. [Reporting & Compliance](#9-reporting--compliance)
10. [Policy Engine](#10-policy-engine)
11. [Platform Components](#11-platform-components)
12. [Language Support](#12-language-support)
13. [Security Standards Coverage](#13-security-standards-coverage)
14. [Configuration Reference](#14-configuration-reference)
15. [All VS Code Commands](#15-all-vs-code-commands)

---

## 1. What Is CodeGuard AI

CodeGuard AI is an **AI-era security platform** delivered as a VS Code/Windsurf/Cursor extension, CLI tool, GitHub Action, and web service. It protects developers from both classic vulnerabilities (CVEs, secrets, injection) and threats unique to AI-assisted development (hallucinated packages, LLM jailbreaks, unsafe ML models, malicious MCP servers).

### Core Philosophy

| Principle | Detail |
|---|---|
| **AI-first, not AI-only** | Critical security decisions use deterministic rules. LLM enriches — never decides alone |
| **Offline-capable** | All regex engines + local CVE/GHIN databases work fully offline |
| **Zero-friction** | Diagnostics appear as inline squiggles — no separate scan step |
| **Defense in depth** | 12+ independent engines, each catching different threat classes |

### Problems Solved

| Threat | Traditional Tool | CodeGuard AI |
|---|---|---|
| AI suggests a non-existent package | ❌ | ✅ GHIN database + registry check |
| LLM jailbreak in `.cursorrules` | ❌ | ✅ 20+ jailbreak rules |
| Malicious MCP server config | ❌ | ✅ CVE DB + behavioral scan |
| Pickle exploit in ML model | ❌ | ✅ Byte-level opcode analysis |
| Cryptominer in `postinstall` | ❌ | ✅ Script + pool + wallet detection |
| Hardcoded OpenAI/AWS key | Partial | ✅ 60+ AI/cloud provider patterns |
| SQL injection | ✅ | ✅ + LLM adversarial verification |
| GPL license in proprietary project | ❌ | ✅ SPDX-aware compliance engine |

---

## 2. System Architecture

### Module Map

| Directory | Files | Responsibility |
|---|---|---|
| `src/checkers/` | 17 | All detection engines (SAST, secrets, CVE, license, IaC…) |
| `src/shield/` | 8 | AI assistant protection (MCP, rules scanner, install gate…) |
| `src/intelligence/` | 7 | Supply chain data (GHIN, trust scores, maintainers…) |
| `src/ai/` | 8 | LLM integration (chat participant, advisor, patch agent…) |
| `src/ui/` | 4 | Editor UI (tree views, hover provider, status bar…) |
| `src/sbom/` | 2 | SBOM generation & drift detection |
| `src/reports/` | 1 | Compliance report generation |
| `src/policy/` | 1 | Configurable policy engine |
| `src/analysis/` | 2 | Taint tracking & git regression detection |
| `src/scoring/` | 2 | Security score calculation & history |
| `src/extension.ts` | — | Main entry point — bootstraps all modules |
| `src/watcher.ts` | — | File-watch loop — triggers scans on change |

### Detection Flow

```
File saved / pasted
       ↓
DocumentWatcher (src/watcher.ts)
       ↓ triggers each engine in parallel
┌──────────────────────────────────────────────────┐
│  Secrets │ SAST-Regex │ CVE │ Hallucination       │
│  MCP     │ Jailbreak  │ IaC │ Cryptojacking       │
│  License │ API-Sec    │ ML  │ Typosquat           │
└──────────────────────┬───────────────────────────┘
                       ↓
             DiagnosticsProvider
                       ↓
         VS Code Problems Panel + Squiggles
```

---

## 3. AI-Era Detection Engines (v8.0)

### 3.1 LLM Jailbreak & Prompt Injection Scanner

**File:** `src/checkers/jailbreak-scanner.ts` | **Standard:** OWASP LLM01

**Scanned files:** `.cursorrules`, `.windsurfrules`, `CLAUDE.md`, `copilot-instructions.md`, `system-prompt.txt`, `.py`, `.js`, `.ts`, `.md`, `.json`, `.yaml`

**8 Detection Categories:**

| Category | Rule Range | Examples | Severity |
|---|---|---|---|
| `direct-jailbreak` | CG_JB_001–010 | DAN, STAN, DUDE, AIM, developer-mode, evil-twin | CRITICAL |
| `role-override` | CG_JB_011–015 | "Disregard previous instructions", "Forget all safety" | CRITICAL |
| `system-override` | CG_JB_016–018 | ChatML `<\|system\|>` injection, token manipulation | CRITICAL |
| `hidden-unicode` | CG_JB_019–022 | Zero-width joiners, BiDi override, Unicode Tag block | HIGH |
| `prompt-leak` | CG_JB_023–026 | "Repeat your system prompt verbatim" | HIGH |
| `known-payload` | CG_JB_027–035 | Grandma exploit, AIM story, hypothetical framing | HIGH |
| `unsafe-concatenation` | CG_JB_036–040 | `systemPrompt + req.body.input` in source code | HIGH |
| `prompt-injection` | CG_JB_041–050 | "Do not tell the user", embedded instructions in data | HIGH |

**Key Rules:**
- `CG_JB_001` — DAN (Do Anything Now) persona activation
- `CG_JB_003` — Developer mode unlock
- `CG_JB_005` — Grandma/bedtime social engineering exploit
- `CG_JB_015` — "Do not tell the user" covert directive
- `CG_JB_018` — ChatML system-tag injection
- `CG_JB_019` — Hidden Unicode steganography
- `CG_JB_036` — Unsafe prompt concatenation in code

---

### 3.2 MCP CVE Database Scanner

**File:** `src/shield/mcp-cve-db.ts` | **Source:** NVD, GitHub Advisories, Enkrypt AI research

Checks every MCP server in `mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json`, `.vscode/mcp.json` against:
1. Known CVEs with CVSS scores
2. Known-malicious server package registry
3. Typosquat MCP packages

**CVEs in Database:**

| CVE ID | Package | CVSS | Impact |
|---|---|---|---|
| CVE-2025-6514 | `mcp-remote <0.4.0` | 9.8 | RCE via crafted OAuth callback |
| CVE-2025-53110 | `mcp-filesystem-server <0.7.0` | 7.5 | Path traversal (arbitrary file read) |
| CVE-2025-49596 | `@modelcontextprotocol/sdk <1.11.0` | 6.1 | Prompt injection via resource metadata |
| CVE-2025-47279 | `mcp-server-fetch <0.2.0` | 7.8 | SSRF via unvalidated URL |
| CVE-2025-51847 | `claude-mcp-bridge <0.3.0` | 9.1 | Auth bypass via JWT alg:none |

**Known-Bad Server Categories:** `malicious`, `typosquat`, `deprecated-vulnerable`, `abandoned`, `suspicious-origin`

---

### 3.3 MCP Behavioral Scanner

**File:** `src/shield/mcp-scanner.ts`

Detects risky MCP behavior patterns regardless of package name:

| Category | What It Catches |
|---|---|
| `tool-poisoning` | Tool descriptions containing override/injection directives |
| `rug-pull` | Remote servers on ngrok, loca.lt, raw IPs, URL shorteners |
| `prompt-injection` | Embedded LLM instructions in resource templates |
| `unverified` | Missing version pins, `npx` without `@version` |
| `exfiltration` | Tool descriptions containing external data collection URLs |
| `suspicious-command` | `eval()` in args, base64-encoded payloads, shell injection |
| `env-exposure` | Hardcoded secrets in `env:` fields |

---

### 3.4 ML Model File Exploit Scanner

**File:** `src/checkers/model-file-scanner.ts` | **Refs:** CVE-2023-43654, CVE-2024-3660, CVE-2024-5480

**5 Format Categories:**

| Format | Extensions | What's Detected |
|---|---|---|
| Pickle/Python | `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.joblib` | `__reduce__`, `os.system`, `subprocess`, `eval`, `GLOBAL` opcode to dangerous modules |
| Keras/TF | `.h5`, `.keras`, SavedModel dir | Lambda layers with embedded Python (Keras <2.13 RCE) |
| ONNX | `.onnx` | Custom ops from unknown domains, external data URLs, oversized initializers |
| HuggingFace | `config.json`, `tokenizer_config.json` | `auto_map` → remote Python code, `trust_remote_code=True` |
| SafeTensors | `.safetensors` | Header/tensor count mismatch (tampering indicator) |

**Source Code Patterns (all languages):**

| Rule | Code Pattern | Severity |
|---|---|---|
| `CG_MODEL_CODE_001` | `torch.load(...)` without `weights_only=True` | HIGH |
| `CG_MODEL_CODE_002` | `pickle.load(file)` | CRITICAL |
| `CG_MODEL_CODE_003` | `pickle.loads(user_bytes)` | CRITICAL |
| `CG_MODEL_CODE_004` | `joblib.load(...)` (pickle-backed) | HIGH |
| `CG_MODEL_CODE_005` | `yaml.load(f)` without SafeLoader | CRITICAL |
| `CG_MODEL_CODE_007` | `AutoModel.from_pretrained(..., trust_remote_code=True)` | CRITICAL |
| `CG_MODEL_CODE_008` | `keras.models.load_model(...)` without `safe_mode=True` | HIGH |

---

### 3.5 Enhanced Typosquat Detector

**File:** `src/intelligence/typosquat-enhanced.ts`

**10 Scored Detection Signals:**

| Signal | Weight | Example |
|---|---|---|
| Levenshtein distance 1 | 0.90 | `lodahs` → `lodash` |
| Levenshtein distance 2 | 0.60 | `reqsuests` → `requests` |
| Keyboard adjacency (QWERTY) | 0.80 | `expres` → `express` |
| Homoglyph substitution | 0.95 | Cyrillic `а` instead of Latin `a` |
| Phonetic similarity | 0.50 | `ruter` → `router` |
| Transposition | 0.85 | `lodahs` → `lodash` |
| Separator tricks | 0.70 | `re-quests` → `requests` |
| Suffix tricks | 0.60 | `lodash-utils`, `react-official` |
| Prefix tricks | 0.60 | `real-express`, `official-lodash` |
| Scope drops | 0.75 | `scope-package` vs `@scope/package` |

Targets: **Top 200 npm** + **Top 150 PyPI** packages by download count.

---

### 3.6 Cryptojacking Scanner

**File:** `src/checkers/cryptojacking-scanner.ts`

| Category | Rule | Examples |
|---|---|---|
| `miner-binary` | CG_CRYPTO_001 | xmrig, minerd, ethminer, ccminer, lolminer |
| `pool-url` | CG_CRYPTO_010 | 30+ known pool hostnames (nanopool, minexmr, f2pool…) |
| `wallet-address` | CG_CRYPTO_012 | Monero (95-char), BTC (base58), ETH (0x+40hex) |
| `miner-lib` | CG_CRYPTO_015 | coinhive, jsecoin, coinIMP, crypto-loot, webminerpool |
| `shell-miner` | CG_CRYPTO_020 | `./xmrig --algo randomx --url pool --user WALLET` |
| `encoded-payload` | CG_CRYPTO_030 | Base64 strings beginning with `TVq` (MZ/PE header) |
| `wasm-signature` | CG_CRYPTO_040 | WebAssembly SIMD CryptoNight fingerprints |

**Auto-escalation:** Any cryptojacking pattern in `package.json` lifecycle scripts → **CRITICAL**.

---

## 4. Core Security Engines

### 4.1 Secrets & Credentials Checker (60+ patterns)

**File:** `src/checkers/secrets-checker.ts`

**AI Provider Keys:**
OpenAI (`sk-proj-*`), Anthropic (`sk-ant-api03-*`), HuggingFace (`hf_*`), Replicate (`r8_*`), Groq (`gsk_*`), Mistral, Perplexity (`pplx-*`), xAI (`xai-*`), Together AI, DeepSeek, Fireworks (`fw_*`), LangSmith (`lsv2_pt_*`), Cohere, Pinecone — all CRITICAL/HIGH

**Cloud Platform Keys:**
AWS Access Key (`AKIA*`), AWS Secret Key, GCP Service Account JSON, Azure Storage connection string, DigitalOcean PAT (`dop_v1_*`) — all CRITICAL/HIGH

**Dev & CI Tokens:**
GitHub PAT (`gh[pousr]_*`), GitLab PAT (`glpat-*`), Docker Hub (`dckr_pat_*`), CircleCI, Buildkite — CRITICAL/HIGH

**Payment Systems:**
Stripe secret (`sk_live_*`), Stripe test (`sk_test_*`), PayPal client secret, Square (`EAAA*`), Twilio — CRITICAL/HIGH

**Communication & SaaS:**
Slack Bot (`xoxb-*`), Slack User (`xoxp-*`), Shopify (`shpat_*`), Discord, Datadog, Sendgrid (`SG.*`) — CRITICAL/HIGH

**Generic Patterns:**
Private key PEM blocks, hardcoded password assignments, high-entropy strings (>4.5 bits/char) in key/token/secret variable names

---

### 4.2 Hybrid SAST Engine

**File:** `src/checkers/hybrid-sast.ts`

**3-Pass Architecture:**

| Pass | Speed | Method | Offline |
|---|---|---|---|
| Pass 1 — Regex | ~5ms | Deterministic patterns | ✅ Yes |
| Pass 2 — LLM Deep | 2–5s | Semantic analysis with 20-line context | ❌ Needs LLM |
| Pass 3 — Adversarial | 2–5s | LLM argues against its own findings | ❌ Needs LLM |

**Vulnerability Categories (Pass 1):**

| Category | Rule IDs | Languages |
|---|---|---|
| SQL Injection | `CG_SQLI_001–005` | JS, TS, Python, Java, PHP |
| XSS | `CG_XSS_001–004` | JS, TS, HTML |
| Command Injection | `CG_CMD_001–005` | JS, Python, Go |
| Path Traversal | `CG_PATH_001–003` | JS, Python, Go, Java |
| Insecure Deserialization | `CG_DESER_001–007` | Python, Java, PHP, Ruby, .NET |
| SSRF | `CG_SSRF_001–003` | JS, Python, Go |
| JWT Vulnerabilities | `CG_AUTH_001–005` | JS, TS, Python |
| Prototype Pollution | `CG_PROTO_001–003` | JS, TS |
| XXE | `CG_XXE_001–002` | Java, Python |
| CORS Wildcard | `CG_CORS_001` | JS, TS |
| Open Redirect | `CG_REDIR_001–002` | JS, Python, Go |
| Mass Assignment | `CG_MASS_001–003` | JS (Express), Python (Flask/Django) |

Pass 3 reduces false positives by ~40% vs regex-only scanning.

---

### 4.3 CVE / Vulnerability Scanner

**Files:** `src/checkers/osv.ts`, `src/checkers/version-resolver.ts`  
**Sources:** OSV.dev API, GitHub Advisory Database (GHSA)

**Supported Ecosystems:** npm, PyPI, Go modules, Cargo (Rust), Maven (Java), NuGet (.NET)

**Process:** Parse manifest → resolve version ranges → batch query OSV.dev → display per-import diagnostic with CVE ID, CVSS, severity, and one-click safe upgrade version.

---

### 4.4 API Security Scanner

**File:** `src/checkers/api-security-scanner.ts`

**JWT Rules:** `alg:none` (CRITICAL), weak secret (CRITICAL), missing `expiresIn` (HIGH), `jwt.decode` without verify (CRITICAL), algorithm confusion (HIGH), Python `verify_signature: False` (CRITICAL)

**GraphQL Rules:** Introspection in prod (HIGH), playground enabled (MEDIUM), no depth/complexity limit (HIGH)

**Deserialization Rules:** `pickle.load/loads`, `yaml.load` unsafe, Java `ObjectInputStream`, PHP `unserialize`, `node-serialize`, .NET `BinaryFormatter`, Ruby `Marshal.load` — all CRITICAL

**API Design Flaws (OWASP API Top 10:2023):**

| Rule | OWASP | Finding | Severity |
|---|---|---|---|
| `CG_API_001` | API1 | BOLA — resource access without ownership check | HIGH |
| `CG_API_002` | API3 | `Object.assign(user, req.body)` | CRITICAL |
| `CG_API_003` | API3 | `new Model(req.body)` without whitelist | HIGH |
| `CG_API_005` | API7 | CORS wildcard `*` | HIGH |
| `CG_API_006` | API7 | Open redirect via `res.redirect(req.query.url)` | HIGH |
| `CG_API_007` | API7 | Session cookie without `secure` flag | HIGH |

---

### 4.5 License Compliance Engine

**File:** `src/checkers/license-compliance.ts`

**License Categories:** `permissive` (MIT, Apache-2.0) → `weak-copyleft` (LGPL, MPL) → `strong-copyleft` (GPL) → `network-copyleft` (AGPL) → `commercial-restricted` (SSPL, BUSL, Elastic) → `unknown`

**Key Rules:**

| Rule | Condition | Severity |
|---|---|---|
| `LIC_001` | GPL/AGPL in proprietary project | CRITICAL |
| `LIC_002` | SSPL/BUSL in commercial SaaS | CRITICAL |
| `LIC_003` | Unknown or missing license | HIGH |
| `LIC_004` | Copyleft in Apache-2.0 project | HIGH |
| `LIC_006` | Network copyleft (AGPL) in web service | HIGH |

Configurable via `.codeguard/policy.json` `"licenses"` block with `allowList`, `blockList`, `projectLicense`.

---

### 4.6 Hallucination Scanner

**File:** `src/checkers/hallucination.ts`

Per import statement: check standard library → check GHIN local DB → check registry cache → query npm/PyPI → flag if package not found.

18 known hallucinated packages bundled locally (including `starlette-reverse-proxy`, `dotenv-safe-config`, `express-rate-limiter-plus`, `jsonwebtoken-secure`, etc.)

---

## 5. Supply Chain Intelligence

### 5.1 GHIN Network

**Files:** `src/intelligence/ghin.ts`, `src/intelligence/ghin-client.ts`

Crowdsourced + AI-curated database of 500,000+ packages that AI assistants have hallucinated. Updated every 24 hours when online. Contains: package name, ecosystem, first hallucination date, report count, confidence score, AI models known to hallucinate it.

---

### 5.2 Trust Score Engine

**File:** `src/intelligence/trust-score.ts`

Composite 0–100 score from weighted signals:

| Signal | Weight |
|---|---|
| Package exists on registry | 25% |
| Download count (last 30 days) | 15% |
| Public repository exists | 10% |
| Repository age >1 year | 10% |
| Sigstore provenance attestation | 15% |
| Not in GHIN hallucination DB | 20% |
| Maintainer reputation score | 5% |

**Verdicts:** 80–100 `trusted` → 60–79 `caution` → 40–59 `suspect` → 0–39 `untrusted`

---

### 5.3 Maintainer Reputation Tracker

**File:** `src/intelligence/maintainer-reputation.ts`

7 scored signals queried from public npm/PyPI registry (no API key needed):

| Signal | Risk |
|---|---|
| Account created <30 days ago | CRITICAL |
| Account created <1 year ago | HIGH |
| New maintainer added in last 30 days | HIGH |
| Publisher ≠ historical publisher | HIGH |
| Disposable email domain | HIGH |
| 2FA not enforced (npm) | MEDIUM |
| No verified GitHub account | LOW |

Inspired by the 2024 event-stream incident (malicious maintainer handover).

---

### 5.4 Publish Anomaly Detector

**File:** `src/intelligence/publish-anomaly.ts`

| Rule | Anomaly Detected |
|---|---|
| `PA_001` | Version numbers jump backward after a long gap |
| `PA_002` | 5+ versions published within 24 hours (burst) |
| `PA_003` | 2+ year dormancy then sudden re-activation |
| `PA_004` | Version gap attack (v1.0.0 → v1.99.0) |
| `PA_005` | alpha/beta promoted directly to stable without RC |
| `PA_006` | Same maintainer publishes 10+ packages within 1 hour |

---

### 5.5 Provenance Checker

**File:** `src/checkers/provenance.ts`

Verifies Sigstore/Rekor cryptographic provenance for npm packages. Checks SLSA build level and that build was triggered from the declared GitHub repository. Missing provenance = low/medium warning (not a blocking error — most pre-2023 packages predate Sigstore).

---

## 6. AI Shield Layer

### 6.1 Rules File Scanner — `src/shield/rules-scanner.ts`
Scans `.cursorrules`, `.windsurfrules`, `CLAUDE.md`, `copilot-instructions.md` for jailbreak patterns, hardcoded secrets, external URLs, hidden binary content, and oversized files.

### 6.2 Install Gate — `src/shield/install-gate.ts`
Monitors VS Code terminals for `npm install`, `pip install`, `yarn add`, `pnpm add`. Before the command executes, runs GHIN + CVE + Trust Score + Typosquat + Maintainer + Publish Anomaly checks. Shows risk warning dialog — user can confirm or cancel.

### 6.3 Script Analyzer — `src/shield/script-analyzer.ts`
Deep inspection of `package.json` lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`): detects `curl|sh`, `wget|bash`, miner invocations, `base64|eval` chains, file writes to sensitive paths (`/etc/`, `~/.ssh/`), environment variable exfiltration. Any network-download-and-execute → auto-CRITICAL.

### 6.4 Shadow AI Discovery — `src/shield/shadow-ai-discovery.ts`
Discovers AI components in the project the security team may not know about: scans `package.json`/`requirements.txt` for AI libraries, detects AI config files (`.openai`, Ollama configs), identifies AI API endpoints in source code, generates an **AI-SBOM** in CycloneDX format.

### 6.5 Sandbox Runner — `src/shield/sandbox-runner.ts`
Runs suspicious scripts in a constrained Node.js `vm` sandbox with resource limits and network interception to safely analyze behavior before it touches the real file system.

### 6.6 Permission Model — `src/shield/permission-model.ts`
Manages workspace trust levels, controls which engines can make outbound requests, rate-limits API calls, manages user consent for telemetry and remote intelligence sync.

---

## 7. AI Integration Layer

### 7.1 Chat Participant (@codeguard) — `src/ai/chat-participant.ts`
Type `@codeguard [question]` in Copilot Chat (requires VS Code 1.93+ + GitHub Copilot Chat):
- `@codeguard is this code safe?` — analyzes selection
- `@codeguard what CVEs affect my dependencies?` — queries CVE DB
- `@codeguard how do I fix this?` — returns specific remediation

### 7.2 LLM Advisor — `src/ai/llm-advisor.ts`
Powers the "Ask AI to Fix" code action. Sends vulnerable code + finding context to the configured LLM backend and returns a safe replacement snippet as a one-click VS Code code action.

**Supported backends:** GitHub Copilot, Ollama (local/offline), OpenAI API, Anthropic API.

### 7.3 Intent Verifier — `src/ai/intent-verifier.ts`
Completion middleware intercepting AI suggestions. Runs a fast Pass 1 scan on suggested code before insertion. If issues found, annotates with a non-blocking warning decoration.

### 7.4 Patch Agent — `src/ai/patch-agent.ts`
Autonomous agent: identifies all vulnerable dependencies → looks up safe versions via OSV.dev → drafts an upgrade commit → creates PR description with full CVE details.  
**Triggered by:** `CodeGuard: Auto-Patch All Vulnerabilities`

### 7.5 Code Attribution Engine — `src/ai/code-attribution.ts`
Detects and marks AI-generated code blocks. Attribution context is consumed by the SBOM generator to record AI code provenance in the CycloneDX output.

### 7.6 Auto-Patch Engine — `src/checkers/auto-patch.ts`
For every CVE found: provides safe upgrade version, patch command (`npm install pkg@2.1.3`), alternatives for abandoned packages, and a human+AI-readable fix description. Sources: OSV.dev, GHSA, npm audit, PyPI Advisory.

---

## 8. IDE Integration

### 8.1 Real-Time Diagnostics — `src/diagnostics/provider.ts`
Triggered on file open, save, text change (debounced 300ms). Displays in Problems panel + inline squiggles. Severity mapping: CRITICAL/HIGH → error (red), MEDIUM → warning (yellow), LOW → info (blue). Source labels: `CodeGuard AI (Secrets)`, `CodeGuard Hybrid SAST (regex)`, `CodeGuard MCP Scanner`, etc.

### 8.2 CodeLens — `src/ai/feedback.ts`
Inline lenses above vulnerable lines: `🔒 1 security issue`, `⚠️ 3 CVEs in dependency`, `🤖 Ask AI to fix →`

### 8.3 Hover Provider — `src/ui/hover.ts`
Hover any flagged import/expression → full finding details: severity badge, CVE CVSS score, affected versions, remediation steps, "Ask AI to Fix" command link.

### 8.4 Status Bar — `src/ui/statusbar.ts`
Persistent indicator: `🛡️ 0 issues` (green) / `⚠️ 3 HIGH` (orange) / `🔴 1 CRITICAL` (red). Click → opens Problems panel.

### 8.5 Trust Tree View — `src/ui/trust-tree.ts`
Sidebar tree of all dependencies with per-package trust score, CVE count, hallucination status, maintainer score. Color-coded green → yellow → orange → red.

### 8.6 Findings Tree View — `src/ui/findings-tree.ts`
Sidebar tree of all findings organized by severity, by engine, or by file. Click → jumps to exact line.

### 8.7 Code Actions — `src/diagnostics/codeactions.ts`
Right-click any finding → lightbulb menu: **Ask AI to Fix**, **View in Dashboard**, **Copy Fix Command**, **Mark as False Positive**, **View CVE Details** (opens NVD).

---

## 9. Reporting & Compliance

### 9.1 SBOM Generator — `src/sbom/generator.ts`
**Format:** CycloneDX JSON (OWASP standard). Captures all direct + transitive dependencies, CVE findings, trust scores, AI-generated code components, license info, and Sigstore provenance status.  
**Command:** `CodeGuard: Export AI-Aware SBOM` → `codeguard-sbom.cdx.json`

### 9.2 SBOM Drift Detector — `src/sbom/drift.ts`
Compares current SBOM against a baseline: new/removed packages, version changes, new CVEs introduced, trust score changes. Used in CI to detect unintended dependency changes between PRs.

### 9.3 Compliance Report Generator — `src/reports/compliance.ts`

**Framework Coverage:**

| Framework | Mapped Controls |
|---|---|
| SOC2 Type II | CC6.1, CC6.6, CC7.1, CC7.2, CC8.1 |
| PCI-DSS v4 | Req 6.2, 6.3, 6.4, 11.3 |
| HIPAA | §164.312(a)(1), §164.312(b), §164.314 |
| NIST CSF | ID.SC-2, PR.DS-6, DE.CM-3 |
| OWASP Top 10 | All 10 categories |
| OWASP LLM Top 10 | LLM01–LLM10 |

**Output formats:** JSON, Markdown, CSV

### 9.4 Security Score Engine — `src/scoring/security-score.ts`
0–100 composite score: -20 per critical (cap -60), -5 per high (cap -30), dependency trust average (20%), secrets exposure (-15 each), license compliance (10%), MCP safety (10%), +5 for SBOM, +5 for provenance.

### 9.5 Score History — `src/scoring/score-history.ts`
Time-series of scores stored in `.codeguard/score-history.json`. Shows trend (improving/degrading) in status bar and dashboard. Exported as part of compliance reports.

---

## 10. Policy Engine

**File:** `src/policy/engine.ts` | **Config:** `.codeguard/policy.json`

```json
{
  "version": "1.0",
  "risk": {
    "failOn": ["critical", "high"],
    "blockInstall": true,
    "maxRiskScore": 30
  },
  "licenses": {
    "allowList": ["MIT", "Apache-2.0", "BSD-2-Clause"],
    "blockList": ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"],
    "projectLicense": "MIT"
  },
  "engines": {
    "jailbreak": true,
    "mcp": true,
    "mlModel": true,
    "iac": true,
    "cryptojacking": true,
    "apiSec": true
  },
  "suppressions": [
    {
      "ruleId": "CG_CORS_001",
      "path": "src/test/*",
      "reason": "Test server only"
    }
  ],
  "telemetry": { "enabled": false }
}
```

---

## 11. Platform Components

### 11.1 VS Code / Windsurf / Cursor Extension
- **Package:** `codeguard-ai-8.0.0.vsix` (544 KB)
- **Requirement:** VS Code / Windsurf / Cursor ≥ 1.85.0
- **Install:** `windsurf --install-extension codeguard-ai-8.0.0.vsix`
- **Build:** `npm run compile` then `npx @vscode/vsce package --no-dependencies`

### 11.2 CLI Tool — `cli/`
```bash
codeguard scan                        # scan current directory
codeguard scan --format sarif         # SARIF (GitHub Code Scanning)
codeguard scan --fail-on critical     # exit 1 if criticals found
codeguard sbom                        # generate SBOM
codeguard report --framework soc2     # compliance report
```

### 11.3 GitHub Action — `cli/action.yml`
```yaml
- uses: codeguard-ai/security-scan@v8
  with:
    token: ${{ secrets.CODEGUARD_TOKEN }}
    fail-on: critical,high
    upload-sarif: true  # uploads to GitHub Security tab
```
Outputs: `critical-count`, `high-count`, `score`, `report-path`

### 11.4 Web Backend — `backend/`
**Stack:** Node.js + Express + TypeScript + Prisma + PostgreSQL + Docker

**Key API Endpoints:**

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/auth/register` | User registration |
| `POST` | `/api/auth/login` | JWT login |
| `GET` | `/api/packages/check` | Package safety check |
| `GET` | `/api/hallucinations` | Query GHIN database |
| `POST` | `/api/scans` | Submit scan result |
| `GET` | `/api/teams/:id/dashboard` | Team dashboard data |
| `PUT` | `/api/policies/:teamId` | Update team policy |

**Database Models:** `User`, `Team`, `ScanResult`, `Finding`, `Policy`, `HallucinationEntry`, `TrustScore`

### 11.5 Frontend Dashboard — `frontend/`
**Stack:** Next.js + React + TailwindCSS + shadcn/ui

**Pages:** `/dashboard` (overview + trend chart), `/findings` (filterable table), `/dependencies` (trust tree), `/mcp` (MCP inventory), `/sbom` (viewer + export), `/reports` (compliance), `/settings` (policy config), `/team` (management)

---

## 12. Language Support

| Engine | JS/TS | Python | Go | Java | Rust | C# | PHP | Ruby |
|---|---|---|---|---|---|---|---|---|
| Secrets Scanner | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SAST Regex | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ |
| SAST LLM | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| CVE Scanner | npm | PyPI | go.mod | Maven | Cargo | NuGet | — | — |
| Hallucination | ✅ | ✅ | — | — | — | — | — | — |
| API Security | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ |
| License | npm | PyPI | — | — | — | — | — | — |
| IaC | Dockerfile + K8s + Terraform | — | — | — | — | — | — | — |
| ML Model | ✅ (code) | ✅ (code + files) | — | — | — | — | — | — |
| Cryptojacking | ✅ | ✅ | — | — | — | — | — | — |

---

## 13. Security Standards Coverage

### OWASP Top 10:2021

| OWASP | Category | Engines |
|---|---|---|
| A01 | Broken Access Control | SAST (BOLA/IDOR), API Security |
| A02 | Cryptographic Failures | Secrets Scanner, SAST |
| A03 | Injection | Hybrid SAST, Taint Tracker |
| A04 | Insecure Design | SAST (mass assignment) |
| A05 | Security Misconfiguration | IaC Scanner, API Security (CORS) |
| A06 | Vulnerable Components | CVE Scanner, Trust Score |
| A07 | Auth & Session Failures | API Security (JWT), SAST |
| A08 | Software & Data Integrity | Provenance Checker, SBOM |
| A09 | Logging & Monitoring | Policy Engine |
| A10 | SSRF | Hybrid SAST |

### OWASP LLM Top 10:2025

| LLM# | Category | Engine |
|---|---|---|
| LLM01 | Prompt Injection | Jailbreak Scanner |
| LLM02 | Sensitive Info Disclosure | Secrets Scanner, Rules Scanner |
| LLM03 | Supply Chain | GHIN, Provenance, Trust Score |
| LLM04 | Data & Model Poisoning | ML Model File Scanner |
| LLM06 | Excessive Agency | MCP Scanner (permission analysis) |
| LLM07 | System Prompt Leakage | Jailbreak Scanner (CG_JB_023–026) |
| LLM09 | Misinformation | Hallucination Scanner |
| LLM10 | Unbounded Consumption | MCP Scanner, API Security (rate limit) |

### CIS Benchmarks (IaC Scanner)

| Standard | Coverage |
|---|---|
| CIS Docker 4.1 | No root USER |
| CIS Docker 4.2 | Trusted base images |
| CIS K8s 5.2.1 | No privileged containers |
| CIS K8s 5.2.2 | No hostPID |
| CIS K8s 5.2.4 | No hostNetwork |
| CIS K8s 5.2.6 | No runAsUser: 0 |

---

## 14. Configuration Reference

### VS Code Settings (`settings.json`)

```json
{
  "codeguard.enabled": true,
  "codeguard.scanOnSave": true,
  "codeguard.scanOnType": false,
  "codeguard.minimumSeverity": "medium",
  "codeguard.llmBackend": "copilot",
  "codeguard.offlineMode": false,
  "codeguard.ghinSyncInterval": 86400,
  "codeguard.trustScoreThreshold": 60,
  "codeguard.engines.jailbreak": true,
  "codeguard.engines.mcp": true,
  "codeguard.engines.mlModel": true,
  "codeguard.engines.iac": true,
  "codeguard.engines.cryptojacking": true,
  "codeguard.engines.secrets": true,
  "codeguard.engines.sast": true,
  "codeguard.engines.cve": true,
  "codeguard.engines.license": true,
  "codeguard.telemetry.enabled": false
}
```

### Environment Variables

| Variable | Used By | Description |
|---|---|---|
| `OPENAI_API_KEY` | LLM Advisor | OpenAI backend for AI fix suggestions |
| `ANTHROPIC_API_KEY` | LLM Advisor | Anthropic Claude backend |
| `CODEGUARD_TOKEN` | GitHub Action | API token for cloud intelligence |
| `DATABASE_URL` | Backend | PostgreSQL connection string |
| `JWT_SECRET` | Backend | JWT signing secret |

---

## 15. All VS Code Commands

Access via `Ctrl+Shift+P` → type `CodeGuard`:

| Command | Description |
|---|---|
| `CodeGuard: Scan Current File` | Immediately scan the active file |
| `CodeGuard: Scan Workspace Dependencies` | Full dependency audit |
| `CodeGuard: Show Security Dashboard` | Open the webview dashboard |
| `CodeGuard: Ask AI to Fix` | Invoke LLM Advisor on current finding |
| `CodeGuard: Clear Vulnerability Cache` | Force-refresh all cached CVE data |
| `CodeGuard: Export AI-Aware SBOM` | Generate CycloneDX SBOM |
| `CodeGuard: Scan MCP Servers` | Run MCP CVE + behavioral scan |
| `CodeGuard: Discover Shadow AI` | Find undeclared AI components |
| `CodeGuard: View Security Score` | Show current score + history |
| `CodeGuard: Generate Compliance Report` | Export SOC2/PCI/HIPAA report |
| `CodeGuard: Auto-Patch All Vulnerabilities` | Launch patch agent |
| `CodeGuard v8: Scan for Jailbreaks` | Workspace-wide jailbreak scan |
| `CodeGuard v8: Scan ML Model Files` | Pickle/ONNX/Keras exploit scan |
| `CodeGuard v8: Check Typosquat` | Check current package for typosquat |
| `CodeGuard v8: Scan for Cryptojacking` | Cryptominer pattern scan |
| `CodeGuard v8: Check License Compliance` | License audit against policy |
| `CodeGuard v8: Scan IaC Files` | Docker/K8s/Terraform audit |
| `CodeGuard v8: Comprehensive Scan` | All v8.0 engines in one pass |
| `CodeGuard v8: Show Engine Statistics` | Print stats for all 12 engines |

---

*CodeGuard AI v8.0.0 — Built for the AI development era.*
