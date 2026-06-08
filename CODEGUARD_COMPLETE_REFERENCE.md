# CodeGuard AI — Complete Technical Reference

**Version:** 9.0.0 | **Coverage:** Every module, engine, rule, integration, and configuration

> **What's new in v9.0:** Agentic AI Security Scanner (OWASP ASI01–ASI08), Vibe Code Security Analyzer (22 rules + security debt scoring), 75+ secret patterns (Gemini #1 most-leaked key), and full Admin Dashboard with .env-based credentials.

---

## Table of Contents

1. [What Is CodeGuard AI](#1-what-is-codeguard-ai)
2. [System Architecture](#2-system-architecture)
3. [Agentic AI Security Engines (v9.0)](#3-agentic-ai-security-engines-v90) ⭐ NEW
4. [AI-Era Detection Engines (v8.0)](#4-ai-era-detection-engines-v80)
5. [Core Security Engines](#5-core-security-engines)
6. [Supply Chain Intelligence](#6-supply-chain-intelligence)
7. [AI Shield Layer](#7-ai-shield-layer)
8. [AI Integration Layer](#8-ai-integration-layer)
9. [IDE Integration](#9-ide-integration)
10. [Reporting & Compliance](#10-reporting--compliance)
11. [Policy Engine](#11-policy-engine)
12. [Platform Components](#12-platform-components)
13. [Admin Dashboard & Backend](#13-admin-dashboard--backend) ⭐ NEW
14. [Language Support](#14-language-support)
15. [Security Standards Coverage](#15-security-standards-coverage)
16. [Configuration Reference](#16-configuration-reference)
17. [All VS Code Commands](#17-all-vs-code-commands)

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
| Hardcoded OpenAI/AWS key | Partial | ✅ 75+ AI/cloud provider patterns |
| Agentic AI memory poisoning | ❌ | ✅ OWASP ASI06 — RAG/vector store injection |
| Wildcard tool permissions in agents | ❌ | ✅ OWASP ASI03 — privilege escalation |
| Vibe-coded app security debt | ❌ | ✅ 22 rules, 0–100 security debt score |
| Missing auth in AI-generated routes | ❌ | ✅ Vibe Code Analyzer — Georgia Tech #1 gap |
| SQL injection | ✅ | ✅ + LLM adversarial verification |
| GPL license in proprietary project | ❌ | ✅ SPDX-aware compliance engine |

---

## 2. System Architecture

### Module Map

| Directory | Files | Responsibility |
|---|---|---|
| `src/checkers/` | 19 | All detection engines (SAST, secrets, CVE, license, IaC, agentic, vibe-code) |
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
| `backend/src/routes/auth.ts` | — | Auth routes incl. `POST /api/auth/admin/login` |
| `frontend/src/pages/AdminDashboard.tsx` | — | Admin-only system overview page |

### Detection Flow

```
File saved / pasted
       ↓
DocumentWatcher (src/watcher.ts)
       ↓ triggers each engine in parallel
┌──────────────────────────────────────────────────────────┐
│  Secrets │ SAST-Regex │ CVE  │ Hallucination             │
│  MCP     │ Jailbreak  │ IaC  │ Cryptojacking             │
│  License │ API-Sec    │ ML   │ Typosquat                 │
│  Agentic Security (v9) │ Vibe Code Analyzer (v9)        │
└───────────────────────┬──────────────────────────────────┘
                        ↓
              DiagnosticsProvider
                        ↓
          VS Code Problems Panel + Squiggles
```

---

## 3. Agentic AI Security Engines (v9.0)

### 3.1 Agentic AI Security Scanner

**File:** `src/checkers/agentic-security-scanner.ts` | **Standard:** OWASP Agentic Application Top 10 (ASI01–ASI08)

**Research basis:** OWASP published the Agentic Application Top 10 in 2026. BeyondScale research showed 80%+ attack success rates for memory poisoning. This scanner is the first IDE-integrated tool targeting these threats.

**Scanned files:** `agent.json`, `claude-code-config.json`, `*.agent.ts`, `*.agent.py`, LangGraph/AutoGen/CrewAI config files, `.agent/` directories, any source file using agentic framework APIs.

**18 Rules across 8 OWASP ASI categories:**

| Rule ID | Category | OWASP ASI | Severity | What It Flags |
|---|---|---|---|---|
| `CG_AGT_001` | Memory Poisoning | ASI06 | CRITICAL | Unsanitized user input flowing to vector store / RAG memory |
| `CG_AGT_002` | Memory Poisoning | ASI06 | CRITICAL | Instruction override directives in agent memory fields (`ignore previous`, `new directive`) |
| `CG_AGT_003` | Memory Poisoning | ASI06 | HIGH | Direct object assignment from external source to memory context |
| `CG_AGT_010` | Tool Misuse | ASI03 | CRITICAL | Wildcard permissions `"permissions": ["*"]` |
| `CG_AGT_011` | Tool Misuse | ASI03 | CRITICAL | Unrestricted shell access `"allow_shell": true` |
| `CG_AGT_012` | Tool Misuse | ASI03 | HIGH | Unbounded iteration / recursion limit (`max_iterations: 0` or absent) |
| `CG_AGT_020` | Confused Deputy | ASI04 | CRITICAL | System prompt concatenated directly with user input |
| `CG_AGT_021` | Confused Deputy | ASI04 | HIGH | `trust_level: high` assigned to external / user sources |
| `CG_AGT_030` | Agent Injection | ASI07 | CRITICAL | CrewAI/LangGraph agent with no delegation constraints |
| `CG_AGT_031` | Agent Injection | ASI07 | HIGH | AutoGen multi-agent with unconstrained message propagation |
| `CG_AGT_040` | Missing HITL | ASI01 | CRITICAL | `human_in_the_loop: false` + `auto_execute: true` together |
| `CG_AGT_041` | Missing HITL | ASI01 | HIGH | Destructive operations (`delete`, `drop`, `truncate`) in allowed actions without confirmation gate |
| `CG_AGT_050` | Tool Registration | ASI08 | CRITICAL | Tool loaded from raw GitHub URL, ngrok, pastebin, or URL shortener |
| `CG_AGT_051` | Tool Registration | ASI08 | HIGH | Dynamic tool loading without integrity hash check |
| `CG_AGT_060` | Context Leak | ASI02 | HIGH | Debug scratchpad or full agent context written to logs |
| `CG_AGT_061` | Context Leak | ASI02 | MEDIUM | `verbose_logging: true` or `log_full_context: true` in agent config |
| `CG_AGT_070` | Privilege Escalation | ASI03 | CRITICAL | Agent granted file system write + network access + code execution simultaneously |
| `CG_AGT_080` | Autonomous Destructive | ASI01 | CRITICAL | `rm -rf`, `DROP TABLE`, `DELETE FROM` in agent allowed-operations list without `require_confirmation` |

**Framework detection:** AutoGen, CrewAI, LangGraph, OpenAI Agents SDK, Anthropic Computer Use — flagged for security review when detected.

**VS Code Command:** `CodeGuard v9: Scan for Agentic AI Security Issues (OWASP ASI)` → workspace scan with OWASP ASI coverage report in webview panel.

---

### 3.2 Vibe Code Security Analyzer

**File:** `src/checkers/vibe-code-analyzer.ts` | **Standard:** OWASP API Top 10:2023, Georgia Tech Vibe Security Radar

**Research basis:** Veracode 2026 — 45% of LLMs produce insecure code on security-sensitive tasks. Wiz — 400 exposed secrets in 5,600 vibe-coded apps. Georgia Tech — 74 real CVEs in AI-generated code Q1 2026. 78% of `// TODO: add auth` comments never fixed before deploy.

**22 Rules across 13 anti-pattern categories:**

| Rule ID | Category | Severity | Pattern Detected | Common Generator |
|---|---|---|---|---|
| `CG_VIBE_001` | Missing Auth | CRITICAL | Route handler without any auth middleware | All AI coding assistants |
| `CG_VIBE_002` | Missing Auth | HIGH | `app.get/post/put/delete` without `authenticate`/`requireAuth` call | Copilot, Cursor |
| `CG_VIBE_010` | Missing Validation | HIGH | `req.body` used directly without schema validation (no zod/joi/yup) | All AI scaffolding |
| `CG_VIBE_011` | Missing Validation | HIGH | User input passed to DB query without sanitization | ChatGPT, Copilot |
| `CG_VIBE_020` | Missing Rate Limit | HIGH | Auth/login endpoint without `rateLimit` middleware | All AI assistants |
| `CG_VIBE_030` | Missing CSRF | MEDIUM | Express POST route without CSRF token validation | All AI assistants |
| `CG_VIBE_040` | CORS Wildcard | HIGH | `cors({ origin: "*" })` — universal AI boilerplate default | **ALL AI tools** |
| `CG_VIBE_041` | CORS Wildcard | HIGH | `Access-Control-Allow-Origin: *` in response headers | All AI tools |
| `CG_VIBE_050` | SQL Injection | CRITICAL | SQL built with template literal / f-string containing variable | All AI tutorial code |
| `CG_VIBE_051` | SQL Injection | CRITICAL | `db.query("SELECT..." + variable)` concatenation | All AI tools |
| `CG_VIBE_060` | IDOR | HIGH | `findById(req.params.id)` without ownership/authorization check | All CRUD generators |
| `CG_VIBE_070` | Frontend Secrets | CRITICAL | `NEXT_PUBLIC_`, `REACT_APP_`, `VITE_` prefix on API key variable | Bolt.new, Lovable, v0 |
| `CG_VIBE_071` | Frontend Secrets | CRITICAL | Hardcoded API key string in JavaScript/TypeScript source | All AI tools |
| `CG_VIBE_080` | Debug Leak | HIGH | `console.log` / `print` of password, token, secret, or key | All AI tools |
| `CG_VIBE_090` | JWT Weak Secret | CRITICAL | `jwt.sign({}, "secret"\|"mysecret"\|"changeme"\|"password")` | All AI auth scaffolding |
| `CG_VIBE_091` | JWT No Expiry | HIGH | `jwt.sign({}, secret)` without `expiresIn` option | All AI auth scaffolding |
| `CG_VIBE_100` | Missing HTTPS | MEDIUM | Express app without HTTPS enforcement or HSTS header | All AI scaffolding |
| `CG_VIBE_110` | Security Debt | HIGH | `// TODO.*auth\|// TODO.*security\|// TODO.*validate` comment | All AI coding assistants |
| `CG_VIBE_111` | Security Debt | MEDIUM | `// FIXME.*security\|// HACK.*auth` | All AI coding assistants |
| `CG_VIBE_120` | Insecure Cookie | HIGH | `res.cookie(...)` without `httpOnly: true` or `secure: true` | All AI scaffolding |
| `CG_VIBE_130` | Missing Error Handling | MEDIUM | Async route without try/catch → unhandled rejection leaks stack trace | All AI code generators |
| `CG_VIBE_140` | Prototype Pollution | HIGH | `Object.assign(target, req.body)` without prototype check | Copilot, ChatGPT |

**Security Debt Scoring (0–100 composite per file):**

| Score | Verdict | Action |
|---|---|---|
| 70–100 | 🔴 CRITICAL debt — do not deploy | Block PR, require full security review |
| 40–69 | 🟠 HIGH debt — immediate remediation required | Fix before merge |
| 20–39 | 🟡 MEDIUM debt — fix before production | Schedule remediation |
| 0–19 | 🟢 LOW — minor improvements | Optional improvement |

**AI Tool Attribution:** Each finding identifies which AI tool commonly generates it (`"All AI coding assistants — universal pattern"`, `"Bolt.new, Lovable, v0 — vibe-coding platforms"`, etc.).

**VS Code Command:** `CodeGuard v9: Analyze Vibe Code Security (AI Anti-patterns)` → per-file debt score + attribution report.

---

## 4. AI-Era Detection Engines (v8.0)

### 4.1 LLM Jailbreak & Prompt Injection Scanner

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

### 4.2 MCP CVE Database Scanner

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

### 4.3 MCP Behavioral Scanner

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

### 4.4 ML Model File Exploit Scanner

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

### 4.5 Enhanced Typosquat Detector

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

### 4.6 Cryptojacking Scanner

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

## 5. Core Security Engines

### 5.1 Secrets & Credentials Checker (75+ patterns — expanded in v9.0)

**File:** `src/checkers/secrets-checker.ts`

**AI Provider Keys (v9.0 additions marked ⭐):**

| Provider | Pattern | Severity | v9 Note |
|---|---|---|---|
| OpenAI | `sk-proj-*` / `sk-[a-zA-Z0-9]{48}` | CRITICAL | — |
| Anthropic | `sk-ant-api03-*` / `sk-ant-api0[4-9]-*` ⭐ | CRITICAL | Updated format |
| Google Gemini / AI Studio ⭐ | `AIza[0-9A-Za-z\-_]{35}` | CRITICAL | **#1 most leaked AI key — 72% of all leaks** |
| ElevenLabs ⭐ | `xi-api-key` context pattern | CRITICAL | **#3 most leaked — 8% of all leaks** |
| OpenRouter ⭐ | `sk-or-v1-[A-Za-z0-9]{64}` | CRITICAL | Proxies all LLM providers |
| HuggingFace | `hf_[A-Za-z0-9]{34}` | CRITICAL | — |
| Replicate | `r8_[a-zA-Z0-9]{40}` | CRITICAL | — |
| Groq | `gsk_[a-zA-Z0-9]{52}` | CRITICAL | — |
| Mistral | Context pattern | HIGH | — |
| Perplexity | `pplx-[0-9a-f]{48}` | HIGH | — |
| xAI / Grok | `xai-[a-zA-Z0-9]{80}` | HIGH | — |
| DeepSeek | Context pattern | HIGH | — |
| Nvidia NIM ⭐ | `nvapi-[a-zA-Z0-9\-_]{82}` | CRITICAL | Enterprise AI inference |
| Vercel AI / v0 ⭐ | Context pattern | HIGH | Vibe-coding platform |
| Stability AI ⭐ | `sk-[A-Za-z0-9]{48,56}` | HIGH | Image diffusion API |
| Cerebras AI ⭐ | `csk-[a-zA-Z0-9]{56}` | HIGH | Fast inference |
| SambaNova ⭐ | Context pattern | HIGH | Enterprise AI |
| Meta Llama / Meta AI ⭐ | Context pattern | HIGH | Open-weight API |
| Supabase Service Role ⭐ | `eyJ...` JWT + supabase context | CRITICAL | **Bypasses Row Level Security — full DB access** |
| Supabase Anon Key ⭐ | `eyJ...` JWT + supabase context | HIGH | RLS bypass warning |
| LangSmith | `lsv2_pt_[a-f0-9]{32}` | HIGH | — |
| Cohere | `[a-zA-Z0-9]{40}` context | HIGH | — |
| Pinecone | Context pattern | HIGH | — |
| Fireworks AI | `fw_[a-zA-Z0-9]{24}` | HIGH | — |
| Together AI | Context pattern | HIGH | — |

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

### 5.2 Hybrid SAST Engine

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

### 5.3 CVE / Vulnerability Scanner

**Files:** `src/checkers/osv.ts`, `src/checkers/version-resolver.ts`  
**Sources:** OSV.dev API, GitHub Advisory Database (GHSA)

**Supported Ecosystems:** npm, PyPI, Go modules, Cargo (Rust), Maven (Java), NuGet (.NET)

**Process:** Parse manifest → resolve version ranges → batch query OSV.dev → display per-import diagnostic with CVE ID, CVSS, severity, and one-click safe upgrade version.

---

### 5.4 API Security Scanner

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

### 5.5 License Compliance Engine

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

### 5.6 Hallucination Scanner

**File:** `src/checkers/hallucination.ts`

Per import statement: check standard library → check GHIN local DB → check registry cache → query npm/PyPI → flag if package not found.

18 known hallucinated packages bundled locally (including `starlette-reverse-proxy`, `dotenv-safe-config`, `express-rate-limiter-plus`, `jsonwebtoken-secure`, etc.)

---

## 6. Supply Chain Intelligence

### 6.1 GHIN Network

**Files:** `src/intelligence/ghin.ts`, `src/intelligence/ghin-client.ts`

Crowdsourced + AI-curated database of 500,000+ packages that AI assistants have hallucinated. Updated every 24 hours when online. Contains: package name, ecosystem, first hallucination date, report count, confidence score, AI models known to hallucinate it.

---

### 6.2 Trust Score Engine

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

### 6.3 Maintainer Reputation Tracker

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

### 6.4 Publish Anomaly Detector

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

### 6.5 Provenance Checker

**File:** `src/checkers/provenance.ts`

Verifies Sigstore/Rekor cryptographic provenance for npm packages. Checks SLSA build level and that build was triggered from the declared GitHub repository. Missing provenance = low/medium warning (not a blocking error — most pre-2023 packages predate Sigstore).

---

## 7. AI Shield Layer

### 7.1 Rules File Scanner — `src/shield/rules-scanner.ts`
Scans `.cursorrules`, `.windsurfrules`, `CLAUDE.md`, `copilot-instructions.md` for jailbreak patterns, hardcoded secrets, external URLs, hidden binary content, and oversized files.

### 7.2 Install Gate — `src/shield/install-gate.ts`
Monitors VS Code terminals for `npm install`, `pip install`, `yarn add`, `pnpm add`. Before the command executes, runs GHIN + CVE + Trust Score + Typosquat + Maintainer + Publish Anomaly checks. Shows risk warning dialog — user can confirm or cancel.

### 7.3 Script Analyzer — `src/shield/script-analyzer.ts`
Deep inspection of `package.json` lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`): detects `curl|sh`, `wget|bash`, miner invocations, `base64|eval` chains, file writes to sensitive paths (`/etc/`, `~/.ssh/`), environment variable exfiltration. Any network-download-and-execute → auto-CRITICAL.

### 7.4 Shadow AI Discovery — `src/shield/shadow-ai-discovery.ts`
Discovers AI components in the project the security team may not know about: scans `package.json`/`requirements.txt` for AI libraries, detects AI config files (`.openai`, Ollama configs), identifies AI API endpoints in source code, generates an **AI-SBOM** in CycloneDX format.

### 7.5 Sandbox Runner — `src/shield/sandbox-runner.ts`
Runs suspicious scripts in a constrained Node.js `vm` sandbox with resource limits and network interception to safely analyze behavior before it touches the real file system.

### 7.6 Permission Model — `src/shield/permission-model.ts`
Manages workspace trust levels, controls which engines can make outbound requests, rate-limits API calls, manages user consent for telemetry and remote intelligence sync.

---

## 8. AI Integration Layer

### 8.1 Chat Participant (@codeguard) — `src/ai/chat-participant.ts`
Type `@codeguard [question]` in Copilot Chat (requires VS Code 1.93+ + GitHub Copilot Chat):
- `@codeguard is this code safe?` — analyzes selection
- `@codeguard what CVEs affect my dependencies?` — queries CVE DB
- `@codeguard how do I fix this?` — returns specific remediation

### 8.2 LLM Advisor — `src/ai/llm-advisor.ts`
Powers the "Ask AI to Fix" code action. Sends vulnerable code + finding context to the configured LLM backend and returns a safe replacement snippet as a one-click VS Code code action.

**Supported backends:** GitHub Copilot, Ollama (local/offline), OpenAI API, Anthropic API.

### 8.3 Intent Verifier — `src/ai/intent-verifier.ts`
Completion middleware intercepting AI suggestions. Runs a fast Pass 1 scan on suggested code before insertion. If issues found, annotates with a non-blocking warning decoration.

### 8.4 Patch Agent — `src/ai/patch-agent.ts`
Autonomous agent: identifies all vulnerable dependencies → looks up safe versions via OSV.dev → drafts an upgrade commit → creates PR description with full CVE details.  
**Triggered by:** `CodeGuard: Auto-Patch All Vulnerabilities`

### 8.5 Code Attribution Engine — `src/ai/code-attribution.ts`
Detects and marks AI-generated code blocks. Attribution context is consumed by the SBOM generator to record AI code provenance in the CycloneDX output.

### 8.6 Auto-Patch Engine — `src/checkers/auto-patch.ts`
For every CVE found: provides safe upgrade version, patch command (`npm install pkg@2.1.3`), alternatives for abandoned packages, and a human+AI-readable fix description. Sources: OSV.dev, GHSA, npm audit, PyPI Advisory.

---

## 9. IDE Integration

### 9.1 Real-Time Diagnostics — `src/diagnostics/provider.ts`
Triggered on file open, save, text change (debounced 300ms). Displays in Problems panel + inline squiggles. Severity mapping: CRITICAL/HIGH → error (red), MEDIUM → warning (yellow), LOW → info (blue). Source labels: `CodeGuard AI (Secrets)`, `CodeGuard Hybrid SAST (regex)`, `CodeGuard MCP Scanner`, etc.

### 9.2 CodeLens — `src/ai/feedback.ts`
Inline lenses above vulnerable lines: `🔒 1 security issue`, `⚠️ 3 CVEs in dependency`, `🤖 Ask AI to fix →`

### 9.3 Hover Provider — `src/ui/hover.ts`
Hover any flagged import/expression → full finding details: severity badge, CVE CVSS score, affected versions, remediation steps, "Ask AI to Fix" command link.

### 9.4 Status Bar — `src/ui/statusbar.ts`
Persistent indicator: `🛡️ 0 issues` (green) / `⚠️ 3 HIGH` (orange) / `🔴 1 CRITICAL` (red). Click → opens Problems panel.

### 9.5 Trust Tree View — `src/ui/trust-tree.ts`
Sidebar tree of all dependencies with per-package trust score, CVE count, hallucination status, maintainer score. Color-coded green → yellow → orange → red.

### 9.6 Findings Tree View — `src/ui/findings-tree.ts`
Sidebar tree of all findings organized by severity, by engine, or by file. Click → jumps to exact line.

### 9.7 Code Actions — `src/diagnostics/codeactions.ts`
Right-click any finding → lightbulb menu: **Ask AI to Fix**, **View in Dashboard**, **Copy Fix Command**, **Mark as False Positive**, **View CVE Details** (opens NVD).

---

## 10. Reporting & Compliance

### 10.1 SBOM Generator — `src/sbom/generator.ts`
**Format:** CycloneDX JSON (OWASP standard). Captures all direct + transitive dependencies, CVE findings, trust scores, AI-generated code components, license info, and Sigstore provenance status.  
**Command:** `CodeGuard: Export AI-Aware SBOM` → `codeguard-sbom.cdx.json`

### 10.2 SBOM Drift Detector — `src/sbom/drift.ts`
Compares current SBOM against a baseline: new/removed packages, version changes, new CVEs introduced, trust score changes. Used in CI to detect unintended dependency changes between PRs.

### 10.3 Compliance Report Generator — `src/reports/compliance.ts`

**Framework Coverage:**

| Framework | Mapped Controls |
|---|---|
| SOC2 Type II | CC6.1, CC6.6, CC7.1, CC7.2, CC8.1 |
| PCI-DSS v4 | Req 6.2, 6.3, 6.4, 11.3 |
| HIPAA | §164.312(a)(1), §164.312(b), §164.314 |
| NIST CSF | ID.SC-2, PR.DS-6, DE.CM-3 |
| OWASP Top 10 | All 10 categories |
| OWASP LLM Top 10 | LLM01–LLM10 |
| OWASP Agentic Application Top 10 | ASI01–ASI08 |

**Output formats:** JSON, Markdown, CSV

### 10.4 Security Score Engine — `src/scoring/security-score.ts`
0–100 composite score: -20 per critical (cap -60), -5 per high (cap -30), dependency trust average (20%), secrets exposure (-15 each), license compliance (10%), MCP safety (10%), +5 for SBOM, +5 for provenance.

### 10.5 Score History — `src/scoring/score-history.ts`
Time-series of scores stored in `.codeguard/score-history.json`. Shows trend (improving/degrading) in status bar and dashboard. Exported as part of compliance reports.

---

## 11. Policy Engine

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
    "apiSec": true,
    "agenticSecurity": true,
    "vibeCodeAnalyzer": true
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

## 12. Platform Components

### 12.1 VS Code / Windsurf / Cursor Extension
- **Package:** `codeguard-ai-9.0.0.vsix` (577 KB)
- **Requirement:** VS Code / Windsurf / Cursor ≥ 1.85.0
- **Install:** `windsurf --install-extension codeguard-ai-9.0.0.vsix`
- **Build:** `npm run compile` then `npx @vscode/vsce package --no-dependencies`

### 12.2 CLI Tool — `cli/`
```bash
codeguard scan                        # scan current directory
codeguard scan --format sarif         # SARIF (GitHub Code Scanning)
codeguard scan --fail-on critical     # exit 1 if criticals found
codeguard sbom                        # generate SBOM
codeguard report --framework soc2     # compliance report
```

### 12.3 GitHub Action — `cli/action.yml`
```yaml
- uses: codeguard-ai/security-scan@v9
  with:
    token: ${{ secrets.CODEGUARD_TOKEN }}
    fail-on: critical,high
    upload-sarif: true  # uploads to GitHub Security tab
```
Outputs: `critical-count`, `high-count`, `score`, `report-path`

### 12.4 Web Backend — `backend/`
**Stack:** Node.js + Express + TypeScript + Prisma + PostgreSQL (Supabase)

**Key API Endpoints:**

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | None | Health check |
| `GET` | `/api/auth/github` | None | Redirect to GitHub OAuth |
| `GET` | `/api/auth/callback/github` | None | GitHub OAuth callback |
| `POST` | `/api/auth/session` | None | Exchange Supabase token for JWT |
| `POST` | `/api/auth/admin/login` | None | **Admin login (email+password from .env)** |
| `GET` | `/api/auth/me` | JWT | Get current user profile |
| `POST` | `/api/auth/api-keys` | JWT | Create API key |
| `GET` | `/api/auth/api-keys` | JWT | List API keys |
| `DELETE` | `/api/auth/api-keys/:id` | JWT | Revoke API key |
| `GET` | `/api/scans` | JWT | List user scans |
| `GET` | `/api/scans/:id` | JWT | Get scan detail |
| `GET` | `/api/ghin/stats` | None | GHIN database stats |
| `GET` | `/api/ghin/packages` | None | List GHIN packages |
| `GET` | `/api/ghin/check/:eco/:name` | None | Check package |
| `POST` | `/api/ghin/report` | JWT | Submit hallucination report |
| `GET` | `/api/teams` | JWT | List teams |
| `POST` | `/api/teams` | JWT | Create team |
| `GET` | `/api/admin/stats` | JWT+ADMIN | **System stats (users, scans, GHIN, server)** |
| `GET` | `/api/admin/flags` | JWT+ADMIN | **List feature flags** |
| `POST` | `/api/admin/flags` | JWT+ADMIN | **Set feature flag override** |
| `DELETE` | `/api/admin/flags` | JWT+ADMIN | **Clear all flag overrides** |
| `POST` | `/api/admin/ghin/consolidate` | JWT+ADMIN | **Trigger GHIN consolidation** |
| `POST` | `/api/admin/ghin/verify` | JWT+ADMIN | **Trigger GHIN memory verification** |
| `POST` | `/api/admin/ghin/decay` | JWT+ADMIN | **Apply confidence decay** |

**Database Models:** `User`, `ApiKey`, `Team`, `TeamMember`, `Project`, `Scan`, `GhinReport`, `GhinPackage`, `PolicyTemplate`, `Webhook`, `WebhookDelivery`

### 12.5 Frontend Dashboard — `frontend/`
**Stack:** React + Vite + TailwindCSS + Zustand + TanStack Query

**Pages:**

| Route | Page | Access |
|---|---|---|
| `/login` | Login (GitHub OAuth + Admin email/password tabs) | Public |
| `/auth/callback` | OAuth callback handler | Public |
| `/` | Security Dashboard (scan trends, stats) | Authenticated |
| `/scans` | Scan history list | Authenticated |
| `/scans/:id` | Scan detail + findings | Authenticated |
| `/ghin` | GHIN packages browser | Authenticated |
| `/teams` | Team management | Authenticated |
| `/settings` | User settings, API key management | Authenticated |
| `/admin` | **Admin Dashboard (system stats, feature flags, GHIN controls)** | ADMIN role only |

---

## 13. Admin Dashboard & Backend

### 13.1 Admin Login

The admin account bypasses GitHub OAuth entirely. Credentials are defined in `backend/.env`:

```env
ADMIN_EMAIL=admin@codeguard.ai
ADMIN_PASSWORD=CodeGuard@Admin2026
ADMIN_NAME=CodeGuard Administrator
```

**How to login:**
1. Navigate to `/login`
2. Click the **Administrator** tab (amber)
3. Enter the email and password from your `.env`
4. You are redirected to `/admin`

**Security notes:**
- Admin JWT expires in 12 hours (shorter than regular 7-day tokens)
- Password supports both plaintext (dev) and `salt:hash` format from `hashPassword()` (production)
- The admin user is auto-created in the database on first login with `role=ADMIN`
- Non-admin users who know the `/admin` URL are redirected to `/` by `AdminRoute` guard

### 13.2 Admin Dashboard Sections

| Section | Data Shown | Actions |
|---|---|---|
| **System** | Total users, total scans, scans last 24h, teams, active API keys | Refresh (auto every 30s) |
| **GHIN** | Total packages, total reports, top 10 most-reported hallucinated packages | Trigger GHIN consolidation |
| **Feature Flags** | All runtime flags with current state | Live toggle on/off |
| **Server** | Uptime, heap memory used/total, Node.js version | — |
| **Navigation** | Quick links to Dashboard, Scans, GHIN, Teams | Navigate |

### 13.3 Password Hashing (Production)

To store a hashed password instead of plaintext in `.env`:

```typescript
import { hashPassword } from './src/utils/crypto';
const hashed = await hashPassword('MyNewPassword!');
// Set ADMIN_PASSWORD=<hashed output> in .env
```

The `verifyPassword()` function detects `salt:hash` format automatically.

---

## 14. Language Support

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

## 15. Security Standards Coverage

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

### OWASP Agentic Application Top 10:2026 (NEW in v9.0)

| ASI# | Category | Engine | Rules |
|---|---|---|---|
| ASI01 | Missing Human-in-the-Loop | Agentic Security Scanner | CG_AGT_040–041 |
| ASI02 | Leaked Agent Context | Agentic Security Scanner | CG_AGT_060–061 |
| ASI03 | Tool Misuse / Privilege Escalation | Agentic Security Scanner | CG_AGT_010–012, CG_AGT_070 |
| ASI04 | Confused Deputy | Agentic Security Scanner | CG_AGT_020–021 |
| ASI06 | Memory & Context Poisoning | Agentic Security Scanner | CG_AGT_001–003 |
| ASI07 | Agent-to-Agent Injection | Agentic Security Scanner | CG_AGT_030–031 |
| ASI08 | Insecure Tool Registration | Agentic Security Scanner | CG_AGT_050–051 |

### Vibe Code Security (Georgia Tech / Wiz / Veracode 2026)

| Finding | Statistic | Engine |
|---|---|---|
| Missing auth in AI-generated routes | #1 most common gap (Georgia Tech) | Vibe Code Analyzer CG_VIBE_001 |
| CORS wildcard in AI boilerplate | Universal — every AI Express template | Vibe Code Analyzer CG_VIBE_040 |
| Weak JWT secrets | Tutorial secrets shipped to prod | Vibe Code Analyzer CG_VIBE_090 |
| Exposed secrets (Gemini `AIza*`) | 72% of all AI key leaks | Secrets Scanner + Vibe Code CG_VIBE_071 |
| Frontend secret exposure | 400 found in 5,600 vibe-coded apps | Vibe Code Analyzer CG_VIBE_070 |
| TODO security debt | 78% unresolved before deploy | Vibe Code Analyzer CG_VIBE_110 |

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

## 16. Configuration Reference

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
  "codeguard.engines.agenticSecurity": true,
  "codeguard.engines.vibeCodeAnalyzer": true,
  "codeguard.telemetry.enabled": false
}
```

### Environment Variables

| Variable | Used By | Required | Description |
|---|---|---|---|
| `DATABASE_URL` | Backend (Prisma) | ✅ | PostgreSQL connection string (Supabase pooler) |
| `DIRECT_URL` | Backend (Prisma) | ✅ | PostgreSQL direct connection (migrations) |
| `SUPABASE_URL` | Backend | ✅ | Supabase project URL |
| `SUPABASE_ANON_KEY` | Backend | ✅ | Supabase anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | Backend | ✅ | Supabase service role key (admin ops) |
| `JWT_SECRET` | Backend | ✅ | JWT signing secret (256-bit minimum) |
| `ADMIN_EMAIL` | Backend | ✅ | **Admin account email (bypasses GitHub OAuth)** |
| `ADMIN_PASSWORD` | Backend | ✅ | **Admin account password (plaintext or salt:hash)** |
| `ADMIN_NAME` | Backend | — | Admin display name (default: `CodeGuard Administrator`) |
| `GITHUB_CLIENT_ID` | Backend | — | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | Backend | — | GitHub OAuth app client secret |
| `PORT` | Backend | — | Server port (default: 3000) |
| `API_BASE_URL` | Backend | — | Public backend URL |
| `CORS_ORIGINS` | Backend | — | Comma-separated allowed origins |
| `UPSTASH_REDIS_REST_URL` | Rate limiter | — | Upstash Redis REST URL |
| `UPSTASH_REDIS_REST_TOKEN` | Rate limiter | — | Upstash Redis REST token |
| `SENTRY_DSN` | Error monitoring | — | Sentry DSN |
| `RESEND_API_KEY` | Email | — | Resend API key |
| `OPENAI_API_KEY` | LLM Advisor | — | OpenAI backend for AI fix suggestions |
| `ANTHROPIC_API_KEY` | LLM Advisor | — | Anthropic Claude backend |
| `CODEGUARD_TOKEN` | GitHub Action | — | API token for cloud intelligence |

---

## 17. All VS Code Commands

Access via `Ctrl+Shift+P` → type `CodeGuard`:

| Command | Description |Version |
|---|---|---|
| `CodeGuard: Scan Current File` | Immediately scan the active file | Core |
| `CodeGuard: Scan Workspace Dependencies` | Full dependency audit | Core |
| `CodeGuard: Show Security Dashboard` | Open the webview dashboard | Core |
| `CodeGuard: Ask AI to Fix` | Invoke LLM Advisor on current finding | Core |
| `CodeGuard: Clear Vulnerability Cache` | Force-refresh all cached CVE data | Core |
| `CodeGuard: Scan AI Config Files for Attacks` | Scan `.cursorrules`, `CLAUDE.md`, etc. | Core |
| `CodeGuard: Sanitize Rules File` | Remove hidden Unicode from rules files | Core |
| `CodeGuard: GHIN Hallucination Database Stats` | Show GHIN stats | Core |
| `CodeGuard: Check Package Provenance (Sigstore)` | Verify Sigstore provenance | Core |
| `CodeGuard: Get Patch Report for Package` | Get safe upgrade info | Core |
| `CodeGuard: Analyze Install Command (Install Gate)` | Pre-run risk analysis | Core |
| `CodeGuard: Run Patch Agent (Auto-fix)` | Launch autonomous patch agent | Core |
| `CodeGuard: Generate SBOM (CycloneDX)` | Generate AI-aware SBOM | Core |
| `CodeGuard: Explain Security Issue with AI` | LLM explanation of finding | Core |
| `CodeGuard: Show Security Score` | Current score + trend | Core |
| `CodeGuard: Detect Dependency Drift (SBOM)` | Compare against baseline SBOM | Core |
| `CodeGuard: Save SBOM Baseline` | Save current SBOM as baseline | Core |
| `CodeGuard: Scan for Hardcoded Secrets` | 75+ pattern secrets scan | Core |
| `CodeGuard: Scan for Code Vulnerabilities (SAST)` | Regex SAST engine | Core |
| `CodeGuard: Deep SAST Scan (LLM + Adversarial)` | 3-pass hybrid SAST | Core |
| `CodeGuard: Cross-File Taint Analysis` | Taint tracking across files | Core |
| `CodeGuard: AI Code Attribution Report` | Identify AI-generated code | Core |
| `CodeGuard: Evaluate Security Policy` | Run `.codeguard/policy.json` | Core |
| `CodeGuard: Create Default Policy File` | Scaffold policy config | Core |
| `CodeGuard: Scan Git Changes for Security Regressions` | Git diff security check | Core |
| `CodeGuard: Export Compliance Report (CSV/Markdown/JSON)` | SOC2/PCI/HIPAA export | Core |
| `CodeGuard: Scan MCP Server Configurations` | MCP CVE + behavioral scan | Core |
| `CodeGuard: Discover Shadow AI (AI-SBOM)` | Find undeclared AI components | Core |
| `CodeGuard: Export AI-SBOM (JSON)` | Export AI inventory | Core |
| `CodeGuard v8: Scan MCP Servers Against CVE Database` | MCP CVE DB check | v8.0 |
| `CodeGuard v8: Scan for LLM Jailbreak Patterns` | Workspace jailbreak scan | v8.0 |
| `CodeGuard v8: Scan ML Model Files (Pickle/ONNX/Keras)` | ML exploit detection | v8.0 |
| `CodeGuard v8: Check Package for Typosquat Risk` | Enhanced typosquat check | v8.0 |
| `CodeGuard v8: Run All New Detection Engines` | All v8 engines in one pass | v8.0 |
| **`CodeGuard v9: Scan for Agentic AI Security Issues (OWASP ASI)`** | **OWASP ASI01–ASI08 workspace scan** | **v9.0** |
| **`CodeGuard v9: Analyze Vibe Code Security (AI Anti-patterns)`** | **Per-file debt score + AI attribution** | **v9.0** |

---

---

## 18. Test Files

| File | What It Tests | Findings Expected |
|---|---|---|
| `test-samples/v8-jailbreak-test.cursorrules` | LLM jailbreak patterns | 8+ CG_JB rules |
| `test-samples/v8-secrets-test.py` | Hardcoded API keys | 26+ secrets including Gemini, ElevenLabs |
| `test-samples/v8-pickle-test.py` | Unsafe ML model loading | CG_MODEL_CODE_001–007 |
| `test-samples/v8-api-security-test.js` | JWT/CORS/BOLA vulnerabilities | CG_AUTH, CG_API rules |
| `test-samples/v8-iac-test/` | Docker/K8s misconfigurations | CIS-mapped findings |
| `test-samples/mcp.json` | Malicious MCP server configs | MCP CVE + behavioral |
| `test-samples/v9-agentic-test.json` | Agentic AI security issues | CG_AGT_001–CG_AGT_080 |
| `test-samples/v9-vibe-test.js` | Vibe-coded app anti-patterns | CG_VIBE_001–CG_VIBE_140 |

---

*CodeGuard AI v9.0.0 — Built for the agentic AI development era.*
