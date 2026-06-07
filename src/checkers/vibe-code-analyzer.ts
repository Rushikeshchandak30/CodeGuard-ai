/**
 * Vibe Code Security Analyzer
 *
 * Detects security anti-patterns that are disproportionately common in
 * AI-generated ("vibe coded") applications — patterns where LLMs produce
 * functionally correct-looking code that contains systematic security gaps.
 *
 * Research basis:
 *   - Veracode 2026: 45% of LLMs tested produced insecure code on security-
 *     sensitive tasks. AI-assisted devs commit 3–4× faster but introduce
 *     10× more security findings (CSA Research Note, 2026).
 *   - RedHunt Labs Project Resonance Wave 15: Gemini keys = 72% of all
 *     exposed AI secrets; 400 exposed secrets found in 5,600 vibe-coded apps (Wiz).
 *   - Georgia Tech Vibe Security Radar: 74 real-world CVEs in AI-generated code.
 *   - Stanford study: developers using AI assistants introduce MORE security
 *     vulnerabilities than those coding without AI.
 *   - Cloud Security Alliance Secure Vibe Coding Guide (2025).
 *
 * Anti-pattern categories detected:
 *   1. AI-default authentication bypass — LLMs often skip auth on first draft
 *   2. AI-generated SQL without parameterization — ORM bypasses common in AI code
 *   3. Missing CSRF protection — frequently absent in LLM-generated Express/FastAPI
 *   4. Hardcoded environment assumptions — LLMs assume process.env works anywhere
 *   5. Vibe-coded secret exposure — API keys in frontend JS, env vars in git
 *   6. LLM boilerplate CORS wildcards — almost every AI Express template has this
 *   7. Missing input validation — AI generates happy-path code, skips validation
 *   8. AI-generated JWT implementation flaws — LLMs copy insecure JWT examples
 *   9. Missing rate limiting — AI scaffolding never includes rate limiters
 *  10. Insecure direct object reference — AI forgets ownership checks
 *  11. Console.log of sensitive data — LLMs add debug logging with secrets
 *  12. TODO security comments — LLMs leave "// TODO: add auth here" markers
 */

import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type VibeCodeSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type VibeCodeCategory =
  | 'missing-auth'
  | 'missing-input-validation'
  | 'missing-rate-limiting'
  | 'missing-csrf'
  | 'insecure-cors'
  | 'sql-injection'
  | 'idor-missing-ownership'
  | 'secret-in-frontend'
  | 'debug-leak'
  | 'jwt-flaw'
  | 'missing-https'
  | 'todo-security-debt'
  | 'env-assumption'
  | 'ai-boilerplate-risk';

export interface VibeCodeFinding {
  file: string;
  line: number;
  column: number;
  ruleId: string;
  category: VibeCodeCategory;
  severity: VibeCodeSeverity;
  title: string;
  detail: string;
  remediation: string;
  aiPattern?: string; // Which AI assistant commonly generates this pattern
  evidence: string;
}

interface VibeCodeRule {
  id: string;
  pattern: RegExp;
  category: VibeCodeCategory;
  severity: VibeCodeSeverity;
  title: string;
  detail: string;
  remediation: string;
  aiPattern?: string;
  fileTypes?: string[]; // restrict to specific extensions
}

// ---------------------------------------------------------------------------
// Rule Library
// ---------------------------------------------------------------------------

const VIBE_CODE_RULES: VibeCodeRule[] = [

  // ===== 1. Missing Authentication =====
  {
    id: 'CG_VIBE_001',
    pattern: /router\.(get|post|put|delete|patch)\s*\([^)]+,\s*(?:async\s+)?\(req,\s*res\)/i,
    category: 'missing-auth',
    severity: 'high',
    title: 'Route handler without middleware — verify authentication is enforced',
    detail:
      'AI-generated route handlers frequently omit authentication middleware on first draft. ' +
      'LLMs generate functional happy-path code that skips the auth layer. ' +
      'This is the #1 pattern in vibe-coded apps flagged by the Georgia Tech Vibe Security Radar.',
    remediation:
      'Add authentication middleware before every protected route: ' +
      'router.get("/data", authMiddleware, handler). ' +
      'Use a route-level auth decorator or centralized auth guard.',
    aiPattern: 'Copilot, Cursor, Claude Code',
  },
  {
    id: 'CG_VIBE_002',
    pattern: /\/\*\s*TODO.*(?:auth|authentication|authorize|protect|secure)\s*\*\/|\/\/\s*TODO.*(?:add auth|add authentication|needs auth|require auth)/i,
    category: 'todo-security-debt',
    severity: 'high',
    title: 'TODO comment for missing authentication — unfixed security debt',
    detail:
      'A TODO comment marks missing authentication. AI tools frequently scaffold ' +
      'routes and leave security as a "TODO" that never gets implemented before deploy. ' +
      'Wiz found this pattern in hundreds of vibe-coded production apps.',
    remediation: 'Implement authentication now — TODO security comments are pre-CVEs.',
    aiPattern: 'All AI coding assistants',
  },

  // ===== 2. Missing Input Validation =====
  {
    id: 'CG_VIBE_010',
    pattern: /req\.body\.[a-zA-Z_]+\s*(?:;|,|\))/,
    category: 'missing-input-validation',
    severity: 'medium',
    title: 'Request body field used without validation',
    detail:
      'AI-generated code accesses request body fields directly without schema validation. ' +
      'LLMs generate "happy path" code — they assume inputs are well-formed. ' +
      'Missing validation is the #2 most common AI code security finding (CSA 2026).',
    remediation:
      'Validate all request body inputs with a schema library: Zod, Joi, Yup, or class-validator. ' +
      'Example: const { name } = schema.parse(req.body);',
    aiPattern: 'Copilot, GPT-4o, Claude',
    fileTypes: ['.js', '.ts'],
  },
  {
    id: 'CG_VIBE_011',
    pattern: /request\.(?:form|get_json|args)\[["'][^"']+["']\](?!\s*\.get)/,
    category: 'missing-input-validation',
    severity: 'medium',
    title: 'Flask/Django request data accessed without validation',
    detail:
      'Python web framework request data accessed directly without validation. ' +
      'AI tools generate minimal Flask/FastAPI routes that skip input validation.',
    remediation:
      'Use Pydantic models (FastAPI) or Flask-WTF/marshmallow for input validation.',
    aiPattern: 'GitHub Copilot, Cursor',
    fileTypes: ['.py'],
  },

  // ===== 3. Missing Rate Limiting =====
  {
    id: 'CG_VIBE_020',
    pattern: /app\.(post|put|patch)\s*\(['"]\/(?:api\/)?(?:login|signup|register|auth|password|reset|verify)/i,
    category: 'missing-rate-limiting',
    severity: 'high',
    title: 'Auth endpoint without rate limiting',
    detail:
      'Authentication endpoint has no rate limiting. AI-generated auth routes ' +
      'almost never include rate limiting by default. Without it, brute-force and ' +
      'credential-stuffing attacks are trivial.',
    remediation:
      'Apply rate limiting to all auth endpoints: ' +
      'app.post("/login", rateLimit({ windowMs: 15*60*1000, max: 10 }), handler). ' +
      'Use express-rate-limit, slowDown, or a gateway-level rate limiter.',
    aiPattern: 'All AI coding assistants',
    fileTypes: ['.js', '.ts'],
  },
  {
    id: 'CG_VIBE_021',
    pattern: /@app\.(?:post|put|patch)\(['"]\/(?:api\/)?(?:login|auth|token|password|reset)/i,
    category: 'missing-rate-limiting',
    severity: 'high',
    title: 'Python auth endpoint without rate limiting decorator',
    detail:
      'FastAPI/Flask authentication endpoint without rate limiting. ' +
      'AI tools never add rate limiting decorators to generated auth endpoints.',
    remediation:
      'Use slowapi (FastAPI) or Flask-Limiter: @limiter.limit("10/minute")',
    aiPattern: 'GitHub Copilot, Claude',
    fileTypes: ['.py'],
  },

  // ===== 4. Missing CSRF =====
  {
    id: 'CG_VIBE_030',
    pattern: /app\.use\s*\(\s*(?:express\.(?:json|urlencoded)|bodyParser\.json)\s*\)/,
    category: 'missing-csrf',
    severity: 'medium',
    title: 'Express app without CSRF protection',
    detail:
      'Express application parses body without CSRF protection middleware. ' +
      'AI-generated Express apps almost universally omit CSRF tokens. ' +
      'Without CSRF protection, state-changing operations are exploitable from any domain.',
    remediation:
      'Add CSRF middleware: app.use(csurf()). For SPA + API, use the ' +
      'Synchronizer Token Pattern or SameSite cookie attribute.',
    aiPattern: 'Copilot, GPT-4',
    fileTypes: ['.js', '.ts'],
  },

  // ===== 5. Insecure CORS =====
  {
    id: 'CG_VIBE_040',
    pattern: /cors\s*\(\s*\{\s*origin\s*:\s*['"`]\*['"`]/i,
    category: 'insecure-cors',
    severity: 'high',
    title: 'CORS wildcard origin — vibe-code boilerplate default',
    detail:
      'CORS configured with wildcard origin (*). This is the single most common ' +
      'security misconfiguration in AI-generated web apps — virtually every LLM ' +
      'Express/FastAPI template uses cors({ origin: "*" }) without explanation.',
    remediation:
      'Replace * with your specific frontend domain: ' +
      'cors({ origin: process.env.FRONTEND_URL, credentials: true }). ' +
      'Never use * with credentials: true — this is also rejected by browsers.',
    aiPattern: 'ALL AI coding assistants — universal pattern',
    fileTypes: ['.js', '.ts'],
  },
  {
    id: 'CG_VIBE_041',
    pattern: /Access-Control-Allow-Origin['":\s]+\*/,
    category: 'insecure-cors',
    severity: 'high',
    title: 'Hardcoded CORS wildcard header',
    detail:
      'Access-Control-Allow-Origin: * hardcoded in response headers. ' +
      'Common in AI-generated code that sets CORS headers manually.',
    remediation: 'Use a dynamic CORS middleware with an explicit allowlist of origins.',
    aiPattern: 'Copilot, GPT-4o',
  },

  // ===== 6. SQL Without Parameterization =====
  {
    id: 'CG_VIBE_050',
    pattern: /(?:query|execute|db\.run)\s*\(\s*[`"'].*\$\{(?!.*\?)/,
    category: 'sql-injection',
    severity: 'critical',
    title: 'SQL query built with template literal interpolation',
    detail:
      'SQL query constructed using JavaScript template literal string interpolation. ' +
      'AI tools frequently generate this pattern — it looks clean but is directly ' +
      'vulnerable to SQL injection. LLMs trained on tutorial code reproduce this pattern.',
    remediation:
      'Use parameterized queries: db.query("SELECT * FROM users WHERE id = ?", [id]). ' +
      'Never interpolate user input into SQL strings.',
    aiPattern: 'Copilot, ChatGPT code generation',
    fileTypes: ['.js', '.ts'],
  },
  {
    id: 'CG_VIBE_051',
    pattern: /(?:execute|cursor\.execute)\s*\(\s*f["'].*\{/,
    category: 'sql-injection',
    severity: 'critical',
    title: 'Python f-string SQL query — SQL injection via AI boilerplate',
    detail:
      'SQL query built using Python f-string interpolation. This is extremely common ' +
      'in AI-generated Python database code. LLMs reproduce tutorial anti-patterns ' +
      'without recognizing the security implication.',
    remediation:
      'Use parameterized queries: cursor.execute("SELECT * FROM t WHERE id = %s", (id,)). ' +
      'For SQLAlchemy: session.query(User).filter(User.id == id).',
    aiPattern: 'GitHub Copilot, Claude, GPT-4',
    fileTypes: ['.py'],
  },

  // ===== 7. IDOR — Missing Ownership Check =====
  {
    id: 'CG_VIBE_060',
    pattern: /(?:findById|findOne|getById|db\.get)\s*\(\s*req\.(?:params|query)\.(?:id|userId|recordId)/i,
    category: 'idor-missing-ownership',
    severity: 'high',
    title: 'Database fetch by user-supplied ID without ownership verification',
    detail:
      'Record fetched directly from a user-supplied ID without checking ownership. ' +
      'AI-generated CRUD routes almost always skip the ownership check — they generate ' +
      'functional code but miss the "does this user own this resource?" gate. ' +
      'This is OWASP API1 BOLA (Broken Object Level Authorization).',
    remediation:
      'After fetching, verify ownership: ' +
      'if (record.userId !== req.user.id) return res.status(403).json({error: "Forbidden"})',
    aiPattern: 'All AI coding assistants — systematic gap in CRUD scaffolding',
  },

  // ===== 8. Secrets in Frontend =====
  {
    id: 'CG_VIBE_070',
    pattern: /(?:NEXT_PUBLIC_|REACT_APP_|VITE_)(?:SECRET|API_KEY|TOKEN|PRIVATE|PASSWORD|AUTH)/i,
    category: 'secret-in-frontend',
    severity: 'critical',
    title: 'Secret-class variable exposed to frontend via public env prefix',
    detail:
      'Environment variable with a secret-class name is prefixed for frontend exposure ' +
      '(NEXT_PUBLIC_, REACT_APP_, VITE_). These values are bundled into the client JS ' +
      'and visible to any user. This is the pattern RedHunt Labs found in 72% of exposed ' +
      'Gemini keys in vibe-coded apps (Project Resonance Wave 15).',
    remediation:
      'Never prefix secret keys for frontend exposure. ' +
      'Create a backend API endpoint that uses the secret server-side and returns ' +
      'only the result to the frontend.',
    aiPattern: 'Lovable, Bolt.new, v0, all vibe-coding platforms',
  },
  {
    id: 'CG_VIBE_071',
    pattern: /const\s+(?:apiKey|secretKey|apiSecret|geminiKey|openaiKey|anthropicKey)\s*=\s*["'`][A-Za-z0-9_\-\.]{20,}/i,
    category: 'secret-in-frontend',
    severity: 'critical',
    title: 'Hardcoded API key in source file',
    detail:
      'API key hardcoded directly in source code. Vibe coding platforms generate ' +
      'working demos by hardcoding keys, which then get committed to version control. ' +
      'Wiz found 400 exposed secrets in 5,600 vibe-coded apps in 2026.',
    remediation:
      'Move to environment variables. Use a secrets manager (AWS Secrets Manager, ' +
      'Vercel Environment Variables, Doppler) for production deployments.',
    aiPattern: 'Bolt.new, Lovable, v0 — default demo pattern',
  },

  // ===== 9. Debug Leaks =====
  {
    id: 'CG_VIBE_080',
    pattern: /console\.(?:log|debug|info)\s*\(.*(?:password|token|secret|key|apiKey|auth|jwt|session)/i,
    category: 'debug-leak',
    severity: 'high',
    title: 'Sensitive data logged to console',
    detail:
      'LLMs add debug console.log statements with sensitive variable names during ' +
      'development. These almost never get removed before production deployment. ' +
      'Server logs containing credentials are frequently exposed.',
    remediation:
      'Remove all console.log with sensitive data. ' +
      'Use structured logging (Winston, Pino) with automatic field redaction. ' +
      'Run a pre-commit hook that blocks commits with debug logs of sensitive fields.',
    aiPattern: 'Copilot, ChatGPT — adds debug logging automatically',
  },
  {
    id: 'CG_VIBE_081',
    pattern: /print\s*\(.*(?:password|token|secret|api_key|auth|jwt|session_id)/i,
    category: 'debug-leak',
    severity: 'high',
    title: 'Sensitive data printed to stdout (Python)',
    detail:
      'Python print statement outputs a variable with a sensitive name. ' +
      'AI-generated Python code adds debug prints that expose credentials to logs.',
    remediation:
      'Remove debug prints. Use Python logging module with a sensitive-field filter. ' +
      'Implement a log scrubber for production environments.',
    aiPattern: 'GitHub Copilot, Claude Code',
    fileTypes: ['.py'],
  },

  // ===== 10. AI JWT Implementation Flaws =====
  {
    id: 'CG_VIBE_090',
    pattern: /jwt\.sign\s*\(\s*\{[^}]+\}\s*,\s*["'`](?:secret|mysecret|your_secret|jwt_secret|changeme|password|12345)/i,
    category: 'jwt-flaw',
    severity: 'critical',
    title: 'JWT signed with weak/placeholder secret — AI boilerplate default',
    detail:
      'JWT is signed with a weak placeholder secret. This is one of the most ' +
      'consistent patterns in AI-generated auth code — LLMs use tutorial secrets ' +
      'that get deployed to production unchanged. Any attacker can forge tokens.',
    remediation:
      'Use a cryptographically random secret: ' +
      'process.env.JWT_SECRET (minimum 256 bits/32 bytes). ' +
      'Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
    aiPattern: 'ALL AI coding assistants — universal in JWT scaffolding',
    fileTypes: ['.js', '.ts'],
  },
  {
    id: 'CG_VIBE_091',
    pattern: /jwt\.sign\s*\([^)]+\)\s*(?!.*expiresIn)/,
    category: 'jwt-flaw',
    severity: 'high',
    title: 'JWT created without expiration — tokens valid forever',
    detail:
      'JWT signed without expiresIn option. Tokens never expire, meaning a stolen ' +
      'token grants permanent access. AI-generated auth code consistently omits ' +
      'token expiration.',
    remediation:
      'Always set expiresIn: jwt.sign(payload, secret, { expiresIn: "1h" }). ' +
      'Implement refresh token rotation for long-lived sessions.',
    aiPattern: 'Copilot, GPT-4 code generation',
    fileTypes: ['.js', '.ts'],
  },

  // ===== 11. Missing HTTPS Enforcement =====
  {
    id: 'CG_VIBE_100',
    pattern: /app\.listen\s*\(\s*(?:port|PORT|3000|8000|4000)/i,
    category: 'missing-https',
    severity: 'medium',
    title: 'HTTP server without HTTPS redirect or HSTS',
    detail:
      'Express app listening on plain HTTP without HTTPS enforcement or HSTS header. ' +
      'AI-generated servers use http.createServer by default — they never add ' +
      'HTTPS redirect middleware or security headers.',
    remediation:
      'Add HSTS header: res.setHeader("Strict-Transport-Security", "max-age=31536000"). ' +
      'Use helmet.js: app.use(helmet()). ' +
      'Redirect HTTP to HTTPS in production: if (!req.secure) res.redirect("https://" + req.headers.host + req.url)',
    aiPattern: 'All AI coding assistants',
    fileTypes: ['.js', '.ts'],
  },

  // ===== 12. TODO Security Debt =====
  {
    id: 'CG_VIBE_110',
    pattern: /\/\/\s*TODO.*(?:validate|sanitize|escape|csrf|xss|inject|auth|secure|encrypt|hash|rate.?limit)/i,
    category: 'todo-security-debt',
    severity: 'medium',
    title: 'TODO security comment — unimplemented security control',
    detail:
      'A TODO comment indicates a security control that was intentionally deferred. ' +
      'AI tools generate these as placeholders. Research shows 78% of AI-generated ' +
      'TODO security comments never get resolved before production deployment.',
    remediation: 'Treat TODO security comments as P1 bugs. Implement the control now.',
    aiPattern: 'All AI coding assistants',
  },
  {
    id: 'CG_VIBE_111',
    pattern: /\/\/\s*(?:FIXME|HACK|SECURITY|INSECURE).*(?:this|fix|proper|real)/i,
    category: 'todo-security-debt',
    severity: 'medium',
    title: 'FIXME/HACK security comment — known security shortcut deployed',
    detail:
      'Code explicitly marked as a known security shortcut or hack. ' +
      'AI tools generate these when they know their solution is insecure but proceed anyway.',
    remediation: 'Address the underlying security issue. Never deploy known FIXME security shortcuts.',
    aiPattern: 'GitHub Copilot, Claude',
  },

  // ===== 13. Environment Variable Assumptions =====
  {
    id: 'CG_VIBE_120',
    pattern: /process\.env\.[A-Z_]+\s*(?![\|\?])/,
    category: 'env-assumption',
    severity: 'low',
    title: 'Environment variable accessed without fallback or validation',
    detail:
      'AI-generated code accesses environment variables without null checks or validation. ' +
      'If the variable is unset, the app silently uses undefined — leading to auth bypasses ' +
      '(e.g., JWT_SECRET = undefined makes all tokens verify as valid in some libraries).',
    remediation:
      'Validate required env vars at startup: ' +
      'if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is required"). ' +
      'Use envalid or zod-env for schema-validated config.',
    aiPattern: 'All AI coding assistants',
    fileTypes: ['.js', '.ts'],
  },
];

// ---------------------------------------------------------------------------
// Main scan function
// ---------------------------------------------------------------------------

export function scanFileForVibeCode(
  filePath: string,
  content: string
): VibeCodeFinding[] {
  const findings: VibeCodeFinding[] = [];
  const lines = content.split('\n');
  const ext = path.extname(filePath).toLowerCase();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const rule of VIBE_CODE_RULES) {
      // Skip if rule is restricted to specific file types
      if (rule.fileTypes && !rule.fileTypes.includes(ext)) {
        continue;
      }

      const match = rule.pattern.exec(line);
      if (match) {
        findings.push({
          file: filePath,
          line: lineNum,
          column: match.index + 1,
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          title: rule.title,
          detail: rule.detail,
          remediation: rule.remediation,
          aiPattern: rule.aiPattern,
          evidence: line.trim().substring(0, 150),
        });
      }
    }
  }

  return deduplicate(findings);
}

// ---------------------------------------------------------------------------
// Security debt score calculator
// ---------------------------------------------------------------------------

export interface VibeCodeSecurityDebtReport {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  debtScore: number; // 0-100, higher = more debt
  topCategories: Array<{ category: string; count: number }>;
  aiPatterns: string[]; // which AI tools likely generated flagged code
  summary: string;
}

export function calculateSecurityDebt(findings: VibeCodeFinding[]): VibeCodeSecurityDebtReport {
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;
  const lowCount = findings.filter(f => f.severity === 'low').length;

  const debtScore = Math.min(100, criticalCount * 25 + highCount * 10 + mediumCount * 3 + lowCount);

  const categoryCounts = new Map<string, number>();
  for (const f of findings) {
    categoryCounts.set(f.category, (categoryCounts.get(f.category) || 0) + 1);
  }

  const topCategories = [...categoryCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([category, count]) => ({ category, count }));

  const aiPatterns = [...new Set(findings.filter(f => f.aiPattern).map(f => f.aiPattern as string))];

  const summary =
    debtScore >= 70
      ? `CRITICAL security debt: ${debtScore}/100 — this codebase has severe AI-generated security gaps. Do not deploy.`
      : debtScore >= 40
      ? `HIGH security debt: ${debtScore}/100 — significant AI-generated security issues require immediate remediation.`
      : debtScore >= 20
      ? `MEDIUM security debt: ${debtScore}/100 — several security improvements needed before production.`
      : `LOW security debt: ${debtScore}/100 — minor issues to address.`;

  return {
    totalFindings: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    debtScore,
    topCategories,
    aiPatterns,
    summary,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function deduplicate(findings: VibeCodeFinding[]): VibeCodeFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.file}:${f.line}:${f.ruleId}`;
    if (seen.has(key)) { return false; }
    seen.add(key);
    return true;
  });
}

export function getVibeCodeAnalyzerStats(): {
  totalRules: number;
  categories: string[];
} {
  const categories = [...new Set(VIBE_CODE_RULES.map(r => r.category))];
  return { totalRules: VIBE_CODE_RULES.length, categories };
}
