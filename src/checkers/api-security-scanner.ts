/**
 * API Security Scanner — consolidated detector for:
 *
 *   1. JWT vulnerabilities (alg:none, weak secrets, missing expiry, algorithm confusion)
 *   2. GraphQL security (introspection in prod, no query depth limit, mass assignment)
 *   3. Insecure deserialization (pickle, YAML unsafe, Java serialize, PHP unserialize,
 *      Marshal/BinaryFormatter)
 *   4. API design flaws (BOLA/IDOR patterns, missing rate limiting, mass assignment,
 *      no authn/authz, CORS *, missing CSRF, open redirect)
 *
 * Language support: JavaScript/TypeScript, Python, Java, Ruby, Go, PHP, C#.
 */

import * as fs from 'fs';
import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ApiSecSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ApiSecCategory =
  | 'jwt'
  | 'graphql'
  | 'deserialization'
  | 'api-design'
  | 'cors'
  | 'csrf'
  | 'open-redirect'
  | 'auth-bypass'
  | 'rate-limit';

export interface ApiSecFinding {
  file: string;
  line: number;
  column: number;
  ruleId: string;
  category: ApiSecCategory;
  severity: ApiSecSeverity;
  title: string;
  detail: string;
  remediation: string;
  cwe?: string;
  owasp?: string; // OWASP API Top 10 mapping
  languages?: string[];
}

interface ApiSecRule {
  id: string;
  pattern: RegExp;
  category: ApiSecCategory;
  severity: ApiSecSeverity;
  title: string;
  detail: string;
  remediation: string;
  cwe?: string;
  owasp?: string;
  languages?: string[];
}

// ---------------------------------------------------------------------------
// JWT rules
// ---------------------------------------------------------------------------

const JWT_RULES: ApiSecRule[] = [
  {
    id: 'CG_API_JWT_001',
    pattern: /\balgorithm[s]?\s*[:=]\s*\[?\s*['"]none['"]/i,
    category: 'jwt',
    severity: 'critical',
    title: 'JWT algorithm set to "none"',
    detail:
      'alg:"none" disables signature verification — any forged token will be accepted.',
    remediation: 'Explicitly set algorithm to HS256/RS256/ES256 and reject "none".',
    cwe: 'CWE-347',
    owasp: 'API2:2023 Broken Authentication',
  },
  {
    id: 'CG_API_JWT_002',
    pattern: /\balgorithms?\s*[:=]\s*\[\s*['"](?:HS256|RS256|ES256|HS384|HS512)['"][^\]]*['"]none['"]/i,
    category: 'jwt',
    severity: 'critical',
    title: 'JWT algorithms list includes "none"',
    detail: 'Including "none" in the algorithms list lets attackers downgrade.',
    remediation: 'Remove "none" from the algorithms list.',
    cwe: 'CWE-347',
  },
  {
    id: 'CG_API_JWT_003',
    pattern: /\bjwt\.verify\s*\([^,)]+,\s*['"][^'"]{1,7}['"]/i,
    category: 'jwt',
    severity: 'critical',
    title: 'JWT verification uses a short (<8 char) secret',
    detail: 'Short HMAC secrets are brute-forceable in minutes.',
    remediation:
      'Use a secret of at least 256 bits (32+ random bytes), stored in an env var or secret manager.',
    cwe: 'CWE-326',
    languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'],
  },
  {
    id: 'CG_API_JWT_004',
    pattern: /\bjwt\.verify\s*\([^,)]+,\s*['"](?:secret|changeme|password|key|test|1234\d*|jwt_secret)['"]/i,
    category: 'jwt',
    severity: 'critical',
    title: 'JWT verify uses placeholder secret',
    detail: 'Placeholder secrets like "secret", "changeme" make tokens trivial to forge.',
    remediation: 'Generate a random 32+ byte secret; store in env var.',
    cwe: 'CWE-259',
  },
  {
    id: 'CG_API_JWT_005',
    pattern: /\bjwt\.sign\s*\(\s*\{[^}]*\}\s*,\s*[^,)]+,\s*\{[^}]*\}\s*\)/,
    category: 'jwt',
    severity: 'medium',
    title: 'JWT signed — verify expiresIn is set',
    detail:
      'If options object has no expiresIn, the token never expires. Verify manually.',
    remediation: 'Add expiresIn: "15m" (or similar short window).',
    cwe: 'CWE-613',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CG_API_JWT_006',
    pattern: /\bjwt\.decode\s*\(/,
    category: 'jwt',
    severity: 'high',
    title: 'jwt.decode() called (does NOT verify signature)',
    detail:
      'jwt.decode() decodes without signature verification. Attackers can forge claims.',
    remediation: 'Use jwt.verify() with the secret/public key.',
    cwe: 'CWE-347',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CG_API_JWT_007',
    pattern: /\bverify_signature\s*[:=]\s*False\b/i,
    category: 'jwt',
    severity: 'critical',
    title: 'PyJWT verify_signature=False',
    detail: 'Disables signature verification in PyJWT.',
    remediation: 'Never pass verify_signature=False in production.',
    cwe: 'CWE-347',
    languages: ['python'],
  },
  {
    id: 'CG_API_JWT_008',
    pattern: /\bverify\s*[:=]\s*False\b.*\bjwt\.decode/i,
    category: 'jwt',
    severity: 'critical',
    title: 'PyJWT decode with verify=False',
    detail: 'Skips signature verification — tokens can be forged.',
    remediation: 'Remove verify=False.',
    cwe: 'CWE-347',
    languages: ['python'],
  },
];

// ---------------------------------------------------------------------------
// GraphQL rules
// ---------------------------------------------------------------------------

const GRAPHQL_RULES: ApiSecRule[] = [
  {
    id: 'CG_API_GQL_001',
    pattern: /\bintrospection\s*[:=]\s*true\b/i,
    category: 'graphql',
    severity: 'medium',
    title: 'GraphQL introspection enabled',
    detail:
      'Introspection lets anyone map your entire schema. In production this aids attackers.',
    remediation:
      'Set introspection: process.env.NODE_ENV !== "production" to disable in prod.',
    cwe: 'CWE-200',
  },
  {
    id: 'CG_API_GQL_002',
    pattern: /\bplayground\s*[:=]\s*true\b/i,
    category: 'graphql',
    severity: 'medium',
    title: 'GraphQL Playground/Explorer enabled in production',
    detail: 'Playground exposes a query UI and often enables introspection.',
    remediation: 'Gate on NODE_ENV or remove in production builds.',
  },
  {
    id: 'CG_API_GQL_003',
    pattern: /\bApolloServer\s*\(\s*\{[^}]*\}\s*\)/,
    category: 'graphql',
    severity: 'info',
    title: 'ApolloServer initialized — verify it has depth/complexity limits',
    detail:
      'Without query depth / complexity / cost limits, a single nested query can DoS the server.',
    remediation:
      'Add validationRules: [depthLimit(5), createComplexityLimitRule(1000)] or use graphql-armor.',
    cwe: 'CWE-770',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CG_API_GQL_004',
    pattern: /\bbatching\s*[:=]\s*true\b|\ballowBatchedHttpRequests\s*[:=]\s*true\b/i,
    category: 'graphql',
    severity: 'low',
    title: 'GraphQL query batching enabled',
    detail: 'Batching amplifies DoS and rate-limit bypass.',
    remediation: 'Disable unless you have rate limiting that counts per-operation.',
  },
];

// ---------------------------------------------------------------------------
// Deserialization rules
// ---------------------------------------------------------------------------

const DESER_RULES: ApiSecRule[] = [
  {
    id: 'CG_API_DES_001',
    pattern: /\bpickle\.loads?\s*\(/,
    category: 'deserialization',
    severity: 'critical',
    title: 'Python pickle.load/loads with untrusted data',
    detail: 'pickle deserializes arbitrary Python objects and executes code.',
    remediation:
      'Use JSON or protobuf. If you must use pickle, sign the data with HMAC first.',
    cwe: 'CWE-502',
    languages: ['python'],
  },
  {
    id: 'CG_API_DES_002',
    pattern: /\byaml\.load\s*\(\s*(?:[^)]*(?<!Loader\s*=\s*(?:yaml\.)?SafeLoader))[^)]*\)/,
    category: 'deserialization',
    severity: 'high',
    title: 'yaml.load() without SafeLoader',
    detail: 'yaml.load deserializes arbitrary Python objects (CVE-2017-18342).',
    remediation: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
    cwe: 'CWE-502',
    languages: ['python'],
  },
  {
    id: 'CG_API_DES_003',
    pattern: /\bObjectInputStream\b.*\breadObject\s*\(\s*\)/,
    category: 'deserialization',
    severity: 'critical',
    title: 'Java ObjectInputStream.readObject() on untrusted data',
    detail:
      'Java serialization gadget chains (ysoserial) lead to RCE. Dozens of CVEs.',
    remediation:
      'Migrate to JSON (Jackson with @JsonTypeInfo disabled for user data) or protobuf.',
    cwe: 'CWE-502',
    languages: ['java'],
  },
  {
    id: 'CG_API_DES_004',
    pattern: /\bunserialize\s*\(/,
    category: 'deserialization',
    severity: 'critical',
    title: 'PHP unserialize() on untrusted data',
    detail: 'unserialize() allows PHP object injection (POP chains).',
    remediation: 'Use json_decode(). If unserialize() is required, pass allowed_classes: false.',
    cwe: 'CWE-502',
    languages: ['php'],
  },
  {
    id: 'CG_API_DES_005',
    pattern: /\bMarshal\.load\s*\(/,
    category: 'deserialization',
    severity: 'critical',
    title: 'Ruby Marshal.load on untrusted data',
    detail: 'Marshal deserialization has led to RCE in Rails, Sidekiq, etc.',
    remediation: 'Use JSON.parse instead.',
    cwe: 'CWE-502',
    languages: ['ruby'],
  },
  {
    id: 'CG_API_DES_006',
    pattern: /\bBinaryFormatter\b|\bNetDataContractSerializer\b|\bSoapFormatter\b/,
    category: 'deserialization',
    severity: 'critical',
    title: '.NET BinaryFormatter / SOAP / NetDataContract',
    detail:
      'Microsoft explicitly deprecated BinaryFormatter due to unfixable RCE risk.',
    remediation:
      'Migrate to System.Text.Json or MessagePack with typesafe contracts.',
    cwe: 'CWE-502',
    languages: ['csharp'],
  },
  {
    id: 'CG_API_DES_007',
    pattern: /\bnode-serialize\b.*\bunserialize\s*\(|\bfuncster\.deepDeserialize\b/,
    category: 'deserialization',
    severity: 'critical',
    title: 'Node.js node-serialize.unserialize() on untrusted data',
    detail: 'node-serialize RCE via IIFE gadget (CVE-2017-5941).',
    remediation: 'Use JSON.parse or safe-stable-stringify.',
    cwe: 'CWE-502',
    languages: ['javascript', 'typescript'],
  },
];

// ---------------------------------------------------------------------------
// API design / auth rules
// ---------------------------------------------------------------------------

const API_DESIGN_RULES: ApiSecRule[] = [
  {
    id: 'CG_API_CORS_001',
    pattern: /\bAccess-Control-Allow-Origin['"\s,:]+\*\b/,
    category: 'cors',
    severity: 'high',
    title: 'CORS Access-Control-Allow-Origin: *',
    detail:
      'Wildcard CORS + credentials leaks session data. Even without credentials, it invites CSRF-like abuse of authenticated endpoints.',
    remediation: 'Echo an allowlisted origin instead of "*". Never combine * with credentials.',
    cwe: 'CWE-942',
    owasp: 'API7:2023',
  },
  {
    id: 'CG_API_CORS_002',
    pattern: /\bcors\s*\(\s*\{\s*origin\s*:\s*(?:true|['"]\*['"])/i,
    category: 'cors',
    severity: 'high',
    title: 'Express cors middleware with origin: true or "*"',
    detail: 'origin:true reflects the Origin header — effectively * with credentials.',
    remediation:
      'Pass a function that validates against an allowlist, or an explicit array of URLs.',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CG_API_CSRF_001',
    pattern: /\bapp\.use\s*\(\s*csrf\s*\(\s*\{\s*cookie\s*:\s*\{\s*secure\s*:\s*false/i,
    category: 'csrf',
    severity: 'medium',
    title: 'CSRF cookie secure: false',
    detail: 'CSRF cookie sent over HTTP can be intercepted.',
    remediation: 'Set secure: true in production.',
    cwe: 'CWE-614',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CG_API_OR_001',
    pattern: /\bres\.redirect\s*\(\s*req\.(?:query|params|body)\b/,
    category: 'open-redirect',
    severity: 'high',
    title: 'Open redirect: res.redirect() with user-supplied URL',
    detail:
      'Redirecting to arbitrary user-supplied URLs enables phishing.',
    remediation: 'Validate URL against an allowlist of internal paths.',
    cwe: 'CWE-601',
    owasp: 'API7:2023',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CG_API_BOLA_001',
    pattern: /\bfindOne\s*\(\s*\{\s*(?:_?id|userId)\s*:\s*req\.(?:params|query|body)\.[a-z]+\s*\}\s*\)/i,
    category: 'auth-bypass',
    severity: 'high',
    title: 'Possible BOLA/IDOR: .findOne() on user-supplied id without ownership check',
    detail:
      'Broken Object Level Authorization (#1 in OWASP API Security Top 10). Anyone who ' +
      'can guess an id can read the record.',
    remediation:
      'Add the current user scope: .findOne({ _id, ownerId: req.user.id }). Always authorize.',
    cwe: 'CWE-639',
    owasp: 'API1:2023',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CG_API_BOLA_002',
    pattern: /@app\.route\s*\(\s*['"][^'"]*<\w+>['"][^)]*\)\s*\n\s*def\s+\w+\s*\([^)]*\)\s*:/,
    category: 'auth-bypass',
    severity: 'info',
    title: 'Flask route with URL parameter — verify authorization',
    detail:
      'Routes with <id>/<uuid> parameters must validate that the requesting user owns the object.',
    remediation: 'Check ownership before returning or mutating data.',
    owasp: 'API1:2023',
    languages: ['python'],
  },
  {
    id: 'CG_API_MA_001',
    pattern: /\b(?:Object\.assign|spread)\s*\(\s*\w+\s*,\s*req\.body\s*\)/,
    category: 'api-design',
    severity: 'high',
    title: 'Mass assignment: spread of req.body into model',
    detail:
      'Object.assign(user, req.body) allows attackers to set fields like isAdmin, role, etc.',
    remediation: 'Pick specific fields: const { name, email } = req.body.',
    cwe: 'CWE-915',
    owasp: 'API6:2023',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CG_API_MA_002',
    pattern: /\bnew\s+\w+\s*\(\s*req\.body\s*\)/,
    category: 'api-design',
    severity: 'high',
    title: 'Mass assignment: constructor with req.body',
    detail: 'Passing req.body directly to a model constructor risks mass assignment.',
    remediation: 'Whitelist fields before constructing.',
    cwe: 'CWE-915',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CG_API_RL_001',
    pattern: /\bapp\.use\s*\(\s*rateLimit\s*\(\s*\{\s*max\s*:\s*(?:[5-9]\d{2,}|\d{4,})/,
    category: 'rate-limit',
    severity: 'low',
    title: 'Rate limit is unusually permissive (>500/window)',
    detail: 'Very high limits defeat the purpose of rate limiting.',
    remediation: 'Tune per-route to realistic usage; stricter for auth routes.',
    cwe: 'CWE-770',
    owasp: 'API4:2023',
    languages: ['javascript', 'typescript'],
  },
  {
    id: 'CG_API_AUTH_001',
    pattern: /\bapp\.use\s*\(\s*(?:cors|helmet)\s*\(\s*\)\s*\)/,
    category: 'api-design',
    severity: 'info',
    title: 'cors()/helmet() used with default config — review',
    detail: 'Defaults may be more permissive than intended.',
    remediation: 'Explicitly configure allowed origins, CSP, HSTS, etc.',
  },
];

// ---------------------------------------------------------------------------
// Combined rule set
// ---------------------------------------------------------------------------

const ALL_RULES: ApiSecRule[] = [
  ...JWT_RULES,
  ...GRAPHQL_RULES,
  ...DESER_RULES,
  ...API_DESIGN_RULES,
];

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

const SUPPORTED_LANGUAGES = new Set([
  'javascript',
  'typescript',
  'javascriptreact',
  'typescriptreact',
  'python',
  'java',
  'ruby',
  'go',
  'php',
  'csharp',
]);

export function scanTextForApiSec(
  text: string,
  filePath: string,
  languageId?: string
): ApiSecFinding[] {
  const findings: ApiSecFinding[] = [];
  const lines = text.split(/\r?\n/);
  const lang = languageId ?? guessLanguage(filePath);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0 || line.length > 6000) continue;
    // Skip comments
    if (/^\s*(?:\/\/|#|\/\*|\*)/.test(line)) continue;

    for (const rule of ALL_RULES) {
      if (rule.languages && lang && !rule.languages.includes(lang)) continue;
      const m = rule.pattern.exec(line);
      if (m) {
        findings.push({
          file: filePath,
          line: i + 1,
          column: (m.index ?? 0) + 1,
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          title: rule.title,
          detail: rule.detail,
          remediation: rule.remediation,
          cwe: rule.cwe,
          owasp: rule.owasp,
          languages: rule.languages,
        });
      }
    }
  }

  return findings;
}

function guessLanguage(filePath: string): string | undefined {
  const ext = filePath.toLowerCase().split('.').pop();
  const map: Record<string, string> = {
    js: 'javascript',
    jsx: 'javascriptreact',
    ts: 'typescript',
    tsx: 'typescriptreact',
    mjs: 'javascript',
    cjs: 'javascript',
    py: 'python',
    pyw: 'python',
    java: 'java',
    rb: 'ruby',
    go: 'go',
    php: 'php',
    cs: 'csharp',
  };
  return ext ? map[ext] : undefined;
}

export function scanFileForApiSec(filePath: string): ApiSecFinding[] {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 3 * 1024 * 1024) return [];
    const text = fs.readFileSync(filePath, 'utf8');
    return scanTextForApiSec(text, filePath);
  } catch {
    return [];
  }
}

export function scanDocumentForApiSec(doc: vscode.TextDocument): ApiSecFinding[] {
  if (!SUPPORTED_LANGUAGES.has(doc.languageId)) return [];
  return scanTextForApiSec(doc.getText(), doc.fileName, doc.languageId);
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

export function getApiSecScannerStats(): {
  jwtRules: number;
  graphqlRules: number;
  deserializationRules: number;
  apiDesignRules: number;
  totalRules: number;
} {
  return {
    jwtRules: JWT_RULES.length,
    graphqlRules: GRAPHQL_RULES.length,
    deserializationRules: DESER_RULES.length,
    apiDesignRules: API_DESIGN_RULES.length,
    totalRules: ALL_RULES.length,
  };
}
