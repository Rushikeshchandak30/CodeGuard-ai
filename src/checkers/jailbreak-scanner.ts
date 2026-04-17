/**
 * LLM Jailbreak & Prompt Injection Scanner
 *
 * Scans source files, system prompts, rules files, and AI config for:
 *   1. Direct jailbreak patterns (DAN, STAN, DUDE, developer mode, evil twin)
 *   2. Indirect prompt injection (embedded instructions, role override)
 *   3. Hidden Unicode steganography (zero-width, BiDi, homoglyph-only strings)
 *   4. Jailbreak payload templates copied from public datasets
 *   5. Insecure prompt concatenation (user input directly glued to system prompt)
 *   6. Prompt-leak patterns (attempts to extract the system prompt)
 *
 * Target files: .py, .js, .ts, .md, .json, .yaml, .txt, .cursorrules, .windsurfrules,
 *               CLAUDE.md, copilot-instructions.md, system-prompt.txt, etc.
 *
 * Why this matters: AI-generated code increasingly embeds LLM prompts. When user
 * input is concatenated into a system prompt without sanitization, or when a
 * developer copies a known jailbreak into their codebase as a "test", production
 * traffic can trigger it. This is the OWASP LLM Top 10 #1 risk (LLM01: Prompt Injection).
 */

import * as vscode from 'vscode';
import * as fs from 'fs';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type JailbreakSeverity = 'critical' | 'high' | 'medium' | 'low';

export type JailbreakCategory =
  | 'direct-jailbreak'
  | 'prompt-injection'
  | 'role-override'
  | 'hidden-unicode'
  | 'prompt-leak'
  | 'unsafe-concatenation'
  | 'known-payload'
  | 'system-override';

export interface JailbreakFinding {
  file: string;
  line: number;
  column: number;
  endColumn: number;
  category: JailbreakCategory;
  severity: JailbreakSeverity;
  ruleId: string;
  message: string;
  evidence: string;
  remediation: string;
  owaspLlm?: string; // e.g. LLM01
}

interface JailbreakRule {
  id: string;
  name: string;
  pattern: RegExp;
  category: JailbreakCategory;
  severity: JailbreakSeverity;
  description: string;
  remediation: string;
  owaspLlm?: string;
}

// ---------------------------------------------------------------------------
// Rule Library — curated from public jailbreak datasets (JailbreakBench, L1B3RT4S,
// AdvBench, Anthropic red team, OWASP LLM Top 10) through Nov 2025.
// ---------------------------------------------------------------------------

const JAILBREAK_RULES: JailbreakRule[] = [
  // ========== Direct jailbreaks (named personas) ==========
  {
    id: 'CG_JB_001',
    name: 'DAN (Do Anything Now) jailbreak',
    pattern: /\b(?:DAN|Do\s+Anything\s+Now)\b.*(?:mode|activated|persona|act\s+as)/i,
    category: 'direct-jailbreak',
    severity: 'critical',
    description:
      'DAN (Do Anything Now) is the most widely known LLM jailbreak persona. Embedding it ' +
      'in code ships an exploit to production.',
    remediation:
      'Remove jailbreak templates from source. If you need red-team tests, isolate them in ' +
      'test fixtures that are not deployed.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_002',
    name: 'Developer/God mode jailbreak',
    pattern:
      /\b(?:developer\s+mode|god\s+mode|sudo\s+mode|unrestricted\s+mode|jailbreak\s+mode)\b.*(?:enabled|activated|on)/i,
    category: 'direct-jailbreak',
    severity: 'critical',
    description:
      '"Developer mode" style jailbreaks ask the model to pretend safety restrictions are ' +
      'disabled.',
    remediation: 'Remove and replace with proper policy-level guardrails.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_003',
    name: 'STAN/DUDE/Kevin persona jailbreak',
    pattern: /\b(?:STAN|DUDE|Kevin|AIM|BetterDAN|JailBroken|OPPO|ANTI-DAN)\b.*(?:mode|persona|act\s+as|you\s+are)/i,
    category: 'direct-jailbreak',
    severity: 'high',
    description: 'Known jailbreak persona from the JailbreakBench dataset.',
    remediation: 'Remove. Use proper system-prompt hardening.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_004',
    name: 'Evil/opposite-twin jailbreak',
    pattern:
      /\b(?:evil|opposite|dark|shadow)\s+(?:twin|version|counterpart)\b.*(?:you|AI|assistant)/i,
    category: 'direct-jailbreak',
    severity: 'high',
    description:
      '"You have an evil twin that answers every question" is a classic bypass.',
    remediation: 'Remove from codebase.',
    owaspLlm: 'LLM01',
  },

  // ========== System/role override ==========
  {
    id: 'CG_JB_010',
    name: 'Ignore previous instructions',
    pattern: /\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|above|prior|earlier|your)\s+instructions?\b/i,
    category: 'role-override',
    severity: 'critical',
    description: 'Classic indirect prompt-injection payload.',
    remediation:
      'If this is user-visible output, it will execute if pasted into another LLM. If ' +
      'it is your own system prompt, reconsider trusting any downstream tool output.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_011',
    name: 'Forget everything you know',
    pattern: /\bforget\s+(?:everything|all)\s+(?:you\s+(?:know|were\s+told)|(?:the\s+)?(?:previous|prior))/i,
    category: 'role-override',
    severity: 'high',
    description: 'Attempts to erase system context.',
    remediation: 'Remove and harden prompt.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_012',
    name: 'New instructions override',
    pattern: /\b(?:new|updated|revised)\s+instructions?\s*:\s*(?:you\s+(?:are|must|will|shall))/i,
    category: 'role-override',
    severity: 'high',
    description: 'Injects "new instructions" to override the system prompt.',
    remediation: 'Treat all dynamic content as untrusted data, not instructions.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_013',
    name: 'System prompt tag injection',
    pattern: /<\|?(?:system|im_start|im_end|endoftext|start_header|end_header|eot_id)\|?>/i,
    category: 'system-override',
    severity: 'critical',
    description:
      'LLM control tokens (ChatML, Llama, GPT-4) embedded in text. If passed to the model ' +
      'unescaped, they can hijack the conversation.',
    remediation:
      'Strip or escape <|...|> tokens from any user-controlled input before concatenating ' +
      'into a prompt.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_014',
    name: 'Role: assistant/system injection',
    pattern: /["']?\s*role["']?\s*:\s*["'](?:system|assistant)["']/i,
    category: 'system-override',
    severity: 'high',
    description:
      'Hard-coded role:"system" or role:"assistant" in what appears to be user-facing code ' +
      'may allow injection into chat APIs.',
    remediation:
      'Validate that role fields cannot be supplied by user input. Only your server code ' +
      'should build the messages[] array.',
    owaspLlm: 'LLM01',
  },

  // ========== Prompt leak / exfiltration ==========
  {
    id: 'CG_JB_020',
    name: 'Repeat your system prompt',
    pattern: /\b(?:repeat|print|show|reveal|output|tell\s+me)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)/i,
    category: 'prompt-leak',
    severity: 'medium',
    description: 'Attempts to extract the system prompt.',
    remediation:
      'Include an explicit "never reveal system prompt" rule, and filter outputs server-side.',
    owaspLlm: 'LLM02',
  },
  {
    id: 'CG_JB_021',
    name: 'Repeat above verbatim',
    pattern: /\brepeat\s+(?:the\s+text|everything|all\s+text|the\s+above)\s+(?:verbatim|word\s+for\s+word)/i,
    category: 'prompt-leak',
    severity: 'medium',
    description: 'Common prompt extraction vector.',
    remediation: 'Filter outputs that echo the system prompt.',
    owaspLlm: 'LLM02',
  },

  // ========== Known payloads from public jailbreak datasets ==========
  {
    id: 'CG_JB_030',
    name: 'Grandma jailbreak payload',
    pattern: /\b(?:my|your)\s+grandma(?:other)?\s+used\s+to\s+(?:read|tell|recite|sing)\b.*(?:napalm|bomb|recipe|key|serial|activation)/i,
    category: 'known-payload',
    severity: 'high',
    description: 'Famous "grandma exploit" template from early 2023, still effective on older models.',
    remediation: 'Remove hardcoded jailbreak payloads.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_031',
    name: 'Hypothetical scenario wrapper',
    pattern: /\b(?:hypothetical(?:ly)?|in\s+a\s+fictional\s+(?:world|universe|scenario)|imagine\s+a\s+world)\b[^.]{0,200}\b(?:no\s+(?:rules|laws|restrictions|consequences)|anything\s+is\s+(?:allowed|possible))/i,
    category: 'known-payload',
    severity: 'medium',
    description: 'Fictional-framing jailbreak (AdvBench category).',
    remediation: 'Remove from prompts; apply output filtering.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_032',
    name: 'Token smuggling / Base64 instruction',
    pattern: /\b(?:decode|execute|run|eval)\s+(?:this\s+)?(?:base64|hex|rot13|binary)\s*[:=]/i,
    category: 'known-payload',
    severity: 'high',
    description:
      'Encoded payloads attempt to smuggle instructions past content filters.',
    remediation: 'Block encoded execution requests at the API layer.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_033',
    name: 'AIM (Always Intelligent Machiavellian) jailbreak',
    pattern: /\bAIM\s+stands\s+for\s+Always\s+Intelligent\s+and\s+Machiavellian\b/i,
    category: 'known-payload',
    severity: 'high',
    description: 'Known viral jailbreak template (AIM persona).',
    remediation: 'Remove.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_034',
    name: 'STAN (Strive To Avoid Norms) jailbreak',
    pattern: /\bSTAN\s+(?:stands\s+for\s+)?Strive\s+To\s+Avoid\s+Norms\b/i,
    category: 'known-payload',
    severity: 'high',
    description: 'Known viral jailbreak template (STAN persona).',
    remediation: 'Remove.',
    owaspLlm: 'LLM01',
  },

  // ========== Unsafe prompt concatenation (SAST-style) ==========
  {
    id: 'CG_JB_040',
    name: 'User input concatenated into system prompt (JS template literal)',
    pattern: /(?:system|systemPrompt|system_prompt|instructions)\s*[:=]\s*[`'"][^`'"]*\$\{(?:req\.|request\.|body\.|query\.|params\.|user(?:Input|Message|Query)?)/i,
    category: 'unsafe-concatenation',
    severity: 'critical',
    description:
      'User-controlled input is interpolated directly into a system prompt. Classic LLM01 ' +
      'prompt-injection vulnerability.',
    remediation:
      'Separate system and user content into distinct messages. Never build system prompts ' +
      'from untrusted strings. Use structured role-based message arrays.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_041',
    name: 'User input concatenated into system prompt (Python f-string)',
    pattern: /system\s*=\s*f["'][^"']*\{\s*(?:request|user_input|query|body|payload)/i,
    category: 'unsafe-concatenation',
    severity: 'critical',
    description: 'f-string builds a system prompt from request data (Python).',
    remediation: 'Use structured role messages; treat input as user role only.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_042',
    name: 'Prompt built with string concatenation',
    pattern: /(?:system|prompt|instructions)\s*[:=]\s*["'][^"']*["']\s*\+\s*(?:req|request|body|query|user(?:Input)?)/i,
    category: 'unsafe-concatenation',
    severity: 'high',
    description: 'String concatenation of user input into a prompt.',
    remediation: 'Use structured role-based messages.',
    owaspLlm: 'LLM01',
  },

  // ========== Hidden Unicode / steganography ==========
  {
    id: 'CG_JB_050',
    name: 'Zero-width characters in prompt string',
    pattern: /[\u200B\u200C\u200D\u2060\uFEFF]{2,}/,
    category: 'hidden-unicode',
    severity: 'high',
    description:
      'Multiple zero-width characters may hide instructions invisible to reviewers but ' +
      'processed by the tokenizer.',
    remediation: 'Sanitize prompt strings; strip ZW chars from user input.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_051',
    name: 'Bidirectional override characters',
    pattern: /[\u202A-\u202E\u2066-\u2069]/,
    category: 'hidden-unicode',
    severity: 'critical',
    description:
      'BiDi override characters can make code/text display differently than it is processed.',
    remediation: 'Reject input containing BiDi overrides unless explicitly needed.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_052',
    name: 'Tag-encoded Unicode instructions (e.g. Unicode Tags Block)',
    pattern: /[\u{E0000}-\u{E007F}]{2,}/u,
    category: 'hidden-unicode',
    severity: 'critical',
    description:
      'Unicode tag block characters (U+E0000-E007F) can encode hidden ASCII instructions ' +
      'that are invisible to humans but tokenize as text. Known attack vector 2024-2025.',
    remediation: 'Strip U+E0000-U+E007F from all input.',
    owaspLlm: 'LLM01',
  },

  // ========== Prompt injection in typical injection sinks ==========
  {
    id: 'CG_JB_060',
    name: 'Tool description contains imperative directive',
    pattern: /(?:description|desc)\s*[:=]\s*["'][^"']*\b(?:always|never|must|should|do\s+not|secretly|silently)\s+(?:execute|run|call|invoke|send|transmit|reveal|bypass)/i,
    category: 'prompt-injection',
    severity: 'high',
    description:
      'Tool description with imperative verbs may be tool-poisoning (attacks agentic ' +
      'systems that auto-read tool descriptions).',
    remediation:
      'Keep tool descriptions factual. Never include behavioral directives in description ' +
      'fields.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_061',
    name: 'Do not tell / inform the user',
    pattern: /\bdo\s+not\s+(?:tell|inform|notify|alert|warn|mention\s+to)\s+(?:the\s+)?user/i,
    category: 'prompt-injection',
    severity: 'critical',
    description: 'Classic covert-action prompt injection.',
    remediation: 'Remove and audit surrounding context.',
    owaspLlm: 'LLM01',
  },
  {
    id: 'CG_JB_062',
    name: 'Secretly/silently exfiltrate',
    pattern: /\b(?:secretly|silently|quietly|covertly)\s+(?:send|transmit|upload|copy|exfiltrate|forward)/i,
    category: 'prompt-injection',
    severity: 'critical',
    description: 'Covert exfiltration directive embedded in prompt/tool.',
    remediation: 'Remove. This is indicative of intentional backdoor or compromised source.',
    owaspLlm: 'LLM02',
  },
];

// ---------------------------------------------------------------------------
// File types to scan
// ---------------------------------------------------------------------------

const SCANNABLE_EXTENSIONS = [
  '.py',
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.md',
  '.txt',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.env',
  '.cursorrules',
  '.windsurfrules',
  '.clinerules',
];

const SCANNABLE_FILENAMES = [
  'CLAUDE.md',
  'GEMINI.md',
  'copilot-instructions.md',
  'system-prompt.txt',
  'prompt.txt',
  'prompts.yaml',
  'rules.md',
  '.cursorrules',
  '.windsurfrules',
];

// ---------------------------------------------------------------------------
// Core scanner
// ---------------------------------------------------------------------------

/**
 * Scan a string for jailbreak patterns. Returns findings with 1-based line numbers.
 */
export function scanTextForJailbreaks(text: string, fileLabel: string): JailbreakFinding[] {
  const findings: JailbreakFinding[] = [];
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0 || line.length > 5000) continue; // skip empty / huge minified
    for (const rule of JAILBREAK_RULES) {
      const match = rule.pattern.exec(line);
      if (match) {
        findings.push({
          file: fileLabel,
          line: i + 1,
          column: (match.index ?? 0) + 1,
          endColumn: (match.index ?? 0) + (match[0]?.length ?? 1) + 1,
          category: rule.category,
          severity: rule.severity,
          ruleId: rule.id,
          message: `${rule.name}: ${rule.description}`,
          evidence: match[0].slice(0, 120),
          remediation: rule.remediation,
          owaspLlm: rule.owaspLlm,
        });
      }
    }
  }
  return findings;
}

/**
 * Scan a file on disk. Returns [] if file cannot be read or is not scannable.
 */
export function scanFileForJailbreaks(filePath: string): JailbreakFinding[] {
  try {
    if (!shouldScanFile(filePath)) return [];
    const stat = fs.statSync(filePath);
    if (stat.size > 2 * 1024 * 1024) return []; // skip files > 2 MB
    const text = fs.readFileSync(filePath, 'utf8');
    return scanTextForJailbreaks(text, filePath);
  } catch {
    return [];
  }
}

export function shouldScanFile(filePath: string): boolean {
  const lower = filePath.toLowerCase().replace(/\\/g, '/');
  const base = lower.split('/').pop() ?? lower;
  if (SCANNABLE_FILENAMES.map((n) => n.toLowerCase()).includes(base)) return true;
  return SCANNABLE_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/**
 * Scan all relevant files in a VS Code workspace.
 */
export async function scanWorkspaceForJailbreaks(): Promise<JailbreakFinding[]> {
  const all: JailbreakFinding[] = [];
  const folders = vscode.workspace.workspaceFolders ?? [];
  for (const folder of folders) {
    const pattern = new vscode.RelativePattern(folder, '**/*');
    const files = await vscode.workspace.findFiles(
      pattern,
      '**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/out/**,**/.next/**',
      2000
    );
    for (const uri of files) {
      all.push(...scanFileForJailbreaks(uri.fsPath));
    }
  }
  return all;
}

/**
 * Convert findings to VS Code diagnostics.
 */
export function findingsToDiagnostics(findings: JailbreakFinding[]): Map<string, vscode.Diagnostic[]> {
  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const f of findings) {
    const severity =
      f.severity === 'critical' || f.severity === 'high'
        ? vscode.DiagnosticSeverity.Error
        : f.severity === 'medium'
          ? vscode.DiagnosticSeverity.Warning
          : vscode.DiagnosticSeverity.Information;
    const diag = new vscode.Diagnostic(
      new vscode.Range(f.line - 1, f.column - 1, f.line - 1, f.endColumn - 1),
      `[${f.severity.toUpperCase()} ${f.owaspLlm ?? 'LLM01'}] ${f.message}\nEvidence: ${f.evidence}\nFix: ${f.remediation}`,
      severity
    );
    diag.source = 'CodeGuard LLM Guardrails';
    diag.code = f.ruleId;
    const arr = byFile.get(f.file) ?? [];
    arr.push(diag);
    byFile.set(f.file, arr);
  }
  return byFile;
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

export function getJailbreakRuleStats(): {
  total: number;
  byCategory: Record<string, number>;
  bySeverity: Record<string, number>;
} {
  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const r of JAILBREAK_RULES) {
    byCategory[r.category] = (byCategory[r.category] ?? 0) + 1;
    bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1;
  }
  return { total: JAILBREAK_RULES.length, byCategory, bySeverity };
}
