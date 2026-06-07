/**
 * Agentic AI Security Scanner
 *
 * Detects security vulnerabilities specific to agentic AI systems — autonomous
 * agents that can read/write memory, call tools, spawn sub-agents, and execute
 * multi-step tasks with minimal human supervision.
 *
 * Based on:
 *   - OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)
 *   - Lasso Security / Lakera AI research on memory injection (Nov 2026)
 *   - Microsoft Defender AI research on Recommendation Poisoning (Feb 2026)
 *   - BeyondScale AI Agent Memory Poisoning Defense Guide 2026
 *   - Cisco AI Agent Security Scanner research
 *
 * Threat classes covered:
 *   1. Memory Poisoning (ASI06) — malicious data injected into agent memory stores
 *   2. Tool Misuse / Privilege Escalation (ASI03) — agents granted excess permissions
 *   3. Confused Deputy (ASI04) — agent tricked into acting on behalf of attacker
 *   4. Agent-to-Agent Injection (ASI07) — cross-agent prompt propagation
 *   5. Autonomous Action Without Confirmation (ASI01) — missing human-in-the-loop
 *   6. Insecure Tool Registration (ASI08) — unverified third-party tool bindings
 *   7. Over-privileged Agent Configs — too many file/shell/network permissions
 *   8. Leaked Agent Context — sensitive data in agent scratchpad/reasoning trace
 *
 * Scanned files: agent.json, .agent/, claude-code-config.json, agents/*.json,
 *                .github/copilot-agent.yml, langgraph configs, autogen configs,
 *                crewai configs, .cursor/agents/, *.agent.ts, *.agent.py
 */

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AgentSecSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AgentSecCategory =
  | 'memory-poisoning'
  | 'tool-misuse'
  | 'privilege-escalation'
  | 'confused-deputy'
  | 'agent-injection'
  | 'missing-human-loop'
  | 'insecure-tool-registration'
  | 'over-privileged-config'
  | 'leaked-context'
  | 'insecure-memory-store'
  | 'autonomous-destructive-action';

export interface AgentSecFinding {
  file: string;
  line: number;
  column: number;
  ruleId: string;
  category: AgentSecCategory;
  severity: AgentSecSeverity;
  title: string;
  detail: string;
  remediation: string;
  owaspAsi?: string; // e.g. ASI06
  evidence: string;
}

interface AgentSecRule {
  id: string;
  pattern: RegExp;
  category: AgentSecCategory;
  severity: AgentSecSeverity;
  title: string;
  detail: string;
  remediation: string;
  owaspAsi?: string;
}

// ---------------------------------------------------------------------------
// Rule Library — sourced from OWASP Agentic App Top 10 2026, Cisco research,
// Microsoft Defender AI, Lakera/Lasso security research.
// ---------------------------------------------------------------------------

const AGENT_SEC_RULES: AgentSecRule[] = [
  // ===== Memory Poisoning (ASI06) =====
  {
    id: 'CG_AGT_001',
    pattern: /memory\s*[=:]\s*["'`].*(?:ignore|forget|override|disregard|new\s+instruction)/i,
    category: 'memory-poisoning',
    severity: 'critical',
    title: 'Memory poisoning pattern in agent config',
    detail:
      'Instruction override directive found in an agent memory field. Attackers embed ' +
      '"ignore previous instructions" in data that gets stored in agent memory, causing ' +
      'persistent behavior modification. OWASP ASI06 — Memory & Context Poisoning.',
    remediation:
      'Sanitize all user-controlled data before writing to agent memory. ' +
      'Implement memory content validation with allowlisted instruction patterns. ' +
      'Use separate memory namespaces for user data vs system instructions.',
    owaspAsi: 'ASI06',
  },
  {
    id: 'CG_AGT_002',
    pattern: /(?:vector_store|memory_store|agent_memory|long_term_memory)\s*[=:]\s*\{[^}]*(?:user_input|req\.body|request\.data)/i,
    category: 'memory-poisoning',
    severity: 'critical',
    title: 'Unsanitized user input written directly to agent memory store',
    detail:
      'User-controlled data flows directly into the agent memory store without validation. ' +
      'This is the primary attack vector for persistent memory poisoning — attackers plant ' +
      'instructions that influence future agent behavior across sessions.',
    remediation:
      'Apply semantic filtering before memory writes. Use a separate "user data" memory tier ' +
      'with reduced trust. Validate memory entries against a schema before persisting.',
    owaspAsi: 'ASI06',
  },
  {
    id: 'CG_AGT_003',
    pattern: /RAG|retrieval.augmented|vectordb|chroma|pinecone|weaviate|qdrant|faiss/i,
    category: 'memory-poisoning',
    severity: 'medium',
    title: 'RAG vector store usage — ensure retrieval poisoning protection',
    detail:
      'RAG (Retrieval Augmented Generation) pipelines are vulnerable to indirect prompt injection: ' +
      'an attacker poisons a document in the knowledge base with hidden instructions. When retrieved, ' +
      'those instructions execute in the agent\'s context.',
    remediation:
      'Scan all documents before indexing with a prompt injection detector. ' +
      'Implement retrieval trust scoring. Separate internal knowledge from user-uploaded documents.',
    owaspAsi: 'ASI06',
  },

  // ===== Tool Misuse / Privilege Escalation (ASI03) =====
  {
    id: 'CG_AGT_010',
    pattern: /permissions?\s*[=:]\s*[\[{]["']?\*["']?/i,
    category: 'privilege-escalation',
    severity: 'critical',
    title: 'Wildcard permissions in agent tool config',
    detail:
      'Agent is granted wildcard (*) permissions for tool access. This violates the ' +
      'principle of least privilege and allows any tool invocation. If the agent is ' +
      'compromised via prompt injection, the attacker gains unrestricted tool access.',
    remediation:
      'Enumerate exactly which tools the agent needs. Replace * with an explicit allowlist. ' +
      'Follow OWASP ASI03 — implement scoped permissions per agent role.',
    owaspAsi: 'ASI03',
  },
  {
    id: 'CG_AGT_011',
    pattern: /allow_shell\s*[=:]\s*true|exec_shell\s*[=:]\s*true|shell_access\s*[=:]\s*true/i,
    category: 'privilege-escalation',
    severity: 'critical',
    title: 'Unrestricted shell access granted to AI agent',
    detail:
      'The agent configuration grants unrestricted shell command execution. ' +
      'A prompt injection or memory poisoning attack can weaponize this into arbitrary ' +
      'command execution on the host system.',
    remediation:
      'Remove shell access unless absolutely required. If needed, restrict to a ' +
      'curated command allowlist. Run agents in isolated containers. ' +
      'Log all shell invocations with full arguments.',
    owaspAsi: 'ASI03',
  },
  {
    id: 'CG_AGT_012',
    pattern: /(?:allow_file_write|write_files|file_write_access)\s*[=:]\s*(?:true|"all"|'all'|\*)/i,
    category: 'over-privileged-config',
    severity: 'high',
    title: 'Unrestricted file-write access in agent config',
    detail:
      'Agent can write to any file path. Combined with a prompt injection, this enables ' +
      'persistence mechanisms, config file tampering, or SSH key injection.',
    remediation:
      'Restrict file write access to a specific sandboxed directory. ' +
      'Use path allowlists, not blocklists.',
    owaspAsi: 'ASI03',
  },
  {
    id: 'CG_AGT_013',
    pattern: /max_iterations\s*[=:]\s*(?:[0-9]{4,}|999|unlimited|none|-1)/i,
    category: 'missing-human-loop',
    severity: 'high',
    title: 'Unbounded agent iteration limit',
    detail:
      'Agent has no meaningful iteration cap, enabling infinite autonomous action loops. ' +
      'Runaway agents can exhaust API quotas, delete data, or cause unexpected side effects.',
    remediation:
      'Set a reasonable max_iterations (≤50 for most tasks). ' +
      'Add checkpoints that require human confirmation before continuing past a threshold.',
    owaspAsi: 'ASI01',
  },

  // ===== Confused Deputy (ASI04) =====
  {
    id: 'CG_AGT_020',
    pattern: /system_prompt\s*[=:+].*\+.*(?:user_input|message\.content|req\.body|human_input)/i,
    category: 'confused-deputy',
    severity: 'critical',
    title: 'System prompt concatenated with untrusted user input',
    detail:
      'The agent system prompt is built by concatenating user-controlled input. ' +
      'This is the root cause of the confused deputy problem — the agent cannot ' +
      'distinguish between operator instructions and attacker injections. ' +
      'OWASP ASI04, LLM01.',
    remediation:
      'Never concatenate user input into system prompts. Use structured message ' +
      'formats with clear role separation (system / user / assistant). ' +
      'Apply input validation and prompt injection detection before constructing context.',
    owaspAsi: 'ASI04',
  },
  {
    id: 'CG_AGT_021',
    pattern: /trust_level\s*[=:]\s*["']?(?:high|full|admin|system|trusted)["']?.*(?:user|external|remote)/i,
    category: 'confused-deputy',
    severity: 'critical',
    title: 'High trust level assigned to external/user input source',
    detail:
      'An external or user-originating data source is being granted high trust. ' +
      'Confused deputy attacks exploit this: the agent acts on behalf of an attacker ' +
      'because it cannot distinguish their instructions from legitimate operator commands.',
    remediation:
      'Apply zero-trust to all external inputs. Maintain a strict trust hierarchy: ' +
      'system config > operator config > verified tools > user messages > external data.',
    owaspAsi: 'ASI04',
  },

  // ===== Agent-to-Agent Injection (ASI07) =====
  {
    id: 'CG_AGT_030',
    pattern: /sub_agent|spawn_agent|delegate_to|agent\.run\(|agent\.invoke\(/i,
    category: 'agent-injection',
    severity: 'medium',
    title: 'Agent spawns sub-agents — ensure injection isolation',
    detail:
      'Multi-agent orchestration detected. Prompt injections in the orchestrator agent ' +
      'can propagate to all sub-agents (OWASP ASI07). One compromised agent can poison ' +
      'the entire agent network.',
    remediation:
      'Implement inter-agent message validation. Pass structured data objects between ' +
      'agents, not raw strings. Apply prompt injection scanning at every agent boundary.',
    owaspAsi: 'ASI07',
  },
  {
    id: 'CG_AGT_031',
    pattern: /(?:crewai|langgraph|autogen|swarm|openai_agents|agentops).*(?:allow_delegation|full_self_play|recursive)/i,
    category: 'agent-injection',
    severity: 'high',
    title: 'Unconstrained agent delegation in multi-agent framework',
    detail:
      'Multi-agent framework configured with unrestricted delegation. In LangGraph, ' +
      'AutoGen, CrewAI, and similar frameworks, recursive delegation can cause ' +
      'unbounded agent spawning and cascading injection propagation.',
    remediation:
      'Set explicit agent role boundaries. Limit delegation depth (max 3 levels). ' +
      'Validate all inter-agent messages with the same scrutiny as user input.',
    owaspAsi: 'ASI07',
  },

  // ===== Missing Human-in-the-Loop (ASI01) =====
  {
    id: 'CG_AGT_040',
    pattern: /human_in_the_loop\s*[=:]\s*(?:false|0|"false"|'false')/i,
    category: 'missing-human-loop',
    severity: 'high',
    title: 'Human-in-the-loop explicitly disabled',
    detail:
      'The agent configuration explicitly disables human oversight. This removes the ' +
      'last defense against harmful autonomous actions. ' +
      'MCP specification (section 8.1) states: "there SHOULD always be a human in the ' +
      'loop with the ability to deny tool invocations."',
    remediation:
      'Enable human confirmation gates for irreversible actions (file deletion, ' +
      'API calls with side effects, external service invocations, code execution).',
    owaspAsi: 'ASI01',
  },
  {
    id: 'CG_AGT_041',
    pattern: /(?:confirm_actions?|require_approval|ask_permission)\s*[=:]\s*(?:false|0|never)/i,
    category: 'missing-human-loop',
    severity: 'high',
    title: 'Agent action confirmation disabled',
    detail:
      'Agent is configured to execute actions without requesting user confirmation. ' +
      'Autonomous destructive actions — deleting files, sending emails, calling APIs — ' +
      'cannot be reviewed before execution.',
    remediation:
      'Implement a confirmation step before any destructive or side-effectful action. ' +
      'Use a risk-based approach: read-only = auto-allow, writes = confirm.',
    owaspAsi: 'ASI01',
  },

  // ===== Insecure Tool Registration (ASI08) =====
  {
    id: 'CG_AGT_050',
    pattern: /(?:register_tool|add_tool|tool_registry).*(?:http:\/\/|raw\.githubusercontent|pastebin)/i,
    category: 'insecure-tool-registration',
    severity: 'critical',
    title: 'Agent tool registered from untrusted remote URL',
    detail:
      'An agent tool definition is being fetched from an untrusted or unauthenticated URL. ' +
      'A man-in-the-middle or supply chain attack can replace the tool definition with a ' +
      'malicious one. OWASP ASI08 — Insecure Tool Registration.',
    remediation:
      'Pin tool definitions to specific checksums. Use only verified, checksummed tool ' +
      'registries. Never fetch tool schemas from raw GitHub, pastebin, or HTTP URLs.',
    owaspAsi: 'ASI08',
  },
  {
    id: 'CG_AGT_051',
    pattern: /dynamic_tools?\s*[=:]\s*true|load_tools_from_registry\s*[=:]\s*true/i,
    category: 'insecure-tool-registration',
    severity: 'high',
    title: 'Dynamic tool loading enabled — risk of malicious tool injection',
    detail:
      'Agent can dynamically load tools at runtime from a registry. Without integrity ' +
      'verification, an attacker who compromises the registry can inject malicious tools.',
    remediation:
      'Verify tool signatures (SHA-256 or Sigstore) before loading. ' +
      'Maintain a local approved-tool manifest. Disable dynamic loading in production.',
    owaspAsi: 'ASI08',
  },

  // ===== Leaked Agent Context =====
  {
    id: 'CG_AGT_060',
    pattern: /(?:debug_mode|verbose_reasoning|expose_scratchpad|show_chain_of_thought)\s*[=:]\s*true/i,
    category: 'leaked-context',
    severity: 'medium',
    title: 'Agent reasoning/scratchpad exposed in debug mode',
    detail:
      'Debug mode exposes the agent\'s internal reasoning trace, scratchpad, and ' +
      'chain-of-thought to users. This can leak system prompts, tool credentials, ' +
      'and internal architecture details.',
    remediation:
      'Disable debug/verbose modes in production. Use a separate, sandboxed environment ' +
      'for agent debugging. Never expose reasoning traces to end users.',
    owaspAsi: 'ASI02',
  },
  {
    id: 'CG_AGT_061',
    pattern: /(?:log_all_messages|full_context_logging|log_system_prompt)\s*[=:]\s*true/i,
    category: 'leaked-context',
    severity: 'medium',
    title: 'Full agent context being logged — potential secret exposure',
    detail:
      'Complete agent context logging is enabled. Log files containing system prompts, ' +
      'API keys passed in context, and user PII can be inadvertently exposed or stolen.',
    remediation:
      'Implement structured log redaction. Scrub API keys, PII, and system prompt content ' +
      'from logs. Use log levels — debug logging should never reach production log streams.',
    owaspAsi: 'ASI02',
  },

  // ===== Autonomous Destructive Actions =====
  {
    id: 'CG_AGT_070',
    pattern: /allowed_operations?\s*[=:]\s*\[?["']?(?:delete|drop|truncate|rm|unlink|destroy|wipe)/i,
    category: 'autonomous-destructive-action',
    severity: 'critical',
    title: 'Destructive operations in agent allowed actions without confirmation gate',
    detail:
      'Agent is explicitly permitted to perform destructive operations (delete, drop, truncate) ' +
      'without a human confirmation requirement. A single prompt injection can trigger ' +
      'irreversible data loss.',
    remediation:
      'Destructive operations must always require explicit human confirmation. ' +
      'Implement a two-step confirmation for any irreversible action. ' +
      'Log and alert on all destructive operation attempts.',
    owaspAsi: 'ASI01',
  },
  {
    id: 'CG_AGT_071',
    pattern: /(?:auto_execute|auto_run|execute_without_review)\s*[=:]\s*true/i,
    category: 'autonomous-destructive-action',
    severity: 'high',
    title: 'Auto-execution enabled — code runs without review',
    detail:
      'Agent is configured to automatically execute generated code without review. ' +
      'LLM-generated code has a 45% rate of security vulnerabilities (Veracode 2026). ' +
      'Auto-execution removes the human review layer.',
    remediation:
      'Require explicit approval before executing any AI-generated code. ' +
      'Run generated code in a sandboxed environment first. ' +
      'Implement code scanning before execution.',
    owaspAsi: 'ASI01',
  },
];

// ---------------------------------------------------------------------------
// Known risky agent framework patterns
// ---------------------------------------------------------------------------

const RISKY_FRAMEWORK_PATTERNS: Array<{pattern: RegExp; name: string; risk: string}> = [
  {
    pattern: /from\s+autogen\s+import|import\s+autogen/i,
    name: 'AutoGen',
    risk: 'Multi-agent framework — verify inter-agent message validation and delegation limits',
  },
  {
    pattern: /from\s+crewai\s+import|import\s+crewai/i,
    name: 'CrewAI',
    risk: 'CrewAI agents can delegate freely — ensure delegation depth limits are set',
  },
  {
    pattern: /from\s+langgraph\s+import|import\s+langgraph/i,
    name: 'LangGraph',
    risk: 'LangGraph stateful agents maintain persistent memory — ensure memory is scoped per user',
  },
  {
    pattern: /openai.*agents|from\s+agents\s+import|@openai\/agents/i,
    name: 'OpenAI Agents SDK',
    risk: 'OpenAI Agents SDK — verify handoff validation and tool permission scoping',
  },
  {
    pattern: /anthropic.*computer_use|computer_use.*anthropic/i,
    name: 'Anthropic Computer Use',
    risk: 'Computer Use gives agent full desktop control — highest privilege level possible',
  },
];

// ---------------------------------------------------------------------------
// Agent config file detector
// ---------------------------------------------------------------------------

const AGENT_CONFIG_FILES = [
  'agent.json',
  'agents.json',
  '.agent',
  'claude-code-config.json',
  'copilot-agent.yml',
  '.copilot/agent.yml',
  'langgraph.json',
  'autogen_config.json',
  'crewai.yml',
  'crewai_config.yaml',
  'agent_config.yaml',
  'agent_config.json',
  'openai-agents.json',
];

// ---------------------------------------------------------------------------
// Main scan function
// ---------------------------------------------------------------------------

export function scanFileForAgentSecurity(
  filePath: string,
  content: string
): AgentSecFinding[] {
  const findings: AgentSecFinding[] = [];
  const lines = content.split('\n');
  const ext = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath).toLowerCase();

  // Only scan relevant files
  const isAgentConfig = AGENT_CONFIG_FILES.some(f => basename.includes(f.replace(/^\./, '')));
  const isCodeFile = ['.ts', '.js', '.py', '.yml', '.yaml', '.json', '.toml'].includes(ext);

  if (!isAgentConfig && !isCodeFile) {
    return findings;
  }

  // Apply all rules line by line
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const rule of AGENT_SEC_RULES) {
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
          owaspAsi: rule.owaspAsi,
          evidence: line.trim().substring(0, 150),
        });
      }
    }

    // Check for risky frameworks in source code
    if (['.ts', '.js', '.py'].includes(ext)) {
      for (const fw of RISKY_FRAMEWORK_PATTERNS) {
        if (fw.pattern.test(line)) {
          findings.push({
            file: filePath,
            line: lineNum,
            column: 1,
            ruleId: 'CG_AGT_FW_001',
            category: 'agent-injection',
            severity: 'info',
            title: `Agentic framework detected: ${fw.name}`,
            detail: fw.risk,
            remediation:
              'Ensure agent framework is configured with least-privilege tools, bounded iterations, ' +
              'human-in-the-loop checkpoints, and inter-agent message validation.',
            owaspAsi: 'ASI07',
            evidence: line.trim().substring(0, 150),
          });
          break; // one framework notice per line
        }
      }
    }
  }

  return deduplicate(findings);
}

// ---------------------------------------------------------------------------
// Workspace-level scan
// ---------------------------------------------------------------------------

export async function scanWorkspaceForAgentSecurity(
  workspaceFolders: readonly vscode.WorkspaceFolder[]
): Promise<AgentSecFinding[]> {
  const allFindings: AgentSecFinding[] = [];

  for (const folder of workspaceFolders) {
    const files = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, '**/*.{ts,js,py,json,yaml,yml,toml}'),
      '**/node_modules/**'
    );

    for (const fileUri of files) {
      try {
        const content = fs.readFileSync(fileUri.fsPath, 'utf8');
        const findings = scanFileForAgentSecurity(fileUri.fsPath, content);
        allFindings.push(...findings);
      } catch {
        // skip unreadable files
      }
    }
  }

  return allFindings;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function deduplicate(findings: AgentSecFinding[]): AgentSecFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.file}:${f.line}:${f.ruleId}`;
    if (seen.has(key)) { return false; }
    seen.add(key);
    return true;
  });
}

export function getAgentSecScannerStats(): {
  totalRules: number;
  categories: string[];
  owaspCoverage: string[];
} {
  const categories = [...new Set(AGENT_SEC_RULES.map(r => r.category))];
  const owaspCoverage = [...new Set(AGENT_SEC_RULES.map(r => r.owaspAsi).filter(Boolean) as string[])];
  return { totalRules: AGENT_SEC_RULES.length, categories, owaspCoverage };
}
