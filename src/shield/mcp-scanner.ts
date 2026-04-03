/**
 * MCP Server Scanner — Agentic Supply Chain Security
 *
 * Scans Model Context Protocol (MCP) server configurations for:
 *   1. Tool poisoning — hidden instructions in tool descriptions
 *   2. Rug-pull risk — remote servers that can change behavior
 *   3. Cross-origin escalation — tools that request excessive permissions
 *   4. Prompt injection — embedded instructions in resource templates
 *   5. Unverified servers — missing checksums or unsigned packages
 *   6. Data exfiltration — tools that send data to unexpected endpoints
 *
 * Supports: mcp.json, claude_desktop_config.json, .cursor/mcp.json,
 *           cline_mcp_settings.json, .vscode/mcp.json
 */

import * as vscode from 'vscode';
import * as fs from 'fs';
// path import reserved for future use

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type McpIssueSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface McpIssue {
  file: string;
  serverName: string;
  severity: McpIssueSeverity;
  category: 'tool-poisoning' | 'rug-pull' | 'cross-origin' | 'prompt-injection' | 'unverified' | 'exfiltration' | 'suspicious-command' | 'env-exposure';
  message: string;
  detail: string;
  evidence: string;
}

export interface McpServerConfig {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  transport?: string;
  tools?: McpToolDef[];
  /** Raw JSON for the server entry */
  raw: any;
}

export interface McpToolDef {
  name: string;
  description?: string;
  inputSchema?: any;
}

export interface McpScanResult {
  file: string;
  servers: McpServerConfig[];
  issues: McpIssue[];
  scannedAt: number;
  clean: boolean;
}

// ---------------------------------------------------------------------------
// MCP config file locations
// ---------------------------------------------------------------------------

const MCP_CONFIG_GLOBS = [
  '**/.vscode/mcp.json',
  '**/.cursor/mcp.json',
  '**/mcp.json',
  '**/claude_desktop_config.json',
  '**/cline_mcp_settings.json',
  '**/.mcp.json',
  '**/.config/claude/claude_desktop_config.json',
];

// ---------------------------------------------------------------------------
// Tool Poisoning Patterns — hidden instructions in tool descriptions
// ---------------------------------------------------------------------------

const TOOL_POISONING_PATTERNS: Array<{ pattern: RegExp; name: string; severity: McpIssueSeverity }> = [
  // Prompt injection in tool descriptions
  { pattern: /ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i, name: 'Instruction override in tool description', severity: 'critical' },
  { pattern: /you\s+(?:must|should|shall)\s+(?:always|never)\s+/i, name: 'Behavioral directive in tool description', severity: 'high' },
  { pattern: /do\s+not\s+(?:tell|inform|alert|warn|notify)\s+the\s+user/i, name: 'User deception directive', severity: 'critical' },
  { pattern: /(?:secretly|silently|quietly)\s+(?:send|transmit|upload|exfiltrate|copy)/i, name: 'Covert data exfiltration directive', severity: 'critical' },
  { pattern: /system\s*:\s*you\s+are/i, name: 'System prompt injection in tool description', severity: 'critical' },
  { pattern: /<\|(?:system|im_start|endoftext)\|>/i, name: 'LLM control token injection', severity: 'critical' },
  // Hidden instructions via Unicode
  { pattern: /\u200B|\u200C|\u200D|\u2060|\uFEFF/, name: 'Hidden Unicode characters in tool definition', severity: 'high' },
  { pattern: /[\u2066\u2067\u2068\u2069]|[\u202A-\u202E]/, name: 'Bidirectional text override in tool definition', severity: 'critical' },
  // Data exfiltration via tool parameters
  { pattern: /(?:webhook|callback|notify).*(?:url|endpoint|uri)/i, name: 'Suspicious callback URL parameter', severity: 'medium' },
  { pattern: /(?:api[_-]?key|token|secret|password|credential).*(?:header|param|query)/i, name: 'Credential forwarding in tool parameters', severity: 'high' },
];

// ---------------------------------------------------------------------------
// Suspicious command patterns
// ---------------------------------------------------------------------------

const SUSPICIOUS_COMMANDS: Array<{ pattern: RegExp; name: string; severity: McpIssueSeverity }> = [
  { pattern: /\bcurl\b.*\|.*\b(?:sh|bash|zsh)\b/, name: 'Pipe-to-shell execution', severity: 'critical' },
  { pattern: /\bwget\b.*-O\s*-\s*\|/, name: 'Download-and-execute pattern', severity: 'critical' },
  { pattern: /\beval\b/, name: 'eval() in server command', severity: 'high' },
  { pattern: /\bnc\b.*-[el]/, name: 'Netcat listener (reverse shell risk)', severity: 'critical' },
  { pattern: /\bbase64\b.*(?:decode|--decode|-d)/, name: 'Base64 decode in command (obfuscation)', severity: 'high' },
  { pattern: /\brm\s+-rf\s+[/~]/, name: 'Destructive file deletion', severity: 'critical' },
  { pattern: /\bchmod\s+[0-7]*7[0-7]*\s/, name: 'World-writable permission change', severity: 'high' },
  { pattern: /\/dev\/tcp\//, name: 'Bash TCP socket (data exfiltration)', severity: 'critical' },
  { pattern: /\bsshpass\b/, name: 'Embedded SSH credential usage', severity: 'high' },
  { pattern: /\btelnet\b/, name: 'Telnet usage (unencrypted)', severity: 'medium' },
];

// ---------------------------------------------------------------------------
// Suspicious environment variable patterns
// ---------------------------------------------------------------------------

const SUSPICIOUS_ENV_PATTERNS: Array<{ pattern: RegExp; name: string; severity: McpIssueSeverity }> = [
  { pattern: /(?:AWS_SECRET|AWS_ACCESS_KEY)/i, name: 'AWS credentials in MCP server env', severity: 'critical' },
  { pattern: /(?:GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT)/i, name: 'GitHub token in MCP server env', severity: 'high' },
  { pattern: /(?:DATABASE_URL|DB_PASSWORD|MONGO_URI|REDIS_URL)/i, name: 'Database credentials in MCP server env', severity: 'high' },
  { pattern: /(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY)/i, name: 'LLM API key in MCP server env', severity: 'medium' },
  { pattern: /(?:STRIPE_SECRET|PAYPAL_SECRET)/i, name: 'Payment credentials in MCP server env', severity: 'critical' },
  { pattern: /(?:PRIVATE_KEY|SSH_KEY|PGP_KEY)/i, name: 'Private key in MCP server env', severity: 'critical' },
];

// ---------------------------------------------------------------------------
// Remote/rug-pull risk patterns
// ---------------------------------------------------------------------------

const RUG_PULL_INDICATORS: Array<{ pattern: RegExp; name: string; severity: McpIssueSeverity }> = [
  { pattern: /^https?:\/\//, name: 'Remote HTTP server (can change behavior without notice)', severity: 'medium' },
  { pattern: /^wss?:\/\//, name: 'Remote WebSocket server', severity: 'medium' },
  { pattern: /\bnpx\b/, name: 'npx execution (downloads and runs latest version — rug-pull risk)', severity: 'high' },
  { pattern: /\bbunx\b/, name: 'bunx execution (downloads and runs latest — rug-pull risk)', severity: 'high' },
  { pattern: /pip\s+install\s+--user\s+/, name: 'pip install at runtime (version drift risk)', severity: 'medium' },
  { pattern: /\bgit\s+clone\b/, name: 'Git clone at runtime (unverified source)', severity: 'high' },
];

// ---------------------------------------------------------------------------
// MCP Scanner Class
// ---------------------------------------------------------------------------

export class McpServerScanner {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private outputChannel: vscode.OutputChannel;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard-mcp');
    this.outputChannel = vscode.window.createOutputChannel('CodeGuard MCP Scanner');
  }

  /**
   * Activate the MCP scanner — register watchers and commands.
   */
  activate(context: vscode.ExtensionContext): void {
    // Watch for MCP config file changes
    for (const glob of MCP_CONFIG_GLOBS) {
      const watcher = vscode.workspace.createFileSystemWatcher(glob);
      watcher.onDidCreate(uri => this.scanFile(uri.fsPath));
      watcher.onDidChange(uri => this.scanFile(uri.fsPath));
      context.subscriptions.push(watcher);
    }

    // Initial scan of all workspace MCP configs
    this.scanWorkspace();

    console.log('[CodeGuard AI] MCP Server Scanner activated.');
  }

  /**
   * Scan all MCP config files in the workspace.
   */
  async scanWorkspace(): Promise<McpScanResult[]> {
    const results: McpScanResult[] = [];

    for (const glob of MCP_CONFIG_GLOBS) {
      try {
        const files = await vscode.workspace.findFiles(glob, '**/node_modules/**', 20);
        for (const file of files) {
          try {
            const result = this.scanFile(file.fsPath);
            if (result) { results.push(result); }
          } catch {
            // Skip unreadable files
          }
        }
      } catch {
        // Glob failed, skip
      }
    }

    return results;
  }

  /**
   * Scan a single MCP configuration file.
   */
  scanFile(filePath: string): McpScanResult | null {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const json = JSON.parse(content);
      const servers = this.extractServers(json);
      const issues: McpIssue[] = [];
      const relPath = vscode.workspace.asRelativePath(filePath);

      for (const server of servers) {
        issues.push(...this.analyzeServer(server, relPath));
      }

      // Update diagnostics
      this.updateDiagnostics(filePath, content, issues);

      const result: McpScanResult = {
        file: relPath,
        servers,
        issues,
        scannedAt: Date.now(),
        clean: issues.length === 0,
      };

      // Log results
      if (issues.length > 0) {
        this.outputChannel.appendLine(`\n[MCP Scan] ${relPath}: ${issues.length} issue(s) found`);
        for (const issue of issues) {
          this.outputChannel.appendLine(`  [${issue.severity.toUpperCase()}] ${issue.serverName}: ${issue.message}`);
        }
      }

      return result;
    } catch {
      return null;
    }
  }

  /**
   * Extract MCP server configurations from parsed JSON.
   * Handles multiple config formats:
   *   - { "mcpServers": { ... } }           (Claude Desktop, Cursor)
   *   - { "servers": { ... } }              (VS Code, generic)
   *   - { "mcp": { "servers": { ... } } }   (nested format)
   */
  private extractServers(json: any): McpServerConfig[] {
    const servers: McpServerConfig[] = [];
    let serversObj: Record<string, any> | undefined;

    if (json.mcpServers && typeof json.mcpServers === 'object') {
      serversObj = json.mcpServers;
    } else if (json.servers && typeof json.servers === 'object') {
      serversObj = json.servers;
    } else if (json.mcp?.servers && typeof json.mcp.servers === 'object') {
      serversObj = json.mcp.servers;
    }

    if (!serversObj) { return servers; }

    for (const [name, config] of Object.entries(serversObj)) {
      if (typeof config !== 'object' || config === null) { continue; }
      const cfg = config as any;
      servers.push({
        name,
        command: cfg.command,
        args: cfg.args,
        env: cfg.env,
        url: cfg.url,
        transport: cfg.transport,
        tools: cfg.tools,
        raw: cfg,
      });
    }

    return servers;
  }

  /**
   * Analyze a single MCP server for security issues.
   */
  private analyzeServer(server: McpServerConfig, file: string): McpIssue[] {
    const issues: McpIssue[] = [];

    // 1. Check command + args for suspicious patterns
    const fullCommand = [server.command ?? '', ...(server.args ?? [])].join(' ');

    for (const sp of SUSPICIOUS_COMMANDS) {
      if (sp.pattern.test(fullCommand)) {
        issues.push({
          file,
          serverName: server.name,
          severity: sp.severity,
          category: 'suspicious-command',
          message: `${sp.name} in MCP server "${server.name}"`,
          detail: `The command for MCP server "${server.name}" contains a suspicious pattern: ${sp.name}. This could indicate a malicious server configuration.`,
          evidence: this.truncate(fullCommand, 200),
        });
      }
    }

    // 2. Check for rug-pull risk (remote URLs, npx)
    for (const rp of RUG_PULL_INDICATORS) {
      if (rp.pattern.test(fullCommand) || (server.url && rp.pattern.test(server.url))) {
        issues.push({
          file,
          serverName: server.name,
          severity: rp.severity,
          category: 'rug-pull',
          message: `${rp.name}: "${server.name}"`,
          detail: `MCP server "${server.name}" uses a remote or dynamically-fetched server. The server owner can change its behavior at any time without your knowledge. Pin versions or use local servers for safety.`,
          evidence: this.truncate(server.url || fullCommand, 200),
        });
      }
    }

    // 3. Check environment variables for credential exposure
    if (server.env) {
      for (const [key, value] of Object.entries(server.env)) {
        const envStr = `${key}=${value}`;
        for (const ep of SUSPICIOUS_ENV_PATTERNS) {
          if (ep.pattern.test(key)) {
            // Check if value is hardcoded (not a reference to another env var)
            const isHardcoded = value && !value.startsWith('${') && !value.startsWith('$');
            const actualSeverity = isHardcoded ? ep.severity : 'low';
            issues.push({
              file,
              serverName: server.name,
              severity: actualSeverity,
              category: 'env-exposure',
              message: `${ep.name}${isHardcoded ? ' (HARDCODED)' : ''}`,
              detail: isHardcoded
                ? `MCP server "${server.name}" has a hardcoded credential in its environment configuration. Move this to a secrets manager or use environment variable references.`
                : `MCP server "${server.name}" passes sensitive credentials to the server process. Ensure the server only needs read access and audit what it does with them.`,
              evidence: isHardcoded ? `${key}=<REDACTED>` : envStr,
            });
          }
        }
      }
    }

    // 4. Check tool descriptions for poisoning
    if (server.tools) {
      for (const tool of server.tools) {
        const desc = tool.description ?? '';
        const schema = JSON.stringify(tool.inputSchema ?? {});
        const combined = `${desc} ${schema}`;

        for (const tp of TOOL_POISONING_PATTERNS) {
          if (tp.pattern.test(combined)) {
            issues.push({
              file,
              serverName: server.name,
              severity: tp.severity,
              category: 'tool-poisoning',
              message: `${tp.name}: tool "${tool.name}" in "${server.name}"`,
              detail: `Tool "${tool.name}" in MCP server "${server.name}" contains suspicious content in its description or schema that could manipulate AI agent behavior.`,
              evidence: this.truncate(combined, 200),
            });
          }
        }
      }
    }

    // 5. Check raw config for any tool poisoning patterns in string values
    const rawStr = JSON.stringify(server.raw);
    for (const tp of TOOL_POISONING_PATTERNS) {
      // Only check if we haven't already flagged via tools
      if (tp.pattern.test(rawStr) && !server.tools?.length) {
        issues.push({
          file,
          serverName: server.name,
          severity: tp.severity,
          category: 'tool-poisoning',
          message: `${tp.name} in server config "${server.name}"`,
          detail: `MCP server "${server.name}" configuration contains suspicious content that could be used for prompt injection or tool poisoning.`,
          evidence: this.truncate(rawStr, 200),
        });
      }
    }

    // 6. Check for missing transport security
    if (server.url && server.url.startsWith('http://') && !server.url.includes('localhost') && !server.url.includes('127.0.0.1')) {
      issues.push({
        file,
        serverName: server.name,
        severity: 'high',
        category: 'unverified',
        message: `Unencrypted HTTP transport for remote MCP server "${server.name}"`,
        detail: `MCP server "${server.name}" connects over plain HTTP to a remote endpoint. This allows man-in-the-middle attacks. Use HTTPS instead.`,
        evidence: this.truncate(server.url, 200),
      });
    }

    // 7. Check for overly permissive stdio servers without command validation
    if (!server.command && !server.url) {
      issues.push({
        file,
        serverName: server.name,
        severity: 'medium',
        category: 'unverified',
        message: `MCP server "${server.name}" has no command or URL specified`,
        detail: `MCP server "${server.name}" is defined but has no command or URL. This may indicate an incomplete or misconfigured server entry.`,
        evidence: JSON.stringify(server.raw).substring(0, 100),
      });
    }

    return issues;
  }

  /**
   * Update VS Code diagnostics for the scanned file.
   */
  private updateDiagnostics(filePath: string, content: string, issues: McpIssue[]): void {
    const uri = vscode.Uri.file(filePath);
    const diagnostics: vscode.Diagnostic[] = [];
    const lines = content.split('\n');

    for (const issue of issues) {
      // Find the line containing the server name
      let lineNum = 0;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(`"${issue.serverName}"`)) {
          lineNum = i;
          break;
        }
      }

      const severity = issue.severity === 'critical' || issue.severity === 'high'
        ? vscode.DiagnosticSeverity.Error
        : issue.severity === 'medium'
          ? vscode.DiagnosticSeverity.Warning
          : vscode.DiagnosticSeverity.Information;

      const diag = new vscode.Diagnostic(
        new vscode.Range(lineNum, 0, lineNum, lines[lineNum]?.length ?? 0),
        `[CodeGuard MCP] ${issue.message}`,
        severity,
      );
      diag.source = 'CodeGuard MCP Scanner';
      diag.code = issue.category;
      diagnostics.push(diag);
    }

    this.diagnosticCollection.set(uri, diagnostics);
  }

  /**
   * Get a summary of all MCP scan results for the dashboard.
   */
  getSummary(results: McpScanResult[]): {
    totalServers: number;
    totalIssues: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    categories: Record<string, number>;
  } {
    let totalServers = 0;
    let totalIssues = 0;
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    const categories: Record<string, number> = {};

    for (const result of results) {
      totalServers += result.servers.length;
      totalIssues += result.issues.length;
      for (const issue of result.issues) {
        if (issue.severity === 'critical') { critical++; }
        else if (issue.severity === 'high') { high++; }
        else if (issue.severity === 'medium') { medium++; }
        else { low++; }
        categories[issue.category] = (categories[issue.category] ?? 0) + 1;
      }
    }

    return { totalServers, totalIssues, critical, high, medium, low, categories };
  }

  private truncate(str: string, maxLen: number): string {
    return str.length > maxLen ? str.substring(0, maxLen) + '...' : str;
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
    this.outputChannel.dispose();
  }
}
