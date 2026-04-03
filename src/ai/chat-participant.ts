import * as vscode from 'vscode';
import { SecurityContextProvider } from './context';

/**
 * VS Code Chat Participant — registers @codeguard in Copilot Chat.
 * Users can ask "@codeguard is this code safe?" and get security analysis.
 * 
 * Note: The Chat Participant API requires VS Code 1.93+ and GitHub Copilot Chat.
 * This gracefully degrades if the API is unavailable.
 */

export class CodeGuardChatParticipant {
  private participant: vscode.ChatParticipant | undefined;
  private contextProvider: SecurityContextProvider;

  constructor(contextProvider: SecurityContextProvider) {
    this.contextProvider = contextProvider;
  }

  /**
   * Register the @codeguard chat participant.
   * Returns true if registration succeeded.
   */
  register(context: vscode.ExtensionContext): boolean {
    try {
      // Check if Chat Participant API is available
      if (!vscode.chat || !vscode.chat.createChatParticipant) {
        console.log('[CodeGuard] Chat Participant API not available — skipping registration');
        return false;
      }

      this.participant = vscode.chat.createChatParticipant(
        'codeguard-ai.security',
        this.handleRequest.bind(this)
      );
      this.participant.iconPath = vscode.Uri.joinPath(context.extensionUri, 'assets', 'icon.svg');

      context.subscriptions.push(this.participant);
      console.log('[CodeGuard] Chat Participant @codeguard registered');
      return true;
    } catch (error) {
      console.log('[CodeGuard] Chat Participant registration failed (API may not be available):', error);
      return false;
    }
  }

  /**
   * Handle chat requests from users.
   */
  private async handleRequest(
    request: vscode.ChatRequest,
    chatContext: vscode.ChatContext,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken
  ): Promise<vscode.ChatResult> {
    const query = request.prompt.toLowerCase();

    // Get current security context
    const securityContext = this.contextProvider.getContext();

    // Route to appropriate handler
    if (query.includes('scan') || query.includes('check') || query.includes('safe')) {
      return this.handleScanRequest(stream, securityContext);
    }

    if (query.includes('fix') || query.includes('update') || query.includes('resolve')) {
      return this.handleFixRequest(stream, securityContext);
    }

    if (query.includes('hallucin') || query.includes('fake') || query.includes('exist')) {
      return this.handleHallucinationRequest(stream, securityContext);
    }

    if (query.includes('status') || query.includes('dashboard') || query.includes('summary')) {
      return this.handleStatusRequest(stream, securityContext);
    }

    // Default: show current security status
    return this.handleStatusRequest(stream, securityContext);
  }

  private async handleScanRequest(
    stream: vscode.ChatResponseStream,
    ctx: ReturnType<SecurityContextProvider['getContext']>
  ): Promise<vscode.ChatResult> {
    stream.markdown('## 🛡️ CodeGuard Security Scan\n\n');

    if (ctx.vulnerablePackages.length === 0 && ctx.hallucinatedPackages.length === 0) {
      stream.markdown('✅ **No security issues found** in the current workspace.\n\n');
      stream.markdown('All imported packages have been verified against vulnerability databases and package registries.\n');
      return { metadata: { command: 'scan' } };
    }

    if (ctx.vulnerablePackages.length > 0) {
      stream.markdown(`### ⚠️ ${ctx.vulnerablePackages.length} Vulnerable Package(s)\n\n`);
      for (const pkg of ctx.vulnerablePackages) {
        stream.markdown(`- **${pkg.name}@${pkg.version || 'latest'}** — `);
        stream.markdown(`${pkg.cves.join(', ')} [${pkg.severity}]\n`);
        if (pkg.fixVersion) {
          stream.markdown(`  - ✅ Fix: Update to \`${pkg.fixVersion}\`\n`);
        }
      }
      stream.markdown('\n');
    }

    if (ctx.hallucinatedPackages.length > 0) {
      stream.markdown(`### 🚨 ${ctx.hallucinatedPackages.length} Hallucinated Package(s)\n\n`);
      for (const pkg of ctx.hallucinatedPackages) {
        stream.markdown(`- **${pkg.name}** — Does not exist on ${pkg.ecosystem}`);
        if (pkg.suggestion) {
          stream.markdown(` (did you mean \`${pkg.suggestion}\`?)`);
        }
        stream.markdown('\n');
      }
      stream.markdown('\n');
    }

    stream.markdown('---\n');
    stream.markdown('*Use `@codeguard fix` for remediation suggestions.*\n');
    return { metadata: { command: 'scan' } };
  }

  private async handleFixRequest(
    stream: vscode.ChatResponseStream,
    ctx: ReturnType<SecurityContextProvider['getContext']>
  ): Promise<vscode.ChatResult> {
    stream.markdown('## 🔧 CodeGuard Fix Suggestions\n\n');

    if (ctx.vulnerablePackages.length === 0 && ctx.hallucinatedPackages.length === 0) {
      stream.markdown('✅ Nothing to fix — all packages are clean!\n');
      return { metadata: { command: 'fix' } };
    }

    for (const pkg of ctx.vulnerablePackages) {
      stream.markdown(`### ${pkg.name}\n\n`);
      if (pkg.fixVersion) {
        stream.markdown(`Update to the safe version:\n\n`);
        stream.markdown(`\`\`\`\nnpm install ${pkg.name}@${pkg.fixVersion}\n\`\`\`\n\n`);
      } else {
        stream.markdown(`No fix version available. Consider using an alternative:\n\n`);
        if (pkg.alternatives && pkg.alternatives.length > 0) {
          for (const alt of pkg.alternatives) {
            stream.markdown(`- \`${alt}\`\n`);
          }
        } else {
          stream.markdown(`- Search for alternatives at [npmjs.com](https://www.npmjs.com/search?q=${encodeURIComponent(pkg.name)})\n`);
        }
      }
      stream.markdown('\n');
    }

    for (const pkg of ctx.hallucinatedPackages) {
      stream.markdown(`### ${pkg.name} (Hallucinated)\n\n`);
      stream.markdown(`This package **does not exist**. `);
      if (pkg.suggestion) {
        stream.markdown(`You probably meant **${pkg.suggestion}**:\n\n`);
        stream.markdown(`\`\`\`\nnpm install ${pkg.suggestion}\n\`\`\`\n\n`);
      } else {
        stream.markdown(`Remove this import and search for a real alternative.\n\n`);
      }
    }

    return { metadata: { command: 'fix' } };
  }

  private async handleHallucinationRequest(
    stream: vscode.ChatResponseStream,
    ctx: ReturnType<SecurityContextProvider['getContext']>
  ): Promise<vscode.ChatResult> {
    stream.markdown('## 👻 Hallucination Detection Report\n\n');

    stream.markdown('**What is package hallucination?**\n\n');
    stream.markdown('AI models sometimes generate package names that don\'t exist. ');
    stream.markdown('This is called "slopsquatting" — attackers monitor AI outputs, ');
    stream.markdown('identify commonly hallucinated names, then register those names on npm/PyPI ');
    stream.markdown('with malware. When developers blindly `npm install` the AI\'s suggestion, ');
    stream.markdown('they install the attacker\'s malicious code.\n\n');

    if (ctx.hallucinatedPackages.length === 0) {
      stream.markdown('✅ **No hallucinated packages detected** in current workspace.\n');
    } else {
      stream.markdown(`🚨 **${ctx.hallucinatedPackages.length} hallucinated package(s) found:**\n\n`);
      for (const pkg of ctx.hallucinatedPackages) {
        stream.markdown(`- **${pkg.name}** — Not found on ${pkg.ecosystem}`);
        if (pkg.suggestion) {
          stream.markdown(` → Try \`${pkg.suggestion}\` instead`);
        }
        stream.markdown('\n');
      }
    }

    return { metadata: { command: 'hallucination' } };
  }

  private async handleStatusRequest(
    stream: vscode.ChatResponseStream,
    ctx: ReturnType<SecurityContextProvider['getContext']>
  ): Promise<vscode.ChatResult> {
    const score = ctx.securityScore;
    const scoreEmoji = score >= 80 ? '🟢' : score >= 50 ? '🟡' : '🔴';

    stream.markdown('## 🛡️ CodeGuard AI — Security Status\n\n');
    stream.markdown(`**Security Score:** ${scoreEmoji} ${score}/100\n\n`);
    stream.markdown(`| Metric | Count |\n|--------|-------|\n`);
    stream.markdown(`| Packages Scanned | ${ctx.totalScanned} |\n`);
    stream.markdown(`| Vulnerable | ${ctx.vulnerablePackages.length} |\n`);
    stream.markdown(`| Hallucinated | ${ctx.hallucinatedPackages.length} |\n`);
    stream.markdown(`| Clean | ${ctx.totalScanned - ctx.vulnerablePackages.length - ctx.hallucinatedPackages.length} |\n\n`);

    stream.markdown('**Commands:**\n');
    stream.markdown('- `@codeguard scan` — Full security scan\n');
    stream.markdown('- `@codeguard fix` — Get fix suggestions\n');
    stream.markdown('- `@codeguard hallucination` — Hallucination detection report\n');

    return { metadata: { command: 'status' } };
  }

  dispose(): void {
    // participant is disposed via context.subscriptions
  }
}
