import * as vscode from 'vscode';

/**
 * Provides CodeActions (lightbulb quick-fixes) for CodeGuard diagnostics.
 * When a vulnerability is found, offers actions like "Update to safe version".
 */
export class CodeGuardCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'CodeGuard AI') { continue; }

      if (diagnostic.code === 'codeguard-hallucinated') {
        // Hallucinated package — offer to remove the line
        const removeAction = new vscode.CodeAction(
          `Remove hallucinated import`,
          vscode.CodeActionKind.QuickFix
        );
        removeAction.diagnostics = [diagnostic];
        removeAction.edit = new vscode.WorkspaceEdit();
        const fullLine = new vscode.Range(
          diagnostic.range.start.line, 0,
          diagnostic.range.start.line + 1, 0
        );
        removeAction.edit.delete(document.uri, fullLine);
        removeAction.isPreferred = false;
        actions.push(removeAction);

        // Offer to search for the real package
        const searchAction = new vscode.CodeAction(
          `Search npm/PyPI for similar packages`,
          vscode.CodeActionKind.QuickFix
        );
        searchAction.diagnostics = [diagnostic];
        searchAction.command = {
          command: 'vscode.open',
          title: 'Search for package',
          arguments: [vscode.Uri.parse(
            `https://www.npmjs.com/search?q=${encodeURIComponent(this.extractPackageName(diagnostic.message))}`
          )],
        };
        actions.push(searchAction);
      } else {
        // Vulnerable package — offer to view CVE details
        if (diagnostic.code && typeof diagnostic.code === 'object' && 'target' in diagnostic.code) {
          const viewAction = new vscode.CodeAction(
            `View vulnerability details (${(diagnostic.code as { value: string }).value})`,
            vscode.CodeActionKind.QuickFix
          );
          viewAction.diagnostics = [diagnostic];
          viewAction.command = {
            command: 'vscode.open',
            title: 'Open CVE details',
            arguments: [(diagnostic.code as { target: vscode.Uri }).target],
          };
          actions.push(viewAction);
        }

        // Extract fix version from diagnostic message if present
        const fixMatch = diagnostic.message.match(/Fix: update to (.+)/);
        if (fixMatch) {
          const fixVersion = fixMatch[1].trim();
          const updateAction = new vscode.CodeAction(
            `Update to safe version (${fixVersion})`,
            vscode.CodeActionKind.QuickFix
          );
          updateAction.diagnostics = [diagnostic];
          updateAction.isPreferred = true;

          // If this is a package.json, we can directly edit the version
          if (document.fileName.endsWith('package.json') || document.fileName.endsWith('requirements.txt')) {
            updateAction.edit = new vscode.WorkspaceEdit();
            const line = document.lineAt(diagnostic.range.start.line);
            const versionMatch = line.text.match(/"[^"]+"\s*:\s*"([^"]+)"/);
            if (versionMatch) {
              const oldVersion = versionMatch[1];
              const newText = line.text.replace(oldVersion, `^${fixVersion}`);
              updateAction.edit.replace(
                document.uri,
                line.range,
                newText
              );
            }
          }

          actions.push(updateAction);
        }

        // Add to ignore list
        const ignoreAction = new vscode.CodeAction(
          `Ignore "${this.extractPackageName(diagnostic.message)}" in CodeGuard`,
          vscode.CodeActionKind.QuickFix
        );
        ignoreAction.diagnostics = [diagnostic];
        ignoreAction.command = {
          command: 'codeguard.ignorePackage',
          title: 'Ignore package',
          arguments: [this.extractPackageName(diagnostic.message)],
        };
        actions.push(ignoreAction);
      }
    }

    return actions;
  }

  /**
   * Extract package name from diagnostic message.
   */
  private extractPackageName(message: string): string {
    const match = message.match(/"([^"]+)"/);
    return match ? match[1] : 'unknown';
  }
}
