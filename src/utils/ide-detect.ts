/**
 * Shared IDE & AI Agent Detection Utilities
 *
 * Detects the current IDE and active AI agent extensions.
 * Used by Install Gate, GHIN Client, and Telemetry Reporter.
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type IdeSlug =
    | 'vscode' | 'cursor' | 'windsurf' | 'jetbrains' | 'neovim'
    | 'vscode-web' | 'github-codespaces' | 'unknown';

export type AiAgentSlug =
    | 'copilot' | 'copilot-chat' | 'chatgpt' | 'claude'
    | 'cursor-ai' | 'windsurf-cascade' | 'codewhisperer'
    | 'cody' | 'gemini-code-assist' | 'tabnine'
    | 'manual' | 'unknown';

export type AiInteractionType =
    | 'inline_completion' | 'chat_response' | 'agent_action' | 'manual';

export interface IdeContext {
    ide: IdeSlug;
    ideVersion: string;
}

export interface AiAgentContext {
    aiAgent: AiAgentSlug;
    aiAgentVersion: string;
}

// ---------------------------------------------------------------------------
// IDE Detection
// ---------------------------------------------------------------------------

/**
 * Detect which IDE is running this extension.
 * VS Code, Cursor, and Windsurf all use the VS Code extension API but expose
 * different app names via vscode.env.appName.
 */
export function detectIde(): IdeContext {
    const appName = (vscode.env.appName ?? '').toLowerCase();
    const version = vscode.version ?? 'unknown';

    if (appName.includes('cursor')) {
        return { ide: 'cursor', ideVersion: version };
    }
    if (appName.includes('windsurf')) {
        return { ide: 'windsurf', ideVersion: version };
    }
    if (appName.includes('codespaces') || appName.includes('github.dev')) {
        return { ide: 'github-codespaces', ideVersion: version };
    }
    if (appName.includes('visual studio code') || appName.includes('vscode') || appName.includes('code')) {
        return { ide: 'vscode', ideVersion: version };
    }
    return { ide: 'unknown', ideVersion: version };
}

// ---------------------------------------------------------------------------
// AI Agent Detection
// ---------------------------------------------------------------------------

/**
 * Detect which AI agent extensions are currently active.
 * Returns the most likely agent based on installed/active extensions.
 */
export function detectAiAgent(): AiAgentContext {
    const extensions = vscode.extensions.all;

    const find = (id: string) => extensions.find(e => e.id.toLowerCase() === id.toLowerCase());

    // Check in priority order (most specific first)
    const cursorExt = find('cursor.cursor');
    if (cursorExt) {
        return { aiAgent: 'cursor-ai', aiAgentVersion: cursorExt.packageJSON?.version ?? 'unknown' };
    }

    const windsurfExt = find('codeium.windsurf') ?? find('codeium.codeium');
    if (windsurfExt) {
        return { aiAgent: 'windsurf-cascade', aiAgentVersion: windsurfExt.packageJSON?.version ?? 'unknown' };
    }

    const copilotExt = find('github.copilot-chat') ?? find('github.copilot');
    if (copilotExt) {
        const isChatOnly = !!find('github.copilot-chat');
        return {
            aiAgent: isChatOnly ? 'copilot-chat' : 'copilot',
            aiAgentVersion: copilotExt.packageJSON?.version ?? 'unknown',
        };
    }

    const codyExt = find('sourcegraph.cody-ai');
    if (codyExt) {
        return { aiAgent: 'cody', aiAgentVersion: codyExt.packageJSON?.version ?? 'unknown' };
    }

    const tabnineExt = find('tabnine.tabnine-vscode');
    if (tabnineExt) {
        return { aiAgent: 'tabnine', aiAgentVersion: tabnineExt.packageJSON?.version ?? 'unknown' };
    }

    const codewhispererExt = find('amazonwebservices.aws-toolkit-vscode');
    if (codewhispererExt) {
        return { aiAgent: 'codewhisperer', aiAgentVersion: codewhispererExt.packageJSON?.version ?? 'unknown' };
    }

    const geminiExt = find('google.cloudcode') ?? find('google.gemini-code-assist');
    if (geminiExt) {
        return { aiAgent: 'gemini-code-assist', aiAgentVersion: geminiExt.packageJSON?.version ?? 'unknown' };
    }

    return { aiAgent: 'unknown', aiAgentVersion: 'unknown' };
}
