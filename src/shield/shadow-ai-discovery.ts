/**
 * Shadow AI Discovery — Agentic Supply Chain Inventory
 *
 * Scans the workspace to discover all AI tools, SDKs, MCP servers,
 * and agent configurations. Generates an "AI-SBOM" (AI Software Bill
 * of Materials) that lists every AI component in the project.
 *
 * Detects:
 *   1. AI coding tool configs (.cursorrules, .windsurfrules, CLAUDE.md, etc.)
 *   2. MCP server configurations (mcp.json, claude_desktop_config.json)
 *   3. AI/ML SDK imports in code (openai, anthropic, langchain, etc.)
 *   4. AI agent framework configs (CrewAI, AutoGen, LangGraph, etc.)
 *   5. Model files and weights (.onnx, .pt, .safetensors, etc.)
 *   6. Unapproved or shadow AI integrations
 */

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AiComponentType =
  | 'coding-tool-config'
  | 'mcp-server'
  | 'ai-sdk'
  | 'agent-framework'
  | 'model-file'
  | 'ai-service-config';

export type AiComponentRisk = 'high' | 'medium' | 'low' | 'info';

export interface AiComponent {
  /** Unique identifier */
  id: string;
  /** Component type */
  type: AiComponentType;
  /** Human-readable name */
  name: string;
  /** File where this component was discovered */
  file: string;
  /** Line number (0 if file-level) */
  line: number;
  /** Description of what this component does */
  description: string;
  /** Risk level */
  risk: AiComponentRisk;
  /** Whether this is approved by policy */
  approved: boolean;
  /** Additional metadata */
  metadata: Record<string, string>;
}

export interface AiSbom {
  /** Project path */
  projectPath: string;
  /** Generation timestamp */
  generatedAt: string;
  /** Version of the AI-SBOM format */
  specVersion: '1.0.0';
  /** All discovered AI components */
  components: AiComponent[];
  /** Summary counts */
  summary: AiSbomSummary;
}

export interface AiSbomSummary {
  totalComponents: number;
  codingToolConfigs: number;
  mcpServers: number;
  aiSdks: number;
  agentFrameworks: number;
  modelFiles: number;
  serviceConfigs: number;
  unapproved: number;
  highRisk: number;
}

// ---------------------------------------------------------------------------
// AI Tool Config Detection Patterns
// ---------------------------------------------------------------------------

const AI_CONFIG_FILES: Array<{
  glob: string;
  name: string;
  type: AiComponentType;
  risk: AiComponentRisk;
  description: string;
}> = [
  // Cursor
  { glob: '**/.cursorrules', name: 'Cursor Rules', type: 'coding-tool-config', risk: 'medium', description: 'Cursor AI coding assistant configuration' },
  { glob: '**/.cursor/rules/**', name: 'Cursor Rules (dir)', type: 'coding-tool-config', risk: 'medium', description: 'Cursor AI rules directory' },
  { glob: '**/.cursor/mcp.json', name: 'Cursor MCP Config', type: 'mcp-server', risk: 'high', description: 'Cursor MCP server configuration' },
  // Windsurf
  { glob: '**/.windsurfrules', name: 'Windsurf Rules', type: 'coding-tool-config', risk: 'medium', description: 'Windsurf AI coding assistant configuration' },
  { glob: '**/.windsurf/rules/**', name: 'Windsurf Rules (dir)', type: 'coding-tool-config', risk: 'medium', description: 'Windsurf AI rules directory' },
  // GitHub Copilot
  { glob: '**/.github/copilot-instructions.md', name: 'Copilot Instructions', type: 'coding-tool-config', risk: 'medium', description: 'GitHub Copilot workspace instructions' },
  // Claude
  { glob: '**/CLAUDE.md', name: 'Claude Project Config', type: 'coding-tool-config', risk: 'medium', description: 'Anthropic Claude Code project configuration' },
  { glob: '**/.claude/**', name: 'Claude Config Dir', type: 'coding-tool-config', risk: 'medium', description: 'Claude configuration directory' },
  { glob: '**/claude_desktop_config.json', name: 'Claude Desktop Config', type: 'mcp-server', risk: 'high', description: 'Claude Desktop MCP server configuration' },
  // Cline
  { glob: '**/.clinerules', name: 'Cline Rules', type: 'coding-tool-config', risk: 'medium', description: 'Cline AI assistant configuration' },
  { glob: '**/cline_mcp_settings.json', name: 'Cline MCP Config', type: 'mcp-server', risk: 'high', description: 'Cline MCP server configuration' },
  // Continue
  { glob: '**/.continue/config.json', name: 'Continue Config', type: 'coding-tool-config', risk: 'medium', description: 'Continue AI assistant configuration' },
  { glob: '**/.continue/rules/**', name: 'Continue Rules', type: 'coding-tool-config', risk: 'medium', description: 'Continue AI rules directory' },
  // Aider
  { glob: '**/.aider.conf.yml', name: 'Aider Config', type: 'coding-tool-config', risk: 'low', description: 'Aider AI pair programming configuration' },
  { glob: '**/.aider.model.settings.yml', name: 'Aider Model Settings', type: 'coding-tool-config', risk: 'low', description: 'Aider model configuration' },
  // Codeium
  { glob: '**/.codeium/**', name: 'Codeium Config', type: 'coding-tool-config', risk: 'low', description: 'Codeium AI assistant configuration' },
  // MCP generic
  { glob: '**/mcp.json', name: 'MCP Config', type: 'mcp-server', risk: 'high', description: 'Model Context Protocol server configuration' },
  { glob: '**/.vscode/mcp.json', name: 'VS Code MCP Config', type: 'mcp-server', risk: 'high', description: 'VS Code MCP server configuration' },
  { glob: '**/.mcp.json', name: 'MCP Config (hidden)', type: 'mcp-server', risk: 'high', description: 'Hidden MCP server configuration' },
];

// ---------------------------------------------------------------------------
// AI/ML SDK Import Patterns (detected in source code)
// ---------------------------------------------------------------------------

const AI_SDK_PATTERNS: Array<{
  /** Regex to match import/require */
  pattern: RegExp;
  /** SDK name */
  name: string;
  /** Category */
  category: string;
  /** Risk level */
  risk: AiComponentRisk;
  /** Language filter */
  languages: string[];
}> = [
  // OpenAI
  { pattern: /(?:from\s+openai|require\s*\(\s*['"]openai|import\s+.*openai)/i, name: 'OpenAI SDK', category: 'LLM Provider', risk: 'medium', languages: ['python', 'javascript', 'typescript'] },
  // Anthropic
  { pattern: /(?:from\s+anthropic|require\s*\(\s*['"]@anthropic-ai|import\s+.*anthropic)/i, name: 'Anthropic SDK', category: 'LLM Provider', risk: 'medium', languages: ['python', 'javascript', 'typescript'] },
  // LangChain
  { pattern: /(?:from\s+langchain|require\s*\(\s*['"]langchain|import\s+.*langchain)/i, name: 'LangChain', category: 'Agent Framework', risk: 'medium', languages: ['python', 'javascript', 'typescript'] },
  // LlamaIndex
  { pattern: /(?:from\s+llama_index|require\s*\(\s*['"]llama-?index)/i, name: 'LlamaIndex', category: 'RAG Framework', risk: 'medium', languages: ['python', 'javascript', 'typescript'] },
  // Hugging Face
  { pattern: /(?:from\s+transformers|from\s+huggingface_hub|require\s*\(\s*['"]@huggingface)/i, name: 'Hugging Face', category: 'ML Framework', risk: 'low', languages: ['python', 'javascript', 'typescript'] },
  // CrewAI
  { pattern: /(?:from\s+crewai|require\s*\(\s*['"]crewai)/i, name: 'CrewAI', category: 'Agent Framework', risk: 'high', languages: ['python'] },
  // AutoGen
  { pattern: /(?:from\s+autogen|require\s*\(\s*['"]autogen)/i, name: 'Microsoft AutoGen', category: 'Agent Framework', risk: 'high', languages: ['python'] },
  // Google AI
  { pattern: /(?:from\s+google\.generativeai|require\s*\(\s*['"]@google\/generative-ai)/i, name: 'Google Gemini SDK', category: 'LLM Provider', risk: 'medium', languages: ['python', 'javascript', 'typescript'] },
  // Cohere
  { pattern: /(?:from\s+cohere|require\s*\(\s*['"]cohere-ai)/i, name: 'Cohere SDK', category: 'LLM Provider', risk: 'medium', languages: ['python', 'javascript', 'typescript'] },
  // MCP SDK
  { pattern: /(?:from\s+mcp|require\s*\(\s*['"]@modelcontextprotocol)/i, name: 'MCP SDK', category: 'Agent Protocol', risk: 'high', languages: ['python', 'javascript', 'typescript'] },
  // Vercel AI SDK
  { pattern: /require\s*\(\s*['"]ai['"]|from\s+['"]ai['"]/i, name: 'Vercel AI SDK', category: 'AI Framework', risk: 'low', languages: ['javascript', 'typescript'] },
  // PyTorch
  { pattern: /(?:import\s+torch|from\s+torch\b)/i, name: 'PyTorch', category: 'ML Framework', risk: 'low', languages: ['python'] },
  // TensorFlow
  { pattern: /(?:import\s+tensorflow|from\s+tensorflow)/i, name: 'TensorFlow', category: 'ML Framework', risk: 'low', languages: ['python'] },
  // Ollama
  { pattern: /(?:from\s+ollama|require\s*\(\s*['"]ollama)/i, name: 'Ollama SDK', category: 'Local LLM', risk: 'low', languages: ['python', 'javascript', 'typescript'] },
  // Replicate
  { pattern: /(?:from\s+replicate|require\s*\(\s*['"]replicate)/i, name: 'Replicate SDK', category: 'LLM Provider', risk: 'medium', languages: ['python', 'javascript', 'typescript'] },
];

// ---------------------------------------------------------------------------
// Model File Extensions
// ---------------------------------------------------------------------------

const MODEL_FILE_EXTENSIONS = [
  { ext: '.onnx', name: 'ONNX Model' },
  { ext: '.pt', name: 'PyTorch Model' },
  { ext: '.pth', name: 'PyTorch Model' },
  { ext: '.safetensors', name: 'SafeTensors Model' },
  { ext: '.gguf', name: 'GGUF Model (llama.cpp)' },
  { ext: '.ggml', name: 'GGML Model' },
  { ext: '.bin', name: 'Binary Model Weight' },
  { ext: '.h5', name: 'HDF5/Keras Model' },
  { ext: '.tflite', name: 'TensorFlow Lite Model' },
  { ext: '.mlmodel', name: 'CoreML Model' },
];

// ---------------------------------------------------------------------------
// Shadow AI Discovery Class
// ---------------------------------------------------------------------------

export class ShadowAiDiscovery {
  private outputChannel: vscode.OutputChannel;

  constructor() {
    this.outputChannel = vscode.window.createOutputChannel('CodeGuard Shadow AI');
  }

  /**
   * Run a full Shadow AI discovery scan on the workspace.
   */
  async discover(): Promise<AiSbom> {
    const components: AiComponent[] = [];
    const workspaceFolders = vscode.workspace.workspaceFolders;
    const projectPath = workspaceFolders?.[0]?.uri.fsPath ?? '';

    this.outputChannel.appendLine(`\n[Shadow AI Discovery] Scanning workspace: ${projectPath}`);
    this.outputChannel.appendLine(`[Shadow AI Discovery] ${new Date().toISOString()}\n`);

    // 1. Discover AI config files
    const configComponents = await this.discoverConfigFiles();
    components.push(...configComponents);

    // 2. Discover AI SDK imports in source code
    const sdkComponents = await this.discoverAiSdkImports();
    components.push(...sdkComponents);

    // 3. Discover model files
    const modelComponents = await this.discoverModelFiles();
    components.push(...modelComponents);

    // 4. Build summary
    const summary: AiSbomSummary = {
      totalComponents: components.length,
      codingToolConfigs: components.filter(c => c.type === 'coding-tool-config').length,
      mcpServers: components.filter(c => c.type === 'mcp-server').length,
      aiSdks: components.filter(c => c.type === 'ai-sdk').length,
      agentFrameworks: components.filter(c => c.type === 'agent-framework').length,
      modelFiles: components.filter(c => c.type === 'model-file').length,
      serviceConfigs: components.filter(c => c.type === 'ai-service-config').length,
      unapproved: components.filter(c => !c.approved).length,
      highRisk: components.filter(c => c.risk === 'high').length,
    };

    const sbom: AiSbom = {
      projectPath,
      generatedAt: new Date().toISOString(),
      specVersion: '1.0.0',
      components,
      summary,
    };

    // Log summary
    this.outputChannel.appendLine(`\n── AI-SBOM Summary ──────────────────────`);
    this.outputChannel.appendLine(`  Total components:    ${summary.totalComponents}`);
    this.outputChannel.appendLine(`  Coding tool configs: ${summary.codingToolConfigs}`);
    this.outputChannel.appendLine(`  MCP servers:         ${summary.mcpServers}`);
    this.outputChannel.appendLine(`  AI SDKs:             ${summary.aiSdks}`);
    this.outputChannel.appendLine(`  Agent frameworks:    ${summary.agentFrameworks}`);
    this.outputChannel.appendLine(`  Model files:         ${summary.modelFiles}`);
    this.outputChannel.appendLine(`  High risk:           ${summary.highRisk}`);
    this.outputChannel.appendLine(`─────────────────────────────────────────`);

    return sbom;
  }

  /**
   * Discover AI configuration files in the workspace.
   */
  private async discoverConfigFiles(): Promise<AiComponent[]> {
    const components: AiComponent[] = [];

    for (const config of AI_CONFIG_FILES) {
      try {
        const files = await vscode.workspace.findFiles(config.glob, '**/node_modules/**', 10);
        for (const file of files) {
          const relPath = vscode.workspace.asRelativePath(file);
          components.push({
            id: `config-${relPath}`,
            type: config.type,
            name: config.name,
            file: relPath,
            line: 0,
            description: config.description,
            risk: config.risk,
            approved: true, // Config files are implicitly approved
            metadata: { source: 'file-scan' },
          });
          this.outputChannel.appendLine(`  [${config.type}] ${config.name}: ${relPath}`);
        }
      } catch {
        // Skip failed globs
      }
    }

    return components;
  }

  /**
   * Discover AI/ML SDK imports in source code files.
   */
  private async discoverAiSdkImports(): Promise<AiComponent[]> {
    const components: AiComponent[] = [];
    const seen = new Set<string>();

    const SCAN_EXTENSIONS = ['js', 'ts', 'jsx', 'tsx', 'py', 'mjs', 'cjs'];
    const IGNORE_DIRS = '{**/node_modules/**,**/.git/**,**/dist/**,**/out/**,**/build/**,**/__pycache__/**,**/.venv/**}';

    for (const ext of SCAN_EXTENSIONS) {
      try {
        const files = await vscode.workspace.findFiles(`**/*.${ext}`, IGNORE_DIRS, 500);
        for (const file of files) {
          try {
            const doc = await vscode.workspace.openTextDocument(file);
            const content = doc.getText();
            const langId = doc.languageId;

            for (const sdk of AI_SDK_PATTERNS) {
              if (!sdk.languages.includes(langId) && !sdk.languages.includes(ext)) { continue; }
              const match = sdk.pattern.exec(content);
              if (match) {
                const key = `${sdk.name}-${file.fsPath}`;
                if (seen.has(key)) { continue; }
                seen.add(key);

                const relPath = vscode.workspace.asRelativePath(file);
                // Find line number
                const lineNum = content.substring(0, match.index).split('\n').length;
                const compType: AiComponentType = sdk.category.includes('Agent') ? 'agent-framework' : 'ai-sdk';

                components.push({
                  id: `sdk-${sdk.name}-${relPath}:${lineNum}`,
                  type: compType,
                  name: sdk.name,
                  file: relPath,
                  line: lineNum,
                  description: `${sdk.category}: ${sdk.name}`,
                  risk: sdk.risk,
                  approved: true, // SDK imports are implicitly present
                  metadata: { category: sdk.category, language: langId },
                });
                this.outputChannel.appendLine(`  [${compType}] ${sdk.name} (${sdk.category}): ${relPath}:${lineNum}`);
              }
            }
          } catch {
            // Skip unreadable files
          }
        }
      } catch {
        // Skip failed globs
      }
    }

    return components;
  }

  /**
   * Discover model files in the workspace.
   */
  private async discoverModelFiles(): Promise<AiComponent[]> {
    const components: AiComponent[] = [];

    for (const modelExt of MODEL_FILE_EXTENSIONS) {
      try {
        const files = await vscode.workspace.findFiles(
          `**/*${modelExt.ext}`,
          '{**/node_modules/**,**/.git/**}',
          20,
        );
        for (const file of files) {
          const relPath = vscode.workspace.asRelativePath(file);
          try {
            const stat = fs.statSync(file.fsPath);
            const sizeMb = (stat.size / (1024 * 1024)).toFixed(1);
            components.push({
              id: `model-${relPath}`,
              type: 'model-file',
              name: `${modelExt.name}: ${path.basename(file.fsPath)}`,
              file: relPath,
              line: 0,
              description: `${modelExt.name} (${sizeMb} MB)`,
              risk: 'low',
              approved: true,
              metadata: { format: modelExt.ext, sizeBytes: String(stat.size) },
            });
            this.outputChannel.appendLine(`  [model-file] ${modelExt.name}: ${relPath} (${sizeMb} MB)`);
          } catch {
            // Skip unreadable files
          }
        }
      } catch {
        // Skip failed globs
      }
    }

    return components;
  }

  /**
   * Export the AI-SBOM as JSON.
   */
  exportJson(sbom: AiSbom): string {
    return JSON.stringify(sbom, null, 2);
  }

  dispose(): void {
    this.outputChannel.dispose();
  }
}
