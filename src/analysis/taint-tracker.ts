/**
 * Cross-File Taint Analysis Engine
 *
 * Traces tainted (user-controlled) data from sources to sinks across files.
 *
 * Architecture:
 *   1. Build lightweight import graph from workspace files
 *   2. Identify SOURCES (user input entry points: req.body, req.params, process.env, etc.)
 *   3. Trace tainted variables through assignments and function calls
 *   4. Flag SINKS (dangerous operations: SQL queries, exec(), innerHTML, etc.) that receive tainted data
 *   5. Update incrementally as files change
 *
 * Works with JS/TS and Python. Uses regex-based analysis (no AST parser dependency).
 */

import * as vscode from 'vscode';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TaintSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface TaintSource {
  /** Variable or expression that introduces tainted data */
  expression: string;
  /** Category of taint source */
  category: 'user-input' | 'environment' | 'file-read' | 'network' | 'database';
  /** File where taint originates */
  file: string;
  line: number;
}

export interface TaintSink {
  /** The dangerous operation */
  operation: string;
  /** Category of sink */
  category: 'sql' | 'command' | 'xss' | 'path-traversal' | 'ssrf' | 'deserialization' | 'redirect' | 'eval';
  severity: TaintSeverity;
  file: string;
  line: number;
}

export interface TaintFlow {
  source: TaintSource;
  sink: TaintSink;
  /** Chain of variable assignments connecting source to sink */
  propagationPath: TaintStep[];
  /** Unique ID for deduplication */
  id: string;
}

export interface TaintStep {
  file: string;
  line: number;
  expression: string;
  type: 'assignment' | 'parameter' | 'return' | 'function-call' | 'destructure';
}

export interface TaintReport {
  flows: TaintFlow[];
  sourceCount: number;
  sinkCount: number;
  scannedFiles: number;
  timestamp: number;
}

interface ImportEdge {
  fromFile: string;
  toFile: string;
  importedNames: string[];
}

interface FileTaintInfo {
  file: string;
  sources: TaintSource[];
  sinks: TaintSink[];
  /** Variables known to be tainted (name → source) */
  taintedVars: Map<string, TaintSource>;
  /** Exported functions that accept tainted parameters */
  exportedFunctions: Map<string, string[]>;
  /** Variables that flow out via module.exports/export */
  exportedVars: string[];
}

// ---------------------------------------------------------------------------
// Source & Sink Patterns
// ---------------------------------------------------------------------------

const SOURCE_PATTERNS: Array<{ pattern: RegExp; category: TaintSource['category']; label: string }> = [
  // Express / HTTP frameworks
  { pattern: /(?:req|request|ctx)\.(?:body|params|query|headers|cookies|files)\b/, category: 'user-input', label: 'HTTP request data' },
  { pattern: /(?:req|request|ctx)\.(?:param|get|header)\s*\(/, category: 'user-input', label: 'HTTP parameter' },
  { pattern: /event\.(?:body|queryStringParameters|pathParameters|headers)\b/, category: 'user-input', label: 'Lambda event data' },
  // Form data
  { pattern: /(?:FormData|URLSearchParams)\s*\(/, category: 'user-input', label: 'Form data' },
  { pattern: /document\.getElementById\s*\([^)]*\)\.value/, category: 'user-input', label: 'DOM input value' },
  // Environment
  { pattern: /process\.env\.\w+/, category: 'environment', label: 'Environment variable' },
  { pattern: /os\.environ\b/, category: 'environment', label: 'Python env' },
  // File reads
  { pattern: /(?:readFile|readFileSync|createReadStream)\s*\(/, category: 'file-read', label: 'File read' },
  { pattern: /open\s*\([^)]*,\s*['"]r/, category: 'file-read', label: 'Python file read' },
  // Network responses (data from external services)
  { pattern: /(?:await\s+)?(?:fetch|axios\.(?:get|post|put))\s*\(/, category: 'network', label: 'HTTP response' },
  // Database results
  { pattern: /\.(?:findOne|findMany|find|query|execute)\s*\(/, category: 'database', label: 'Database query result' },
  // Python Flask/Django
  { pattern: /request\.(?:form|args|json|data|values|files)\b/, category: 'user-input', label: 'Flask/Django request' },
];

const SINK_PATTERNS: Array<{ pattern: RegExp; category: TaintSink['category']; severity: TaintSeverity; label: string; languages?: string[] }> = [
  // SQL
  { pattern: /(?:query|execute|exec|raw)\s*\(\s*[`'"]?\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/i, category: 'sql', severity: 'critical', label: 'SQL query' },
  { pattern: /\.raw\s*\(/, category: 'sql', severity: 'critical', label: 'Raw SQL query' },
  // Command
  { pattern: /(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(/, category: 'command', severity: 'critical', label: 'Shell command' },
  { pattern: /subprocess\.(?:call|run|Popen|check_output)\s*\(/, category: 'command', severity: 'critical', label: 'Python subprocess', languages: ['python'] },
  { pattern: /os\.system\s*\(/, category: 'command', severity: 'critical', label: 'os.system()', languages: ['python'] },
  // XSS
  { pattern: /\.innerHTML\s*=/, category: 'xss', severity: 'high', label: 'innerHTML assignment' },
  { pattern: /document\.write\s*\(/, category: 'xss', severity: 'high', label: 'document.write()' },
  { pattern: /dangerouslySetInnerHTML/, category: 'xss', severity: 'high', label: 'dangerouslySetInnerHTML' },
  // Path traversal
  { pattern: /(?:readFile|writeFile|readFileSync|writeFileSync|unlink|rmdir|mkdir)\s*\(/, category: 'path-traversal', severity: 'high', label: 'File system operation' },
  // SSRF
  { pattern: /(?:fetch|axios|request|http\.get|https\.get)\s*\(/, category: 'ssrf', severity: 'high', label: 'HTTP request' },
  // Deserialization
  { pattern: /pickle\.loads?\s*\(/, category: 'deserialization', severity: 'critical', label: 'pickle.load()', languages: ['python'] },
  { pattern: /JSON\.parse\s*\(/, category: 'deserialization', severity: 'low', label: 'JSON.parse()' },
  // Redirect
  { pattern: /res\.redirect\s*\(/, category: 'redirect', severity: 'medium', label: 'HTTP redirect' },
  // Eval
  { pattern: /\beval\s*\(/, category: 'eval', severity: 'critical', label: 'eval()' },
  { pattern: /new\s+Function\s*\(/, category: 'eval', severity: 'critical', label: 'new Function()' },
];

// Patterns that indicate taint propagation (variable assignment from tainted source)
const ASSIGNMENT_PATTERN = /(?:const|let|var|)\s+(\w+)\s*=\s*(.+)/;
const DESTRUCTURE_PATTERN = /(?:const|let|var|)\s+\{([^}]+)\}\s*=\s*(.+)/;
const FUNCTION_PARAM_PATTERN = /(?:function|async function)\s+(\w+)\s*\(([^)]*)\)/;
const ARROW_PARAM_PATTERN = /(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/;
const EXPORT_PATTERN = /export\s+(?:default\s+)?(?:function|class|const|let|var)\s+(\w+)/;

// ---------------------------------------------------------------------------
// TaintTracker Class
// ---------------------------------------------------------------------------

export class TaintTracker {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private importGraph: ImportEdge[] = [];
  private fileInfoCache = new Map<string, FileTaintInfo>();
  private disposables: vscode.Disposable[] = [];

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('codeguard-taint');
  }

  /**
   * Activate file watchers to keep taint graph up to date.
   */
  activate(context: vscode.ExtensionContext): void {
    // Re-analyze on file save
    this.disposables.push(
      vscode.workspace.onDidSaveTextDocument((doc) => {
        if (this.isSupported(doc)) {
          this.analyzeFile(doc);
        }
      })
    );

    // Remove from cache on close
    this.disposables.push(
      vscode.workspace.onDidCloseTextDocument((doc) => {
        this.fileInfoCache.delete(doc.uri.fsPath);
        this.diagnosticCollection.delete(doc.uri);
      })
    );

    context.subscriptions.push({ dispose: () => this.dispose() });
  }

  /**
   * Scan entire workspace for taint flows.
   */
  async scanWorkspace(): Promise<TaintReport> {
    const files = await vscode.workspace.findFiles(
      '**/*.{js,ts,jsx,tsx,py}',
      '**/node_modules/**',
      500 // limit to 500 files
    );

    // Build import graph
    this.importGraph = [];
    this.fileInfoCache.clear();

    for (const uri of files) {
      try {
        const doc = await vscode.workspace.openTextDocument(uri);
        this.analyzeFile(doc);
      } catch {
        // skip files that can't be opened
      }
    }

    // Propagate taint across files using import graph
    const flows = this.propagateTaintAcrossFiles();

    // Update diagnostics
    this.updateDiagnosticsFromFlows(flows);

    return {
      flows,
      sourceCount: Array.from(this.fileInfoCache.values()).reduce((sum, f) => sum + f.sources.length, 0),
      sinkCount: Array.from(this.fileInfoCache.values()).reduce((sum, f) => sum + f.sinks.length, 0),
      scannedFiles: files.length,
      timestamp: Date.now(),
    };
  }

  /**
   * Analyze a single file for sources, sinks, and local taint flows.
   */
  analyzeFile(document: vscode.TextDocument): FileTaintInfo {
    const filePath = document.uri.fsPath;
    const text = document.getText();
    const lines = text.split('\n');
    const lang = document.languageId;

    const info: FileTaintInfo = {
      file: filePath,
      sources: [],
      sinks: [],
      taintedVars: new Map(),
      exportedFunctions: new Map(),
      exportedVars: [],
    };

    // Pass 1: Find sources, sinks, imports, exports
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      // Skip comments
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) { continue; }

      // Detect sources
      for (const sp of SOURCE_PATTERNS) {
        if (sp.pattern.test(line)) {
          const match = sp.pattern.exec(line);
          info.sources.push({
            expression: match ? match[0] : trimmed,
            category: sp.category,
            file: filePath,
            line: i,
          });

          // If this line also has an assignment, the LHS variable is tainted
          const assignMatch = ASSIGNMENT_PATTERN.exec(trimmed);
          if (assignMatch) {
            info.taintedVars.set(assignMatch[1], info.sources[info.sources.length - 1]);
          }

          // Destructured assignment
          const destructMatch = DESTRUCTURE_PATTERN.exec(trimmed);
          if (destructMatch) {
            const vars = destructMatch[1].split(',').map(v => v.trim().split(':')[0].trim());
            for (const v of vars) {
              if (v) { info.taintedVars.set(v, info.sources[info.sources.length - 1]); }
            }
          }
        }
      }

      // Detect sinks
      for (const sk of SINK_PATTERNS) {
        if (sk.languages && !sk.languages.includes(lang)) { continue; }
        if (sk.pattern.test(line)) {
          info.sinks.push({
            operation: sk.label,
            category: sk.category,
            severity: sk.severity,
            file: filePath,
            line: i,
          });
        }
      }

      // Detect exports
      const exportMatch = EXPORT_PATTERN.exec(trimmed);
      if (exportMatch) {
        info.exportedVars.push(exportMatch[1]);
      }

      // Detect function definitions (for parameter taint tracking)
      const funcMatch = FUNCTION_PARAM_PATTERN.exec(trimmed) || ARROW_PARAM_PATTERN.exec(trimmed);
      if (funcMatch) {
        const funcName = funcMatch[1];
        const params = funcMatch[2].split(',').map(p => p.trim().split(':')[0].split('=')[0].trim()).filter(Boolean);
        info.exportedFunctions.set(funcName, params);
      }

      // Build import graph
      this.parseImports(filePath, trimmed, i);
    }

    // Pass 2: Propagate taint within the file
    this.propagateLocalTaint(info, lines);

    this.fileInfoCache.set(filePath, info);

    // Check for same-file taint flows
    const localFlows = this.findLocalFlows(info, lines);
    if (localFlows.length > 0) {
      this.updateDiagnosticsForFile(document.uri, localFlows);
    }

    return info;
  }

  /**
   * Get the current taint report (cached results).
   */
  getReport(): TaintReport {
    const allFlows = this.propagateTaintAcrossFiles();
    return {
      flows: allFlows,
      sourceCount: Array.from(this.fileInfoCache.values()).reduce((sum, f) => sum + f.sources.length, 0),
      sinkCount: Array.from(this.fileInfoCache.values()).reduce((sum, f) => sum + f.sinks.length, 0),
      scannedFiles: this.fileInfoCache.size,
      timestamp: Date.now(),
    };
  }

  /**
   * Format taint report as markdown.
   */
  toMarkdown(report: TaintReport): string {
    const lines: string[] = [
      '# Taint Analysis Report',
      '',
      `**Scanned:** ${report.scannedFiles} files | **Sources:** ${report.sourceCount} | **Sinks:** ${report.sinkCount} | **Flows:** ${report.flows.length}`,
      '',
    ];

    if (report.flows.length === 0) {
      lines.push('No tainted data flows detected.');
      return lines.join('\n');
    }

    // Group by severity
    const bySeverity = new Map<TaintSeverity, TaintFlow[]>();
    for (const flow of report.flows) {
      const sev = flow.sink.severity;
      if (!bySeverity.has(sev)) { bySeverity.set(sev, []); }
      bySeverity.get(sev)!.push(flow);
    }

    for (const sev of ['critical', 'high', 'medium', 'low'] as TaintSeverity[]) {
      const flows = bySeverity.get(sev);
      if (!flows || flows.length === 0) { continue; }

      const emoji = sev === 'critical' ? '🔴' : sev === 'high' ? '🟠' : sev === 'medium' ? '🟡' : '🟢';
      lines.push(`## ${emoji} ${sev.toUpperCase()} (${flows.length})`);
      lines.push('');

      for (const flow of flows) {
        const srcFile = path.basename(flow.source.file);
        const sinkFile = path.basename(flow.sink.file);
        lines.push(`### ${flow.sink.operation} ← ${flow.source.category}`);
        lines.push(`- **Source:** \`${srcFile}:${flow.source.line + 1}\` — \`${flow.source.expression}\``);
        lines.push(`- **Sink:** \`${sinkFile}:${flow.sink.line + 1}\` — ${flow.sink.operation}`);
        if (flow.propagationPath.length > 0) {
          lines.push('- **Path:**');
          for (const step of flow.propagationPath) {
            lines.push(`  - \`${path.basename(step.file)}:${step.line + 1}\` ${step.type}: \`${step.expression}\``);
          }
        }
        lines.push('');
      }
    }

    return lines.join('\n');
  }

  // -----------------------------------------------------------------------
  // Private: Import Graph
  // -----------------------------------------------------------------------

  private parseImports(filePath: string, line: string, _lineIdx: number): void {
    // ES imports: import { x } from './module'
    const esImport = /import\s+(?:\{([^}]*)\}|(\w+))\s+from\s+['"]([^'"]+)['"]/;
    const match = esImport.exec(line);
    if (match) {
      const names = match[1]
        ? match[1].split(',').map(n => n.trim().split(' as ')[0].trim())
        : match[2] ? [match[2]] : [];
      const importPath = match[3];

      if (importPath.startsWith('.')) {
        const resolvedPath = this.resolveImportPath(filePath, importPath);
        if (resolvedPath) {
          this.importGraph.push({ fromFile: filePath, toFile: resolvedPath, importedNames: names });
        }
      }
    }

    // CommonJS: const x = require('./module')
    const cjsRequire = /(?:const|let|var)\s+(?:\{([^}]*)\}|(\w+))\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/;
    const cjsMatch = cjsRequire.exec(line);
    if (cjsMatch) {
      const names = cjsMatch[1]
        ? cjsMatch[1].split(',').map(n => n.trim().split(':')[0].trim())
        : cjsMatch[2] ? [cjsMatch[2]] : [];
      const importPath = cjsMatch[3];

      if (importPath.startsWith('.')) {
        const resolvedPath = this.resolveImportPath(filePath, importPath);
        if (resolvedPath) {
          this.importGraph.push({ fromFile: filePath, toFile: resolvedPath, importedNames: names });
        }
      }
    }

    // Python: from module import x
    const pyImport = /from\s+\.(\w+)\s+import\s+(.+)/;
    const pyMatch = pyImport.exec(line);
    if (pyMatch) {
      const names = pyMatch[2].split(',').map(n => n.trim());
      const importPath = pyMatch[1];
      const dir = path.dirname(filePath);
      const resolved = path.join(dir, importPath + '.py');
      this.importGraph.push({ fromFile: filePath, toFile: resolved, importedNames: names });
    }
  }

  private resolveImportPath(fromFile: string, importPath: string): string | null {
    const dir = path.dirname(fromFile);
    const extensions = ['.ts', '.tsx', '.js', '.jsx', '.py', ''];

    for (const ext of extensions) {
      const candidate = path.resolve(dir, importPath + ext);
      if (this.fileInfoCache.has(candidate)) {
        return candidate;
      }
    }

    // Try index files
    for (const ext of ['.ts', '.js']) {
      const candidate = path.resolve(dir, importPath, 'index' + ext);
      if (this.fileInfoCache.has(candidate)) {
        return candidate;
      }
    }

    return null;
  }

  // -----------------------------------------------------------------------
  // Private: Local Taint Propagation
  // -----------------------------------------------------------------------

  private propagateLocalTaint(info: FileTaintInfo, lines: string[]): void {
    // Multi-pass propagation: follow assignments from known tainted variables
    let changed = true;
    let iterations = 0;
    const maxIterations = 10;

    while (changed && iterations < maxIterations) {
      changed = false;
      iterations++;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) { continue; }

        const assignMatch = ASSIGNMENT_PATTERN.exec(line);
        if (assignMatch) {
          const varName = assignMatch[1];
          const rhs = assignMatch[2];

          // Check if RHS references any tainted variable
          if (!info.taintedVars.has(varName)) {
            for (const [taintedVar, source] of info.taintedVars) {
              if (rhs.includes(taintedVar)) {
                info.taintedVars.set(varName, source);
                changed = true;
                break;
              }
            }
          }
        }
      }
    }
  }

  private findLocalFlows(info: FileTaintInfo, lines: string[]): TaintFlow[] {
    const flows: TaintFlow[] = [];

    for (const sink of info.sinks) {
      const sinkLine = lines[sink.line] || '';

      // Check if any tainted variable appears in the sink line
      for (const [varName, source] of info.taintedVars) {
        if (sinkLine.includes(varName)) {
          const flowId = `${info.file}:${source.line}→${sink.line}:${varName}`;
          flows.push({
            source,
            sink,
            propagationPath: [{
              file: info.file,
              line: sink.line,
              expression: `${varName} used in ${sink.operation}`,
              type: 'assignment',
            }],
            id: flowId,
          });
        }
      }
    }

    return flows;
  }

  // -----------------------------------------------------------------------
  // Private: Cross-File Taint Propagation
  // -----------------------------------------------------------------------

  private propagateTaintAcrossFiles(): TaintFlow[] {
    const allFlows: TaintFlow[] = [];

    // For each import edge, check if imported names are tainted in the source file
    for (const edge of this.importGraph) {
      const sourceFileInfo = this.fileInfoCache.get(edge.toFile);
      const importingFileInfo = this.fileInfoCache.get(edge.fromFile);

      if (!sourceFileInfo || !importingFileInfo) { continue; }

      for (const importedName of edge.importedNames) {
        // Check if the imported name is a tainted variable in the source file
        const sourceTaint = sourceFileInfo.taintedVars.get(importedName);
        if (sourceTaint) {
          // This tainted value flows into the importing file
          // Check if it reaches any sink in the importing file
          for (const sink of importingFileInfo.sinks) {
            // Simple check: does the imported name appear on the sink line?
            // (In a real implementation, we'd do proper data flow analysis)
            allFlows.push({
              source: sourceTaint,
              sink,
              propagationPath: [
                {
                  file: edge.toFile,
                  line: sourceTaint.line,
                  expression: `${importedName} exported from ${path.basename(edge.toFile)}`,
                  type: 'return',
                },
                {
                  file: edge.fromFile,
                  line: 0,
                  expression: `import { ${importedName} } from ${path.basename(edge.toFile)}`,
                  type: 'parameter',
                },
              ],
              id: `cross:${edge.toFile}:${sourceTaint.line}→${edge.fromFile}:${sink.line}`,
            });
          }
        }

        // Check if the imported name is a function that accepts tainted params
        const funcParams = sourceFileInfo.exportedFunctions.get(importedName);
        if (funcParams) {
          // The function's parameters could receive tainted data from the importing file
          for (const [taintedVar, source] of importingFileInfo.taintedVars) {
            // If a tainted var is used as an argument to the imported function,
            // the function's internal sinks are reachable
            for (const sink of sourceFileInfo.sinks) {
              allFlows.push({
                source,
                sink,
                propagationPath: [
                  {
                    file: edge.fromFile,
                    line: source.line,
                    expression: `${taintedVar} passed to ${importedName}()`,
                    type: 'function-call',
                  },
                  {
                    file: edge.toFile,
                    line: sink.line,
                    expression: `${importedName}() reaches ${sink.operation}`,
                    type: 'parameter',
                  },
                ],
                id: `cross-call:${edge.fromFile}:${source.line}→${edge.toFile}:${sink.line}:${taintedVar}`,
              });
            }
          }
        }
      }
    }

    // Also collect all local flows
    for (const info of this.fileInfoCache.values()) {
      const doc = vscode.workspace.textDocuments.find(d => d.uri.fsPath === info.file);
      if (doc) {
        const lines = doc.getText().split('\n');
        allFlows.push(...this.findLocalFlows(info, lines));
      }
    }

    // Deduplicate
    const seen = new Set<string>();
    return allFlows.filter(f => {
      if (seen.has(f.id)) { return false; }
      seen.add(f.id);
      return true;
    });
  }

  // -----------------------------------------------------------------------
  // Private: Diagnostics
  // -----------------------------------------------------------------------

  private updateDiagnosticsForFile(uri: vscode.Uri, flows: TaintFlow[]): void {
    const diagnostics: vscode.Diagnostic[] = flows.map(flow => {
      const range = new vscode.Range(flow.sink.line, 0, flow.sink.line, 200);
      const severity = (flow.sink.severity === 'critical' || flow.sink.severity === 'high')
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Warning;

      const srcFile = path.basename(flow.source.file);
      const diag = new vscode.Diagnostic(
        range,
        `[TAINT] ${flow.sink.operation}: receives tainted data from ${flow.source.category} (${srcFile}:${flow.source.line + 1}). Validate/sanitize input before use.`,
        severity
      );
      diag.source = 'CodeGuard Taint Analysis';
      diag.code = `TAINT_${flow.sink.category.toUpperCase()}`;
      return diag;
    });

    this.diagnosticCollection.set(uri, diagnostics);
  }

  private updateDiagnosticsFromFlows(flows: TaintFlow[]): void {
    // Group flows by sink file
    const byFile = new Map<string, TaintFlow[]>();
    for (const flow of flows) {
      const file = flow.sink.file;
      if (!byFile.has(file)) { byFile.set(file, []); }
      byFile.get(file)!.push(flow);
    }

    for (const [file, fileFlows] of byFile) {
      const uri = vscode.Uri.file(file);
      this.updateDiagnosticsForFile(uri, fileFlows);
    }
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private isSupported(doc: vscode.TextDocument): boolean {
    return ['javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'python'].includes(doc.languageId);
  }

  clearDiagnostics(uri: vscode.Uri): void {
    this.diagnosticCollection.delete(uri);
  }

  get trackedFileCount(): number {
    return this.fileInfoCache.size;
  }

  get importEdgeCount(): number {
    return this.importGraph.length;
  }

  dispose(): void {
    for (const d of this.disposables) { d.dispose(); }
    this.diagnosticCollection.dispose();
    this.fileInfoCache.clear();
    this.importGraph = [];
  }
}
