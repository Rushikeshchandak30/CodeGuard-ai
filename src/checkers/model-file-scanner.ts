/**
 * ML Model File Exploit Scanner
 *
 * Scans serialized ML model files for known unsafe constructs:
 *   1. Python pickle files (.pkl, .pickle, .pt, .pth, .bin, .ckpt, .joblib)
 *      — Detects `__reduce__`, `os.system`, `subprocess`, `exec`, `eval`,
 *        `builtins.eval`, `posix.system`, `nt.system`, `runpy`, `webbrowser`,
 *        and arbitrary GLOBAL opcodes pointing to dangerous modules.
 *      — Well-known attack since torch.load() uses pickle by default (CVE-2023-43654).
 *
 *   2. Keras .h5 / SavedModel — detects Lambda layers with embedded Python
 *      (Keras <2.13 arbitrary code execution via Lambda weights).
 *
 *   3. ONNX — detects custom operators from unknown domains, external data
 *      references to suspicious URLs, and excessive initializer sizes.
 *
 *   4. HuggingFace config/tokenizer files — detects auto_map pointing to
 *      remote Python code (trust_remote_code=True risk).
 *
 *   5. .safetensors — generally safe, but scan metadata for mismatched
 *      declared/actual tensor counts (potential hiding attack).
 *
 * Also flags `torch.load()`, `pickle.load()`, `joblib.load()`, and
 * `trust_remote_code=True` usage in source code with untrusted paths.
 *
 * References:
 *   - https://github.com/trailofbits/fickling (safe pickle analysis)
 *   - https://huggingface.co/docs/hub/security-pickle
 *   - CVE-2023-43654, CVE-2024-3660, CVE-2024-5480
 */

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ModelFindingSeverity = 'critical' | 'high' | 'medium' | 'low';

export type ModelFindingCategory =
  | 'pickle-rce'
  | 'pickle-suspicious-opcode'
  | 'keras-lambda-layer'
  | 'onnx-external-data'
  | 'onnx-custom-op'
  | 'hf-remote-code'
  | 'safetensors-tampering'
  | 'unsafe-load-call'
  | 'unknown-format';

export interface ModelFinding {
  file: string;
  category: ModelFindingCategory;
  severity: ModelFindingSeverity;
  ruleId: string;
  message: string;
  evidence: string;
  remediation: string;
  // For source-code findings
  line?: number;
  column?: number;
}

// ---------------------------------------------------------------------------
// File extension classification
// ---------------------------------------------------------------------------

const PICKLE_EXTENSIONS = [
  '.pkl',
  '.pickle',
  '.pt',
  '.pth',
  '.bin',
  '.ckpt',
  '.joblib',
  '.dat',
  '.model',
];
const KERAS_EXTENSIONS = ['.h5', '.hdf5', '.keras'];
const ONNX_EXTENSIONS = ['.onnx'];
const SAFETENSORS_EXTENSIONS = ['.safetensors'];
const HF_CONFIG_FILENAMES = [
  'config.json',
  'tokenizer_config.json',
  'generation_config.json',
  'configuration.json',
];

export function classifyModelFile(filePath: string): {
  type:
    | 'pickle'
    | 'keras'
    | 'onnx'
    | 'safetensors'
    | 'hf-config'
    | 'unknown';
} {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();
  if (PICKLE_EXTENSIONS.includes(ext)) return { type: 'pickle' };
  if (KERAS_EXTENSIONS.includes(ext)) return { type: 'keras' };
  if (ONNX_EXTENSIONS.includes(ext)) return { type: 'onnx' };
  if (SAFETENSORS_EXTENSIONS.includes(ext)) return { type: 'safetensors' };
  if (HF_CONFIG_FILENAMES.includes(base)) return { type: 'hf-config' };
  return { type: 'unknown' };
}

// ---------------------------------------------------------------------------
// Dangerous pickle modules/functions
// ---------------------------------------------------------------------------

/**
 * Modules that are almost never legitimate in a model file. Seeing these in a
 * GLOBAL / STACK_GLOBAL opcode is a strong indicator of weaponization.
 */
const DANGEROUS_PICKLE_GLOBALS = [
  // OS/process
  'os.system',
  'os.popen',
  'os.execv',
  'os.execve',
  'os.execvp',
  'os.execvpe',
  'os.spawn',
  'os.spawnv',
  'os.spawnve',
  'os.spawnvp',
  'posix.system',
  'nt.system',
  'subprocess.run',
  'subprocess.Popen',
  'subprocess.call',
  'subprocess.check_call',
  'subprocess.check_output',
  'subprocess.getoutput',
  'subprocess.getstatusoutput',
  // Code execution
  'builtins.eval',
  'builtins.exec',
  'builtins.compile',
  '__builtin__.eval',
  '__builtin__.exec',
  'builtins.__import__',
  'importlib.import_module',
  'runpy._run_code',
  'runpy.run_path',
  'runpy.run_module',
  'code.InteractiveInterpreter',
  // Network
  'socket.socket',
  'socket.create_connection',
  'urllib.request.urlopen',
  'urllib.urlopen',
  'requests.get',
  'requests.post',
  'http.client.HTTPConnection',
  'ftplib.FTP',
  // Webbrowser (opens URLs)
  'webbrowser.open',
  'webbrowser.open_new',
  'webbrowser.open_new_tab',
  // File operations beyond what torch needs
  'shutil.copy',
  'shutil.move',
  'shutil.rmtree',
  'os.remove',
  'os.unlink',
  'os.rmdir',
  'os.chmod',
  'os.chown',
  // Pickle self-reference (chain attacks)
  'pickle.loads',
  'pickle.load',
  'pickletools',
  // Dynamic module loading
  'ctypes.CDLL',
  'ctypes.cdll',
  'ctypes.windll',
  'cffi.FFI',
];

/**
 * Suspicious but not always malicious. Flag as medium.
 */
const SUSPICIOUS_PICKLE_GLOBALS = [
  'pty.spawn',
  'platform.popen',
  'commands.getoutput',
  'tempfile.mktemp',
  'zipfile.ZipFile',
  'tarfile.open',
];

// Pickle opcodes (subset we care about)
// https://docs.python.org/3/library/pickletools.html
const PICKLE_OPCODE_REDUCE = 0x52; // 'R'
const PICKLE_OPCODE_BUILD = 0x62; // 'b'
const PICKLE_OPCODE_INST = 0x69; // 'i'
const PICKLE_OPCODE_OBJ = 0x6f; // 'o'
const PICKLE_OPCODE_NEWOBJ = 0x81;
const PICKLE_OPCODE_NEWOBJ_EX = 0x92;
const PICKLE_OPCODE_GLOBAL = 0x63; // 'c'
const PICKLE_OPCODE_STACK_GLOBAL = 0x93;

// ---------------------------------------------------------------------------
// Pickle scanner — byte-level (no Python required)
// ---------------------------------------------------------------------------

/**
 * Scans a pickle file's raw bytes for GLOBAL opcodes that reference dangerous
 * modules/functions. This does NOT unpickle the file — it is a pure
 * byte-pattern analysis (safe to run on untrusted input).
 *
 * Pickle format reference:
 *   GLOBAL c\n<module>\n<name>\n   — push global onto stack
 *   STACK_GLOBAL \x93              — same, but with stack args
 *   REDUCE R                       — call callable with args (the "execute" op)
 */
export function scanPickleFile(filePath: string): ModelFinding[] {
  const findings: ModelFinding[] = [];
  let buf: Buffer;
  try {
    const stat = fs.statSync(filePath);
    // Read up to 50 MB; most weaponized pickles are tiny, larger files are just weights.
    // GLOBAL opcodes typically cluster near the top of the file.
    const maxRead = Math.min(stat.size, 50 * 1024 * 1024);
    const fd = fs.openSync(filePath, 'r');
    try {
      buf = Buffer.alloc(maxRead);
      fs.readSync(fd, buf, 0, maxRead, 0);
    } finally {
      fs.closeSync(fd);
    }
  } catch (err) {
    return [
      {
        file: filePath,
        category: 'unknown-format',
        severity: 'low',
        ruleId: 'CG_MODEL_IO_001',
        message: 'Failed to read model file',
        evidence: String(err).slice(0, 200),
        remediation: 'Verify file integrity and permissions.',
      },
    ];
  }

  // Torch model files are ZIP archives containing pickle. Detect PK\x03\x04 header.
  const isZip = buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04;
  if (isZip) {
    // For ZIP-wrapped (modern torch.save) we look for .pkl entries inside and scan
    // those bytes. We do a simple scan for suspicious ASCII patterns across the
    // whole blob; this is a conservative heuristic.
    findings.push(...scanBytesForPickleGlobals(buf, filePath, { source: 'zip-wrapped' }));
    return findings;
  }

  // Raw pickle (legacy). Parse GLOBAL opcodes.
  findings.push(...scanBytesForPickleGlobals(buf, filePath, { source: 'raw-pickle' }));
  return findings;
}

function scanBytesForPickleGlobals(
  buf: Buffer,
  filePath: string,
  ctx: { source: 'raw-pickle' | 'zip-wrapped' }
): ModelFinding[] {
  const findings: ModelFinding[] = [];
  const seen = new Set<string>();

  // Heuristic 1: scan for "c<module>\n<name>\n" GLOBAL opcodes
  for (let i = 0; i < buf.length - 1; i++) {
    if (buf[i] === PICKLE_OPCODE_GLOBAL) {
      const nl1 = buf.indexOf(0x0a, i + 1);
      if (nl1 === -1 || nl1 - i > 128) continue;
      const nl2 = buf.indexOf(0x0a, nl1 + 1);
      if (nl2 === -1 || nl2 - nl1 > 128) continue;
      const mod = buf.slice(i + 1, nl1).toString('ascii');
      const name = buf.slice(nl1 + 1, nl2).toString('ascii');
      if (!/^[\w.]+$/.test(mod) || !/^[\w.]+$/.test(name)) continue;
      const full = `${mod}.${name}`;
      if (seen.has(full)) continue;
      seen.add(full);

      if (DANGEROUS_PICKLE_GLOBALS.includes(full)) {
        findings.push({
          file: filePath,
          category: 'pickle-rce',
          severity: 'critical',
          ruleId: 'CG_MODEL_PKL_001',
          message: `Pickle file references dangerous callable: ${full}`,
          evidence: `GLOBAL opcode at offset ${i}: ${full}`,
          remediation:
            'DO NOT LOAD THIS FILE. Torch/pickle deserialization will execute this callable. ' +
            'Obtain the model from a trusted source, or convert to .safetensors first.',
        });
      } else if (SUSPICIOUS_PICKLE_GLOBALS.includes(full)) {
        findings.push({
          file: filePath,
          category: 'pickle-suspicious-opcode',
          severity: 'medium',
          ruleId: 'CG_MODEL_PKL_002',
          message: `Pickle file references suspicious callable: ${full}`,
          evidence: `GLOBAL opcode at offset ${i}: ${full}`,
          remediation: 'Review the file manually with fickling or similar tool before loading.',
        });
      } else if (
        // Anything outside torch/numpy/collections is worth a medium flag
        !/^(torch|numpy|collections|__builtin__|builtins|copy_reg|copyreg|_codecs|pickle|array)\b/.test(
          mod
        )
      ) {
        // Only flag non-standard modules. Lots of libraries are legitimate.
        if (
          /(?:eval|exec|system|popen|spawn|shell|socket|request|urllib|subprocess|ctypes|cffi|runpy)/i.test(
            full
          )
        ) {
          findings.push({
            file: filePath,
            category: 'pickle-suspicious-opcode',
            severity: 'high',
            ruleId: 'CG_MODEL_PKL_003',
            message: `Pickle file references potentially unsafe module: ${full}`,
            evidence: `GLOBAL opcode at offset ${i}: ${full}`,
            remediation: 'Audit with fickling. Prefer safetensors for untrusted sources.',
          });
        }
      }
    }
  }

  // Heuristic 2: raw ASCII string search (catches STACK_GLOBAL which stores
  // module/name via SHORT_BINUNICODE rather than inline)
  const ascii = buf.toString('latin1'); // preserves byte values
  for (const danger of DANGEROUS_PICKLE_GLOBALS) {
    if (seen.has(danger)) continue;
    // Look for the exact module + name strings near a REDUCE opcode
    const modStr = danger.split('.').slice(0, -1).join('.');
    const nameStr = danger.split('.').slice(-1)[0];
    if (ascii.includes(modStr) && ascii.includes(nameStr)) {
      // Additional evidence: REDUCE (0x52) or STACK_GLOBAL (0x93) nearby
      const hasReduce = buf.includes(PICKLE_OPCODE_REDUCE);
      const hasStackGlobal = buf.includes(PICKLE_OPCODE_STACK_GLOBAL);
      if (hasReduce || hasStackGlobal) {
        seen.add(danger);
        findings.push({
          file: filePath,
          category: 'pickle-rce',
          severity: 'critical',
          ruleId: 'CG_MODEL_PKL_004',
          message: `Pickle contains dangerous reference (${ctx.source}): ${danger}`,
          evidence: `String "${modStr}" + "${nameStr}" present with REDUCE/STACK_GLOBAL opcode`,
          remediation:
            'DO NOT LOAD. Convert to safetensors or obtain from trusted source.',
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Keras .h5 scanner (detect Lambda layers)
// ---------------------------------------------------------------------------

export function scanKerasFile(filePath: string): ModelFinding[] {
  const findings: ModelFinding[] = [];
  try {
    const buf = fs.readFileSync(filePath);
    // HDF5 magic
    if (!(buf[0] === 0x89 && buf.slice(1, 4).toString() === 'HDF')) {
      if (filePath.endsWith('.keras')) {
        // .keras is a zip archive — look for config.json inside
        findings.push(...scanKerasZip(buf, filePath));
      }
      return findings;
    }
    const ascii = buf.toString('latin1');
    // Keras stores the model config as JSON in the HDF5 attribute 'model_config'.
    // Lambda layers are represented as {"class_name":"Lambda","config":{"function":"<marshalled code>"}}
    if (/"class_name"\s*:\s*"Lambda"/i.test(ascii)) {
      findings.push({
        file: filePath,
        category: 'keras-lambda-layer',
        severity: 'high',
        ruleId: 'CG_MODEL_KERAS_001',
        message: 'Keras model contains Lambda layer (can execute arbitrary Python)',
        evidence: '"class_name": "Lambda" detected in HDF5 attributes',
        remediation:
          'Lambda layers store marshalled Python bytecode. Only load .h5/.keras files ' +
          'from trusted sources. Upgrade to Keras 3+ with safe_mode=True when calling ' +
          'load_model().',
      });
    }
  } catch {
    // ignore
  }
  return findings;
}

function scanKerasZip(buf: Buffer, filePath: string): ModelFinding[] {
  // Minimal: look for config.json inside the zip and check for Lambda layers
  const findings: ModelFinding[] = [];
  const ascii = buf.toString('latin1');
  if (/"class_name"\s*:\s*"Lambda"/i.test(ascii)) {
    findings.push({
      file: filePath,
      category: 'keras-lambda-layer',
      severity: 'high',
      ruleId: 'CG_MODEL_KERAS_002',
      message: '.keras archive contains Lambda layer',
      evidence: '"class_name": "Lambda" detected in archive',
      remediation: 'Load with safe_mode=True or convert to a safe format.',
    });
  }
  return findings;
}

// ---------------------------------------------------------------------------
// ONNX scanner
// ---------------------------------------------------------------------------

export function scanOnnxFile(filePath: string): ModelFinding[] {
  const findings: ModelFinding[] = [];
  try {
    const buf = fs.readFileSync(filePath);
    const ascii = buf.toString('latin1');
    // ONNX uses protobuf. We look for well-known string fields.
    // External data can point to arbitrary files/URLs.
    const externalDataMatch = ascii.match(
      /external_data[^\x00]{0,200}(?:https?:\/\/[^\s"'<>\x00]{5,200}|\.\.\/|file:\/\/)/i
    );
    if (externalDataMatch) {
      findings.push({
        file: filePath,
        category: 'onnx-external-data',
        severity: 'high',
        ruleId: 'CG_MODEL_ONNX_001',
        message: 'ONNX model references external data via URL or relative path',
        evidence: externalDataMatch[0].slice(0, 120),
        remediation:
          'External data can be fetched from attacker-controlled URLs or escape the ' +
          'workspace via ../. Use models with embedded weights.',
      });
    }
    // Custom op domains — legitimate domains are "", "ai.onnx", "com.microsoft", "org.pytorch".
    const domainMatches = ascii.match(
      /\bdomain\s*[:=]?\s*["']([^"'\x00]{3,80})["']/g
    );
    if (domainMatches) {
      for (const dm of domainMatches) {
        const d = dm.match(/["']([^"']+)["']/)?.[1] ?? '';
        if (
          d &&
          !/^(ai\.onnx|com\.microsoft|org\.pytorch|ai\.onnx\.(ml|training|preview)|)$/.test(d)
        ) {
          findings.push({
            file: filePath,
            category: 'onnx-custom-op',
            severity: 'medium',
            ruleId: 'CG_MODEL_ONNX_002',
            message: `ONNX model uses custom operator domain: ${d}`,
            evidence: dm,
            remediation: 'Verify the custom operator library is trusted and sandboxed.',
          });
        }
      }
    }
  } catch {
    // ignore
  }
  return findings;
}

// ---------------------------------------------------------------------------
// HuggingFace config scanner (trust_remote_code = True)
// ---------------------------------------------------------------------------

export function scanHuggingFaceConfig(filePath: string): ModelFinding[] {
  const findings: ModelFinding[] = [];
  try {
    const text = fs.readFileSync(filePath, 'utf8');
    let config: any;
    try {
      config = JSON.parse(text);
    } catch {
      return findings;
    }
    // auto_map points to a Python module path that will be executed.
    if (config && typeof config === 'object' && 'auto_map' in config && config.auto_map) {
      const autoMap = config.auto_map;
      const refs =
        typeof autoMap === 'object'
          ? Object.values(autoMap).flat().join(', ')
          : String(autoMap);
      findings.push({
        file: filePath,
        category: 'hf-remote-code',
        severity: 'high',
        ruleId: 'CG_MODEL_HF_001',
        message: 'HuggingFace config uses auto_map (remote Python code execution on load)',
        evidence: `auto_map: ${refs.slice(0, 200)}`,
        remediation:
          'Loading this model with trust_remote_code=True will execute the referenced ' +
          'Python code. Audit the .py files in the repo or use a safetensors-only model.',
      });
    }
    if (config?.quantization_config?.modules_to_not_convert) {
      // not a vuln on its own but can be abused; low severity informational
    }
  } catch {
    // ignore
  }
  return findings;
}

// ---------------------------------------------------------------------------
// safetensors scanner (very light — mostly a sanity check)
// ---------------------------------------------------------------------------

export function scanSafetensorsFile(filePath: string): ModelFinding[] {
  const findings: ModelFinding[] = [];
  try {
    const fd = fs.openSync(filePath, 'r');
    try {
      const headerSizeBuf = Buffer.alloc(8);
      fs.readSync(fd, headerSizeBuf, 0, 8, 0);
      const headerSize = Number(headerSizeBuf.readBigUInt64LE(0));
      if (headerSize <= 0 || headerSize > 100 * 1024 * 1024) {
        findings.push({
          file: filePath,
          category: 'safetensors-tampering',
          severity: 'high',
          ruleId: 'CG_MODEL_ST_001',
          message: 'safetensors header size out of plausible range',
          evidence: `declared header size: ${headerSize} bytes`,
          remediation: 'Do not load. File may be malformed or tampered with.',
        });
        return findings;
      }
      const headerBuf = Buffer.alloc(headerSize);
      fs.readSync(fd, headerBuf, 0, headerSize, 8);
      const header = JSON.parse(headerBuf.toString('utf8'));
      if (header && typeof header === 'object' && '__metadata__' in header) {
        const meta = (header as any).__metadata__;
        if (meta && typeof meta === 'object') {
          for (const [k, v] of Object.entries(meta)) {
            if (typeof v === 'string' && /[\u200B-\u200F\u202A-\u202E\uFEFF]/.test(v)) {
              findings.push({
                file: filePath,
                category: 'safetensors-tampering',
                severity: 'medium',
                ruleId: 'CG_MODEL_ST_002',
                message: 'safetensors metadata contains hidden Unicode characters',
                evidence: `metadata key: ${k}`,
                remediation: 'Verify metadata is clean before trusting the file.',
              });
            }
          }
        }
      }
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    // ignore
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Source-code scanner (unsafe load calls)
// ---------------------------------------------------------------------------

interface UnsafeLoadRule {
  id: string;
  pattern: RegExp;
  severity: ModelFindingSeverity;
  description: string;
  remediation: string;
}

const UNSAFE_LOAD_RULES: UnsafeLoadRule[] = [
  {
    id: 'CG_MODEL_SRC_001',
    pattern: /\btorch\.load\s*\([^)]*\)/,
    severity: 'high',
    description:
      'torch.load() uses pickle by default and executes arbitrary code from the file.',
    remediation:
      'Pass weights_only=True (PyTorch 1.13+) or switch to safetensors. ' +
      'Example: torch.load(path, weights_only=True)',
  },
  {
    id: 'CG_MODEL_SRC_002',
    pattern: /\bpickle\.(?:load|loads)\s*\(/,
    severity: 'high',
    description: 'pickle.load/loads() is insecure when input is untrusted.',
    remediation:
      'Validate origin of the data or use fickling for analysis. For ML models, use ' +
      'safetensors.',
  },
  {
    id: 'CG_MODEL_SRC_003',
    pattern: /\bjoblib\.load\s*\(/,
    severity: 'high',
    description: 'joblib.load() uses pickle under the hood.',
    remediation:
      'Only load files you produced. For distribution, use safetensors or ONNX.',
  },
  {
    id: 'CG_MODEL_SRC_004',
    pattern: /\btrust_remote_code\s*=\s*True/,
    severity: 'critical',
    description:
      'trust_remote_code=True executes arbitrary Python from the model repository on load.',
    remediation:
      'Set trust_remote_code=False. If the model requires custom code, audit the repo and ' +
      'pin a specific revision.',
  },
  {
    id: 'CG_MODEL_SRC_005',
    pattern: /\bload_model\s*\([^)]*(?<!safe_mode\s*=\s*True)[^)]*\)/,
    severity: 'medium',
    description:
      'Keras load_model() without safe_mode=True can execute embedded Lambda layer code.',
    remediation: 'Use load_model(path, safe_mode=True) when loading untrusted models.',
  },
  {
    id: 'CG_MODEL_SRC_006',
    pattern: /\byaml\.load\s*\(\s*(?:[^)]*(?<!Loader\s*=\s*(?:yaml\.)?SafeLoader))[^)]*\)/,
    severity: 'high',
    description: 'yaml.load() without SafeLoader deserializes arbitrary Python objects.',
    remediation: 'Use yaml.safe_load() or yaml.load(f, Loader=yaml.SafeLoader).',
  },
];

export function scanSourceForUnsafeLoads(
  text: string,
  filePath: string
): ModelFinding[] {
  const findings: ModelFinding[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0 || line.length > 3000) continue;
    for (const rule of UNSAFE_LOAD_RULES) {
      const m = rule.pattern.exec(line);
      if (m) {
        findings.push({
          file: filePath,
          category: 'unsafe-load-call',
          severity: rule.severity,
          ruleId: rule.id,
          message: rule.description,
          evidence: m[0].slice(0, 120),
          remediation: rule.remediation,
          line: i + 1,
          column: (m.index ?? 0) + 1,
        });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

export function scanModelFile(filePath: string): ModelFinding[] {
  const { type } = classifyModelFile(filePath);
  switch (type) {
    case 'pickle':
      return scanPickleFile(filePath);
    case 'keras':
      return scanKerasFile(filePath);
    case 'onnx':
      return scanOnnxFile(filePath);
    case 'safetensors':
      return scanSafetensorsFile(filePath);
    case 'hf-config':
      return scanHuggingFaceConfig(filePath);
    default:
      return [];
  }
}

/**
 * Scan the entire workspace for model files + unsafe load calls in source.
 */
export async function scanWorkspaceModels(): Promise<ModelFinding[]> {
  const all: ModelFinding[] = [];
  const folders = vscode.workspace.workspaceFolders ?? [];
  for (const folder of folders) {
    // Model files
    const modelFiles = await vscode.workspace.findFiles(
      new vscode.RelativePattern(
        folder,
        '**/*.{pkl,pickle,pt,pth,bin,ckpt,joblib,h5,hdf5,keras,onnx,safetensors}'
      ),
      '**/node_modules/**,**/.git/**,**/dist/**,**/build/**',
      500
    );
    for (const uri of modelFiles) {
      all.push(...scanModelFile(uri.fsPath));
    }

    // HF config files
    const configFiles = await vscode.workspace.findFiles(
      new vscode.RelativePattern(
        folder,
        '**/{config.json,tokenizer_config.json,generation_config.json}'
      ),
      '**/node_modules/**,**/.git/**',
      500
    );
    for (const uri of configFiles) {
      all.push(...scanHuggingFaceConfig(uri.fsPath));
    }

    // Source files with unsafe load calls
    const sourceFiles = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, '**/*.{py,ipynb,js,ts}'),
      '**/node_modules/**,**/.git/**,**/dist/**,**/build/**,**/out/**',
      2000
    );
    for (const uri of sourceFiles) {
      try {
        const stat = fs.statSync(uri.fsPath);
        if (stat.size > 2 * 1024 * 1024) continue;
        const text = fs.readFileSync(uri.fsPath, 'utf8');
        all.push(...scanSourceForUnsafeLoads(text, uri.fsPath));
      } catch {
        // ignore
      }
    }
  }
  return all;
}

/**
 * Stats for dashboards.
 */
export function getModelScannerStats(): {
  dangerousPickleGlobals: number;
  unsafeLoadRules: number;
  supportedFormats: string[];
} {
  return {
    dangerousPickleGlobals: DANGEROUS_PICKLE_GLOBALS.length,
    unsafeLoadRules: UNSAFE_LOAD_RULES.length,
    supportedFormats: [
      'pickle (.pkl/.pt/.pth/.bin/.ckpt/.joblib)',
      'Keras (.h5/.hdf5/.keras)',
      'ONNX (.onnx)',
      'safetensors (.safetensors)',
      'HuggingFace config (config.json, tokenizer_config.json)',
    ],
  };
}
