import { DependencyParser, ParsedDependency } from './types';

/**
 * Parses Python files for import statements.
 * Also parses requirements.txt and pyproject.toml for pinned versions.
 */
export class PythonParser implements DependencyParser {
  supportedLanguages = ['python'];

  // import package / import package as alias
  private static readonly IMPORT_RE = /^\s*import\s+(\w+)/gm;

  // from package import something / from package.submodule import something
  private static readonly FROM_IMPORT_RE = /^\s*from\s+(\w+)(?:\.\w+)*\s+import/gm;

  // Standard library modules to ignore (top ~100)
  private static readonly STDLIB = new Set([
    'abc', 'argparse', 'ast', 'asyncio', 'base64', 'bisect', 'builtins',
    'calendar', 'cgi', 'cmd', 'codecs', 'collections', 'colorsys',
    'compileall', 'concurrent', 'configparser', 'contextlib', 'contextvars',
    'copy', 'copyreg', 'cProfile', 'csv', 'ctypes', 'curses', 'dataclasses',
    'datetime', 'dbm', 'decimal', 'difflib', 'dis', 'doctest', 'email',
    'encodings', 'enum', 'errno', 'faulthandler', 'filecmp', 'fileinput',
    'fnmatch', 'fractions', 'ftplib', 'functools', 'gc', 'getopt', 'getpass',
    'gettext', 'glob', 'gzip', 'hashlib', 'heapq', 'hmac', 'html', 'http',
    'idlelib', 'imaplib', 'importlib', 'inspect', 'io', 'ipaddress',
    'itertools', 'json', 'keyword', 'linecache', 'locale', 'logging',
    'lzma', 'mailbox', 'math', 'mimetypes', 'mmap', 'multiprocessing',
    'netrc', 'numbers', 'operator', 'os', 'pathlib', 'pdb', 'pickle',
    'pickletools', 'platform', 'plistlib', 'poplib', 'posixpath', 'pprint',
    'profile', 'pstats', 'py_compile', 'pydoc', 'queue', 'quopri',
    'random', 're', 'readline', 'reprlib', 'resource', 'rlcompleter',
    'runpy', 'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex',
    'shutil', 'signal', 'site', 'smtplib', 'socket', 'socketserver',
    'sqlite3', 'ssl', 'stat', 'statistics', 'string', 'stringprep',
    'struct', 'subprocess', 'sys', 'sysconfig', 'syslog', 'tabnanny',
    'tarfile', 'tempfile', 'test', 'textwrap', 'threading', 'time',
    'timeit', 'tkinter', 'token', 'tokenize', 'tomllib', 'trace',
    'traceback', 'tracemalloc', 'turtle', 'turtledemo', 'types',
    'typing', 'unicodedata', 'unittest', 'urllib', 'uuid', 'venv',
    'warnings', 'wave', 'weakref', 'webbrowser', 'wsgiref', 'xml',
    'xmlrpc', 'zipapp', 'zipfile', 'zipimport', 'zlib',
    // common internal / dunder
    '__future__', '_thread', '_io',
  ]);

  parse(text: string, languageId: string): ParsedDependency[] {
    // Detect if this is a requirements.txt style file by content heuristic
    if (this.looksLikeRequirementsTxt(text)) {
      return this.parseRequirementsTxt(text);
    }
    return this.parseSourceCode(text);
  }

  /**
   * Parse Python source code for import / from-import statements.
   */
  private parseSourceCode(text: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];
    const lines = text.split('\n');
    const seen = new Set<string>();

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      // Skip comments
      if (line.trimStart().startsWith('#')) { continue; }

      this.matchPythonImport(line, lineIdx, PythonParser.IMPORT_RE, deps, seen);
      this.matchPythonImport(line, lineIdx, PythonParser.FROM_IMPORT_RE, deps, seen);
    }

    return deps;
  }

  private matchPythonImport(
    line: string,
    lineIdx: number,
    regex: RegExp,
    deps: ParsedDependency[],
    seen: Set<string>
  ): void {
    const re = new RegExp(regex.source, regex.flags);
    let match: RegExpExecArray | null;

    while ((match = re.exec(line)) !== null) {
      const pkgName = match[1];

      // Skip stdlib modules
      if (PythonParser.STDLIB.has(pkgName)) { continue; }
      // Skip relative imports (already filtered by regex, but double check)
      if (pkgName.startsWith('.') || pkgName.startsWith('_')) { continue; }
      // Deduplicate within same file
      if (seen.has(pkgName)) { continue; }
      seen.add(pkgName);

      // Normalize: some PyPI packages use hyphens but import with underscores
      const normalizedName = this.normalizePyPIName(pkgName);

      deps.push({
        name: normalizedName,
        version: null,
        ecosystem: 'PyPI',
        line: lineIdx,
        columnStart: match.index,
        columnEnd: match.index + match[0].length,
        rawStatement: match[0],
      });
    }
  }

  /**
   * Parse requirements.txt style content.
   * Supports: package==1.0.0, package>=1.0.0, package~=1.0, package
   */
  parseRequirementsTxt(text: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];
    const lines = text.split('\n');

    const reqLineRe = /^\s*([a-zA-Z0-9_][\w.-]*)\s*(?:([=!<>~]=?)\s*([\d.]+[\w.]*))?/;

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx].trim();
      if (!line || line.startsWith('#') || line.startsWith('-')) { continue; }

      const match = reqLineRe.exec(line);
      if (!match) { continue; }

      const name = this.normalizePyPIName(match[1]);
      const version = match[3] || null;

      deps.push({
        name,
        version,
        ecosystem: 'PyPI',
        line: lineIdx,
        columnStart: 0,
        columnEnd: line.length,
        rawStatement: line,
      });
    }

    return deps;
  }

  /**
   * Heuristic: if most non-empty non-comment lines match "package==version" pattern,
   * treat as requirements.txt.
   */
  private looksLikeRequirementsTxt(text: string): boolean {
    const lines = text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
    if (lines.length === 0) { return false; }

    const reqPattern = /^[a-zA-Z0-9_][\w.-]*\s*([=!<>~]=)/;
    const matchCount = lines.filter(l => reqPattern.test(l.trim())).length;
    return matchCount / lines.length > 0.5;
  }

  /**
   * Normalize Python import name to PyPI distribution name.
   * Underscores -> hyphens is the common convention (e.g., import PIL -> Pillow).
   * We keep underscores as-is for registry lookup since PyPI normalizes both.
   */
  private normalizePyPIName(name: string): string {
    return name.toLowerCase().replace(/_/g, '-');
  }
}
