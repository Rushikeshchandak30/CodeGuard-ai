import { DependencyParser, ParsedDependency } from './types';

/**
 * Parses JavaScript/TypeScript files for import statements and require() calls.
 * Also parses package.json dependencies.
 */
export class JavaScriptParser implements DependencyParser {
  supportedLanguages = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];

  // ES module: import X from 'package' / import 'package' / import { X } from 'package'
  private static readonly ES_IMPORT_RE =
    /^\s*import\s+(?:(?:[\w*{}\s,]+)\s+from\s+)?['"]([^'"./][^'"]*)['"]/gm;

  // CommonJS: require('package')
  private static readonly REQUIRE_RE =
    /\brequire\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/gm;

  // Dynamic import: import('package')
  private static readonly DYNAMIC_IMPORT_RE =
    /\bimport\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/gm;

  parse(text: string, languageId: string): ParsedDependency[] {
    if (languageId === 'json') {
      return this.parsePackageJson(text);
    }
    return this.parseSourceCode(text);
  }

  private parseSourceCode(text: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];
    const lines = text.split('\n');

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      // ES imports
      this.matchImports(line, lineIdx, JavaScriptParser.ES_IMPORT_RE, deps);
      // require() calls
      this.matchImports(line, lineIdx, JavaScriptParser.REQUIRE_RE, deps);
      // dynamic import()
      this.matchImports(line, lineIdx, JavaScriptParser.DYNAMIC_IMPORT_RE, deps);
    }

    return deps;
  }

  private matchImports(
    line: string,
    lineIdx: number,
    regex: RegExp,
    deps: ParsedDependency[]
  ): void {
    // Reset regex state for each line
    const re = new RegExp(regex.source, regex.flags);
    let match: RegExpExecArray | null;

    while ((match = re.exec(line)) !== null) {
      const rawPackage = match[1];
      const { name } = this.extractPackageName(rawPackage);

      const colStart = match.index;
      const colEnd = match.index + match[0].length;

      deps.push({
        name,
        version: null, // Version comes from package.json/lockfile, not import statements
        ecosystem: 'npm',
        line: lineIdx,
        columnStart: colStart,
        columnEnd: colEnd,
        rawStatement: match[0],
      });
    }
  }

  /**
   * Parses package.json to extract dependencies with versions.
   */
  private parsePackageJson(text: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];

    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(text);
    } catch {
      return deps;
    }

    const depSections = [
      'dependencies',
      'devDependencies',
      'peerDependencies',
      'optionalDependencies',
    ];

    const lines = text.split('\n');

    for (const section of depSections) {
      const sectionDeps = parsed[section] as Record<string, string> | undefined;
      if (!sectionDeps || typeof sectionDeps !== 'object') {
        continue;
      }

      for (const [pkgName, versionStr] of Object.entries(sectionDeps)) {
        if (typeof versionStr !== 'string') { continue; }

        // Find the line where this package appears
        const lineIdx = lines.findIndex(l => l.includes(`"${pkgName}"`));
        const colStart = lineIdx >= 0 ? lines[lineIdx].indexOf(`"${pkgName}"`) : 0;
        const colEnd = lineIdx >= 0 ? lines[lineIdx].length : 0;

        const cleanVersion = this.cleanVersion(versionStr);

        deps.push({
          name: pkgName,
          version: cleanVersion,
          ecosystem: 'npm',
          line: Math.max(lineIdx, 0),
          columnStart: colStart,
          columnEnd: colEnd,
          rawStatement: `"${pkgName}": "${versionStr}"`,
        });
      }
    }

    return deps;
  }

  /**
   * Extracts the bare package name from an import specifier.
   * Handles scoped packages: @scope/package/subpath -> @scope/package
   * Handles subpaths: lodash/merge -> lodash
   */
  private extractPackageName(raw: string): { name: string } {
    if (raw.startsWith('@')) {
      // Scoped: @scope/pkg or @scope/pkg/subpath
      const parts = raw.split('/');
      const name = parts.length >= 2 ? `${parts[0]}/${parts[1]}` : raw;
      return { name };
    }
    // Unscoped: pkg or pkg/subpath
    const name = raw.split('/')[0];
    return { name };
  }

  /**
   * Strips version range prefixes: ^1.2.3 -> 1.2.3, ~1.2.3 -> 1.2.3, >=1.0.0 -> 1.0.0
   */
  private cleanVersion(version: string): string | null {
    const cleaned = version.replace(/^[\^~>=<]*\s*/, '').trim();
    // Must look like a semver
    if (/^\d+\.\d+/.test(cleaned)) {
      return cleaned;
    }
    return null;
  }
}
