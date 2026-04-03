/**
 * Represents a parsed dependency found in source code.
 */
export interface ParsedDependency {
  /** Package name (e.g. "lodash", "requests") */
  name: string;
  /** Version constraint if found (e.g. "4.17.15", ">=2.28.0") */
  version: string | null;
  /** Package ecosystem: npm, PyPI, Go, Maven, crates.io */
  ecosystem: Ecosystem;
  /** Line number in the document (0-indexed) */
  line: number;
  /** Column start position (0-indexed) */
  columnStart: number;
  /** Column end position (0-indexed) */
  columnEnd: number;
  /** The raw import statement text */
  rawStatement: string;
}

export type Ecosystem = 'npm' | 'PyPI' | 'Go' | 'Maven' | 'crates.io';

/**
 * Interface that all language-specific parsers must implement.
 */
export interface DependencyParser {
  /** Which VS Code language IDs this parser handles */
  supportedLanguages: string[];
  /** Parse a document's text and return all found dependencies */
  parse(text: string, languageId: string): ParsedDependency[];
}
