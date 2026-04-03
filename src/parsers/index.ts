import { DependencyParser, ParsedDependency } from './types';
import { JavaScriptParser } from './javascript';
import { PythonParser } from './python';

/**
 * Registry of all language-specific parsers.
 * Routes a document to the correct parser based on its languageId.
 */
export class ParserRegistry {
  private parsers: DependencyParser[] = [];

  constructor() {
    this.parsers.push(new JavaScriptParser());
    this.parsers.push(new PythonParser());
  }

  /**
   * Find the parser that supports the given language and parse the text.
   * Returns empty array if no parser matches.
   */
  parse(text: string, languageId: string): ParsedDependency[] {
    // package.json is special — route to JS parser
    if (languageId === 'json') {
      const jsParser = this.parsers.find(p => p.supportedLanguages.includes('javascript'));
      return jsParser ? jsParser.parse(text, 'json') : [];
    }

    const parser = this.parsers.find(p => p.supportedLanguages.includes(languageId));
    if (!parser) {
      return [];
    }
    return parser.parse(text, languageId);
  }

  /**
   * Check if we have a parser for the given language.
   */
  supports(languageId: string): boolean {
    if (languageId === 'json') { return true; }
    return this.parsers.some(p => p.supportedLanguages.includes(languageId));
  }
}

export { ParsedDependency, Ecosystem, DependencyParser } from './types';
