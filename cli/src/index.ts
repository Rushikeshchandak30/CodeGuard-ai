#!/usr/bin/env node

/**
 * CodeGuard AI CLI — scan projects for security issues from the command line.
 *
 * Usage:
 *   codeguard scan [--path .] [--format table|json|sarif] [--severity low|medium|high|critical]
 *   codeguard pre-commit
 *   codeguard --help
 */

import * as path from 'path';
import { CoreScanner, ScanOptions, ScanResult, Severity } from './scanner';
import { toSarif } from './formatters/sarif';
import { toTable } from './formatters/table';

// ─── CLI Argument Parser (zero-dependency) ───────────────────────────

interface CliArgs {
  command: 'scan' | 'pre-commit' | 'help' | 'version';
  projectPath: string;
  format: 'table' | 'json' | 'sarif';
  severity: Severity;
  noColor: boolean;
  hallucination: boolean;
  vulnerabilities: boolean;
  secrets: boolean;
  sast: boolean;
  policy: boolean;
  ignore: string[];
  privateScopes: string[];
  outputFile: string | null;
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    command: 'scan',
    projectPath: process.cwd(),
    format: 'table',
    severity: 'low',
    noColor: false,
    hallucination: true,
    vulnerabilities: true,
    secrets: true,
    sast: true,
    policy: true,
    ignore: [],
    privateScopes: [],
    outputFile: null,
  };

  // Skip node and script path
  const cliArgs = argv.slice(2);
  let i = 0;

  while (i < cliArgs.length) {
    const arg = cliArgs[i];

    switch (arg) {
      case 'scan':
        args.command = 'scan';
        break;
      case 'pre-commit':
        args.command = 'pre-commit';
        break;
      case '--help':
      case '-h':
        args.command = 'help';
        break;
      case '--version':
      case '-v':
        args.command = 'version';
        break;
      case '--path':
      case '-p':
        i++;
        if (cliArgs[i]) { args.projectPath = path.resolve(cliArgs[i]); }
        break;
      case '--format':
      case '-f':
        i++;
        if (['table', 'json', 'sarif'].includes(cliArgs[i])) {
          args.format = cliArgs[i] as 'table' | 'json' | 'sarif';
        }
        break;
      case '--severity':
      case '-s':
        i++;
        if (['critical', 'high', 'medium', 'low', 'info'].includes(cliArgs[i])) {
          args.severity = cliArgs[i] as Severity;
        }
        break;
      case '--no-color':
        args.noColor = true;
        break;
      case '--no-hallucination':
        args.hallucination = false;
        break;
      case '--no-vuln':
        args.vulnerabilities = false;
        break;
      case '--no-secrets':
        args.secrets = false;
        break;
      case '--no-sast':
        args.sast = false;
        break;
      case '--no-policy':
        args.policy = false;
        break;
      case '--ignore':
        i++;
        if (cliArgs[i]) { args.ignore.push(...cliArgs[i].split(',')); }
        break;
      case '--private-scopes':
        i++;
        if (cliArgs[i]) { args.privateScopes.push(...cliArgs[i].split(',')); }
        break;
      case '--output':
      case '-o':
        i++;
        if (cliArgs[i]) { args.outputFile = cliArgs[i]; }
        break;
      default:
        // If no command given yet and arg doesn't start with --, treat as path
        if (!arg.startsWith('--') && !arg.startsWith('-') && arg !== 'scan' && arg !== 'pre-commit') {
          args.projectPath = path.resolve(arg);
        }
        break;
    }
    i++;
  }

  return args;
}

// ─── Output Formatting ───────────────────────────────────────────────

function formatResult(result: ScanResult, format: string, noColor: boolean): string {
  switch (format) {
    case 'json':
      return JSON.stringify(result, null, 2);
    case 'sarif':
      return toSarif(result);
    case 'table':
    default:
      return toTable(result, !noColor);
  }
}

// ─── Help Text ───────────────────────────────────────────────────────

function printHelp(): void {
  console.log(`
  CodeGuard AI CLI v5.2.0
  Real-time AI code security scanner

  USAGE:
    codeguard scan [options]          Scan a project for security issues
    codeguard pre-commit              Run as a pre-commit hook (exit 1 on critical/high)
    codeguard --help                  Show this help
    codeguard --version               Show version

  OPTIONS:
    --path, -p <dir>                  Project directory to scan (default: cwd)
    --format, -f <fmt>                Output format: table, json, sarif (default: table)
    --severity, -s <level>            Min severity to report: critical, high, medium, low (default: low)
    --output, -o <file>               Write output to file instead of stdout
    --no-color                        Disable colored output
    --no-hallucination                Skip hallucination detection
    --no-vuln                         Skip vulnerability scanning
    --no-secrets                      Skip secrets scanning
    --no-sast                         Skip SAST scanning
    --no-policy                       Skip policy evaluation
    --ignore <pkg1,pkg2>              Packages to ignore (comma-separated)
    --private-scopes <@co1/,@co2/>    Private scoped packages to skip

  EXAMPLES:
    codeguard scan                                     # Scan current directory
    codeguard scan --path ./my-project --format sarif   # SARIF output for CI
    codeguard scan -f json -o report.json               # JSON report to file
    codeguard pre-commit                                # Pre-commit hook mode
    codeguard scan --ignore lodash,express              # Skip known packages
`);
}

// ─── Main ────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  switch (args.command) {
    case 'help':
      printHelp();
      process.exit(0);
      break;
    case 'version':
      console.log('codeguard-ai/cli v5.2.0');
      process.exit(0);
      break;
    case 'pre-commit':
    case 'scan': {
      const options: ScanOptions = {
        projectPath: args.projectPath,
        hallucination: args.hallucination,
        vulnerabilities: args.vulnerabilities,
        secrets: args.secrets,
        sast: args.sast,
        policy: args.policy,
        severityThreshold: args.severity,
        ignoredPackages: args.ignore,
        privateRegistries: args.privateScopes,
      };

      const scanner = new CoreScanner(options);

      // Show scanning message for table format
      if (args.format === 'table' && !args.noColor) {
        process.stderr.write('\x1b[36m  Scanning...\x1b[0m\n');
      }

      try {
        const result = await scanner.scan();
        const output = formatResult(result, args.format, args.noColor);

        // Write to file or stdout
        if (args.outputFile) {
          const fs = await import('fs');
          fs.writeFileSync(args.outputFile, output, 'utf-8');
          if (args.format === 'table') {
            console.log(`  Report written to ${args.outputFile}`);
          }
        } else {
          console.log(output);
        }

        // Exit code based on findings
        if (args.command === 'pre-commit') {
          // Pre-commit mode: fail on any critical or high findings
          if (result.summary.critical > 0 || result.summary.high > 0) {
            process.exit(1);
          }
        } else {
          // Normal mode: fail only on critical
          if (result.summary.critical > 0) {
            process.exit(1);
          }
        }
      } catch (error) {
        console.error(`  Error: ${error instanceof Error ? error.message : String(error)}`);
        process.exit(2);
      }
      break;
    }
    default:
      printHelp();
      process.exit(0);
  }
}

main();
