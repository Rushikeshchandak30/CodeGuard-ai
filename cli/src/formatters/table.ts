/**
 * Human-readable table formatter for terminal output.
 */

import { ScanResult, ScanFinding, Severity } from '../scanner';

// ─── ANSI Color Codes ────────────────────────────────────────────────

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgGreen: '\x1b[42m',
};

function severityColor(severity: Severity): string {
  switch (severity) {
    case 'critical': return COLORS.bgRed + COLORS.white + COLORS.bold;
    case 'high': return COLORS.red + COLORS.bold;
    case 'medium': return COLORS.yellow;
    case 'low': return COLORS.blue;
    case 'info': return COLORS.dim;
    default: return COLORS.reset;
  }
}

function severityBadge(severity: Severity): string {
  const color = severityColor(severity);
  return `${color} ${severity.toUpperCase().padEnd(8)} ${COLORS.reset}`;
}

function typeBadge(type: string): string {
  switch (type) {
    case 'hallucination': return `${COLORS.magenta}HALLUCINATION${COLORS.reset}`;
    case 'vulnerability': return `${COLORS.red}VULNERABILITY${COLORS.reset}`;
    case 'secret': return `${COLORS.bgRed}${COLORS.white}SECRET${COLORS.reset}`;
    case 'sast': return `${COLORS.yellow}SAST${COLORS.reset}`;
    case 'policy': return `${COLORS.cyan}POLICY${COLORS.reset}`;
    case 'mcp': return `${COLORS.bgYellow}${COLORS.white}MCP${COLORS.reset}`;
    default: return type;
  }
}

/**
 * Format scan results as a human-readable table for terminal output.
 */
export function toTable(result: ScanResult, useColor: boolean = true): string {
  const c = useColor ? COLORS : {
    reset: '', bold: '', dim: '', red: '', green: '', yellow: '',
    blue: '', magenta: '', cyan: '', white: '', bgRed: '', bgYellow: '', bgGreen: '',
  };

  const lines: string[] = [];

  // Header
  lines.push('');
  lines.push(`${c.bold}${c.cyan}  CodeGuard AI — Security Scan Report${c.reset}`);
  lines.push(`${c.dim}  ${result.timestamp}${c.reset}`);
  lines.push(`${c.dim}  Project: ${result.projectPath}${c.reset}`);
  lines.push('');

  // Summary bar
  const s = result.summary;
  const scoreColor = s.critical > 0 ? c.red : s.high > 0 ? c.yellow : c.green;
  lines.push(`${c.bold}  Summary${c.reset}`);
  lines.push(`  ${c.dim}─────────────────────────────────────────${c.reset}`);
  lines.push(`  Files scanned:      ${c.bold}${s.scannedFiles}${c.reset}`);
  lines.push(`  Total findings:     ${scoreColor}${c.bold}${s.totalFindings}${c.reset}`);

  if (s.critical > 0) { lines.push(`    Critical:         ${c.red}${c.bold}${s.critical}${c.reset}`); }
  if (s.high > 0)     { lines.push(`    High:             ${c.red}${s.high}${c.reset}`); }
  if (s.medium > 0)   { lines.push(`    Medium:           ${c.yellow}${s.medium}${c.reset}`); }
  if (s.low > 0)      { lines.push(`    Low:              ${c.blue}${s.low}${c.reset}`); }

  lines.push('');
  if (s.hallucinatedPackages > 0) {
    lines.push(`  ${c.magenta}Hallucinated pkgs:  ${s.hallucinatedPackages}${c.reset}`);
  }
  if (s.secretsFound > 0) {
    lines.push(`  ${c.red}Secrets found:      ${s.secretsFound}${c.reset}`);
  }
  if (s.sastFindings > 0) {
    lines.push(`  ${c.yellow}SAST findings:      ${s.sastFindings}${c.reset}`);
  }
  if (s.mcpIssues > 0) {
    lines.push(`  ${c.yellow}MCP issues:         ${s.mcpIssues}${c.reset}`);
  }
  if (s.policyViolations > 0) {
    lines.push(`  ${c.cyan}Policy violations:  ${s.policyViolations}${c.reset}`);
  }
  lines.push('');

  // Findings detail
  if (result.findings.length > 0) {
    lines.push(`${c.bold}  Findings${c.reset}`);
    lines.push(`  ${c.dim}─────────────────────────────────────────${c.reset}`);

    // Group by severity
    const grouped = new Map<Severity, ScanFinding[]>();
    for (const f of result.findings) {
      if (!grouped.has(f.severity)) { grouped.set(f.severity, []); }
      grouped.get(f.severity)!.push(f);
    }

    const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    for (const sev of order) {
      const findings = grouped.get(sev);
      if (!findings || findings.length === 0) { continue; }

      for (const f of findings) {
        const badge = useColor ? severityBadge(f.severity) : `[${f.severity.toUpperCase()}]`;
        const tBadge = useColor ? typeBadge(f.type) : `[${f.type.toUpperCase()}]`;
        lines.push(`  ${badge} ${tBadge}  ${f.message}`);
        lines.push(`    ${c.dim}${f.file}:${f.line}${c.reset}`);
        if (f.fix) {
          lines.push(`    ${c.green}Fix: ${f.fix}${c.reset}`);
        }
        lines.push('');
      }
    }
  } else {
    lines.push(`  ${c.green}${c.bold}No security issues found.${c.reset}`);
    lines.push('');
  }

  // Footer
  const passEmoji = result.summary.critical === 0 && result.summary.high === 0 ? 'PASS' : 'FAIL';
  const passColor = passEmoji === 'PASS' ? c.green : c.red;
  lines.push(`  ${c.dim}─────────────────────────────────────────${c.reset}`);
  lines.push(`  ${passColor}${c.bold}${passEmoji}${c.reset} — CodeGuard AI v7.0.0`);
  lines.push('');

  return lines.join('\n');
}
