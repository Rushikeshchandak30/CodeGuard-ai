/**
 * SBOM Drift Detector — Dependency Drift Detection
 *
 * Compares current SBOM against a saved baseline to detect:
 * - New dependencies added (by AI or developer)
 * - Versions changed (especially to vulnerable versions)
 * - Dependencies removed
 * - Packages yanked from registry since last scan
 * - License changes
 */

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { CycloneDXBom, BomComponent } from './generator';

// ---------------------------------------------------------------------------
// Drift Types
// ---------------------------------------------------------------------------

export type DriftType = 'added' | 'removed' | 'version_changed' | 'license_changed';

export interface DriftEntry {
  type: DriftType;
  packageName: string;
  ecosystem: string;
  previousVersion?: string;
  currentVersion?: string;
  previousLicense?: string;
  currentLicense?: string;
  isNewlyVulnerable?: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
}

export interface DriftReport {
  baselineDate: Date | null;
  currentDate: Date;
  totalChanges: number;
  added: DriftEntry[];
  removed: DriftEntry[];
  versionChanged: DriftEntry[];
  licenseChanged: DriftEntry[];
  hasHighRiskChanges: boolean;
  summary: string;
}

// ---------------------------------------------------------------------------
// SbomDriftDetector
// ---------------------------------------------------------------------------

export class SbomDriftDetector {
  private baselinePath: string | null = null;
  private baseline: CycloneDXBom | null = null;

  constructor() {
    this.loadBaseline();
  }

  /**
   * Load baseline SBOM from .codeguard/sbom-baseline.cdx.json
   */
  private loadBaseline(): void {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) { return; }

    const baselineFile = path.join(
      workspaceFolders[0].uri.fsPath,
      '.codeguard',
      'sbom-baseline.cdx.json'
    );

    if (fs.existsSync(baselineFile)) {
      try {
        const content = fs.readFileSync(baselineFile, 'utf-8');
        this.baseline = JSON.parse(content) as CycloneDXBom;
        this.baselinePath = baselineFile;
      } catch {
        this.baseline = null;
      }
    }
  }

  /**
   * Save current SBOM as the new baseline.
   */
  saveBaseline(bom: CycloneDXBom): void {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) { return; }

    const dir = path.join(workspaceFolders[0].uri.fsPath, '.codeguard');
    if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }

    const baselineFile = path.join(dir, 'sbom-baseline.cdx.json');
    fs.writeFileSync(baselineFile, JSON.stringify(bom, null, 2), 'utf-8');
    this.baseline = bom;
    this.baselinePath = baselineFile;
  }

  /**
   * Compare current SBOM against baseline and return drift report.
   */
  detectDrift(current: CycloneDXBom): DriftReport {
    const entries: DriftEntry[] = [];
    const currentDate = new Date();

    if (!this.baseline) {
      return {
        baselineDate: null,
        currentDate,
        totalChanges: 0,
        added: [],
        removed: [],
        versionChanged: [],
        licenseChanged: [],
        hasHighRiskChanges: false,
        summary: 'No baseline found. Run "CodeGuard: Save SBOM Baseline" to start drift tracking.',
      };
    }

    // Build lookup maps
    const baselineMap = new Map<string, BomComponent>();
    for (const comp of this.baseline.components) {
      baselineMap.set(comp['bom-ref'] ?? comp.name, comp);
    }

    const currentMap = new Map<string, BomComponent>();
    for (const comp of current.components) {
      currentMap.set(comp['bom-ref'] ?? comp.name, comp);
    }

    // Detect added packages
    for (const [key, comp] of currentMap) {
      if (!baselineMap.has(key)) {
        entries.push({
          type: 'added',
          packageName: comp.name,
          ecosystem: this.ecosystemFromPurl(comp.purl),
          currentVersion: comp.version,
          severity: 'medium',
          description: `New dependency added: ${comp.name}@${comp.version}`,
        });
      }
    }

    // Detect removed packages
    for (const [key, comp] of baselineMap) {
      if (!currentMap.has(key)) {
        entries.push({
          type: 'removed',
          packageName: comp.name,
          ecosystem: this.ecosystemFromPurl(comp.purl),
          previousVersion: comp.version,
          severity: 'info',
          description: `Dependency removed: ${comp.name}@${comp.version}`,
        });
      }
    }

    // Detect version changes and license changes
    for (const [key, currentComp] of currentMap) {
      const baselineComp = baselineMap.get(key);
      if (!baselineComp) { continue; }

      if (baselineComp.version !== currentComp.version) {
        // Determine if this is a downgrade (potentially to vulnerable version)
        const isDowngrade = this.isVersionDowngrade(baselineComp.version, currentComp.version);
        entries.push({
          type: 'version_changed',
          packageName: currentComp.name,
          ecosystem: this.ecosystemFromPurl(currentComp.purl),
          previousVersion: baselineComp.version,
          currentVersion: currentComp.version,
          severity: isDowngrade ? 'high' : 'low',
          description: `${currentComp.name}: ${baselineComp.version} → ${currentComp.version}${isDowngrade ? ' (DOWNGRADE ⚠️)' : ''}`,
        });
      }

      // License change detection
      const prevLicense = baselineComp.licenses?.[0]?.license?.id;
      const currLicense = currentComp.licenses?.[0]?.license?.id;
      if (prevLicense && currLicense && prevLicense !== currLicense) {
        const isRestrictive = this.isMoreRestrictiveLicense(prevLicense, currLicense);
        entries.push({
          type: 'license_changed',
          packageName: currentComp.name,
          ecosystem: this.ecosystemFromPurl(currentComp.purl),
          previousLicense: prevLicense,
          currentLicense: currLicense,
          severity: isRestrictive ? 'high' : 'medium',
          description: `${currentComp.name}: license changed from ${prevLicense} to ${currLicense}${isRestrictive ? ' (more restrictive ⚠️)' : ''}`,
        });
      }
    }

    const added = entries.filter(e => e.type === 'added');
    const removed = entries.filter(e => e.type === 'removed');
    const versionChanged = entries.filter(e => e.type === 'version_changed');
    const licenseChanged = entries.filter(e => e.type === 'license_changed');

    const hasHighRiskChanges = entries.some(e => e.severity === 'critical' || e.severity === 'high');

    const baselineDate = this.baseline.metadata?.timestamp
      ? new Date(this.baseline.metadata.timestamp)
      : null;

    let summary = `${entries.length} change(s) since baseline`;
    if (added.length > 0) { summary += ` | +${added.length} added`; }
    if (removed.length > 0) { summary += ` | -${removed.length} removed`; }
    if (versionChanged.length > 0) { summary += ` | ${versionChanged.length} version change(s)`; }
    if (hasHighRiskChanges) { summary += ' | ⚠️ HIGH RISK CHANGES DETECTED'; }

    return {
      baselineDate,
      currentDate,
      totalChanges: entries.length,
      added,
      removed,
      versionChanged,
      licenseChanged,
      hasHighRiskChanges,
      summary,
    };
  }

  /**
   * Extract ecosystem from a purl string (e.g. "pkg:npm/lodash@4.17.21" → "npm").
   */
  private ecosystemFromPurl(purl?: string): string {
    if (!purl) { return 'unknown'; }
    const match = /^pkg:([^/]+)\//.exec(purl);
    return match ? match[1] : 'unknown';
  }

  /**
   * Check if new version is lower than old version (potential downgrade to vulnerable).
   */
  private isVersionDowngrade(oldVersion: string, newVersion: string): boolean {
    try {
      const parseVer = (v: string) => v.replace(/[^0-9.]/g, '').split('.').map(Number);
      const old = parseVer(oldVersion);
      const cur = parseVer(newVersion);
      for (let i = 0; i < Math.max(old.length, cur.length); i++) {
        const o = old[i] ?? 0;
        const c = cur[i] ?? 0;
        if (c < o) { return true; }
        if (c > o) { return false; }
      }
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Check if new license is more restrictive than old (e.g., MIT → GPL).
   */
  private isMoreRestrictiveLicense(oldLicense: string, newLicense: string): boolean {
    const restrictiveness: Record<string, number> = {
      'MIT': 1, 'ISC': 1, 'BSD-2-Clause': 1, 'BSD-3-Clause': 1,
      'Apache-2.0': 2,
      'LGPL-2.0': 3, 'LGPL-2.1': 3, 'LGPL-3.0': 3,
      'GPL-2.0': 4, 'GPL-3.0': 4,
      'AGPL-3.0': 5,
      'SSPL-1.0': 6, 'BUSL-1.1': 6,
    };
    const oldR = restrictiveness[oldLicense] ?? 0;
    const newR = restrictiveness[newLicense] ?? 0;
    return newR > oldR;
  }

  /**
   * Format drift report as markdown.
   */
  toMarkdown(report: DriftReport): string {
    let md = `# SBOM Drift Report\n\n`;
    md += `**Baseline:** ${report.baselineDate?.toLocaleString() ?? 'None'}\n`;
    md += `**Current:** ${report.currentDate.toLocaleString()}\n`;
    md += `**Summary:** ${report.summary}\n\n`;

    if (report.totalChanges === 0) {
      md += `✅ No dependency changes since baseline.\n`;
      return md;
    }

    if (report.added.length > 0) {
      md += `## ➕ Added (${report.added.length})\n\n`;
      for (const e of report.added) {
        md += `- **${e.packageName}@${e.currentVersion}** — ${e.description}\n`;
      }
      md += '\n';
    }

    if (report.removed.length > 0) {
      md += `## ➖ Removed (${report.removed.length})\n\n`;
      for (const e of report.removed) {
        md += `- **${e.packageName}@${e.previousVersion}**\n`;
      }
      md += '\n';
    }

    if (report.versionChanged.length > 0) {
      md += `## 🔄 Version Changes (${report.versionChanged.length})\n\n`;
      for (const e of report.versionChanged) {
        const icon = e.severity === 'high' ? '⚠️' : '→';
        md += `- **${e.packageName}**: ${e.previousVersion} ${icon} ${e.currentVersion}\n`;
      }
      md += '\n';
    }

    if (report.licenseChanged.length > 0) {
      md += `## ⚖️ License Changes (${report.licenseChanged.length})\n\n`;
      for (const e of report.licenseChanged) {
        md += `- **${e.packageName}**: ${e.previousLicense} → ${e.currentLicense}\n`;
      }
      md += '\n';
    }

    return md;
  }

  hasBaseline(): boolean {
    return this.baseline !== null;
  }
}
