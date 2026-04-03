/**
 * Live SBOM Generator
 *
 * Generates a real-time Software Bill of Materials (SBOM) in CycloneDX format.
 * Updates as code is written, tracking:
 * - Direct dependencies
 * - Transitive dependencies (from lockfiles)
 * - Vulnerability status
 * - License information
 * - Provenance status
 *
 * Output: .codeguard/sbom.cdx.json (CycloneDX 1.5 format)
 *
 * Compliance: US Executive Order 14028, EU Cyber Resilience Act
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';

// ---------------------------------------------------------------------------
// CycloneDX Types (1.5 spec)
// ---------------------------------------------------------------------------

export interface CycloneDXBom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: number;
  metadata: BomMetadata;
  components: BomComponent[];
  dependencies: BomDependency[];
  vulnerabilities?: BomVulnerability[];
}

export interface BomMetadata {
  timestamp: string;
  tools: Array<{
    vendor: string;
    name: string;
    version: string;
  }>;
  component?: {
    type: string;
    name: string;
    version: string;
  };
}

export interface BomComponent {
  type: 'library' | 'application' | 'framework' | 'file';
  'bom-ref': string;
  name: string;
  version: string;
  purl?: string;
  licenses?: Array<{ license: { id?: string; name?: string } }>;
  externalReferences?: Array<{
    type: string;
    url: string;
  }>;
  properties?: Array<{
    name: string;
    value: string;
  }>;
}

export interface BomDependency {
  ref: string;
  dependsOn: string[];
}

export interface BomVulnerability {
  id: string;
  source: { name: string; url: string };
  ratings?: Array<{
    severity: string;
    score?: number;
    method?: string;
  }>;
  affects: Array<{
    ref: string;
    versions?: Array<{ version: string; status: string }>;
  }>;
  recommendation?: string;
}

// ---------------------------------------------------------------------------
// SBOM Generator Class
// ---------------------------------------------------------------------------

export class SbomGenerator {
  private outputDir: string = '.codeguard';
  private outputFile: string = 'sbom.cdx.json';
  private currentBom: CycloneDXBom | null = null;
  private bomVersion: number = 1;
  private watcher: vscode.FileSystemWatcher | null = null;

  constructor() {
    this.initializeBom();
  }

  /**
   * Activate the SBOM generator with file watchers.
   */
  activate(context: vscode.ExtensionContext): void {
    // Watch package.json and requirements.txt for changes
    this.watcher = vscode.workspace.createFileSystemWatcher('**/{package.json,package-lock.json,yarn.lock,pnpm-lock.yaml,requirements.txt,Pipfile.lock,Cargo.lock,go.sum}');

    this.watcher.onDidChange(() => this.regenerate());
    this.watcher.onDidCreate(() => this.regenerate());
    this.watcher.onDidDelete(() => this.regenerate());

    context.subscriptions.push(this.watcher);

    // Initial generation
    this.regenerate();
  }

  /**
   * Generate SBOM for the current workspace.
   */
  async generate(): Promise<CycloneDXBom> {
    this.initializeBom();

    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
      return this.currentBom!;
    }

    const rootPath = workspaceFolders[0].uri.fsPath;

    // Parse npm dependencies
    await this.parseNpmDependencies(rootPath);

    // Parse Python dependencies
    await this.parsePythonDependencies(rootPath);

    // Parse Cargo dependencies
    await this.parseCargoDependencies(rootPath);

    // Parse Go dependencies
    await this.parseGoDependencies(rootPath);

    // Update metadata
    this.currentBom!.metadata.timestamp = new Date().toISOString();
    this.currentBom!.version = this.bomVersion++;

    return this.currentBom!;
  }

  /**
   * Regenerate and save SBOM to disk.
   */
  async regenerate(): Promise<void> {
    try {
      const bom = await this.generate();
      await this.saveToDisk(bom);
    } catch (err) {
      console.error('[CodeGuard SBOM] Generation failed:', err);
    }
  }

  /**
   * Save SBOM to .codeguard/sbom.cdx.json
   */
  async saveToDisk(bom: CycloneDXBom): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
      return;
    }

    const rootPath = workspaceFolders[0].uri.fsPath;
    const outputDirPath = path.join(rootPath, this.outputDir);
    const outputFilePath = path.join(outputDirPath, this.outputFile);

    // Create .codeguard directory if it doesn't exist
    if (!fs.existsSync(outputDirPath)) {
      fs.mkdirSync(outputDirPath, { recursive: true });
    }

    // Write SBOM
    fs.writeFileSync(outputFilePath, JSON.stringify(bom, null, 2));
  }

  /**
   * Get the current SBOM.
   */
  getBom(): CycloneDXBom | null {
    return this.currentBom;
  }

  /**
   * Add a vulnerability to the SBOM.
   */
  addVulnerability(vuln: BomVulnerability): void {
    if (!this.currentBom) { return; }
    if (!this.currentBom.vulnerabilities) {
      this.currentBom.vulnerabilities = [];
    }

    // Check if already exists
    const existing = this.currentBom.vulnerabilities.find(v => v.id === vuln.id);
    if (!existing) {
      this.currentBom.vulnerabilities.push(vuln);
    }
  }

  /**
   * Get component count.
   */
  getComponentCount(): number {
    return this.currentBom?.components.length ?? 0;
  }

  /**
   * Get vulnerability count.
   */
  getVulnerabilityCount(): number {
    return this.currentBom?.vulnerabilities?.length ?? 0;
  }

  // -------------------------------------------------------------------------
  // Private methods
  // -------------------------------------------------------------------------

  private initializeBom(): void {
    this.currentBom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${this.generateUuid()}`,
      version: this.bomVersion,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{
          vendor: 'CodeGuard AI',
          name: 'codeguard-sbom-generator',
          version: '0.3.0',
        }],
      },
      components: [],
      dependencies: [],
    };
  }

  private generateUuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  private async parseNpmDependencies(rootPath: string): Promise<void> {
    const packageJsonPath = path.join(rootPath, 'package.json');
    const packageLockPath = path.join(rootPath, 'package-lock.json');

    if (!fs.existsSync(packageJsonPath)) {
      return;
    }

    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));

      // Set root component
      if (packageJson.name) {
        this.currentBom!.metadata.component = {
          type: 'application',
          name: packageJson.name,
          version: packageJson.version || '0.0.0',
        };
      }

      // Parse direct dependencies
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
      };

      for (const [name, versionSpec] of Object.entries(allDeps)) {
        const version = this.cleanVersion(versionSpec as string);
        this.addComponent({
          type: 'library',
          'bom-ref': `pkg:npm/${name}@${version}`,
          name,
          version,
          purl: `pkg:npm/${name}@${version}`,
          properties: [{
            name: 'cdx:npm:package:development',
            value: packageJson.devDependencies?.[name] ? 'true' : 'false',
          }],
        });
      }

      // Parse lockfile for transitive dependencies
      if (fs.existsSync(packageLockPath)) {
        const lockfile = JSON.parse(fs.readFileSync(packageLockPath, 'utf-8'));
        const packages = lockfile.packages || {};

        for (const [pkgPath, pkgInfo] of Object.entries(packages)) {
          if (pkgPath === '' || !pkgPath.includes('node_modules/')) { continue; }

          const info = pkgInfo as { version?: string; resolved?: string; license?: string };
          const name = pkgPath.replace(/.*node_modules\//, '');
          const version = info.version || 'unknown';

          // Skip if already added
          const bomRef = `pkg:npm/${name}@${version}`;
          if (this.currentBom!.components.some(c => c['bom-ref'] === bomRef)) {
            continue;
          }

          const component: BomComponent = {
            type: 'library',
            'bom-ref': bomRef,
            name,
            version,
            purl: bomRef,
          };

          if (info.license) {
            component.licenses = [{ license: { id: info.license } }];
          }

          this.addComponent(component);
        }
      }
    } catch (err) {
      console.error('[CodeGuard SBOM] Error parsing npm dependencies:', err);
    }
  }

  private async parsePythonDependencies(rootPath: string): Promise<void> {
    const requirementsPath = path.join(rootPath, 'requirements.txt');

    if (!fs.existsSync(requirementsPath)) {
      return;
    }

    try {
      const content = fs.readFileSync(requirementsPath, 'utf-8');
      const lines = content.split('\n');

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
          continue;
        }

        // Parse package==version or package>=version
        const match = /^([a-zA-Z0-9_-]+)(?:[=<>!~]+(.+))?/.exec(trimmed);
        if (match) {
          const name = match[1];
          const version = match[2] || 'latest';

          this.addComponent({
            type: 'library',
            'bom-ref': `pkg:pypi/${name}@${version}`,
            name,
            version,
            purl: `pkg:pypi/${name}@${version}`,
          });
        }
      }
    } catch (err) {
      console.error('[CodeGuard SBOM] Error parsing Python dependencies:', err);
    }
  }

  private async parseCargoDependencies(rootPath: string): Promise<void> {
    const cargoTomlPath = path.join(rootPath, 'Cargo.toml');

    if (!fs.existsSync(cargoTomlPath)) {
      return;
    }

    try {
      const content = fs.readFileSync(cargoTomlPath, 'utf-8');

      // Simple TOML parsing for dependencies section
      const depMatch = /\[dependencies\]([\s\S]*?)(?:\[|$)/i.exec(content);
      if (depMatch) {
        const depsSection = depMatch[1];
        const lines = depsSection.split('\n');

        for (const line of lines) {
          // Match: name = "version" or name = { version = "x.y.z" }
          const simpleMatch = /^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/.exec(line.trim());
          const complexMatch = /^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/.exec(line.trim());

          const match = simpleMatch || complexMatch;
          if (match) {
            const name = match[1];
            const version = match[2];

            this.addComponent({
              type: 'library',
              'bom-ref': `pkg:cargo/${name}@${version}`,
              name,
              version,
              purl: `pkg:cargo/${name}@${version}`,
            });
          }
        }
      }
    } catch (err) {
      console.error('[CodeGuard SBOM] Error parsing Cargo dependencies:', err);
    }
  }

  private async parseGoDependencies(rootPath: string): Promise<void> {
    const goModPath = path.join(rootPath, 'go.mod');

    if (!fs.existsSync(goModPath)) {
      return;
    }

    try {
      const content = fs.readFileSync(goModPath, 'utf-8');
      const lines = content.split('\n');

      let inRequire = false;

      for (const line of lines) {
        const trimmed = line.trim();

        if (trimmed.startsWith('require (')) {
          inRequire = true;
          continue;
        }

        if (trimmed === ')') {
          inRequire = false;
          continue;
        }

        if (inRequire || trimmed.startsWith('require ')) {
          // Match: module/path v1.2.3
          const match = /^(?:require\s+)?([^\s]+)\s+(v[\d.]+(?:-[^\s]+)?)/.exec(trimmed);
          if (match) {
            const name = match[1];
            const version = match[2];

            this.addComponent({
              type: 'library',
              'bom-ref': `pkg:golang/${name}@${version}`,
              name,
              version,
              purl: `pkg:golang/${name}@${version}`,
            });
          }
        }
      }
    } catch (err) {
      console.error('[CodeGuard SBOM] Error parsing Go dependencies:', err);
    }
  }

  private addComponent(component: BomComponent): void {
    if (!this.currentBom) { return; }

    // Avoid duplicates
    const existing = this.currentBom.components.find(c => c['bom-ref'] === component['bom-ref']);
    if (!existing) {
      this.currentBom.components.push(component);
    }
  }

  private cleanVersion(version: string): string {
    return version.replace(/^[\^~>=<]+/, '').split(' ')[0];
  }

  dispose(): void {
    this.watcher?.dispose();
  }
}
