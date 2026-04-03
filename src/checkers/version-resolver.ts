import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import { Ecosystem } from '../parsers/types';

/**
 * Resolves the actual version of a package when an import has no version.
 * Resolution chain: package.json → lockfile → registry latest.
 */

export interface ResolvedVersion {
  version: string | null;
  source: 'manifest' | 'lockfile' | 'registry-latest' | 'none';
  isDeprecated: boolean;
  deprecationMessage?: string;
  latestVersion?: string;
}

export class VersionResolver {
  private manifestCache = new Map<string, Map<string, string>>();
  private lockfileCache = new Map<string, Map<string, string>>();
  private latestVersionCache = new Map<string, { version: string; deprecated: boolean; message?: string; ts: number }>();
  private static readonly LATEST_CACHE_TTL = 30 * 60 * 1000; // 30 minutes

  /**
   * Resolve the version for a package, checking manifest → lockfile → registry.
   */
  async resolve(
    packageName: string,
    ecosystem: Ecosystem,
    workspaceRoot?: string
  ): Promise<ResolvedVersion> {
    const root = workspaceRoot || this.getWorkspaceRoot();
    if (!root) {
      return { version: null, source: 'none', isDeprecated: false };
    }

    // 1. Check manifest (package.json / requirements.txt)
    const manifestVersion = this.resolveFromManifest(packageName, ecosystem, root);
    if (manifestVersion) {
      return { version: manifestVersion, source: 'manifest', isDeprecated: false };
    }

    // 2. Check lockfile
    const lockVersion = this.resolveFromLockfile(packageName, ecosystem, root);
    if (lockVersion) {
      return { version: lockVersion, source: 'lockfile', isDeprecated: false };
    }

    // 3. Check registry for latest version + deprecation status
    try {
      const registryInfo = await this.resolveFromRegistry(packageName, ecosystem);
      if (registryInfo) {
        return {
          version: registryInfo.version,
          source: 'registry-latest',
          isDeprecated: registryInfo.deprecated,
          deprecationMessage: registryInfo.message,
          latestVersion: registryInfo.version,
        };
      }
    } catch {
      // Registry unavailable
    }

    return { version: null, source: 'none', isDeprecated: false };
  }

  /**
   * Resolve version from package.json or requirements.txt.
   */
  private resolveFromManifest(
    packageName: string,
    ecosystem: Ecosystem,
    root: string
  ): string | null {
    if (ecosystem === 'npm') {
      return this.resolveFromPackageJson(packageName, root);
    }
    if (ecosystem === 'PyPI') {
      return this.resolveFromRequirementsTxt(packageName, root);
    }
    return null;
  }

  private resolveFromPackageJson(packageName: string, root: string): string | null {
    const pkgPath = path.join(root, 'package.json');
    const cacheKey = pkgPath;

    // Check cache
    if (!this.manifestCache.has(cacheKey)) {
      this.loadPackageJson(pkgPath, cacheKey);
    }

    const cache = this.manifestCache.get(cacheKey);
    if (!cache) { return null; }

    const raw = cache.get(packageName);
    if (!raw) { return null; }

    // Strip range prefixes: ^1.2.3 → 1.2.3
    return this.cleanVersion(raw);
  }

  private loadPackageJson(pkgPath: string, cacheKey: string): void {
    try {
      if (!fs.existsSync(pkgPath)) { return; }
      const content = fs.readFileSync(pkgPath, 'utf8');
      const parsed = JSON.parse(content);
      const depMap = new Map<string, string>();

      for (const section of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
        const deps = parsed[section];
        if (deps && typeof deps === 'object') {
          for (const [name, version] of Object.entries(deps)) {
            if (typeof version === 'string') {
              depMap.set(name, version);
            }
          }
        }
      }

      this.manifestCache.set(cacheKey, depMap);
    } catch {
      // Invalid package.json
    }
  }

  private resolveFromRequirementsTxt(packageName: string, root: string): string | null {
    const files = ['requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt'];
    for (const file of files) {
      const filePath = path.join(root, file);
      try {
        if (!fs.existsSync(filePath)) { continue; }
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('#') || trimmed.startsWith('-')) { continue; }
          const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*[=~!<>]+\s*([\d][^\s,;]*)/);
          if (match) {
            const name = match[1].toLowerCase().replace(/_/g, '-');
            if (name === packageName.toLowerCase().replace(/_/g, '-')) {
              return match[2];
            }
          }
        }
      } catch {
        // Skip unreadable files
      }
    }
    return null;
  }

  /**
   * Resolve version from lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml).
   */
  private resolveFromLockfile(
    packageName: string,
    ecosystem: Ecosystem,
    root: string
  ): string | null {
    if (ecosystem !== 'npm') { return null; }

    // package-lock.json
    const lockPath = path.join(root, 'package-lock.json');
    const cacheKey = lockPath;

    if (!this.lockfileCache.has(cacheKey)) {
      this.loadPackageLockJson(lockPath, cacheKey);
    }

    const cache = this.lockfileCache.get(cacheKey);
    return cache?.get(packageName) || null;
  }

  private loadPackageLockJson(lockPath: string, cacheKey: string): void {
    try {
      if (!fs.existsSync(lockPath)) { return; }
      const content = fs.readFileSync(lockPath, 'utf8');
      const parsed = JSON.parse(content);
      const depMap = new Map<string, string>();

      // package-lock.json v2/v3 format
      if (parsed.packages) {
        for (const [key, info] of Object.entries(parsed.packages)) {
          if (!key) { continue; } // root package
          const pkgName = key.replace(/^node_modules\//, '');
          const version = (info as any)?.version;
          if (typeof version === 'string') {
            depMap.set(pkgName, version);
          }
        }
      }

      // package-lock.json v1 format
      if (parsed.dependencies) {
        for (const [name, info] of Object.entries(parsed.dependencies)) {
          const version = (info as any)?.version;
          if (typeof version === 'string' && !depMap.has(name)) {
            depMap.set(name, version);
          }
        }
      }

      this.lockfileCache.set(cacheKey, depMap);
    } catch {
      // Invalid lockfile
    }
  }

  /**
   * Fetch latest version + deprecation status from registry.
   */
  private async resolveFromRegistry(
    packageName: string,
    ecosystem: Ecosystem
  ): Promise<{ version: string; deprecated: boolean; message?: string } | null> {
    const cacheKey = `${ecosystem}:${packageName}`;
    const cached = this.latestVersionCache.get(cacheKey);
    if (cached && Date.now() - cached.ts < VersionResolver.LATEST_CACHE_TTL) {
      return { version: cached.version, deprecated: cached.deprecated, message: cached.message };
    }

    if (ecosystem === 'npm') {
      return this.fetchNpmLatest(packageName, cacheKey);
    }
    if (ecosystem === 'PyPI') {
      return this.fetchPyPILatest(packageName, cacheKey);
    }
    return null;
  }

  private async fetchNpmLatest(
    packageName: string,
    cacheKey: string
  ): Promise<{ version: string; deprecated: boolean; message?: string } | null> {
    try {
      const encoded = packageName.startsWith('@')
        ? `@${encodeURIComponent(packageName.slice(1).replace('/', '%2f'))}`
        : encodeURIComponent(packageName);
      const url = `https://registry.npmjs.org/${encoded}/latest`;
      const body = await this.httpsGet(url);
      const parsed = JSON.parse(body);
      const version = parsed.version || null;
      const deprecated = typeof parsed.deprecated === 'string';
      const message = deprecated ? parsed.deprecated : undefined;

      if (version) {
        this.latestVersionCache.set(cacheKey, { version, deprecated, message, ts: Date.now() });
        return { version, deprecated, message };
      }
    } catch {
      // Network error
    }
    return null;
  }

  private async fetchPyPILatest(
    packageName: string,
    cacheKey: string
  ): Promise<{ version: string; deprecated: boolean; message?: string } | null> {
    try {
      const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
      const body = await this.httpsGet(url);
      const parsed = JSON.parse(body);
      const version = parsed.info?.version || null;
      // PyPI doesn't have a simple deprecated field; check classifiers
      const classifiers: string[] = parsed.info?.classifiers || [];
      const deprecated = classifiers.some((c: string) =>
        c.toLowerCase().includes('inactive') || c.toLowerCase().includes('deprecated')
      );
      const message = deprecated ? 'This package is marked as inactive/deprecated on PyPI' : undefined;

      if (version) {
        this.latestVersionCache.set(cacheKey, { version, deprecated, message, ts: Date.now() });
        return { version, deprecated, message };
      }
    } catch {
      // Network error
    }
    return null;
  }

  /**
   * Invalidate caches (e.g., when files change).
   */
  invalidateManifestCache(): void {
    this.manifestCache.clear();
    this.lockfileCache.clear();
  }

  private cleanVersion(raw: string): string | null {
    const cleaned = raw.replace(/^[\^~>=<!\s]*/, '').trim();
    if (/^\d+\.\d+/.test(cleaned)) { return cleaned; }
    return null;
  }

  private getWorkspaceRoot(): string | undefined {
    const folders = vscode.workspace.workspaceFolders;
    if (folders && folders.length > 0) {
      return folders[0].uri.fsPath;
    }
    return undefined;
  }

  private httpsGet(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const options: https.RequestOptions = {
        hostname: urlObj.hostname,
        path: urlObj.pathname + urlObj.search,
        method: 'GET',
        headers: {
          'User-Agent': 'CodeGuard-AI-VSCode/0.2.0',
          'Accept': 'application/json',
        },
        timeout: 8000,
      };

      const req = https.request(options, (res) => {
        // Follow redirects
        if (res.statusCode && [301, 302, 307].includes(res.statusCode) && res.headers.location) {
          this.httpsGet(res.headers.location).then(resolve).catch(reject);
          res.resume();
          return;
        }
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve(body);
          } else {
            reject(new Error(`HTTP ${res.statusCode}`));
          }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.end();
    });
  }
}
