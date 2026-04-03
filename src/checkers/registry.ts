import * as https from 'https';
import * as http from 'http';
import { Ecosystem } from '../parsers/types';

/**
 * Checks whether a package actually exists on its registry.
 * This is the core of hallucination/slopsquatting detection.
 */
export class RegistryChecker {

  /**
   * Check if a package exists on its ecosystem's registry.
   * Returns true if found, false if 404/not found.
   */
  async exists(packageName: string, ecosystem: Ecosystem): Promise<boolean> {
    try {
      switch (ecosystem) {
        case 'npm':
          return await this.checkNpm(packageName);
        case 'PyPI':
          return await this.checkPyPI(packageName);
        case 'Go':
          return await this.checkGo(packageName);
        case 'Maven':
          return await this.checkMaven(packageName);
        case 'crates.io':
          return await this.checkCratesIo(packageName);
        default:
          return true; // Assume exists for unsupported ecosystems
      }
    } catch (error) {
      console.error(`[CodeGuard] Registry check failed for ${packageName} (${ecosystem}):`, error);
      // On network error, assume package exists (avoid false positives)
      return true;
    }
  }

  /**
   * npm: HEAD request to https://registry.npmjs.org/{package}
   * Returns 200 if exists, 404 if not.
   */
  private async checkNpm(packageName: string): Promise<boolean> {
    const encodedName = packageName.startsWith('@')
      ? `@${encodeURIComponent(packageName.slice(1).replace('/', '%2f'))}`
      : encodeURIComponent(packageName);
    const url = `https://registry.npmjs.org/${encodedName}`;
    return this.headRequest(url);
  }

  /**
   * PyPI: HEAD request to https://pypi.org/pypi/{package}/json
   * Returns 200 if exists, 404 if not.
   */
  private async checkPyPI(packageName: string): Promise<boolean> {
    const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
    return this.headRequest(url);
  }

  /**
   * Go: HEAD request to https://proxy.golang.org/{module}/@latest
   */
  private async checkGo(moduleName: string): Promise<boolean> {
    // Go modules use case-encoded paths (uppercase -> !lowercase)
    const encoded = moduleName.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
    const url = `https://proxy.golang.org/${encoded}/@latest`;
    return this.headRequest(url);
  }

  /**
   * Maven: Check Maven Central search API.
   * Package name should be "groupId:artifactId" format.
   */
  private async checkMaven(packageName: string): Promise<boolean> {
    const parts = packageName.split(':');
    if (parts.length !== 2) { return true; } // Can't check without groupId:artifactId
    const [groupId, artifactId] = parts;
    const url = `https://search.maven.org/solrsearch/select?q=g:${encodeURIComponent(groupId)}+AND+a:${encodeURIComponent(artifactId)}&rows=1&wt=json`;
    try {
      const body = await this.getRequest(url);
      const parsed = JSON.parse(body);
      return parsed.response && parsed.response.numFound > 0;
    } catch {
      return true;
    }
  }

  /**
   * crates.io: HEAD request to https://crates.io/api/v1/crates/{name}
   */
  private async checkCratesIo(packageName: string): Promise<boolean> {
    const url = `https://crates.io/api/v1/crates/${encodeURIComponent(packageName)}`;
    return this.headRequest(url);
  }

  /**
   * Perform an HTTP HEAD request. Returns true if status is 2xx, false if 404.
   * On other errors, throws.
   */
  private headRequest(url: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const client = urlObj.protocol === 'https:' ? https : http;

      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: 'HEAD',
        headers: {
          'User-Agent': 'CodeGuard-AI-VSCode/0.1.0',
          'Accept': 'application/json',
        },
        timeout: 8000,
      };

      const req = client.request(options, (res: http.IncomingMessage) => {
        // Consume response
        res.resume();
        const status = res.statusCode || 0;
        if (status >= 200 && status < 400) {
          resolve(true);
        } else if (status === 404) {
          resolve(false);
        } else {
          // Other status — assume exists to avoid false positives
          resolve(true);
        }
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        // On timeout, assume exists to avoid false positives
        resolve(true);
      });
      req.end();
    });
  }

  /**
   * Perform an HTTP GET request and return the response body.
   */
  private getRequest(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const client = urlObj.protocol === 'https:' ? https : http;

      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: 'GET',
        headers: {
          'User-Agent': 'CodeGuard-AI-VSCode/0.1.0',
          'Accept': 'application/json',
        },
        timeout: 10000,
      };

      const req = client.request(options, (res: http.IncomingMessage) => {
        let body = '';
        res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        res.on('end', () => resolve(body));
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timed out'));
      });
      req.end();
    });
  }
}
