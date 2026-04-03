import * as fs from 'fs';
import * as path from 'path';
import { ScanResult } from '../checkers/types';

interface CacheEntry {
  result: ScanResult;
  expiresAt: number;
}

/**
 * Simple in-memory cache with file persistence and TTL.
 * Stores vulnerability scan results to minimize API calls.
 */
export class Cache {
  private store = new Map<string, CacheEntry>();
  private ttlMs: number;
  private persistPath: string | null;

  /**
   * @param ttlMinutes How long entries remain valid (default 60 min)
   * @param persistDir Directory to persist cache file (null = memory only)
   */
  constructor(ttlMinutes: number = 60, persistDir: string | null = null) {
    this.ttlMs = ttlMinutes * 60 * 1000;
    this.persistPath = persistDir ? path.join(persistDir, 'codeguard-cache.json') : null;
    this.loadFromDisk();
  }

  /**
   * Get a cached scan result if it exists and hasn't expired.
   */
  get(packageName: string): ScanResult | null {
    const entry = this.store.get(packageName);
    if (!entry) { return null; }

    if (Date.now() > entry.expiresAt) {
      this.store.delete(packageName);
      return null;
    }

    return entry.result;
  }

  /**
   * Cache a scan result.
   */
  set(packageName: string, result: ScanResult): void {
    this.store.set(packageName, {
      result,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /**
   * Clear all cached entries.
   */
  clear(): void {
    this.store.clear();
    if (this.persistPath) {
      try {
        fs.unlinkSync(this.persistPath);
      } catch {
        // File may not exist
      }
    }
  }

  /**
   * Get cache stats.
   */
  stats(): { size: number; ttlMinutes: number } {
    // Prune expired entries
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now > entry.expiresAt) {
        this.store.delete(key);
      }
    }
    return {
      size: this.store.size,
      ttlMinutes: this.ttlMs / 60000,
    };
  }

  /**
   * Persist cache to disk (called periodically or on deactivate).
   */
  saveToDisk(): void {
    if (!this.persistPath) { return; }

    try {
      const data: Record<string, CacheEntry> = {};
      for (const [key, entry] of this.store) {
        data[key] = entry;
      }
      const dir = path.dirname(this.persistPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(this.persistPath, JSON.stringify(data), 'utf-8');
    } catch (error) {
      console.error('[CodeGuard] Failed to persist cache:', error);
    }
  }

  /**
   * Load cache from disk on startup.
   */
  private loadFromDisk(): void {
    if (!this.persistPath) { return; }

    try {
      if (!fs.existsSync(this.persistPath)) { return; }

      const raw = fs.readFileSync(this.persistPath, 'utf-8');
      const data = JSON.parse(raw) as Record<string, CacheEntry>;
      const now = Date.now();

      for (const [key, entry] of Object.entries(data)) {
        if (now < entry.expiresAt) {
          this.store.set(key, entry);
        }
      }
    } catch (error) {
      console.error('[CodeGuard] Failed to load cache from disk:', error);
    }
  }
}
