// ═══════════════════════════════════════════════════════════════════════
// CodeGuard AI Backend — Crypto Utilities
// ═══════════════════════════════════════════════════════════════════════

import crypto from 'crypto';

/**
 * Generate a random API key with prefix.
 * Format: cg_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (cg_ + 36 random hex chars)
 */
export function generateApiKey(): { key: string; hash: string; prefix: string } {
  const raw = crypto.randomBytes(24).toString('hex');
  const key = `cg_${raw}`;
  const hash = hashApiKey(key);
  const prefix = key.substring(0, 7) + '...';
  return { key, hash, prefix };
}

/**
 * Hash an API key for storage (SHA-256).
 */
export function hashApiKey(key: string): string {
  return crypto.createHash('sha256').update(key).digest('hex');
}

/**
 * Generate a random webhook signing secret.
 */
export function generateWebhookSecret(): string {
  return `whsec_${crypto.randomBytes(24).toString('hex')}`;
}

/**
 * Sign a webhook payload with HMAC-SHA256.
 */
export function signWebhookPayload(payload: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

// ─── Password Hashing (admin credentials) ────────────────────────────

/**
 * Hash a plaintext password using scrypt (Node.js built-in, no extra dep).
 * Returns "salt:hash" as a single storable string.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await new Promise<string>((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) { reject(err); } else { resolve(derivedKey.toString('hex')); }
    });
  });
  return `${salt}:${hash}`;
}

/**
 * Verify a plaintext password against a stored "salt:hash" string.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) { return false; }
  const derivedKey = await new Promise<Buffer>((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) { reject(err); } else { resolve(key); }
    });
  });
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), derivedKey);
}
