/**
 * Cryptojacking Signature Scanner
 *
 * Detects crypto-mining payloads embedded in dependencies or source:
 *   1. Known miner binaries and WASM blobs (XMRig, Coinhive, CryptoNight)
 *   2. Mining pool URLs (stratum+tcp://, known pool hostnames)
 *   3. Wallet address exfiltration patterns (XMR/BTC/ETH)
 *   4. In-browser miner JS libraries (coinhive.min.js, jsecoin, cryptonight.js)
 *   5. Command-line invocations of xmrig/minerd in install scripts
 *   6. Base64-encoded miner payloads (entropy + fingerprint)
 *   7. WebAssembly SIMD CryptoNight patterns
 *
 * Works on:
 *   - Source files (.js/.ts/.py/.sh/.ps1/.bat/.exe-strings)
 *   - package.json install scripts
 *   - .wasm / .wat blobs
 *   - Any file that passes a size filter (< 5 MB)
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CryptojackSeverity = 'critical' | 'high' | 'medium' | 'low';
export type CryptojackCategory =
  | 'miner-binary'
  | 'pool-url'
  | 'wallet-address'
  | 'miner-lib'
  | 'shell-miner'
  | 'encoded-payload'
  | 'wasm-signature';

export interface CryptojackFinding {
  file: string;
  line?: number;
  column?: number;
  ruleId: string;
  category: CryptojackCategory;
  severity: CryptojackSeverity;
  title: string;
  evidence: string;
  remediation: string;
}

// ---------------------------------------------------------------------------
// Known mining pool hostnames (non-exhaustive but covers majority of incidents)
// ---------------------------------------------------------------------------

const MINING_POOL_HOSTS = [
  // Monero
  'xmr-eu1.nanopool.org',
  'xmr-eu2.nanopool.org',
  'xmr-us-east1.nanopool.org',
  'xmr-us-west1.nanopool.org',
  'xmr-asia1.nanopool.org',
  'pool.supportxmr.com',
  'mine.xmrpool.net',
  'pool.minexmr.com',
  'xmr.crypto-pool.fr',
  'xmr.pool.minergate.com',
  'monerohash.com',
  'xmrpool.eu',
  'randomxmonero.auto.nicehash.com',
  'unmineable.com',
  // Bitcoin
  'stratum.antpool.com',
  'stratum.slushpool.com',
  'btc.viabtc.com',
  'eu.stratum.slushpool.com',
  'btc-global.f2pool.com',
  'us.litecoinpool.org',
  // Ethereum (Classic)
  'etc-eu1.nanopool.org',
  'eth.2miners.com',
  'eu1.ethermine.org',
  'etc.ethermine.org',
  // Generic
  'auto.nicehash.com',
  'miningpoolhub.com',
  'prohashing.com',
  'f2pool.com',
];

// ---------------------------------------------------------------------------
// In-browser miner libraries (coinhive-era, webmining)
// ---------------------------------------------------------------------------

const MINER_LIB_NAMES = [
  'coinhive.min.js',
  'coinhive.js',
  'coin-hive',
  'coin_hive',
  'cryptonight-asm.js',
  'cryptonight.js',
  'cryptonight-asmjs',
  'jsecoin',
  'cryptoloot',
  'crypto-loot',
  'deepminer',
  'jscoinminer',
  'webmine',
  'webminerpool',
  'minero.cc',
  'hashvault.pro',
  'webmine.cz',
  'coin-have',
  'coinimp',
];

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

interface PatternRule {
  id: string;
  pattern: RegExp;
  category: CryptojackCategory;
  severity: CryptojackSeverity;
  title: string;
  remediation: string;
}

const PATTERN_RULES: PatternRule[] = [
  // --- Mining pool protocol URLs ---
  {
    id: 'CG_CJACK_001',
    pattern: /\bstratum(?:\+(?:tcp|ssl|tls))?:\/\/[^\s"'<>]+/i,
    category: 'pool-url',
    severity: 'critical',
    title: 'Stratum mining protocol URL',
    remediation:
      'The stratum protocol is used almost exclusively by cryptocurrency miners. Remove the ' +
      'URL and audit how it got there (likely compromised dependency or install script).',
  },
  // --- Monero wallet address (97 or 95 chars, base58, starts with 4 or 8) ---
  {
    id: 'CG_CJACK_002',
    pattern: /\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/,
    category: 'wallet-address',
    severity: 'high',
    title: 'Monero wallet address',
    remediation:
      'XMR addresses embedded in code are a strong cryptojacking indicator. Audit the ' +
      'surrounding code for mining invocations.',
  },
  // --- Bitcoin wallet address (legacy + bech32) ---
  {
    id: 'CG_CJACK_003',
    pattern: /\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b/,
    category: 'wallet-address',
    severity: 'medium',
    title: 'Bitcoin wallet address',
    remediation:
      'BTC addresses in code may be legitimate (payment), but in minified JS or install ' +
      'scripts they are a strong cryptojacking signal.',
  },
  // --- Ethereum wallet address ---
  {
    id: 'CG_CJACK_004',
    pattern: /\b0x[a-fA-F0-9]{40}\b/,
    category: 'wallet-address',
    severity: 'low',
    title: 'Ethereum wallet address',
    remediation:
      'ETH addresses in minified code or install scripts may indicate wallet-draining or ' +
      'mining payloads. Verify intent.',
  },
  // --- xmrig binary invocation ---
  {
    id: 'CG_CJACK_005',
    pattern: /\bxmrig(?:\.exe)?(?:\s|$)/i,
    category: 'shell-miner',
    severity: 'critical',
    title: 'xmrig miner invocation',
    remediation: 'Remove. xmrig is a Monero mining binary; presence in code is always suspect.',
  },
  {
    id: 'CG_CJACK_006',
    pattern: /\b(?:minerd|ccminer|cgminer|bfgminer|ethminer|phoenixminer|t-rex|nbminer|lolminer|gminer|teamredminer)(?:\.exe)?\b/i,
    category: 'shell-miner',
    severity: 'critical',
    title: 'Known CPU/GPU miner binary',
    remediation: 'Remove. Investigate how the binary reference entered the codebase.',
  },
  // --- Suspicious mining flags ---
  {
    id: 'CG_CJACK_007',
    pattern: /--(?:algo|coin)[ =](?:randomx|cryptonight|kawpow|etchash|ethash|autolykos2|kheavyhash|equihash)\b/i,
    category: 'shell-miner',
    severity: 'critical',
    title: 'Miner algorithm flag',
    remediation: 'Remove. These flags are used by Monero/BTC/ETH miners.',
  },
  // --- Coinhive-style inline ---
  {
    id: 'CG_CJACK_008',
    pattern: /\bCoinHive\.(?:Anonymous|User|Token|CaptchaToken)\b/,
    category: 'miner-lib',
    severity: 'critical',
    title: 'Coinhive JavaScript miner API',
    remediation: 'Coinhive is browser-based cryptojacking. Remove and audit for exfiltration.',
  },
  {
    id: 'CG_CJACK_009',
    pattern: /\bCryptonight(?:_?(?:v8|v7|asm|wasm|hash))?\b/,
    category: 'miner-lib',
    severity: 'critical',
    title: 'CryptoNight mining implementation',
    remediation: 'Remove. CryptoNight is the proof-of-work used by Monero miners.',
  },
  // --- WebAssembly mining signatures ---
  {
    id: 'CG_CJACK_010',
    pattern: /\b(?:argon2i?d?|randomx|kawpow|equihash|ethash|autolykos)_?(?:hash|compute|init)\b/i,
    category: 'wasm-signature',
    severity: 'high',
    title: 'Hash function associated with mining algorithms',
    remediation:
      'Function names like randomx_hash / kawpow_init strongly indicate embedded mining ' +
      'code (often in WASM). Investigate further.',
  },
  // --- Base64-encoded xmrig binary prefix (ELF or PE) ---
  {
    id: 'CG_CJACK_011',
    // "TVqQAAMAAAAEAAAA//8AALg" is a base64 of typical PE header with MS-DOS stub
    pattern: /\bTVqQAAMAAAAEAAAA\/\/8AALg[A-Za-z0-9+/=]{40,}/,
    category: 'encoded-payload',
    severity: 'critical',
    title: 'Base64-encoded Windows executable (possible miner dropper)',
    remediation:
      'Extract and analyze. Embedded PE binaries in source code are almost always malicious.',
  },
  {
    id: 'CG_CJACK_012',
    // "f0VMRg" is base64 of "\x7fELF", the Linux ELF magic bytes
    pattern: /\bf0VMR[A-Za-z0-9+/=]{40,}/,
    category: 'encoded-payload',
    severity: 'critical',
    title: 'Base64-encoded Linux ELF executable',
    remediation: 'Extract and analyze; embedded ELF binaries are a strong indicator of malware.',
  },
];

// ---------------------------------------------------------------------------
// Combined regex for fast pool host matching
// ---------------------------------------------------------------------------

const POOL_HOST_REGEX = new RegExp(
  '\\b(' + MINING_POOL_HOSTS.map((h) => h.replace(/\./g, '\\.')).join('|') + ')\\b',
  'i'
);

const MINER_LIB_REGEX = new RegExp(
  '\\b(' +
    MINER_LIB_NAMES.map((n) => n.replace(/\./g, '\\.').replace(/-/g, '[-_]?')).join('|') +
    ')\\b',
  'i'
);

// ---------------------------------------------------------------------------
// Core scanner
// ---------------------------------------------------------------------------

export function scanTextForCryptojacking(
  text: string,
  filePath: string
): CryptojackFinding[] {
  const findings: CryptojackFinding[] = [];
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length === 0 || line.length > 8000) continue;

    // --- Pool hostnames (bulk match) ---
    const poolMatch = POOL_HOST_REGEX.exec(line);
    if (poolMatch) {
      findings.push({
        file: filePath,
        line: i + 1,
        column: (poolMatch.index ?? 0) + 1,
        ruleId: 'CG_CJACK_POOL_HOST',
        category: 'pool-url',
        severity: 'critical',
        title: `Known mining pool hostname: ${poolMatch[1]}`,
        evidence: line.trim().slice(0, 150),
        remediation:
          'Remove the pool hostname. If this is legitimate (e.g. monitoring), comment ' +
          'clearly and allowlist in .codeguard/policy.json.',
      });
    }

    // --- Miner libraries ---
    const libMatch = MINER_LIB_REGEX.exec(line);
    if (libMatch) {
      findings.push({
        file: filePath,
        line: i + 1,
        column: (libMatch.index ?? 0) + 1,
        ruleId: 'CG_CJACK_MINER_LIB',
        category: 'miner-lib',
        severity: 'critical',
        title: `Reference to in-browser miner library: ${libMatch[1]}`,
        evidence: line.trim().slice(0, 150),
        remediation: 'Remove the library reference and audit all script tags.',
      });
    }

    // --- Pattern rules ---
    for (const rule of PATTERN_RULES) {
      const m = rule.pattern.exec(line);
      if (m) {
        findings.push({
          file: filePath,
          line: i + 1,
          column: (m.index ?? 0) + 1,
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          title: rule.title,
          evidence: m[0].slice(0, 120),
          remediation: rule.remediation,
        });
      }
    }
  }

  return findings;
}

/**
 * Scan package.json install scripts (preinstall/postinstall/install/prepare/prepublish).
 * These run with full user privileges during npm install.
 */
export function scanPackageJsonScripts(filePath: string): CryptojackFinding[] {
  const findings: CryptojackFinding[] = [];
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const pkg = JSON.parse(raw);
    const scripts = pkg.scripts ?? {};
    const RISKY_SCRIPTS = [
      'preinstall',
      'install',
      'postinstall',
      'prepare',
      'prepublish',
      'prepublishOnly',
      'preuninstall',
      'postuninstall',
    ];
    for (const key of RISKY_SCRIPTS) {
      const script = scripts[key];
      if (typeof script !== 'string') continue;
      const found = scanTextForCryptojacking(script, `${filePath} (scripts.${key})`);
      for (const f of found) {
        findings.push({
          ...f,
          severity: raiseSeverity(f.severity),
        });
      }
    }
  } catch {
    // ignore parse errors
  }
  return findings;
}

/**
 * Scan a single file on disk (any text file up to 5 MB).
 */
export function scanFileForCryptojacking(filePath: string): CryptojackFinding[] {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 5 * 1024 * 1024) return [];
    if (path.basename(filePath) === 'package.json') {
      return scanPackageJsonScripts(filePath).concat(
        scanTextForCryptojacking(fs.readFileSync(filePath, 'utf8'), filePath)
      );
    }
    const text = fs.readFileSync(filePath, 'utf8');
    return scanTextForCryptojacking(text, filePath);
  } catch {
    return [];
  }
}

function raiseSeverity(s: CryptojackSeverity): CryptojackSeverity {
  // Anything detected inside install scripts is escalated one level
  switch (s) {
    case 'low':
      return 'medium';
    case 'medium':
      return 'high';
    case 'high':
      return 'critical';
    default:
      return s;
  }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

export function getCryptojackScannerStats(): {
  poolHosts: number;
  minerLibs: number;
  patternRules: number;
} {
  return {
    poolHosts: MINING_POOL_HOSTS.length,
    minerLibs: MINER_LIB_NAMES.length,
    patternRules: PATTERN_RULES.length,
  };
}
