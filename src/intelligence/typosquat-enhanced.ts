/**
 * Enhanced Typosquat Detector
 *
 * Multi-signal detection of packages that imitate popular packages:
 *   1. Levenshtein edit distance (classical)
 *   2. Keyboard adjacency (QWERTY) — characters near each other on the keyboard
 *   3. Homoglyph substitution (Cyrillic/Greek lookalikes, number-for-letter)
 *   4. Phonetic similarity (Metaphone) — "ruter" vs "router"
 *   5. Character insertion/deletion/transposition bias
 *   6. Hyphenation/underscore/separator tricks (requests vs re-quests)
 *   7. Scope / prefix tricks (lodash vs lodash-utils-official)
 *   8. Suffix tricks (cli, js, ts, 2, v2, -core, -pro, -official, -tools)
 *   9. Plural/singular flips (react-router vs react-routers)
 *  10. Case-only variants where the registry normalizes (npm is case-insensitive)
 *
 * Each hit produces a score and the user is warned if score >= threshold.
 *
 * Inspired by: Socket.dev, npm's built-in typosquat detector, and the 2024
 * research paper "WHATS THE NAME OF THIS GAME" (USENIX Security).
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TyposquatMatch {
  candidate: string; // the package the user wrote
  target: string; // the popular package it's impersonating
  distance: number;
  score: number; // 0..1 (1 = certain typosquat)
  signals: TyposquatSignal[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  recommendation: string;
}

export type TyposquatSignal =
  | 'levenshtein-1'
  | 'levenshtein-2'
  | 'keyboard-adjacent'
  | 'homoglyph'
  | 'phonetic'
  | 'transposition'
  | 'insertion'
  | 'deletion'
  | 'separator'
  | 'suffix-trick'
  | 'prefix-trick'
  | 'plural-flip'
  | 'scope-drop'
  | 'case-variant';

// ---------------------------------------------------------------------------
// Popular package lists — top targets for typosquatting
// ---------------------------------------------------------------------------

/**
 * Top 200 npm packages (by downloads, 2025-ish). These are the most lucrative
 * typosquat targets — a single malicious hit installs on millions of machines.
 */
export const POPULAR_NPM: string[] = [
  'react', 'react-dom', 'lodash', 'chalk', 'express', 'axios', 'moment', 'typescript',
  'webpack', 'eslint', 'prettier', 'next', 'vue', 'angular', 'rxjs', 'jquery',
  '@babel/core', 'babel-core', 'babel-loader', '@types/node', '@types/react',
  'underscore', 'ramda', 'debug', 'commander', 'yargs', 'mocha', 'jest', 'chai',
  'sinon', 'nyc', 'ts-node', 'nodemon', 'cors', 'body-parser', 'dotenv', 'uuid',
  'jsonwebtoken', 'bcrypt', 'bcryptjs', 'passport', 'helmet', 'morgan', 'winston',
  'bunyan', 'pino', 'fs-extra', 'glob', 'minimist', 'inquirer', 'ora', 'cli-progress',
  'puppeteer', 'playwright', 'cheerio', 'jsdom', 'ws', 'socket.io', 'node-fetch',
  'got', 'request', 'form-data', 'multer', 'sharp', 'pdfkit', 'archiver', 'zod',
  'yup', 'joi', 'ajv', 'semver', 'dayjs', 'date-fns', 'luxon', 'numeral',
  'mongodb', 'mongoose', 'mysql', 'mysql2', 'pg', 'redis', 'ioredis', 'sqlite3',
  'sequelize', 'prisma', 'typeorm', 'knex', 'graphql', 'apollo-server', 'apollo-client',
  '@apollo/client', 'swr', 'react-query', '@tanstack/react-query', 'redux', '@reduxjs/toolkit',
  'react-redux', 'zustand', 'recoil', 'mobx', 'tailwindcss', 'styled-components',
  '@emotion/react', '@emotion/styled', 'bootstrap', 'material-ui', '@mui/material',
  '@chakra-ui/react', 'antd', 'framer-motion', 'react-router', 'react-router-dom',
  'vite', 'rollup', 'parcel', 'esbuild', 'swc', '@swc/core', 'gulp', 'grunt',
  'browserify', 'core-js', 'regenerator-runtime', 'polyfill', 'is-promise',
  'is-array', 'is-buffer', 'is-stream', 'safe-buffer', 'readable-stream', 'stream',
  'minimatch', 'rimraf', 'mkdirp', 'ncp', 'cross-spawn', 'execa', 'shelljs',
  'npm', 'yarn', 'pnpm', 'electron', 'nw', 'firebase', '@firebase/app',
  'aws-sdk', '@aws-sdk/client-s3', 'stripe', '@sentry/node', '@sentry/react',
  'openai', '@anthropic-ai/sdk', 'langchain', '@langchain/core', 'tiktoken',
  'cohere-ai', 'replicate', 'huggingface', '@huggingface/inference',
];

/**
 * Top 150 PyPI packages.
 */
export const POPULAR_PYPI: string[] = [
  'numpy', 'pandas', 'scipy', 'matplotlib', 'scikit-learn', 'tensorflow', 'torch',
  'keras', 'requests', 'urllib3', 'flask', 'django', 'fastapi', 'starlette',
  'pydantic', 'sqlalchemy', 'alembic', 'psycopg2', 'pymongo', 'redis', 'celery',
  'pytest', 'unittest', 'mock', 'coverage', 'tox', 'black', 'flake8', 'pylint',
  'mypy', 'isort', 'autopep8', 'pre-commit', 'click', 'typer', 'argparse',
  'rich', 'pygments', 'loguru', 'structlog', 'python-dotenv', 'pyyaml', 'toml',
  'jsonschema', 'marshmallow', 'attrs', 'dataclasses-json', 'pytz', 'arrow',
  'pendulum', 'python-dateutil', 'cryptography', 'pycryptodome', 'pyjwt',
  'bcrypt', 'passlib', 'paramiko', 'fabric', 'ansible', 'docker', 'kubernetes',
  'boto3', 'botocore', 'aws-cdk', 'google-cloud', 'google-api-python-client',
  'azure-core', 'azure-storage-blob', 'openai', 'anthropic', 'langchain',
  'langchain-core', 'langchain-community', 'llama-index', 'transformers',
  'datasets', 'accelerate', 'huggingface-hub', 'sentence-transformers',
  'tiktoken', 'tokenizers', 'safetensors', 'peft', 'bitsandbytes', 'diffusers',
  'opencv-python', 'pillow', 'imageio', 'scikit-image', 'albumentations',
  'beautifulsoup4', 'lxml', 'html5lib', 'selenium', 'playwright', 'scrapy',
  'aiohttp', 'httpx', 'websockets', 'asyncio', 'trio', 'anyio', 'uvloop',
  'uvicorn', 'gunicorn', 'hypercorn', 'waitress', 'flask-login', 'flask-sqlalchemy',
  'djangorestframework', 'graphene', 'strawberry-graphql', 'ariadne', 'gql',
  'jinja2', 'mako', 'chameleon', 'werkzeug', 'itsdangerous', 'blinker',
  'setuptools', 'wheel', 'pip', 'virtualenv', 'poetry', 'pipenv', 'hatch',
  'cython', 'pybind11', 'numba', 'cffi', 'pycparser', 'nltk', 'spacy',
  'gensim', 'textblob', 'polyglot', 'networkx', 'igraph', 'graph-tool',
  'sympy', 'statsmodels', 'seaborn', 'plotly', 'bokeh', 'altair', 'dash',
  'streamlit', 'gradio', 'jupyter', 'ipython', 'notebook', 'jupyterlab',
  'papermill', 'nbformat', 'ipykernel', 'ipywidgets',
];

// ---------------------------------------------------------------------------
// Keyboard adjacency map (QWERTY)
// ---------------------------------------------------------------------------

const KEYBOARD_NEIGHBORS: Record<string, string[]> = {
  a: ['q', 'w', 's', 'z'],
  b: ['v', 'g', 'h', 'n'],
  c: ['x', 'd', 'f', 'v'],
  d: ['s', 'e', 'r', 'f', 'c', 'x'],
  e: ['w', '3', '4', 'r', 'd', 's'],
  f: ['d', 'r', 't', 'g', 'v', 'c'],
  g: ['f', 't', 'y', 'h', 'b', 'v'],
  h: ['g', 'y', 'u', 'j', 'n', 'b'],
  i: ['u', '8', '9', 'o', 'k', 'j'],
  j: ['h', 'u', 'i', 'k', 'm', 'n'],
  k: ['j', 'i', 'o', 'l', 'm'],
  l: ['k', 'o', 'p'],
  m: ['n', 'j', 'k'],
  n: ['b', 'h', 'j', 'm'],
  o: ['i', '9', '0', 'p', 'l', 'k'],
  p: ['o', '0', 'l'],
  q: ['1', '2', 'w', 'a'],
  r: ['e', '4', '5', 't', 'f', 'd'],
  s: ['a', 'w', 'e', 'd', 'x', 'z'],
  t: ['r', '5', '6', 'y', 'g', 'f'],
  u: ['y', '7', '8', 'i', 'j', 'h'],
  v: ['c', 'f', 'g', 'b'],
  w: ['q', '2', '3', 'e', 's', 'a'],
  x: ['z', 's', 'd', 'c'],
  y: ['t', '6', '7', 'u', 'h', 'g'],
  z: ['a', 's', 'x'],
  '0': ['9', 'o', 'p'],
  '1': ['q', '2'],
  '2': ['1', 'q', 'w', '3'],
  '3': ['2', 'w', 'e', '4'],
  '4': ['3', 'e', 'r', '5'],
  '5': ['4', 'r', 't', '6'],
  '6': ['5', 't', 'y', '7'],
  '7': ['6', 'y', 'u', '8'],
  '8': ['7', 'u', 'i', '9'],
  '9': ['8', 'i', 'o', '0'],
};

function areKeyboardAdjacent(a: string, b: string): boolean {
  const la = a.toLowerCase();
  const lb = b.toLowerCase();
  return (KEYBOARD_NEIGHBORS[la] ?? []).includes(lb);
}

// ---------------------------------------------------------------------------
// Homoglyph map — Unicode lookalikes and number-for-letter
// ---------------------------------------------------------------------------

const HOMOGLYPHS: Record<string, string[]> = {
  a: ['а', 'α', '@', '4', 'ä', 'à', 'á'], // Cyrillic 'а', Greek alpha
  b: ['Ь', 'β', '6', '8'],
  c: ['с', 'ϲ', '¢'],
  d: ['ԁ', 'đ'],
  e: ['е', 'ε', '3', 'è', 'é'],
  g: ['ɡ', '9'],
  h: ['һ'],
  i: ['і', 'ι', '1', 'l', '|'],
  j: ['ј'],
  k: ['κ', 'к'],
  l: ['1', 'I', '|', 'ł', 'ł'],
  m: ['м'],
  n: ['η', 'п'],
  o: ['о', 'ο', '0', 'ö'],
  p: ['р', 'ρ'],
  q: ['ԛ'],
  r: ['г'],
  s: ['ѕ', '$', '5'],
  t: ['т', '7'],
  u: ['υ', 'μ'],
  v: ['ν'],
  w: ['ш', 'w'],
  x: ['х', 'χ'],
  y: ['у', 'γ'],
  z: ['z', '2'],
};

// ---------------------------------------------------------------------------
// Algorithm implementations
// ---------------------------------------------------------------------------

/** Levenshtein edit distance. */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  // Use single-row DP for O(min(a,b)) space
  const short = a.length <= b.length ? a : b;
  const long = a.length <= b.length ? b : a;
  let prev = new Array(short.length + 1);
  let curr = new Array(short.length + 1);
  for (let i = 0; i <= short.length; i++) prev[i] = i;
  for (let i = 1; i <= long.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= short.length; j++) {
      const cost = short[j - 1] === long[i - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[short.length];
}

/**
 * Damerau-Levenshtein: like Levenshtein but adjacent transpositions cost 1
 * (useful for catching "receuste" vs "requests").
 */
export function damerauLevenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[m][n];
}

/** Normalize string for separator-insensitive comparison. */
function stripSeparators(s: string): string {
  return s.replace(/[-_.]/g, '');
}

/** Simple phonetic code (Metaphone-lite). */
export function phoneticKey(s: string): string {
  let x = s.toLowerCase();
  // Drop vowels except leading
  x = x[0] + x.slice(1).replace(/[aeiou]/g, '');
  // Common substitutions
  x = x
    .replace(/ph/g, 'f')
    .replace(/ck/g, 'k')
    .replace(/ght/g, 't')
    .replace(/[cq]/g, 'k')
    .replace(/z/g, 's')
    .replace(/y/g, 'i');
  // Collapse repeated consonants
  x = x.replace(/(.)\1+/g, '$1');
  return x;
}

/** Does `a` differ from `b` by only keyboard-adjacent swaps at the same position? */
function isKeyboardAdjacentMistake(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diffs = 0;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      if (!areKeyboardAdjacent(a[i], b[i])) return false;
      diffs++;
      if (diffs > 2) return false;
    }
  }
  return diffs >= 1 && diffs <= 2;
}

/** Does `a` differ from `b` by homoglyph substitution only? */
function hasHomoglyphSubstitution(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let homoglyphDiffs = 0;
  for (let i = 0; i < a.length; i++) {
    const ca = a[i].toLowerCase();
    const cb = b[i].toLowerCase();
    if (ca === cb) continue;
    const list = HOMOGLYPHS[cb] ?? [];
    if (list.includes(ca) || list.includes(a[i])) {
      homoglyphDiffs++;
    } else {
      return false;
    }
  }
  return homoglyphDiffs > 0;
}

/** Is `a` = `b` with a common suspicious suffix attached? */
function hasSuspiciousSuffix(a: string, b: string): string | null {
  const suspiciousSuffixes = [
    '-cli', '-js', '-ts', '-pro', '-plus', '-official', '-core', '-utils',
    '-helper', '-helpers', '-tools', '-bundle', '-toolkit', '-lib', '-library',
    '-sdk', '-api', '-v2', '-v3', '-next', '-fork', '-community', '-enterprise',
    '-official', '2', '3', '-free', '-premium', '-nightly',
  ];
  for (const suf of suspiciousSuffixes) {
    if (a === b + suf) return suf;
  }
  return null;
}

function hasSuspiciousPrefix(a: string, b: string): string | null {
  const prefixes = ['official-', 'real-', 'true-', 'genuine-', 'fast-', 'better-', 'improved-', 'secure-'];
  for (const p of prefixes) {
    if (a === p + b) return p;
  }
  return null;
}

function isPluralFlip(a: string, b: string): boolean {
  return a === b + 's' || b === a + 's' || a === b + 'es' || b === a + 'es';
}

function isScopeDrop(a: string, b: string): boolean {
  // @foo/bar -> foo-bar, foo_bar, foobar
  if (!b.startsWith('@')) return false;
  const inner = b.slice(1).replace('/', '-');
  const inner2 = b.slice(1).replace('/', '_');
  const inner3 = b.slice(1).replace('/', '');
  return a === inner || a === inner2 || a === inner3;
}

// ---------------------------------------------------------------------------
// Main detection function
// ---------------------------------------------------------------------------

export interface TyposquatOptions {
  /** Packages the user's project actually depends on — these are allowlisted. */
  knownPackages?: Set<string>;
  /** Popular packages to compare against. Defaults to npm + pypi top lists. */
  targetList?: string[];
  /** Ecosystem hint. */
  ecosystem?: 'npm' | 'pypi' | 'both';
  /** Minimum score (0..1) to return. Default 0.55. */
  scoreThreshold?: number;
}

/**
 * Check a single package name for typosquat risk against popular package lists.
 */
export function checkTyposquat(
  name: string,
  opts: TyposquatOptions = {}
): TyposquatMatch[] {
  const {
    knownPackages,
    ecosystem = 'both',
    scoreThreshold = 0.55,
  } = opts;

  // Allowlist — already-installed packages are assumed to be known-good
  if (knownPackages?.has(name)) return [];

  const targets =
    opts.targetList ??
    (ecosystem === 'npm'
      ? POPULAR_NPM
      : ecosystem === 'pypi'
        ? POPULAR_PYPI
        : [...POPULAR_NPM, ...POPULAR_PYPI]);

  const matches: TyposquatMatch[] = [];
  const nameLower = name.toLowerCase();
  const nameStripped = stripSeparators(nameLower);
  const namePhon = phoneticKey(nameLower);

  for (const target of targets) {
    if (target === name || target === nameLower) continue; // exact match = not a typosquat

    const targetLower = target.toLowerCase();
    const targetStripped = stripSeparators(targetLower);

    // Skip if too different in length (> 3 char diff can't be a close typosquat)
    if (Math.abs(nameLower.length - targetLower.length) > 4) continue;

    const signals: TyposquatSignal[] = [];
    let distance = Infinity;

    // --- 1. Levenshtein / Damerau ---
    const lev = damerauLevenshtein(nameLower, targetLower);
    if (lev === 1) {
      signals.push('levenshtein-1');
      distance = Math.min(distance, 1);
    } else if (lev === 2 && targetLower.length >= 6) {
      signals.push('levenshtein-2');
      distance = Math.min(distance, 2);
    }

    // --- 2. Keyboard adjacency ---
    if (isKeyboardAdjacentMistake(nameLower, targetLower)) {
      signals.push('keyboard-adjacent');
      distance = Math.min(distance, 1);
    }

    // --- 3. Homoglyph ---
    if (hasHomoglyphSubstitution(nameLower, targetLower)) {
      signals.push('homoglyph');
      distance = Math.min(distance, 1);
    }

    // --- 4. Phonetic ---
    if (namePhon === phoneticKey(targetLower) && nameLower !== targetLower && lev <= 3) {
      signals.push('phonetic');
      distance = Math.min(distance, 2);
    }

    // --- 5. Transposition (Damerau distance specifically) ---
    if (damerauLevenshtein(nameLower, targetLower) < levenshtein(nameLower, targetLower)) {
      signals.push('transposition');
    }

    // --- 6. Separator flip ---
    if (nameStripped === targetStripped && nameLower !== targetLower) {
      signals.push('separator');
      distance = Math.min(distance, 1);
    }

    // --- 7. Insertion/deletion ---
    if (lev === 1) {
      if (nameLower.length > targetLower.length) signals.push('insertion');
      else if (nameLower.length < targetLower.length) signals.push('deletion');
    }

    // --- 8. Suffix/prefix tricks ---
    const suf = hasSuspiciousSuffix(nameLower, targetLower);
    if (suf) signals.push('suffix-trick');
    const pre = hasSuspiciousPrefix(nameLower, targetLower);
    if (pre) signals.push('prefix-trick');

    // --- 9. Plural flip ---
    if (isPluralFlip(nameLower, targetLower)) {
      signals.push('plural-flip');
      distance = Math.min(distance, 1);
    }

    // --- 10. Scope drop ---
    if (isScopeDrop(nameLower, target)) {
      signals.push('scope-drop');
      distance = Math.min(distance, 1);
    }

    // --- 11. Case variant ---
    if (name !== target && nameLower === targetLower) {
      signals.push('case-variant');
      distance = Math.min(distance, 0);
    }

    if (signals.length === 0) continue;

    // --- Scoring ---
    const score = scoreTyposquat(signals, distance, targetLower);
    if (score < scoreThreshold) continue;

    const severity: TyposquatMatch['severity'] =
      score >= 0.9 ? 'critical' : score >= 0.75 ? 'high' : score >= 0.6 ? 'medium' : 'low';

    matches.push({
      candidate: name,
      target,
      distance: distance === Infinity ? lev : distance,
      score,
      signals,
      severity,
      recommendation: buildRecommendation(name, target, signals),
    });
  }

  // Sort by score descending; return top 5 to avoid noise
  matches.sort((a, b) => b.score - a.score);
  return matches.slice(0, 5);
}

function scoreTyposquat(
  signals: TyposquatSignal[],
  distance: number,
  target: string
): number {
  let score = 0;
  const weights: Partial<Record<TyposquatSignal, number>> = {
    'levenshtein-1': 0.7,
    'levenshtein-2': 0.3,
    'keyboard-adjacent': 0.3,
    homoglyph: 0.85,
    phonetic: 0.35,
    transposition: 0.25,
    insertion: 0.2,
    deletion: 0.2,
    separator: 0.4,
    'suffix-trick': 0.45,
    'prefix-trick': 0.5,
    'plural-flip': 0.35,
    'scope-drop': 0.55,
    'case-variant': 0.9,
  };
  for (const s of signals) {
    score += weights[s] ?? 0.1;
  }
  // Boost score for longer targets — accidental collisions are less likely
  if (target.length >= 8) score += 0.05;
  if (target.length >= 12) score += 0.05;
  // Cap
  return Math.min(score, 1);
}

function buildRecommendation(
  candidate: string,
  target: string,
  signals: TyposquatSignal[]
): string {
  const parts: string[] = [];
  if (signals.includes('homoglyph')) {
    parts.push(
      `"${candidate}" contains Unicode lookalikes of "${target}". This is a deliberate ` +
        'deception technique — do NOT install.'
    );
  } else if (signals.includes('case-variant')) {
    parts.push(
      `"${candidate}" differs from "${target}" only in case. npm normalizes case, but ` +
        'other registries may not. This is a confusion attack.'
    );
  } else if (signals.includes('keyboard-adjacent')) {
    parts.push(
      `"${candidate}" differs from "${target}" by adjacent-key typos — classic typosquat.`
    );
  } else if (signals.includes('suffix-trick') || signals.includes('prefix-trick')) {
    parts.push(
      `"${candidate}" attaches a marketing suffix/prefix to "${target}" — this is a ` +
        'known impersonation pattern (e.g. "official-", "-tools", "-pro").'
    );
  } else {
    parts.push(
      `"${candidate}" is suspiciously close to the popular package "${target}" (edit ` +
        'distance 1-2).'
    );
  }
  parts.push(`Did you mean to install "${target}"?`);
  return parts.join(' ');
}

// ---------------------------------------------------------------------------
// Batch API
// ---------------------------------------------------------------------------

export function batchCheckTyposquat(
  names: string[],
  opts: TyposquatOptions = {}
): Map<string, TyposquatMatch[]> {
  const map = new Map<string, TyposquatMatch[]>();
  for (const n of names) {
    const matches = checkTyposquat(n, opts);
    if (matches.length > 0) map.set(n, matches);
  }
  return map;
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

export function getTyposquatEngineStats(): {
  npmTargets: number;
  pypiTargets: number;
  keyboardKeys: number;
  homoglyphLetters: number;
  suspiciousSuffixes: number;
} {
  return {
    npmTargets: POPULAR_NPM.length,
    pypiTargets: POPULAR_PYPI.length,
    keyboardKeys: Object.keys(KEYBOARD_NEIGHBORS).length,
    homoglyphLetters: Object.keys(HOMOGLYPHS).length,
    suspiciousSuffixes: 29,
  };
}
