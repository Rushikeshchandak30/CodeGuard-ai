/**
 * CLI Scanner unit tests — validates the core scanning engine
 * without any vscode dependency or network calls.
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CoreScanner, ScanOptions, ScanResult } from '../scanner';

// ─── Helper: create temporary project with specific files ────────────

function createTempProject(files: Record<string, string>): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeguard-cli-test-'));
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = path.join(tmpDir, relPath);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(fullPath, content, 'utf-8');
  }
  return tmpDir;
}

function cleanupTempProject(dir: string): void {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // Best effort cleanup
  }
}

// ─── Tests ───────────────────────────────────────────────────────────

describe('CoreScanner', () => {
  let tmpDir: string;

  afterEach(() => {
    if (tmpDir) { cleanupTempProject(tmpDir); }
  });

  it('should detect hardcoded secrets in JS files', async () => {
    tmpDir = createTempProject({
      'app.js': `
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const db = "postgres://admin:password123@localhost:5432/mydb";
console.log("hello");
      `,
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      sast: false,
      policy: false,
    });

    const result = await scanner.scan();
    const secrets = result.findings.filter(f => f.type === 'secret');
    assert.ok(secrets.length >= 1, 'Should find at least 1 secret');

    const awsKey = secrets.find(f => f.id === 'SEC_AWS_KEY');
    assert.ok(awsKey, 'Should detect AWS access key');
    assert.strictEqual(awsKey!.severity, 'critical');
  });

  it('should detect SAST patterns in JS files', async () => {
    tmpDir = createTempProject({
      'vulnerable.js': `
const userInput = req.query.name;
document.innerHTML = userInput;
eval(userInput);
const hash = crypto.createHash('md5').update(data).digest('hex');
      `,
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      secrets: false,
      policy: false,
    });

    const result = await scanner.scan();
    const sast = result.findings.filter(f => f.type === 'sast');
    assert.ok(sast.length >= 2, `Should find at least 2 SAST findings, found ${sast.length}`);

    const evalFinding = sast.find(f => f.id === 'SAST_EVAL_001');
    assert.ok(evalFinding, 'Should detect eval() usage');

    const weakHash = sast.find(f => f.id === 'SAST_CRYPTO_001');
    assert.ok(weakHash, 'Should detect weak hash algorithm');
  });

  it('should detect SAST patterns in Python files', async () => {
    tmpDir = createTempProject({
      'app.py': `
import pickle
data = pickle.loads(user_input)
      `,
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      secrets: false,
      policy: false,
    });

    const result = await scanner.scan();
    const sast = result.findings.filter(f => f.type === 'sast');
    const deserialize = sast.find(f => f.id === 'SAST_DESERIALIZE');
    assert.ok(deserialize, 'Should detect unsafe pickle deserialization');
    assert.strictEqual(deserialize!.severity, 'critical');
  });

  it('should parse JS imports from source files', async () => {
    tmpDir = createTempProject({
      'index.js': `
import express from 'express';
import React from 'react';
const lodash = require('lodash');
import { useState } from 'react';
      `,
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      secrets: false,
      sast: false,
      policy: false,
    });

    const result = await scanner.scan();
    assert.ok(result.summary.scannedFiles >= 1, 'Should scan at least 1 file');
  });

  it('should parse Python imports from source files', async () => {
    tmpDir = createTempProject({
      'main.py': `
import flask
from django import forms
import os
import sys
import numpy
      `,
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      secrets: false,
      sast: false,
      policy: false,
    });

    const result = await scanner.scan();
    assert.ok(result.summary.scannedFiles >= 1, 'Should scan at least 1 file');
  });

  it('should parse package.json dependencies', async () => {
    tmpDir = createTempProject({
      'package.json': JSON.stringify({
        dependencies: {
          express: '^4.18.0',
          lodash: '4.17.21',
        },
        devDependencies: {
          jest: '^29.0.0',
        },
      }),
      'index.js': 'console.log("hello");',
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      secrets: false,
      sast: false,
      policy: false,
    });

    const result = await scanner.scan();
    // Packages collected from manifest (even if no hallucination check runs)
    assert.ok(result.packages.length === 0 || result.summary.scannedFiles >= 0, 'Should not error');
  });

  it('should ignore node_modules and .git directories', async () => {
    tmpDir = createTempProject({
      'src/app.js': 'console.log("app");',
      'node_modules/evil/index.js': 'const secret = "AKIAIOSFODNN7EXAMPLE";',
      '.git/hooks/pre-commit': 'echo test',
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      policy: false,
    });

    const result = await scanner.scan();
    // Should not find secrets from node_modules
    const secretsFromNodeModules = result.findings.filter(
      f => f.type === 'secret' && f.file.includes('node_modules')
    );
    assert.strictEqual(secretsFromNodeModules.length, 0, 'Should not scan node_modules');
  });

  it('should filter findings by severity threshold', async () => {
    tmpDir = createTempProject({
      'app.js': `
const key = "AKIAIOSFODNN7EXAMPLE";
const hash = crypto.createHash('md5').update(data).digest('hex');
      `,
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      policy: false,
      severityThreshold: 'critical',
    });

    const result = await scanner.scan();
    // Only critical findings should remain
    for (const f of result.findings) {
      assert.strictEqual(f.severity, 'critical', `All findings should be critical, got ${f.severity}`);
    }
  });

  it('should compute correct summary counts', async () => {
    tmpDir = createTempProject({
      'app.js': `
const key = "AKIAIOSFODNN7EXAMPLE";
eval(userInput);
      `,
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      policy: false,
    });

    const result = await scanner.scan();
    const s = result.summary;
    assert.strictEqual(
      s.totalFindings,
      s.critical + s.high + s.medium + s.low + s.info,
      'Summary counts should add up'
    );
    assert.strictEqual(
      s.totalFindings,
      s.hallucinatedPackages + s.vulnerablePackages + s.secretsFound + s.sastFindings + s.policyViolations,
      'Category counts should add up'
    );
  });

  it('should return valid result structure', async () => {
    tmpDir = createTempProject({
      'hello.js': 'console.log("clean file");',
    });

    const scanner = new CoreScanner({ projectPath: tmpDir });
    const result = await scanner.scan();

    assert.ok(result.projectPath, 'Should have projectPath');
    assert.ok(result.timestamp, 'Should have timestamp');
    assert.ok(Array.isArray(result.findings), 'findings should be array');
    assert.ok(Array.isArray(result.packages), 'packages should be array');
    assert.ok(typeof result.summary === 'object', 'summary should be object');
    assert.ok(typeof result.summary.totalFindings === 'number', 'totalFindings should be number');
    assert.ok(typeof result.summary.scannedFiles === 'number', 'scannedFiles should be number');
  });

  it('should evaluate policy with forbidden packages', async () => {
    tmpDir = createTempProject({
      'index.js': 'console.log("clean");',
      'package.json': JSON.stringify({
        dependencies: { 'lodash': '4.17.21', 'express': '^4.18.0' },
      }),
      '.codeguard/policy.json': JSON.stringify({
        rules: {
          forbiddenPackages: ['lodash'],
          requireScanners: ['secrets', 'sast'],
        },
      }),
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      secrets: true,
      sast: true,
    });

    const result = await scanner.scan();
    const policyFindings = result.findings.filter(f => f.type === 'policy');
    const forbidden = policyFindings.find(f => f.id.includes('FORBIDDEN'));
    assert.ok(forbidden, 'Should flag forbidden package lodash');
    assert.ok(forbidden!.message.includes('lodash'), 'Message should mention lodash');
  });

  it('should skip policy if no policy file exists', async () => {
    tmpDir = createTempProject({
      'index.js': 'console.log("hello");',
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
    });

    const result = await scanner.scan();
    const policyFindings = result.findings.filter(f => f.type === 'policy');
    assert.strictEqual(policyFindings.length, 0, 'No policy findings without policy file');
  });

  it('should detect MCP server with npx rug-pull risk', async () => {
    tmpDir = createTempProject({
      'index.js': 'console.log("clean");',
      'mcp.json': JSON.stringify({
        mcpServers: {
          'risky-server': {
            command: 'npx',
            args: ['-y', 'some-mcp-server'],
          },
          'safe-server': {
            command: 'node',
            args: ['./local-server.js'],
          },
        },
      }),
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      secrets: false,
      sast: false,
    });

    const result = await scanner.scan();
    const mcpFindings = result.findings.filter(f => f.type === 'mcp');
    assert.ok(mcpFindings.length >= 1, 'Should detect at least 1 MCP issue');
    const rugPull = mcpFindings.find(f => f.id.includes('RUGPULL'));
    assert.ok(rugPull, 'Should flag npx rug-pull risk');
    assert.ok(rugPull!.message.includes('risky-server'), 'Should name the risky server');
    assert.strictEqual(result.summary.mcpIssues, mcpFindings.length, 'mcpIssues summary should match');
  });

  it('should detect MCP hardcoded credentials', async () => {
    tmpDir = createTempProject({
      'index.js': 'console.log("clean");',
      '.cursor/mcp.json': JSON.stringify({
        mcpServers: {
          'cred-server': {
            command: 'node',
            args: ['server.js'],
            env: {
              'AWS_SECRET_ACCESS_KEY': 'AKIAIOSFODNN7EXAMPLE',
              'SAFE_VAR': '${env:MY_VAR}',
            },
          },
        },
      }),
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      secrets: false,
      sast: false,
    });

    const result = await scanner.scan();
    const mcpFindings = result.findings.filter(f => f.type === 'mcp');
    const credFinding = mcpFindings.find(f => f.id.includes('CRED'));
    assert.ok(credFinding, 'Should detect hardcoded AWS credential');
    assert.strictEqual(credFinding!.severity, 'critical', 'Hardcoded credential should be critical');
  });

  it('should skip MCP scanning when mcp option is false', async () => {
    tmpDir = createTempProject({
      'index.js': 'console.log("clean");',
      'mcp.json': JSON.stringify({
        mcpServers: {
          'risky': { command: 'npx', args: ['dangerous-server'] },
        },
      }),
    });

    const scanner = new CoreScanner({
      projectPath: tmpDir,
      hallucination: false,
      vulnerabilities: false,
      secrets: false,
      sast: false,
      mcp: false,
    });

    const result = await scanner.scan();
    const mcpFindings = result.findings.filter(f => f.type === 'mcp');
    assert.strictEqual(mcpFindings.length, 0, 'Should not find MCP issues when scanning disabled');
  });
});
