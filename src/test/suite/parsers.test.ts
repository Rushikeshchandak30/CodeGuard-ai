import * as assert from 'assert';
import { JavaScriptParser } from '../../parsers/javascript';
import { PythonParser } from '../../parsers/python';

suite('JavaScript/TypeScript Parser', () => {
  const parser = new JavaScriptParser();

  test('parses ES module imports', () => {
    const code = `
import lodash from 'lodash';
import { merge } from 'lodash';
import * as React from 'react';
import 'express';
`;
    const deps = parser.parse(code, 'javascript');
    const names = deps.map(d => d.name);
    assert.ok(names.includes('lodash'), 'Should find lodash');
    assert.ok(names.includes('react'), 'Should find react');
    assert.ok(names.includes('express'), 'Should find express');
  });

  test('parses CommonJS require()', () => {
    const code = `
const fs = require('fs');
const axios = require('axios');
const { Router } = require('express');
`;
    const deps = parser.parse(code, 'javascript');
    const names = deps.map(d => d.name);
    // fs is a built-in but JS parser doesn't filter stdlib (that's Python's job)
    assert.ok(names.includes('axios'), 'Should find axios');
    assert.ok(names.includes('express'), 'Should find express');
  });

  test('parses scoped packages', () => {
    const code = `import { something } from '@angular/core';`;
    const deps = parser.parse(code, 'javascript');
    assert.strictEqual(deps[0].name, '@angular/core');
  });

  test('ignores relative imports', () => {
    const code = `
import { foo } from './utils';
import bar from '../lib/bar';
const baz = require('./baz');
`;
    const deps = parser.parse(code, 'javascript');
    assert.strictEqual(deps.length, 0, 'Should not find relative imports');
  });

  test('parses package.json dependencies', () => {
    const pkgJson = JSON.stringify({
      dependencies: {
        'express': '^4.18.2',
        'lodash': '4.17.21',
      },
      devDependencies: {
        'typescript': '~5.3.3',
      },
    }, null, 2);

    const deps = parser.parse(pkgJson, 'json');
    assert.strictEqual(deps.length, 3);

    const express = deps.find(d => d.name === 'express');
    assert.ok(express, 'Should find express');
    assert.strictEqual(express!.version, '4.18.2');
    assert.strictEqual(express!.ecosystem, 'npm');

    const ts = deps.find(d => d.name === 'typescript');
    assert.ok(ts, 'Should find typescript');
    assert.strictEqual(ts!.version, '5.3.3');
  });

  test('handles dynamic imports', () => {
    const code = `const mod = import('some-module');`;
    const deps = parser.parse(code, 'javascript');
    assert.strictEqual(deps.length, 1);
    assert.strictEqual(deps[0].name, 'some-module');
  });

  test('correctly strips subpaths', () => {
    const code = `import merge from 'lodash/merge';`;
    const deps = parser.parse(code, 'javascript');
    assert.strictEqual(deps[0].name, 'lodash');
  });
});

suite('Python Parser', () => {
  const parser = new PythonParser();

  test('parses import statements', () => {
    const code = `
import requests
import flask
import numpy
`;
    const deps = parser.parse(code, 'python');
    const names = deps.map(d => d.name);
    assert.ok(names.includes('requests'), 'Should find requests');
    assert.ok(names.includes('flask'), 'Should find flask');
    assert.ok(names.includes('numpy'), 'Should find numpy');
  });

  test('parses from-import statements', () => {
    const code = `
from flask import Flask, jsonify
from requests.auth import HTTPBasicAuth
`;
    const deps = parser.parse(code, 'python');
    const names = deps.map(d => d.name);
    assert.ok(names.includes('flask'), 'Should find flask');
    assert.ok(names.includes('requests'), 'Should find requests');
  });

  test('filters stdlib modules', () => {
    const code = `
import os
import sys
import json
import pathlib
import requests
`;
    const deps = parser.parse(code, 'python');
    assert.strictEqual(deps.length, 1, 'Should only find requests (non-stdlib)');
    assert.strictEqual(deps[0].name, 'requests');
  });

  test('deduplicates imports', () => {
    const code = `
import requests
from requests import get
`;
    const deps = parser.parse(code, 'python');
    assert.strictEqual(deps.length, 1, 'Should deduplicate requests');
  });

  test('parses requirements.txt format', () => {
    const reqs = `
requests==2.28.1
flask>=2.0.0
numpy~=1.24.0
# comment line
-r base.txt
pandas
`;
    const deps = parser.parseRequirementsTxt(reqs);
    assert.strictEqual(deps.length, 4);

    const requests = deps.find(d => d.name === 'requests');
    assert.ok(requests);
    assert.strictEqual(requests!.version, '2.28.1');
    assert.strictEqual(requests!.ecosystem, 'PyPI');

    const pandas = deps.find(d => d.name === 'pandas');
    assert.ok(pandas);
    assert.strictEqual(pandas!.version, null, 'Unpinned package should have null version');
  });

  test('normalizes underscore to hyphen', () => {
    const code = `import my_package`;
    const deps = parser.parse(code, 'python');
    assert.strictEqual(deps[0].name, 'my-package');
  });

  test('all deps have PyPI ecosystem', () => {
    const code = `import requests\nimport flask`;
    const deps = parser.parse(code, 'python');
    assert.ok(deps.every(d => d.ecosystem === 'PyPI'));
  });
});
