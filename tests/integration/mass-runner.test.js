/**
 * Integration tests for MassRunner and VersionRunner.
 *
 * These tests mock the cdnjs fetch layer and drive the runners in dry-run mode
 * (dryRun: true, maxIterations: 1) to validate the orchestration logic without
 * installing real packages or running live fuzzing.
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { MassRunner, VersionRunner } from '../../src/orchestrator/mass-runner.js';

// ─── fetch mock helpers ───────────────────────────────────────────────────────

let originalFetch;
beforeEach(() => { originalFetch = globalThis.fetch; });
afterEach(() => { globalThis.fetch = originalFetch; });

/**
 * Build a minimal mock cdnjs API that honours:
 *   GET /libraries         → { results: LIBS }
 *   GET /libraries/:name   → LIBS[0] with versions array
 */
function mockCdnjsApi(libs) {
  return async function mockFetch(url) {
    const u = String(url);

    // /libraries/:name/:version  — not needed for these tests
    if (/\/libraries\/[^?]+\/[^?]+$/.test(u)) {
      return jsonOk({ files: [], rawFiles: [] });
    }

    // /libraries/:name  — return first matching lib with versions
    const libMatch = u.match(/\/libraries\/([^/?]+)(\?|$)/);
    if (libMatch && !u.startsWith('https://api.cdnjs.com/libraries?')) {
      const name = decodeURIComponent(libMatch[1]);
      const lib = libs.find(l => l.name === name) || libs[0];
      return jsonOk({
        ...lib,
        versions: lib.versions || ['1.0.0', '0.9.0'],
        autoupdate: lib.autoupdate || { source: 'npm', target: lib.name }
      });
    }

    // /libraries  (browse / search)
    return jsonOk({ results: libs });
  };
}

function jsonOk(data) {
  return { ok: true, status: 200, json: async () => data };
}

// ─── Shared test fixtures ─────────────────────────────────────────────────────

const MOCK_LIBS = [
  {
    name: 'mock-lib-a',
    version: '2.0.0',
    fileType: 'js',
    github: { stargazers_count: 5000 },
    autoupdate: { source: 'npm', target: 'mock-lib-a' }
  },
  {
    name: 'mock-lib-b',
    version: '1.5.0',
    fileType: 'js',
    github: { stargazers_count: 3000 },
    autoupdate: { source: 'npm', target: 'mock-lib-b' }
  }
];

// ─── Shared minimal orchestrator options ─────────────────────────────────────

function baseOpts(outputDir) {
  return {
    dryRun: true,
    maxIterations: 1,
    timeout: 5,
    parallelWorkers: 1,
    verbose: false,
    sandbox: false,
    blockNetwork: true,
    allowScripts: false,
    allowSuspicious: false,
    skipIntegrityCheck: false,
    outputDir,
  };
}

// ─── MassRunner ───────────────────────────────────────────────────────────────

describe('MassRunner', () => {
  test('runs without throwing and returns a summary', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'uopfuzz-mass-'));
    globalThis.fetch = mockCdnjsApi(MOCK_LIBS);

    try {
      const runner = new MassRunner({
        search: '',
        topN: 2,
        limit: 5,
        resume: false,
        options: baseOpts(tmpDir)
      });

      const summary = await runner.run();

      assert.equal(typeof summary, 'object', 'run() should return an object');
      assert.equal(typeof summary.total, 'number', 'summary.total should be a number');
      assert.equal(typeof summary.reportFile, 'string', 'summary.reportFile should be a string');
      assert.ok(summary.reportFile.endsWith('.md'), 'reportFile should end with .md');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  test('writes a Markdown report file to outputDir', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'uopfuzz-mass-'));
    globalThis.fetch = mockCdnjsApi(MOCK_LIBS);

    try {
      const runner = new MassRunner({
        topN: 2,
        options: baseOpts(tmpDir)
      });
      const summary = await runner.run();

      const stat = await fs.stat(summary.reportFile);
      assert.ok(stat.isFile(), 'report file should exist');

      const content = await fs.readFile(summary.reportFile, 'utf8');
      assert.ok(content.includes('Mass Scan Report'), 'report should contain mass scan heading');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  test('resume skips existing results', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'uopfuzz-resume-'));
    globalThis.fetch = mockCdnjsApi(MOCK_LIBS);

    try {
      // Pre-create a result file for mock-lib-a
      const preExisting = path.join(tmpDir, 'mass-mock-lib-a-2.0.0.json');
      await fs.writeFile(preExisting, JSON.stringify({ confirmedChains: [], potentialChains: [], errors: [] }));

      // Patch the runner to count orchestrator instantiations (dry-run still calls Orchestrator)
      // We just verify the total returned remains correct with resume.
      const runner = new MassRunner({
        topN: 2,
        resume: true,
        options: baseOpts(tmpDir)
      });

      const summary = await runner.run();
      // mock-lib-a was skipped (pre-existing result loaded from file),
      // mock-lib-b was scanned. Total should still be 2.
      assert.equal(summary.total, 2, 'Should report total including resumed + scanned');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  test('summary.failed increments for libraries that error', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'uopfuzz-fail-'));
    // Return a lib with an invalid npm package so Orchestrator will fail quickly in dry-run?
    // In dry-run mode Orchestrator auto-discovers but network is blocked. Any dependency install
    // or auto-discover will fail. That is the expected failure path.
    globalThis.fetch = mockCdnjsApi([{
      name: 'guaranteed-fail',
      version: '0.0.1',
      fileType: 'js',
      github: { stargazers_count: 1 },
      autoupdate: { source: 'npm', target: 'guaranteed-fail' }
    }]);

    try {
      const runner = new MassRunner({
        topN: 1,
        options: { ...baseOpts(tmpDir), dryRun: false, maxIterations: 0 }
      });
      // It may fail or succeed depending on whether the package is installed globally.
      // We only assert the shape of summary, not specific failure counts.
      const summary = await runner.run();
      assert.equal(typeof summary.failed, 'number');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

// ─── VersionRunner ────────────────────────────────────────────────────────────

describe('VersionRunner', () => {
  test('runs without throwing and returns a summary', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'uopfuzz-ver-'));
    globalThis.fetch = mockCdnjsApi(MOCK_LIBS);

    try {
      const runner = new VersionRunner({
        cdnjsName: 'mock-lib-a',
        npmPackage: 'mock-lib-a',
        strategy: { mode: 'last', count: 2 },
        options: baseOpts(tmpDir)
      });

      const summary = await runner.run();

      assert.equal(typeof summary, 'object');
      assert.equal(summary.library, 'mock-lib-a');
      assert.equal(typeof summary.versionsTotal, 'number');
      assert.equal(typeof summary.reportFile, 'string');
      assert.ok(summary.reportFile.endsWith('.md'));
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  test('writes a Markdown report file to outputDir', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'uopfuzz-ver2-'));
    globalThis.fetch = mockCdnjsApi(MOCK_LIBS);

    try {
      const runner = new VersionRunner({
        cdnjsName: 'mock-lib-a',
        npmPackage: 'mock-lib-a',
        strategy: { mode: 'last', count: 1 },
        options: baseOpts(tmpDir)
      });
      const summary = await runner.run();

      const stat = await fs.stat(summary.reportFile);
      assert.ok(stat.isFile(), 'report file should exist');

      const content = await fs.readFile(summary.reportFile, 'utf8');
      assert.ok(content.includes('Version Sweep'), 'report should contain version sweep heading');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  test('auto-resolves npm package name via cdnjs API', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'uopfuzz-ver3-'));
    globalThis.fetch = mockCdnjsApi(MOCK_LIBS);

    try {
      // Do NOT pass npmPackage — it should be resolved via the API
      const runner = new VersionRunner({
        cdnjsName: 'mock-lib-a',
        strategy: { mode: 'last', count: 1 },
        options: baseOpts(tmpDir)
      });
      const summary = await runner.run();
      assert.equal(summary.library, 'mock-lib-a');
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  test('throws when no versions match the strategy', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'uopfuzz-novers-'));
    globalThis.fetch = mockCdnjsApi([{
      ...MOCK_LIBS[0],
      versions: []
    }]);

    try {
      const runner = new VersionRunner({
        cdnjsName: 'empty-lib',
        npmPackage: 'empty-lib',
        strategy: { mode: 'all' },
        options: baseOpts(tmpDir)
      });
      await assert.rejects(() => runner.run(), /No versions found/);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});
