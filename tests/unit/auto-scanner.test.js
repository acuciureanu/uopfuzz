import { test, describe } from 'node:test';
import assert from 'node:assert';
import { AutoScanner } from '../../src/auto-scanner.js';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('AutoScanner', () => {
  test('should detect template engine type', async () => {
    const scanner = new AutoScanner('handlebars', { dryRun: true });
    const type = await scanner.detectLibraryType();

    assert.strictEqual(type, 'template', 'Should detect handlebars as template engine');
  });

  test('should detect merge library type', async () => {
    const scanner = new AutoScanner('lodash', { dryRun: true });
    const type = await scanner.detectLibraryType();

    // lodash might be detected as generic or merge
    assert.ok(['merge', 'generic'].includes(type), `Type should be merge or generic, got: ${type}`);
  });

  test('should generate config for template engine', async () => {
    const scanner = new AutoScanner('pug@3.0.2', { dryRun: true });
    const config = scanner.generateConfig('template');

    assert.strictEqual(config.name, 'pug');
    assert.strictEqual(config.version, '3.0.2');
    assert.ok(Array.isArray(config.entryPoints));
    assert.ok(config.entryPoints.length > 0);
    assert.ok(Array.isArray(config.sinks));
    assert.ok(config.sinks.includes('eval'));
    assert.ok(Array.isArray(config.pollutionPoints));
  });

  test('should handle package without version', async () => {
    const scanner = new AutoScanner('express', { dryRun: true });

    assert.strictEqual(scanner.packageName, 'express');
    assert.strictEqual(scanner.packageVersion, 'latest');
  });

  test('should generate different configs for different types', async () => {
    const scanner = new AutoScanner('test', { dryRun: true });

    const templateConfig = scanner.generateConfig('template');
    const mergeConfig = scanner.generateConfig('merge');

    // Entry points should differ
    const templateEntries = templateConfig.entryPoints.map(e => e.name);
    const mergeEntries = mergeConfig.entryPoints.map(e => e.name);

    assert.ok(templateEntries.includes('render'));
    assert.ok(mergeEntries.includes('merge'));
    assert.notDeepEqual(templateEntries, mergeEntries);
  });

  test('should run scan in dry-run mode', async () => {
    const scanner = new AutoScanner('handlebars', {
      dryRun: true,
      maxIterations: 10
    });

    const results = await scanner.scan();

    assert.ok(results, 'Should return results');
    assert.ok(Array.isArray(results.potentialChains));
    assert.ok(results.iterationsCompleted >= 0);
  });

  test('should handle invalid package gracefully', async () => {
    const scanner = new AutoScanner('this-package-does-not-exist-12345', {
      dryRun: true,
      maxIterations: 5
    });

    // Should fall back to generic type
    const type = await scanner.detectLibraryType();
    assert.strictEqual(type, 'generic');
  });

  test('should parse package spec correctly', async () => {
    const testCases = [
      { spec: 'lodash', expectedName: 'lodash', expectedVersion: 'latest' },
      { spec: 'pug@3.0.2', expectedName: 'pug', expectedVersion: '3.0.2' },
      { spec: 'express@4.18.0', expectedName: 'express', expectedVersion: '4.18.0' }
    ];

    for (const { spec, expectedName, expectedVersion } of testCases) {
      const scanner = new AutoScanner(spec);
      assert.strictEqual(scanner.packageName, expectedName);
      assert.strictEqual(scanner.packageVersion, expectedVersion);
    }
  });
});
