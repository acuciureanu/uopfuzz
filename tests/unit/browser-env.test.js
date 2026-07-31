import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BROWSER_ONLY_PACKAGES,
  isBrowserOnly,
  JSDOM_STARTUP_ALLOWANCE_MS,
} from '../../src/utils/browser-env.js';
import { executeInSandbox } from '../../src/utils/sandbox.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

describe('browser-env — classification (fast)', () => {
  test('the known browser-only packages are recognized', () => {
    for (const pkg of ['jquery', 'jquery-ui', 'backbone', 'underscore']) {
      assert.equal(isBrowserOnly(pkg), true, `${pkg} must be browser-only`);
      assert.ok(BROWSER_ONLY_PACKAGES.has(pkg));
    }
  });

  test('a normal package is not browser-only', () => {
    assert.equal(isBrowserOnly('lodash'), false);
    assert.equal(isBrowserOnly('gated-gadget'), false);
  });

  test('a positive jsdom startup allowance is exported', () => {
    assert.ok(Number.isFinite(JSDOM_STARTUP_ALLOWANCE_MS) && JSDOM_STARTUP_ALLOWANCE_MS > 0);
  });
});

// The jsdom path forks a child and cold-starts jsdom, which is heavy — these
// run longer than a typical unit test (seconds, more on a slow filesystem).
describe('browser-env — jsdom sandbox execution', () => {
  test('a DOM-requiring library FAILS to load without browserEnv', async () => {
    const r = await executeInSandbox(FIX('fake-browser-lib'), 'extend', [{}], {
      timeoutMs: 2000, blockNetwork: true, mode: 'merge_pp',
      pollution: { property: 'polluted', value: true },
      // browserEnv omitted → no DOM → the module throws at load.
    });
    // No pollution detected because the module could not even load.
    assert.ok(!r?.pollutionDetected, 'must not detect anything when the DOM library cannot load');
  });

  test('with browserEnv, the library loads under jsdom and its PP is detected in the sandbox', async () => {
    const r = await executeInSandbox(FIX('fake-browser-lib'), 'extend', [{}], {
      timeoutMs: 2000, blockNetwork: true, browserEnv: true, mode: 'merge_pp',
      pollution: { property: 'polluted', value: true },
    });
    assert.equal(r?.pollutionDetected, true, 'browserEnv must let the DOM library load and its PP be observed');
    assert.ok((r.pollutedProperties || []).some(p => p.includes('polluted')));
  });

  test('the sandbox stays contained — the DOM library never touches the parent prototype', () => {
    // The merge_pp above ran in a child; this parent process must be clean.
    assert.equal(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted'), false);
  });
});
