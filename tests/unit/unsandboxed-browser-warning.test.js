import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';

import { Instrumentation } from '../../src/instrumentation/index.js';
import { logger } from '../../src/utils/logger.js';

// With --no-sandbox a browser-only target runs in-process again, which is the
// exact configuration that lets a synchronous jsdom XHR freeze the fuzzer's
// event loop (neither the per-call nor the iteration timeout can fire on a
// frozen loop). That is a deliberate "faster, less safe" opt-in, but it should
// not be silent.
describe('--no-sandbox + browser-only target emits a freeze-risk warning', () => {
  let warnings;
  let originalWarn;

  beforeEach(() => {
    warnings = [];
    originalWarn = logger.warn;
    logger.warn = (msg) => { warnings.push(String(msg)); };
  });

  afterEach(() => { logger.warn = originalWarn; });

  const browserConfig = { name: 'jquery', package: 'jquery', version: '3.7.1', browserEnv: true };

  test('warns when sandboxing is disabled for a browser-only target', () => {
    const instr = new Instrumentation({ sandbox: false });
    const warned = instr.warnIfUnsandboxedBrowserTarget(browserConfig);

    assert.equal(warned, true, 'should report that it warned');
    assert.equal(warnings.length, 1, `expected exactly one warning, got ${warnings.length}`);
    assert.match(warnings[0], /--no-sandbox/, 'warning should name the flag responsible');
    assert.match(warnings[0], /freeze|hang|block/i, 'warning should describe the freeze risk');
  });

  test('recognises a known browser-only package even without the browserEnv flag', () => {
    const instr = new Instrumentation({ sandbox: false });
    const warned = instr.warnIfUnsandboxedBrowserTarget({ name: 'backbone', package: 'backbone@1.4.0' });
    assert.equal(warned, true, 'a known browser-only package must be recognised by name');
  });

  test('stays quiet when sandboxing is enabled (the safe default)', () => {
    const instr = new Instrumentation({ sandbox: true });
    const warned = instr.warnIfUnsandboxedBrowserTarget(browserConfig);
    assert.equal(warned, false);
    assert.equal(warnings.length, 0, 'sandboxed browser targets are safe — no warning');
  });

  test('stays quiet for a non-browser target even without a sandbox', () => {
    const instr = new Instrumentation({ sandbox: false });
    const warned = instr.warnIfUnsandboxedBrowserTarget({ name: 'lodash', package: 'lodash' });
    assert.equal(warned, false);
    assert.equal(warnings.length, 0, 'a non-browser target has no jsdom sync-XHR freeze risk');
  });
});
