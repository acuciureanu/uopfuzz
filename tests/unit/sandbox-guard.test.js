import { test, describe } from 'node:test';
import assert from 'node:assert';

import {
  isSandboxed,
  evaluateSandboxGate,
  assertSandboxedOrRefuse,
} from '../../src/utils/sandbox-guard.js';

/**
 * The host-safety gate for the untrusted-package modes (`mass`, cdnjs
 * `versions`). These modes install and execute arbitrary packages, so on a
 * non-sandboxed host they must hard-refuse rather than expose the host to a
 * supply-chain payload. These tests pin that contract.
 */

describe('isSandboxed (detection)', () => {
  test('true when UOPFUZZ_CONTAINER is set and non-empty', () => {
    assert.equal(isSandboxed({ UOPFUZZ_CONTAINER: '1' }, () => false), true);
  });

  test('false when UOPFUZZ_CONTAINER is empty/whitespace and no marker exists', () => {
    assert.equal(isSandboxed({ UOPFUZZ_CONTAINER: '' }, () => false), false);
    assert.equal(isSandboxed({ UOPFUZZ_CONTAINER: '   ' }, () => false), false);
    assert.equal(isSandboxed({}, () => false), false);
  });

  test('true when a container marker file exists even without the env var', () => {
    assert.equal(isSandboxed({}, (p) => p === '/.dockerenv'), true);
    assert.equal(isSandboxed({}, (p) => p === '/run/.containerenv'), true);
  });

  test('a throwing fs check degrades to not-sandboxed, never crashes', () => {
    assert.equal(isSandboxed({}, () => { throw new Error('fs blew up'); }), false);
  });
});

describe('evaluateSandboxGate (pure decision)', () => {
  test('sandboxed → allow, level ok', () => {
    const d = evaluateSandboxGate({ sandboxed: true, override: false });
    assert.equal(d.allow, true);
    assert.equal(d.level, 'ok');
  });

  test('not sandboxed, no override → refuse', () => {
    const d = evaluateSandboxGate({ sandboxed: false, override: false });
    assert.equal(d.allow, false);
    assert.equal(d.level, 'refuse');
    assert.match(d.message, /run-sandboxed\.sh/);
  });

  test('not sandboxed, override → allow but warn loudly', () => {
    const d = evaluateSandboxGate({ sandboxed: false, override: true });
    assert.equal(d.allow, true);
    assert.equal(d.level, 'warn');
    assert.match(d.message, /accepted this risk/i);
  });

  test('sandboxed wins even when override is also set', () => {
    const d = evaluateSandboxGate({ sandboxed: true, override: true });
    assert.equal(d.level, 'ok');
  });
});

describe('assertSandboxedOrRefuse (enforcement)', () => {
  const silentLog = { info() {}, warn() {}, error() {} };

  test('exits non-zero on a non-sandboxed host with no override', () => {
    let exitCode = null;
    const proceeded = assertSandboxedOrRefuse({
      mode: 'mass',
      override: false,
      sandboxedFn: () => false,
      exit: (c) => { exitCode = c; },
      log: silentLog,
    });
    assert.equal(exitCode, 1, 'must call exit(1)');
    assert.equal(proceeded, false, 'must not signal proceed on refuse');
  });

  test('proceeds without exiting when sandboxed', () => {
    let exited = false;
    const proceeded = assertSandboxedOrRefuse({
      mode: 'mass',
      sandboxedFn: () => true,
      exit: () => { exited = true; },
      log: silentLog,
    });
    assert.equal(exited, false, 'must not exit when sandboxed');
    assert.equal(proceeded, true);
  });

  test('proceeds (with warning) when overridden on a non-sandboxed host', () => {
    let exited = false;
    let warned = false;
    const proceeded = assertSandboxedOrRefuse({
      mode: 'versions',
      override: true,
      sandboxedFn: () => false,
      exit: () => { exited = true; },
      log: { info() {}, warn() { warned = true; }, error() {} },
    });
    assert.equal(exited, false);
    assert.equal(warned, true, 'override must warn');
    assert.equal(proceeded, true);
  });
});
