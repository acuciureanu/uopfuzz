import { test, describe } from 'node:test';
import assert from 'node:assert';
import { sinkImpact, impactFromProof } from '../../src/gadget-analysis/sink-impact.js';

describe('sinkImpact — RCE is reserved for genuine code/command execution', () => {
  test('code-execution sinks are RCE', () => {
    for (const s of ['code-execution', 'eval', 'Function', 'vm.runInThisContext']) {
      const r = sinkImpact(s);
      assert.equal(r.category, 'code-execution');
      assert.equal(r.isRce, true);
    }
  });

  test('command-injection is RCE-class but its own category', () => {
    const r = sinkImpact('child_process.execSync');
    assert.equal(r.category, 'command-injection');
    assert.equal(r.isRce, true);
  });

  test('SSRF / LFI / XSS are NOT labelled RCE', () => {
    assert.equal(sinkImpact('http.request').category, 'ssrf');
    assert.equal(sinkImpact('http.request').isRce, false);
    assert.equal(sinkImpact('fs.readFile').category, 'lfi');
    assert.equal(sinkImpact('fs.readFile').isRce, false);
    assert.equal(sinkImpact('innerHTML').category, 'xss');
    assert.equal(sinkImpact('innerHTML').isRce, false);
  });

  test('an unknown/absent sink is a conservative reachability category, never RCE', () => {
    assert.equal(sinkImpact(null).isRce, false);
    assert.equal(sinkImpact('something-weird').isRce, false);
  });
});

describe('impactFromProof — impact + proven flag from the reproduction proof', () => {
  test('a fired canary is proven code execution', () => {
    const r = impactFromProof({ type: 'code-execution', sink: 'code-execution' });
    assert.equal(r.category, 'code-execution');
    assert.equal(r.isRce, true);
    assert.equal(r.proven, true);
  });

  test('sink-reachability to exec is command injection, reachability-only', () => {
    const r = impactFromProof({ type: 'sink-reachability', sink: 'child_process.execSync' });
    assert.equal(r.category, 'command-injection');
    assert.equal(r.isRce, true);
    assert.equal(r.proven, false); // reached the sink; execution not proven
  });

  test('sink-reachability to http is SSRF (reachability), not RCE', () => {
    const r = impactFromProof({ type: 'sink-reachability', sink: 'http.request' });
    assert.equal(r.category, 'ssrf');
    assert.equal(r.isRce, false);
    assert.equal(r.proven, false);
  });

  test('a pp source has the prototype-pollution impact, not a sink', () => {
    const r = impactFromProof({ type: 'prototype-pollution' });
    assert.equal(r.category, 'prototype-pollution');
    assert.equal(r.isRce, false);
    assert.equal(r.proven, true);
  });
});
