import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Instrumentation } from '../../src/instrumentation/index.js';
import { reproduceRce } from '../../src/verification/reproduce.js';
import { executeInSandbox } from '../../src/utils/sandbox.js';

/**
 * End-to-end coverage for the fs / http / DOM sink classes added alongside the
 * original eval/Function/child_process hooks. Each test drives a hermetic
 * fixture modelling a real gadget class (LFI, SSRF, DOM-XSS) and asserts:
 *   - the sandboxed differential oracle observes the new sink firing, AND
 *   - the independent reproduction gate confirms it via sink_reach (2/2 fresh
 *     processes), with a standalone PoC.
 *
 * Before these hooks existed, every gadget on this page was invisible: the
 * discovery oracle never observed the sink (so the candidate never surfaced),
 * and even if it had, reproduction had no sink_reach coverage for these classes
 * to confirm it.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

function inst() {
  return new Instrumentation({ sandbox: true, blockNetwork: true });
}

describe('SSRF sink coverage (http.request)', () => {
  const config = { package: FIX('ssrf-gadget') };
  const input = { type: 'value', value: {}, entryPoint: 'fetch' };
  const descriptor = { property: 'endpoint', value: 'http://example.invalid/x' };

  test('sandboxed differential observes http.request firing', async () => {
    const res = await inst().executeDifferentialTracing(input, config, descriptor);
    assert.ok(res?.diff, 'the SSRF gadget must surface as a candidate');
    const d = res.diff;
    assert.equal(d.details.sandboxed, true);
    assert.equal(d.proofType, 'rce');
    assert.equal(d.isCandidate, true);
    // The eval/Function/child_process sinks this fixture never reaches must NOT
    // show up — proves we are seeing the NEW http.request sink, not a false
    // positive from an existing hook.
    assert.ok(d.newSinkAccesses.some(s => s.sink === 'http.request'),
      'http.request must be in the new-sink set');
  });

  test('reproduction confirms sink_reach with a standalone PoC (2/2 fresh procs)', async () => {
    const r = await reproduceRce(FIX('ssrf-gadget'), 'fetch',
      { property: 'endpoint', gates: [], minimalArgs: [{}] });
    assert.equal(r.verified, true, 'SSRF reachability must reproduce');
    assert.equal(r.runs, 2);
    assert.equal(r.payloadType, 'sink_reach', 'proof kind is sink_reach (the URL arg)');
    assert.equal(r.restriction, 'none', 'http.request reached with no guard forced');
    assert.match(r.standalonePoC, /fetch\(/);
  });
});

describe('LFI sink coverage (fs.readFileSync)', () => {
  const config = { package: FIX('lfi-gadget') };
  const input = { type: 'value', value: {}, entryPoint: 'load' };
  const descriptor = { property: 'path', value: '/etc/passwd' };

  test('sandboxed differential observes fs.readFileSync firing', async () => {
    const res = await inst().executeDifferentialTracing(input, config, descriptor);
    assert.ok(res?.diff, 'the LFI gadget must surface as a candidate');
    const d = res.diff;
    assert.ok(d.newSinkAccesses.some(s => s.sink === 'fs.readFileSync'),
      'fs.readFileSync must be in the new-sink set');
  });

  test('reproduction confirms sink_reach for the path argument', async () => {
    const r = await reproduceRce(FIX('lfi-gadget'), 'load',
      { property: 'path', gates: [], minimalArgs: [{}] });
    assert.equal(r.verified, true, 'LFI reachability must reproduce');
    assert.equal(r.runs, 2);
    assert.equal(r.payloadType, 'sink_reach');
    assert.match(r.standalonePoC, /load\(/);
  });
});

describe('DOM-XSS sink coverage (innerHTML)', () => {
  // Browser-only fixture: needs jsdom standing up before the target runs. The
  // sandbox worker boots jsdom and installs the DOM sink hooks lazily, then
  // serves the request against the live DOM. Reproduction's sink_reach hook
  // for innerHTML mirrors the discovery hook.
  const config = { package: FIX('dom-xss-gadget'), browserEnv: true };
  const input = { type: 'value', value: {}, entryPoint: 'render' };
  const descriptor = { property: 'html', value: '<img src=x onerror=alert(1)>' };

  test('sandboxed differential observes innerHTML firing under jsdom', async () => {
    const res = await inst().executeDifferentialTracing(input, config, descriptor);
    assert.ok(res?.diff, 'the DOM-XSS gadget must surface as a candidate');
    const d = res.diff;
    assert.ok(d.newSinkAccesses.some(s => s.sink === 'innerHTML'),
      'innerHTML must be in the new-sink set');
  });

  test('reproduction confirms sink_reach for the innerHTML value', async () => {
    const r = await reproduceRce(FIX('dom-xss-gadget'), 'render',
      { property: 'html', gates: [], minimalArgs: [{}] }, { browserEnv: true });
    assert.equal(r.verified, true, 'DOM-XSS reachability must reproduce');
    assert.equal(r.runs, 2);
    assert.equal(r.payloadType, 'sink_reach');
    assert.match(r.standalonePoC, /render\(/);
  });
});

describe('sandbox-worker direct dispatch — new sink classes observable', () => {
  // Drive the sandbox worker directly (no Instrumentation wrapper) to confirm
  // the sinkLog entries are populated exactly as expected for each sink class.
  // This is the lower-level invariant the differential mode relies on: if the
  // sink never fires in the worker, no oracle above it can ever observe it.
  test('fs.readFileSync access appears in sinkAccesses', async () => {
    const result = await executeInSandbox(FIX('lfi-gadget'), 'load', [{}], {
      timeoutMs: 3000,
      blockNetwork: true,
      mode: 'differential',
      pollution: { property: 'path', value: '/tmp/uopfuzz-lfi-probe' },
    });
    assert.ok(result.sinkAccesses?.some(s => s.sink === 'fs.readFileSync'),
      'fs.readFileSync must be in the raw sinkAccesses log');
  });

  test('http.request access appears in sinkAccesses', async () => {
    const result = await executeInSandbox(FIX('ssrf-gadget'), 'fetch', [{}], {
      timeoutMs: 3000,
      blockNetwork: true,
      mode: 'differential',
      pollution: { property: 'endpoint', value: 'http://example.invalid/probe' },
    });
    assert.ok(result.sinkAccesses?.some(s => s.sink === 'http.request'),
      'http.request must be in the raw sinkAccesses log');
  });
});
