import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Instrumentation } from '../../src/instrumentation/index.js';
import { reproduceRce } from '../../src/verification/reproduce.js';
import { executeInSandbox } from '../../src/utils/sandbox.js';

/**
 * Every discovery mode that executes untrusted target code must run through the
 * sandbox child process, not in-process with the fuzzer's privileges. These
 * tests drive the sandboxed forced-branch, multi-property, and UOP-discovery
 * modes end-to-end against hermetic fixtures and assert:
 *   - a gated gadget the single-property oracle MISSES is found by the
 *     sandboxed forced-branch mode, and the independent reproduction gate
 *     confirms it (2/2 fresh processes) — the full "find a real gadget" path;
 *   - the zero-FP direction still holds (benign fixture never reproduces).
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

function inst() {
  return new Instrumentation({ sandbox: true, blockNetwork: true });
}

describe('sandboxed forced-branch discovery', () => {
  const config = { package: FIX('gated-gadget') };
  const input = { type: 'value', value: {}, entryPoint: 'render' };
  const descriptor = { property: 'command', value: 'globalThis.__x=1' };

  test('single-property differential MISSES a gate-guarded sink', async () => {
    const res = await inst().executeDifferentialTracing(input, config, descriptor);
    // The sink is behind `if (opts.debug)`; polluting only `command` leaves the
    // gate closed, so there is nothing to report.
    assert.equal(res, null, 'gate-guarded gadget must not surface without forcing the gate');
  });

  test('forced-branch FINDS it by co-polluting the debug gate (sandboxed)', async () => {
    const res = await inst().executeForcedBranchDifferentialTracing(input, config, descriptor);
    assert.ok(res?.diff, 'forced-branch must surface the gated gadget');
    const d = res.diff;
    assert.equal(d.details.sandboxed, true, 'must have run in the sandbox child process');
    assert.equal(d.proofType, 'rce');
    assert.equal(d.isCandidate, true);
    assert.equal(d.reproducible, true);
    assert.ok(d.newSinkAccesses.some(s => s.sink === 'eval'), 'the eval sink must have fired');
    assert.ok(d.details.forcedGatesFired.includes('debug'), 'the debug gate must have opened');
  });

  test('the gated gadget survives independent reproduction (2/2 fresh procs) with a PoC', async () => {
    const repro = await reproduceRce(FIX('gated-gadget'), 'render',
      { property: 'command', gates: ['debug'] }, { version: '1.0.0' });
    assert.equal(repro.verified, true);
    assert.equal(repro.runs, 2);
    assert.ok(repro.gates.includes('debug'));
    // PoC uses bracket notation so any gate/property name is valid JS
    // (e.g. Object.prototype["debug"] = true). Accept either notation.
    assert.match(repro.standalonePoC, /Object\.prototype(?:\.debug|\["debug"\]) = true/);
    assert.match(repro.standalonePoC, /render\(/);
  });

  test('zero-FP: a benign target never reproduces even with a forced gate', async () => {
    const repro = await reproduceRce(FIX('benign'), 'greet', { property: 'command', gates: ['debug'] }, {});
    assert.equal(repro.verified, false);
  });
});

describe('sandboxed multi-property + UOP discovery worker modes', () => {
  test('multi_property mode co-pollutes and reaches a gate-guarded sink', async () => {
    // Two properties, neither of which alone opens the sink: `debug` is the gate,
    // `command` is the payload. Co-polluting both fires eval.
    const result = await executeInSandbox(FIX('gated-gadget'), 'render', [{}], {
      timeoutMs: 3000,
      blockNetwork: true,
      mode: 'multi_property',
      pollution: { descriptors: [
        { property: 'debug', value: true },
        { property: 'command', value: 'globalThis.__x=1' },
      ] },
    });
    assert.ok(result.newSinkAccesses?.some(s => s.sink === 'eval'), 'eval must fire under co-pollution');
    assert.equal(result.pollutionWasRead, true);
    assert.ok(result.firedProperties.includes('command'));
  });

  test('discover_uop mode returns properties the target reads as undefined', async () => {
    const result = await executeInSandbox(FIX('rce-gadget'), 'render', [{}], {
      timeoutMs: 3000,
      blockNetwork: true,
      mode: 'discover_uop',
    });
    assert.ok(Array.isArray(result.uopProperties));
    assert.ok(result.uopProperties.includes('command'), 'render reads opts.command → a UOP candidate');
  });
});
