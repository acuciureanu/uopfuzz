import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { reproduceRce } from '../../src/verification/reproduce.js';

/**
 * Reproduction-gate behaviour for the gate/coercion fixture family. These
 * fixtures previously shipped with no test referencing them (and two described a
 * per-gate probe the pipeline never implemented). Each test below pins the
 * DETERMINISTIC reproduction verdict — the actual zero-false-positive gate —
 * against the fixture's real behaviour.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

describe('coercion FP vs real coercion sink (reproduction gate)', () => {
  test('engine coercion of a polluted toString is NOT confirmed (no sink reached)', async () => {
    // render() only does `${opts}`; the coercion result never reaches a sink. The
    // function_call payload (a real callable) is skipped by design, and the
    // string payloads never execute through a non-callable toString — so the gate
    // must reject. This is the withdrawn pug@latest/toString false positive.
    const r = await reproduceRce(FIX('coercion-fp-gadget'), 'render',
      { property: 'toString' },
      { blockNetwork: true });
    assert.equal(r.verified, false, 'coercion-only, sinkless gadget must NOT confirm');
  });

  test('an explicit eval(opts.toString) IS confirmed via eval_string', async () => {
    const r = await reproduceRce(FIX('coercion-sink-gadget'), 'render',
      { property: 'toString' },
      { blockNetwork: true });
    assert.equal(r.verified, true, 'explicit read of the polluted value into eval is a real gadget');
    assert.equal(r.payloadType, 'eval_string', 'the fired proof is real string execution');
  });
});

describe('gated RCE gadgets (reproduction gate)', () => {
  test('multi-gate gadget confirms only when BOTH gates are forced', async () => {
    const withGates = await reproduceRce(FIX('multi-gate-gadget'), 'render',
      { property: 'command', gates: ['debug', 'verbose'] },
      { blockNetwork: true });
    assert.equal(withGates.verified, true, 'both gates forced → sink reached');
    assert.deepEqual(withGates.gates, ['debug', 'verbose']);

    const noGates = await reproduceRce(FIX('multi-gate-gadget'), 'render',
      { property: 'command', gates: [] },
      { blockNetwork: true });
    assert.equal(noGates.verified, false, 'without the gates the guarded sink is unreachable');
  });

  test('ungated-list gadget reproduces once its non-standard gate is supplied', async () => {
    // Documents the known limitation: `enableFeatureX` is not in GATE_PROPERTIES,
    // so static discovery does not open it — but the reproduction gate forces an
    // arbitrary caller-supplied gate set, so the gadget is provably real.
    const r = await reproduceRce(FIX('ungated-list-gadget'), 'render',
      { property: 'command', gates: ['enableFeatureX'] },
      { blockNetwork: true });
    assert.equal(r.verified, true, 'forcing the discovered gate reaches the sink');
  });
});
