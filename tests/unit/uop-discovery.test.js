import { test, describe } from 'node:test';
import assert from 'node:assert';

import { discoverTarget } from '../../src/target-integration/discovery.js';

// Phase 2 — agnostic candidate discovery. The properties the differential oracle
// pollutes are meant to be TARGET-DRIVEN: taint discovery observes which keys the
// library reads off the prototype chain (resolve to undefined) and pollutes
// exactly those, instead of relying on a ~230-name static vocabulary. That signal
// was starved — only the first 10 exports were probed, and only with
// template-shaped inputs — so a real config property was invisible unless it
// happened to be on the static list.
describe('taint UOP discovery is target-driven and broad', () => {
  test('discovers a config property read via an object-first argument', async () => {
    // Reads arg0.uopUnlisted — needs an OBJECT as the first argument to observe,
    // which the template-only probe shapes never supplied.
    const mod = {
      configure(opts) { return opts && opts.uopUnlisted ? 'on' : 'off'; },
    };
    const cfg = await discoverTarget(mod, 'obj-arg-lib', '1.0.0', {});
    assert.ok(
      cfg.pollutionPoints.includes('uopUnlisted'),
      `object-first UOP read must be discovered; got: ${cfg.pollutionPoints.join(', ')}`,
    );
  });

  test('does not surface coercion-artifact keys like "[object Object]"', async () => {
    // A library that indexes by a non-string key produces a stringified property
    // read ("[object Object]"). That is harness noise, never a real gadget key.
    const mod = {
      lookup(opts) {
        const table = {};
        const key = opts && opts.which ? opts.which : {};
        return table[key]; // table[{}] → reads "[object Object]"
      },
    };
    const cfg = await discoverTarget(mod, 'coercion-lib', '1.0.0', {});
    assert.ok(
      !cfg.pollutionPoints.some((p) => /\[object |\s/.test(p)),
      `coercion-artifact keys must be filtered; got: ${cfg.pollutionPoints.join(', ')}`,
    );
  });

  test('probes exports beyond the first handful', async () => {
    const mod = {};
    for (let i = 0; i < 14; i++) mod[`pad${String(i).padStart(2, '0')}`] = () => 'x';
    // The interesting reader is the 15th export — past the old slice(0, 10).
    mod.lateReader = (opts) => (opts && opts.uopLateProp ? 'hit' : 'miss');

    const cfg = await discoverTarget(mod, 'late-lib', '1.0.0', {});
    assert.ok(
      cfg.pollutionPoints.includes('uopLateProp'),
      `a UOP read on a later export must be discovered; got: ${cfg.pollutionPoints.join(', ')}`,
    );
  });
});
