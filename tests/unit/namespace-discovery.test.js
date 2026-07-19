import { test, describe } from 'node:test';
import assert from 'node:assert';

import { discoverTarget } from '../../src/target-integration/discovery.js';

// Regression for a real-world miss: @feathersjs/commons (and lodash, underscore,
// and every library following that convention) exports its entire public API
// under a namespace object literally named `_`. Discovery's private-member
// filter skipped any export whose name starts with `_`, which is meant to hide
// internal helpers like `_privateHelper` — but a bare `_` is a PUBLIC namespace,
// not a private member. Skipping it discarded `_.merge`, the one function that
// carries CVE-2026-54335, before it was ever probed.
//
// The convention here is general: descend into a namespace object regardless of
// whether its container name looks private; keep filtering genuinely-private
// leaf members inside it. No package name or method name is hardcoded.
describe('discovery descends into underscore-named public namespaces', () => {
  test('finds a merge function exported under a `_` namespace', async () => {
    // Lodash/underscore/feathers-commons shape: public utilities under `_`.
    const mod = {
      _: {
        merge(target, source) { return Object.assign(target, source); },
        extend(target, source) { return Object.assign(target, source); },
      },
      stripSlashes(s) { return s; },
    };

    const config = await discoverTarget(mod, 'ns-lib', '1.0.0', {});
    const names = config.entryPoints.map((ep) => ep.name);

    const mergeEp = names.find((n) => n === '_.merge' || n.split('.').pop() === 'merge');
    assert.ok(
      mergeEp,
      `expected a merge entry point under the _ namespace; got: ${names.join(', ')}`,
    );
  });

  test('still skips genuinely-private leaf members (_internalHelper)', async () => {
    const mod = {
      publicFn(x) { return x; },
      _internalHelper(x) { return x; }, // conventionally private — should stay skipped
    };

    const config = await discoverTarget(mod, 'priv-lib', '1.0.0', {});
    const names = config.entryPoints.map((ep) => ep.name);

    assert.ok(names.includes('publicFn'), `public fn should be discovered; got: ${names.join(', ')}`);
    assert.ok(
      !names.some((n) => n.split('.').pop() === '_internalHelper'),
      `private _-prefixed leaf must stay skipped; got: ${names.join(', ')}`,
    );
  });
});
