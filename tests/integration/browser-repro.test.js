import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { reproduceProto } from '../../src/verification/reproduce.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

// Phase C (the zero-false-positive reproduction gate) runs each attempt in a
// fresh Node process via repro-worker.js. That worker only knew how to
// `import()/require()` a package — it had no jsdom path — so a browser-only
// target (jQuery, Backbone, and any library that needs `window`/`document` at
// load time) could NEVER be reproduced: the module threw on load and every
// finding was filed as an unproven candidate, even when the pollution was real.
//
// The fake-browser-lib fixture throws unless a DOM exists at load time and
// exposes a prototype-pollution-vulnerable deep `extend`. Reproduction with
// browserEnv must stand up jsdom in the fresh process, load the module, and
// confirm the real pollution.
describe('Phase C — browser-only targets are reproducible with browserEnv', () => {
  test('reproduceProto confirms pollution in a jsdom-only library', async () => {
    const result = await reproduceProto(
      FIX('fake-browser-lib'),
      'extend',
      { property: 'uopReproBrowser', value: 'POLLUTED' },
      { browserEnv: true, timeoutMs: 8000, blockNetwork: true },
    );

    assert.equal(result.verified, true,
      `browser-only pollution must reproduce; got: ${JSON.stringify(result)}`);
    assert.equal(result.matchedProperty, 'uopReproBrowser');
    assert.equal(result.runs, 2, 'both independent fresh processes must agree');
  });

  test('without browserEnv the same target cannot load (proves the DOM is what mattered)', async () => {
    const result = await reproduceProto(
      FIX('fake-browser-lib'),
      'extend',
      { property: 'uopReproNoDom', value: 'POLLUTED' },
      { browserEnv: false, timeoutMs: 8000, blockNetwork: true },
    );

    assert.equal(result.verified, false,
      `without a DOM the browser-only module must fail to load; got: ${JSON.stringify(result)}`);
  });
});
