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
    // with the DISCOVERED gadget property in the __proto__ query param and a
    // <PAYLOAD> placeholder — no hardcoded/invented exploit string.
    assert.match(r.standalonePoC, /https:\/\/TARGET\/\?__proto__\[scriptSrc\]=<PAYLOAD>/);
    assert.match(r.standalonePoC, /constructor\[prototype\]\[scriptSrc\]=<PAYLOAD>/);
    assert.doesNotMatch(r.standalonePoC, /alert\(|attacker\.example|onerror=/,
      'the PoC must not contain a hardcoded exploit payload');
  });

  test('gadget-only library: URL chain is NOT verified, PoC says a source is required', async () => {
    const r = await reproduceRce(FIX('client-script-src-gadget'), 'loadWidget',
      { property: 'scriptSrc' },
      { browserEnv: true, blockNetwork: true });
    assert.equal(r.verified, true);
    assert.equal(r.urlChain?.verified ?? false, false, 'a gadget-only lib does not parse URLs, so no chain');
    assert.match(r.standalonePoC, /client-side PP SOURCE/);
    assert.match(r.standalonePoC, /NOT[\s/]+verified/);
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

describe('self-contained client-side chain (URL parser + DOM gadget)', () => {
  test('verifies the chained URL -> pollution -> sink end-to-end via the library own parsing', async () => {
    const r = await reproduceRce(FIX('client-url-source-gadget'), 'render',
      { property: 'template' },
      { browserEnv: true, blockNetwork: true });
    assert.equal(r.verified, true, 'the DOM gadget must reproduce');
    assert.equal(r.sink, 'innerHTML');
    // The library also parses the URL, so the chain is verified — no assumed source.
    assert.equal(r.urlChain?.verified, true, 'the URL -> pollution step must be verified');
    assert.equal(r.urlChain.syntax, '__proto__[template]', 'the confirmed chained syntax is reported');
    assert.match(r.standalonePoC, /VERIFIED END-TO-END/);
    assert.match(r.standalonePoC, /https:\/\/TARGET\/\?__proto__\[template\]=<PAYLOAD>/);
    // still no invented exploit payload
    assert.doesNotMatch(r.standalonePoC, /alert\(|attacker\.example|onerror=/);
  });
});
