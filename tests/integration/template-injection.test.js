import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { reproduceRce } from '../../src/verification/reproduce.js';

/**
 * Template-compilation injection (EJS CVE-2022-29078 / pug / hogan class): the
 * polluted value is spliced into GENERATED function source at a declaration
 * position, so the generic `globalThis[x]=y` canary is a syntax error there.
 * The reproduction gate's `template_injection` payload handles it. This guards
 * that path hermetically (no network / real EJS needed).
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

describe('template-compilation injection (reproduction gate)', () => {
  test('confirms RCE via the template_injection payload', async () => {
    const r = await reproduceRce(FIX('template-injection-gadget'), 'render',
      { property: 'outputFunctionName', minimalArgs: ['<p>hi</p>', {}] },
      { blockNetwork: true });
    assert.equal(r.verified, true, 'the template-injection gadget must reproduce');
    assert.equal(r.payloadType, 'template_injection');
    assert.ok(r.standalonePoC, 'a standalone PoC must be produced');
  });

  test('a benign template engine does not reproduce', async () => {
    // 'greet' does not exist on the benign fixture → no sink, no confirmation.
    const r = await reproduceRce(FIX('benign'), 'greet',
      { property: 'outputFunctionName', minimalArgs: ['<p>hi</p>', {}] },
      { blockNetwork: true });
    assert.equal(r.verified, false);
  });
});
