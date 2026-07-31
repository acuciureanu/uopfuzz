import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { reproduceRce, reproduceProto } from '../../src/verification/reproduce.js';

/**
 * Regression test for the reproduction INTEGRITY gate (review finding C1).
 *
 * The whole zero-false-positive guarantee rests on the reproduction verdict. If
 * target code — which runs inside the reproduction worker for any real package —
 * could send its own IPC message, a malicious package would manufacture a
 * "confirmed" vulnerability by replying `{ verified: true }`.
 *
 * The forge-confirmation-gadget fixture actively attempts exactly that (see its
 * source). This test asserts both reproduction entry points still return
 * verified:false, i.e. the seal on process.send + the parent's per-fork reply
 * token hold.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.resolve(__dirname, '..', 'fixtures', 'forge-confirmation-gadget');

describe('reproduction integrity — a hostile package cannot forge a confirmation', () => {
  test('reproduceRce does not confirm a forged reply', async () => {
    const r = await reproduceRce(FIX, 'run',
      { property: 'whatever' },
      { blockNetwork: true });
    assert.equal(r.verified, false, 'a forged process.send({verified:true}) must NOT confirm RCE');
    assert.ok(!r.standalonePoC, 'no PoC should be produced for an unconfirmed finding');
  });

  test('reproduceProto does not confirm a forged reply', async () => {
    const r = await reproduceProto(FIX, 'run',
      { property: 'whatever', value: true },
      { blockNetwork: true });
    assert.equal(r.verified, false, 'a forged process.send({verified:true}) must NOT confirm pollution');
  });
});
