import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

import { reproduceProto, reproduceRce } from '../../src/verification/reproduce.js';
import { versionInRange, classifyFinding } from '../../src/gadget-analysis/novelty.js';
import { executeDifferential, executeMergePPTest } from '../../src/instrumentation/differential.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

/**
 * Zero-false-positive validation.
 *
 * The "no false positives" guarantee is expressed empirically: for every SAFE
 * fixture/package, the independent reproduction harness returns verified:false,
 * so nothing can reach confirmedChains. For every VULNERABLE one, it reproduces.
 */

// ─── Hermetic (always offline) ───────────────────────────────────────────────
describe('reproduction harness — hermetic fixtures (offline)', () => {
  test('confirms a real prototype-pollution source (vuln-merge)', async () => {
    const r = await reproduceProto(FIX('vuln-merge'), 'merge', { property: 'polluted', value: true });
    assert.equal(r.verified, true, 'a vulnerable deep-merge must reproduce as a PP source');
    assert.equal(r.runs, 2, 'must be reproduced twice in fresh processes');
    assert.ok(r.newProps?.some(p => p.endsWith('.polluted')));
    assert.match(r.standalonePoC, /prototype pollution/);
  });

  test('does NOT confirm a guarded safe merge (no false positive)', async () => {
    const r = await reproduceProto(FIX('safe-merge'), 'merge', { property: 'polluted', value: true });
    assert.equal(r.verified, false, 'a __proto__-guarded merge must never reproduce');
  });

  test('confirms real code execution via canary (rce-gadget)', async () => {
    const r = await reproduceRce(FIX('rce-gadget'), 'render', { property: 'command', gates: [], minimalArgs: [{}] });
    assert.equal(r.verified, true, 'a read-to-eval gadget must reproduce code execution');
    assert.equal(r.runs, 2);
    assert.ok(r.payloadType, 'a payload type must be recorded');
  });

  test('does NOT confirm a benign function (no false positive)', async () => {
    const r = await reproduceRce(FIX('benign'), 'greet', { property: 'command', gates: [], minimalArgs: [{}] });
    assert.equal(r.verified, false, 'a function that never reaches a sink must never reproduce');
  });
});

// ─── Discovery-oracle demotion (offline) ─────────────────────────────────────
describe('discovery oracle demotes behavioral signals (offline)', () => {
  test('output change is a candidate, never a confirmed gadget', async () => {
    const gadget = (opts) => (opts.command ? `RUN:${opts.command}` : 'noop');
    const { diff } = await executeDifferential(gadget, [{}], { property: 'command', value: 'id' });
    assert.equal(diff.isConfirmedGadget, false, 'behavioral change must not confirm');
    assert.equal(diff.isCandidate, true);
    assert.equal(diff.proofType, 'rce');
  });

  test('a real prototype mutation is a pp candidate', async () => {
    const require = createRequire(import.meta.url);
    const { merge } = require('../fixtures/vuln-merge');
    const res = await executeMergePPTest(merge, [{}], 'polluted', true);
    assert.ok(res, 'a vulnerable merge must be detected as a PP source');
    assert.equal(res.diff.proofType, 'pp');
    assert.equal(res.diff.isConfirmedGadget, true);
    assert.equal(Object.prototype.hasOwnProperty('polluted'), false, 'must not leak pollution');
  });
});

// ─── Novelty / 0-day classifier (offline) ────────────────────────────────────
describe('novelty classifier (offline)', () => {
  test('versionInRange handles the DB range forms', () => {
    assert.equal(versionInRange('4.17.4', '<4.17.5'), true);
    assert.equal(versionInRange('4.17.21', '<4.17.5'), false);
    assert.equal(versionInRange('1.2.3', '*'), true);
    assert.equal(versionInRange('5.0.0', '<=5.0.0'), true);
    assert.equal(versionInRange('4.10.0', '4.0.0..4.17.0'), true);
    assert.equal(versionInRange('4.18.0', '4.0.0..4.17.0'), false);
  });

  test('labels a known lodash CVE version as known-cve', () => {
    const finding = { source: { property: 'polluted' }, input: { entryPoint: 'merge' } };
    const c = classifyFinding(finding, { package: 'lodash', version: '4.17.4' });
    assert.equal(c.label, 'known-cve');
    assert.ok(c.cve, 'a CVE id should be attached');
  });

  test('labels an unknown package/property as novel-0day', () => {
    const finding = { source: { property: 'whatever' }, input: { entryPoint: 'frobnicate' } };
    const c = classifyFinding(finding, { package: 'totally-unknown-pkg', version: '9.9.9' });
    assert.equal(c.label, 'novel-0day');
  });

  test('flags reproduction on a patched version as regression-suspect', () => {
    const finding = { source: { property: 'polluted' }, input: { entryPoint: 'merge' } };
    const c = classifyFinding(finding, { package: 'lodash', version: '4.17.21' });
    assert.equal(c.label, 'novel-0day');
    assert.equal(c.regressionSuspect, true);
  });
});

// ─── Real-package (gated: skip when not installed) ───────────────────────────
describe('real-package reproduction (skipped when absent)', () => {
  const require = createRequire(import.meta.url);
  let lodash = null;
  try { lodash = require('lodash'); } catch { /* not installed */ }

  test('reproduction verdict matches lodash ground truth', { skip: !lodash ? 'lodash not installed' : false }, async () => {
    // Ground truth for the installed lodash version.
    lodash.merge({}, JSON.parse('{"__proto__":{"__uop_probe":1}}'));
    const trulyVulnerable = Object.prototype.hasOwnProperty('__uop_probe');
    delete Object.prototype.__uop_probe;

    const r = await reproduceProto('lodash', 'merge', { property: 'uopf_polluted', value: true });
    assert.equal(r.verified, trulyVulnerable,
      `reproduction (${r.verified}) must match ground truth (${trulyVulnerable}) for lodash ${lodash.VERSION}`);
    // No pollution may leak into this process.
    assert.equal(Object.prototype.hasOwnProperty('uopf_polluted'), false);
  });
});
