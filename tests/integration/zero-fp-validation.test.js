import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

import { reproduceProto, reproduceRce } from '../../src/verification/reproduce.js';
import { versionInRange, classifyFinding } from '../../src/gadget-analysis/novelty.js';
import { executeDifferential, executeMergePPTest } from '../../src/instrumentation/differential.js';
import {
  loadDiscoveries,
  appendDiscovery,
  findPriorSighting,
  buildRecord,
} from '../../src/gadget-analysis/discovery-store.js';

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

  test('confirms RCE that only fires once the compile()-returned function is invoked (two-step sequence)', async () => {
    // Mirrors CVE-2022-29078 (EJS): compile() alone never executes the gadget —
    // only calling the function it returns does. A reproduction driver that
    // only ever calls the entry point once (ignoring config.sequences) can
    // never confirm this, even though the vulnerability is real.
    const sequence = {
      steps: [
        { call: 'compile', args: ['tmpl', {}] },
        { call: '__result__', args: [{ name: 'test' }] },
      ],
    };
    const r = await reproduceRce(FIX('sequence-gadget'), 'compile',
      { property: 'command', gates: [], minimalArgs: ['tmpl'], sequence });
    assert.equal(r.verified, true, 'a gadget that only executes when the compiled function is invoked must still reproduce');
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

// ─── Novelty / undocumented-vulnerability classifier (offline) ───────────────
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

  test('labels an unknown package/property as undocumented-vulnerability', () => {
    const finding = { source: { property: 'whatever' }, input: { entryPoint: 'frobnicate' } };
    const c = classifyFinding(finding, { package: 'totally-unknown-pkg', version: '9.9.9' });
    assert.equal(c.label, 'undocumented-vulnerability');
  });

  test('a PP source classifies by version, not the attacker property', () => {
    // merge-deep <3.0.3 is a documented PP source (CVE-2021-23397). The finding
    // must be known-cve regardless of which arbitrary key demonstrated it.
    const f1 = { source: { property: 'polluted' }, input: { entryPoint: 'clone' } };
    const f2 = { source: { property: 'isBuffer' }, input: { entryPoint: 'clone' } };
    const c1 = classifyFinding(f1, { package: 'merge-deep', version: '3.0.0', proofType: 'pp' });
    const c2 = classifyFinding(f2, { package: 'merge-deep', version: '3.0.0', proofType: 'pp' });
    assert.equal(c1.label, 'known-cve');
    assert.equal(c2.label, 'known-cve', 'a different attacker property must not fake an undocumented vulnerability');
    assert.equal(c1.cve, c2.cve);
  });

  test('a PP source in an unknown package is an undocumented-vulnerability', () => {
    const f = { source: { property: 'x' }, input: { entryPoint: 'merge' } };
    const c = classifyFinding(f, { package: 'nobody-knows-this', version: '1.0.0', proofType: 'pp' });
    assert.equal(c.label, 'undocumented-vulnerability');
  });

  test('flags reproduction on a patched version as regression-suspect', () => {
    const finding = { source: { property: 'polluted' }, input: { entryPoint: 'merge' } };
    const c = classifyFinding(finding, { package: 'lodash', version: '4.17.21' });
    assert.equal(c.label, 'undocumented-vulnerability');
    assert.equal(c.regressionSuspect, true);
  });
});

// ─── OSV.dev augmentation (synthetic vulns, no network) ──────────────────────
describe('novelty classifier + OSV.dev (offline, synthetic osvVulns)', () => {
  const ppOsvVuln = (introduced, fixed) => ({
    id: 'GHSA-test-pp', summary: 'Prototype Pollution in x', aliases: ['CVE-2099-0001'],
    database_specific: { cwe_ids: ['CWE-1321'] },
    affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced }, ...(fixed ? [{ fixed }] : [])] }] }],
  });
  const nonPpOsvVuln = () => ({
    id: 'GHSA-test-redos', summary: 'ReDoS in x', aliases: ['CVE-2099-9999'],
    database_specific: { cwe_ids: ['CWE-1333'] },
    affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }],
  });

  test('OSV alone labels a package absent from the static DB as known-cve', () => {
    const f = { source: { property: 'x' }, input: { entryPoint: 'merge' } };
    const c = classifyFinding(f, {
      package: 'nobody-knows-this', version: '1.0.0', proofType: 'pp',
      osvVulns: [ppOsvVuln('0', '2.0.0')],
    });
    assert.equal(c.label, 'known-cve');
    assert.equal(c.source, 'osv');
    assert.equal(c.cve, 'CVE-2099-0001');
  });

  test('OSV upgrades a regression-suspect to a clean known-cve', () => {
    // lodash@4.17.21 is out of the static DB range → normally regression-suspect.
    // OSV confirming a PP advisory covering 4.17.21 makes it a clean known-cve.
    const finding = { source: { property: 'polluted' }, input: { entryPoint: 'merge' } };
    const c = classifyFinding(finding, {
      package: 'lodash', version: '4.17.21', proofType: 'pp',
      osvVulns: [ppOsvVuln('0', '5.0.0')],
    });
    assert.equal(c.label, 'known-cve');
    assert.notEqual(c.regressionSuspect, true);
    assert.equal(c.source, 'osv');
  });

  test('a non-PP OSV advisory does NOT suppress a novel finding', () => {
    const f = { source: { property: 'x' }, input: { entryPoint: 'merge' } };
    const c = classifyFinding(f, {
      package: 'nobody-knows-this', version: '1.0.0', proofType: 'pp',
      osvVulns: [nonPpOsvVuln()],
    });
    assert.equal(c.label, 'undocumented-vulnerability', 'an unrelated CVE must not bury a genuine undocumented PP vulnerability');
    assert.ok(c.osvNote, 'but it should be noted as an FYI');
  });

  test('static+OSV agree → source static+osv, static CVE id preserved', () => {
    const f = { source: { property: 'polluted' }, input: { entryPoint: 'merge' } };
    const staticOnly = classifyFinding(f, { package: 'lodash', version: '4.17.4', proofType: 'pp' });
    const withOsv = classifyFinding(f, {
      package: 'lodash', version: '4.17.4', proofType: 'pp',
      osvVulns: [ppOsvVuln('0', '4.17.12')],
    });
    assert.equal(withOsv.label, 'known-cve');
    assert.equal(withOsv.source, 'static+osv');
    assert.equal(withOsv.cve, staticOnly.cve, 'static DB CVE id wins over OSV');
  });

  test('osvVulns:null is identical to today (fully backward compatible)', () => {
    const f = { source: { property: 'x' }, input: { entryPoint: 'merge' } };
    const a = classifyFinding(f, { package: 'nobody-knows-this', version: '1.0.0', proofType: 'pp' });
    const b = classifyFinding(f, { package: 'nobody-knows-this', version: '1.0.0', proofType: 'pp', osvVulns: null });
    assert.deepEqual(a, b);
    assert.equal(a.label, 'undocumented-vulnerability');
  });
});

// ─── Discovery store (offline, temp JSONL files) ─────────────────────────────
describe('discovery store — durable memory across runs (offline)', () => {
  // Each test gets its own temp file so no real writes hit data/.
  function tmpStore() {
    return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'uopfuzz-store-')), 'discoveries.jsonl');
  }

  test('loadDiscoveries on a missing file degrades to []', () => {
    const missing = path.join(os.tmpdir(), 'uopfuzz-definitely-missing-' + Date.now() + '.jsonl');
    assert.deepEqual(loadDiscoveries(missing), []);
  });

  test('loadDiscoveries skips malformed lines, keeping the valid subset', () => {
    const f = tmpStore();
    fs.writeFileSync(f, [
      JSON.stringify({ package: 'a', entryPoint: 'x', property: 'p', discoveredAt: '2026-01-01T00:00:00.000Z' }),
      '{ this is not json',
      JSON.stringify({ package: 'b', entryPoint: 'y', property: 'q', discoveredAt: '2026-02-01T00:00:00.000Z' }),
      '',
      '   ',
    ].join('\n'));
    const recs = loadDiscoveries(f);
    assert.equal(recs.length, 2, 'two valid records survive; malformed/blank lines skipped');
    assert.deepEqual(recs.map(r => r.package).sort(), ['a', 'b']);
  });

  test('appendDiscovery writes one JSON line and never throws on a bad path', () => {
    const f = tmpStore();
    appendDiscovery({ package: 'ejs', entryPoint: 'compile', property: 'escapeFunction', discoveredAt: '2026-07-06T12:00:00.000Z' }, f);
    appendDiscovery({ package: 'pug', entryPoint: 'compile', property: 'debug', discoveredAt: '2026-07-06T12:00:01.000Z' }, f);
    const lines = fs.readFileSync(f, 'utf8').trim().split('\n');
    assert.equal(lines.length, 2, 'each append is one line');
    assert.deepEqual(lines.map(l => JSON.parse(l).package), ['ejs', 'pug']);

    // A write to an unwritable path must be swallowed, not thrown.
    assert.doesNotThrow(() => appendDiscovery({}, '/no/such/dir-at-all/discoveries.jsonl'));
  });

  test('findPriorSighting matches package+entryPoint+property and returns the earliest', () => {
    const discoveries = [
      { package: 'ejs', entryPoint: 'compile', property: 'escapeFunction', discoveredAt: '2026-07-06T12:00:00.000Z', version: '3.1.6' },
      { package: 'ejs', entryPoint: 'compile', property: 'escapeFunction', discoveredAt: '2026-06-01T00:00:00.000Z', version: '3.1.5' }, // earlier
      { package: 'ejs', entryPoint: 'compile', property: 'other', discoveredAt: '2026-01-01T00:00:00.000Z' }, // different property
      { package: 'other', entryPoint: 'compile', property: 'escapeFunction', discoveredAt: '2026-01-01T00:00:00.000Z' }, // different package
    ];
    const earliest = findPriorSighting(discoveries, { package: 'ejs', entryPoint: 'compile', property: 'escapeFunction' });
    assert.equal(earliest?.version, '3.1.5', 'must return the earliest by discoveredAt');
    assert.equal(findPriorSighting(discoveries, { package: 'ejs', entryPoint: 'render' }), null, 'no entryPoint match');
    assert.equal(findPriorSighting([], { package: 'ejs', entryPoint: 'compile' }), null);
  });
});

// ─── Rediscovery recognition (offline, synthetic priorDiscoveries) ───────────
describe('novelty classifier + prior discoveries (offline)', () => {
  test('a first sighting with no prior record is undocumented-vulnerability', () => {
    const finding = { source: { property: 'escapeFunction' }, input: { entryPoint: 'compile' } };
    const c = classifyFinding(finding, {
      package: 'totally-unknown', version: '1.0.0', proofType: 'rce', priorDiscoveries: [],
    });
    assert.equal(c.label, 'undocumented-vulnerability');
    assert.equal(c.priorSighting, undefined);
  });

  test('a second run with a matching prior sighting is previously-discovered', () => {
    const finding = { source: { property: 'escapeFunction' }, input: { entryPoint: 'compile' } };
    const priorDiscoveries = [{
      package: 'totally-unknown', entryPoint: 'compile', property: 'escapeFunction',
      discoveredAt: '2026-06-01T00:00:00.000Z', version: '0.9.0', label: 'undocumented-vulnerability',
    }];
    const c = classifyFinding(finding, {
      package: 'totally-unknown', version: '1.0.0', proofType: 'rce', priorDiscoveries,
    });
    assert.equal(c.label, 'previously-discovered');
    assert.equal(c.priorSighting.discoveredAt, '2026-06-01T00:00:00.000Z');
    assert.equal(c.priorSighting.version, '0.9.0');
  });

  test('a PP source is matched property-agnostically across runs', () => {
    // Run 1 recorded the source via property 'polluted'; run 2 demonstrates it
    // via a different property. The bug is the function, so it must still match.
    const f = { source: { property: 'isBuffer' }, input: { entryPoint: 'merge' } };
    const priorDiscoveries = [{
      package: 'nobody-knows-this', entryPoint: 'merge', property: 'polluted',
      discoveredAt: '2026-06-01T00:00:00.000Z', version: '1.0.0',
    }];
    const c = classifyFinding(f, {
      package: 'nobody-knows-this', version: '1.0.1', proofType: 'pp', priorDiscoveries,
    });
    assert.equal(c.label, 'previously-discovered');
  });

  test('a static-DB / OSV known-cve still wins over a matching prior sighting', () => {
    // lodash@4.17.4 is a documented known-cve in the static DB; even if this
    // tool previously recorded it, the advisory precedence is unchanged.
    const finding = { source: { property: 'polluted' }, input: { entryPoint: 'merge' } };
    const priorDiscoveries = [{
      package: 'lodash', entryPoint: 'merge', property: 'polluted',
      discoveredAt: '2026-01-01T00:00:00.000Z', version: '4.17.4', label: 'undocumented-vulnerability',
    }];
    const c = classifyFinding(finding, {
      package: 'lodash', version: '4.17.4', proofType: 'rce', priorDiscoveries,
    });
    assert.equal(c.label, 'known-cve', 'a real CVE must outrank our own prior sighting');
    assert.ok(c.cve);
  });

  test('a regression-suspect is NOT relabeled as previously-discovered', () => {
    // lodash@4.17.21 is out-of-range → regression-suspect. A prior sighting for
    // the same key must not change that triage verdict.
    const finding = { source: { property: 'polluted' }, input: { entryPoint: 'merge' } };
    const priorDiscoveries = [{
      package: 'lodash', entryPoint: 'merge', property: 'polluted',
      discoveredAt: '2026-01-01T00:00:00.000Z', version: '4.17.21',
    }];
    const c = classifyFinding(finding, {
      package: 'lodash', version: '4.17.21', proofType: 'rce', priorDiscoveries,
    });
    assert.equal(c.label, 'undocumented-vulnerability');
    assert.equal(c.regressionSuspect, true);
    assert.equal(c.priorSighting, undefined);
  });

  test('priorDiscoveries omitted is fully backward compatible', () => {
    const f = { source: { property: 'x' }, input: { entryPoint: 'merge' } };
    const a = classifyFinding(f, { package: 'nobody-knows-this', version: '1.0.0', proofType: 'pp' });
    const b = classifyFinding(f, { package: 'nobody-knows-this', version: '1.0.0', proofType: 'pp', priorDiscoveries: [] });
    assert.deepEqual(a, b);
    assert.equal(a.label, 'undocumented-vulnerability');
  });

  test('buildRecord collapses the novelty verdict into a store label', () => {
    const baseChain = {
      source: { property: 'escapeFunction' }, input: { entryPoint: 'compile' },
      riskLevel: 7.5, standalonePoC: '// poc', metadata: { cvssVector: 'AV:N/AC:L' },
    };
    assert.equal(buildRecord({ ...baseChain, novelty: { label: 'known-cve' } }, { package: 'ejs', version: '3.1.6', proofType: 'rce' }).label, 'known-cve');
    assert.equal(buildRecord({ ...baseChain, novelty: { label: 'previously-discovered' } }, { package: 'ejs', version: '3.1.6', proofType: 'rce' }).label, 'previously-discovered');
    assert.equal(buildRecord({ ...baseChain, novelty: { label: 'undocumented-vulnerability', regressionSuspect: true } }, { package: 'ejs', version: '3.1.6', proofType: 'rce' }).label, 'regression-suspect');
    assert.equal(buildRecord({ ...baseChain, novelty: { label: 'undocumented-vulnerability' } }, { package: 'ejs', version: '3.1.6', proofType: 'rce' }).label, 'undocumented-vulnerability');

    const rec = buildRecord({ ...baseChain, novelty: { label: 'undocumented-vulnerability' } }, { package: 'ejs', version: '3.1.6', proofType: 'rce' });
    assert.equal(rec.package, 'ejs');
    assert.equal(rec.entryPoint, 'compile');
    assert.equal(rec.property, 'escapeFunction');
    assert.equal(rec.proofType, 'rce');
    assert.match(rec.description, /CONFIRMED CODE-EXECUTION/);
    assert.equal(rec.cvssVector, 'AV:N/AC:L');
    assert.equal(rec.riskLevel, 7.5);
    assert.ok(rec.discoveredAt);
  });

  test('end-to-end: first sighting appends a record; a second run recognizes it', () => {
    const store = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'uopfuzz-e2e-')), 'discovered-gadgets.jsonl');
    const ctx = { package: 'ghost-pkg', version: '2.0.0', proofType: 'rce' };
    const finding = { source: { property: 'sink' }, input: { entryPoint: 'render' } };

    // Run 1: no memory → first sighting.
    const c1 = classifyFinding(finding, { ...ctx, priorDiscoveries: loadDiscoveries(store) });
    assert.equal(c1.label, 'undocumented-vulnerability');
    appendDiscovery(buildRecord({ ...finding, novelty: c1, riskLevel: 8.0 }, ctx), store);

    // Run 2: the store now remembers → rediscovered.
    const c2 = classifyFinding(finding, { ...ctx, priorDiscoveries: loadDiscoveries(store) });
    assert.equal(c2.label, 'previously-discovered');
    assert.ok(c2.priorSighting.discoveredAt);
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
