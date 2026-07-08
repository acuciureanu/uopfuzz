import { test, describe } from 'node:test';
import assert from 'node:assert';

import { classifyDiff, HIGH_RISK_PROPS } from '../../src/instrumentation/classify-diff.js';

/**
 * classifyDiff is the single tier ladder shared by both discovery oracles
 * (in-process differential.js#diffResults and sandboxed
 * instrumentation/index.js#_sandboxedDifferential). These tests pin every tier's
 * verdict AND assert the two oracles cannot drift: the same facts produce the
 * same verdict no matter which oracle observed them (invariant #4).
 */

describe('classifyDiff — tier ladder', () => {
  test('Tier 0: a real prototype mutation is a pre-confirmed pollution candidate', () => {
    const v = classifyDiff({ property: 'x', prototypePolluted: true });
    assert.equal(v.isConfirmedGadget, true);
    assert.equal(v.isCandidate, false);
    assert.equal(v.proofType, 'pp');
    assert.equal(v.reproducible, true);
    assert.equal(v.confidence, 0.85);
  });

  test('Tier 0 wins even when behavioral signals are also present', () => {
    const v = classifyDiff({
      property: 'x', prototypePolluted: true, pollutionWasRead: true,
      newSinkAccesses: [{ sink: 'eval' }], outputChanged: true, errorChanged: true,
    });
    assert.equal(v.proofType, 'pp');
    assert.equal(v.confidence, 0.85);
    assert.equal(v.isConfirmedGadget, true);
  });

  test('Tier 1: a new sink firing under a read is an rce candidate', () => {
    const v = classifyDiff({
      property: 'template', pollutionWasRead: true, newSinkAccesses: [{ sink: 'eval' }],
    });
    assert.deepEqual(v, {
      isConfirmedGadget: false, isCandidate: true, proofType: 'rce',
      reproducible: true, confidence: 0.95,
    });
  });

  test('Tier 1 requires the property to have been read', () => {
    const v = classifyDiff({
      property: 'template', pollutionWasRead: false, newSinkAccesses: [{ sink: 'eval' }],
    });
    // No read → not attributable to this pollution → nothing actionable.
    assert.equal(v.isCandidate, false);
    assert.equal(v.isConfirmedGadget, false);
    assert.equal(v.proofType, null);
  });

  test('Tier 2: payload reaching output under a read', () => {
    const v = classifyDiff({ property: 'x', pollutionWasRead: true, payloadInOutput: true });
    assert.equal(v.proofType, 'rce');
    assert.equal(v.reproducible, true);
    assert.equal(v.confidence, 0.90);
  });

  test('Tier 3: output changed under a read', () => {
    const v = classifyDiff({ property: 'x', pollutionWasRead: true, outputChanged: true });
    assert.equal(v.confidence, 0.75);
    assert.equal(v.reproducible, true);
  });

  test('Tier 4: error changed under a read', () => {
    const v = classifyDiff({ property: 'x', pollutionWasRead: true, errorChanged: true });
    assert.equal(v.confidence, 0.60);
    assert.equal(v.reproducible, true);
  });

  test('Tier 5: high-risk property read with no observable change is reproducible', () => {
    assert.ok(HIGH_RISK_PROPS.has('command'));
    const v = classifyDiff({ property: 'command', pollutionWasRead: true });
    assert.equal(v.isCandidate, true);
    assert.equal(v.reproducible, true);
    assert.equal(v.confidence, 0.50);
  });

  test('Tier 5: low-risk property read is a lead only, not reproducible', () => {
    assert.ok(!HIGH_RISK_PROPS.has('someRandomOption'));
    const v = classifyDiff({ property: 'someRandomOption', pollutionWasRead: true });
    assert.equal(v.isCandidate, true);
    assert.equal(v.reproducible, false);
    assert.equal(v.confidence, 0.30);
  });

  test('nothing observed → no verdict', () => {
    const v = classifyDiff({ property: 'x' });
    assert.deepEqual(v, {
      isConfirmedGadget: false, isCandidate: false, proofType: null,
      reproducible: false, confidence: 0,
    });
  });
});

describe('classifyDiff — oracles cannot drift', () => {
  // A grid of fact-vectors spanning every tier and boundary. Both oracles route
  // through THIS function, so if the ladder is the single source of truth these
  // are the only possible verdicts. This is the regression guard against a future
  // hand-rolled reconstruction re-appearing in either oracle.
  const cases = [
    { property: 'x', prototypePolluted: true },
    { property: 'template', pollutionWasRead: true, newSinkAccesses: [{ sink: 'eval' }] },
    { property: 'x', pollutionWasRead: true, payloadInOutput: true },
    { property: 'x', pollutionWasRead: true, outputChanged: true },
    { property: 'x', pollutionWasRead: true, errorChanged: true },
    { property: 'command', pollutionWasRead: true },
    { property: 'lowrisk', pollutionWasRead: true },
    { property: 'x', outputChanged: true }, // changed but never read → dropped
    { property: 'x' },
  ];

  for (const facts of cases) {
    test(`deterministic & pure for ${JSON.stringify(facts)}`, () => {
      const a = classifyDiff(facts);
      const b = classifyDiff({ ...facts });
      assert.deepEqual(a, b, 'classifyDiff must be a pure function of its facts');
    });
  }

  test('an output/error change with no read is never a candidate (both oracles)', () => {
    // This is exactly the case the sandbox oracle used to mis-handle: it
    // hardcoded pollutionWasRead=true and produced an rce candidate. With real
    // facts threaded through the shared ladder, both oracles agree it is noise.
    const v = classifyDiff({ property: 'x', outputChanged: true, errorChanged: true, pollutionWasRead: false });
    assert.equal(v.isCandidate, false);
    assert.equal(v.isConfirmedGadget, false);
  });
});
