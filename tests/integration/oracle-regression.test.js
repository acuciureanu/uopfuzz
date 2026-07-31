import { test, describe } from 'node:test';
import assert from 'node:assert';
import { createRequire } from 'module';

import {
  snapshotPrototype,
  detectAndRestorePrototype,
  MONITORED_PROTOTYPES,
} from '../../src/utils/prototype-monitor.js';
import {
  executeDifferential,
  executeMergePPTest,
} from '../../src/instrumentation/differential.js';
import { benchmarkDetection, getGadgetsForPackage } from '../../src/gadget-analysis/known-gadgets.js';

/**
 * Ground-truth regression tests for the detection CORE.
 *
 * These directly exercise the differential oracle — the module the rest of the
 * suite never touched. They exist because a fatal crash once lived here and CI
 * stayed green: snapshotPrototype() read Function.prototype's poisoned
 * `caller`/`arguments` accessors, which throw under strict mode, so every
 * oracle call threw and was swallowed to null. The tool reported zero gadgets
 * against lodash — its own ground truth — and no test caught it.
 *
 * The assertions below fail loudly if that regression (or an equivalent break
 * in the core) ever returns.
 */

// ─── The exact crash regression ─────────────────────────────────────────────

describe('prototype-monitor (crash regression)', () => {
  test('snapshotPrototype does not throw on Function.prototype poisoned accessors', () => {
    // In strict mode (ES modules), reading Function.prototype.caller/arguments
    // throws. The monitor must record names without reading values.
    assert.doesNotThrow(() => {
      const snap = snapshotPrototype();
      assert.ok(snap.has('Function.caller'), 'must snapshot Function.prototype keys');
      assert.ok(snap.has('Object.hasOwnProperty'), 'must snapshot Object.prototype keys');
    });
  });

  test('detects and restores pollution on Object.prototype', () => {
    const snap = snapshotPrototype();
    Object.prototype.__uopfuzz_regression_marker = 'x';
    const detection = detectAndRestorePrototype(snap);
    assert.equal(detection.polluted, true);
    assert.ok(detection.newProps.some(p => p.includes('__uopfuzz_regression_marker')));
    // restore must have removed it
    assert.equal(
      Object.prototype.hasOwnProperty('__uopfuzz_regression_marker'),
      false,
      'detect must delete the polluted property',
    );
  });

  test('monitors all four attack-relevant prototypes (GHunter)', () => {
    const names = MONITORED_PROTOTYPES.map(p => p.name);
    assert.deepEqual(names, ['Object', 'Function', 'Array', 'String']);
  });
});

// ─── PP source detection (in-process, hermetic) ─────────────────────────────

/**
 * Faithful reproduction of the canonical vulnerable recursive deep-merge
 * (lodash.merge / jQuery.extend family). JSON.parse creates a real own
 * `__proto__` property, which for-in visits, driving the merge into
 * Object.prototype — exactly the CVE-2018-3721 pattern.
 */
function vulnerableMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      vulnerableMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

/** A merge that guards against __proto__ — must NOT be flagged as a source. */
function safeMerge(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

describe('PP source detection (executeMergePPTest)', () => {
  test('confirms a vulnerable deep merge as a pollution source', async () => {
    const result = await executeMergePPTest(vulnerableMerge, [{}], 'polluted', true);
    assert.ok(result, 'must return a confirmation, not null');
    assert.equal(result.diff.isConfirmedGadget, true);
    assert.equal(result.diff.prototypePolluted, true);
    // and it must have cleaned up after itself
    assert.equal(Object.prototype.hasOwnProperty('polluted'), false);
  });

  test('does not flag a __proto__-guarded merge', async () => {
    const result = await executeMergePPTest(safeMerge, [{}], 'polluted', true);
    assert.equal(result, null, 'a guarded merge must not be reported as a source');
  });
});

// ─── Gadget detection (executeDifferential) ─────────────────────────────────

describe('gadget detection (executeDifferential)', () => {
  test('flags a real read-to-sink gadget as a reproduction candidate', async () => {
    // Reads options.command off the prototype chain and changes output.
    // ZERO-FP contract: the discovery oracle NO LONGER "confirms" a behavioral
    // gadget on its own (that was the Tier-3/4/5 false-positive class). It marks
    // it a reproduction candidate ('rce'); only independent reproduction confirms.
    const gadget = (opts) => {
      const cmd = opts.command;
      return cmd ? `RUN:${cmd}` : 'noop';
    };
    const { diff } = await executeDifferential(gadget, [{}], { property: 'command', value: 'id' });
    assert.equal(diff.isConfirmedGadget, false, 'behavioral gadget must NOT be confirmed by discovery alone');
    assert.equal(diff.isCandidate, true, 'it must be a reproduction candidate');
    assert.equal(diff.proofType, 'rce');
    assert.equal(diff.reproducible, true);
    assert.equal(diff.pollutionWasRead, true);
  });

  test('does not flag a function that ignores the polluted property', async () => {
    // Never reads `command`; output is invariant under pollution.
    const benign = (opts) => opts.name || 'anon';
    const { diff } = await executeDifferential(benign, [{}], { property: 'command', value: 'id' });
    assert.equal(diff.isConfirmedGadget, false);
    assert.equal(diff.isCandidate, false);
    assert.equal(diff.pollutionWasRead, false);
  });

  test('leaves Object.prototype clean after a differential run', async () => {
    const snap = snapshotPrototype();
    const gadget = (opts) => opts.template || 'x';
    await executeDifferential(gadget, [{}], { property: 'template', value: 'PAYLOAD' });
    const { polluted } = detectAndRestorePrototype(snap);
    assert.equal(polluted, false, 'oracle must not leak pollution between runs');
  });
});

// ─── Detection-rate benchmark scorer (benchmarkDetection) ───────────────────

/**
 * `benchmarkDetection` is the ground-truth detection-rate scorer. It was defined
 * "for benchmark scoring" but never asserted anywhere — so a regression that made
 * it silently report success (or stop matching real detections) would not fail
 * the suite. These tests give it teeth: they bind an actual oracle confirmation
 * to the scorer and assert the rate reflects reality.
 */
describe('detection-rate benchmark (benchmarkDetection)', () => {
  test('counts a real confirmed PP source as detected against ground truth', async () => {
    // Confirm the canonical vulnerable merge via the real oracle, then feed a
    // confirmedChain shaped exactly as the orchestrator builds it into the
    // benchmark scorer for a package whose known gadget uses that property.
    const result = await executeMergePPTest(vulnerableMerge, [{}], 'polluted', true);
    assert.ok(result?.diff?.prototypePolluted, 'precondition: oracle confirmed the PP source');

    const confirmedChains = [{ source: { property: 'polluted' } }];
    const bench = benchmarkDetection(confirmedChains, 'lodash');
    assert.ok(bench.detectionRate > 0, 'a matching confirmed chain must raise the detection rate');
    assert.ok(
      bench.detected.some(g => (g.property || g.payload?.property) === 'polluted'),
      'the polluted-property gadget must be listed as detected',
    );
  });

  test('reports zero detection when nothing is confirmed for a known-vulnerable package', () => {
    // The exact shape of the past silent failure: a package with known gadgets,
    // but the tool confirmed nothing. The scorer must report 0, not a vacuous 1.
    assert.ok(getGadgetsForPackage('lodash').length > 0, 'precondition: lodash has known gadgets');
    const bench = benchmarkDetection([], 'lodash');
    assert.equal(bench.detectionRate, 0, 'no confirmations against a known-vulnerable package = 0% detection');
    assert.ok(bench.missed.length > 0, 'the known gadgets must be listed as missed');
  });

  test('an unknown package has nothing to miss (rate 1.0 by definition)', () => {
    const bench = benchmarkDetection([], '__no_such_package__');
    assert.equal(bench.detectionRate, 1.0);
    assert.deepEqual(bench.missed, []);
  });
});

// ─── Real-world smoke test (skipped when lodash absent) ──────────────────────

describe('real-world PP source (lodash, if available)', () => {
  const require = createRequire(import.meta.url);
  let lodash = null;
  try { lodash = require('lodash'); } catch { /* not installed */ }

  // Version-agnostic: whichever lodash is installed (the CLI mutates
  // node_modules/lodash to the target version), the oracle's verdict must match
  // the library's actual behavior. Vulnerable (<4.17.5) → detected; patched →
  // silent. This asserts both the true-positive and the no-false-positive
  // direction against real ground truth.
  test('oracle verdict matches lodash.merge ground truth', { skip: !lodash ? 'lodash not installed' : false }, async () => {
    lodash.merge({}, JSON.parse('{"__proto__":{"__uopfuzz_gt":1}}'));
    const trulyVulnerable = Object.prototype.hasOwnProperty('__uopfuzz_gt');
    delete Object.prototype.__uopfuzz_gt;

    const result = await executeMergePPTest(lodash.merge, [{}], 'polluted', true);
    assert.equal(
      !!result, trulyVulnerable,
      `oracle verdict (${!!result}) must match ground truth (${trulyVulnerable}) for lodash ${lodash.VERSION}`,
    );
    if (result) {
      assert.equal(result.diff.prototypePolluted, true);
      assert.equal(Object.prototype.hasOwnProperty('polluted'), false);
    }
  });
});
