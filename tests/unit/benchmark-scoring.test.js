import { test, describe } from 'node:test';
import assert from 'node:assert';

import {
  deriveProofType,
  summarizeRun,
  scoreRows,
  runSelfTest,
} from '../../benchmark/run-benchmark.js';

/**
 * The benchmark's scoring is the part that decides PASS/FAIL and the process
 * exit code, so CI's verdict rides on it. These tests validate it offline —
 * no npm install, no orchestrator — exactly the build-only guarantee.
 */

describe('deriveProofType', () => {
  test('honours an explicit proofType', () => {
    assert.equal(deriveProofType({ proofType: 'pp' }), 'pp');
    assert.equal(deriveProofType({ proofType: 'rce' }), 'rce');
  });
  test('infers rce from a code-execution proof, else pp', () => {
    assert.equal(deriveProofType({ proof: { type: 'code-execution' } }), 'rce');
    assert.equal(deriveProofType({ proof: { type: 'prototype-mutation' } }), 'pp');
    assert.equal(deriveProofType({}), 'pp');
  });
});

describe('summarizeRun', () => {
  test('counts confirmed chains and those matching the expected proof type', () => {
    const results = { confirmedChains: [
      { proofType: 'pp' },
      { proof: { type: 'code-execution' } },
      { proofType: 'pp' },
    ] };
    const s = summarizeRun(results, 'pp');
    assert.equal(s.confirmed, 3);
    assert.equal(s.matched, 2);
  });
  test('null/absent results = no confirmations', () => {
    assert.deepEqual(summarizeRun(null, 'pp'), { confirmed: 0, matched: 0 });
    assert.deepEqual(summarizeRun({}, 'pp'), { confirmed: 0, matched: 0 });
  });
});

describe('scoreRows', () => {
  const clean = (detected, flagged) => ({
    vuln: { error: null, detected },
    patched: { error: null, flagged },
  });

  test('a perfect corpus passes at 100% TP / 0% FP', () => {
    const s = scoreRows([clean(true, false), clean(true, false)]);
    assert.equal(s.tp, 2); assert.equal(s.fp, 0);
    assert.equal(s.tpRate, 1); assert.equal(s.fpRate, 0);
    assert.equal(s.pass, true);
  });

  test('a missed vuln drops TP-rate below threshold → fail', () => {
    const s = scoreRows([clean(true, false), clean(false, false)]);
    assert.equal(s.tp, 1); assert.equal(s.fn, 1);
    assert.equal(s.tpRate, 0.5);
    assert.equal(s.meetsTp, false);
    assert.equal(s.pass, false);
  });

  test('a flagged patched version is a false positive → fail', () => {
    const s = scoreRows([clean(true, false), clean(true, true)]);
    assert.equal(s.fp, 1);
    assert.equal(s.fpRate, 0.5);
    assert.equal(s.meetsFp, false);
    assert.equal(s.pass, false);
  });

  test('an inconclusive row (error) fails the benchmark even if rates look fine', () => {
    const rows = [
      clean(true, false),
      { vuln: { error: 'install failed', detected: false }, patched: { error: null, flagged: false } },
    ];
    const s = scoreRows(rows);
    assert.equal(s.inconclusive, 1);
    assert.equal(s.tpRate, 1, 'the one evaluable vuln row is a TP');
    assert.equal(s.pass, false, 'inconclusive rows must block a pass');
  });

  test('custom thresholds are honoured', () => {
    const rows = [clean(true, false), clean(false, false)]; // 50% TP
    assert.equal(scoreRows(rows, { minTruePositiveRate: 0.5, maxFalsePositiveRate: 0.1 }).pass, true);
    assert.equal(scoreRows(rows, { minTruePositiveRate: 0.9, maxFalsePositiveRate: 0.1 }).pass, false);
  });
});

describe('runSelfTest', () => {
  test('passes: the scorer classifies the synthetic corpus exactly as expected', () => {
    const { ok, mismatches } = runSelfTest();
    assert.equal(ok, true, `self-test mismatches: ${mismatches.join('; ')}`);
  });
});
