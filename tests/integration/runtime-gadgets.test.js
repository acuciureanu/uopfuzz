import { test, describe } from 'node:test';
import assert from 'node:assert';

import { RUNTIME_GADGETS } from '../../benchmark/runtime-gadgets/corpus.js';
import { classify, isExpected, probeRepro, probeDifferential, probeDos, probeMulti } from '../../benchmark/runtime-gadgets/run.js';

// Fast representative subset of the runtime-gadget benchmark — the full corpus
// (node benchmark/runtime-gadgets/run.js) forks ~50 fresh processes and belongs
// in the benchmark workflow, not the test suite. These entries cover each
// oracle: repro (sink recorder), differential, and the DoS exit-code oracle.
const byId = (id) => {
  const e = RUNTIME_GADGETS.find(g => g.id === id);
  assert.ok(e, `corpus entry ${id} exists`);
  return e;
};

describe('runtime-gadget corpus — classifier', () => {
  test('a live gadget with no observation is a capability gap', () => {
    assert.equal(classify({ id: 'x' }, { detected: false }), 'NOT-DETECTED');
    assert.equal(isExpected({ id: 'x' }, 'NOT-DETECTED'), false);
  });

  test('a documented fix below the running Node classifies as FIXED-UPSTREAM', () => {
    assert.equal(classify({ id: 'x', fixedIn: '18.19.0' }, { detected: false }), 'FIXED-UPSTREAM');
    assert.equal(isExpected({ id: 'x', fixedIn: '18.19.0' }, 'FIXED-UPSTREAM'), true);
  });

  test('a mitigated entry with no observation classifies as MITIGATED-UPSTREAM', () => {
    assert.equal(classify({ id: 'x', mitigated: 'verified dead' }, { detected: false }), 'MITIGATED-UPSTREAM');
    assert.equal(isExpected({ id: 'x', mitigated: 'verified dead' }, 'MITIGATED-UPSTREAM'), true);
  });

  test('corpus integrity: every entry has the fields its oracle needs', () => {
    for (const e of RUNTIME_GADGETS) {
      assert.ok(e.id && e.api && e.category, `${e.id}: base fields`);
      assert.ok(e.property || e.properties, `${e.id}: property or properties`);
      if (e.via === 'dos') assert.ok(e.dosDriver && e.value, `${e.id}: dos fields`);
      else if (e.via === 'behavioral') assert.ok(e.bhvProbe && e.value, `${e.id}: behavioral fields`);
      else assert.ok(e.entryPoint, `${e.id}: entryPoint`);
      if (e.via === 'repro' || e.via === 'multi') assert.ok('expectSink' in e, `${e.id}: expectSink`);
      if (e.via === 'multi') assert.ok(Array.isArray(e.properties) && e.properties.length > 1, `${e.id}: multi needs 2+ properties`);
    }
  });
});

describe('runtime-gadget corpus — oracles (Node ' + process.versions.node + ')', () => {
  test('cp-exec-env: polluted NODE_OPTIONS reaches child_process.exec (2x fresh processes)', async () => {
    const obs = await probeRepro(byId('cp-exec-env'));
    assert.equal(obs.detected, true, obs.detail);
    assert.equal(classify(byId('cp-exec-env'), obs), 'DETECTED');
  });

  test('worker-ctor-eval: polluted eval reaches the Worker constructor', async () => {
    const obs = await probeRepro(byId('worker-ctor-eval'));
    assert.equal(obs.detected, true, obs.detail);
  });

  test('fetch-body: polluted body observably changes fetch behavior', async () => {
    const obs = await probeDifferential(byId('fetch-body'));
    assert.equal(obs.detected, true, obs.detail);
  });

  test('fetch-socketPath: GHunter socketPath SSRF is dead on this Node (mitigated)', async () => {
    const obs = await probeDifferential(byId('fetch-socketPath'));
    assert.equal(obs.detected, false, 'socketPath must NOT be observable on Node >= 24');
    assert.equal(classify(byId('fetch-socketPath'), obs), 'MITIGATED-UPSTREAM');
  });

  test('dos-fetch-signal: polluted signal kills the process, clean run exits 0', async () => {
    const obs = await probeDos(byId('dos-fetch-signal'));
    assert.equal(obs.detected, true, obs.detail);
    assert.match(obs.detail, /clean exit 0, polluted exit [^0]/);
  });

  test('dos-stream-hwm: polluted highWaterMark kills the process, clean run exits 0', async () => {
    const obs = await probeDos(byId('dos-stream-hwm'));
    assert.equal(obs.detected, true, obs.detail);
  });

  test('cp-spawn-shell-env-combo: shell+NODE_OPTIONS land in spawn args together', async () => {
    const obs = await probeMulti(byId('cp-spawn-shell-env-combo'));
    assert.equal(obs.detected, true, obs.detail);
  });
});
