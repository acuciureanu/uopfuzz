import { test, describe } from 'node:test';
import assert from 'node:assert';

import { mineClass, differentialProbe } from '../../src/runtime-miner/mine.js';

// Small-scope end-to-end run of the miner: one real API class, including the
// properties the committed corpus already covers, so the test doubles as a
// rediscovery gate (the miner must independently re-derive known gadgets).
describe('runtime gadget miner — stream.Readable scope (Node ' + process.versions.node + ')', () => {
  let findings;
  test('mines the class without error', async () => {
    const r = await mineClass('stream.Readable', { includeKnown: true });
    findings = new Map(r.findings.map(f => [f.property, f]));
    assert.ok(findings.size > 0, 'some candidates are non-inert');
  });

  test('rediscovers the highWaterMark gadget (LIVE or DoS)', () => {
    const f = findings.get('highWaterMark');
    assert.ok(f, 'highWaterMark is a finding');
    assert.ok(f.verdict === 'LIVE' || f.verdict === 'DoS', `verdict ${f.verdict}`);
  });

  test('rediscovers the signal crash (DoS — fatal on the stock runtime)', () => {
    const f = findings.get('signal');
    assert.ok(f, 'signal is a finding');
    assert.ok(f.verdict === 'LIVE' || f.verdict === 'DoS', `verdict ${f.verdict}`);
  });

  test('false-positive guard: a property the runtime never reads is INERT', async () => {
    const r = await differentialProbe('probeStreamReadable', 'uopfuzz_inert_sentinel_xyz');
    assert.equal(r.verdict, 'INERT', `sentinel verdict ${r.verdict} (${r.detail})`);
  });

  test('no finding rests on sink recording alone (every finding has an oracle detail)', () => {
    for (const [, f] of findings) {
      assert.ok(f.detail && f.detail.length > 0, `${f.property} has evidence`);
      assert.ok(['LIVE', 'DoS', 'READ-ONLY'].includes(f.verdict), `${f.property} verdict known`);
    }
  });
});
