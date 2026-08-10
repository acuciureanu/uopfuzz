import { test, describe } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { getKnownProperties } from '../../src/gadget-analysis/known-gadgets.js';
import { GATE_PROPERTIES } from '../../src/instrumentation/gate-properties.js';
import { Instrumentation } from '../../src/instrumentation/index.js';
import { reproduceRce } from '../../src/verification/reproduce.js';
import { executeInSandbox } from '../../src/utils/sandbox.js';

/**
 * Credibility proof: detection is not list lookup.
 *
 * The gadget property `zqxkvBlorple` is in NO static list — not the fuzzer's
 * seed dictionary (GENERIC_POLLUTION_PROPS / PAYLOADS), not the known-gadget
 * CVE DB, not the gate list. The only way the pipeline can find it is the
 * target-driven mechanism: taint observation of which absent properties the
 * library reads (discover_uop), differential confirmation, and the
 * reproduction gate. Each stage is asserted below.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);
const NOVEL = 'zqxkvBlorple';

describe('novel-property gadget: no static list knows it', () => {
  test('the property is absent from every hardcoded list', () => {
    // GENERIC_POLLUTION_PROPS and PAYLOADS are module-private; the seed
    // dictionary can only contain the name if it appears in the source text.
    const seedSource = fs.readFileSync(
      path.resolve(__dirname, '..', '..', 'src', 'input-generation', 'index.js'), 'utf8');
    assert.ok(!seedSource.includes(NOVEL), 'seed dictionary must not contain the novel property');
    assert.ok(!getKnownProperties().includes(NOVEL), 'known-gadget DB must not contain it');
    assert.ok(!GATE_PROPERTIES.includes(NOVEL), 'gate list must not contain it');
  });

  test('discover_uop finds it from target behaviour, sandboxed', async () => {
    const result = await executeInSandbox(FIX('novel-prop-gadget'), 'render', [{}], {
      timeoutMs: 3000,
      blockNetwork: true,
      mode: 'discover_uop',
    });
    assert.ok(result.uopProperties.includes(NOVEL),
      `UOP discovery must observe the read of ${NOVEL}; got: ${(result.uopProperties || []).join(', ')}`);
  });

  test('the differential oracle detects the gadget once the property is polluted', async () => {
    const inst = new Instrumentation({ sandbox: true, blockNetwork: true });
    const res = await inst.executeDifferentialTracing(
      { type: 'value', value: {}, entryPoint: 'render' },
      { package: FIX('novel-prop-gadget') },
      { property: NOVEL, value: 'globalThis.__x=1' },
    );
    assert.ok(res?.diff, 'differential run must surface the gadget');
    assert.ok(res.diff.newSinkAccesses.some(s => s.sink === 'eval'), 'the eval sink must have fired');
  });

  test('the reproduction gate confirms it in 2 fresh processes with a PoC', async () => {
    const repro = await reproduceRce(FIX('novel-prop-gadget'), 'render',
      { property: NOVEL }, { blockNetwork: true });
    assert.equal(repro.verified, true, 'a gadget no list knows must still reproduce');
    assert.equal(repro.runs, 2);
    assert.ok(repro.standalonePoC.includes(NOVEL), 'the PoC names the discovered property');
  });
});
