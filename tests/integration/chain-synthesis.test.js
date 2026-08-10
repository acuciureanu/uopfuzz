import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { reproduceChain } from '../../src/verification/reproduce.js';
import { REFERENCE_SOURCE } from '../../src/verification/source-registry.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

// A proven PP source described the way the registry stores it. vuln-merge is a
// recursive deep-merge with no __proto__ guard (module.exports = { merge }).
const VULN_MERGE_SOURCE = {
  package: FIX('vuln-merge'),
  entryPoint: 'merge',
  callConvention: 'fn(target, payload)',
  payloadKind: 'proto-json',
};
// safe-merge guards __proto__/constructor — it cannot pollute, so it must never
// yield a verified chain.
const SAFE_MERGE_SOURCE = { ...VULN_MERGE_SOURCE, package: FIX('safe-merge') };

describe('reproduceChain — end-to-end source → gadget → sink', () => {
  test('a real source + an eval gadget reproduces a verified code-execution chain', async () => {
    // rce-gadget: render(opts) eval()s opts.command, which falls through to a
    // polluted Object.prototype.command.
    const r = await reproduceChain(FIX('rce-gadget'), 'render', { property: 'command' }, VULN_MERGE_SOURCE);
    assert.equal(r.verified, true, 'chain reproduced');
    assert.equal(r.payloadType, 'eval_string');
    assert.equal(r.sink, 'code-execution', 'proven sink is code execution (RCE)');
    assert.equal(r.runs, 2, 'reproduced in two fresh processes');
    // The PoC is a REAL end-to-end exploit: it require()s the source and calls it
    // with attacker JSON, then require()s and calls the gadget — no faked
    // Object.prototype[...] = write.
    assert.match(r.standalonePoC, /END-TO-END/);
    assert.match(r.standalonePoC, /const source = require\(/);
    assert.match(r.standalonePoC, /JSON\.parse/);
    assert.doesNotMatch(r.standalonePoC, /Object\.prototype\[.*\] = "<attacker code>"/,
      'the pollution is driven by the source, not a direct write');
  });

  test('a command-injection gadget reproduces a sink-reachability chain', async () => {
    // cmd-gadget: run(opts) passes opts.cmd to execSync (blocked in the worker);
    // the proof is that the polluted value REACHED the command sink.
    const r = await reproduceChain(FIX('cmd-gadget'), 'run', { property: 'cmd' }, VULN_MERGE_SOURCE);
    assert.equal(r.verified, true);
    assert.equal(r.payloadType, 'sink_reach');
    assert.match(r.sink, /^child_process\./, 'proven sink names the command-exec sink (→ command injection)');
  });

  test('a __proto__-guarded source yields NO chain (the source cannot pollute)', async () => {
    const r = await reproduceChain(FIX('rce-gadget'), 'render', { property: 'command' }, SAFE_MERGE_SOURCE);
    assert.equal(r.verified, false, 'a safe source must never produce a verified chain');
  });

  test('a benign gadget yields NO chain even with a real source', async () => {
    // rce-gadget.render has a no-op path when the property is absent; point the
    // chain at a property the gadget never reads → nothing fires.
    const r = await reproduceChain(FIX('rce-gadget'), 'render', { property: 'nonexistent_prop_xyz' }, VULN_MERGE_SOURCE);
    assert.equal(r.verified, false);
  });

  test('REFERENCE_SOURCE (the orchestrator default) reproduces the same chain offline', async () => {
    const r = await reproduceChain(FIX('rce-gadget'), 'render', { property: 'command' }, REFERENCE_SOURCE);
    assert.equal(r.verified, true);
    // Fixture-reproduced PoC names the class of real-world sources honestly.
    assert.match(r.standalonePoC, /equivalent real-world source/i);
  });
});
