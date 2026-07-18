import { test, describe, after } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Instrumentation } from '../../src/instrumentation/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

// Phase A (coverage exploration) used to run the target IN-PROCESS. For a
// browser-only package (jQuery, …) that is unsafe: a fuzzer input reaching an
// ajax-family entry point makes jsdom perform a SYNCHRONOUS XHR, which blocks
// the fuzzer's own event loop — freezing the whole run at ~0% CPU because
// neither safeExecute's timer nor the orchestrator's iteration timeout can fire
// on a frozen loop. The fix routes Phase A execution for browser-only targets
// through the sandbox pool (which has a parent-side SIGKILL watchdog), exactly
// like the differential phase already does.
describe('Phase A — browser-only targets execute in the sandbox child, not in-process', () => {
  let instr;
  after(() => { try { instr?.destroy?.(); } catch { /* best effort */ } });

  test('a browser-only + sandbox target never touches the in-process module', async () => {
    instr = new Instrumentation({ sandbox: true, blockNetwork: true, timeout: 5 });

    // Poison the in-process module: if Phase A ever runs the target in-process,
    // this throws and its message lands in the trace. The fix must route to the
    // sandbox child instead, so this is never called.
    instr.setTargetModule({
      extend: () => { throw new Error('RAN_IN_PROCESS'); },
    });

    const config = {
      name: 'fake-browser-lib',
      package: FIX('fake-browser-lib'), // absolute fixture path — loadable by the worker
      version: '1.0.0',
      browserEnv: true,                 // set at setup time when loaded via jsdom
      entryPoints: [{ name: 'extend' }],
      sinks: [],
    };

    const input = { entryPoint: 'extend', type: 'object', value: { a: 1 } };

    const traces = await instr.executeWithTracing([input], config);

    assert.equal(traces.length, 1);
    const trace = traces[0];

    // The poisoned in-process module must never be touched — the evidence would
    // surface either as a thrown error in the trace or (because safeExecute
    // swallows throws into the call result) as the call's result string.
    const errorMessages = (trace.errors || []).map(e => e.message).join(' | ');
    const call = (trace.functionCalls || []).find(c => c.function === 'extend');
    assert.ok(call, 'a functionCall for the entry point should be recorded');
    const evidence = `${errorMessages} | ${String(call.result)}`;
    assert.ok(
      !evidence.includes('RAN_IN_PROCESS'),
      `browser-only Phase A must NOT run the target in-process (got: ${evidence})`,
    );

    // The sandbox child loaded the fixture under jsdom and ran extend() there, so
    // the recorded result is the child's real output, not the in-process error.
    assert.notEqual(call.result, undefined, 'the sandboxed call should record a result');
  });

  test("a target that blocks its loop (sync-XHR analog) does NOT freeze the fuzzer's loop", async () => {
    instr = new Instrumentation({ sandbox: true, blockNetwork: true, timeout: 5 });

    const config = {
      name: 'fake-browser-lib',
      package: FIX('fake-browser-lib'),
      version: '1.0.0',
      browserEnv: true,
      entryPoints: [{ name: 'blockLoop' }],
      sinks: [],
    };
    const input = { entryPoint: 'blockLoop', type: 'object', value: {} };

    // Watchdog on the fuzzer's own loop. If Phase A ran blockLoop() in-process
    // (the bug), Atomics.wait would block THIS loop and the interval could not
    // fire during the call. Routed to the child (the fix), the fuzzer loop stays
    // free and the interval keeps ticking.
    let ticks = 0;
    const beat = setInterval(() => { ticks++; }, 100);

    try {
      const traces = await instr.executeWithTracing([input], config);
      assert.equal(traces.length, 1);
    } finally {
      clearInterval(beat);
    }

    // The blocking call takes ~3s in the child; a free fuzzer loop should have
    // ticked many times. Require a comfortable margin (well above the ~jsdom
    // cold-start + 3s window) to stay robust on slow CI.
    assert.ok(ticks >= 5, `fuzzer event loop must stay responsive during a blocking target call (ticks=${ticks})`);
  });
});
