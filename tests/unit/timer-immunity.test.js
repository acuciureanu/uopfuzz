import { test, describe } from 'node:test';
import assert from 'node:assert';
import { setTimeout as realSetTimeout, clearTimeout as realClearTimeout } from 'node:timers';
import { Instrumentation } from '../../src/instrumentation/index.js';

/**
 * Regression: sink tracing replaces global.setTimeout/setInterval with a stub
 * that returns the sentinel string '[SIMULATED_SINK_RESULT]' (to observe target
 * sink calls). The tool's OWN control-flow timers must not go through that stub,
 * or they capture the sentinel string and `clearTimeout(sentinel)` throws:
 *
 *   TypeError: Cannot create property '_onTimeout' on string '[SIMULATED_SINK_RESULT]'
 *
 * observed in the orchestrator's iteration timeout and in safeExecute. Both now
 * use node:timers handles, which are immune to `global.setTimeout = …`.
 */
describe('timer immunity to sink-instrumented global setTimeout', () => {
  test('node:timers handles survive global.setTimeout being stubbed to a sentinel', () => {
    const origSet = global.setTimeout;
    const origClear = global.clearTimeout;
    try {
      // Emulate setupSinkTracing swapping in a sentinel-returning stub.
      global.setTimeout = () => '[SIMULATED_SINK_RESULT]';
      const handle = realSetTimeout(() => {}, 1000);
      assert.notStrictEqual(typeof handle, 'string', 'node:timers must return a real handle, not the sentinel');
      assert.doesNotThrow(() => realClearTimeout(handle), 'clearTimeout on a real handle must not throw');
    } finally {
      global.setTimeout = origSet;
      global.clearTimeout = origClear;
    }
  });

  test('safeExecute completes and does not crash when global timers are sink stubs', async () => {
    const instr = new Instrumentation({});
    const origSet = global.setTimeout;
    const origClear = global.clearTimeout;
    try {
      // The exact failure conditions: setTimeout yields the sentinel, and any
      // clearTimeout on it throws just like Node's real clearTimeout does.
      global.setTimeout = () => '[SIMULATED_SINK_RESULT]';
      global.clearTimeout = () => { throw new TypeError("Cannot create property '_onTimeout' on string '[SIMULATED_SINK_RESULT]'"); };

      const result = await instr.safeExecute((x) => x + 1, [41]);
      assert.strictEqual(result, 42, 'safeExecute must complete despite stubbed global timers');
    } finally {
      global.setTimeout = origSet;
      global.clearTimeout = origClear;
    }
  });
});
