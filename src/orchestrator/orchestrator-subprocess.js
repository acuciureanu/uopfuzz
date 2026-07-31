/**
 * Child-process worker that runs ONE target's full Orchestrator in isolation.
 *
 * Mass and version sweeps fork this per target so that an uncaught crash or a
 * hang while fuzzing one library cannot kill the whole sweep. This matters most
 * for browser-only packages (jQuery, Backbone, …) which run IN-PROCESS via jsdom
 * rather than in the discovery sandbox: their fuzzed Object.prototype pollution
 * can leak into Node's own internals (e.g. undici's HTTP parser reading a
 * polluted `timeout` off the prototype chain) and throw in a timer/immediate
 * callback — an uncaught exception that would otherwise take the fuzzer down.
 *
 * Communication is over child_process IPC (default JSON serialization), so the
 * `results` object crosses the boundary already JSON-shaped — the same shape
 * saveResults() persists. The parent (mass-runner.js) treats a non-zero exit or
 * a missing reply as a contained per-target failure and moves on.
 */
import { Orchestrator } from './index.js';

// Report an uncaught failure with a reason, then exit non-zero so the parent
// records the failure. We deliberately let the process die here rather than
// swallow the error — isolation is the point.
function die(reason) {
  try { process.send?.({ type: 'error', error: reason }); } catch { /* IPC gone */ }
  process.exit(1);
}

process.on('uncaughtException', (err) => die(`uncaught: ${err?.message || err}`));
process.on('unhandledRejection', (err) => die(`unhandledRejection: ${err?.message || err}`));

process.on('message', async (msg) => {
  if (!msg || msg.type !== 'run') return;
  let exitCode = 0;
  try {
    const orchestrator = new Orchestrator(msg.options);
    const results = await orchestrator.run();
    process.send?.({ type: 'success', results });
  } catch (error) {
    exitCode = 1;
    process.send?.({ type: 'error', error: error.message });
  } finally {
    // Flush IPC on the next tick, then exit so a lingering timer/handle left by
    // target code cannot keep this child alive.
    setImmediate(() => process.exit(exitCode));
  }
});
