// DoS harness — runs a dos-driver in a PLAIN child process (stock runtime, no
// hardening), exactly like GHunter's unexpected-termination stage (§4.3): the
// drivers are our own corpus code (loopback-only, ephemeral ports), so no
// capability blocks are needed. The runner compares exit codes clean vs
// polluted; a polluted-only non-zero exit is the DoS signal.
//
// Exit codes: 0 = completed, 3 = watchdog (hang/timeout), anything else = crash.
const prop = process.env.UOPF_DOS_PROP;
if (prop) {
  // Typed pollution values: env vars are strings, so the runner passes a type
  // hint and the value is re-materialized here (number/boolean/JSON).
  const raw = process.env.UOPF_DOS_VALUE;
  const type = process.env.UOPF_DOS_TYPE || 'string';
  let value = raw;
  if (type === 'number') value = Number(raw);
  else if (type === 'boolean') value = raw === 'true';
  else if (type === 'json') { try { value = JSON.parse(raw); } catch { value = raw; } }
  Object.prototype[prop] = value;
}

const { setTimeout: realSetTimeout } = require('node:timers');
// Watchdog: fires only if the driver keeps the event loop alive (hang). Unref'd
// so a driver that completes cleanly exits 0 on loop drain.
realSetTimeout(() => process.exit(3), 5000).unref();

require(`./${process.env.UOPF_DOS_DRIVER}.js`);
