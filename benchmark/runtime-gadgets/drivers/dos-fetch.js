// DoS driver: fetch with a polluted `signal` (string instead of AbortSignal).
// undici's add-abort-signal throws ERR_INVALID_ARG_TYPE from an async context —
// uncatchable by user code, so the process dies (exit 1). Loopback port 9 with
// no listener: a clean run rejects the fetch and exits 0. Fatal-only under
// pollution = GHunter §4.3 unexpected termination.
fetch('http://127.0.0.1:9/').then(
  () => process.exit(0),
  () => process.exit(0),
);
require('node:timers').setTimeout(() => process.exit(0), 2000).unref();
