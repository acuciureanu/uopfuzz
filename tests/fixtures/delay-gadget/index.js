// Hermetic fixture for pool-concurrency tests: a function that synchronously
// blocks its worker's event loop for ~500ms via Atomics.wait. Long enough that
// N concurrent sends will all be in-flight when the test inspects the pool; short
// enough that the test completes in well under a second per probe even when
// dispatch is sequential.
//
// The function is intentionally a Node-only no-DOM fallback to fake-browser-lib's
// `blockLoop` — using a plain Node fixture here keeps cold-start at ~50ms instead
// of the ~2s jsdom boot, so the concurrency test stays fast (~1s wall clock).

function blockMs(opts) {
  const ms = (opts && typeof opts.ms === 'number') ? opts.ms : 500;
  const sab = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(sab, 0, 0, ms);
  return 'unblocked';
}

module.exports = { blockMs };