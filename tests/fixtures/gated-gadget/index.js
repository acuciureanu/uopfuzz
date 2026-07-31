// Hermetic fixture: a prototype-pollution -> RCE gadget behind a boolean GATE.
//
// The dangerous sink (eval of options.command) is only reachable when
// options.debug is truthy. In a clean run, and in a single-property differential
// that only pollutes `command`, the guard is closed and the sink never fires —
// the standard oracle misses it. The forced-branch technique co-pollutes the
// gate property `debug` with `true`, opening the guarded path so the sink fires.
//
// Used to prove the SANDBOXED forced-branch mode surfaces the gadget (and that
// the independent reproduction worker, which also forces gates, confirms it).

function render(opts) {
  const options = opts || {};
  if (options.debug) {            // gate — falsy unless forced open
    if (options.command) {
      // eslint-disable-next-line no-eval
      return eval(options.command); // code-execution sink
    }
  }
  return 'no-op';
}

module.exports = { render };
