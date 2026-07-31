// Hermetic fixture: a prototype-pollution -> RCE gadget behind TWO boolean
// gates. The dangerous sink (eval of options.command) is only reachable when
// BOTH `options.debug` AND `options.verbose` are truthy. Both gate names are in
// GATE_PROPERTIES, so the all-gates forced-branch differential opens the path,
// and reproduction confirms it by forcing both gates alongside the command
// payload (see reproduceRce's `gates`). No single gate alone reaches the sink.

function render(opts) {
  const options = opts || {};
  if (options.debug && options.verbose) {    // two independent gates
    if (options.command) {
      // eslint-disable-next-line no-eval
      return eval(options.command);           // code-execution sink
    }
  }
  return 'no-op';
}

module.exports = { render };
