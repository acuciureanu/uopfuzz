// Hermetic fixture: a prototype-pollution -> RCE gadget behind a boolean gate
// whose name is NOT in the static GATE_PROPERTIES list. The dangerous sink
// (eval of options.command) is only reachable when `options.enableFeatureX` is
// truthy. `enableFeatureX` is a plausible runtime option name but not the kind
// of generic name (debug, verbose, strict, ...) the static 18-name list covers.
//
// KNOWN LIMITATION: the static all-gates forced-branch differential forces only
// GATE_PROPERTIES, so it does not open `enableFeatureX` and discovery alone does
// not surface this gadget autonomously. The REPRODUCTION gate, however, already
// forces an arbitrary caller-supplied gate set (reproduceRce's `gates`), so once
// the gate name is known the gadget reproduces and confirms — which the test for
// this fixture asserts. Feeding UOP-discovered property names into the
// forced-branch gate candidates (so discovery finds gates like this on its own)
// is a worthwhile future enhancement, not yet implemented.

function render(opts) {
  const options = opts || {};
  if (options.enableFeatureX) {       // gate NOT in GATE_PROPERTIES
    if (options.command) {
      // eslint-disable-next-line no-eval
      return eval(options.command);   // code-execution sink
    }
  }
  return 'no-op';
}

module.exports = { render };
