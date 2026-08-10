// Hermetic fixture: identical shape to rce-gadget, but the gadget property
// `zqxkvBlorple` is deliberately absent from every static list in the tool —
// GENERIC_POLLUTION_PROPS, PAYLOADS, the known-gadget DB, and GATE_PROPERTIES
// (asserted by tests/integration/novel-property-detection.test.js). It can only
// be found by target-driven UOP discovery: observe that render() reads
// opts.zqxkvBlorple, that the read resolves to undefined, and pollute it.
// This is the executable proof that detection is not list lookup.

function render(opts) {
  const options = opts || {};
  // Falls through to Object.prototype.zqxkvBlorple when polluted.
  if (options.zqxkvBlorple) {
    // eslint-disable-next-line no-eval
    return eval(options.zqxkvBlorple); // code-execution sink
  }
  return 'no-op';
}

module.exports = { render };
