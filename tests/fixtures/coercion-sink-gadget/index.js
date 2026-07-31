// Hermetic fixture: a function that EXPLICITLY reads the toString property
// value (not via engine coercion) and feeds the result to a code-execution
// sink. Even though `toString` is an engine-coercion property name, this IS a
// real gadget: the attacker-controlled value flows to eval.
//
// Setting `Object.prototype.toString = <string>` breaks V8's ToString protocol
// (a non-callable toString is skipped, not invoked), so engine coercion cannot
// propagate a sink-token string. The only way a coercion property's VALUE
// reaches a sink is when the target reads it explicitly. This fixture models
// that pattern.

function render(opts) {
  // Explicit read of opts.toString's value (not an invocation), then eval.
  // eslint-disable-next-line no-eval
  return eval(opts.toString);
}

module.exports = { render };
