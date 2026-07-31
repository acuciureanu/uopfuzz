// Hermetic fixture mirroring EJS's compile()/invoke split (CVE-2022-29078):
// compile() only builds a function — it never touches the polluted `command`
// option itself. The option only reaches its code sink when the RETURNED
// function is subsequently invoked with locals. A reproduction harness that
// calls compile() once and stops (never invoking the result) will never
// observe the canary, even though the gadget is real and calling the returned
// function does trigger it.
//
// Like the real CVE, the polluted option is a STRING that the gadget feeds to a
// code sink (here `eval`), NOT a live function the target merely calls — a
// prototype-pollution attacker injects data via JSON, never a callable. So this
// confirms via the eval_string proof, exercising the two-step sequence replay
// without depending on the (unrealizable) function_call payload.

function compile(template, opts) {
  const options = opts || {};
  return function render(locals) {
    // Reads `command` — falls through to Object.prototype.command when polluted
    // — and evaluates it. Fires only on THIS second call, never on compile().
    // eslint-disable-next-line no-eval
    if (options.command) { eval(options.command); }
    return `rendered:${template}:${JSON.stringify(locals)}`;
  };
}

module.exports = { compile };
