// Hermetic fixture mirroring EJS's compile()/invoke split (CVE-2022-29078):
// compile() only builds a function — it never calls the polluted `command`
// option itself. The option only fires when the RETURNED function is
// subsequently invoked with locals. A reproduction harness that calls
// compile() once and stops (never invoking the result) will never observe
// the canary, even though the gadget is real and calling the returned
// function does trigger it.

function compile(template, opts) {
  const options = opts || {};
  return function render(locals) {
    if (typeof options.command === 'function') options.command();
    return `rendered:${template}:${JSON.stringify(locals)}`;
  };
}

module.exports = { compile };
