// Hermetic fixture: a function that reads an option off the prototype chain and
// feeds it to a code-execution sink (eval). With Object.prototype.command
// polluted, calling render({}) executes attacker-controlled code — a real
// prototype-pollution → RCE gadget. Used to prove the reproduction harness
// confirms code execution via the canary.

function render(opts) {
  const options = opts || {};
  // Reads `command` — falls through to Object.prototype.command when polluted.
  if (options.command) {
    // eslint-disable-next-line no-eval
    return eval(options.command); // code-execution sink
  }
  return 'no-op';
}

module.exports = { render };
