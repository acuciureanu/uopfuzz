// Hermetic fixture: a function that never reads attacker-influenced properties
// off the prototype chain and never reaches a sink. The reproduction harness
// must NOT confirm anything here (no-false-positive direction).

function greet(opts) {
  const name = (opts && Object.prototype.hasOwnProperty.call(opts, 'name')) ? opts.name : 'anon';
  return `hello ${name}`;
}

// Returns a plain object and reaches no sink. Exists to pin a specific false
// positive: if the reproduction harness wraps this return value in
// Promise.resolve()/await, then polluting Object.prototype.then with a callable
// canary makes the HARNESS invoke it during thenable adoption — "code execution"
// that this function never performed.
function makeThing(opts) {
  return { ok: true, echoed: opts && opts.name };
}

module.exports = { greet, makeThing };
