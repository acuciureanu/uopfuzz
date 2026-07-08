// Hermetic fixture: a function that never reads attacker-influenced properties
// off the prototype chain and never reaches a sink. The reproduction harness
// must NOT confirm anything here (no-false-positive direction).

function greet(opts) {
  const name = (opts && Object.prototype.hasOwnProperty.call(opts, 'name')) ? opts.name : 'anon';
  return `hello ${name}`;
}

module.exports = { greet };
