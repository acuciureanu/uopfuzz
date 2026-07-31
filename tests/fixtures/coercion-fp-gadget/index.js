// Hermetic fixture: a function that internally coerces its argument via a
// template literal. Polluting Object.prototype.toString with a Function makes
// the function_call canary fire via V8's ToString coercion — but the result of
// the coercion never reaches any code/command sink, so this is NOT a real
// RCE primitive. The reproduction gate must REJECT it.
//
// Mirrors the practical pattern behind the false-positive `pug@latest/toString`
// filing (since withdrawn): a callable canary firing through engine coercion
// alone, with no sink-reaching evidence.

function render(opts) {
  // Engine coercion: template literal invokes the inherited toString on `opts`.
  // The result is returned to the caller as a plain string; it is never eval'd,
  // never passed to new Function, never handed to child_process.
  return `rendered: ${opts}`;
}

module.exports = { render };
