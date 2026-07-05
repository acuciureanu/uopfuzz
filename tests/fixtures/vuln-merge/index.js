// Hermetic fixture: a recursive deep-merge that is vulnerable to prototype
// pollution (no __proto__ guard). Used by the zero-FP validation harness to
// prove the reproduction harness confirms a REAL pollution source.

function merge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]); // recurses into __proto__ → pollutes
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = { merge };
