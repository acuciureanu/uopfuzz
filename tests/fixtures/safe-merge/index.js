// Hermetic fixture: a deep-merge that guards against __proto__/constructor keys.
// Used by the zero-FP validation harness to prove the reproduction harness does
// NOT confirm a safe merge (the no-false-positive direction).

const FORBIDDEN = new Set(['__proto__', 'prototype', 'constructor']);

function merge(target, source) {
  for (const key in source) {
    if (FORBIDDEN.has(key)) continue; // guard — no pollution possible
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = { merge };
