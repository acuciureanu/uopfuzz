// Hermetic fixture: the conventional NAMES are all safe, and the real
// prototype-pollution gadget hides under a name no heuristic list contains.
//
// Two failure modes this pins down:
//  1. Ranking entry points by a hardcoded vocabulary ('merge', 'extend', …)
//     puts the three harmless decoys first and never reaches applyPatch.
//  2. Giving up on a descriptor after N consecutive entry points that produced
//     no finding — the decoys are callable and CLEAN, which must not be
//     mistaken for "un-callable" and abort the scan before applyPatch.

function merge(t, s) { return { ...t, ...JSON.parse(JSON.stringify(s || {})) }; } // safe
function extend(t, s) { return Object.assign({}, t, s); }                         // safe (shallow)
function clone(o) { return JSON.parse(JSON.stringify(o || {})); }                 // safe
function defaults(t, s) { return Object.assign({}, s, t); }                       // safe (shallow)

// The real vulnerability: recursive merge with no __proto__ guard.
function applyPatch(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      applyPatch(target[key], source[key]); // recurses into __proto__ → pollutes
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = { merge, extend, clone, defaults, applyPatch };
