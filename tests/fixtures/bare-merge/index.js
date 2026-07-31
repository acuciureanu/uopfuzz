// Hermetic fixture: a bare-function-export module (module.exports = fn),
// mirroring real packages like extend-deep@0.1.6 where the whole module IS
// the merge function rather than a named method on it. Auto-discovery names
// a bare-function entry point after the package itself
// (src/target-integration/discovery.js:270-272), so entryPoint === package
// name in this case — used to verify the standalone PoC generator calls
// target(...) directly instead of the invalid target.<entryPoint>(...).

module.exports = function merge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key] || typeof target[key] !== 'object') target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
};
