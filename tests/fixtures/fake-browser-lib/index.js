// Hermetic stand-in for a browser-only library (jQuery-style): it requires a DOM
// at load time and exposes a prototype-pollution-vulnerable deep `extend`. Used
// to prove the sandbox worker's jsdom environment (browserEnv) lets browser-only
// packages load AND be analyzed in the isolated child — and that without a DOM
// the module refuses to load at all.
if (typeof window === 'undefined' || typeof document === 'undefined') {
  throw new Error('window is not defined — this library requires a DOM environment');
}

function extend(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      extend(target[key], source[key]); // recurses into __proto__ → pollutes
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

module.exports = { extend };
