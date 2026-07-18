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

// Synchronously blocks the event loop of whatever process runs it — a hermetic
// stand-in for jsdom's synchronous XHR (`$.ajax({async:false})`), which is what
// froze the fuzzer when browser libs ran in-process. When executed in the
// sandbox child (the fix), only the child's loop blocks; the fuzzer's stays free
// and the pool's SIGKILL watchdog can rescue the child.
function blockLoop() {
  const sab = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(sab, 0, 0, 3000); // block ~3s, then return normally
  return 'unblocked';
}

module.exports = { extend, blockLoop };
