/**
 * Options-aware sink argument recording — GHunter-style argument traversal.
 *
 * The repro/sandbox workers used to record only a string first argument. That
 * misses the largest universal-gadget class (GHunter, USENIX '24): pollution
 * that flows through an OPTIONS OBJECT — `exec(cmd, {env})` where
 * `env.NODE_OPTIONS` falls through to a polluted prototype, `tls.connect(opts)`
 * reading `opts.rejectUnauthorized`, `http.request(opts)` reading `opts.path`.
 * Node reads those options through the prototype chain, so the recorder must do
 * the same to observe what the runtime will actually use.
 *
 * Safety contract (the recorded code runs while Object.prototype may carry
 * attacker-controlled values):
 * - Strings are recorded (truncated); non-strings are NEVER coerced — a
 *   polluted toString/valueOf must not fire during recording.
 * - Own ACCESSOR properties are never invoked (a target-defined getter could be
 *   hostile); only own DATA properties are read directly.
 * - Inherited properties ARE read — that is precisely what the runtime does —
 *   but each read is individually try/catch'd, so a throwing getter loses one
 *   value, never the worker. Our own pollution traps answer these reads, which
 *   is how the planted token gets captured.
 * - Traversal is bounded: depth ≤ 3, ≤ 50 strings per call site — a cyclic or
 *   huge object can't hang or flood the log.
 */

const MAX_DEPTH = 3;
const MAX_STRINGS = 50;
const MAX_STRING_LEN = 200;

/**
 * Collect the string values a sink could act on from an argument list.
 *
 * @param {any} value - typically the args array of a sink call
 * @param {object} [opts]
 * @param {number} [opts.maxDepth]
 * @param {number} [opts.maxStrings]
 * @returns {string[]} found strings, each truncated to 200 chars
 */
export function collectSinkStrings(value, { maxDepth = MAX_DEPTH, maxStrings = MAX_STRINGS } = {}) {
  const out = [];
  const seen = new Set();

  const push = (s) => {
    if (out.length < maxStrings) out.push(s.length > MAX_STRING_LEN ? s.slice(0, MAX_STRING_LEN) : s);
  };

  const visit = (v, depth) => {
    if (out.length >= maxStrings || depth > maxDepth) return;
    if (typeof v === 'string') { push(v); return; }
    // Only plain-ish objects are traversed. Functions are skipped entirely —
    // recursing into them would just collect `.name` strings off constructors
    // (reached via `constructor` on the prototype chain), which is pure noise.
    if (!v || typeof v !== 'object' || seen.has(v)) return;
    seen.add(v);

    // URL-ish objects: the href the sink will actually use (single guarded read).
    try {
      const href = v.href;
      if (typeof href === 'string') push(href);
    } catch { /* hostile getter — lose this value, not the worker */ }

    // Own DATA properties (never invoke an own accessor).
    let descs;
    try { descs = Object.getOwnPropertyDescriptors(v); } catch { return; }
    for (const d of Object.values(descs)) {
      if (out.length >= maxStrings) return;
      if ('value' in d) visit(d.value, depth + 1);
    }

    // Inherited reads: walk the prototype chain and read each inherited
    // property through the object, exactly as the runtime's option handling
    // would. Our pollution traps (non-enumerable accessors on Object.prototype)
    // answer these reads with the planted value.
    let proto;
    try { proto = Object.getPrototypeOf(v); } catch { proto = null; }
    while (proto && proto !== Object.prototype && out.length < maxStrings) {
      let pdescs;
      try { pdescs = Object.getOwnPropertyDescriptors(proto); } catch { break; }
      for (const key of Object.keys(pdescs)) {
        if (out.length >= maxStrings) return;
        if (key === '__proto__' || key === 'constructor' || Object.prototype.hasOwnProperty.call(v, key)) continue;
        try { visit(v[key], depth + 1); } catch { /* hostile inherited getter */ }
      }
      try { proto = Object.getPrototypeOf(proto); } catch { break; }
    }
    // Object.prototype itself: read only accessor/data props NOT already own on
    // v — this is where pollution lands. Skip functions (constructor etc.).
    if (proto === Object.prototype && out.length < maxStrings) {
      let odescs;
      try { odescs = Object.getOwnPropertyDescriptors(Object.prototype); } catch { odescs = {}; }
      for (const [key, d] of Object.entries(odescs)) {
        if (out.length >= maxStrings) return;
        if (key === '__proto__' || typeof d.value === 'function') continue;
        if (Object.prototype.hasOwnProperty.call(v, key)) continue;
        try { visit(v[key], depth + 1); } catch { /* hostile inherited getter */ }
      }
    }
  };

  visit(value, 0);
  return out;
}
