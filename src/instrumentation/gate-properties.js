/**
 * Boolean "gate" property names co-polluted during forced-branch execution.
 *
 * Many gadgets are guarded by a boolean check the attacker does not directly
 * control, e.g. `if (opts.debug) { eval(opts.template); }`. Normal differential
 * testing never reaches the sink because the gate is falsy in a clean run.
 * Forcing these gates to `true` alongside the payload opens the guarded path.
 * (Dasty, KTH WWW 2024, found 67 additional exploitable packages this way.)
 *
 * This list is the SINGLE SOURCE OF TRUTH shared by the in-process oracle
 * (differential.js) and the sandboxed oracle (sandbox-worker.js) so the two can
 * never disagree on which branches they force open (invariant #4).
 */
export const GATE_PROPERTIES = [
  'debug', 'compileDebug', 'verbose', 'cache', 'client', 'strict',
  'self', 'async', 'raw', 'unsafe', 'dev', 'development', 'production',
  'allowDots', 'allowPrototypes', 'pretty', 'rmWhitespace',
];
