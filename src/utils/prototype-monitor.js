/**
 * Shared prototype-pollution monitor.
 *
 * Single source of truth for which prototypes UoPFuzz watches and how it
 * snapshots, detects, and restores pollution. Imported by BOTH execution
 * paths — the in-process oracle (instrumentation/differential.js) and the
 * sandbox child process (utils/sandbox-worker.js) — so the two cannot drift.
 *
 * Monitors Object, Function, Array, and String prototypes: GHunter (USENIX
 * Security 2024) showed pollution of Function/Array/String.prototype is a
 * real attack vector (e.g. polluting Array.prototype.join with a callable),
 * not just Object.prototype.
 */

export const MONITORED_PROTOTYPES = [
  { name: 'Object', proto: Object.prototype },
  { name: 'Function', proto: Function.prototype },
  { name: 'Array', proto: Array.prototype },
  { name: 'String', proto: String.prototype },
];

/**
 * Snapshot the own-property NAMES of every monitored prototype.
 *
 * Records key presence only — it never reads a property's *value*. Reading
 * values would touch Function.prototype's poisoned `caller`/`arguments`/
 * `callee` accessors, which throw under strict mode (and ES modules are
 * always strict). That read previously crashed the entire differential
 * oracle on its first call. Pollution detection needs names, not values.
 *
 * @returns {Set<string>} keys of the form "Object.hasOwnProperty"
 */
export function snapshotPrototype() {
  const snap = new Set();
  for (const { name, proto } of MONITORED_PROTOTYPES) {
    for (const key of Object.getOwnPropertyNames(proto)) {
      snap.add(`${name}.${key}`);
    }
  }
  return snap;
}

/**
 * Detect and remove any properties added to a monitored prototype since the
 * snapshot, restoring a clean baseline for the next run.
 *
 * @param {Set<string>} snapshot - result of snapshotPrototype()
 * @returns {{ polluted: boolean, newProps: string[] }} newProps are qualified
 *   names like "Object.prototype.isAdmin"
 */
export function detectAndRestorePrototype(snapshot) {
  let polluted = false;
  const newProps = [];

  for (const { name, proto } of MONITORED_PROTOTYPES) {
    for (const key of Object.getOwnPropertyNames(proto)) {
      if (!snapshot.has(`${name}.${key}`)) {
        polluted = true;
        newProps.push(`${name}.prototype.${key}`);
        try { delete proto[key]; } catch { /* sealed */ }
      }
    }
  }

  return { polluted, newProps };
}
