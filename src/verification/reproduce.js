import { executeInSandbox } from '../utils/sandbox.js';
import { logger } from '../utils/logger.js';

/**
 * Independent reproduction driver — the zero-false-positive gate.
 *
 * A proposed finding becomes a reported vulnerability only if this driver
 * reproduces its ground-truth condition in TWO independent fresh Node processes
 * (both must agree). The reproduction worker (../utils/repro-worker.js) shares no
 * verdict logic with the discovery oracle, and each attempt runs in its own
 * process, so there is no shared mutable state and no observer effect that could
 * manufacture a false confirmation.
 *
 * Two proof kinds:
 *   reproduceProto → real prototype pollution (own-property added, named exactly
 *                    like the attacker-supplied property).
 *   reproduceRce   → real code execution (a canary token reaches globalThis).
 */

const REPRO_WORKER = 'repro-worker.js';
const DEFAULT_TIMEOUT_MS = 2000;
const REQUIRED_AGREEING_RUNS = 2;

/**
 * @param {string} packageName - installable/require-able package (or absolute path for fixtures)
 * @param {string} entryPoint  - function path, e.g. 'merge' or 'utils.extend'
 * @param {{ property: string, value: any }} descriptor
 * @param {object} [opts] - { timeoutMs, blockNetwork, version }
 * @returns {Promise<{ verified: boolean, newProps?: string[], matchedProperty?: string, callConvention?: string, runs: number, standalonePoC?: string }>}
 */
export async function reproduceProto(packageName, entryPoint, descriptor, opts = {}) {
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  // Run both agreeing forks concurrently. They are fully independent fresh
  // processes (no shared state), so overlapping them halves per-confirmation
  // latency; the verdict is unchanged — BOTH must still verify. We forgo the
  // sequential fail-fast (a false lead now pays for two forks instead of one),
  // a good trade since confirmations are rare and the common path here is the
  // positive one, where fail-fast never fired anyway.
  const results = await Promise.all(
    Array.from({ length: REQUIRED_AGREEING_RUNS }, (_, run) =>
      executeInSandbox(packageName, entryPoint, [{}], {
        timeoutMs,
        blockNetwork: opts.blockNetwork !== false,
        browserEnv: opts.browserEnv === true,
        workerScript: REPRO_WORKER,
        mode: 'repro_pp',
        extra: { property: descriptor.property, value: descriptor.value, nonce: run },
      }).catch(err => ({ verified: false, error: err.message }))
    )
  );

  const verified = results.length === REQUIRED_AGREEING_RUNS && results.every(r => r?.verified);
  if (!verified) {
    return { verified: false, runs: results.length };
  }
  const first = results[0];
  return {
    verified: true,
    newProps: first.newProps,
    matchedProperty: first.matchedProperty,
    callConvention: first.callConvention,
    runs: REQUIRED_AGREEING_RUNS,
    standalonePoC: buildProtoPoC(packageName, opts.version, entryPoint, descriptor, first),
  };
}

/**
 * @param {string} packageName
 * @param {string} entryPoint
 * @param {{ property: string, gates?: string[], minimalArgs?: any[], sequence?: { steps: Array<{ call: string, method?: string, args?: any[] }> } }} spec
 *   `sequence`, when present, mirrors a config.sequences entry with each step's
 *   args already resolved to plain values (e.g. `compile()` followed by
 *   invoking its returned function — CVE-2022-29078-style gadgets only fire on
 *   the second call, never on the entry point alone).
 * @param {object} [opts]
 * @returns {Promise<{ verified: boolean, payloadType?: string, canary?: string, gates?: string[], runs: number, standalonePoC?: string }>}
 */
export async function reproduceRce(packageName, entryPoint, spec, opts = {}) {
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const minimalArgs = Array.isArray(spec.minimalArgs) && spec.minimalArgs.length ? spec.minimalArgs : [{}];
  // Both agreeing forks run concurrently — see reproduceProto for the rationale.
  // Verdict is unchanged: both independent fresh processes must verify.
  const results = await Promise.all(
    Array.from({ length: REQUIRED_AGREEING_RUNS }, (_, run) =>
      executeInSandbox(packageName, entryPoint, minimalArgs, {
        timeoutMs,
        blockNetwork: opts.blockNetwork !== false,
        browserEnv: opts.browserEnv === true,
        workerScript: REPRO_WORKER,
        mode: 'repro_rce',
        extra: { property: spec.property, gates: spec.gates || [], sequence: spec.sequence || null, nonce: run },
      }).catch(err => ({ verified: false, error: err.message }))
    )
  );

  const verified = results.length === REQUIRED_AGREEING_RUNS && results.every(r => r?.verified);
  if (!verified) return { verified: false, runs: results.length };
  const first = results[0];
  return {
    verified: true,
    payloadType: first.payloadType,
    canary: first.canary,
    gates: first.gates || spec.gates || [],
    runs: REQUIRED_AGREEING_RUNS,
    standalonePoC: buildRcePoC(packageName, opts.version, entryPoint, spec, first),
  };
}

// ─── Standalone PoC builders (exact minimal reproduction) ────────────────────

/**
 * Render how to invoke `entryPoint` on the `target` require()'d in the PoC.
 * Three cases:
 *   - entryPoint IS the package name (bare-function module, e.g. `module.exports
 *     = fn` for merge-deep/deep-extend) → call `target` directly, never
 *     `target.<hyphenated-name>(...)`, which would be invalid JS.
 *   - entryPoint is a dotted path of valid identifiers (e.g. 'utils.extend') →
 *     plain dot notation.
 *   - anything else (unusual/non-identifier property names) → bracket notation,
 *     which is safe for any string.
 */
function targetRef(pkg, entryPoint) {
  if (entryPoint === pkg) return 'target';
  const segments = String(entryPoint).split('.');
  const validIdent = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
  if (segments.every(s => validIdent.test(s))) return `target.${entryPoint}`;
  return `target${segments.map(s => `[${JSON.stringify(s)}]`).join('')}`;
}

function buildProtoPoC(pkg, version, entryPoint, descriptor, res) {
  const spec = version ? `${pkg}@${version}` : pkg;
  const valJson = JSON.stringify(descriptor.value);
  const conv = res.callConvention || 'fn({}, payload)';
  const ref = targetRef(pkg, entryPoint);
  const call = conv.startsWith("fn({}, '")
    ? `${ref}({}, '__proto__.${descriptor.property}', ${valJson});`
    : conv === 'fn(true, {}, payload)'
      ? `${ref}(true, {}, payload);`
      : conv === 'fn(payload)'
        ? `${ref}(payload);`
        : `${ref}({}, payload);`;
  return `// PoC — prototype pollution in ${spec} via ${entryPoint}()
// Reproduced independently in ${res.runs || 2} fresh Node processes.
const target = require('${pkg}');
const payload = JSON.parse('{"__proto__":{"${descriptor.property}":${valJson}}}');
${call}
console.log(({}).${descriptor.property}); // => ${valJson}  (Object.prototype polluted)`;
}

function buildRcePoC(pkg, version, entryPoint, spec, res) {
  const specStr = version ? `${pkg}@${version}` : pkg;
  const gateLines = (res.gates || []).map(g => `Object.prototype.${g} = true; // force guarded branch`).join('\n');
  const ref = targetRef(pkg, entryPoint);
  return `// PoC — prototype pollution -> code execution in ${specStr} via ${entryPoint}()
// Reproduced independently in ${res.runs || 2} fresh Node processes (canary fired).
const target = require('${pkg}');
${gateLines ? gateLines + '\n' : ''}// attacker-controlled payload on the polluted property (${res.payloadType})
Object.prototype.${spec.property} = "<attacker code>";
${ref}(/* attacker-influenced input */);
// The polluted property reaches a code-execution sink and runs attacker code.`;
}
