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
  const results = [];
  for (let run = 0; run < REQUIRED_AGREEING_RUNS; run++) {
    const r = await executeInSandbox(packageName, entryPoint, [{}], {
      timeoutMs,
      blockNetwork: opts.blockNetwork !== false,
      workerScript: REPRO_WORKER,
      mode: 'repro_pp',
      extra: { property: descriptor.property, value: descriptor.value, nonce: run },
    }).catch(err => ({ verified: false, error: err.message }));
    results.push(r);
    if (!r?.verified) break; // fail fast — no point running the second fork
  }

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
 * @param {{ property: string, gates?: string[], minimalArgs?: any[] }} spec
 * @param {object} [opts]
 * @returns {Promise<{ verified: boolean, payloadType?: string, canary?: string, gates?: string[], runs: number, standalonePoC?: string }>}
 */
export async function reproduceRce(packageName, entryPoint, spec, opts = {}) {
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const minimalArgs = Array.isArray(spec.minimalArgs) && spec.minimalArgs.length ? spec.minimalArgs : [{}];
  const results = [];
  for (let run = 0; run < REQUIRED_AGREEING_RUNS; run++) {
    const r = await executeInSandbox(packageName, entryPoint, minimalArgs, {
      timeoutMs,
      blockNetwork: opts.blockNetwork !== false,
      workerScript: REPRO_WORKER,
      mode: 'repro_rce',
      extra: { property: spec.property, gates: spec.gates || [], nonce: run },
    }).catch(err => ({ verified: false, error: err.message }));
    results.push(r);
    if (!r?.verified) break;
  }

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
function buildProtoPoC(pkg, version, entryPoint, descriptor, res) {
  const spec = version ? `${pkg}@${version}` : pkg;
  const valJson = JSON.stringify(descriptor.value);
  const conv = res.callConvention || 'fn({}, payload)';
  const call = conv.startsWith("fn({}, '")
    ? `target.${entryPoint}({}, '__proto__.${descriptor.property}', ${valJson});`
    : conv === 'fn(true, {}, payload)'
      ? `target.${entryPoint}(true, {}, payload);`
      : conv === 'fn(payload)'
        ? `target.${entryPoint}(payload);`
        : `target.${entryPoint}({}, payload);`;
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
  return `// PoC — prototype pollution -> code execution in ${specStr} via ${entryPoint}()
// Reproduced independently in ${res.runs || 2} fresh Node processes (canary fired).
const target = require('${pkg}');
${gateLines ? gateLines + '\n' : ''}// attacker-controlled payload on the polluted property (${res.payloadType})
Object.prototype.${spec.property} = "<attacker code>";
target.${entryPoint}(/* attacker-influenced input */);
// The polluted property reaches a code-execution sink and runs attacker code.`;
}
