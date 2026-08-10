import { executeInSandbox } from '../utils/sandbox.js';
import { renderSourceCalls } from './source-call.js';

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
    urlChain: first.urlChain || null,
    gates,
    restriction: gates.length ? 'gated' : 'none',
    runs: REQUIRED_AGREEING_RUNS,
    standalonePoC: buildRcePoC(packageName, opts.version, entryPoint, spec, first, opts.browserEnv === true),
  };
}

/**
 * Prove a FULL end-to-end exploit: attacker-input → SOURCE → gadget → sink.
 *
 * Same 2×-agreeing-fresh-processes gate as reproduceRce, but the pollution is
 * performed by a real, proven prototype-pollution *source* (`source`, a registry
 * entry) called with attacker JSON — not faked with a direct Object.prototype
 * write. Both packages (the gadget's and the source's) must be loadable in the
 * sandbox; the caller is responsible for installing the source (or passing a
 * fixture whose `package` is an absolute path).
 *
 * @param {string} packageName - the gadget package
 * @param {string} entryPoint  - the gadget entry point
 * @param {{ property: string, gates?: string[], minimalArgs?: any[], sequence?: object }} spec
 * @param {{ package, version?, entryPoint, callConvention, payloadKind, fixture?, label? }} source
 * @param {object} [opts]
 * @returns {Promise<{ verified: boolean, payloadType?, canary?, gates?, sink?, source?, runs, standalonePoC? }>}
 */
export async function reproduceChain(packageName, entryPoint, spec, source, opts = {}) {
  if (!source?.package || !source?.entryPoint) return { verified: false, runs: 0 };
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const minimalArgs = Array.isArray(spec.minimalArgs) && spec.minimalArgs.length ? spec.minimalArgs : [{}];
  const results = await Promise.all(
    Array.from({ length: REQUIRED_AGREEING_RUNS }, (_, run) =>
      executeInSandbox(packageName, entryPoint, minimalArgs, {
        timeoutMs,
        blockNetwork: opts.blockNetwork !== false,
        browserEnv: opts.browserEnv === true,
        workerScript: REPRO_WORKER,
        mode: 'repro_chain',
        extra: {
          property: spec.property,
          gates: spec.gates || [],
          sequence: spec.sequence || null,
          nonce: run,
          source: {
            package: source.package,
            entryPoint: source.entryPoint,
            callConvention: source.callConvention,
            payloadKind: source.payloadKind,
          },
        },
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
    source,
    runs: REQUIRED_AGREEING_RUNS,
    standalonePoC: buildChainPoC(packageName, opts.version, entryPoint, spec, first, source, opts.browserEnv === true),
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
const target = require(${JSON.stringify(pkg)});
${payloadLine ? payloadLine + '\n' : ''}${call}
console.log(${readBack}); // => ${valJson}  (Object.prototype polluted)`;
}

// Describe the payload SHAPE a given DOM sink expects — this is derived from the
// sink's own semantics (what kind of value it consumes), not a canned exploit
// string. The tool does NOT invent a payload; it verified that a controlled
// value reaches the sink, and the operator supplies their exploit.
function payloadShapeForSink(sink) {
  if (!sink || sink === 'a DOM sink') return 'a value your target sink consumes';
  if (sink === 'script.src' || sink.endsWith('.src') || sink === 'setAttribute:src') {
    return 'a script/resource URL';
  }
  if (sink === 'setAttribute:href' || sink === 'setAttribute:formaction' || sink === 'setAttribute:action') {
    return 'a URL (e.g. a javascript: URI)';
  }
  // innerHTML / outerHTML / insertAdjacentHTML / document.write / srcdoc
  return 'an HTML string';
}

// Client-side gadgets are exploited from the URL: a page that pollutes
// Object.prototype from query-string params (the standard client-side PP source)
// + this library's gadget = DOM XSS. Emit the exploit URL rather than a Node
// require() PoC — with a <PAYLOAD> placeholder, not an invented exploit string.
// The tool confirmed the LIBRARY gadget (prop -> DOM sink) reachability; jsdom
// doesn't execute scripts, so this is reachability, and the full exploit also
// needs a client-side PP source on the target page.
function buildBrowserGadgetPoC(pkg, version, entryPoint, spec, res) {
  const specStr = version ? `${pkg}@${version}` : pkg;
  const prop = spec.property;
  const sink = res.sink || (res.payloadType === 'sink_reach' ? 'a DOM sink' : 'a code-execution sink');
  const gateParams = (res.gates || []).map(g => `&__proto__[${encodeURIComponent(g)}]=1`).join('');
  const shape = payloadShapeForSink(res.sink);
  const chain = res.urlChain;

  if (chain?.verified) {
    // The target itself parses the URL and pollutes — the whole chain is verified
    // within this one library (source + gadget), using its own parsing.
    return `// PoC — CLIENT-SIDE prototype pollution gadget in ${specStr} via ${entryPoint}()
// VERIFIED END-TO-END in ${res.runs || 2} fresh processes: ${pkg} parses this URL
// query, pollutes Object.prototype.${prop}, which then reaches ${sink}. The chained
// syntax "${chain.syntax}" was confirmed to pollute via the library's OWN parsing.
//
//   https://TARGET/?${chain.syntax}=<PAYLOAD>${gateParams}
//
// <PAYLOAD> is your exploit for ${sink} (${shape}). The tool did not invent one —
// it verified reachability. REACHABILITY, not script execution (jsdom does not run
// scripts).`;
  }

  // Gadget-only: the URL → pollution step depends on a client-side PP SOURCE on
  // the host page (a vulnerable query parser), which is external to this library
  // and was NOT verified. Present the URL forms honestly as unverified.
  return `// PoC — CLIENT-SIDE prototype pollution gadget in ${specStr} via ${entryPoint}()
// Reproduced in ${res.runs || 2} fresh processes: a controlled value on
// Object.prototype.${prop} reaches ${sink}. The URL → pollution step was NOT
// verified (this library is a gadget, not a URL parser), so it requires a
// client-side PP SOURCE on the target page.
//
//   https://TARGET/?__proto__[${prop}]=<PAYLOAD>${gateParams}
//   https://TARGET/?constructor[prototype][${prop}]=<PAYLOAD>${gateParams}
//
// <PAYLOAD> is your exploit for ${sink} (${shape}). The tool did not invent one.`;
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
const target = require(${JSON.stringify(pkg)});
${gateLines ? gateLines + '\n' : ''}// attacker-controlled payload on the polluted property (${res.payloadType})
Object.prototype[${JSON.stringify(spec.property)}] = "<attacker code>";
${ref}(/* attacker-influenced input */);
// ${proofNote}`;
}

// How the SOURCE function is addressed in a chain PoC (mirrors targetRef, but the
// PoC binds the source module to a `source` variable).
function sourceRef(pkg, entryPoint) {
  if (entryPoint === pkg) return 'source';
  const segments = String(entryPoint).split('.');
  const validIdent = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
  if (segments.every(s => validIdent.test(s))) return `source.${entryPoint}`;
  return `source${segments.map(s => `[${JSON.stringify(s)}]`).join('')}`;
}

/**
 * Chain PoC — the full attacker-input → SOURCE → gadget → sink exploit, reproduced
 * end-to-end. Unlike buildRcePoC, the pollution is NOT a faked
 * `Object.prototype[prop] = …` write: it is the exact call to a real, proven PP
 * source that the reproduction actually made. That is the whole point — the
 * exploit names a concrete, currently-shipping source, not a placeholder.
 */
function buildChainPoC(pkg, version, entryPoint, spec, res, source, browserEnv) {
  const specStr = version ? `${pkg}@${version}` : pkg;
  const srcRef = browserEnv ? null : sourceRef(source.package, source.entryPoint);
  const gadgetRef = targetRef(pkg, entryPoint);
  // The property → attacker-expression map the source plants: the primary
  // property carries the exploit placeholder; any gate properties are forced true
  // through the SAME source call (a merge sets them all at once).
  const propExprs = { [spec.property]: '"<attacker code>"' };
  for (const g of res.gates || []) propExprs[g] = 'true';

  const sourceStr = source.version ? `${source.package}@${source.version}` : source.package;
  const sourceTitle = source.fixture
    ? `${source.label || 'reference merge source'} (any recursive merge of attacker JSON is an equivalent real-world source)`
    : `${sourceStr}${source.cve ? ' (' + source.cve + ')' : ''}`;
  const sinkNote = res.payloadType === 'sink_reach'
    ? 'The polluted value reached a code/command sink argument (reachability; execution not proven).'
    : 'The polluted property reaches a code-execution sink and runs attacker code.';

  if (browserEnv) {
    // Client-side chains are exploited from the URL, not a require() — defer to the
    // existing browser PoC, which already renders the exploit URL.
    return buildBrowserGadgetPoC(pkg, version, entryPoint, spec, res);
  }

  const sourceCallJs = renderSourceCalls(srcRef, source.payloadKind, source.callConvention, propExprs);
  return `// PoC — END-TO-END prototype pollution exploit in ${specStr} via ${entryPoint}()
// Reproduced independently in ${res.runs || 2} fresh Node processes: the SOURCE
// below pollutes Object.prototype, then the gadget reaches its sink. No pollution
// is assumed — the source does it, exactly as an attacker request would.
//
// Source: ${sourceTitle}
const source = require(${JSON.stringify(source.package)});
const target = require(${JSON.stringify(pkg)});
// attacker JSON drives the source; <attacker code> is your exploit for the sink.
${sourceCallJs}
${gadgetRef}(/* attacker-influenced input */);
// ${sinkNote}`;
}
