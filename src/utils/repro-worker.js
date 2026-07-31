/**
 * Reproduction Worker — the independent second oracle.
 *
 * This worker exists to *reproduce* a proposed finding in a fresh Node process,
 * completely separate from the discovery oracle (sandbox-worker.js / the
 * in-process differential). It deliberately shares NONE of the fuzzy verdict
 * logic (no output/error diffing, no getter-trap "read" heuristic). It computes
 * only two booleans, each from ground-truth facts:
 *
 *   repro_pp  — did feeding a crafted __proto__ / constructor.prototype / path
 *               payload to the target actually add an own-property (named exactly
 *               like the attacker-supplied property) to a monitored prototype?
 *   repro_rce — did setting a canary payload on Object.prototype and invoking the
 *               entry point actually execute code (a unique token appears on
 *               globalThis)?
 *
 * Because discovery and reproduction are two independent oracles, an
 * observer-effect or bug in discovery cannot self-confirm a finding. A finding is
 * only reported as a vulnerability when this worker agrees — twice, in two fresh
 * processes (enforced by the driver in ../verification/reproduce.js).
 *
 * Security hardening mirrors sandbox-worker.js (network + child_process + exit
 * blocked, env scrubbed by the parent). Crucially, this worker does NOT stub
 * eval/Function — for the canary to prove code execution, the sink must actually
 * run. child_process stays blocked, so proof-of-execution means "attacker code
 * ran" (a global write), never "a shell spawned".
 */

import { createRequire } from 'module';
import { snapshotPrototype, detectAndRestorePrototype } from './prototype-monitor.js';
import { hardenWorkerProcess } from './worker-hardening.js';
import { setupJsdomGlobals, loadBrowserModule, JSDOM_STARTUP_ALLOWANCE_MS, installDomSinkHooks as installDomSinkHooksShared } from './browser-env.js';
import { callAndAwaitReal } from './proto-safe.js';
import { argContainsTransformedValue } from './value-contains.js';
const require = createRequire(import.meta.url);

// ─── SECURITY: capability blocks (shared with sandbox-worker.js) ─────────────
// child_process and worker_threads are always blocked; network egress is blocked
// unless the operator opted in via --allow-network. See worker-hardening.js for
// the threat model. eval/Function are intentionally NOT hooked here — the canary
// payload must actually execute for repro_rce to prove code execution; it is
// contained by blocking the effects (network/child_process) plus the container.
const { send: sealedSend } = hardenWorkerProcess(require, { blockNetwork: process.env.UOPFUZZ_BLOCK_NETWORK === '1' });

// Every reply to the parent goes through here, never the (now-sealed) public
// `process.send`. The parent (executeInSandbox) mints a per-fork token and only
// accepts a reply that echoes it, so a hostile target — which cannot reach the
// captured `sealedSend` and never sees the token (it is stripped from the
// message before any target code runs) — cannot forge a `verified:true` verdict.
let activeReplyToken;
function emit(payload) {
  try { sealedSend?.({ ...payload, __replyToken: activeReplyToken }); } catch { /* channel gone */ }
}

// If the parent dies between fork and first message (or mid-reproduction),
// the IPC channel disconnects — exit rather than lingering as an orphan.
// (sandbox-worker.js has the same handler.) Uses the original exit captured
// below, not the hooked process.exit — this is our own shutdown, not target
// code, so no "Target called process.exit(0)" notice should be sent. The
// binding is initialized during module evaluation, before any disconnect
// event can fire.
process.on('disconnect', () => {
  originalExit.call(process, 0);
});

// (emit + activeReplyToken are defined above, right after hardening.)

// ─── SINK REACHABILITY RECORDING ─────────────────────────────
// Some gadgets flow a polluted value into a code/command sink as a STRING
// (child_process.execSync(cmd), eval(code), vm.runInThisContext(code)). The
// globalThis execution-canary cannot prove those — a shell command is not
// runnable JS, and spawning is blocked for safety. So we ALSO record the string
// argument every sink receives; if a unique token planted on the prototype shows
// up there, the polluted value provably reached that sink (reachability), with no
// external effect. Only STRING args are recorded — never coerce a target object
// (that could route through a polluted toString/valueOf). Recording delegates to
// the original so eval/Function still execute for the execution-canary; for
// child_process the original is already the blocked stub, so nothing spawns.
const sinkArgs = [];
// DOM sinks record {sink, value} (not just the value) so a confirmed client-side
// gadget can name the exact sink (innerHTML, script.src, …) and emit an accurate
// browser-URL PoC. Kept separate from sinkArgs so the code/command-sink path is
// untouched.
const domSinkHits = [];
function installSinkRecorders() {
  const record = (arg) => { if (typeof arg === 'string') sinkArgs.push(arg); };
  const wrap = (obj, name) => {
    const orig = obj[name];
    if (typeof orig !== 'function') return;
    const wrapped = function (...args) { record(args[0]); return orig.apply(this, args); };
    // Preserve the original's prototype — jsdom and other code rely on
    // `Function.prototype` identity (matches the sandbox worker's eval/Function
    // hooks). Without this, wrapping Function breaks browser-only targets.
    try { wrapped.prototype = orig.prototype; } catch { /* frozen */ }
    obj[name] = wrapped;
  };
  wrap(globalThis, 'eval');
  wrap(globalThis, 'Function');
  try {
    const vm = require('vm');
    for (const m of ['runInThisContext', 'runInNewContext', 'compileFunction']) wrap(vm, m);
  } catch { /* vm unavailable */ }
  try {
    const cp = require('child_process');
    for (const m of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) wrap(cp, m);
  } catch { /* child_process unavailable */ }
  // SSRF sinks: http(s).request/get — record the URL argument BEFORE delegating,
  // so the token is captured however the call ends: a whole-token-as-URL string
  // throws synchronously inside the ClientRequest constructor, but the common
  // real-world pattern (polluted value interpolated into a VALID URL, e.g.
  // `http://example.invalid/${token}`) constructs fine and only errors
  // asynchronously on the blocked socket. Like the discovery worker's hook
  // (sandbox-worker.js), absorb that guaranteed error with a no-op listener —
  // otherwise the unhandled 'error' event kills this worker before it can send
  // its result, and the zero-FP gate would discard a genuinely proven
  // sink_reach (false negative). A target's own error listener still fires
  // (listeners are additive).
  const wrapHttp = (obj, name) => {
    const orig = obj[name];
    if (typeof orig !== 'function') return;
    obj[name] = function (...args) {
      record(args[0]);
      const req = orig.apply(this, args);
      if (req && typeof req.on === 'function') req.on('error', () => {});
      return req;
    };
  };
  try {
    const http = require('http');
    wrapHttp(http, 'request');
    wrapHttp(http, 'get');
  } catch { /* http unavailable */ }
  try {
    const https = require('https');
    wrapHttp(https, 'request');
    wrapHttp(https, 'get');
  } catch { /* https unavailable */ }
  // LFI sinks: fs.readFileSync/readFile — record the path argument. fs is not
  // blocked; a nonexistent token path just throws in the original, which the
  // caller (reproRCE) already expects and catches.
  try {
    const fs = require('fs');
    wrap(fs, 'readFileSync');
    wrap(fs, 'readFile');
  } catch { /* fs unavailable */ }
}
installSinkRecorders();

// DOM-XSS / script-injection sinks. jsdom only exists once loadPackage stands it
// up for a browser-only target, so this recorder installs lazily there — via the
// same shared hook the discovery worker uses (browser-env.js), so a polluted
// value reaching innerHTML/outerHTML/insertAdjacentHTML/document.write/
// setAttribute/<script|iframe|img>.src is recorded for the sink_reach proof.
let _domRecordedWindow = null;
function installDomSinkRecorder(dom) {
  const win = dom?.window;
  if (!win || _domRecordedWindow === win) return; // already hooked for this DOM
  installDomSinkHooksShared(dom, (sink, value) => domSinkHits.push({ sink, value }));
  _domRecordedWindow = win;
}

// ─── SECURITY: Restrict dangerous process methods ────────────
const originalExit = process.exit;
process.exit = function (code) {
  emit({ error: `Target called process.exit(${code})`, verified: false, exitAttempt: true });
  originalExit.call(process, 0);
};

const CANARY_GLOBAL = '__uopfuzz_repro_canary';

// A prototype-pollution attacker's injection vector (JSON `__proto__`, a
// recursive data merge, a query string) can carry only DATA — never a live
// callable: `{"__proto__":{"toString":…}}` sets a string, not a function. So a
// `function_call` proof (a real Function installed on Object.prototype[prop])
// never corresponds to a realizable exploit, no matter which property it is.
//
// It *does* self-trigger, though, whenever the target invokes the property as a
// method — implicitly via engine coercion (toString/valueOf during
// `new Date(obj)` / `${obj}`) OR explicitly via a normal method call
// (`obj.split(',')`, `obj.replace(…)`, `for..of` → @@iterator). An earlier fix
// suppressed only the four engine-coercion names; that missed the explicit-
// dispatch cases (real-world FPs: 6to5 `split`, marked `replace`, immutable
// `@@iterator`). The unrealizability is identical for every name, so the
// executable-function payload is skipped for ALL properties below.
//
// The realizable RCE proofs are the STRING payloads, kept for every property:
// eval_string (fires only if the target genuinely eval()s the injected string)
// and sink_reach (the token must reach a real code/command sink argument). A
// string installed on a method name never executes — `obj.split(',')` on a
// string-valued split just throws "split is not a function" — so these never
// self-trigger from coercion or method dispatch.

// ─── MESSAGE HANDLER ─────────────────────────────────────────
process.on('message', async (msg) => {
  // Capture and strip the parent's per-fork reply token before any target code
  // runs, so every reply from this request echoes it and the target never sees
  // it. (process.send is already sealed, so this is defense in depth.)
  activeReplyToken = msg?.__replyToken;
  if (msg && '__replyToken' in msg) { try { delete msg.__replyToken; } catch { /* frozen */ } }
  const { mode, packageName, entryPoint, args, timeoutMs, browserEnv } = msg;
  // Browser-only targets must boot jsdom before loading; give the same cold-start
  // allowance the discovery worker and the sandbox driver use, so the module
  // graph + DOM setup does not race the self-timeout on the first (only) load.
  const startupAllowance = browserEnv ? JSDOM_STARTUP_ALLOWANCE_MS : 0;
  const killTimer = setTimeout(() => {
    emit({ error: 'Self-timeout reached', verified: false, timedOut: true });
    originalExit.call(process, 0);
  }, (timeoutMs || 3000) + startupAllowance + 500);

  try {
    const result = await handle(mode, packageName, entryPoint, args, msg, timeoutMs);
    clearTimeout(killTimer);
    emit(result);
  } catch (error) {
    clearTimeout(killTimer);
    emit({ error: error.message, verified: false });
  }
  originalExit.call(process, 0);
});

async function handle(mode, packageName, entryPoint, args, msg, timeoutMs) {
  const targetModule = await loadPackage(packageName, msg.browserEnv);
  if (targetModule?.__loadError) {
    return { error: `Cannot load ${packageName}: ${targetModule.__loadError}`, verified: false };
  }

  const fn = resolveEntryPoint(targetModule, entryPoint, packageName);
  if (!fn) return { error: `Entry point ${entryPoint} not found in ${packageName}`, verified: false };

  const realArgs = deserializeArgs(args);

  switch (mode) {
    case 'repro_pp':  return reproPP(fn, realArgs, msg, timeoutMs);
    case 'repro_rce': return reproRCE(fn, realArgs, msg, timeoutMs, targetModule, packageName);
    default:          return { error: `Unknown repro mode: ${mode}`, verified: false };
  }
}

/**
 * Run a config.sequences-style multi-step call chain with pre-resolved args
 * (mirrors buildCallableThunk in ../instrumentation/index.js). Needed because
 * some gadgets (e.g. CVE-2022-29078: EJS's compile()) only execute when the
 * function an entry point RETURNS is subsequently invoked — a single call to
 * the entry point itself never reaches the sink.
 */
async function runSequence(targetModule, steps, timeoutMs, packageName) {
  let lastResult = null;
  for (const step of steps) {
    let fn;
    if (step.call === '__result__') {
      if (step.method && lastResult && typeof lastResult[step.method] === 'function') {
        fn = lastResult[step.method].bind(lastResult);
      } else if (typeof lastResult === 'function') {
        fn = lastResult;
      } else {
        return lastResult;
      }
    } else {
      fn = resolveEntryPoint(targetModule, step.call, packageName);
      if (!fn) return null;
    }
    const args = deserializeArgs(step.args || []);
    lastResult = (await callAndAwaitReal(fn, args, timeoutMs)).value;
  }
  return lastResult;
}

async function loadPackage(packageName, browserEnv) {
  // Browser-only libraries (jQuery, Backbone, …) touch `window`/`document` at
  // load time and export a factory; stand up jsdom first and load through it,
  // mirroring the discovery worker (sandbox-worker.js loadTargetCached). Without
  // this, the fresh reproduction process could never load such a target, so any
  // real browser-library gadget was permanently unprovable.
  if (browserEnv) {
    try {
      const dom = await setupJsdomGlobals();
      installDomSinkRecorder(dom);
      return loadBrowserModule(require, packageName, dom);
    } catch (err) {
      return { __loadError: `browser-only load failed: ${err.message}` };
    }
  }
  try { return await import(packageName); }
  catch {
    try { return require(packageName); }
    catch (err) { return { __loadError: err.message }; }
  }
}

/**
 * repro_pp: prove the target pollutes a monitored prototype when fed a crafted
 * payload, with the polluted property NAME matching the attacker-supplied one.
 * Tries the same real-world calling conventions as the discovery merge-PP test.
 */
async function reproPP(fn, baseArgs, msg, timeoutMs) {
  const prop = msg.property;
  const val = msg.value;

  let protoPayload = null;
  try { protoPayload = JSON.parse(`{"__proto__":{"${prop}":${JSON.stringify(val)}}}`); } catch { /* non-serializable */ }
  const ctorPayload = { constructor: { prototype: { [prop]: val } } };

  const targetObj = baseArgs[0] && typeof baseArgs[0] === 'object' ? baseArgs[0] : {};
  // Each variant carries the payload KIND that would verify it, so the PoC
  // builder renders the exact vector that reproduced (a target pollutable only
  // via constructor.prototype must not get a __proto__ PoC that fails to run).
  const argVariants = [
    ...(protoPayload ? [
      { args: [protoPayload], kind: 'proto-json' },
      { args: [{}, protoPayload], kind: 'proto-json' },
      { args: [true, {}, protoPayload], kind: 'proto-json' },
      { args: [targetObj, protoPayload], kind: 'proto-json' },
    ] : []),
    { args: [ctorPayload], kind: 'ctor-object' },
    { args: [{}, ctorPayload], kind: 'ctor-object' },
    { args: [true, {}, ctorPayload], kind: 'ctor-object' },
    { args: [{}, `__proto__.${prop}`, val], kind: 'proto-path' },
    { args: [{}, `constructor.prototype.${prop}`, val], kind: 'ctor-path' },
  ];

  for (const { args: callArgs, kind } of argVariants) {
    const snapshot = snapshotPrototype();
    try { await callAndAwaitReal(fn, clone(callArgs), timeoutMs); }
    catch { /* execution errors are expected */ }
    const detection = detectAndRestorePrototype(snapshot);

    if (detection.polluted) {
      // Attacker control: require the polluted key to match the supplied property.
      // Guards against a package that benignly extends a prototype under a
      // different name.
      const matched = detection.newProps.find(p => lastKey(p) === prop);
      if (matched) {
        return {
          verified: true,
          newProps: detection.newProps,
          matchedProperty: prop,
          callConvention: describeConvention(callArgs, prop),
          payloadKind: kind,
        };
      }
    }
  }
  return { verified: false };
}

/**
 * repro_rce: prove code execution. Set a canary payload on Object.prototype for
 * the primary property; force any gate properties to true; invoke the entry
 * point (or replay a resolved multi-step sequence, for gadgets like
 * CVE-2022-29078 that only fire on a function the entry point RETURNS); check
 * whether the canary token reached globalThis.
 *
 * The constructor_chain payload ends with a NUL character (built at runtime via
 * String.fromCharCode, never written as literal escape text in this source file,
 * so the file itself stays plain UTF-8 with no embedded control bytes). Some
 * template/code-generation gadgets splice this payload into generated source,
 * and a trailing NUL can terminate a subsequent literal there, letting the
 * injected call survive compilation.
 */
async function reproRCE(fn, baseArgs, msg, timeoutMs, targetModule, packageName) {
  const prop = msg.property;
  const gates = Array.isArray(msg.gates) ? msg.gates.filter(g => g && g !== prop) : [];
  const sequenceSteps = msg.sequence?.steps;
  // Unique per-attempt token; built inside the worker so no function crosses IPC.
  const token = `UOPFUZZ_${msg.nonce || 'x'}_${gates.length}`;
  const sinkToken = `UOPFUZZ_SINK_${msg.nonce || 'x'}_${gates.length}`;
  const nulChar = String.fromCharCode(0);

  // Two proof kinds, each with its own `fired()` oracle:
  //  - EXECUTION: the polluted value is invoked/eval'd and writes the canary to
  //    globalThis (proof of actual code execution).
  //  - REACHABILITY: the polluted value is a token STRING that shows up in a code
  //    or command sink's argument (proof it flowed to a sink; used for command
  //    injection, which cannot be safely executed).
  const canaryFired = () => globalThis[CANARY_GLOBAL] === token;
  const payloads = [
    { type: 'function_call', make: () => new Function(`globalThis['${CANARY_GLOBAL}']='${token}'`), fired: canaryFired },
    { type: 'eval_string', make: () => `globalThis['${CANARY_GLOBAL}']='${token}'`, fired: canaryFired },
    // Template-compilation injection (ejs outputFunctionName, pug, hogan, …): the
    // polluted value is spliced into GENERATED function source at an identifier /
    // declaration position (e.g. `var <value> = ...`), so a bare
    // `globalThis[...]=...` is a syntax error there. This payload is a valid
    // identifier, then the canary statement, then re-supplies the identifier so
    // the surrounding `var <ident> = ...` stays syntactically valid and runs. Still
    // a plain string a prototype-pollution attacker can inject.
    { type: 'template_injection', make: () => `x;globalThis['${CANARY_GLOBAL}']='${token}';x`, fired: canaryFired },
    { type: 'constructor_chain', make: () => `constructor.constructor("globalThis['${CANARY_GLOBAL}']='${token}'")()${nulChar}`, fired: canaryFired },
    // sink_reach fires when the planted token reaches a sink argument — even
    // after the reversible value transforms real gadget code applies (case fold,
    // dash/underscore, URL-encode). argContainsTransformedValue is a strict
    // superset of includes(), so this never loses a plain-substring match.
    { type: 'sink_reach', make: () => sinkToken, fired: () => sinkArgs.some(a => argContainsTransformedValue(a, sinkToken)) || domSinkHits.some(h => argContainsTransformedValue(h.value, sinkToken)) },
  ];

  for (const payload of payloads) {
    // A live *function* on Object.prototype[prop] fires the canary whenever the
    // target invokes the property as a method — engine coercion (toString/
    // valueOf) OR an explicit call (obj.split(), obj.replace(), for..of →
    // @@iterator). None of that is reachable by a prototype-pollution attacker,
    // who can only inject data (never a callable) — so the function_call proof
    // is unrealizable for EVERY property and is skipped unconditionally. The
    // remaining string proofs (eval_string, constructor_chain, sink_reach) are
    // realizable and never self-trigger — a string on a method name just throws.
    if (payload.type === 'function_call') continue;

    delete globalThis[CANARY_GLOBAL];
    sinkArgs.length = 0;
    domSinkHits.length = 0;
    const installed = [];
    try {
      installProp(prop, payload.make(), installed);
      for (const g of gates) installProp(g, true, installed);
      try {
        if (Array.isArray(sequenceSteps) && sequenceSteps.length) {
          await runSequence(targetModule, sequenceSteps, timeoutMs, packageName);
        } else {
          // Try the discovery-supplied args first, then a few generic argument
          // shapes. A template engine (ejs/hogan/…) only reaches the gadget when
          // it's given a STRING template to compile; discovery often probes it
          // with an object or empty value, which never triggers the sink. Extra
          // shapes can only surface a REAL gadget — the canary still requires
          // actual execution, so this adds recall without any false-positive
          // risk. Stop as soon as the canary fires.
          for (const av of argVariants(baseArgs)) {
            try { await callAndAwaitReal(fn, clone(av), timeoutMs); }
            catch { /* exploit payloads routinely throw after firing */ }
            if (payload.fired()) break;
          }
        }
      } catch { /* exploit payloads routinely throw after firing */ }
    } finally {
      for (const p of installed.reverse()) restoreProp(p);
    }

    if (payload.fired()) {
      const domHit = domSinkHits.find(h => argContainsTransformedValue(h.value, sinkToken));
      delete globalThis[CANARY_GLOBAL];
      sinkArgs.length = 0;
      domSinkHits.length = 0;
      // For client-side gadgets, also check whether the target ITSELF turns a
      // chained/nested URL query string into this pollution — verifying the
      // URL → pollution step with the target's own parsing (no embedded parser).
      // A confirmed syntax makes the browser-URL PoC a verified end-to-end chain.
      const urlChain = msg.browserEnv ? await verifyUrlChain(fn, prop, timeoutMs) : null;
      return { verified: true, payloadType: payload.type, canary: token, gates, sink: domHit?.sink || null, urlChain };
    }
  }
  delete globalThis[CANARY_GLOBAL];
  sinkArgs.length = 0;
  domSinkHits.length = 0;
  return { verified: false };
}

// Chained/nested URL query-string forms a vulnerable client-side parser turns
// into prototype pollution. We feed the RAW query string to the target and check
// whether IT parses the string and pollutes Object.prototype[prop] with a
// generated marker — verifying the URL → pollution step with the target's OWN
// parsing (no embedded parser, no hardcoded payload). Covers the canonical and
// chained/nested syntaxes. Returns the exact syntax that verified, or unverified.
async function verifyUrlChain(fn, prop, timeoutMs) {
  const marker = `UOPFUZZ_URL_${prop}`;
  const queries = [
    `__proto__[${prop}]=${marker}`,
    `constructor[prototype][${prop}]=${marker}`,
    `a[__proto__][${prop}]=${marker}`,
    `a[b][__proto__][${prop}]=${marker}`,
  ];
  for (const query of queries) {
    // A parser might take the raw pairs, a leading-'?' string, or the query as a
    // second argument (fn(target, query)).
    for (const args of [[query], [`?${query}`], [{}, query]]) {
      const had = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
      const orig = had ? Object.prototype[prop] : undefined;
      try { await callAndAwaitReal(fn, clone(args), timeoutMs); }
      catch { /* parse/exec errors are expected for non-parser entry points */ }
      const polluted = Object.prototype.hasOwnProperty.call(Object.prototype, prop) &&
        Object.prototype[prop] === marker;
      try { delete Object.prototype[prop]; } catch { /* sealed */ }
      if (had) { try { Object.prototype[prop] = orig; } catch { /* sealed */ } }
      if (polluted) return { verified: true, syntax: query.split('=')[0] };
    }
  }
  return { verified: false };
}

// ─── prototype install/restore ───────────────────────────────
function installProp(prop, value, installed) {
  const hadProp = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
  const origVal = hadProp ? Object.prototype[prop] : undefined;
  // enumerable: true — a real __proto__/merge pollution creates an ENUMERABLE
  // own property, so gadgets shaped `for (const k in opts) …` only see it when
  // the reproduced pollution is enumerable too. Installing it non-enumerable
  // made that whole (large) gadget class unreproducible → silent false negatives.
  try { Object.defineProperty(Object.prototype, prop, { value, writable: true, configurable: true, enumerable: true }); }
  catch { try { Object.prototype[prop] = value; } catch { /* sealed */ } }
  installed.push({ prop, hadProp, origVal });
}

function restoreProp({ prop, hadProp, origVal }) {
  try { delete Object.prototype[prop]; } catch { /* sealed */ }
  if (hadProp) { try { Object.prototype[prop] = origVal; } catch { /* sealed */ } }
}

// The self-trigger guard (await only a real Promise; never adopt a plain return
// value's inherited `then`) and the pollution-invariant serializer now live in
// the shared proto-safe.js so the discovery oracles and this reproduction gate
// cannot drift.

function clone(arr) {
  return arr.map(a => {
    if (a && typeof a === 'object') {
      try { return structuredClone(a); } catch { return a; }
    }
    return a;
  });
}

// Argument shapes reproRCE tries for a direct entry-point call. The
// discovery-supplied args come first; when they aren't already a non-empty
// string, a benign template string is added so string-template engines
// (ejs/hogan/…) actually reach their compile step, where the polluted option is
// spliced into generated source. Extra shapes only ever surface a REAL gadget —
// the canary requires genuine execution — so there is no false-positive risk.
function argVariants(baseArgs) {
  const variants = [Array.isArray(baseArgs) ? baseArgs : [baseArgs]];
  const firstIsNonEmptyString = typeof baseArgs?.[0] === 'string' && baseArgs[0].length > 0;
  if (!firstIsNonEmptyString) variants.push(['<p>x</p>']);
  return variants;
}

function lastKey(qualifiedName) {
  return String(qualifiedName).split('.').pop();
}

function describeConvention(callArgs, prop) {
  if (typeof callArgs[1] === 'string' && callArgs[1].includes(prop)) return `fn({}, '${callArgs[1]}', value)`;
  if (callArgs[0] === true) return 'fn(true, {}, payload)';
  if (callArgs.length === 1) return 'fn(payload)';
  return 'fn(target, payload)';
}

/**
 * Resolve the callable for `name` on `module`. The bare-function fallback
 * (module.exports = fn, e.g. merge-deep, deep-extend) only applies when `name`
 * actually identifies the module itself (equals the package name) — it must
 * never silently substitute the whole module for an unrelated/unresolved name.
 */
function resolveEntryPoint(module, name, packageName) {
  if (!name) return null;
  // Bare-function module: `module.exports = fn` (merge-deep, deep-extend, …).
  // Only fall back to the module itself when `name` IS the package's own name —
  // never as a catch-all for an unrelated or nonexistent entry point name.
  // Checked BEFORE the dotted-path branch below: a package identifier can be a
  // filesystem path (a local target, or a test fixture) whose directory contains
  // a dot — e.g. `.../.claude/worktrees/.../bare-merge`. Treating that as a
  // dotted property path would walk nonexistent keys and never reach this
  // fallback, so a bare-function module addressed by a dotted path would fail to
  // resolve. This short-circuits only when the module itself is callable.
  if (name === packageName) {
    if (typeof module === 'function') return module;
    if (typeof module.default === 'function') return module.default;
  }
  if (name.includes('.')) {
    const parts = name.split('.');
    let current = module;
    for (const part of parts) {
      if (current && current[part]) current = current[part];
      else return null;
    }
    return typeof current === 'function' ? current : null;
  }
  if (typeof module[name] === 'function') return module[name];
  if (module.default && typeof module.default[name] === 'function') return module.default[name];
  return null;
}

function deserializeArgs(args) {
  return (args || []).map(arg => {
    if (arg && typeof arg === 'object' && arg.__type) {
      switch (arg.__type) {
        case 'date': return new Date(arg.iso);
        case 'buffer': return Buffer.from(arg.data, 'base64');
        case 'function': return new Function('return ' + arg.source)();
        default: return arg;
      }
    }
    return arg;
  });
}
