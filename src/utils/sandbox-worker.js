/**
 * Sandbox Worker Process
 *
 * Runs in a child process forked by sandbox.js. Receives execution
 * requests via IPC, loads the target package, executes the function,
 * and returns results.
 *
 * Security measures applied at startup:
 * 1. Network blocking (if UOPFUZZ_BLOCK_NETWORK=1)
 * 2. Sensitive global restriction (process.env scrubbed by parent)
 * 3. Execution timeout (enforced by both parent and self)
 * 4. Prototype pollution cleanup
 */

import { createRequire } from 'module';
import { snapshotPrototype, detectAndRestorePrototype } from './prototype-monitor.js';
import { hardenWorkerProcess } from './worker-hardening.js';
import { GATE_PROPERTIES } from '../instrumentation/gate-properties.js';
import { setupJsdomGlobals, loadBrowserModule, JSDOM_STARTUP_ALLOWANCE_MS } from './browser-env.js';
import { callAndAwaitReal, structuralSerialize } from './proto-safe.js';
import { V8CoverageCollector } from './v8-coverage.js';
const require = createRequire(import.meta.url);

// ─── SECURITY: capability blocks (shared with repro-worker.js) ───────────────
// child_process and worker_threads are always blocked; network egress is blocked
// unless the operator opted in via --allow-network (UOPFUZZ_BLOCK_NETWORK unset).
// See worker-hardening.js for the threat model — these are best-effort in-process
// blocks, and the dev container is the real isolation boundary.
const { send: sealedSend } = hardenWorkerProcess(require, { blockNetwork: process.env.UOPFUZZ_BLOCK_NETWORK === '1' });

// ─── SECURITY: Restrict dangerous process methods ────────────
// The pool matches a reply to its in-flight request by an echoed requestId, and
// the one-shot caller (executeInSandbox) matches by an echoed __replyToken; both
// drop every untagged message. Track the active request's correlation here so
// the control messages below (exit hook, disconnect) are tagged when they relate
// to a request and harmlessly dropped when they don't. Replies go through the
// captured `sealedSend`, never the (now-sealed) public process.send — target
// code that reaches for process.send hits a throwing stub, so it cannot forge a
// reply. See sealProcessSend() in worker-hardening.js.
let activeRequestId;
let activeReplyToken;
function emit(payload) {
  try { sealedSend?.({ ...payload, requestId: activeRequestId, __replyToken: activeReplyToken }); }
  catch { /* channel gone */ }
}
const originalExit = process.exit;
process.exit = function (code) {
  // Don't let target code kill our process — send result instead
  emit({
    error: `Target called process.exit(${code})`,
    output: null,
    exitAttempt: true,
  });
  // Actually exit after sending
  originalExit.call(process, 0);
};

// A pooled worker outlives a single request (it serves many). If the parent
// goes away — the run ended, the process crashed, or the pool was destroyed —
// the IPC channel disconnects; exit rather than lingering as an orphan.
process.on('disconnect', () => {
  originalExit.call(process, 0);
});

// ─── SECURITY: Sink interception ─────────────────────────────
// Intercept dangerous sinks to detect when polluted values reach them.
// These are NOT blocked — they execute normally — but accesses are logged
// so the differential oracle can detect new sink activity.
const sinkLog = [];

// Hook eval() — the most common PP gadget target
const originalEval = globalThis.eval;
globalThis.eval = function(code) {
  sinkLog.push({ sink: 'eval', args: [String(code).substring(0, 200)], timestamp: Date.now() });
  return originalEval.call(this, code);
};

// Hook Function() constructor — second most common RCE sink
const OriginalFunction = globalThis.Function;
globalThis.Function = function(...args) {
  sinkLog.push({ sink: 'Function', args: args.map(a => String(a).substring(0, 200)), timestamp: Date.now() });
  return new OriginalFunction(...args);
};
// Preserve prototype chain
globalThis.Function.prototype = OriginalFunction.prototype;

// Hook setTimeout/setInterval with string args (equivalent to eval)
const originalSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = function(fn, delay, ...args) {
  if (typeof fn === 'string') {
    sinkLog.push({ sink: 'setTimeout', args: [fn.substring(0, 200)], timestamp: Date.now() });
  }
  return originalSetTimeout.call(this, fn, delay, ...args);
};

const originalSetInterval = globalThis.setInterval;
globalThis.setInterval = function(fn, delay, ...args) {
  if (typeof fn === 'string') {
    sinkLog.push({ sink: 'setInterval', args: [fn.substring(0, 200)], timestamp: Date.now() });
  }
  return originalSetInterval.call(this, fn, delay, ...args);
};

// Hook vm module (code execution in sandbox context)
try {
  const vm = require('vm');
  for (const method of ['runInThisContext', 'runInNewContext', 'compileFunction']) {
    if (vm[method]) {
      const orig = vm[method];
      vm[method] = function(...args) {
        sinkLog.push({ sink: `vm.${method}`, args: [String(args[0]).substring(0, 200)], timestamp: Date.now() });
        return orig.apply(this, args);
      };
    }
  }
} catch { /* vm not available */ }

// Hook child_process — command-injection sinks. worker-hardening already replaced
// these with throwing stubs (nothing spawns), but logging the access surfaces a
// command-injection gadget as a high-tier candidate; reproduction then proves the
// polluted value reached the sink (repro-worker's sink_reach proof). Only string
// args are stringified for the log — never coerce a target object here.
try {
  const cp = require('child_process');
  for (const method of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
    const orig = cp[method];
    if (typeof orig === 'function') {
      cp[method] = function(...args) {
        const a = typeof args[0] === 'string' ? args[0].substring(0, 200) : '';
        sinkLog.push({ sink: `child_process.${method}`, args: [a], timestamp: Date.now() });
        return orig.apply(this, args);
      };
    }
  }
} catch { /* child_process not available */ }

// Hook http.request/get and https.request/get — SSRF sinks. RECORD-THEN-DELEGATE:
// worker-hardening blocks the actual socket at net.Socket.prototype.connect, so
// no packet ever leaves, but the URL argument must be logged BEFORE the blocked
// connect fires (the block only errors asynchronously — http.request itself
// returns a ClientRequest normally) so the access is observable even when egress
// is blocked. Only string/URL-ish args are logged — never coerce a target object.
try {
  for (const modName of ['http', 'https']) {
    const mod = require(modName);
    for (const method of ['request', 'get']) {
      const orig = mod[method];
      if (typeof orig === 'function') {
        mod[method] = function(...args) {
          const a0 = args[0];
          let a = '';
          if (typeof a0 === 'string') {
            a = a0.substring(0, 200);
          } else if (a0) {
            const href = a0.href; // single read — a URL-ish object may define href as a getter
            if (typeof href === 'string') a = href.substring(0, 200);
          }
          sinkLog.push({ sink: `${modName}.${method}`, args: [a], timestamp: Date.now() });
          const req = orig.apply(this, args);
          // The network block guarantees this request errors out on a destroyed
          // socket; a target that attaches no 'error' listener would otherwise
          // take the whole worker down with an unhandled 'error' event — possibly
          // before the sink log for this very access could be reported. Absorbing
          // the guaranteed error keeps recording observable; a target's own error
          // listener still fires (listeners are additive). Under --allow-network
          // the guarantee is false and this absorbs real network errors the
          // target didn't handle — still additive and harmless.
          if (req && typeof req.on === 'function') req.on('error', () => {});
          return req;
        };
      }
    }
  }
} catch { /* http(s) not available */ }

// Hook fs.readFileSync / fs.readFile — LFI sinks. fs is NOT blocked by the
// hardening, so record and delegate straight to the original. Only string paths
// are logged — never coerce a target object (Buffer/URL paths log as '').
try {
  const fs = require('fs');
  for (const method of ['readFileSync', 'readFile']) {
    const orig = fs[method];
    if (typeof orig === 'function') {
      fs[method] = function(...args) {
        const a = typeof args[0] === 'string' ? args[0].substring(0, 200) : '';
        sinkLog.push({ sink: `fs.${method}`, args: [a], timestamp: Date.now() });
        return orig.apply(this, args);
      };
    }
  }
} catch { /* fs not available */ }

// ─── PERSISTENT TARGET CACHE ─────────────────────────────────
// A pooled worker serves many requests for the SAME package. Loading the target
// (and, for browser-only packages, standing up jsdom) once and reusing it — the
// costliest part of a probe — is the whole point of the pool: it removes the
// per-probe Node-startup + module-graph-eval + jsdom cold-start that dominated
// wall-clock. Keyed by package+browserEnv defensively; a worker is normally
// dedicated to one package for its whole life.
let _target = { key: null, module: null, baseline: null, error: null };

/** Cache key for a (package, browserEnv) pair — shared by the loader and the
 *  self-timeout, so both agree on whether this request is a cold start. */
function targetCacheKey(packageName, browserEnv) {
  return `${packageName}::${browserEnv ? 1 : 0}`;
}

/** True when this request still has to load the target (and, for a browser-only
 *  package, boot jsdom) — i.e. it is a cold start and earns the startup
 *  allowance. Mirrors the parent pool's `warm` flag; they must not drift. */
function isColdStart(packageName, browserEnv) {
  return _target.key !== targetCacheKey(packageName, browserEnv);
}

// ─── DOM SINK HOOKS (browserEnv only) ────────────────────────
// The classic DOM-XSS sink: the innerHTML setter. jsdom is stood up lazily when
// a browser-only target first loads, so the hook installs lazily too — on that
// jsdom's Element.prototype. Record-then-delegate, exactly like the code sinks
// above: the assigned value is logged, then the real setter runs so the DOM
// behaves normally. These hooks only RECORD; they confirm nothing.
// Deliberately NOT hooked (YAGNI): ShadowRoot.innerHTML, outerHTML, and
// insertAdjacentHTML — rarer sinks we have no fixtures or findings for; add
// them when a real gadget needs them.
let _domHookedWindow = null;
function installDomSinkHooks(dom) {
  const win = dom?.window;
  if (!win || _domHookedWindow === win) return; // already hooked for this DOM
  const proto = win.Element?.prototype;
  if (!proto) return;
  const desc = Object.getOwnPropertyDescriptor(proto, 'innerHTML');
  if (desc?.set && desc.configurable !== false) {
    const origSet = desc.set;
    Object.defineProperty(proto, 'innerHTML', {
      ...desc,
      set(value) {
        const a = typeof value === 'string' ? value.substring(0, 200) : '';
        sinkLog.push({ sink: 'innerHTML', args: [a], timestamp: Date.now() });
        return origSet.call(this, value);
      },
    });
  }
  _domHookedWindow = win;
}

async function loadTargetCached(packageName, browserEnv) {
  const key = targetCacheKey(packageName, browserEnv);
  if (_target.key === key) return _target; // hit (a cached module, or a cached load error)

  let module = null;
  let error = null;
  if (browserEnv) {
    try {
      const dom = await setupJsdomGlobals();
      installDomSinkHooks(dom);
      module = loadBrowserModule(require, packageName, dom);
    } catch (err) {
      error = `Cannot load browser-only package ${packageName}: ${err.message}`;
    }
  } else {
    try {
      module = await import(packageName);
    } catch {
      try {
        module = require(packageName);
      } catch (err) {
        error = `Cannot load package ${packageName}: ${err.message}`;
      }
    }
  }
  // Snapshot the monitored prototypes AFTER load, so any properties the module
  // legitimately adds at load time are part of the baseline (not mistaken for a
  // leak). Each subsequent request restores to this baseline before running.
  _target = { key, module, baseline: module ? snapshotPrototype() : null, error };
  return _target;
}

// ─── MESSAGE HANDLER (persistent request loop) ───────────────
process.on('message', async (msg) => {
  const { mode, packageName, entryPoint, args, timeoutMs, pollution, browserEnv, requestId, __replyToken, collectCoverage } = msg;
  activeRequestId = requestId;
  activeReplyToken = __replyToken;

  // Self-enforced timeout as backup. Browser-only targets get extra time to
  // stand up jsdom before the operation timeout applies (kept in sync with the
  // parent's allowance in sandbox.js / sandbox-pool.js). A synchronous infinite
  // loop in the target blocks this timer entirely (single thread) — the parent's
  // own per-request timeout SIGKILLs the worker in that case.
  //
  // The allowance is for the COLD start only. Once the target is cached (this
  // worker is pooled and has served a request) there is no jsdom boot to pay
  // for, and keeping the allowance would only delay the parent's rescue of a
  // wedged worker. The parent tracks the same warm/cold state.
  const startupAllowance = browserEnv && isColdStart(packageName, browserEnv)
    ? JSDOM_STARTUP_ALLOWANCE_MS
    : 0;
  let settled = false;
  const reply = (payload) => {
    if (settled) return;
    settled = true;
    clearTimeout(killTimer);
    // Echo requestId (for the pool) and __replyToken (for the one-shot caller)
    // so the parent can match this reply to its request; each is harmlessly
    // undefined for the caller that doesn't use it.
    emit(payload);
    // No request is in flight once the reply is out — later control messages
    // (e.g. the exit hook) are untagged and the parent drops them.
    activeRequestId = undefined;
    activeReplyToken = undefined;
  };
  const killTimer = setTimeout(() => {
    // An async-hung request: report a timeout, then exit so the parent pool
    // discards and respawns a clean worker (a hung async op may have left
    // pending work that isn't safe to keep serving requests over). This is our
    // own timer doing the exiting, not target code — use the original exit so
    // the hooked process.exit doesn't send a spurious "Target called
    // process.exit(0)" notice for the request we just settled as timed out.
    reply({ error: 'Self-timeout reached', output: null, timedOut: true });
    originalExit.call(process, 0);
  }, (timeoutMs || 5000) + startupAllowance + 500);

  // Optional per-probe V8 coverage feedback (Phase B → Phase A loop). When the
  // caller sets collectCoverage, wrap the WHOLE request in ONE inspector
  // session (clean + polluted runs both count — every probe's execution work
  // feeds the bitmap, not just confirmations) and attach the ScriptCoverage
  // snapshot to the reply as `v8Coverage`. Instrumentation passes it ON by
  // default (`collectCoverage !== false`); the message default here is off so
  // direct pool/one-shot users opt in explicitly. The session is always
  // stop()ed, even on error.
  let coverageCollector = null;
  if (collectCoverage) {
    coverageCollector = new V8CoverageCollector();
    try {
      await coverageCollector.start();
    } catch {
      coverageCollector = null; // inspector unavailable — the probe still runs
    }
  }

  try {
    const result = await executeRequest(mode, packageName, entryPoint, args, timeoutMs, pollution, browserEnv);
    // Attach coverage on every executed-request outcome (hits, behavioral
    // misses, mode-level error results) — the reply path, not only the hit
    // path. A THROWN error (catch below) replies with v8Coverage: null.
    if (coverageCollector) {
      try {
        result.v8Coverage = await coverageCollector.takeCoverage();
      } catch {
        result.v8Coverage = null;
      }
    } else {
      result.v8Coverage = null;
    }
    reply(result);
  } catch (error) {
    reply({ error: error.message, stack: error.stack, output: null, v8Coverage: null });
  } finally {
    if (coverageCollector) {
      try { await coverageCollector.stop(); } catch { /* session already gone */ }
    }
  }

  // NOTE: no process.exit() here. The worker stays alive to serve the next
  // request — this is what makes pooling work. The legacy one-shot caller in
  // sandbox.js kills the child after reading its single reply, so persistence is
  // transparent there. Crash/hang isolation is preserved by the parent (pool or
  // one-shot), which owns the wall-clock timeout and respawns on exit.
});

async function executeRequest(mode, packageName, entryPoint, args, timeoutMs, pollution, browserEnv) {
  // Load the target package (once, then cached). Browser-only packages (jQuery,
  // …) need a jsdom DOM in place at load time; we stand one up in this isolated
  // child so their fuzzed pollution — and any network the DOM's XHR attempts
  // (blocked here) — stays contained instead of corrupting the fuzzer process.
  const target = await loadTargetCached(packageName, browserEnv);
  if (target.error) return { error: target.error, output: null };

  // Cross-request isolation: undo any prototype leak a previous request in this
  // reused worker may have left, before running this one. Each differential mode
  // also snapshots/restores around its own call; this is the belt-and-suspenders
  // that makes reuse as clean as a fresh fork for discovery purposes.
  if (target.baseline) detectAndRestorePrototype(target.baseline);

  // Resolve the entry point function
  const fn = resolveEntryPoint(target.module, entryPoint, packageName);
  if (!fn) {
    return { error: `Entry point ${entryPoint} not found in ${packageName}`, output: null };
  }

  // Deserialize args
  const realArgs = deserializeArgs(args);

  switch (mode) {
    case 'execute':
      return await executeCall(fn, realArgs, timeoutMs);

    case 'differential':
      return await executeDifferential(fn, realArgs, pollution, timeoutMs);

    case 'forced_branch':
      return await forcedBranchTest(fn, realArgs, pollution, timeoutMs);

    case 'multi_property':
      return await multiPropertyTest(fn, realArgs, pollution, timeoutMs);

    case 'discover_uop':
      return await discoverUOP(fn, realArgs, timeoutMs);

    case 'merge_pp':
      return await mergePPTest(fn, realArgs, pollution, timeoutMs);

    default:
      return { error: `Unknown mode: ${mode}`, output: null };
  }
}

async function executeCall(fn, args, timeoutMs) {
  sinkLog.length = 0; // A pooled worker serves many requests — don't let entries accumulate across them.
  try {
    const box = await callAndAwaitReal(fn, args, timeoutMs);
    return {
      output: structuralSerialize(box.value),
      error: null,
    };
  } catch (error) {
    return { output: null, error: error.message };
  }
}

async function executeDifferential(fn, args, pollution, timeoutMs) {
  if (!pollution) return { error: 'No pollution descriptor', output: null };

  // Merge-style functions mutate args[0]; each run gets its own deep copy so
  // the polluted run never starts from the clean run's mutations.
  const cleanArgs = clone(args);
  const pollutedArgs = clone(args);

  // Clean execution
  let cleanOutput, cleanError;
  sinkLog.length = 0; // Clear any previous sink logs
  try {
    cleanOutput = structuralSerialize((await callAndAwaitReal(fn, cleanArgs, timeoutMs)).value);
  } catch (err) {
    cleanError = err.message;
  }
  const cleanSinkCount = sinkLog.length;

  // Snapshot all monitored prototypes (Object/Function/Array/String) via the
  // shared monitor — same detection the in-process oracle uses.
  const snapshot = snapshotPrototype();

  // Polluted execution
  const prop = pollution.property;
  const val = pollution.value;
  const hadProp = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
  const origVal = Object.prototype[prop];

  let pollutedOutput, pollutedError;
  const pollutedProperties = [];
  let trapFired = false;

  try {
    // Use an active getter trap instead of simple assignment so we can detect
    // reads of the polluted property on ANY object (not just proxied input args).
    // This catches gadgets where the library reads Object.prototype[prop] on
    // internally-created objects (e.g., plain option objects, merge targets).
    let trapVal = val;
    try {
      Object.defineProperty(Object.prototype, prop, {
        get() { trapFired = true; return trapVal; },
        set(v) { trapFired = true; trapVal = v; },
        configurable: true,
        enumerable: false, // discovery trap stays non-enumerable (jsdom stability); repro install is enumerable
      });
    } catch {
      // Property may be non-configurable; fall back to simple assignment
      Object.prototype[prop] = val;
    }
    pollutedOutput = structuralSerialize((await callAndAwaitReal(fn, pollutedArgs, timeoutMs)).value);
  } catch (err) {
    pollutedError = err.message;
  } finally {
    // Restore: delete our descriptor first, then reinstate original if it existed
    try { delete Object.prototype[prop]; } catch { /* sealed */ }
    if (hadProp) {
      try { Object.prototype[prop] = origVal; } catch { /* sealed */ }
    }

    // Detect new properties added to any monitored prototype
    const detection = detectAndRestorePrototype(snapshot);
    if (detection.polluted) pollutedProperties.push(...detection.newProps);
  }

  // Separate sink accesses: entries [0..cleanSinkCount) are from clean execution,
  // entries [cleanSinkCount..) are from polluted execution
  const cleanSinks = sinkLog.slice(0, cleanSinkCount);
  const pollutedSinks = sinkLog.slice(cleanSinkCount);
  const newSinkAccesses = pollutedSinks.filter(ps =>
    !cleanSinks.some(cs => cs.sink === ps.sink)
  );

  return {
    clean: { output: cleanOutput, error: cleanError },
    polluted: { output: pollutedOutput, error: pollutedError },
    outputChanged: cleanOutput !== pollutedOutput,
    errorChanged: cleanError !== pollutedError,
    prototypePolluted: pollutedProperties.length > 0,
    pollutedProperties,
    pollutionWasRead: trapFired,
    sinkAccesses: pollutedSinks,
    newSinkAccesses,
  };
}

/** Install a getter/setter trap on Object.prototype; returns cleanup state. */
function installTrap(prop, val) {
  const hadProp = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
  const origVal = hadProp ? Object.prototype[prop] : undefined;
  const state = { prop, hadProp, origVal, fired: false, trapVal: val };
  try {
    Object.defineProperty(Object.prototype, prop, {
      get() { state.fired = true; return state.trapVal; },
      set(v) { state.fired = true; state.trapVal = v; },
      configurable: true,
      enumerable: false, // discovery trap stays non-enumerable (jsdom stability); repro install is enumerable
    });
  } catch {
    // Non-configurable; fall back to plain assignment (read is not observable).
    try { Object.prototype[prop] = val; } catch { /* sealed */ }
  }
  return state;
}

function restoreTrap({ prop, hadProp, origVal }) {
  try { delete Object.prototype[prop]; } catch { /* sealed */ }
  if (hadProp) { try { Object.prototype[prop] = origVal; } catch { /* sealed */ } }
}

/**
 * Run one clean call then one call with ALL of `traps` installed on
 * Object.prototype simultaneously, and return the raw differential FACTS (never
 * a verdict — the shared classifyDiff() on the parent side owns tiering). Shared
 * by the forced-branch and multi-property modes so they observe sinks, reads,
 * and real prototype mutations exactly the way the single-property differential
 * mode does.
 *
 * @param {Function} fn
 * @param {Array} args
 * @param {Array<{property:string,value:any}>} descriptors - traps to install
 * @param {number} timeoutMs
 */
async function runWithTraps(fn, args, descriptors, timeoutMs) {
  sinkLog.length = 0;
  let cleanOutput, cleanError;
  try {
    cleanOutput = structuralSerialize((await callAndAwaitReal(fn, clone(args), timeoutMs)).value);
  } catch (err) {
    cleanError = err.message;
  }
  const cleanSinkCount = sinkLog.length;

  const snapshot = snapshotPrototype();
  const traps = descriptors.map(d => installTrap(d.property, d.value));
  const pollutedProperties = [];
  let pollutedOutput, pollutedError;

  try {
    pollutedOutput = structuralSerialize((await callAndAwaitReal(fn, clone(args), timeoutMs)).value);
  } catch (err) {
    pollutedError = err.message;
  } finally {
    for (const t of traps.reverse()) restoreTrap(t);
    const detection = detectAndRestorePrototype(snapshot);
    if (detection.polluted) pollutedProperties.push(...detection.newProps);
  }

  const cleanSinks = sinkLog.slice(0, cleanSinkCount);
  const pollutedSinks = sinkLog.slice(cleanSinkCount);
  const newSinkAccesses = pollutedSinks.filter(ps => !cleanSinks.some(cs => cs.sink === ps.sink));

  return {
    clean: { output: cleanOutput, error: cleanError },
    polluted: { output: pollutedOutput, error: pollutedError },
    outputChanged: cleanOutput !== pollutedOutput,
    errorChanged: cleanError !== pollutedError,
    prototypePolluted: pollutedProperties.length > 0,
    pollutedProperties,
    firedProperties: traps.filter(t => t.fired).map(t => t.prop),
    pollutionWasRead: traps.some(t => t.fired),
    sinkAccesses: pollutedSinks,
    newSinkAccesses,
  };
}

/**
 * forced_branch: co-pollute the payload property AND every boolean gate property
 * (GATE_PROPERTIES) with `true`, forcing guarded code paths open (Dasty).
 * `pollution` is the single { property, value } payload descriptor.
 */
async function forcedBranchTest(fn, args, pollution, timeoutMs) {
  if (!pollution) return { error: 'No pollution descriptor', output: null };
  const prop = pollution.property;
  const descriptors = [{ property: prop, value: pollution.value }];
  const forcedGates = [];
  for (const gate of GATE_PROPERTIES) {
    if (gate === prop) continue;
    descriptors.push({ property: gate, value: true });
    forcedGates.push(gate);
  }

  const facts = await runWithTraps(fn, args, descriptors, timeoutMs);
  // The main payload property drives pollutionWasRead; gate reads are reported
  // separately so the parent can record which gates actually opened a branch.
  const forcedGatesFired = facts.firedProperties.filter(p => p !== prop);
  return {
    ...facts,
    property: prop,
    pollutionWasRead: facts.firedProperties.includes(prop),
    forcedGates,
    forcedGatesFired,
  };
}

/**
 * multi_property: co-pollute several attacker-controlled properties at once, for
 * conjunctive gadgets where no single property alone reaches the sink.
 * `pollution.descriptors` is the array of { property, value } to co-pollute.
 */
async function multiPropertyTest(fn, args, pollution, timeoutMs) {
  const descriptors = Array.isArray(pollution?.descriptors) ? pollution.descriptors : [];
  if (!descriptors.length) return { error: 'No descriptors for multi_property', output: null };
  const facts = await runWithTraps(fn, args, descriptors, timeoutMs);
  return { ...facts, property: descriptors.map(d => d.property).join('+') };
}

async function discoverUOP(fn, args, timeoutMs) {
  // Use a Proxy to detect which properties are read as undefined
  const uopCandidates = new Set();
  const trackedArgs = args.map(arg => {
    if (arg && typeof arg === 'object' && !Buffer.isBuffer(arg)) {
      return new Proxy(arg, {
        get(target, prop) {
          if (typeof prop === 'string' && !(prop in target) &&
              !prop.startsWith('__') && prop !== 'constructor' &&
              prop !== 'prototype' && prop.length > 1) {
            uopCandidates.add(prop);
          }
          return Reflect.get(target, prop);
        }
      });
    }
    return arg;
  });

  try {
    await callAndAwaitReal(fn, trackedArgs, timeoutMs);
  } catch { /* errors expected */ }

  return {
    uopProperties: [...uopCandidates],
    error: null,
  };
}

/**
 * Test whether the function causes prototype pollution when given crafted merge payloads.
 * Tries multiple calling conventions (fn(payload), fn({}, payload), fn(true, {}, payload))
 * to cover the most common merge/extend/assign patterns.
 */
async function mergePPTest(fn, baseArgs, pollution, timeoutMs) {
  const prop = pollution.property;
  const val = pollution.value;

  // Craft both __proto__ and constructor.prototype payloads
  let protoPayload, ctorPayload;
  try {
    protoPayload = JSON.parse(`{"__proto__":{${JSON.stringify(prop)}:${JSON.stringify(val)}}}`);
  } catch {
    protoPayload = null;
  }
  ctorPayload = { constructor: { prototype: { [prop]: val } } };

  // Calling conventions: cover jQuery.extend, lodash.merge, deepmerge, etc.
  const targetObj = baseArgs[0] && typeof baseArgs[0] === 'object' ? baseArgs[0] : {};
  const argVariants = [
    ...(protoPayload ? [
      [protoPayload],                            // fn(payload)
      [{}, protoPayload],                        // fn({}, payload)
      [true, {}, protoPayload],                  // fn(true, {}, payload)  — jQuery deep extend
      [targetObj, protoPayload],                 // fn(target, payload)
    ] : []),
    [ctorPayload],
    [{}, ctorPayload],
    [true, {}, ctorPayload],
    // Path-based patterns: fn({}, '__proto__.prop', val)
    [{}, `__proto__.${prop}`, val],
    [{}, `constructor.prototype.${prop}`, val],
  ];

  for (const callArgs of argVariants) {
    const snapshot = snapshotPrototype();

    try {
      await callAndAwaitReal(fn, callArgs, timeoutMs);
    } catch { /* expected */ }

    const detection = detectAndRestorePrototype(snapshot);
    if (detection.polluted) {
      return { pollutionDetected: true, pollutedProperties: detection.newProps };
    }
  }

  return { pollutionDetected: false };
}

/** Deep-clone args between the clean and polluted runs so a mutation in one run
 *  cannot leak into the other. Falls back to the original on non-cloneable args. */
function clone(arr) {
  return arr.map(a => {
    if (a && typeof a === 'object' && !Buffer.isBuffer(a)) {
      try { return structuredClone(a); } catch { return a; }
    }
    return a;
  });
}

function resolveEntryPoint(module, name, packageName) {
  if (!name) return null;
  // Bare-function module: `module.exports = fn` (merge-deep, deep-extend, …).
  // Only fall back to the module itself when `name` IS the package's own name —
  // never as a catch-all for an unrelated or nonexistent entry point name.
  // Checked BEFORE the dotted-path branch: a package identifier can be a
  // filesystem path (a local target or test fixture) whose directory contains a
  // dot (e.g. `.../.claude/worktrees/.../bare-merge`); treating that as a dotted
  // property path would walk nonexistent keys and never reach this fallback.
  // Short-circuits only when the module itself is callable.
  if (name === packageName) {
    if (typeof module === 'function') return module;
    if (typeof module.default === 'function') return module.default;
  }
  if (name.includes('.')) {
    const parts = name.split('.');
    let current = module;
    for (const part of parts) {
      if (current && current[part]) {
        current = current[part];
      } else {
        return null;
      }
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

