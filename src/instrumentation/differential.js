import { createTaintProxy, analyzeTaintLog } from '../utils/taint-proxy.js';
import { logger } from '../utils/logger.js';
import { snapshotPrototype, detectAndRestorePrototype } from '../utils/prototype-monitor.js';
import { classifyDiff } from './classify-diff.js';
import { GATE_PROPERTIES } from './gate-properties.js';
import { callAndAwaitReal, structuralSerialize } from '../utils/proto-safe.js';

/**
 * Differential Execution Oracle
 *
 * The key insight: run the same code twice — once clean, once with
 * Object.prototype polluted — and compare. If behavior changes,
 * the pollution caused it. This eliminates the entire class of
 * false positives from timestamp-correlation chain detection.
 *
 * This is the difference between "a sink was called after a prototype
 * change" (correlation) and "this pollution CAUSED this sink to fire"
 * (causation).
 *
 * Reference: Differential testing (McKeeman, 1998) applied to
 * prototype pollution gadget discovery.
 */

/**
 * Execute a function call with full tracing but no pollution.
 * Returns a normalized execution result for comparison.
 */
async function executeClean(fn, args, timeoutMs = 5000) {
  const taintLog = [];
  const sinkAccesses = [];
  const result = { output: null, error: null, sinkAccesses, taintLog, taintAnalysis: null };

  // Wrap object args in taint proxy for property access tracking
  const trackedArgs = args.map(arg => {
    if (arg && typeof arg === 'object' && !Buffer.isBuffer(arg)) {
      try { return createTaintProxy(arg, taintLog); } catch { return arg; }
    }
    return arg;
  });

  try {
    // callAndAwaitReal never adopts the target's return value as a thenable, so
    // a polluted `then` can't self-trigger; it applies the timeout to a genuine
    // async result. box.value is the raw return (see proto-safe.js).
    result.output = (await callAndAwaitReal(fn, trackedArgs, timeoutMs)).value;
    // Drain microtask queue for consistent comparison with polluted run
    await new Promise(r => setTimeout(r, 0));
    await new Promise(r => setTimeout(r, 0));
  } catch (error) {
    result.error = error.message;
  }

  if (taintLog.length > 0) {
    result.taintAnalysis = analyzeTaintLog(taintLog);
  }

  return result;
}

/**
 * Prototype snapshot/detect/restore is provided by ../utils/prototype-monitor.js
 * (imported above) so the in-process oracle and the sandbox child process share
 * one implementation and cannot drift. It monitors Object, Function, Array, and
 * String prototypes and records key presence only — never reads property values,
 * which would throw on Function.prototype's poisoned `caller`/`arguments`
 * accessors under strict mode.
 */

/**
 * Execute with Object.prototype pollution active.
 * Uses snapshot-based detection to catch ANY new properties the target
 * introduces on Object.prototype (e.g. via _.merge deep merge PP).
 */
async function executePolluted(fn, args, pollutionDescriptor, timeoutMs = 5000) {
  const taintLog = [];
  const sinkAccesses = [];
  const result = {
    output: null, error: null, sinkAccesses, taintLog, taintAnalysis: null,
    pollutionWasRead: false,
    prototypePolluted: false,
    pollutedProperties: []
  };

  const trackedArgs = args.map(arg => {
    if (arg && typeof arg === 'object' && !Buffer.isBuffer(arg)) {
      try { return createTaintProxy(arg, taintLog); } catch { return arg; }
    }
    return arg;
  });

  const prop = pollutionDescriptor.property;
  const val = pollutionDescriptor.value;
  const hadProperty = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
  const originalValue = Object.prototype[prop];

  const snapshot = snapshotPrototype();

  // Context-aware getter trap: records when Object.prototype[prop] is read on
  // ANY object, and returns the MOST USEFUL value depending on read context.
  //
  // Problem: simple traps return a fixed value. But real gadgets may read the
  // same property twice:
  //   if (opts.debug) {           // 1st read: expects truthy
  //     const cmd = opts.debug;   // 2nd read: expects string
  //     eval(cmd);
  //   }
  //
  // Solution: first read returns the actual payload value. If the payload is a
  // string (RCE payload), the trap also satisfies boolean truthiness checks.
  // If the payload is boolean, we return it consistently.
  //
  // For extra coverage, the trap logs each read with a count so the analysis
  // layer can detect multi-read patterns.
  let trapFired = false;
  let trapReadCount = 0;
  let trapVal = val;

  try {
    try {
      Object.defineProperty(Object.prototype, prop, {
        get() {
          trapFired = true;
          trapReadCount++;
          // For RCE string payloads, they're already truthy (non-empty strings).
          // For boolean payloads, return as-is.
          // For function payloads, return as-is (truthy + callable).
          return trapVal;
        },
        set(v) { trapFired = true; trapVal = v; },
        configurable: true,
        enumerable: false,
      });
    } catch {
      // Property is non-configurable; fall back to simple assignment
      Object.prototype[prop] = val;
    }

    result.output = (await callAndAwaitReal(fn, trackedArgs, timeoutMs)).value;

    // Drain microtask queue: some libraries schedule reads via Promise.resolve().then()
    // or process.nextTick(). Without draining, the getter trap is torn down before the
    // async read fires, causing false negatives for async gadgets.
    // Two rounds of microtask drain catches .then().then() chains (depth 2).
    await new Promise(r => setTimeout(r, 0));
    await new Promise(r => setTimeout(r, 0));
  } catch (error) {
    result.error = error.message;
  } finally {
    // Restore: remove our descriptor, then reinstate original if it existed
    try { delete Object.prototype[prop]; } catch { /* sealed */ }
    if (hadProperty) {
      try { Object.prototype[prop] = originalValue; } catch { /* sealed */ }
    }

    // Detect any NEW properties the target added to Object.prototype
    const detection = detectAndRestorePrototype(snapshot);
    if (detection.polluted) {
      result.prototypePolluted = true;
      result.pollutedProperties = detection.newProps;
    }
  }

  if (taintLog.length > 0) {
    result.taintAnalysis = analyzeTaintLog(taintLog);
  }

  // Combine active trap signal with taint-proxy signal.
  // The active trap is the authoritative source: if it fired, the property was
  // definitely read via Object.prototype during execution.
  const taintSignal = taintLog.some(
    e => e.type === 'get' && e.property === prop && (e.isPrototypeChainLookup || e.isUOPCandidate)
  );
  result.pollutionWasRead = trapFired || taintSignal;
  result.trapReadCount = trapReadCount; // How many times the trap fired (multi-read detection)

  return result;
}

/**
 * Compare clean and polluted execution results.
 * Returns a differential result that confirms or rejects the gadget.
 */
function diffResults(cleanResult, pollutedResult, pollutionDescriptor) {
  const diff = {
    property: pollutionDescriptor.property,
    payload: pollutionDescriptor.value,
    outputChanged: false,
    errorChanged: false,
    newSinkAccesses: [],
    pollutionWasRead: pollutedResult.pollutionWasRead,
    prototypePolluted: pollutedResult.prototypePolluted || false,
    pollutedProperties: pollutedResult.pollutedProperties || [],
    isConfirmedGadget: false,
    confidence: 0,
    details: {}
  };

  // Compare outputs
  const cleanOutput = structuralSerialize(cleanResult.output);
  const pollutedOutput = structuralSerialize(pollutedResult.output);
  diff.outputChanged = cleanOutput !== pollutedOutput;

  if (diff.outputChanged) {
    diff.details.cleanOutput = cleanOutput?.substring(0, 500);
    diff.details.pollutedOutput = pollutedOutput?.substring(0, 500);
  }

  // Compare errors
  diff.errorChanged = cleanResult.error !== pollutedResult.error;
  if (diff.errorChanged) {
    diff.details.cleanError = cleanResult.error;
    diff.details.pollutedError = pollutedResult.error;
  }

  // Check for new sink accesses in polluted run
  const cleanSinkSet = new Set(cleanResult.sinkAccesses.map(s => s.sink));
  diff.newSinkAccesses = pollutedResult.sinkAccesses.filter(s => !cleanSinkSet.has(s.sink));

  // Check if polluted payload appears in output (data flow confirmation)
  const payloadStr = String(pollutionDescriptor.value);
  const payloadInOutput = pollutedOutput?.includes(payloadStr) &&
                          !cleanOutput?.includes(payloadStr);
  diff.details.payloadReachedOutput = payloadInOutput;

  // ── Tiering ──────────────────────────────────────────────────────────────
  //
  // The discovery oracle NO LONGER asserts a vulnerability from a behavioral
  // diff. It only proposes *reproduction candidates* with a `proofType` hint and
  // a `reproducible` flag; the independent reproduction harness
  // (src/verification/reproduce.js) is the sole confirmer. This kills the entire
  // Tier 3/4/5 false-positive class — reading a property, or output/error merely
  // changing, no longer flips a library to "VULNERABLE".
  //
  //   proofType 'pp'  → try to reproduce real Object.prototype mutation
  //   proofType 'rce' → try to reproduce real code execution (canary)
  //
  // The tier ladder is shared with the sandboxed oracle via classifyDiff() so
  // the two can never drift (invariant #4). `confidence` is retained for
  // ranking/effort ordering only.
  const verdict = classifyDiff({
    property: pollutionDescriptor.property,
    prototypePolluted: diff.prototypePolluted,
    pollutionWasRead: diff.pollutionWasRead,
    newSinkAccesses: diff.newSinkAccesses,
    payloadInOutput,
    outputChanged: diff.outputChanged,
    errorChanged: diff.errorChanged,
  });
  Object.assign(diff, verdict);

  return diff;
}

/**
 * Test whether the target function itself causes prototype pollution
 * when given crafted merge-payload arguments.
 *
 * This tests a fundamentally different attack vector than executeDifferential:
 * - executeDifferential: pre-pollutes Object.prototype, checks if behavior changes
 * - executeMergePPTest: passes crafted input, checks if Object.prototype is modified
 *
 * Covers attack patterns:
 * - _.merge({}, {__proto__: {prop: val}})
 * - _.merge({}, {constructor: {prototype: {prop: val}}})
 * - _.set(obj, '__proto__.prop', val)
 * - deepAssign({}, JSON.parse('{"__proto__":{"prop":"val"}}'))
 *
 * @param {Function} fn - Target function
 * @param {Array} baseArgs - Original arguments
 * @param {string} prop - Property name to test polluting
 * @param {*} val - Value to set
 * @param {number} timeoutMs
 * @returns {object|null} Differential result if PP detected
 */
export async function executeMergePPTest(fn, baseArgs, prop, val, timeoutMs = 5000) {
  // CRITICAL: { __proto__: {...} } as a JS literal sets the prototype chain,
  // it does NOT create an own property named "__proto__". Deep merge functions
  // like jQuery.extend iterate own properties, so they'd never see it.
  // JSON.parse creates a real own property named "__proto__" — this is how
  // real-world attacks work (attacker-controlled JSON from HTTP request body).
  const payloads = [
    JSON.parse(`{"__proto__":{"${prop}":${JSON.stringify(val)}}}`),
    { constructor: { prototype: { [prop]: val } } },
  ];

  // Try multiple calling conventions:
  // 1. fn({}, payload) — standard merge (lodash.merge, Object.assign wrappers)
  // 2. fn(true, {}, payload) — deep merge (jQuery.extend, deepmerge)
  // 3. fn('__proto__.' + prop, val) — path-based set (lodash.set)
  const argVariants = [
    baseArgs,                           // original: fn({}, payload)
    [true, ...baseArgs],                // deep copy: fn(true, {}, payload) — jQuery.extend
    [baseArgs[0] || {}, baseArgs[0] || {}],  // self-merge variant
  ];

  for (const payload of payloads) {
    for (const variant of argVariants) {
    const snapshot = snapshotPrototype();

    const args = variant.map((arg, i) => {
      if (arg && typeof arg === 'object') {
        try { return structuredClone(arg); } catch { return arg; }
      }
      return arg;
    });

    // Append payload to the end of args
    args.push(payload);

    logger.debug(`MergePP calling fn with ${args.length} args, payload keys: ${Object.keys(payload).join(',')}`);

    let timer;
    let output = null;
    let error = null;
    try {
      output = (await callAndAwaitReal(fn, args, timeoutMs)).value;
    } catch (e) {
      error = e.message;
      logger.debug(`MergePP execution error: ${error}`);
    } finally {
      clearTimeout(timer);
    }

    const detection = detectAndRestorePrototype(snapshot);
    logger.debug(`MergePP detection: polluted=${detection.polluted}, newProps=${detection.newProps.join(',')}`);

    if (detection.polluted) {
      const payloadType = payload.__proto__ ? '__proto__' : 'constructor.prototype';
      logger.debug(`MergePP detected pollution via ${payloadType}: ${detection.newProps.join(', ')}`);
      return {
        diff: {
          property: detection.newProps[0] || prop,
          payload: val,
          isConfirmedGadget: true,
          proofType: 'pp',
          reproducible: true,
          confidence: 0.95,
          prototypePolluted: true,
          pollutedProperties: detection.newProps,
          pollutionWasRead: false,
          outputChanged: false,
          errorChanged: false,
          newSinkAccesses: [],
          details: {
            payloadType,
            payloadReachedOutput: false
          }
        },
        output,
        error
      };
    }
    } // end argVariants loop
  }

  // Also try path-based set pattern: fn(obj, '__proto__.prop', val)
  const pathPayloads = [
    [`__proto__.${prop}`, val],
    [`constructor.prototype.${prop}`, val],
  ];
  for (const [pathStr, pathVal] of pathPayloads) {
    const snapshot = snapshotPrototype();
    let output = null;
    let error = null;
    let timer;
    try {
      output = (await callAndAwaitReal(fn, [{}, pathStr, pathVal], timeoutMs)).value;
    } catch (e) {
      error = e.message;
    } finally {
      clearTimeout(timer);
    }
    const detection = detectAndRestorePrototype(snapshot);
    if (detection.polluted) {
      const payloadType = pathStr.startsWith('__proto__') ? '__proto__path' : 'constructor.prototype.path';
      return {
        diff: {
          property: detection.newProps[0] || prop,
          payload: val,
          isConfirmedGadget: true,
          proofType: 'pp',
          reproducible: true,
          confidence: 0.95,
          prototypePolluted: true,
          pollutedProperties: detection.newProps,
          pollutionWasRead: false,
          outputChanged: false,
          errorChanged: false,
          newSinkAccesses: [],
          details: { payloadType, payloadReachedOutput: false }
        },
        output,
        error
      };
    }
  }

  return null;
}

/**
 * Test URL-based prototype pollution gadget chains.
 *
 * Simulates the attack: attacker crafts URL query string → parser produces
 * a nested object with __proto__ or constructor.prototype keys → target
 * function (merge/set/extend) pollutes Object.prototype.
 *
 * Generates exploit URLs like:
 *   http://localhost/?constructor[prototype][isAdmin]=true
 *   http://localhost/?__proto__[isAdmin]=true
 *
 * @param {Function} fn - Target function (e.g., lodash.merge)
 * @param {string} prop - Property name to pollute
 * @param {*} val - Value to set
 * @param {number} timeoutMs
 * @returns {object|null} Result with exploit URL if PP detected
 */
export async function executeURLGadgetTest(fn, prop, val, timeoutMs = 5000) {
  // Use JSON.parse for __proto__ payloads — JS literals set prototype chain,
  // not an own property. Real attacks use parsed JSON (from HTTP body/query).
  const valStr = JSON.stringify(val);
  const urlPayloads = [
    {
      url: `http://localhost/?__proto__[${encodeURIComponent(prop)}]=${encodeURIComponent(val)}`,
      object: JSON.parse(`{"__proto__":{"${prop}":${valStr}}}`),
      payloadType: 'url___proto__',
    },
    {
      url: `http://localhost/?constructor[prototype][${encodeURIComponent(prop)}]=${encodeURIComponent(val)}`,
      object: { constructor: { prototype: { [prop]: val } } },
      payloadType: 'url_constructor_prototype',
    },
    {
      url: `http://localhost/?${encodeURIComponent(prop)}[__proto__][${encodeURIComponent(prop)}]=${encodeURIComponent(val)}`,
      object: JSON.parse(`{"${prop}":{"__proto__":{"${prop}":${valStr}}}}`),
      payloadType: 'url_nested___proto__',
    },
    {
      url: `http://localhost/?a[__proto__][${encodeURIComponent(prop)}]=${encodeURIComponent(val)}`,
      object: JSON.parse(`{"a":{"__proto__":{"${prop}":${valStr}}}}`),
      payloadType: 'url_wrapped___proto__',
    },
  ];

  // Try both shallow and deep merge calling conventions
  const callVariants = [
    (target, payload) => fn(target, payload),           // fn({}, payload) — standard merge
    (target, payload) => fn(true, target, payload),     // fn(true, {}, payload) — deep merge (jQuery.extend)
  ];

  for (const { url, object: payload, payloadType } of urlPayloads) {
    for (const callFn of callVariants) {
    const snapshot = snapshotPrototype();

    let output = null;
    let error = null;
    let timer;
    try {
      output = (await callAndAwaitReal(callFn, [{}, payload], timeoutMs)).value;
    } catch (e) {
      error = e.message;
    } finally {
      clearTimeout(timer);
    }

    const detection = detectAndRestorePrototype(snapshot);

    if (detection.polluted) {
      logger.debug(`URL gadget confirmed via ${payloadType}: ${detection.newProps.join(', ')}`);
      return {
        diff: {
          property: detection.newProps[0] || prop,
          payload: val,
          isConfirmedGadget: true,
          proofType: 'pp',
          reproducible: true,
          confidence: 0.95,
          prototypePolluted: true,
          pollutedProperties: detection.newProps,
          pollutionWasRead: false,
          outputChanged: false,
          errorChanged: false,
          newSinkAccesses: [],
          details: {
            payloadType,
            payloadReachedOutput: false,
            exploitURL: url,
          }
        },
        output,
        error,
      };
    }
    } // end callVariants loop
  }

  return null;
}

/**
 * Run the full differential oracle for one pollution descriptor.
 *
 * @param {Function} fn - The function to call (or a thunk that executes a sequence)
 * @param {Array} args - Arguments to pass
 * @param {object} pollutionDescriptor - { property, value }
 * @returns {object} Differential result with confirmation/rejection
 */
export async function executeDifferential(fn, args, pollutionDescriptor, timeoutMs = 5000) {
  const cleanResult = await executeClean(fn, args, timeoutMs);
  const pollutedResult = await executePolluted(fn, args, pollutionDescriptor, timeoutMs);
  const diff = diffResults(cleanResult, pollutedResult, pollutionDescriptor);

  return {
    clean: cleanResult,
    polluted: pollutedResult,
    diff
  };
}

/**
 * Forced Branch Execution — inspired by Dasty (KTH, WWW 2024).
 *
 * Many gadgets are guarded by boolean checks:
 *   if (opts.debug) { eval(opts.template); }
 *
 * Normal differential testing misses these because the gate property (debug)
 * is falsy in clean execution, so the sink (eval) is never reached.
 *
 * Solution: co-pollute known "gate" properties (debug, verbose, cache, strict,
 * client, etc.) with `true` alongside the actual payload property. This forces
 * guarded branches open, exposing sinks that normal execution never reaches.
 *
 * Dasty found 67 additional exploitable packages using this technique.
 *
 * @param {Function} fn - Entry point function
 * @param {Array} args - Arguments
 * @param {object} pollutionDescriptor - { property, value } — the payload
 * @param {number} timeoutMs
 * @returns {object} Differential result with forced branch info
 */
export async function executeForcedBranchDifferential(fn, args, pollutionDescriptor, timeoutMs = 5000) {
  const cleanResult = await executeClean(fn, args, timeoutMs);

  // Polluted execution with GATE PROPERTIES forced to true
  const taintLog = [];
  const sinkAccesses = [];
  const result = {
    output: null, error: null, sinkAccesses, taintLog, taintAnalysis: null,
    pollutionWasRead: false,
    prototypePolluted: false,
    pollutedProperties: [],
    forcedGates: [],
  };

  const trackedArgs = args.map(arg => {
    if (arg && typeof arg === 'object' && !Buffer.isBuffer(arg)) {
      try { return createTaintProxy(arg, taintLog); } catch { return arg; }
    }
    return arg;
  });

  const prop = pollutionDescriptor.property;
  const val = pollutionDescriptor.value;
  const snapshot = snapshotPrototype();

  // Track all installed traps for cleanup
  const installedTraps = new Map(); // property -> { hadProperty, originalValue }

  let timer;
  try {
    // Install the main payload trap
    const mainTrap = installTrap(prop, val);
    installedTraps.set(prop, mainTrap);

    // Force all gate properties to `true` (except the payload property itself)
    for (const gate of GATE_PROPERTIES) {
      if (gate === prop) continue; // Don't override the actual payload
      const gateTrap = installTrap(gate, true);
      installedTraps.set(gate, gateTrap);
      result.forcedGates.push(gate);
    }

    result.output = (await callAndAwaitReal(fn, trackedArgs, timeoutMs)).value;

    // Drain microtask queue
    await new Promise(r => setTimeout(r, 0));
    await new Promise(r => setTimeout(r, 0));
  } catch (error) {
    result.error = error.message;
  } finally {
    clearTimeout(timer);

    // Restore all traps
    for (const [trapProp, state] of installedTraps) {
      try { delete Object.prototype[trapProp]; } catch { /* sealed */ }
      if (state.hadProperty) {
        try { Object.prototype[trapProp] = state.originalValue; } catch { /* sealed */ }
      }
    }

    const detection = detectAndRestorePrototype(snapshot);
    if (detection.polluted) {
      result.prototypePolluted = true;
      result.pollutedProperties = detection.newProps;
    }
  }

  // Check which traps fired
  const mainState = installedTraps.get(prop);
  result.pollutionWasRead = mainState?.fired || false;
  result.forcedGatesFired = [...installedTraps.entries()]
    .filter(([p, s]) => p !== prop && s.fired)
    .map(([p]) => p);

  if (taintLog.length > 0) {
    result.taintAnalysis = analyzeTaintLog(taintLog);
  }

  const diff = diffResults(cleanResult, result, pollutionDescriptor);
  diff.details.forcedBranch = true;
  diff.details.forcedGates = result.forcedGates;
  diff.details.forcedGatesFired = result.forcedGatesFired;

  return { clean: cleanResult, polluted: result, diff };
}

/** Install a getter/setter trap on Object.prototype and return cleanup state. */
function installTrap(prop, val) {
  const hadProperty = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
  const originalValue = Object.prototype[prop];
  const state = { hadProperty, originalValue, fired: false, trapVal: val };

  try {
    Object.defineProperty(Object.prototype, prop, {
      get() { state.fired = true; return state.trapVal; },
      set(v) { state.fired = true; state.trapVal = v; },
      configurable: true,
      enumerable: false,
    });
  } catch {
    Object.prototype[prop] = val;
  }

  return state;
}

/**
 * Multi-property co-pollution differential test.
 *
 * Some gadgets require two or more Object.prototype properties to be polluted
 * simultaneously (e.g., `if (opts.debug) eval(opts.template)`).
 * Single-property testing misses these because neither property alone triggers
 * the dangerous path.
 *
 * @param {Function} fn - Entry point function
 * @param {Array} args - Arguments
 * @param {Array<{property: string, value: any}>} descriptors - Properties to co-pollute
 * @param {number} timeoutMs
 * @returns {object} Differential result
 */
export async function executeMultiPropertyDifferential(fn, args, descriptors, timeoutMs = 5000) {
  const cleanResult = await executeClean(fn, args, timeoutMs);

  // Polluted execution: set ALL descriptors on Object.prototype simultaneously
  const taintLog = [];
  const sinkAccesses = [];
  const result = {
    output: null, error: null, sinkAccesses, taintLog, taintAnalysis: null,
    pollutionWasRead: false,
    prototypePolluted: false,
    pollutedProperties: []
  };

  const trackedArgs = args.map(arg => {
    if (arg && typeof arg === 'object' && !Buffer.isBuffer(arg)) {
      try { return createTaintProxy(arg, taintLog); } catch { return arg; }
    }
    return arg;
  });

  const snapshot = snapshotPrototype();
  const traps = new Map(); // property -> { hadProp, origVal, trapFired }

  let timer;
  try {
    // Install getter traps for ALL properties simultaneously
    for (const desc of descriptors) {
      const prop = desc.property;
      const val = desc.value;
      const hadProperty = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
      const originalValue = Object.prototype[prop];
      const trapState = { hadProperty, originalValue, fired: false, trapVal: val };
      traps.set(prop, trapState);

      try {
        Object.defineProperty(Object.prototype, prop, {
          get() { trapState.fired = true; return trapState.trapVal; },
          set(v) { trapState.fired = true; trapState.trapVal = v; },
          configurable: true,
          enumerable: false,
        });
      } catch {
        Object.prototype[prop] = val;
      }
    }

    result.output = (await callAndAwaitReal(fn, trackedArgs, timeoutMs)).value;
  } catch (error) {
    result.error = error.message;
  } finally {
    clearTimeout(timer);

    // Restore all properties
    for (const [prop, state] of traps) {
      try { delete Object.prototype[prop]; } catch { /* sealed */ }
      if (state.hadProperty) {
        try { Object.prototype[prop] = state.originalValue; } catch { /* sealed */ }
      }
    }

    const detection = detectAndRestorePrototype(snapshot);
    if (detection.polluted) {
      result.prototypePolluted = true;
      result.pollutedProperties = detection.newProps;
    }
  }

  const firedProps = [...traps.entries()].filter(([, s]) => s.fired).map(([p]) => p);
  result.pollutionWasRead = firedProps.length > 0;

  // Build a combined descriptor for diff comparison
  const combinedDescriptor = {
    property: descriptors.map(d => d.property).join('+'),
    value: descriptors.map(d => `${d.property}=${String(d.value).substring(0, 30)}`).join(', '),
  };

  const diff = diffResults(cleanResult, result, combinedDescriptor);
  diff.details.firedProperties = firedProps;
  diff.details.coPolluteCount = descriptors.length;

  return { clean: cleanResult, polluted: result, diff };
}

/**
 * Discover which properties a library reads as undefined (UOP candidates).
 * Run a clean execution and collect all property accesses that resolved to undefined.
 * These are the properties an attacker could control via Object.prototype pollution.
 *
 * @param {Function} fn - Entry point function
 * @param {Array} args - Arguments
 * @returns {string[]} Property names that are UOP candidates
 */
export async function discoverUOPProperties(fn, args, timeoutMs = 5000) {
  const taintLog = [];

  const trackedArgs = args.map(arg => {
    if (arg && typeof arg === 'object' && !Buffer.isBuffer(arg)) {
      try { return createTaintProxy(arg, taintLog); } catch { return arg; }
    }
    return arg;
  });

  let timer;
  try {
    await callAndAwaitReal(fn, trackedArgs, timeoutMs);
  } catch {
    // Errors are expected - we just want the taint log
  } finally {
    clearTimeout(timer);
  }

  // Extract unique property names that were read as undefined
  const uopProps = new Set();
  for (const event of taintLog) {
    if (event.type === 'get' && event.isUOPCandidate && typeof event.property === 'string') {
      // Filter out internal/noise properties
      if (!event.property.startsWith('__') && event.property !== 'constructor' &&
          event.property !== 'prototype' && event.property.length > 1) {
        uopProps.add(event.property);
      }
    }
  }

  return [...uopProps];
}
