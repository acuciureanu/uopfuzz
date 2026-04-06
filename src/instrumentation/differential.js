import { createTaintProxy, analyzeTaintLog } from '../utils/taint-proxy.js';
import { logger } from '../utils/logger.js';

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

  let timer;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Execution timeout')), timeoutMs);
    });
    const execution = Promise.resolve(fn(...trackedArgs));
    result.output = await Promise.race([execution, timeout]);
  } catch (error) {
    result.error = error.message;
  } finally {
    clearTimeout(timer);
  }

  if (taintLog.length > 0) {
    result.taintAnalysis = analyzeTaintLog(taintLog);
  }

  return result;
}

/**
 * Snapshot all own properties of Object.prototype.
 * Returns a Map<propertyName, {had: boolean, value: any}>.
 */
function snapshotPrototype() {
  const snap = new Map();
  for (const key of Object.getOwnPropertyNames(Object.prototype)) {
    snap.set(key, { had: true, value: Object.prototype[key] });
  }
  return snap;
}

/**
 * Detect and clean up any properties added to Object.prototype since snapshot.
 * Returns { polluted: boolean, newProps: string[] }.
 */
function detectAndRestorePrototype(snapshot) {
  let polluted = false;
  const newProps = [];

  for (const key of Object.getOwnPropertyNames(Object.prototype)) {
    if (!snapshot.has(key)) {
      polluted = true;
      newProps.push(key);
      try { delete Object.prototype[key]; } catch { /* sealed */ }
    }
  }

  return { polluted, newProps };
}

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

  let timer;
  try {
    Object.prototype[prop] = val;

    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Execution timeout')), timeoutMs);
    });
    const execution = Promise.resolve(fn(...trackedArgs));
    result.output = await Promise.race([execution, timeout]);
  } catch (error) {
    result.error = error.message;
  } finally {
    clearTimeout(timer);

    // Restore our pre-set pollution first
    if (hadProperty) {
      Object.prototype[prop] = originalValue;
    } else {
      delete Object.prototype[prop];
    }

    // Detect any NEW properties the target added to Object.prototype
    const detection = detectAndRestorePrototype(snapshot);
    if (detection.polluted) {
      result.prototypePolluted = true;
      result.pollutedProperties = detection.newProps;
    }

    // Also detect if the target changed the value of our pre-set property
    // (means it wrote to Object.prototype[prop] itself)
    const currentVal = Object.prototype[prop];
    if (hadProperty) {
      if (currentVal !== originalValue) {
        result.prototypePolluted = true;
        if (!result.pollutedProperties.includes(prop)) {
          result.pollutedProperties.push(prop);
        }
        Object.prototype[prop] = originalValue;
      }
    } else {
      if (Object.prototype.hasOwnProperty.call(Object.prototype, prop)) {
        result.prototypePolluted = true;
        if (!result.pollutedProperties.includes(prop)) {
          result.pollutedProperties.push(prop);
        }
        delete Object.prototype[prop];
      }
    }
  }

  if (taintLog.length > 0) {
    result.taintAnalysis = analyzeTaintLog(taintLog);
    result.pollutionWasRead = taintLog.some(
      e => e.type === 'get' && e.property === prop && (e.isPrototypeChainLookup || e.isUOPCandidate)
    );
  }

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
  const cleanOutput = normalizeOutput(cleanResult.output);
  const pollutedOutput = normalizeOutput(pollutedResult.output);
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

  // Tier 0: Actual Object.prototype was modified = confirmed pollution source
  if (diff.prototypePolluted) {
    diff.isConfirmedGadget = true;
    diff.confidence = Math.max(diff.confidence, 0.85);
  }

  // Tier 1: New sink access caused by pollution = high confidence
  if (diff.newSinkAccesses.length > 0 && diff.pollutionWasRead) {
    diff.isConfirmedGadget = true;
    diff.confidence = Math.max(diff.confidence, 0.95);
  }
  // Tier 2: Payload reached output = confirmed data flow
  else if (payloadInOutput && diff.pollutionWasRead) {
    diff.isConfirmedGadget = true;
    diff.confidence = Math.max(diff.confidence, 0.90);
  }
  // Tier 3: Output changed and property was read = likely gadget
  else if (diff.outputChanged && diff.pollutionWasRead) {
    diff.isConfirmedGadget = true;
    diff.confidence = Math.max(diff.confidence, 0.75);
  }
  // Tier 4: Error changed and property was read = possible gadget
  else if (diff.errorChanged && diff.pollutionWasRead) {
    diff.isConfirmedGadget = true;
    diff.confidence = Math.max(diff.confidence, 0.60);
  }
  // Tier 5: Property was read via prototype chain (gadget read)
  else if (pollutedResult.pollutionWasRead) {
    diff.confidence = Math.max(diff.confidence, 0.40);
  }

  return diff;
}

function normalizeOutput(output) {
  if (output === null || output === undefined) return '';
  if (typeof output === 'string') return output;
  if (typeof output === 'function') return '[function]';
  try { return JSON.stringify(output); } catch { return String(output); }
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
  const payloads = [
    { __proto__: { [prop]: val } },
    { constructor: { prototype: { [prop]: val } } },
  ];

  for (const payload of payloads) {
    const snapshot = snapshotPrototype();

    const args = baseArgs.map((arg, i) => {
      if (i === 0 && arg && typeof arg === 'object') {
        try { return structuredClone(arg); } catch { return arg; }
      }
      return arg;
    });

    if (args.length > 1 && args[1] && typeof args[1] === 'object') {
      Object.assign(args[1], payload);
    } else {
      args.push(payload);
    }

    logger.debug(`MergePP calling fn with ${args.length} args, payload keys: ${Object.keys(payload).join(',')}`);

    let timer;
    let output = null;
    let error = null;
    try {
      const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Execution timeout')), timeoutMs);
      });
      output = await Promise.race([Promise.resolve(fn(...args)), timeoutPromise]);
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
  const urlPayloads = [
    {
      url: `http://localhost/?__proto__[${encodeURIComponent(prop)}]=${encodeURIComponent(val)}`,
      object: { __proto__: { [prop]: val } },
      payloadType: 'url___proto__',
    },
    {
      url: `http://localhost/?constructor[prototype][${encodeURIComponent(prop)}]=${encodeURIComponent(val)}`,
      object: { constructor: { prototype: { [prop]: val } } },
      payloadType: 'url_constructor_prototype',
    },
    {
      url: `http://localhost/?${encodeURIComponent(prop)}[__proto__][${encodeURIComponent(prop)}]=${encodeURIComponent(val)}`,
      object: (() => { const o = {}; o[prop] = { __proto__: { [prop]: val } }; return o; })(),
      payloadType: 'url_nested___proto__',
    },
    {
      url: `http://localhost/?a[__proto__][${encodeURIComponent(prop)}]=${encodeURIComponent(val)}`,
      object: { a: { __proto__: { [prop]: val } } },
      payloadType: 'url_wrapped___proto__',
    },
  ];

  for (const { url, object: payload, payloadType } of urlPayloads) {
    const snapshot = snapshotPrototype();

    let output = null;
    let error = null;
    let timer;
    try {
      const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Execution timeout')), timeoutMs);
      });
      output = await Promise.race([Promise.resolve(fn({}, payload)), timeoutPromise]);
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
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Execution timeout')), timeoutMs);
    });
    await Promise.race([Promise.resolve(fn(...trackedArgs)), timeout]);
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
