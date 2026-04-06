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
 * Execute with Object.prototype pollution active.
 * The pollution is applied globally and cleaned up after.
 */
async function executePolluted(fn, args, pollutionDescriptor, timeoutMs = 5000) {
  const taintLog = [];
  const sinkAccesses = [];
  const result = {
    output: null, error: null, sinkAccesses, taintLog, taintAnalysis: null,
    pollutionWasRead: false
  };

  const trackedArgs = args.map(arg => {
    if (arg && typeof arg === 'object' && !Buffer.isBuffer(arg)) {
      try { return createTaintProxy(arg, taintLog); } catch { return arg; }
    }
    return arg;
  });

  // Apply real Object.prototype pollution
  const prop = pollutionDescriptor.property;
  const val = pollutionDescriptor.value;
  const hadProperty = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
  const originalValue = Object.prototype[prop];

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
    // Always clean up — never leave Object.prototype polluted
    if (hadProperty) {
      Object.prototype[prop] = originalValue;
    } else {
      delete Object.prototype[prop];
    }
  }

  if (taintLog.length > 0) {
    result.taintAnalysis = analyzeTaintLog(taintLog);
    // Check if the polluted property was actually read via prototype chain
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

  // Determine if this is a confirmed gadget
  // Tier 1: New sink access caused by pollution = high confidence
  if (diff.newSinkAccesses.length > 0 && diff.pollutionWasRead) {
    diff.isConfirmedGadget = true;
    diff.confidence = 0.95;
  }
  // Tier 2: Payload reached output = confirmed data flow
  else if (payloadInOutput && diff.pollutionWasRead) {
    diff.isConfirmedGadget = true;
    diff.confidence = 0.90;
  }
  // Tier 3: Output changed and property was read = likely gadget
  else if (diff.outputChanged && diff.pollutionWasRead) {
    diff.isConfirmedGadget = true;
    diff.confidence = 0.75;
  }
  // Tier 4: Error changed and property was read = possible gadget
  else if (diff.errorChanged && diff.pollutionWasRead) {
    diff.isConfirmedGadget = true;
    diff.confidence = 0.60;
  }
  // Tier 5: Property was read but no observable difference
  else if (diff.pollutionWasRead) {
    diff.confidence = 0.30;
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
