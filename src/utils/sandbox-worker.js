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
const require = createRequire(import.meta.url);

// ─── SECURITY: Network blocking ──────────────────────────────
if (process.env.UOPFUZZ_BLOCK_NETWORK === '1') {
  try {
    const net = require('net');
    const originalConnect = net.Socket.prototype.connect;
    net.Socket.prototype.connect = function (...args) {
      const err = new Error('Network access blocked by UoPFuzz sandbox');
      err.code = 'ENETBLOCKED';
      this.destroy(err);
      return this;
    };

    // Also block dgram (UDP)
    try {
      const dgram = require('dgram');
      const originalBind = dgram.Socket.prototype.bind;
      dgram.Socket.prototype.bind = function () {
        throw new Error('Network access blocked by UoPFuzz sandbox');
      };
    } catch { /* dgram not available */ }
  } catch (err) {
    // If we can't block network, log and continue
    process.stderr.write(`Warning: Could not block network: ${err.message}\n`);
  }
}

// ─── SECURITY: Restrict dangerous process methods ────────────
const originalExit = process.exit;
process.exit = function (code) {
  // Don't let target code kill our process — send result instead
  process.send?.({
    error: `Target called process.exit(${code})`,
    output: null,
    exitAttempt: true,
  });
  // Actually exit after sending
  originalExit.call(process, 0);
};

// Prevent target from spawning child processes
try {
  const cp = require('child_process');
  for (const method of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
    if (cp[method]) {
      cp[method] = function () {
        throw new Error(`child_process.${method} blocked by UoPFuzz sandbox`);
      };
    }
  }
} catch { /* child_process not available */ }

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

// ─── MESSAGE HANDLER ─────────────────────────────────────────
process.on('message', async (msg) => {
  const { mode, packageName, entryPoint, args, timeoutMs, pollution } = msg;

  // Self-enforced timeout as backup
  const killTimer = setTimeout(() => {
    process.send?.({ error: 'Self-timeout reached', output: null, timedOut: true });
    process.exit(0);
  }, (timeoutMs || 5000) + 500);

  try {
    const result = await executeRequest(mode, packageName, entryPoint, args, timeoutMs, pollution);
    clearTimeout(killTimer);
    process.send?.(result);
  } catch (error) {
    clearTimeout(killTimer);
    process.send?.({
      error: error.message,
      stack: error.stack,
      output: null,
    });
  }

  // Exit cleanly after responding
  process.exit(0);
});

async function executeRequest(mode, packageName, entryPoint, args, timeoutMs, pollution) {
  // Load the target package
  let targetModule;
  try {
    targetModule = await import(packageName);
  } catch {
    try {
      targetModule = require(packageName);
    } catch (err) {
      return { error: `Cannot load package ${packageName}: ${err.message}`, output: null };
    }
  }

  // Resolve the entry point function
  const fn = resolveEntryPoint(targetModule, entryPoint, packageName);
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

    case 'discover_uop':
      return await discoverUOP(fn, realArgs, timeoutMs);

    case 'merge_pp':
      return await mergePPTest(fn, realArgs, pollution, timeoutMs);

    default:
      return { error: `Unknown mode: ${mode}`, output: null };
  }
}

async function executeCall(fn, args, timeoutMs) {
  let timer;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('Execution timeout')), timeoutMs);
    });
    const output = await Promise.race([Promise.resolve(fn(...args)), timeout]);
    return {
      output: safeSerialize(output),
      error: null,
    };
  } catch (error) {
    return { output: null, error: error.message };
  } finally {
    clearTimeout(timer);
  }
}

async function executeDifferential(fn, args, pollution, timeoutMs) {
  if (!pollution) return { error: 'No pollution descriptor', output: null };

  // Clean execution
  let cleanOutput, cleanError;
  const cleanStartTime = Date.now();
  sinkLog.length = 0; // Clear any previous sink logs
  try {
    cleanOutput = safeSerialize(await withTimeout(fn(...args), timeoutMs));
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
        enumerable: false,
      });
    } catch {
      // Property may be non-configurable; fall back to simple assignment
      Object.prototype[prop] = val;
    }
    pollutedOutput = safeSerialize(await withTimeout(fn(...args), timeoutMs));
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
    await withTimeout(fn(...trackedArgs), timeoutMs);
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
    protoPayload = JSON.parse(`{"__proto__":{"${prop}":${JSON.stringify(val)}}}`);
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
      await withTimeout(Promise.resolve(fn(...callArgs)), timeoutMs);
    } catch { /* expected */ }

    const detection = detectAndRestorePrototype(snapshot);
    if (detection.polluted) {
      return { pollutionDetected: true, pollutedProperties: detection.newProps };
    }
  }

  return { pollutionDetected: false };
}

function withTimeout(promise, ms) {
  let timer;
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('timeout')), ms);
    })
  ]).finally(() => clearTimeout(timer));
}

function resolveEntryPoint(module, name, packageName) {
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
  // Bare-function module: `module.exports = fn` (merge-deep, deep-extend, …).
  // Only fall back to the module itself when `name` IS the package's own name —
  // never as a catch-all for an unrelated or nonexistent entry point name.
  if (name === packageName) {
    if (typeof module === 'function') return module;
    if (typeof module.default === 'function') return module.default;
  }
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

function safeSerialize(value) {
  if (value === null || value === undefined) return String(value);
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (typeof value === 'function') return '[function]';
  try { return JSON.stringify(value); } catch { return String(value); }
}
