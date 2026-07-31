/**
 * Proxy-Based Deep Taint Tracking
 *
 * Uses ES6 Proxy to intercept ALL property access on objects,
 * not just hasOwnProperty/getOwnPropertyDescriptor calls.
 *
 * This captures the fundamental operation that prototype pollution
 * exploits: when code reads `obj.prop` and `prop` doesn't exist on
 * `obj`, JavaScript traverses the prototype chain. A Proxy intercepts
 * this at the language level, catching every single property read.
 *
 * Why this matters vs. the old approach:
 * - Old: Hooked Object.prototype.hasOwnProperty - only catches explicit
 *   ownership checks, which most code doesn't do
 * - New: Proxy.get trap fires on EVERY `.property` access - this is
 *   how real code actually reads properties
 *
 * The taint log records a complete data-flow trace that can identify:
 * 1. Source: Where tainted (polluted) data enters
 * 2. Propagation: How it flows through property accesses
 * 3. Sink: Where it reaches a dangerous function
 * 4. UOP Pattern: Properties read as undefined (prototype chain fallthrough)
 */

// Symbol to mark objects as tainted (invisible to normal code)
const TAINT_MARKER = Symbol('taint');
const TAINT_LOG = Symbol('taintLog');

// Cap log growth: a library reading a proxied object in a hot loop would
// otherwise grow the log (and the trace built from it) without bound.
const MAX_TAINT_LOG = 100000;
function pushTaintEvent(log, event) {
  if (log.length < MAX_TAINT_LOG) log.push(event);
}

/**
 * Create a deeply tainted proxy around an object.
 * Every property access, set, has-check, and delete is logged.
 *
 * @param {object} target - The object to wrap
 * @param {Array} log - Mutable array to append taint events to
 * @param {string} rootPath - Path prefix for nested tracking
 * @returns {Proxy} Tainted proxy object
 */
export function createTaintProxy(target, log, rootPath = '$') {
  if (target === null || typeof target !== 'object') {
    return target; // Primitives can't be proxied
  }

  // Don't double-wrap
  if (target[TAINT_MARKER]) return target;

  // Track type coercion — when a library does String(obj), obj + '', etc.
  // these implicit calls are security-relevant: polluted toString/valueOf
  // can inject attacker strings into eval/template/URL contexts.
  const COERCION_TRAPS = new Set(['toString', 'valueOf', 'toJSON', Symbol.toPrimitive]);

  const proxy = new Proxy(target, {
    get(obj, prop, receiver) {
      // Internal markers bypass logging
      if (prop === TAINT_MARKER) return true;
      if (prop === TAINT_LOG) return log;
      // Symbol.toPrimitive IS security-relevant — log it
      if (typeof prop === 'symbol' && prop !== Symbol.toPrimitive && prop !== Symbol.iterator) {
        return Reflect.get(obj, prop, receiver);
      }

      const propStr = typeof prop === 'symbol' ? prop.toString() : String(prop);
      const fullPath = `${rootPath}.${propStr}`;
      const exists = Object.prototype.hasOwnProperty.call(obj, prop);
      const value = Reflect.get(obj, prop, receiver);

      const isCoercion = COERCION_TRAPS.has(prop);

      pushTaintEvent(log, {
        type: 'get',
        path: fullPath,
        property: propStr,
        exists,
        valueType: value === null ? 'null' : typeof value,
        isUndefined: value === undefined,
        isCoercion,
        // UOP indicator: property doesn't exist on own object,
        // so JS would fall through to prototype chain
        isPrototypeChainLookup: !exists && value !== undefined,
        // Pure UOP: doesn't exist anywhere
        isUOPCandidate: !exists && value === undefined,
        timestamp: Date.now()
      });

      // Recursively proxy nested objects for deep tracking
      if (value !== null && typeof value === 'object') {
        return createTaintProxy(value, log, fullPath);
      }

      return value;
    },

    set(obj, prop, value) {
      const fullPath = `${rootPath}.${String(prop)}`;
      if (typeof prop !== 'symbol') {
        pushTaintEvent(log, {
          type: 'set',
          path: fullPath,
          property: String(prop),
          valueType: value === null ? 'null' : typeof value,
          timestamp: Date.now()
        });
      }
      return Reflect.set(obj, prop, value);
    },

    has(obj, prop) {
      const fullPath = `${rootPath}.${String(prop)}`;
      const result = Reflect.has(obj, prop);
      if (typeof prop !== 'symbol') {
        pushTaintEvent(log, {
          type: 'has',
          path: fullPath,
          property: String(prop),
          result,
          timestamp: Date.now()
        });
      }
      return result;
    },

    deleteProperty(obj, prop) {
      const fullPath = `${rootPath}.${String(prop)}`;
      if (typeof prop !== 'symbol') {
        pushTaintEvent(log, {
          type: 'delete',
          path: fullPath,
          property: String(prop),
          timestamp: Date.now()
        });
      }
      return Reflect.deleteProperty(obj, prop);
    },

    getPrototypeOf(obj) {
      pushTaintEvent(log, {
        type: 'getPrototypeOf',
        path: rootPath,
        timestamp: Date.now()
      });
      return Reflect.getPrototypeOf(obj);
    },

    setPrototypeOf(obj, proto) {
      pushTaintEvent(log, {
        type: 'setPrototypeOf',
        path: rootPath,
        protoType: proto?.constructor?.name || 'null',
        timestamp: Date.now()
      });
      return Reflect.setPrototypeOf(obj, proto);
    },

    ownKeys(obj) {
      pushTaintEvent(log, {
        type: 'ownKeys',
        path: rootPath,
        keys: Reflect.ownKeys(obj).filter(k => typeof k === 'string'),
        timestamp: Date.now()
      });
      return Reflect.ownKeys(obj);
    },

    getOwnPropertyDescriptor(obj, prop) {
      const fullPath = `${rootPath}.${String(prop)}`;
      if (typeof prop !== 'symbol') {
        pushTaintEvent(log, {
          type: 'getOwnPropertyDescriptor',
          path: fullPath,
          property: String(prop),
          exists: Object.prototype.hasOwnProperty.call(obj, prop),
          timestamp: Date.now()
        });
      }
      return Reflect.getOwnPropertyDescriptor(obj, prop);
    },

    // apply trap: fires when the proxied object is called as a function.
    // Catches polluted callback/handler properties being invoked.
    ...(typeof target === 'function' ? {
      apply(fn, thisArg, argsList) {
        pushTaintEvent(log, {
          type: 'apply',
          path: rootPath,
          argsCount: argsList.length,
          timestamp: Date.now()
        });
        return Reflect.apply(fn, thisArg, argsList);
      },
      construct(fn, argsList, newTarget) {
        pushTaintEvent(log, {
          type: 'construct',
          path: rootPath,
          argsCount: argsList.length,
          timestamp: Date.now()
        });
        return Reflect.construct(fn, argsList, newTarget);
      }
    } : {})
  });

  return proxy;
}

/**
 * Analyze a taint log to extract security-relevant patterns.
 *
 * Identifies:
 * - UOP candidates: properties accessed that don't exist (proto fallthrough)
 * - Taint flows: source -> propagation -> sink paths
 * - Gadget indicators: patterns matching known PP gadget shapes
 *
 * @param {Array} log - Taint events from createTaintProxy
 * @returns {object} Analysis results
 */
export function analyzeTaintLog(log) {
  const uopCandidates = [];
  const prototypeChainLookups = [];
  const propertyWriteAfterRead = [];
  const coercionFlows = [];
  const functionInvocations = [];
  const accessFrequency = new Map();
  let totalAccesses = 0;

  // Single pass: collect all analysis results together
  for (let i = 0; i < log.length; i++) {
    const event = log[i];

    if (event.type === 'get') {
      // Track access frequency inline
      const count = (accessFrequency.get(event.property) || 0) + 1;
      accessFrequency.set(event.property, count);
      totalAccesses++;

      // UOP: reading a property that doesn't exist
      if (event.isUOPCandidate) {
        uopCandidates.push({
          path: event.path,
          property: event.property,
          timestamp: event.timestamp
        });

        // Pattern: read undefined property, then write to it later
        // Common gadget pattern: if (!obj.prop) obj.prop = default
        const end = Math.min(i + 20, log.length);
        for (let j = i + 1; j < end; j++) {
          if (log[j].type === 'set' && log[j].property === event.property) {
            propertyWriteAfterRead.push({
              readPath: event.path,
              writePath: log[j].path,
              property: event.property,
              readTimestamp: event.timestamp,
              writeTimestamp: log[j].timestamp
            });
            break;
          }
        }
      }

      // Prototype chain lookup
      if (event.isPrototypeChainLookup) {
        prototypeChainLookups.push({
          path: event.path,
          property: event.property,
          valueType: event.valueType,
          timestamp: event.timestamp
        });
      }

      // Type coercion detection: toString/valueOf/toJSON/Symbol.toPrimitive
      // When a library coerces a tainted object to a string, the resulting
      // string flows into whatever context requested the coercion (template
      // interpolation, URL construction, SQL query, etc.)
      if (event.isCoercion) {
        coercionFlows.push({
          path: event.path,
          property: event.property,
          timestamp: event.timestamp
        });
      }
    }

    // Track function invocations on proxied objects — detects when a
    // polluted callback/handler is actually called
    if (event.type === 'apply') {
      functionInvocations.push({
        path: event.path,
        argsCount: event.argsCount,
        timestamp: event.timestamp
      });
    }
  }

  // Compute Shannon entropy in single pass over frequency map
  let accessEntropy = 0;
  if (totalAccesses > 0) {
    for (const count of accessFrequency.values()) {
      const p = count / totalAccesses;
      if (p > 0) accessEntropy -= p * Math.log2(p);
    }
  }

  return {
    totalEvents: log.length,
    uopCandidates,
    prototypeChainLookups,
    propertyWriteAfterRead,
    coercionFlows,
    functionInvocations,
    accessEntropy,
    uniquePropertiesAccessed: accessFrequency.size,
    accessFrequency: Object.fromEntries(accessFrequency)
  };
}
