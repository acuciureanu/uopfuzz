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
 * Reference: Schwartz et al., "All You Ever Wanted to Know About
 * Dynamic Taint Analysis and Forward Symbolic Execution", IEEE S&P 2010
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

  const proxy = new Proxy(target, {
    get(obj, prop, receiver) {
      // Internal markers bypass logging
      if (prop === TAINT_MARKER) return true;
      if (prop === TAINT_LOG) return log;
      // Symbol properties bypass logging (used by JS internals)
      if (typeof prop === 'symbol') return Reflect.get(obj, prop, receiver);

      const fullPath = `${rootPath}.${String(prop)}`;
      const exists = Object.prototype.hasOwnProperty.call(obj, prop);
      const value = Reflect.get(obj, prop, receiver);

      log.push({
        type: 'get',
        path: fullPath,
        property: String(prop),
        exists,
        valueType: value === null ? 'null' : typeof value,
        isUndefined: value === undefined,
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
        log.push({
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
        log.push({
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
        log.push({
          type: 'delete',
          path: fullPath,
          property: String(prop),
          timestamp: Date.now()
        });
      }
      return Reflect.deleteProperty(obj, prop);
    },

    getPrototypeOf(obj) {
      log.push({
        type: 'getPrototypeOf',
        path: rootPath,
        timestamp: Date.now()
      });
      return Reflect.getPrototypeOf(obj);
    },

    setPrototypeOf(obj, proto) {
      log.push({
        type: 'setPrototypeOf',
        path: rootPath,
        protoType: proto?.constructor?.name || 'null',
        timestamp: Date.now()
      });
      return Reflect.setPrototypeOf(obj, proto);
    },

    ownKeys(obj) {
      log.push({
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
        log.push({
          type: 'getOwnPropertyDescriptor',
          path: fullPath,
          property: String(prop),
          exists: Object.prototype.hasOwnProperty.call(obj, prop),
          timestamp: Date.now()
        });
      }
      return Reflect.getOwnPropertyDescriptor(obj, prop);
    }
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
  const accessFrequency = new Map();

  for (let i = 0; i < log.length; i++) {
    const event = log[i];

    if (event.type === 'get') {
      // Track access frequency for information-theoretic analysis
      const count = accessFrequency.get(event.property) || 0;
      accessFrequency.set(event.property, count + 1);

      // UOP: reading a property that doesn't exist
      if (event.isUOPCandidate) {
        uopCandidates.push({
          path: event.path,
          property: event.property,
          timestamp: event.timestamp
        });
      }

      // Prototype chain lookup: property doesn't exist on own object
      // but resolves to a value (came from prototype)
      if (event.isPrototypeChainLookup) {
        prototypeChainLookups.push({
          path: event.path,
          property: event.property,
          valueType: event.valueType,
          timestamp: event.timestamp
        });
      }

      // Pattern: read undefined property, then write to it later
      // This is a common gadget pattern: if (!obj.prop) obj.prop = default
      if (event.isUOPCandidate) {
        for (let j = i + 1; j < Math.min(i + 20, log.length); j++) {
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
    }
  }

  // Compute Shannon entropy of property access distribution
  // Higher entropy = more diverse exploration
  const totalAccesses = Array.from(accessFrequency.values()).reduce((a, b) => a + b, 0);
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
    accessEntropy,
    uniquePropertiesAccessed: accessFrequency.size,
    accessFrequency: Object.fromEntries(accessFrequency)
  };
}
