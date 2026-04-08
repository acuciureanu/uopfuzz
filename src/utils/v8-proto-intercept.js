/**
 * V8 Prototype Chain Interceptor
 *
 * Inserts a Proxy sentinel between a target object and its prototype chain.
 * When V8's LdaNamedProperty bytecode cannot find a property on an object,
 * the engine walks [[Prototype]] — our Proxy fires before any further
 * traversal, logging the lookup as a prototype-chain event.
 *
 * Gap filled vs. taint-proxy.js:
 *   taint-proxy.js wraps the *input value* passed to the library, so it only
 *   catches lookups on objects we explicitly handed it. It misses lookups on
 *   library-internal objects (e.g. a template AST node, an options cache)
 *   that were never derived from fuzzer input.
 *
 *   This module hooks *any* JS object — including ones constructed deep inside
 *   the library — by inserting a sentinel into their prototype chain.
 *
 * Technical mechanism (ECMA-262 §10.1.8 OrdinaryGet):
 *   1. obj.prop → OrdinaryGet(obj, prop, receiver)
 *   2. own descriptor not found → ownDesc = undefined → go to parent
 *   3. parent = Object.getPrototypeOf(obj) = our Proxy sentinel
 *   4. Proxy.[[Get]](prop, receiver) fires the `get` trap
 *   5. trap logs the lookup, then Reflect.get(originalProto, prop, receiver)
 *      continues through the original chain
 *
 * V8 bytecode relevance:
 *   The LdaNamedProperty / GetNamedProperty bytecodes perform inline-cache
 *   (IC) lookups. An IC miss walks the chain via C++ GetProperty. When
 *   GetProperty encounters a Proxy in the chain it invokes the JS trap
 *   through the standard [[Get]] protocol, making this interception happen
 *   at engine level — no source code modification required.
 *
 * Reference: ECMA-262 2024 §10.1.8, V8 src/objects/lookup.cc LookupIterator
 */

// Private symbol — invisible to library code, marks an already-hooked object
const HOOKED_MARKER = Symbol('v8ProtoInterceptHooked');
// Marks a sentinel proxy so we don't double-hook sentinels themselves
const SENTINEL_MARKER = Symbol('v8ProtoInterceptSentinel');

/**
 * Create a Proxy sentinel that logs every property lookup reaching it.
 *
 * @param {object|null} originalProto - The prototype being intercepted
 * @param {Array} log - Mutable array to append events to
 * @param {string} label - Human-readable label for the hooked object
 * @returns {Proxy} sentinel
 */
function createSentinel(originalProto, log, label) {
  const base = originalProto ?? Object.prototype;

  return new Proxy(base, {
    get(proto, prop, receiver) {
      // Skip internal markers to avoid log noise
      if (prop === SENTINEL_MARKER || prop === HOOKED_MARKER) {
        return prop === SENTINEL_MARKER ? true : false;
      }

      const propStr = typeof prop === 'symbol' ? prop.toString() : String(prop);

      // Check where in the chain this property actually lives
      const inImmediateProto = Object.prototype.hasOwnProperty.call(proto, prop);
      const inObjectProto = !inImmediateProto &&
        Object.prototype.hasOwnProperty.call(Object.prototype, prop);

      log.push({
        type: 'proto_chain_lookup',
        source: 'v8_intercept',
        label,
        property: propStr,
        isSymbol: typeof prop === 'symbol',
        // Property exists on the direct prototype (e.g. Class.prototype.method)
        resolvedInProto: inImmediateProto,
        // Property exists only on Object.prototype (e.g. toString, hasOwnProperty)
        resolvedInObjectProto: inObjectProto,
        // True UOP: property exists nowhere in the chain → will be undefined
        isUOPCandidate: !inImmediateProto && !inObjectProto,
        timestamp: Date.now()
      });

      // Preserve correct `this` binding: receiver is the original object
      return Reflect.get(proto, prop, receiver);
    },

    getPrototypeOf(proto) {
      log.push({
        type: 'getPrototypeOf',
        source: 'v8_intercept',
        label,
        timestamp: Date.now()
      });
      return Reflect.getPrototypeOf(proto);
    },

    has(proto, prop) {
      const propStr = typeof prop === 'symbol' ? prop.toString() : String(prop);
      log.push({
        type: 'has',
        source: 'v8_intercept',
        label,
        property: propStr,
        result: Reflect.has(proto, prop),
        timestamp: Date.now()
      });
      return Reflect.has(proto, prop);
    }
  });
}

/**
 * Insert a Proxy sentinel into `target`'s prototype chain.
 *
 * After this call, any property read on `target` that is not found on
 * `target` itself will trigger the sentinel's `get` trap before reaching
 * the original prototype.
 *
 * @param {object|Function} target - The object to intercept
 * @param {Array} log - Event log to append to
 * @param {string} [label] - Label for log entries
 * @returns {boolean} true if successfully hooked
 */
export function hookObject(target, log, label = 'obj') {
  if (target === null || target === undefined) return false;
  if (typeof target !== 'object' && typeof target !== 'function') return false;

  // Don't hook our own sentinels or already-hooked objects
  try {
    if (target[SENTINEL_MARKER] || target[HOOKED_MARKER]) return false;
  } catch {
    return false;
  }

  const originalProto = Object.getPrototypeOf(target);

  // Don't hook objects with null prototype or if the proto is already a sentinel
  if (originalProto !== null) {
    try {
      if (originalProto[SENTINEL_MARKER]) return false;
    } catch {
      return false;
    }
  }

  const sentinel = createSentinel(originalProto, log, label);

  try {
    Object.setPrototypeOf(target, sentinel);
    // Mark the target (on the target itself, not the sentinel)
    Object.defineProperty(target, HOOKED_MARKER, {
      value: true,
      writable: false,
      enumerable: false,
      configurable: false
    });
    return true;
  } catch {
    // Frozen objects or non-extensible objects cannot have their proto changed
    return false;
  }
}

/**
 * Recursively hook all objects reachable from `root` up to `maxDepth`.
 *
 * Traverses own enumerable properties and hooks each object found,
 * covering library-internal objects that the fuzzer never directly touched.
 *
 * @param {object} root - Starting object
 * @param {Array} log - Event log to append to
 * @param {object} [opts]
 * @param {number} [opts.maxDepth=3] - Maximum recursion depth
 * @param {string} [opts.label='root'] - Root label prefix
 * @returns {number} Count of successfully hooked objects
 */
export function hookAll(root, log, { maxDepth = 3, label = 'root' } = {}) {
  const visited = new WeakSet();
  let count = 0;

  function walk(obj, depth, lbl) {
    if (depth > maxDepth) return;
    if (obj === null || obj === undefined) return;
    if (typeof obj !== 'object' && typeof obj !== 'function') return;
    if (visited.has(obj)) return;
    visited.add(obj);

    if (hookObject(obj, log, lbl)) count++;

    // Recurse into own enumerable properties
    let keys;
    try {
      keys = Object.keys(obj);
    } catch {
      return;
    }

    for (const key of keys) {
      let val;
      try { val = obj[key]; } catch { continue; }
      if (val !== null && (typeof val === 'object' || typeof val === 'function')) {
        walk(val, depth + 1, `${lbl}.${key}`);
      }
    }
  }

  walk(root, 0, label);
  return count;
}

/**
 * Analyze prototype chain lookup events collected by hooked objects.
 *
 * @param {Array} log - Events from hookObject / hookAll
 * @returns {object} Analysis results
 */
export function analyzeProtoLog(log) {
  const uopCandidates = [];
  const resolvedFromProto = [];
  const resolvedFromObjectProto = [];
  const propertyFrequency = new Map();
  let totalLookups = 0;

  for (const event of log) {
    if (event.type !== 'proto_chain_lookup') continue;
    totalLookups++;

    const count = (propertyFrequency.get(event.property) || 0) + 1;
    propertyFrequency.set(event.property, count);

    if (event.isUOPCandidate) {
      uopCandidates.push({
        label: event.label,
        property: event.property,
        timestamp: event.timestamp
      });
    } else if (event.resolvedFromObjectProto) {
      resolvedFromObjectProto.push({
        label: event.label,
        property: event.property,
        timestamp: event.timestamp
      });
    } else if (event.resolvedInProto) {
      resolvedFromProto.push({
        label: event.label,
        property: event.property,
        timestamp: event.timestamp
      });
    }
  }

  return {
    totalLookups,
    uopCandidates,
    resolvedFromProto,
    resolvedFromObjectProto,
    uniqueProperties: propertyFrequency.size,
    propertyFrequency: Object.fromEntries(propertyFrequency)
  };
}
