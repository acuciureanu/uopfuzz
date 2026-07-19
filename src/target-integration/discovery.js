import { logger } from '../utils/logger.js';
import { createTaintProxy } from '../utils/taint-proxy.js';

/**
 * Automatic Target Discovery
 *
 * Given just a package name and version, this module:
 * 1. Deep-walks the module's exports to find all callable functions
 *    (top-level, default, nested objects, prototype methods, returned objects)
 * 2. Probes each function with diverse input shapes to determine signatures
 * 3. Detects multi-step patterns (compile->render, create->method, etc.)
 * 4. Discovers UOP properties via taint-tracked probing across all entry points
 * 5. Generates a complete target config equivalent to a YAML file
 */

const DEFAULT_SINKS = [
  'eval', 'Function', 'child_process.exec',
  'setTimeout', 'setInterval',
  'vm.runInThisContext', 'vm.runInNewContext'
];

// Diverse probe inputs: templates, objects, config-like objects, HTTP-like mocks
const PROBE_INPUTS = [
  // Template strings (template engines)
  { type: 'template', args: ['Hello {{name}}'] },
  { type: 'template', args: ['<h1><%= title %></h1>'] },
  { type: 'template', args: ['p Hello World'] },
  { type: 'template', args: ['Hello World'] },
  // Template + options
  { type: 'template', args: ['Hello World', {}] },
  // Config-like objects (frameworks, libraries)
  { type: 'object', args: [{ dev: true }] },
  { type: 'object', args: [{ dir: '.', dev: false }] },
  { type: 'object', args: [{}] },
  // String-first with options (common pattern: fn(str, opts))
  { type: 'string', args: ['test', {}] },
  { type: 'string', args: ['test'] },
  // HTTP-like objects (Express/Koa/Fastify middleware patterns)
  { type: 'object', args: [{ url: '/', method: 'GET', headers: {} }] },
  { type: 'object', args: [{ url: '/', method: 'GET', headers: {} }, { end: () => {}, write: () => {}, setHeader: () => {} }] },
  // Key-value / merge patterns (lodash-like)
  { type: 'object', args: [{}, { a: 1 }] },
  { type: 'object', args: ['key', 'value'] },
  // Deep merge patterns (jQuery.extend(true, target, source))
  { type: 'object', args: [true, {}, { a: 1 }] },
  { type: 'object', args: [true, { x: 1 }, { y: 2 }] },
  // No args
  { type: 'none', args: [] },
];

// Baseline number of exports to probe. A floor, not a ceiling: every export the
// behavioural probes flagged is always probed, however many that is (see
// discoverTarget). This only bounds how far into the unremarkable tail we go.
const PROBE_CAP = 20;

// Wall-clock budgets for behavioural probing. Probing calls the target's own
// code, so a single export can block for seconds (real network I/O, a busy
// loop). These bound the blast radius by MEASURED cost rather than by guessing
// which names are dangerous. Overrunning only costs an export its behavioural
// ranking — it is still discovered and still probed by the normal pipeline.
const EXPORT_PROBE_BUDGET_MS = 250;
const TOTAL_PROBE_BUDGET_MS = 10000;

// Pre-sliced for UOP discovery — avoids creating a new array per export
const UOP_PROBES = PROBE_INPUTS.slice(0, 5);

// HTTP/AJAX methods — important for URL read-gadgets but MUST NOT be probed
// during auto-discovery (they fire real XHRs in jsdom and hang/timeout).
// Instead, they are injected directly into config.entryPoints after discovery.
const AJAX_LIKE_METHODS = new Set([
  'ajax', 'post', 'getJSON', 'getScript', 'fetch', 'request', 'send',
]);

// Skip these — they're noise, not attack surface
const SKIP_NAMES = new Set([
  'constructor', 'prototype', '__esModule', 'default',
  'toString', 'valueOf', 'toJSON', 'inspect',
  'Symbol(Symbol.toPrimitive)', 'Symbol(Symbol.toStringTag)',
  'then', 'catch', 'finally',
  // Module plumbing. An ESM/CJS interop wrapper exposes the same namespace as
  // `default.x` and `module.exports.x`; walking into them mints alias entry
  // points that can never resolve, because the sandbox and reproduction workers
  // load the package with require() where no such wrapper key exists. (`default`
  // is handled transparently by the dedicated walk at the end of
  // discoverExports, which uses an empty prefix.)
  'module', 'exports',
]);

/**
 * Structural plumbing that must never be walked INTO, as opposed to a member
 * that merely should not be probed itself.
 *
 * Descending into these mints duplicate, unresolvable entry points. That is not
 * just wasteful: the differential phase gives up after 3 consecutive
 * un-callable entry points, so a cluster of dead aliases sorted ahead of a real
 * one silently starves it.
 */
function isStructuralNoise(name) {
  const baseName = name.includes('.') ? name.split('.').pop() : name;
  return SKIP_NAMES.has(baseName);
}

/**
 * Should this export be skipped entirely?
 *
 * Only language/module plumbing qualifies — things that cannot be a meaningful
 * entry point in any library (`constructor`, `prototype`, `then`, the CJS/ESM
 * wrapper keys). A name must never decide whether real code gets TESTED.
 *
 * This used to also drop React vocabulary (`create`, `memo`, `lazy`, `forward`,
 * `/^use[A-Z]/`, PascalCase component names) and anything starting with `_`.
 * Those are ordinary names outside React — `create` especially — so a
 * vulnerable `create` or `useConfig` was silently invisible, and the tool could
 * only find bugs in functions we had thought to name.
 *
 * Nothing is lost by dropping them. The stated reason for the React rules was
 * that hooks cannot run outside a render context — which the behavioural probes
 * already handle: such a function throws when probed, is therefore neither
 * merge-like nor factory-like, and sorts to the bottom on its own. Evidence
 * demotes it; a vocabulary list is not needed, and cannot distinguish React's
 * `create` from anyone else's.
 */
function shouldSkipExport(name) {
  return isStructuralNoise(name);
}

/**
 * Discover target configuration automatically from a loaded module.
 */
export async function discoverTarget(targetModule, packageName, version, subModules = {}) {
  logger.info(`Auto-discovering target: ${packageName}@${version}`);

  // Step 1: Deep-walk exports to find ALL callable functions
  const allExports = discoverExports(targetModule, packageName);

  // Also walk sub-module exports (e.g., next/server, next/headers)
  for (const [subPath, subMod] of Object.entries(subModules)) {
    const prefix = subPath.replace(`${packageName}/`, '');
    const subExports = discoverExports(subMod, prefix);
    for (const exp of subExports) {
      // Avoid duplicates by name
      if (!allExports.some(e => e.name === exp.name)) {
        allExports.push(exp);
      }
    }
  }

  logger.info(`Found ${allExports.length} callable exports: ${allExports.map(e => e.name).slice(0, 15).join(', ')}${allExports.length > 15 ? '...' : ''}`);

  if (allExports.length === 0) {
    throw new Error(`No callable exports found in ${packageName}. Cannot auto-discover target.`);
  }

  // Step 2: Probe each export to determine input types and return behavior
  // Limit to top 20 most interesting exports to avoid probing hundreds of methods
  // IMPORTANT: skip AJAX-like methods — probing them fires real XHRs that hang.
  // AJAX-like methods are excluded BEFORE ranking, not after: ranking now calls
  // each candidate (behavioural merge detection), and calling an ajax method
  // fires a real XHR that hangs the run.
  const probeSafe = allExports.filter(exp => {
    const base = exp.name.includes('.') ? exp.name.split('.').pop() : exp.name;
    return !AJAX_LIKE_METHODS.has(base);
  });
  // The cap bounds probe cost, so it may truncate only the tail the behavioural
  // probes found nothing in. Applying it as a flat top-N would let rank
  // position veto evidence: with more than N merge-like exports, a genuinely
  // vulnerable one could be cut purely for sorting late among its peers.
  const ranked = prioritizeExports(probeSafe);
  const behavioural = ranked.filter(exp => exp.behavioural);
  const toProbe = ranked.slice(0, Math.max(PROBE_CAP, behavioural.length));
  const entryPoints = [];
  const sequences = [];

  for (const exp of toProbe) {
    const probeResult = await probeFunction(exp.fn, exp.name);
    if (!probeResult) continue;

    entryPoints.push({
      name: exp.name,
      inputType: probeResult.inputType,
      description: `Auto-discovered: accepts ${probeResult.inputType}`
    });

    // Detect multi-step patterns
    if (probeResult.returnsFunction) {
      sequences.push({
        entryPoint: exp.name,
        steps: [
          { call: exp.name, args: [probeResult.inputType === 'template' ? 'template' : 'input', 'options'] },
          { call: '__result__', args: ['locals'] }
        ]
      });
      logger.info(`  ${exp.name}() -> function (compile->render pattern)`);
    } else if (probeResult.returnedMethods.length > 0) {
      // Object with callable methods — create sequences for each
      for (const method of probeResult.returnedMethods.slice(0, 5)) {
        sequences.push({
          entryPoint: exp.name,
          steps: [
            { call: exp.name, args: probeResult.acceptedArgs },
            { call: '__result__', method, args: ['input', 'options'] }
          ]
        });
      }
      logger.info(`  ${exp.name}() -> object with methods: ${probeResult.returnedMethods.join(', ')}`);
    }
  }

  // Step 3: Discover UOP properties via taint-tracked probing
  // Probe across multiple entry points with multiple input shapes
  const discoveredProperties = await discoverAllUOPProperties(allExports.slice(0, 10));
  if (discoveredProperties.length > 0) {
    logger.info(`Discovered ${discoveredProperties.length} pollution candidates: ${discoveredProperties.slice(0, 10).join(', ')}${discoveredProperties.length > 10 ? '...' : ''}`);
  }

  // Step 4: Inject AJAX/HTTP entry points directly (no probing — they cause side effects)
  const epNames = new Set(entryPoints.map(ep => ep.name));
  for (const exp of allExports) {
    const base = exp.name.includes('.') ? exp.name.split('.').pop() : exp.name;
    if (AJAX_LIKE_METHODS.has(base) && !epNames.has(exp.name)) {
      entryPoints.push({
        name: exp.name,
        inputType: 'object',
        description: `Auto-discovered HTTP/AJAX method (not probed)`,
        _isUrlSink: true,
      });
      epNames.add(exp.name);
    }
  }

  // Step 5: Build config
  const config = {
    name: packageName,
    package: packageName,
    version,
    description: `Auto-discovered target: ${packageName}@${version}`,
    entryPoints: entryPoints.length > 0 ? entryPoints : [{ name: allExports[0].name, inputType: 'object' }],
    sequences: sequences.length > 0 ? sequences : undefined,
    sinks: DEFAULT_SINKS,
    pollutionPoints: discoveredProperties.length > 0
      ? discoveredProperties
      : getDefaultPollutionPoints(),
    knownPatterns: [],
    testConfig: { timeout: 30, maxDepth: 3, enableAsyncTesting: true },
    _autoDiscovered: true
  };

  logger.info(`Auto-discovery complete: ${entryPoints.length} entry points, ${sequences.length} call sequences, ${config.pollutionPoints.length} pollution candidates`);
  return config;
}

/**
 * Deep-walk module exports to find all callable functions.
 * Recurses into objects, prototypes, and default exports up to 3 levels.
 */
function discoverExports(targetModule, packageName) {
  const exports = [];
  const seen = new Set();

  function walk(obj, prefix, depth) {
    if (!obj || depth > 3) return;
    if (typeof obj !== 'object' && typeof obj !== 'function') return;

    const entries = [];
    try {
      // Own enumerable properties
      for (const key of Object.keys(obj)) {
        entries.push([key, obj[key]]);
      }
      // Also check prototype methods for class instances
      const proto = Object.getPrototypeOf(obj);
      if (proto && proto !== Object.prototype && proto !== Function.prototype) {
        for (const key of Object.getOwnPropertyNames(proto)) {
          if (key !== 'constructor' && typeof proto[key] === 'function') {
            entries.push([key, proto[key].bind(obj)]);
          }
        }
      }
    } catch {
      return; // Some objects throw on enumeration
    }

    for (const [key, value] of entries) {
      const skip = shouldSkipExport(key);
      const name = prefix ? `${prefix}.${key}` : key;

      if (typeof value === 'function' && !seen.has(name)) {
        // The private-member convention (`_foo`) applies to callable leaves:
        // skip a function that looks internal, but still register public ones.
        if (skip) continue;
        seen.add(name);
        exports.push({ name, fn: value });
        // Also walk function properties — libraries like jQuery attach methods
        // directly on the main function ($.extend, $.merge, $.each, etc.)
        if (depth < 3) {
          walk(value, name, depth + 1);
        }
      } else if (typeof value === 'object' && value !== null && !seen.has(name)) {
        // Descend into namespace OBJECTS even when the container name looks
        // PRIVATE. Libraries expose their whole public API under a short
        // namespace — `_` (lodash, underscore, @feathersjs/commons) or `$` —
        // which the `_`-prefix rule would otherwise privatize wholesale,
        // discarding public members like `_.merge`. The members inside are
        // still filtered by their own names on the next level, so genuinely
        // private helpers stay hidden.
        //
        // Structural plumbing is the exception: `default`/`module`/`exports`
        // are re-exports of what we are already walking, so descending mints
        // unresolvable alias entry points that can starve the real ones.
        if (isStructuralNoise(key)) continue;
        seen.add(name);
        walk(value, name, depth + 1);
      }
    }
  }

  // Walk top-level exports
  walk(targetModule, '', 0);

  // The module may itself BE a callable (module.exports = fn) — the common shape
  // for merge/extend utilities like merge-deep, deep-extend, deepmerge. Register
  // it as an entry point so its prototype-pollution surface is probed.
  if (typeof targetModule === 'function' && !seen.has(packageName)) {
    seen.add(packageName);
    exports.push({ name: packageName, fn: targetModule });
  }

  // Walk default export (very common in ESM)
  if (targetModule.default) {
    if (typeof targetModule.default === 'function') {
      if (!seen.has(packageName)) {
        seen.add(packageName);
        exports.push({ name: packageName, fn: targetModule.default });
      }
      walk(targetModule.default, '', 1);
    } else {
      walk(targetModule.default, '', 1);
    }
  }

  return exports;
}

// Probe key for behavioural merge detection. Deliberately obscure so a target
// cannot plausibly carry it already.
const MERGE_PROBE_KEY = '__uopfuzz_merge_probe__';

/**
 * Does this function BEHAVE like a merge/extend/assign?
 *
 * A merge makes the source object's keys observable — either by mutating its
 * first argument (lodash.merge, Object.assign) or by returning an object that
 * carries them. That is a property of behaviour, not of the author's naming
 * taste, so it catches a vulnerable deep-merge called `reconcileConfigurationTree`
 * exactly as well as one called `merge`.
 *
 * Both real calling conventions are tried: fn(target, source) and the
 * jQuery-style fn(true, target, source) deep form. Arity is deliberately NOT
 * checked — plenty of merges are written with rest args (fn.length === 0).
 * Every call is contained: a throwing function simply is not merge-like.
 */
function looksLikeMerge(fn) {
  const source = { [MERGE_PROBE_KEY]: 1 };
  const observed = (target, result) =>
    target[MERGE_PROBE_KEY] === 1 ||
    (result && typeof result === 'object' && result[MERGE_PROBE_KEY] === 1);

  try {
    const target = {};
    if (observed(target, defuse(fn(target, source)))) return true;
  } catch { /* not this convention */ }

  try {
    const target = {};
    if (observed(target, defuse(fn(true, target, source)))) return true;
  } catch { /* not merge-like */ }

  return false;
}

/**
 * Neutralize a returned thenable.
 *
 * Ranking calls every candidate export, so an async function hands back a
 * promise nobody awaits. If it rejects, Node raises unhandledRejection and can
 * take the run down — a probe must never do that. Attaching a no-op handler
 * marks it handled; the value is still returned for shape inspection.
 */
function defuse(value) {
  if (value && (typeof value === 'object' || typeof value === 'function') && typeof value.then === 'function') {
    try { value.then(() => {}, () => {}); } catch { /* not a real promise */ }
  }
  return value;
}

// Representative shapes for the factory probe: a template string (compile
// pattern) and a bare options object (factory pattern).
const FACTORY_PROBE_ARGS = [['Hello {{name}}'], [{}]];

/** Does `value` carry callable methods? Mirrors buildProbeResult's filter, so
 *  ranking and probing agree on what "an object with methods" means. */
function hasCallableMethods(value) {
  try {
    const proto = Object.getPrototypeOf(value);
    const keys = new Set([
      ...Object.keys(value),
      ...(proto && proto !== Object.prototype ? Object.getOwnPropertyNames(proto) : []),
    ]);
    for (const key of keys) {
      if (SKIP_NAMES.has(key) || key.startsWith('_')) continue;
      if (typeof value[key] === 'function') return true;
    }
  } catch { /* exotic object */ }
  return false;
}

/**
 * Does this function BEHAVE like a factory/compiler — does calling it hand back
 * more callable surface (a function, or an object carrying methods) rather than
 * a plain value?
 *
 * This is the behavioural replacement for the INTERESTING_METHODS name list
 * ('compile', 'render', 'parse', …). Multi-step gadgets (compile -> render,
 * CVE-2022-29078) only fire on the SECOND call, so the entry point that returns
 * the callable has to be probed for the chain to be found at all. Ranking that
 * by name meant a compiler named outside our vocabulary was never probed.
 */
function looksLikeFactory(fn) {
  for (const args of FACTORY_PROBE_ARGS) {
    try {
      const value = defuse(fn(...args));
      if (typeof value === 'function') return true;
      if (value && typeof value === 'object' && hasCallableMethods(value)) return true;
    } catch { /* not this shape */ }
  }
  return false;
}

/**
 * Prioritize exports: put likely-interesting functions first.
 *
 * Merge-likeness is decided ONLY by behaviour. There used to be a hardcoded
 * DANGEROUS_MERGE_METHODS list ('merge', 'extend', 'assign', …) leading the
 * sort, which made prototype-pollution discovery depend on guessing the
 * author's vocabulary: because only the top-N ranked exports are probed, a
 * genuinely vulnerable deep-merge with an unlisted name sorted last, fell off
 * the cap, and was never tested. Worse, it flattered the tool — a hit on a
 * conventionally-named `merge` proved nothing about finding an unknown gadget.
 * The list is gone; nothing about prototype-pollution ranking now depends on
 * what a function is called.
 */
function prioritizeExports(exports) {
  // One probe pass per export, computed once: merge-likeness drives
  // prototype-pollution discovery, factory-likeness drives multi-step chains.
  // The flags are recorded on each record so the caller can apply its probe cap
  // to the uninteresting tail ONLY — evidence, not rank position, decides what
  // is worth testing.
  const mergeLike = new Map();
  const factoryLike = new Map();
  let spent = 0;
  for (const exp of exports) {
    // Probing runs the target's own code, and some exports do real I/O when
    // called — jQuery's `_evalUrl` performs a network request and blocks for
    // ~12s per call, which is enough to hang discovery outright.
    //
    // The old defence was a list of ajax-ish NAMES, which cannot work: it has
    // to enumerate every side-effecting function in every library, and it
    // already missed `_evalUrl`. Cost is observable, so budget it instead —
    // that covers functions nobody thought to name. An export that overruns is
    // simply not probed further and ranks as unremarkable; it is still
    // DISCOVERED and still testable, so nothing is gated out by this.
    if (spent >= TOTAL_PROBE_BUDGET_MS) {
      mergeLike.set(exp, false);
      factoryLike.set(exp, false);
      exp.behavioural = false;
      continue;
    }
    const t0 = Date.now();
    mergeLike.set(exp, looksLikeMerge(exp.fn));
    const mergeMs = Date.now() - t0;
    spent += mergeMs;

    // A slow first probe means calling this export is expensive; do not spend a
    // second round of calls on it.
    if (mergeMs <= EXPORT_PROBE_BUDGET_MS) {
      const t1 = Date.now();
      factoryLike.set(exp, looksLikeFactory(exp.fn));
      spent += Date.now() - t1;
    } else {
      factoryLike.set(exp, false);
    }
    exp.behavioural = mergeLike.get(exp) || factoryLike.get(exp);
  }

  return [...exports].sort((a, b) => {
    const aMerges = mergeLike.get(a) === true;
    const bMerges = mergeLike.get(b) === true;
    if (aMerges && !bMerges) return -1;
    if (!aMerges && bMerges) return 1;
    const aFactory = factoryLike.get(a) === true;
    const bFactory = factoryLike.get(b) === true;
    if (aFactory && !bFactory) return -1;
    if (!aFactory && bFactory) return 1;
    // Prefer shorter names (top-level over deeply nested)
    return a.name.length - b.name.length;
  });
}

/**
 * Probe a function with diverse inputs to determine:
 * - What input types it accepts
 * - Whether it returns a function (compile pattern)
 * - Whether it returns an object with interesting methods
 */
async function probeFunction(fn, name) {
  // Try regular function calls first
  for (const probe of PROBE_INPUTS) {
    const result = await tryCall(fn, probe.args);
    if (!result.success) continue;

    return buildProbeResult(result.value, probe);
  }

  // If all regular calls fail, try as constructor (class)
  if (isLikelyConstructor(fn)) {
    for (const probe of PROBE_INPUTS) {
      const result = await tryConstruct(fn, probe.args);
      if (!result.success) continue;

      return buildProbeResult(result.value, probe);
    }
  }

  // Couldn't probe successfully — still include with defaults
  return {
    inputType: 'template',
    returnsFunction: false,
    returnsRenderable: false,
    returnedMethods: [],
    acceptedArgs: ['input'],
    acceptedInput: null
  };
}

function buildProbeResult(value, probe) {
  const returnedMethods = [];
  if (value && typeof value === 'object') {
    try {
      const proto = Object.getPrototypeOf(value);
      const keys = new Set([
        ...Object.keys(value),
        ...(proto && proto !== Object.prototype ? Object.getOwnPropertyNames(proto) : [])
      ]);
      for (const key of keys) {
        if (typeof value[key] === 'function' && !SKIP_NAMES.has(key) && !key.startsWith('_')) {
          returnedMethods.push(key);
        }
      }
    } catch { /* ignore */ }
  }

  return {
    inputType: probe.type === 'none' ? 'object' : probe.type,
    returnsFunction: typeof value === 'function',
    returnsRenderable: value && typeof value === 'object' && typeof value.render === 'function',
    returnedMethods,
    acceptedArgs: probe.args.map(a => typeof a === 'string' ? 'input' : 'options'),
    acceptedInput: probe.args[0] ?? null
  };
}

function isLikelyConstructor(fn) {
  // Class constructors: fn.toString() starts with "class "
  // or fn.prototype has methods beyond constructor
  try {
    const src = fn.toString();
    if (src.startsWith('class ')) return true;
    if (fn.prototype && Object.getOwnPropertyNames(fn.prototype).length > 1) return true;
  } catch { /* ignore */ }
  return false;
}

// Cached console references — avoid saving/restoring per call
const _origConsoleError = console.error;
const _origConsoleWarn = console.warn;
const _noopFn = () => {};

function withSuppressedConsole(fn) {
  console.error = _noopFn;
  console.warn = _noopFn;
  try {
    return fn();
  } finally {
    console.error = _origConsoleError;
    console.warn = _origConsoleWarn;
  }
}

/**
 * Try calling a function with given args, with timeout protection.
 */
async function tryCall(fn, args, timeoutMs = 2000) {
  let timer;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('probe timeout')), timeoutMs);
    });
    const execution = withSuppressedConsole(() => Promise.resolve(fn(...args)));
    const value = await Promise.race([execution, timeout]);
    return { success: true, value };
  } catch {
    return { success: false, value: null };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Try calling a function as a constructor (new Fn(args)).
 */
async function tryConstruct(fn, args, timeoutMs = 2000) {
  let timer;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('probe timeout')), timeoutMs);
    });
    const execution = withSuppressedConsole(() => Promise.resolve(new fn(...args)));
    const value = await Promise.race([execution, timeout]);
    return { success: true, value };
  } catch {
    return { success: false, value: null };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Discover UOP properties across multiple entry points.
 * Probes each function with taint-tracked options objects to find
 * what properties the library reads as undefined.
 */
async function discoverAllUOPProperties(exports) {
  const allProperties = new Set();

  for (const exp of exports) {
    for (const probe of UOP_PROBES) {
      const props = await discoverPropertiesFromProbe(exp.fn, probe);
      for (const p of props) allProperties.add(p);
    }
  }

  return [...allProperties];
}

/**
 * Run a single taint-tracked probe to discover UOP properties.
 */
async function discoverPropertiesFromProbe(fn, probe) {
  const taintLog = [];
  const properties = new Set();

  // Build args with taint-tracked objects
  const args = probe.args.map((arg, i) => {
    if (arg && typeof arg === 'object') {
      try { return createTaintProxy({ ...arg }, taintLog, `$arg${i}`); }
      catch { return arg; }
    }
    return arg;
  });

  // If no object args, add a tracked options object as second arg
  if (!args.some(a => a && typeof a === 'object')) {
    try {
      args.push(createTaintProxy({}, taintLog, '$options'));
    } catch {
      args.push({});
    }
  }

  let timer;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('probe timeout')), 2000);
    });
    // Try regular call; if it fails and fn looks like a constructor, try new
    let result;
    try {
      result = await Promise.race([Promise.resolve(fn(...args)), timeout]);
    } catch {
      if (isLikelyConstructor(fn)) {
        result = await Promise.race([Promise.resolve(new fn(...args)), timeout]);
      } else {
        throw new Error('call failed');
      }
    }

    // If result is callable, probe it too
    if (typeof result === 'function') {
      const innerLog = [];
      const innerOpts = {};
      try {
        const tracked = createTaintProxy(innerOpts, innerLog, '$resultArg');
        await tryCall(result, [tracked], 1500);
      } catch { /* expected */ }
      for (const event of innerLog) {
        if (event.type === 'get' && event.isUOPCandidate && typeof event.property === 'string') {
          addProperty(properties, event.property);
        }
      }
    }

    // If result has .render(), probe it too
    if (result && typeof result === 'object' && typeof result.render === 'function') {
      const innerLog = [];
      try {
        const tracked = createTaintProxy({}, innerLog, '$renderArg');
        await tryCall(result.render.bind(result), [tracked], 1500);
      } catch { /* expected */ }
      for (const event of innerLog) {
        if (event.type === 'get' && event.isUOPCandidate && typeof event.property === 'string') {
          addProperty(properties, event.property);
        }
      }
    }
  } catch {
    // Probe failure is expected
  } finally {
    clearTimeout(timer);
  }

  // Extract UOP candidates from taint log
  for (const event of taintLog) {
    if (event.type === 'get' && event.isUOPCandidate && typeof event.property === 'string') {
      addProperty(properties, event.property);
    }
  }

  return [...properties];
}

function addProperty(set, prop) {
  if (typeof prop !== 'string') return;
  if (prop.startsWith('__') || prop.startsWith('Symbol(') || prop.length <= 1) return;
  if (SKIP_NAMES.has(prop) || prop === 'nodeType' || prop === 'tagName' ||
      prop === 'jquery' || prop === 'length' || prop === 'splice') return;
  set.add(prop);
}

function getDefaultPollutionPoints() {
  return [
    'debug', 'compileDebug', 'self', 'pretty', 'filename', 'basedir',
    'cache', 'template', 'autoEscape', 'defaultFilter', 'globals',
    'doctype', 'filters', 'plugins', 'partials', 'helpers',
    'outputFunctionName', 'rmWhitespace', 'async', 'root', 'views'
  ];
}
