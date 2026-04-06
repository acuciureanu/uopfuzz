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
  // No args
  { type: 'none', args: [] },
];

// Method names that indicate interesting fuzzing targets
const INTERESTING_METHODS = new Set([
  'compile', 'render', 'renderString', 'renderFile', 'renderToString',
  'renderToStaticMarkup', 'parse', 'transform', 'process', 'evaluate',
  'template', 'execute', 'run', 'build', 'generate', 'create',
  'prepare', 'handle', 'getRequestHandler', 'use', 'configure',
  'set', 'get', 'middleware', 'handler', 'resolve', 'load',
  'read', 'write', 'format', 'stringify', 'serialize', 'deserialize',
  'encode', 'decode', 'convert', 'merge', 'assign', 'extend', 'mixin',
  'clone', 'defaults', 'options', 'config', 'init', 'setup',
]);

// Skip these — they're noise, not attack surface
const SKIP_NAMES = new Set([
  'constructor', 'prototype', '__esModule', 'default',
  'toString', 'valueOf', 'toJSON', 'inspect',
  'Symbol(Symbol.toPrimitive)', 'Symbol(Symbol.toStringTag)',
  'then', 'catch', 'finally',
]);

/**
 * Should this export name be skipped?
 * Filters React hooks, internal names, and known-useless patterns.
 */
function shouldSkipExport(name) {
  const baseName = name.includes('.') ? name.split('.').pop() : name;
  if (SKIP_NAMES.has(baseName)) return true;
  if (baseName.startsWith('_')) return true;
  // React hooks — these CANNOT run outside a component render context
  if (/^use[A-Z]/.test(baseName)) return true;
  // React internal patterns
  if (/^(create|forward|lazy|memo|Children|Fragment|Suspense|Profiler|StrictMode)$/.test(baseName)) return true;
  // Common React component indicators (PascalCase single-word + returns JSX)
  // We can't detect JSX statically, but we can skip known React exports
  if (/^(Component|PureComponent|createElement|cloneElement|isValidElement|createContext|createRef)$/.test(baseName)) return true;
  return false;
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
  const toProbe = prioritizeExports(allExports).slice(0, 20);
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

  // Step 4: Build config
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
      if (shouldSkipExport(key)) continue;
      const name = prefix ? `${prefix}.${key}` : key;

      if (typeof value === 'function' && !seen.has(name)) {
        seen.add(name);
        exports.push({ name, fn: value });
      } else if (typeof value === 'object' && value !== null && !seen.has(name)) {
        seen.add(name);
        walk(value, name, depth + 1);
      }
    }
  }

  // Walk top-level exports
  walk(targetModule, '', 0);

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

/**
 * Prioritize exports: put likely-interesting names first.
 */
function prioritizeExports(exports) {
  return [...exports].sort((a, b) => {
    const baseName = (name) => name.includes('.') ? name.split('.').pop() : name;
    const aInteresting = INTERESTING_METHODS.has(baseName(a.name));
    const bInteresting = INTERESTING_METHODS.has(baseName(b.name));
    if (aInteresting && !bInteresting) return -1;
    if (!aInteresting && bInteresting) return 1;
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

/**
 * Temporarily suppress console.error (React/framework internals spam stderr).
 */
function withSuppressedConsole(fn) {
  const origError = console.error;
  const origWarn = console.warn;
  console.error = () => {};
  console.warn = () => {};
  try {
    return fn();
  } finally {
    console.error = origError;
    console.warn = origWarn;
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
    for (const probe of PROBE_INPUTS.slice(0, 5)) {
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
