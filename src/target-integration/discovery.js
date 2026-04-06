import { logger } from '../utils/logger.js';
import { createTaintProxy, analyzeTaintLog } from '../utils/taint-proxy.js';

/**
 * Automatic Target Discovery
 *
 * Given just a package name and version, this module:
 * 1. Inspects the module's exports to find callable functions
 * 2. Probes each function to determine its signature (what args it accepts)
 * 3. Detects compile-then-render patterns (function returns function)
 * 4. Discovers UOP properties via taint-tracked probe execution
 * 5. Generates a complete target config equivalent to a YAML file
 *
 * This eliminates the need for hand-written target configuration —
 * the fuzzer can target any npm package with zero prior knowledge.
 */

// Dangerous sinks we always monitor
const DEFAULT_SINKS = [
  'eval', 'Function', 'child_process.exec',
  'setTimeout', 'setInterval',
  'vm.runInThisContext', 'vm.runInNewContext'
];

// Template strings to probe template engines with
const PROBE_TEMPLATES = [
  'Hello {{name}}',
  '<h1><%= title %></h1>',
  '#{variable}',
  'p Hello World',
  '{{> partial}}',
  '<div>${data}</div>',
  'Hello World',
];

// Object inputs to probe with
const PROBE_OBJECTS = [
  { name: 'test', value: 'data' },
  { template: '{{value}}' },
  {},
];

/**
 * Discover target configuration automatically from a loaded module.
 *
 * @param {object} targetModule - The loaded npm package module
 * @param {string} packageName - Package name (e.g., "pug")
 * @param {string} version - Package version (e.g., "3.0.2")
 * @returns {object} A complete target config (same shape as YAML configs)
 */
export async function discoverTarget(targetModule, packageName, version) {
  logger.info(`Auto-discovering target: ${packageName}@${version}`);

  // Step 1: Find all callable exports
  const exports = discoverExports(targetModule, packageName);
  logger.info(`Found ${exports.length} callable exports: ${exports.map(e => e.name).join(', ')}`);

  if (exports.length === 0) {
    throw new Error(`No callable exports found in ${packageName}. Cannot auto-discover target.`);
  }

  // Step 2: Probe each export to determine input types and find call sequences
  const entryPoints = [];
  const sequences = [];

  for (const exp of exports) {
    const probeResult = await probeFunction(exp.fn, exp.name);
    if (probeResult) {
      entryPoints.push({
        name: exp.name,
        inputType: probeResult.inputType,
        description: `Auto-discovered: accepts ${probeResult.inputType}`
      });

      // If it returns a function, this is a compile-then-render pattern
      if (probeResult.returnsFunction) {
        sequences.push({
          entryPoint: exp.name,
          steps: [
            { call: exp.name, args: [probeResult.inputType === 'template' ? 'template' : 'input', 'options'] },
            { call: '__result__', args: ['locals'] }
          ]
        });
        logger.info(`Detected compile->render sequence for ${exp.name}()`);
      }
      // If it returns an object with a .render method, it's Hogan-style
      else if (probeResult.returnsRenderable) {
        sequences.push({
          entryPoint: exp.name,
          steps: [
            { call: exp.name, args: [probeResult.inputType === 'template' ? 'template' : 'input', 'options'] },
            { call: '__result__', method: 'render', args: ['locals'] }
          ]
        });
        logger.info(`Detected compile->result.render() sequence for ${exp.name}()`);
      }
    }
  }

  // Step 3: Discover UOP properties via taint-tracked probe
  let discoveredProperties = [];
  for (const ep of entryPoints.slice(0, 3)) {
    const exp = exports.find(e => e.name === ep.name);
    if (exp) {
      const props = await discoverPropertiesFromProbe(exp.fn, ep.inputType);
      discoveredProperties.push(...props);
    }
  }
  discoveredProperties = [...new Set(discoveredProperties)];
  if (discoveredProperties.length > 0) {
    logger.info(`Discovered ${discoveredProperties.length} pollution candidate properties: ${discoveredProperties.slice(0, 10).join(', ')}${discoveredProperties.length > 10 ? '...' : ''}`);
  }

  // Step 4: Build the config
  const config = {
    name: packageName,
    package: packageName,
    version,
    description: `Auto-discovered target: ${packageName}@${version}`,
    entryPoints,
    sequences: sequences.length > 0 ? sequences : undefined,
    sinks: DEFAULT_SINKS,
    pollutionPoints: discoveredProperties.length > 0
      ? discoveredProperties
      : getDefaultPollutionPoints(),
    knownPatterns: [],
    testConfig: {
      timeout: 30,
      maxDepth: 3,
      enableAsyncTesting: true
    },
    _autoDiscovered: true
  };

  logger.info(`Auto-discovery complete: ${entryPoints.length} entry points, ${sequences.length} sequences, ${config.pollutionPoints.length} pollution points`);
  return config;
}

/**
 * Find all callable exports from a module, including nested exports.
 */
function discoverExports(targetModule, packageName) {
  const exports = [];
  const seen = new Set();

  function addExport(name, fn) {
    if (seen.has(name) || typeof fn !== 'function') return;
    seen.add(name);
    exports.push({ name, fn });
  }

  // Check top-level exports
  for (const [key, value] of Object.entries(targetModule)) {
    if (key === '__esModule' || key === 'default') continue;
    addExport(key, value);
  }

  // Check default export (common in ESM packages)
  if (targetModule.default) {
    if (typeof targetModule.default === 'function') {
      // The default export IS the function (e.g., `export default function compile()`)
      addExport(packageName, targetModule.default);

      // Also check properties on the default function (e.g., pug.compile, pug.render)
      for (const [key, value] of Object.entries(targetModule.default)) {
        addExport(key, value);
      }
    } else if (typeof targetModule.default === 'object') {
      for (const [key, value] of Object.entries(targetModule.default)) {
        addExport(key, value);
      }
    }
  }

  // Prioritize common entry point names
  const priority = ['compile', 'render', 'renderString', 'renderFile', 'parse', 'transform', 'process', 'template', 'evaluate'];
  exports.sort((a, b) => {
    const aIdx = priority.indexOf(a.name);
    const bIdx = priority.indexOf(b.name);
    if (aIdx >= 0 && bIdx >= 0) return aIdx - bIdx;
    if (aIdx >= 0) return -1;
    if (bIdx >= 0) return 1;
    return 0;
  });

  return exports;
}

/**
 * Probe a function to determine what kind of input it accepts
 * and what it returns.
 */
async function probeFunction(fn, name) {
  // Try string/template inputs first (most template engines accept strings)
  for (const template of PROBE_TEMPLATES) {
    const result = await tryCall(fn, [template]);
    if (result.success) {
      return {
        inputType: 'template',
        returnsFunction: typeof result.value === 'function',
        returnsRenderable: result.value && typeof result.value === 'object' && typeof result.value.render === 'function',
        acceptedInput: template
      };
    }
  }

  // Try with string + options object
  for (const template of PROBE_TEMPLATES) {
    const result = await tryCall(fn, [template, {}]);
    if (result.success) {
      return {
        inputType: 'template',
        returnsFunction: typeof result.value === 'function',
        returnsRenderable: result.value && typeof result.value === 'object' && typeof result.value.render === 'function',
        acceptedInput: template
      };
    }
  }

  // Try object inputs
  for (const obj of PROBE_OBJECTS) {
    const result = await tryCall(fn, [obj]);
    if (result.success) {
      return {
        inputType: 'object',
        returnsFunction: typeof result.value === 'function',
        returnsRenderable: result.value && typeof result.value === 'object' && typeof result.value.render === 'function',
        acceptedInput: obj
      };
    }
  }

  // Try no-arg call
  const noArgResult = await tryCall(fn, []);
  if (noArgResult.success) {
    return {
      inputType: 'object',
      returnsFunction: typeof noArgResult.value === 'function',
      returnsRenderable: noArgResult.value && typeof noArgResult.value === 'object' && typeof noArgResult.value.render === 'function',
      acceptedInput: undefined
    };
  }

  // Function exists but we couldn't figure out how to call it
  // Include it anyway with template type as default
  return {
    inputType: 'template',
    returnsFunction: false,
    returnsRenderable: false,
    acceptedInput: null
  };
}

/**
 * Try calling a function with given args, with timeout protection.
 */
async function tryCall(fn, args, timeoutMs = 3000) {
  let timer;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('probe timeout')), timeoutMs);
    });
    const execution = Promise.resolve(fn(...args));
    const value = await Promise.race([execution, timeout]);
    return { success: true, value };
  } catch {
    return { success: false, value: null };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Discover UOP properties by running a function with taint-tracked input.
 */
async function discoverPropertiesFromProbe(fn, inputType) {
  const taintLog = [];
  const properties = new Set();

  // Build a probe input and wrap it in taint proxy
  let probeInput;
  if (inputType === 'template') {
    probeInput = 'p Hello World';
  } else {
    probeInput = { name: 'test' };
  }

  // Try calling with a taint-proxied options object
  const optionsObj = {};
  let trackedOptions;
  try {
    trackedOptions = createTaintProxy(optionsObj, taintLog, '$options');
  } catch {
    trackedOptions = optionsObj;
  }

  let timer;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('probe timeout')), 3000);
    });
    const execution = Promise.resolve(fn(probeInput, trackedOptions));
    const result = await Promise.race([execution, timeout]);

    // If result is a function, call it too to discover more properties
    if (typeof result === 'function') {
      const localsLog = [];
      const locals = {};
      let trackedLocals;
      try { trackedLocals = createTaintProxy(locals, localsLog, '$locals'); } catch { trackedLocals = locals; }
      try { await Promise.resolve(result(trackedLocals)); } catch { /* expected */ }
      for (const event of localsLog) {
        if (event.type === 'get' && event.isUOPCandidate && typeof event.property === 'string') {
          addProperty(properties, event.property);
        }
      }
    }

    // If result has .render(), call it
    if (result && typeof result === 'object' && typeof result.render === 'function') {
      const localsLog = [];
      const locals = {};
      let trackedLocals;
      try { trackedLocals = createTaintProxy(locals, localsLog, '$locals'); } catch { trackedLocals = locals; }
      try { await Promise.resolve(result.render(trackedLocals)); } catch { /* expected */ }
      for (const event of localsLog) {
        if (event.type === 'get' && event.isUOPCandidate && typeof event.property === 'string') {
          addProperty(properties, event.property);
        }
      }
    }
  } catch {
    // Probe failure is expected for some functions
  } finally {
    clearTimeout(timer);
  }

  // Extract UOP candidates from options taint log
  for (const event of taintLog) {
    if (event.type === 'get' && event.isUOPCandidate && typeof event.property === 'string') {
      addProperty(properties, event.property);
    }
  }

  return [...properties];
}

function addProperty(set, prop) {
  // Filter out noise
  if (prop.startsWith('__') || prop === 'constructor' || prop === 'prototype' ||
      prop === 'then' || prop === 'toJSON' || prop === 'valueOf' ||
      prop === 'toString' || prop.length <= 1 || prop === 'default' ||
      prop === 'Symbol(Symbol.toPrimitive)' || prop === 'Symbol(Symbol.toStringTag)') {
    return;
  }
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
