/**
 * Runtime gadget miner — candidate harvester.
 *
 * GHunter (USENIX Security '24) finds universal-gadget candidates by trapping
 * every undefined property read in a patched V8 across Node's test suite. On a
 * STOCK runtime we get the same candidate set statically: an undefined property
 * read during API use is, at source level, a read of a property the caller did
 * not set on an options/config object. The full source of every builtin JS
 * module is available at runtime via process.binding('natives'), so no engine
 * patch is needed and the miner re-runs on any Node version.
 *
 * This module is the pure/static half: harvestCandidates() works on source
 * text and is unit-tested without a runtime. mine.js drives the dynamic half
 * (value-differential + exit-code oracles) over the harvested candidates.
 */

/**
 * API classes the miner knows how to exercise. `sources` are keys into
 * process.binding('natives') — the public module plus the internal modules
 * that actually read the options (e.g. http's logic lives in _http_client).
 * `driver` names the generic probe in the mining drivers package.
 * `baselineKeys` are properties the driver ALWAYS sets on its options object —
 * they are never undefined at the read site, so pollution cannot reach them
 * through that call shape; harvesting them would waste oracle runs.
 */
export const API_CLASSES = {
  'http.request': {
    sources: ['http', '_http_client', '_http_agent', '_http_common', '_http_outgoing', 'internal/http'],
    driver: 'probeHttpRequest',
    baselineKeys: ['host', 'port', 'path'],
  },
  'http.Server.listen': {
    sources: ['net', 'internal/net', '_http_server'],
    driver: 'probeHttpListen',
    baselineKeys: ['port', 'host'],
  },
  'https.request': {
    sources: ['https', '_http_client', '_http_agent', '_tls_wrap', '_tls_common', 'internal/options'],
    driver: 'probeHttpsRequest',
    baselineKeys: ['host', 'port', 'path'],
  },
  'net.connect': {
    sources: ['net', 'internal/net'],
    driver: 'probeNetConnect',
    baselineKeys: ['host', 'port'],
  },
  'tls.connect': {
    sources: ['tls', '_tls_wrap', '_tls_common', 'internal/tls/secure-context', 'internal/tls/wrap', 'internal/options'],
    driver: 'probeTlsConnect',
    baselineKeys: ['host', 'port'],
  },
  'child_process.spawn': {
    sources: ['child_process', 'internal/child_process'],
    driver: 'probeCpSpawn',
    baselineKeys: ['file', 'args', 'env'],
    // Blocked in the sandbox (the stub throws before any behavior can differ),
    // so the differential oracle is blind for this class — go straight to the
    // sink recorder, which sees the call arguments before the stub throws.
    primaryOracle: 'sink',
  },
  'child_process.execFile': {
    sources: ['child_process', 'internal/child_process'],
    driver: 'probeCpExecFile',
    baselineKeys: ['file', 'args', 'env'],
    primaryOracle: 'sink',
  },
  'stream.Readable': {
    sources: ['_stream_readable', 'internal/streams/readable', 'internal/streams/utils', 'internal/streams/state'],
    driver: 'probeStreamReadable',
    baselineKeys: ['read'],
  },
  'stream.Writable': {
    sources: ['_stream_writable', 'internal/streams/writable', 'internal/streams/utils', 'internal/streams/state'],
    driver: 'probeStreamWritable',
    baselineKeys: ['write'],
  },
  'fs.readFile': {
    sources: ['fs', 'internal/fs/promises', 'internal/fs/read/context', 'internal/fs/utils'],
    driver: 'probeFsReadFile',
    baselineKeys: ['path'],
  },
  'fs.writeFile': {
    sources: ['fs', 'internal/fs/promises', 'internal/fs/utils'],
    driver: 'probeFsWriteFile',
    baselineKeys: ['path', 'data'],
  },
  'dns.lookup': {
    sources: ['dns', 'internal/dns/callback_resolver', 'internal/dns/utils'],
    driver: 'probeDnsLookup',
    baselineKeys: ['hostname'],
  },
  'zlib.createGzip': {
    sources: ['zlib'],
    driver: 'probeZlibGzip',
    baselineKeys: [],
  },
  'worker_threads.Worker': {
    sources: ['worker_threads', 'internal/worker', 'internal/worker/io'],
    driver: 'probeWorkerCtor',
    baselineKeys: ['filename'],
    primaryOracle: 'sink', // blocked in the sandbox — see child_process.spawn
  },
  'vm.Script': {
    sources: ['vm', 'internal/vm'],
    driver: 'probeVmScript',
    baselineKeys: ['code'],
  },
  'crypto.createHash': {
    sources: ['crypto', 'internal/crypto/hash', 'internal/crypto/util'],
    driver: 'probeCryptoHash',
    baselineKeys: ['algorithm'],
  },
  'fetch': {
    // undici ships inside the binary as a single blob. Its Request reads the
    // init dictionary (`init.method`, `init.signal`, …), so this class adds
    // `init` to the harvested binding names. driverDos uses the real fetch()
    // because the fatal signal crash lives in fetch's async teardown path,
    // which the constructor-only probe never reaches.
    sources: ['internal/deps/undici/undici'],
    driver: 'probeFetch',
    driverDos: 'probeFetchNetwork',
    baselineKeys: ['url'],
    extraBindings: ['init'],
  },
};

// Never harvested: dangerous to pollute even in a sandbox, or pure noise.
// hasOwnProperty/hasOwn: a read like options.hasOwnProperty('x') tests
// own-ness — prototype pollution can never satisfy it, so the name is noise.
const GLOBAL_DENYLIST = new Set([
  '__proto__', 'prototype', 'constructor', 'then', 'toString', 'valueOf',
  'toJSON', 'inspect', 'length', 'name', 'caller', 'callee',
  'arguments', 'hasOwnProperty', 'hasOwn', '0', '1', '2',
]);

const IDENT = '[A-Za-z_$][A-Za-z0-9_$]*';

/**
 * Extract candidate property names from one module's source text.
 * Pure — unit-tested with inline fixtures, no runtime needed.
 *
 * Patterns harvested:
 *   options.foo / opts.foo / config.foo (incl. optional chaining)
 *   const { a, b = def, c: renamed } = options|opts|config
 *
 * @param {string} source
 * @param {Set<string>} [denylist]
 * @param {string[]} [extraBindings] additional options-ish binding names
 *   (e.g. undici's Request reads `init.method`, not `options.method`)
 * @returns {string[]} sorted unique candidate names
 */
export function harvestCandidates(source, denylist = new Set(), extraBindings = []) {
  if (typeof source !== 'string' || !source) return [];
  const found = new Set();
  const bindings = ['options', 'opts', 'config', ...extraBindings];
  const bindAlt = bindings.map(b => `\\b${b}`).join('|');

  // Member reads on options-ish bindings: options.foo, opts?.bar, init.baz
  const memberRe = new RegExp(`(?:${bindAlt})\\s*\\?*\\.\\s*(${IDENT})`, 'g');
  for (const m of source.matchAll(memberRe)) found.add(m[1]);

  // process.env.FOO reads — env lookups fall through to Object.prototype, so
  // a polluted NODE_TLS_REJECT_UNAUTHORIZED/NODE_OPTIONS-style name IS a
  // gadget candidate (GHunter's https NODE_TLS_REJECT_UNAUTHORIZED row).
  const envRe = /process\.env\s*\??\.\s*([A-Z_][A-Z0-9_]{2,39})/g;
  for (const m of source.matchAll(envRe)) found.add(m[1]);

  // Destructuring of an options-ish binding: const { a, b = 1, c: d } = options
  const destrRe = new RegExp(`\\{([^{}]+)\\}\\s*=\\s*(?:${bindAlt})\\b`, 'g');
  for (const m of source.matchAll(destrRe)) {
    for (const part of m[1].split(',')) {
      // 'a', 'a = 1', 'a: renamed', 'a: { nested }' — the candidate is the KEY
      const key = part.trim().match(new RegExp(`^\\.\\.\\.?(${IDENT})|^(${IDENT})`));
      const name = key && (key[1] || key[2]);
      if (name) found.add(name);
    }
  }

  // Drop global noise/own-ness names and the class's always-set baseline keys.
  const out = [];
  for (const name of found) {
    if (GLOBAL_DENYLIST.has(name) || denylist.has(name)) continue;
    out.push(name);
  }
  return out.sort();
}

/**
 * Computed-read suspects. A read like `options[k]` hides the property name
 * behind a variable, which the member/destructuring patterns above cannot see
 * — but the possible names almost always appear nearby as string literals in
 * comparisons (`mode === 'writable'`) or `case 'x':` labels. Harvest those as
 * suspects; the oracle filters the noise (many literals are VALUES, not names,
 * and those simply come back INERT).
 *
 * Filtered to lowercase-initial identifier-shaped literals of reasonable
 * length — this excludes error codes (ERR_*), messages, and encodings with
 * dashes — plus the typeof keyword results, which are never property names.
 */
const TYPEOF_NOISE = new Set([
  'object', 'string', 'number', 'function', 'undefined', 'boolean', 'symbol', 'bigint',
]);

export function harvestLiteralSuspects(source, denylist = new Set()) {
  if (typeof source !== 'string' || !source) return [];
  const found = new Set();
  const literalRe = /(?:case\s+|===?\s*|!==?\s*)'([a-z][A-Za-z0-9_$]{1,29})'/g;
  for (const m of source.matchAll(literalRe)) {
    const name = m[1];
    if (GLOBAL_DENYLIST.has(name) || TYPEOF_NOISE.has(name) || denylist.has(name)) continue;
    found.add(name);
  }
  // ALL-CAPS string literals: env-var-style option names (e.g. the maps in
  // internal/options) — GHunter's NODE_TLS_REJECT_UNAUTHORIZED gadget is read
  // this way, not via a process.env.X member read. ERR_* codes excluded.
  const capsRe = /'([A-Z][A-Z0-9_]{3,39})'/g;
  for (const m of source.matchAll(capsRe)) {
    const name = m[1];
    if (name.startsWith('ERR_') || name.startsWith('UV_') || denylist.has(name)) continue;
    found.add(name);
  }
  return [...found].sort();
}

/**
 * Harvest candidates for one API class from the runtime's builtin source.
 * Combines member/destructuring reads with computed-read literal suspects.
 * @param {string} classId key of API_CLASSES
 * @param {object} [natives] injectable for tests (defaults to the real map)
 * @returns {{ classId: string, driver: string, properties: string[] }}
 */
export function harvestClass(classId, natives) {
  const cls = API_CLASSES[classId];
  if (!cls) throw new Error(`unknown API class: ${classId}`);
  const n = natives || process.binding('natives');
  const deny = new Set(cls.baselineKeys);
  const all = new Set();
  for (const mod of cls.sources) {
    const src = n[mod];
    if (typeof src !== 'string') continue; // module absent on this Node version
    for (const p of harvestCandidates(src, deny, cls.extraBindings)) all.add(p);
    for (const p of harvestLiteralSuspects(src, deny)) all.add(p);
  }
  return { classId, driver: cls.driver, properties: [...all].sort() };
}

/** Harvest every known class. @returns {Map<string, {driver, properties[]}>} */
export function harvestAll({ classes, natives } = {}) {
  const ids = classes || Object.keys(API_CLASSES);
  const out = new Map();
  for (const id of ids) {
    const { driver, properties } = harvestClass(id, natives);
    out.set(id, { driver, properties });
  }
  return out;
}
