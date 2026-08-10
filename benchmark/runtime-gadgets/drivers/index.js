/**
 * Side-effect-free drivers for the GHunter runtime-gadget corpus.
 *
 * Each probe exercises a Node core API the way the corresponding GHunter PoC
 * (KTH-LangSec/server-side-prototype-pollution, nodejs/) does, so the fuzzer's
 * oracle can observe whether a polluted Object.prototype property flows into
 * the API. Drivers never produce external effects on their own:
 * child_process/worker_threads are blocked by the worker hardening (the sink
 * recorder sees the call BEFORE the blocked stub throws), network is blocked at
 * the socket, and everything here is local-only anyway.
 */

// ─── child_process env/NODE_OPTIONS family (ACE / EoP) ───────────────────────
// GHunter PoCs: nodejs/child_process/*.env.PoC.js — a polluted env var (e.g.
// NODE_OPTIONS=--inspect-brk / --require) is picked up by spawn normalization
// through prototype fall-through on the options/env object.
function cpCall(method) {
  return function probe() {
    const cp = require('child_process');
    try {
      if (method === 'fork') cp.fork(require.resolve('./sub'), { env: { AAA: 'BBB' } });
      else if (method === 'execFile') cp.execFile('node', ['-e', '0'], { env: { AAA: 'BBB' } });
      else if (method === 'execFileSync') cp.execFileSync('node', ['-e', '0'], { env: { AAA: 'BBB' } });
      else if (method === 'spawn') cp.spawn('node', ['-e', '0'], { env: { AAA: 'BBB' } });
      else if (method === 'spawnSync') cp.spawnSync('node', ['-e', '0'], { env: { AAA: 'BBB' } });
      else if (method === 'execSync') cp.execSync('node -e 0', { env: { AAA: 'BBB' } });
      else cp.exec('node -e 0', { env: { AAA: 'BBB' } });
    } catch { /* blocked — recording already happened */ }
    return 'called';
  };
}

// ─── http(s) options family (EoP / SSRF / DoS) ───────────────────────────────
// GHunter PoCs: nodejs/http(s)/get|requiest.options.PoC.js — polluted
// method/port/path/headers/hostname fall through into request options.
function httpCall(modName, method) {
  return async function probe() {
    const mod = require(modName);
    try {
      const req = mod[method]({ host: '127.0.0.1' });
      if (req && typeof req.on === 'function') req.on('error', () => {});
      if (req && typeof req.end === 'function') req.end();
      // Read back what Node decided — polluted options change these.
      return { method: req.method, path: req.path, host: req.host };
    } catch (e) {
      return { error: String(e && e.message || e).slice(0, 120) };
    }
  };
}

// ─── fetch socketPath / options (SSRF to local sockets, EoP) ─────────────────
// GHunter PoC: nodejs/http/fetch.socketPath.PoC.js — polluted socketPath
// redirects fetch to a local unix socket (e.g. the Docker daemon).
//
// Two probe shapes:
//  - probeFetch (differential): constructs the undici Request directly — the
//    init dictionary is fully consumed at construction (method/headers/referer
//    reflected on the instance), so the fingerprint needs NO network and is
//    value-sensitive (the marker itself shows up in the readback).
//  - probeFetchNetwork (DoS oracle): a real fetch(), because the fatal
//    `signal` crash lives in fetch's async teardown path, not the constructor.
function probeFetch() {
  try {
    const req = new Request('http://127.0.0.1:9/x', {});
    return {
      method: req.method,
      referer: req.headers.get('referer'),
      mode: req.mode,
      credentials: req.credentials,
      cache: req.cache,
      redirect: req.redirect,
      hasBody: req.body !== null,
    };
  } catch (e) {
    return { err: String((e && (e.code || e.name)) || e).slice(0, 80) };
  }
}
async function probeFetchNetwork() {
  try {
    const res = await fetch('http://127.0.0.1:9/');
    return { status: res.status };
  } catch (e) {
    const cause = e && e.cause;
    return { error: String(cause && cause.code || cause && cause.message || e && e.message || e).slice(0, 160) };
  }
}

// ─── tls.connect options (crypto downgrade / DoS) ────────────────────────────
// GHunter PoC: nodejs/https/tls.connect.PoC.js — polluted port/path/session/
// rejectUnauthorized fall through into the TLS options.
function probeTlsConnect() {
  const tls = require('tls');
  try {
    const sock = tls.connect({ host: '127.0.0.1', port: 1 });
    if (sock && typeof sock.on === 'function') sock.on('error', () => {});
    if (sock && typeof sock.destroy === 'function') sock.destroy();
    return 'called';
  } catch (e) {
    return { error: String(e && e.message || e).slice(0, 120) };
  }
}

// ─── dynamic import source (ACE; fixed in current Node) ──────────────────────
// GHunter PoC: nodejs/import/import.source.PoC.js — polluted `source` is
// evaluated instead of the file contents when importing an .mjs module.
async function probeImport() {
  try {
    await import('./plain.mjs');
    return 'imported';
  } catch (e) {
    return { error: String(e && e.message || e).slice(0, 120) };
  }
}

// ─── require main (ACE; fixed in Node v18.19.0) ──────────────────────────────
// GHunter PoC: nodejs/require/require.main*.PoC.js — polluted `main` redirects
// directory requires to an attacker-chosen entry file.
function probeRequireDir() {
  try {
    require('./sub');
    return 'required';
  } catch (e) {
    return { error: String(e && e.message || e).slice(0, 120) };
  }
}

// ─── worker_threads ctor options (EoP / second-order ACE) ────────────────────
// GHunter PoC: nodejs/working_threads/ctor.PoC.js — polluted env/eval/execArgv
// fall through into the Worker constructor options.
function probeWorkerCtor() {
  const { Worker } = require('worker_threads');
  try {
    new Worker(require.resolve('./sub'), { workerData: {} });
    return 'spawned';
  } catch (e) {
    return { error: String(e && e.message || e).slice(0, 120) };
  }
}

// ─── MINING PROBES ───────────────────────────────────────────────────────────
// Generic probes for the runtime gadget miner (src/runtime-miner/). Each probe
// invokes its API class with a minimal, safe, deterministic baseline call and
// returns a FINGERPRINT: public observable state or the thrown error's
// code/name only — never raw messages containing ports, pids, or paths, so the
// differential oracle's clean-vs-polluted comparison is stable run-to-run.
// Loopback-only; no external effect (a plain-process DoS run may spawn
// `node -e 0` or a trivial worker — both exit immediately).

const errFp = (e) => ({ err: String((e && (e.code || e.name)) || e).slice(0, 80) });

// http.Server.listen — ephemeral port, fingerprint is just "listening"/error.
function probeHttpListen() {
  return new Promise((resolve) => {
    try {
      const server = require('http').createServer(() => {});
      server.on('error', (e) => resolve(errFp(e)));
      server.listen(0, '127.0.0.1', () => server.close(() => resolve({ listening: true })));
    } catch (e) { resolve(errFp(e)); }
  });
}

// net.connect — port 1 loopback: deterministic ECONNREFUSED baseline.
function probeNetConnect() {
  return new Promise((resolve) => {
    try {
      const sock = require('net').connect({ port: 1, host: '127.0.0.1' });
      sock.on('error', (e) => resolve(errFp(e)));
      sock.on('connect', () => { sock.destroy(); resolve({ connected: true }); });
    } catch (e) { resolve(errFp(e)); }
  });
}

// child_process — spawn/execFile of a trivial node one-liner. In the sandbox
// these hit the blocked stub (sync throw); in a plain DoS process the child
// exits immediately. Fingerprint: error code/name, or 'spawned'.
function probeCpSpawn() {
  try {
    const cp = require('child_process');
    const c = cp.spawn('node', ['-e', '0'], { env: { AAA: 'BBB' } });
    if (c && typeof c.on === 'function') { c.on('error', () => {}); c.unref && c.unref(); }
    return { spawned: true };
  } catch (e) { return errFp(e); }
}
function probeCpExecFile() {
  try {
    const cp = require('child_process');
    const c = cp.execFile('node', ['-e', '0'], { env: { AAA: 'BBB' } }, () => {});
    if (c && typeof c.on === 'function') { c.on('error', () => {}); c.unref && c.unref(); }
    return { spawned: true };
  } catch (e) { return errFp(e); }
}

// stream.Readable / Writable — the fingerprint captures whether construction,
// first read/write, and end complete normally. A polluted highWaterMark /
// decodeStrings / objectMode observably changes this (or kills the process —
// which the miner's DoS oracle scores separately).
function probeStreamReadable() {
  return new Promise((resolve) => {
    try {
      const s = new (require('stream').Readable)({ read() { this.push(null); } });
      let data = null;
      s.on('data', (c) => { data = (data || '') + String(c); });
      s.on('end', () => resolve({ ended: true, dataType: data === null ? 'none' : typeof data }));
      s.on('error', (e) => resolve(errFp(e)));
      s.resume();
    } catch (e) { resolve(errFp(e)); }
  });
}
function probeStreamWritable() {
  return new Promise((resolve) => {
    try {
      const w = new (require('stream').Writable)({ write(c, e, cb) { cb(); } });
      w.on('finish', () => resolve({ finished: true }));
      w.on('error', (e) => resolve(errFp(e)));
      w.write('x');
      w.end();
    } catch (e) { resolve(errFp(e)); }
  });
}

// fs.readFile — read this package's own package.json (fixed content).
// A polluted `encoding` flips the result type Buffer→string; a polluted
// `flag` changes the outcome. Both are observable in the fingerprint.
function probeFsReadFile() {
  return new Promise((resolve) => {
    try {
      require('fs').readFile(require.resolve('./package.json'), (err, data) => {
        if (err) return resolve(errFp(err));
        resolve({ type: Buffer.isBuffer(data) ? 'buffer' : typeof data, len: data.length });
      });
    } catch (e) { resolve(errFp(e)); }
  });
}

// fs.writeFile — write+unlink a fixed temp file. Fingerprint is success/error
// code; the file content is constant.
function probeFsWriteFile() {
  return new Promise((resolve) => {
    const p = require('path').join(require('os').tmpdir(), 'uopfuzz-miner-write.probe');
    try {
      require('fs').writeFile(p, 'x', (err) => {
        try { require('fs').unlinkSync(p); } catch { /* never written */ }
        if (err) return resolve(errFp(err));
        resolve({ written: true });
      });
    } catch (e) { resolve(errFp(e)); }
  });
}

// dns.lookup — 'localhost' is deterministic within a run (the differential
// compares clean vs polluted inside the same process).
function probeDnsLookup() {
  return new Promise((resolve) => {
    try {
      require('dns').lookup('localhost', (err, address, family) => {
        if (err) return resolve(errFp(err));
        resolve({ isIp: require('net').isIP(address), family });
      });
    } catch (e) { resolve(errFp(e)); }
  });
}

// zlib.createGzip — compress a constant byte; fingerprint is the compressed
// length (changes with level/strategy/params pollution) or the error.
function probeZlibGzip() {
  return new Promise((resolve) => {
    try {
      const gz = require('zlib').createGzip({});
      const chunks = [];
      gz.on('data', (c) => chunks.push(c));
      gz.on('end', () => resolve({ len: chunks.reduce((n, c) => n + c.length, 0) }));
      gz.on('error', (e) => resolve(errFp(e)));
      gz.end('x');
    } catch (e) { resolve(errFp(e)); }
  });
}

// vm.Script — compile and run a constant expression. Polluted filename/
// produceCachedData/etc. surface as an error change; the result is constant.
function probeVmScript() {
  try {
    const vm = require('vm');
    const s = new vm.Script('1+1', {});
    return { result: s.runInThisContext() };
  } catch (e) { return errFp(e); }
}

// crypto.createHash — constant input → constant digest. A polluted options
// key (outputEncoding, readableObjectMode, …) shows up as an error or a
// digest-type change.
function probeCryptoHash() {
  try {
    const d = require('crypto').createHash('sha256').update('x').digest('hex');
    return { digest: d };
  } catch (e) { return errFp(e); }
}

module.exports = {
  probeExec: cpCall('exec'),
  probeExecSync: cpCall('execSync'),
  probeExecFile: cpCall('execFile'),
  probeExecFileSync: cpCall('execFileSync'),
  probeSpawn: cpCall('spawn'),
  probeSpawnSync: cpCall('spawnSync'),
  probeFork: cpCall('fork'),
  probeHttpRequest: httpCall('http', 'request'),
  probeHttpGet: httpCall('http', 'get'),
  probeHttpsRequest: httpCall('https', 'request'),
  probeHttpsGet: httpCall('https', 'get'),
  probeFetch,
  probeFetchNetwork,
  probeTlsConnect,
  probeImport,
  probeRequireDir,
  probeWorkerCtor,
  // mining probes
  probeHttpListen,
  probeNetConnect,
  probeCpSpawn,
  probeCpExecFile,
  probeStreamReadable,
  probeStreamWritable,
  probeFsReadFile,
  probeFsWriteFile,
  probeDnsLookup,
  probeZlibGzip,
  probeVmScript,
  probeCryptoHash,
};
