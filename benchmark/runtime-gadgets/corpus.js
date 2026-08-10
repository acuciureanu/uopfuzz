/**
 * The GHunter runtime-gadget corpus (head-to-head benchmark).
 *
 * Each entry encodes one universal gadget from GHunter's published Node.js PoC
 * set (KTH-LangSec/server-side-prototype-pollution, nodejs/ — GHunter,
 * USENIX Security '24) at the property level: which Object.prototype property
 * is polluted, which driver entry point exercises the affected Node core API,
 * and through which oracle the flow is observed:
 *
 *   via 'repro'        — the reproduction worker plants a unique token on the
 *                        property and the sink recorder must capture it in the
 *                        sink's arguments (options-aware traversal). DETECTED
 *                        means a 2× fresh-process sink_reach/RCE proof.
 *   via 'differential' — the sandbox differential observes the pollution being
 *                        read (getter trap) and/or a behavior/error change.
 *   via 'dos'          — GHunter §4.3 style: the driver runs in a plain child
 *                        process (stock runtime, exactly like GHunter's
 *                        unexpected-termination stage); a polluted-only
 *                        non-zero exit is a DoS gadget.
 *
 * `fixedIn` records the Node version that fixed the gadget, where the PoC or
 * the paper documents it. On a current-enough Node the CORRECT verdict for
 * those entries is FIXED-UPSTREAM (no effect) — the benchmark fails if a
 * fixed gadget suddenly becomes observable again (a Node regression).
 *
 * `mitigated` marks gadgets with NO documented fix (Node considers runtime
 * gadgets out of its threat model, per GHunter's disclosure) that are
 * empirically non-exploitable on this Node due to incidental hardening —
 * verified by direct experiment before being marked (the reason string says
 * how). Their correct verdict is MITIGATED-UPSTREAM; if one becomes
 * observable again the benchmark fails, exactly like a fixed gadget.
 */

export const DRIVERS_PACKAGE = new URL('./drivers', import.meta.url).pathname;

export const RUNTIME_GADGETS = [
  // ─── child_process env / NODE_OPTIONS family — ACE / privilege escalation ──
  { id: 'cp-exec-env',         api: 'child_process.exec',         entryPoint: 'probeExec',         property: 'NODE_OPTIONS', category: 'ACE', via: 'repro', expectSink: 'child_process.exec',         ghunter: 'nodejs/child_process/exec.env.PoC.js' },
  { id: 'cp-execSync-env',     api: 'child_process.execSync',     entryPoint: 'probeExecSync',     property: 'NODE_OPTIONS', category: 'ACE', via: 'repro', expectSink: 'child_process.execSync',     ghunter: 'nodejs/child_process/execSync.env.lnx.PoC.js' },
  { id: 'cp-execFile-env',     api: 'child_process.execFile',     entryPoint: 'probeExecFile',     property: 'NODE_OPTIONS', category: 'ACE', via: 'repro', expectSink: 'child_process.execFile',     ghunter: 'nodejs/child_process/execFile.env.PoC.js' },
  { id: 'cp-execFileSync-env', api: 'child_process.execFileSync', entryPoint: 'probeExecFileSync', property: 'NODE_OPTIONS', category: 'ACE', via: 'repro', expectSink: 'child_process.execFileSync', ghunter: 'nodejs/child_process/execFileSync.input.win.PoC.js' },
  { id: 'cp-spawn-env',        api: 'child_process.spawn',        entryPoint: 'probeSpawn',        property: 'NODE_OPTIONS', category: 'ACE', via: 'repro', expectSink: 'child_process.spawn',        ghunter: 'nodejs/child_process/spawn.env.PoC.js' },
  { id: 'cp-spawnSync-env',    api: 'child_process.spawnSync',    entryPoint: 'probeSpawnSync',    property: 'NODE_OPTIONS', category: 'ACE', via: 'repro', expectSink: 'child_process.spawnSync',    ghunter: 'nodejs/child_process/spawnSync.env.lnx.PoC.js' },
  { id: 'cp-fork-env',         api: 'child_process.fork',         entryPoint: 'probeFork',         property: 'NODE_OPTIONS', category: 'ACE', via: 'repro', expectSink: 'child_process.fork',         ghunter: 'nodejs/child_process/fork.env.PoC.js' },
  // The shell-override variant: options.shell fall-through (the PoC notes the
  // env-rewrite part was fixed; the shell flow is checked empirically).
  { id: 'cp-execSync-shell',   api: 'child_process.execSync',     entryPoint: 'probeExecSync',     property: 'shell',        category: 'ACE', via: 'repro', expectSink: 'child_process.execSync',     ghunter: 'nodejs/child_process/execSync.env.lnx.PoC.js' },
  // Conjunctive combo (shell + NODE_OPTIONS in ONE pollution) — beyond
  // GHunter, which pollutes a single property at a time (paper §4.5).
  { id: 'cp-spawn-shell-env-combo', api: 'child_process.spawn', entryPoint: 'probeCpSpawn', properties: ['shell', 'NODE_OPTIONS'], category: 'ACE', via: 'multi', expectSink: 'child_process.spawn', ghunter: 'nodejs/child_process/spawn.env.PoC.js (combo form)' },
  // The remaining published shell/env fall-through variants (Silent Spring
  // rows of the KTH table) — same sink family, distinct normalization paths.
  { id: 'cp-exec-shell',         api: 'child_process.exec',         entryPoint: 'probeExec',         property: 'shell', category: 'ACE', via: 'repro', expectSink: 'child_process.exec',         ghunter: 'KTH README table (SS row)' },
  { id: 'cp-execSync-env',       api: 'child_process.execSync',     entryPoint: 'probeExecSync',     property: 'env',   category: 'ACE', via: 'repro', expectSink: 'child_process.execSync',     ghunter: 'KTH README table (SS row)' },
  { id: 'cp-execFileSync-shell', api: 'child_process.execFileSync', entryPoint: 'probeExecFileSync', property: 'shell', category: 'ACE', via: 'repro', expectSink: 'child_process.execFileSync', ghunter: 'KTH README table (SS row)' },
  { id: 'cp-spawn-shell',        api: 'child_process.spawn',        entryPoint: 'probeSpawn',        property: 'shell', category: 'ACE', via: 'repro', expectSink: 'child_process.spawn',        ghunter: 'KTH README table (SS row)' },
  { id: 'cp-spawn-env',          api: 'child_process.spawn',        entryPoint: 'probeSpawn',        property: 'env',   category: 'ACE', via: 'repro', expectSink: 'child_process.spawn',        ghunter: 'KTH README table (SS row)' },
  { id: 'cp-spawnSync-shell',    api: 'child_process.spawnSync',    entryPoint: 'probeSpawnSync',    property: 'shell', category: 'ACE', via: 'repro', expectSink: 'child_process.spawnSync',    ghunter: 'KTH README table (SS row)' },
  { id: 'cp-spawnSync-env',      api: 'child_process.spawnSync',    entryPoint: 'probeSpawnSync',    property: 'env',   category: 'ACE', via: 'repro', expectSink: 'child_process.spawnSync',    ghunter: 'KTH README table (SS row)' },

  // ─── http(s) request options — EoP / SSRF ──────────────────────────────────
  { id: 'http-request-path',   api: 'http.request',   entryPoint: 'probeHttpRequest',   property: 'path',   category: 'EoP', via: 'repro', expectSink: 'http.request',   ghunter: 'nodejs/http/requiest.options.PoC.js' },
  { id: 'http-request-method', api: 'http.request',   entryPoint: 'probeHttpRequest',   property: 'method', category: 'EoP', via: 'repro', expectSink: 'http.request',   ghunter: 'nodejs/http/requiest.options.PoC.js' },
  { id: 'http-get-path',       api: 'http.get',       entryPoint: 'probeHttpGet',       property: 'path',   category: 'EoP', via: 'repro', expectSink: 'http.get',       ghunter: 'nodejs/http/get.options.PoC.js' },
  { id: 'https-request-path',  api: 'https.request',  entryPoint: 'probeHttpsRequest',  property: 'path',   category: 'EoP', via: 'repro', expectSink: 'https.request',  ghunter: 'nodejs/https/requiest.options.PoC.js' },
  { id: 'https-get-path',      api: 'https.get',      entryPoint: 'probeHttpsGet',      property: 'path',   category: 'EoP', via: 'repro', expectSink: 'https.get',      ghunter: 'nodejs/https/get.options.PoC.js' },
  { id: 'https-request-method', api: 'https.request', entryPoint: 'probeHttpsRequest',  property: 'method', category: 'EoP', via: 'repro', expectSink: 'https.request',  ghunter: 'KTH README table' },
  // hostname/headers/port pollution: LIVE on GHunter's Node v21, DEAD on
  // Node 24 — verified by direct experiment (2026-08-10): a polluted port is
  // ignored (connection goes to the default port), polluted headers never
  // reach the wire, polluted hostname does not change the Host header. Node
  // now normalizes/copies these options instead of reading them lazily.
  { id: 'http-request-hostname',  api: 'http.request',  bhvProbe: 'bhv-http-options',  property: 'hostname', value: 'polluted.example', category: 'SSRF', via: 'behavioral', ghunter: 'KTH README table', mitigated: 'options normalized before use (verified Node 24.17)' },
  { id: 'http-request-headers',   api: 'http.request',  bhvProbe: 'bhv-http-options',  property: 'headers',  value: '{"x-polluted":"yes"}', bhvType: 'json', category: 'SSRF', via: 'behavioral', ghunter: 'KTH README table', mitigated: 'polluted headers never reach the wire (verified Node 24.17)' },
  { id: 'http-request-port',      api: 'http.request',  bhvProbe: 'bhv-http-port',     property: 'port',     value: '45932', bhvType: 'json', category: 'SSRF', via: 'behavioral', ghunter: 'KTH README table', mitigated: 'polluted port ignored (verified Node 24.17)' },
  { id: 'https-request-hostname', api: 'https.request', bhvProbe: 'bhv-https-options', property: 'hostname', value: 'polluted.example', category: 'SSRF', via: 'behavioral', ghunter: 'KTH README table', mitigated: 'same _http_client normalization as http.request (verified Node 24.17)' },
  { id: 'https-request-headers',  api: 'https.request', bhvProbe: 'bhv-https-options', property: 'headers',  value: '{"x-polluted":"yes"}', bhvType: 'json', category: 'SSRF', via: 'behavioral', ghunter: 'KTH README table', mitigated: 'same _http_client normalization as http.request (verified Node 24.17)' },
  { id: 'https-request-port',     api: 'https.request', bhvProbe: 'bhv-https-port',    property: 'port',     value: '45934', bhvType: 'json', category: 'SSRF', via: 'behavioral', ghunter: 'KTH README table', mitigated: 'same _http_client normalization as http.request (verified Node 24.17)' },

  // ─── fetch — SSRF to local sockets / EoP (undici reads its own options) ────
  // socketPath: GHunter's Docker-socket SSRF. NOT observable on Node 24 —
  // verified directly: a unix-socket server + polluted socketPath still hits
  // the TCP URL (undici no longer falls through for connect options).
  { id: 'fetch-socketPath', api: 'fetch', entryPoint: 'probeFetch', property: 'socketPath', category: 'SSRF', via: 'differential', ghunter: 'nodejs/http/fetch.socketPath.PoC.js', mitigated: 'undici ignores prototype socketPath (verified Node 24.17)' },
  { id: 'fetch-method',     api: 'fetch', entryPoint: 'probeFetch', property: 'method',     category: 'EoP',  via: 'differential', ghunter: 'nodejs/http/fetch.options.PoC.js' },
  // body: verified LIVE on Node 24 — polluted body turns a plain GET fetch into
  // "Request with GET/HEAD method cannot have body" (error change) and a body
  // is attached for other methods. Same init-dictionary fall-through as method.
  { id: 'fetch-body',       api: 'fetch', entryPoint: 'probeFetch', property: 'body',       category: 'EoP',  via: 'differential', ghunter: 'nodejs/http/fetch.options.PoC.js' },

  // ─── tls.connect options — crypto downgrade / path control ────────────────
  { id: 'tls-connect-rejectUnauthorized', api: 'tls.connect', entryPoint: 'probeTlsConnect', property: 'rejectUnauthorized', category: 'crypto-downgrade', via: 'repro', expectSink: 'tls.connect', ghunter: 'nodejs/https/tls.connect.PoC.js' },
  { id: 'tls-connect-path',               api: 'tls.connect', entryPoint: 'probeTlsConnect', property: 'path',               category: 'crypto-downgrade', via: 'repro', expectSink: 'tls.connect', ghunter: 'nodejs/https/tls.connect.PoC.js' },
  // port: verified LIVE on Node 24 — tls.connect({host}) with a polluted port
  // connects to the polluted port (direct experiment, plain net server).
  { id: 'tls-connect-port',               api: 'tls.connect', entryPoint: 'probeTlsConnect', property: 'port',               category: 'second-order-SSRF', via: 'repro', expectSink: 'tls.connect', ghunter: 'nodejs/https/tls.connect.PoC.js' },
  // NODE_TLS_REJECT_UNAUTHORIZED: verified LIVE on Node 24 by end-to-end
  // behavioral experiment — against a self-signed loopback server the clean
  // run fails validation (DEPTH_ZERO_SELF_SIGNED_CERT) and the polluted run
  // completes the handshake. Full crypto downgrade, certificate verification
  // off process-wide.
  { id: 'tls-connect-tls-reject',  api: 'tls.connect',   bhvProbe: 'bhv-tls-reject',   property: 'NODE_TLS_REJECT_UNAUTHORIZED', value: '0', category: 'crypto-downgrade', via: 'behavioral', ghunter: 'KTH README table' },
  { id: 'https-request-tls-reject', api: 'https.request', bhvProbe: 'bhv-https-reject', property: 'NODE_TLS_REJECT_UNAUTHORIZED', value: '0', category: 'crypto-downgrade', via: 'behavioral', ghunter: 'KTH README table' },

  // ─── module loaders — ACE (both fixed upstream; verified empirically) ──────
  // import-source: NOT observable on Node 24 — behavioral probe imports the
  // real module both ways; the polluted `source` is never used (ESM loader
  // rewrite). If it ever becomes live, the fingerprint flips to imported=666.
  { id: 'import-source', api: 'import()', bhvProbe: 'bhv-import-source', property: 'source', value: 'data:text/javascript,export default 666', category: 'ACE', via: 'behavioral', ghunter: 'nodejs/import/import.source.PoC.js', mitigated: 'ESM loader no longer reads prototype source (verified Node 24.17)' },
  { id: 'require-main',  api: 'require',  bhvProbe: 'bhv-require-main',  property: 'main',   value: 'evil.js', category: 'ACE', via: 'behavioral', ghunter: 'nodejs/require/require.main2.PoC.js', fixedIn: '18.19.0' },
  // require + NODE_OPTIONS: the ACE required the `main` resolution gadget to
  // load the attacker's file; with that fixed (18.19.0) the NODE_OPTIONS half
  // is inert — same probe, fingerprint must stay main=1.
  { id: 'require-node-options', api: 'require', bhvProbe: 'bhv-require-main', property: 'NODE_OPTIONS', value: '--inspect-brk=127.0.0.1:0', category: 'ACE', via: 'behavioral', ghunter: 'KTH README table', mitigated: 'ACE mechanism was the require-main gadget, fixed in 18.19.0; no effect verified Node 24.17' },

  // ─── worker_threads ctor options — EoP / second-order ACE ─────────────────
  { id: 'worker-ctor-env', api: 'worker_threads.Worker', entryPoint: 'probeWorkerCtor', property: 'env', category: 'EoP', via: 'repro', expectSink: 'worker_threads.Worker', ghunter: 'nodejs/working_threads/ctor.PoC.js' },
  // eval + argv: verified LIVE on Node 24 — polluted eval=true makes Worker
  // execute the "filename" string as code (ACE), polluted argv reaches the
  // worker's process.argv (direct experiments). Still unhardened upstream.
  { id: 'worker-ctor-eval', api: 'worker_threads.Worker', entryPoint: 'probeWorkerCtor', property: 'eval', category: 'ACE', via: 'repro', expectSink: 'worker_threads.Worker', ghunter: 'nodejs/working_threads/ctor.PoC.js' },
  { id: 'worker-ctor-argv', api: 'worker_threads.Worker', entryPoint: 'probeWorkerCtor', property: 'argv', category: 'EoP', via: 'repro', expectSink: 'worker_threads.Worker', ghunter: 'nodejs/working_threads/ctor.PoC.js' },

  // ─── DoS via unexpected termination (GHunter §4.3 — stock runtime) ────────
  // backlog: NOT observable on Node 24 — string backlog is silently ignored in
  // every listen() shape (direct experiment); the libuv segfault is gone.
  { id: 'dos-listen-backlog', api: 'http.Server.listen', dosDriver: 'dos-listen', property: 'backlog', value: 'uopfuzz-not-a-number', category: 'DoS', via: 'dos', ghunter: 'nodejs/http/listen.host.PoC.js', mitigated: 'net validates/ignores prototype backlog (verified Node 24.17)' },
  // session: NOT observable on Node 24 — tls.connect no longer throws on a
  // non-Buffer prototype session (direct experiment).
  { id: 'dos-tls-session',    api: 'tls.connect',        dosDriver: 'dos-tls',    property: 'session',  value: 'uopfuzz-not-a-buffer', category: 'DoS', via: 'dos', ghunter: 'nodejs/https/tls.connect.PoC.js', mitigated: 'tls.connect ignores prototype session (verified Node 24.17)' },
  // signal: verified LIVE fatal DoS on Node 24 — a polluted non-AbortSignal
  // makes undici's add-abort-signal throw ERR_INVALID_ARG_TYPE asynchronously,
  // uncatchable from user code (exit 1). The Node twin of GHunter's Deno
  // fetch-signal crash.
  { id: 'dos-fetch-signal',   api: 'fetch',              dosDriver: 'dos-fetch',  property: 'signal',   value: 'uopfuzz-not-a-signal', category: 'DoS', via: 'dos', ghunter: 'paper §3 (Deno fetch signal; Node twin verified live)' },
  // highWaterMark: verified LIVE fatal DoS on Node 24 — a polluted non-number
  // hwm makes stream state validation throw ERR_INVALID_ARG_VALUE
  // asynchronously, uncatchable (exit 1). Not in GHunter's Node list — found
  // by re-running their unexpected-termination methodology on Node 24.
  { id: 'dos-stream-hwm',     api: 'stream.Readable',    dosDriver: 'dos-stream', property: 'highWaterMark', value: 'uopfuzz-not-a-number', category: 'DoS', via: 'dos', ghunter: null },
];
