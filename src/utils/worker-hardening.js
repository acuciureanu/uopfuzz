/**
 * Shared worker-process hardening.
 *
 * Single source of truth for the capability blocks applied at the top of every
 * worker that executes untrusted target code — the discovery sandbox
 * (sandbox-worker.js) and the independent reproduction oracle (repro-worker.js).
 * Both import this so they cannot drift on *what* is blocked, exactly as both
 * share prototype-monitor.js for pollution detection.
 *
 * ── Threat model (read this before trusting it) ──────────────────────────────
 * These are best-effort, in-process JavaScript monkey-patches, NOT a security
 * sandbox. The target runs with the SAME uid, filesystem, and network namespace
 * as this process; a determined adversary can reach primitives that aren't
 * patched here, or obtain fresh references through paths these overrides don't
 * cover. They exist to stop the common, accidental, and low-effort cases —
 * telemetry, install-time beacons, a library that shells out — not to contain a
 * targeted exploit.
 *
 * The ACTUAL isolation boundary is the dev container (see .devcontainer/): no
 * secrets in its environment, egress governed by the network policy, ephemeral
 * filesystem. Run untrusted targets there. Everything below is defense in depth
 * layered inside that boundary, and is deliberately conservative about claiming
 * more than it delivers.
 *
 * What is blocked: outbound network (TCP via net.Socket, UDP via dgram, HTTP/2
 * client sessions), child-process spawning, and worker_threads (a Worker would
 * otherwise run on a fresh thread with none of these patches applied — the most
 * obvious escape, so it is closed here explicitly).
 *
 * What is intentionally NOT blocked: eval / Function. Reproduction must let the
 * canary payload actually execute to prove code execution, and the discovery
 * sandbox calls through to the originals so it can observe sink activity. Code
 * execution is contained by blocking the things that turn "attacker code ran in
 * this process" into external effects (network, child_process), plus the
 * container around it — not by preventing execution.
 */

const BLOCKED = 'blocked by UoPFuzz worker hardening';

/**
 * Apply the capability blocks to the current process. Idempotent and
 * side-effect only — call once at worker startup, before any target is loaded.
 *
 * `child_process` and `worker_threads` are ALWAYS blocked: there is no
 * legitimate reason for a fuzzed pure-JS library to shell out or spawn an
 * unpatched thread, and both are escape hatches out of every other block.
 * Outbound network is blocked only when `blockNetwork` is set, because the
 * operator can deliberately allow a target network egress (--allow-network) for
 * libraries that need it during execution.
 *
 * @param {NodeRequire} requireImpl - the worker's own
 *   `createRequire(import.meta.url)`; passed in because this module cannot
 *   synthesize a caller-relative require of its own for the builtins.
 * @param {{ blockNetwork?: boolean }} [opts]
 * @returns {{ send: (Function|null) }} `send` is a bound reference to the REAL
 *   `process.send` captured before the public one is sealed off. The worker must
 *   use this for its own replies; target code that reaches for `process.send`
 *   now hits a throwing stub. Null when there is no IPC channel.
 */
export function hardenWorkerProcess(requireImpl, opts = {}) {
  if (typeof requireImpl !== 'function') {
    throw new Error('hardenWorkerProcess requires the caller\'s require function');
  }
  const req = requireImpl;

  if (opts.blockNetwork) blockOutboundNetwork(req);
  blockChildProcess(req);
  blockWorkerThreads(req);
  return { send: sealProcessSend() };
}

/**
 * Capture the real `process.send` and replace the public one with a throwing
 * stub, so target code loaded later cannot emit an IPC message. Without this a
 * hostile package could `process.send({ verified: true })` at load time and
 * manufacture a "confirmed" finding — the parent resolves on the child's reply,
 * and the reproduction verdict is the whole zero-false-positive guarantee. The
 * parent's reply-token check (executeInSandbox in sandbox.js) is the second half
 * of the defense: even a target that recovers a raw send handle cannot guess the
 * per-fork token. Mirrors the process.exit hook each worker installs.
 *
 * @returns {Function|null} bound original send, or null with no IPC channel.
 */
function sealProcessSend() {
  const original = typeof process.send === 'function' ? process.send.bind(process) : null;
  const stub = function () {
    throw new Error(`process.send ${BLOCKED}`);
  };
  try {
    Object.defineProperty(process, 'send', { value: stub, writable: false, configurable: false });
  } catch {
    try { process.send = stub; } catch { /* ignore — cannot reassign */ }
  }
  return original;
}

/** TCP (net.Socket.prototype.connect), UDP (dgram bind), and HTTP/2 client sessions. */
function blockOutboundNetwork(req) {
  try {
    const net = req('net');
    // net.connect / net.createConnection / http(s) agents all funnel through
    // Socket.prototype.connect, so overriding the one method covers them.
    net.Socket.prototype.connect = function () {
      const err = new Error(`Network access ${BLOCKED}`);
      err.code = 'ENETBLOCKED';
      this.destroy(err);
      return this;
    };
  } catch (err) {
    process.stderr.write(`Warning: could not block TCP: ${err.message}\n`);
  }

  try {
    const dgram = req('dgram');
    dgram.Socket.prototype.bind = function () {
      throw new Error(`Network access ${BLOCKED}`);
    };
  } catch { /* dgram unavailable */ }

  // HTTP/2 has its own connection path that does not go through net.Socket in a
  // way the override above intercepts; block the client entry point directly.
  try {
    const http2 = req('http2');
    http2.connect = function () {
      throw new Error(`Network access ${BLOCKED}`);
    };
  } catch { /* http2 unavailable */ }
}

/** child_process.{exec,spawn,fork,…} — proof of execution is a global write, never a shell. */
function blockChildProcess(req) {
  try {
    const cp = req('child_process');
    for (const method of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
      if (cp[method]) {
        cp[method] = function () {
          throw new Error(`child_process.${method} ${BLOCKED}`);
        };
      }
    }
  } catch { /* child_process unavailable */ }
}

/**
 * worker_threads.Worker — without this a target could spawn a fresh thread that
 * carries NONE of the patches above (its own net, child_process, eval), which is
 * the single most obvious way to sidestep every other block. Closed for the
 * common `require('worker_threads').Worker` path; see the module threat model
 * for why this remains best-effort rather than a guarantee.
 */
function blockWorkerThreads(req) {
  try {
    const wt = req('worker_threads');
    const Blocked = function () {
      throw new Error(`worker_threads.Worker ${BLOCKED}`);
    };
    // Preserve the prototype so `instanceof` / feature checks don't throw before
    // construction is even attempted. But the shared prototype's `constructor`
    // backref still points at the REAL Worker, so `require('worker_threads')
    // .Worker.prototype.constructor` would hand target code an unpatched Worker
    // and reopen every block above — the one-liner escape. Repoint constructor
    // at the stub to close it.
    if (wt.Worker) {
      Blocked.prototype = wt.Worker.prototype;
      try {
        Object.defineProperty(Blocked.prototype, 'constructor', {
          value: Blocked, writable: true, configurable: true, enumerable: false,
        });
      } catch { /* prototype frozen — constructor cannot be repointed */ }
    }
    wt.Worker = Blocked;
  } catch { /* worker_threads unavailable */ }
}
