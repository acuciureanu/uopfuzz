import { forkSandboxWorker, serializeArgs } from './sandbox.js';
import { logger } from './logger.js';
import { JSDOM_STARTUP_ALLOWANCE_MS } from './browser-env.js';

/**
 * Persistent sandbox worker pool.
 *
 * The discovery differential phase issues hundreds of probes per iteration, and
 * the one-shot `executeInSandbox` forked a fresh Node process — re-`import()`ing
 * the whole target (and rebuilding jsdom for browser packages) — for EVERY one.
 * That per-probe Node-startup + module-graph-eval cost dominated a real run's
 * wall-clock. This pool keeps one long-lived worker per (package, browserEnv,
 * blockNetwork), so the target is loaded once and reused across probes.
 *
 * Scope / safety:
 * - ONLY the discovery worker (sandbox-worker.js) is pooled. The independent
 *   REPRODUCTION worker (repro-worker.js) deliberately stays one-shot in fresh
 *   processes — the zero-false-positive proof is unchanged.
 * - The worker restores monitored prototypes to a post-load baseline before each
 *   request, so reuse is as clean as a fresh fork for discovery purposes.
 * - Crash/hang containment is preserved: the parent owns a wall-clock timeout
 *   that SIGKILLs a wedged worker, and a died/killed worker fails only its
 *   in-flight probe (same null/error result the caller already handles) and is
 *   respawned lazily. One probe crashing no longer costs a whole fresh fork for
 *   the healthy majority around it.
 *
 * Concurrency: one in-flight request per worker (the differential loop is
 * sequential); extra requests queue FIFO. Matching a reply to its request is by
 * an echoed requestId.
 */

const DISCOVERY_WORKER = 'sandbox-worker.js';

class PooledWorker {
  constructor(key, blockNetwork) {
    this.key = key;
    this.blockNetwork = blockNetwork;
    this.child = null;
    this.busy = false;
    this.queue = [];      // [{ msg, timeoutMs, browserEnv, resolve }]
    this.current = null;  // { requestId, resolve, timer }
    this.nextId = 1;
    this.destroyed = false;
  }

  _ensureChild() {
    if (this.child) return;
    const child = forkSandboxWorker(DISCOVERY_WORKER, this.blockNetwork);
    child.on('message', (msg) => this._onMessage(msg));
    child.on('exit', (code) => this._onDeath(`sandbox worker exited (code ${code})`));
    child.on('error', (err) => this._onDeath(`sandbox worker error: ${err.message}`));
    // An idle pooled worker must NOT keep the parent's event loop alive — a
    // caller that forgets to destroy() the pool (e.g. a unit test that drives
    // the differential engine directly) would otherwise hang on exit. During an
    // in-flight request the referenced timeout timer keeps the loop alive, so
    // requests are never dropped; the worker still self-exits on parent
    // disconnect, so unref'd workers are never leaked as orphans.
    child.unref();
    child.channel?.unref();
    // The worker's stdout/stderr are piped (from forkSandboxWorker) but the pool
    // never reads them; leave those pipe handles referenced and an idle worker
    // still keeps the parent's loop alive under `node --test`. Unref them all.
    child.stdout?.unref?.();
    child.stderr?.unref?.();
    child.stdin?.unref?.();
    this.child = child;
  }

  _onMessage(msg) {
    const cur = this.current;
    if (!cur) return;
    // Ignore a stale reply from a worker we've already moved past.
    if (msg && msg.requestId !== undefined && msg.requestId !== cur.requestId) return;
    clearTimeout(cur.timer);
    this.current = null;
    this.busy = false;
    const result = msg ? { ...msg } : { error: 'empty worker reply', output: null };
    delete result.requestId;
    cur.resolve(result);
    this._pump();
  }

  // Worker process died (crash, OOM, or our own SIGKILL). Fail the in-flight
  // probe as a contained error and drop the child; the next request respawns.
  _onDeath(reason) {
    const cur = this.current;
    this.child = null;
    this.busy = false;
    this.current = null;
    if (cur) {
      clearTimeout(cur.timer);
      cur.resolve({ error: reason, output: null, crashed: true });
    }
    this._pump();
  }

  send(msg, timeoutMs, browserEnv) {
    return new Promise((resolve) => {
      this.queue.push({ msg, timeoutMs, browserEnv, resolve });
      this._pump();
    });
  }

  _pump() {
    if (this.destroyed || this.busy) return;
    const job = this.queue.shift();
    if (!job) return;

    this._ensureChild();
    const requestId = this.nextId++;
    const startupAllowance = job.browserEnv ? JSDOM_STARTUP_ALLOWANCE_MS : 0;

    // Parent-side wall-clock: SIGKILL a worker whose request wedges the event
    // loop (a synchronous infinite loop in the target blocks the worker's own
    // self-timer, so only the parent can rescue it). +1s IPC grace, matching the
    // one-shot path in sandbox.js.
    const timer = setTimeout(() => {
      this.current = null;
      this.busy = false;
      try { this.child?.kill('SIGKILL'); } catch { /* already gone */ }
      this.child = null;
      job.resolve({ error: 'Sandbox execution timed out', timedOut: true, output: null });
      this._pump();
    }, (job.timeoutMs || 5000) + startupAllowance + 1000);

    this.current = { requestId, resolve: job.resolve, timer };
    this.busy = true;
    try {
      this.child.send({ ...job.msg, requestId });
    } catch (err) {
      clearTimeout(timer);
      this.current = null;
      this.busy = false;
      this.child = null;
      job.resolve({ error: `sandbox worker send failed: ${err.message}`, output: null, crashed: true });
      this._pump();
    }
  }

  destroy() {
    this.destroyed = true;
    this.queue = [];
    if (this.current) {
      clearTimeout(this.current.timer);
      this.current = null;
    }
    try { this.child?.kill('SIGKILL'); } catch { /* already gone */ }
    this.child = null;
  }
}

export class SandboxPool {
  constructor() {
    this.workers = new Map();
  }

  _key(packageName, browserEnv, blockNetwork) {
    return `${packageName}::${browserEnv ? 1 : 0}::${blockNetwork ? 1 : 0}`;
  }

  /**
   * Run one discovery probe, mirroring executeInSandbox's signature and return
   * shape, but reusing a persistent worker for the package.
   */
  run(packageName, entryPoint, args, options = {}) {
    const {
      timeoutMs = 5000,
      blockNetwork = true,
      pollution = null,
      mode = 'execute',
      browserEnv = false,
      extra = null,
    } = options;

    const key = this._key(packageName, browserEnv, blockNetwork);
    let worker = this.workers.get(key);
    if (!worker) {
      worker = new PooledWorker(key, blockNetwork);
      this.workers.set(key, worker);
    }

    // Identical IPC message to the one-shot path (so the worker's dispatch is
    // unchanged); args serialized the same way.
    const msg = {
      mode,
      packageName,
      entryPoint,
      args: serializeArgs(args),
      timeoutMs,
      pollution,
      browserEnv,
      ...(extra || {}),
    };
    return worker.send(msg, timeoutMs, browserEnv);
  }

  /** SIGKILL every worker and drop them. Call at run teardown. */
  destroy() {
    for (const worker of this.workers.values()) {
      worker.destroy();
    }
    this.workers.clear();
    logger.debug('SandboxPool destroyed');
  }
}
