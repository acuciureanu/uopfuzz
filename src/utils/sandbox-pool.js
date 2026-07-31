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
 * wall-clock. This pool keeps up to `maxConcurrency` long-lived workers per
 * (package, browserEnv, blockNetwork), so the target is loaded once and
 * reused across probes.
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
 * Concurrency: one in-flight request per worker; extra requests on the same
 * worker queue FIFO. `maxConcurrency` (default 1) bounds how many workers the
 * pool lazily spawns per (package, browserEnv, blockNetwork) key: dispatch
 * picks the first non-busy worker, spawns another while all are busy and the
 * key is under its cap, and otherwise falls back to the least-queued busy
 * worker (whose own FIFO queue serializes). Matching a reply to its request
 * is by an echoed requestId.
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
    // False until this child has completed one request. Only that first (cold)
    // request pays the jsdom startup allowance; afterwards the target is loaded
    // and the allowance would just delay rescuing a wedged worker. Reset to
    // false whenever the child is dropped, since the replacement starts cold.
    this.warm = false;
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
    // Only the in-flight request's tagged reply may settle it. Untagged
    // control messages (exit-hook notices, kill-timer paths) are dropped.
    if (!msg || msg.requestId !== cur.requestId) return;
    clearTimeout(cur.timer);
    this.current = null;
    this.busy = false;
    // This child has now served a request, so its target (and jsdom, for a
    // browser-only package) is loaded and cached — subsequent requests are warm.
    // True even when the reply is a load error: that outcome is cached too, so
    // the next request returns immediately rather than re-attempting the load.
    this.warm = true;
    const result = { ...msg };
    delete result.requestId;
    delete result.__replyToken; // present-but-undefined for the pool path; keep results clean
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
    this.warm = false; // the replacement child starts cold
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
    // Cold starts only: a warm worker already has the target (and jsdom) loaded,
    // so charging it the 20s boot allowance would just delay rescuing a wedged
    // child. The worker computes the same allowance from its own target cache,
    // so the two deadlines stay in the intended order (worker self-timer first,
    // parent watchdog 500ms later).
    const startupAllowance = job.browserEnv && !this.warm ? JSDOM_STARTUP_ALLOWANCE_MS : 0;

    // Parent-side wall-clock: SIGKILL a worker whose request wedges the event
    // loop (a synchronous infinite loop in the target blocks the worker's own
    // self-timer, so only the parent can rescue it). +1s IPC grace, matching the
    // one-shot path in sandbox.js.
    const timer = setTimeout(() => {
      this.current = null;
      this.busy = false;
      this.warm = false; // killed child is replaced by a cold one
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
      this.warm = false; // dropped child is replaced by a cold one
      job.resolve({ error: `sandbox worker send failed: ${err.message}`, output: null, crashed: true });
      this._pump();
    }
  }

  destroy() {
    this.destroyed = true;
    // Settle every waiter — dropping queued/in-flight jobs unresolved would
    // hang any caller awaiting run() at teardown.
    const dropped = { error: 'sandbox pool destroyed', output: null };
    for (const job of this.queue) job.resolve(dropped);
    this.queue = [];
    if (this.current) {
      clearTimeout(this.current.timer);
      this.current.resolve(dropped);
      this.current = null;
    }
    try { this.child?.kill('SIGKILL'); } catch { /* already gone */ }
    this.child = null;
  }
}

export class SandboxPool {
  constructor({ maxConcurrency = 1 } = {}) {
    // Map<key, PooledWorker[]> — up to maxConcurrency lazily-spawned workers
    // per (package, browserEnv, blockNetwork) key.
    this.workers = new Map();
    this.maxConcurrency = Math.max(1, maxConcurrency);
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
      // Ask the worker to wrap the probe in a V8 inspector session and attach a
      // ScriptCoverage snapshot (`v8Coverage`) to the reply. The pool-level
      // default is off; Instrumentation passes it explicitly (on by default).
      collectCoverage = false,
      extra = null,
    } = options;

    const key = this._key(packageName, browserEnv, blockNetwork);
    let workers = this.workers.get(key);
    if (!workers) {
      workers = [];
      this.workers.set(key, workers);
    }

    // Dispatch: prefer a non-busy worker; spawn another while all are busy
    // and the key is under its concurrency cap; otherwise fall back to the
    // least-queued busy worker (its internal FIFO queue serializes the jobs).
    let worker = workers.find((w) => !w.busy);
    if (!worker) {
      if (workers.length < this.maxConcurrency) {
        worker = new PooledWorker(key, blockNetwork);
        workers.push(worker);
      } else {
        worker = workers.reduce((a, b) => (b.queue.length < a.queue.length ? b : a));
      }
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
      collectCoverage,
      ...(extra || {}),
    };
    return worker.send(msg, timeoutMs, browserEnv);
  }

  /** Structural snapshot of the pool, keyed by the same key `_key` builds. */
  inspect() {
    const snap = {};
    for (const [key, workers] of this.workers) {
      snap[key] = {
        maxConcurrency: this.maxConcurrency,
        spawned: workers.length,
        busy: workers.filter((w) => w.busy).length,
      };
    }
    return snap;
  }

  /** SIGKILL every worker and drop them. Call at run teardown. */
  destroy() {
    for (const workers of this.workers.values()) {
      for (const worker of workers) {
        worker.destroy();
      }
    }
    this.workers.clear();
    logger.debug('SandboxPool destroyed');
  }
}
