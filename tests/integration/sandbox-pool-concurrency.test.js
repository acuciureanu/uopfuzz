import { test, describe, after } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SandboxPool } from '../../src/utils/sandbox-pool.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

/**
 * The sandbox pool's `maxConcurrency` option enables N independent worker
 * processes per (package, browserEnv, blockNetwork) key. Dispatch is round-robin
 * to the least-busy, with a new worker spawned lazily up to the per-key cap when
 * all existing workers are busy.
 *
 * These tests pin the pool's STRUCTURAL invariants via `inspect()`. Timing-
 * based comparisons are flaky on tiny fixtures (a warm worker answers four
 * probes in ~3ms total), so we observe the actual mechanism: under N concurrent
 * live-blocking probes the pool spawns min(N, maxConcurrency) workers. The
 * `blockLoop` fixture holds each worker for ~3s — long enough to inspect the
 * mid-flight pool, then `destroy()` SIGKILLs every worker so the test stays
 * fast (no need to wait for the 3s block to expire).
 */
describe('sandbox pool — concurrent dispatch (maxConcurrency)', () => {
  let pools = [];
  after(() => { for (const p of pools) { try { p.destroy(); } catch { /* best effort */ } } });

  test('maxConcurrency=4 spawns up to 4 busy workers under concurrent dispatch', async () => {
    const pool = new SandboxPool({ maxConcurrency: 4 });
    pools.push(pool);
    const pkg = FIX('delay-gadget');
    // Node-only fixture (no DOM): cold-start ~50ms, so 4 concurrent forks + a
    // 500ms blockLoop finish in well under a second.
    const opts = { blockNetwork: true, browserEnv: false, mode: 'execute', timeoutMs: 4000 };

    // Pre-warm one worker so the first probe's cold-start doesn't race the
    // measured concurrent dispatch.
    await pool.run(pkg, 'blockMs', [{ ms: 1 }], opts);

    // Fan out 4 blockMs(500ms) probes concurrently. Each holds its worker for
    // ~500ms — plenty of time to inspect the mid-flight pool. The probes are
    // awaited at the end so the test framework doesn't see the destroy() reset
    // as a "worker died unexpectedly" failure for an unrelated reason.
    const probes = Array.from({ length: 4 }, () =>
      pool.run(pkg, 'blockMs', [{ ms: 500 }], { ...opts, timeoutMs: 4000 })
    );

    // Give the pool a moment to spawn/assign workers. ~50ms covers one cold
    // fork; 100ms gives the parent loop time to dequeue and fork the extras.
    await new Promise(r => setTimeout(r, 100));

    const snap = pool.inspect();
    const keys = Object.keys(snap);
    assert.equal(keys.length, 1, 'all probes target one package → one key');
    const info = snap[keys[0]];
    assert.equal(info.maxConcurrency, 4);
    assert.ok(info.spawned >= 4,
      `concurrent dispatch must spawn up to maxConcurrency workers (got ${info.spawned}, expected >= 4)`);
    // All spawned workers should be busy now (each is mid-blockMs).
    assert.equal(info.busy, info.spawned,
      `all spawned workers must be busy (got busy=${info.busy}, spawned=${info.spawned})`);

    // Wait for the probes to drain naturally (500ms each, concurrent).
    await Promise.all(probes);
  });

  test('maxConcurrency=1 keeps exactly one worker per key under concurrent load', async () => {
    const pool = new SandboxPool({ maxConcurrency: 1 });
    pools.push(pool);
    const pkg = FIX('delay-gadget');
    const opts = { blockNetwork: true, browserEnv: false, mode: 'execute', timeoutMs: 4000 };

    await pool.run(pkg, 'blockMs', [{ ms: 1 }], opts);

    // Fan out 4 concurrent blockMs(200ms) probes — they must QUEUE on the single
    // worker, not spawn extras. 4 × 200ms = 800ms sequential wall-clock.
    const probes = Array.from({ length: 4 }, () =>
      pool.run(pkg, 'blockMs', [{ ms: 200 }], { ...opts, timeoutMs: 4000 })
    );

    await new Promise(r => setTimeout(r, 50));
    const snap = pool.inspect();
    const keys = Object.keys(snap);
    const info = snap[keys[0]];
    assert.equal(info.maxConcurrency, 1);
    assert.equal(info.spawned, 1,
      `maxConcurrency=1 must spawn EXACTLY ONE worker per key under concurrent load (got ${info.spawned})`);
    assert.equal(info.busy, 1,
      'only the single worker is in-flight; the rest queue');

    await Promise.all(probes);
  });

  test('concurrent dispatch returns identical results to sequential dispatch (correctness)', async () => {
    // The orchestrator discarded the dead worker-thread executeParallelFuzzing
    // path on the strength of this invariant: dispatching the same probes via a
    // parallel pool yields the same verdicts (diff facts) as dispatching them
    // one at a time. Below the orchestrator's threshold the observable fields
    // (outputChanged, prototypePolluted, pollutionWasRead) must match exactly.
    const pkg = FIX('rce-gadget');
    const opts = { blockNetwork: true, browserEnv: false, mode: 'differential' };
    const descriptors = ['command', 'debug', 'template', 'isAdmin'];

    const parallelPool = new SandboxPool({ maxConcurrency: 4 });
    const sequentialPool = new SandboxPool({ maxConcurrency: 1 });
    pools.push(parallelPool, sequentialPool);

    // Warm both pools first so cold-start doesn't bias correctness.
    await Promise.all([
      parallelPool.run(pkg, 'render', [{}], { ...opts, timeoutMs: 1500, pollution: { property: 'warmup', value: true } }),
      sequentialPool.run(pkg, 'render', [{}], { ...opts, timeoutMs: 1500, pollution: { property: 'warmup', value: true } }),
    ]);

    const parResults = await Promise.all(descriptors.map(d =>
      parallelPool.run(pkg, 'render', [{}], { ...opts, timeoutMs: 1500, pollution: { property: d, value: true } })
    ));
    const seqResults = [];
    for (const d of descriptors) {
      seqResults.push(await sequentialPool.run(pkg, 'render', [{}],
        { ...opts, timeoutMs: 1500, pollution: { property: d, value: true } }));
    }

    assert.equal(parResults.length, seqResults.length);
    for (let i = 0; i < parResults.length; i++) {
      assert.equal(parResults[i]?.outputChanged, seqResults[i]?.outputChanged,
        `outputChanged must match for descriptor ${descriptors[i]} regardless of concurrency`);
      assert.equal(parResults[i]?.prototypePolluted, seqResults[i]?.prototypePolluted);
      assert.equal(parResults[i]?.pollutionWasRead, seqResults[i]?.pollutionWasRead);
    }
  });
});