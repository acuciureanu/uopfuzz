import { test, describe, after } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SandboxPool } from '../../src/utils/sandbox-pool.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.resolve(__dirname, '..', 'fixtures', name);

// The jsdom startup allowance (20s) exists so a browser-only target's COLD
// start — forking a child and booting jsdom — isn't mistaken for a hang. But it
// was added to every request's watchdog, including requests served by an
// already-warm worker whose jsdom is long since loaded. That made recovery from
// a wedged child (e.g. a synchronous jsdom XHR) take ~22.5s instead of ~2.5s.
//
// The allowance must apply to a worker's first (cold) request only.
describe('sandbox pool — jsdom startup allowance applies to cold starts only', () => {
  let pool;
  after(() => { try { pool?.destroy(); } catch { /* best effort */ } });

  test('a warm worker enforces the operation timeout without the cold-start allowance', async () => {
    pool = new SandboxPool();
    const pkg = FIX('fake-browser-lib');
    const opts = { blockNetwork: true, browserEnv: true, mode: 'execute' };

    // Cold request: forks the child and boots jsdom. The allowance covers this,
    // so a quick call must succeed despite the tight per-op timeout.
    const cold = await pool.run(pkg, 'extend', [{ a: 1 }], { ...opts, timeoutMs: 1000 });
    assert.ok(!cold?.timedOut, `cold start must not be killed by the operation timeout (got ${JSON.stringify(cold)})`);
    assert.ok(!cold?.error, `cold start should succeed (got ${cold?.error})`);

    // Warm request: jsdom is already loaded in this worker. blockLoop() freezes
    // the child's event loop for ~3s — the child's own self-timer cannot fire, so
    // only the parent watchdog can rescue it. With the allowance correctly scoped
    // to cold starts that watchdog is ~2s, so this MUST be killed. If the
    // allowance still applied, the watchdog would be ~22s and the call would
    // simply return 'unblocked' after 3s.
    const started = Date.now();
    const warm = await pool.run(pkg, 'blockLoop', [{}], { ...opts, timeoutMs: 1000 });
    const elapsed = Date.now() - started;

    assert.ok(
      warm?.timedOut,
      `a wedged warm worker must hit the parent watchdog, not the cold-start allowance (got ${JSON.stringify(warm)} after ${elapsed}ms)`,
    );
    assert.ok(
      elapsed < 10000,
      `recovery from a wedged warm worker should be seconds, not the ~22s allowance window (took ${elapsed}ms)`,
    );
  });
});
