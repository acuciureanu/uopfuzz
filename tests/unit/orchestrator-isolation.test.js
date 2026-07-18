import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runOrchestratorIsolated } from '../../src/orchestrator/mass-runner.js';

/**
 * Mass and version sweeps run each target's Orchestrator in a forked child so a
 * crash or hang on one target cannot kill the whole sweep. These tests exercise
 * that isolation boundary directly against a fixture worker (no npm installs),
 * covering every way a per-target run can end.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WORKER = path.resolve(__dirname, '..', 'fixtures', 'isolation-worker.mjs');

function run(behavior, opts = {}) {
  return runOrchestratorIsolated(
    { __behavior: behavior, ...opts },
    { workerPath: WORKER, silent: true, timeoutMs: opts.__timeoutMs ?? 15000 },
  );
}

describe('runOrchestratorIsolated', () => {
  test('returns the child results on success', async () => {
    const { results, error } = await run('ok', { __marker: 42 });
    assert.equal(error, null);
    assert.ok(results);
    assert.equal(results.marker, 42);
    assert.deepEqual(results.confirmedChains, []);
  });

  test('surfaces a reported failure as an error, not a throw', async () => {
    const { results, error } = await run('reported-error');
    assert.equal(results, null);
    assert.match(error, /orchestrator reported failure/);
  });

  test('CONTAINS an uncaught crash — the parent survives and records a failure', async () => {
    const { results, error } = await run('throw');
    assert.equal(results, null);
    assert.match(error, /crashed/);
    // The real proof is implicit: this test process is still running to make
    // the next assertions, i.e. the child's uncaught throw did not kill us.
  });

  test('records a non-zero exit as a contained failure', async () => {
    const { results, error } = await run('exit');
    assert.equal(results, null);
    assert.match(error, /exit 3/);
  });

  test('kills and reports a hung target after the wall-clock budget', async () => {
    const { results, error } = await run('hang', { __timeoutMs: 800 });
    assert.equal(results, null);
    assert.match(error, /wall-clock budget/);
  });

  test('a crash on one target does not stop the next target from succeeding', async () => {
    // Sequential mix — the sweep pattern. The crash in the middle must not
    // prevent the subsequent run from completing normally.
    const a = await run('ok', { __marker: 'a' });
    const b = await run('throw');
    const c = await run('ok', { __marker: 'c' });
    assert.equal(a.results?.marker, 'a');
    assert.equal(b.error && b.results, null);
    assert.equal(c.results?.marker, 'c', 'sweep continued after the crash');
  });
});
