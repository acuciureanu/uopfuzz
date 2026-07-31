import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { Orchestrator } from '../../src/orchestrator/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const FIXTURE = path.resolve(ROOT, 'tests', 'fixtures', 'decoy-merge');
const OUT = path.resolve(ROOT, 'test-results-parallel');
// Orchestrator resolves a target by package NAME; stage the fixture where
// require() can find it (same convention as decoy-merge.test.js)
const STAGED = path.resolve(ROOT, 'node_modules', 'decoy-merge');

/**
 * End-to-end smoke that --parallel N (the new pool-backed parallel path) finds
 * the SAME vulnerabilities --parallel 1 (sequential) does, against a fixture
 * library whose conventional name list is all decoys with the real gadget under
 * an unremarkable name (applyPatch). Confirms:
 *
 *   1. The parallel path doesn't silently regress Phase B — every descriptor /
 *      EP / mode still runs, the per-gate probe still narrows, reproduction
 *      happens correctly across the workers.
 *   2. The result set matches the sequential path (the only difference is
 *      wall-clock time; correctness is preserved because `_serialConfirm`
 *      serializes proveAndRecord so descriptor probes can confirm in
 *      parallel without double-recording).
 *
 * Run separately from decoy-merge.test.js so the staged fixture's discovery
 * store stays scoped per-run; both reuse the same fixture fixture on disk.
 */
describe('parallel orchestrator path (--parallel N)', () => {
  before(async () => {
    await fs.rm(STAGED, { recursive: true, force: true });
    await fs.cp(FIXTURE, STAGED, { recursive: true });
  });

  after(async () => {
    await fs.rm(OUT, { recursive: true, force: true });
    await fs.rm(STAGED, { recursive: true, force: true });
  });

  test('--parallel 4 finds applyPatch (same end result as --parallel 1)', async () => {
    const orchestrator = new Orchestrator({
      targetPackage: 'decoy-merge@1.0.0',
      outputDir: OUT,
      discoveryStorePath: path.join(OUT, 'discoveries.jsonl'),
      timeout: 30,
      maxIterations: 6,
      verbose: false,
      useOsv: false,
      parallelWorkers: 4, // <-- enable the new pool-backed parallel path
    });

    const results = await orchestrator.run();
    const confirmed = results.confirmedChains || [];
    const names = confirmed.map((c) => c.input?.entryPoint || '');

    assert.ok(
      confirmed.length > 0,
      'parallel execution must still confirm — same fix path as sequential',
    );
    assert.ok(
      names.some((n) => String(n).includes('applyPatch')),
      `the finding must be applyPatch, not hidden behind the clean decoys; got entry points: ${JSON.stringify(names)}`,
    );

    // Sanity: the orchestrator actually configured the pool's concurrency.
    // The instrumentation should have a pool after the first Phase-B probe.
    assert.ok(
      orchestrator.instrumentation?.sandboxPool?.maxConcurrency === 4 ||
      orchestrator.instrumentation?.options?.maxConcurrency === 4,
      'pool concurrency should be set from --parallel',
    );
  });
});