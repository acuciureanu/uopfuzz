import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { Orchestrator } from '../../src/orchestrator/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const FIXTURE = path.resolve(ROOT, 'tests', 'fixtures', 'decoy-merge');
const OUT = path.resolve(ROOT, 'test-results-decoy');
// The orchestrator resolves a target by package NAME (a path is treated as an
// npm spec), so stage the fixture where require() can find it. It is already
// at the right version, so the installer short-circuits and stays offline.
const STAGED = path.resolve(ROOT, 'node_modules', 'decoy-merge');

// A library whose conventional names are all SAFE, with the real gadget under
// an unremarkable name (applyPatch). This is the case that exposes heuristics
// which stand in for evidence:
//
//   - ranking entry points by a hardcoded vocabulary puts the harmless
//     merge/extend/clone/defaults first, and
//   - abandoning a descriptor after N consecutive entry points yielded no
//     finding treats "callable and clean" as "un-callable", aborting the scan
//     before applyPatch is ever reached.
//
// Both produce the worst possible output: a confident "No vulnerabilities
// reproduced" for a package that pollutes Object.prototype on the first call.
describe('decoy library — safe conventional names, real gadget under an unlisted name', () => {
  before(async () => {
    await fs.rm(STAGED, { recursive: true, force: true });
    await fs.cp(FIXTURE, STAGED, { recursive: true });
  });

  after(async () => {
    await fs.rm(OUT, { recursive: true, force: true });
    await fs.rm(STAGED, { recursive: true, force: true });
  });

  test('proves the vulnerable applyPatch despite four clean decoys ahead of it', async () => {
    const orchestrator = new Orchestrator({
      targetPackage: 'decoy-merge@1.0.0',
      outputDir: OUT,
      // Never append this fixture's finding to the repo's real discovery ledger.
      discoveryStorePath: path.join(OUT, 'discoveries.jsonl'),
      timeout: 20,
      maxIterations: 6,
      verbose: false,
      useOsv: false,
    });

    const results = await orchestrator.run();
    const confirmed = results.confirmedChains || [];
    const names = confirmed.map((c) => c.input?.entryPoint || '');

    assert.ok(
      confirmed.length > 0,
      'the vulnerable entry point must be proven, not hidden behind the clean decoys',
    );
    assert.ok(
      names.some((n) => String(n).includes('applyPatch')),
      `the finding must be applyPatch; got entry points: ${JSON.stringify(names)}`,
    );
  });
});
