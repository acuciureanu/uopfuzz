import { test, describe } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROBE = path.resolve(__dirname, '..', 'fixtures', 'hardening-probe.mjs');

/**
 * The probe hardens its own process, then attempts each capability and reports
 * whether it was blocked. It runs in a forked process — never here — because
 * hardenWorkerProcess mutates global builtins that other tests rely on.
 */
function runProbe(arg) {
  return new Promise((resolve, reject) => {
    execFile('node', [PROBE, ...(arg ? [arg] : [])], { timeout: 10000 }, (err, stdout) => {
      if (err) return reject(err);
      try {
        resolve(JSON.parse(stdout.trim().split('\n').pop()));
      } catch (e) {
        reject(new Error(`bad probe output: ${stdout}`));
      }
    });
  });
}

describe('worker-hardening capability blocks', () => {
  test('with blockNetwork: everything is blocked', async () => {
    const r = await runProbe();
    assert.equal(r.childProcess, 'blocked', 'child_process must be blocked');
    assert.equal(r.workerThreads, 'blocked', 'worker_threads (escape hatch) must be blocked');
    assert.equal(r.http2, 'blocked', 'http2 client must be blocked when network is denied');
    assert.equal(r.net, 'blocked', 'TCP connect must be blocked when network is denied');
  });

  test('without blockNetwork: process/thread escapes stay blocked, network is allowed', async () => {
    const r = await runProbe('nonet');
    // These have no opt-out — they are escape hatches out of every other block.
    assert.equal(r.childProcess, 'blocked', 'child_process must be blocked even with --allow-network');
    assert.equal(r.workerThreads, 'blocked', 'worker_threads must be blocked even with --allow-network');
    // Network is deliberately permitted so --allow-network targets can run.
    assert.equal(r.http2, 'NOT_BLOCKED', 'http2 should be permitted when network is allowed');
    assert.equal(r.net, 'NOT_BLOCKED', 'TCP should be permitted when network is allowed');
  });

  test('rejects a call without the caller require', async () => {
    const { hardenWorkerProcess } = await import('../../src/utils/worker-hardening.js');
    assert.throws(() => hardenWorkerProcess(undefined), /require/);
  });
});
