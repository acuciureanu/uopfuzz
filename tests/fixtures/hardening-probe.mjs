/**
 * Probe used by tests/unit/worker-hardening.test.js. Run in a FORKED process
 * (never the test runner) because hardenWorkerProcess mutates global builtins.
 *
 * Usage: node hardening-probe.mjs [nonet]
 *   default → blockNetwork: true   |   "nonet" → blockNetwork: false
 * Emits a single JSON line on stdout: { childProcess, workerThreads, net, http2 }
 * where each value is "blocked" or "NOT_BLOCKED".
 */
import { createRequire } from 'module';
import { hardenWorkerProcess } from '../../src/utils/worker-hardening.js';

const require = createRequire(import.meta.url);
const blockNetwork = process.argv[2] !== 'nonet';

hardenWorkerProcess(require, { blockNetwork });

const result = {};

// child_process — always expected blocked
try {
  require('child_process').execSync('echo uopfuzz');
  result.childProcess = 'NOT_BLOCKED';
} catch { result.childProcess = 'blocked'; }

// worker_threads — always expected blocked (constructor throws synchronously)
try {
  const wt = require('worker_threads');
  // eslint-disable-next-line no-new
  new wt.Worker('/nonexistent-uopfuzz-worker.js');
  result.workerThreads = 'NOT_BLOCKED';
} catch { result.workerThreads = 'blocked'; }

// http2 — blocked only when blockNetwork. When allowed, connect() returns a live
// session that will emit an async 'error' (nothing is listening); attach a
// handler so that expected failure doesn't crash the probe.
try {
  const session = require('http2').connect('http://127.0.0.1:0');
  session.on('error', () => {});
  try { session.destroy(); } catch { /* noop */ }
  result.http2 = 'NOT_BLOCKED';
} catch { result.http2 = 'blocked'; }

// net (TCP) — blocked only when blockNetwork. connect() destroys with an error
// rather than throwing, so listen for the ENETBLOCKED error event.
const net = require('net');
const sock = new net.Socket();
let netBlocked = false;
sock.on('error', (e) => { netBlocked = e && e.code === 'ENETBLOCKED'; });
try {
  sock.connect(9, '192.0.2.1'); // TEST-NET-1, guaranteed non-routable
} catch (e) {
  netBlocked = e && e.code === 'ENETBLOCKED';
}

setTimeout(() => {
  try { sock.destroy(); } catch { /* already destroyed */ }
  result.net = netBlocked ? 'blocked' : 'NOT_BLOCKED';
  process.stdout.write(JSON.stringify(result) + '\n');
  process.exit(0);
}, 100);
