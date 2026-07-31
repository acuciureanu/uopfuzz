#!/usr/bin/env node
/**
 * Ground-truth benchmark runner.
 *
 * For every corpus entry, run the REAL end-to-end pipeline against both the
 * known-vulnerable and the patched version, then score:
 *
 *   True positive  (TP): vulnerable version → a matching confirmed vulnerability.
 *   False negative (FN): vulnerable version → nothing confirmed.
 *   False positive (FP): patched version    → any confirmed vulnerability.
 *   True negative  (TN): patched version    → silence.
 *
 * "Confirmed" means the tool's own zero-false-positive gate reproduced the
 * finding twice in fresh processes — we assert on `results.confirmedChains`, the
 * exact output a real scan produces, via `runOrchestratorIsolated` (which also
 * installs the exact version and contains any crash to a child process).
 *
 * The benchmark PASSES only when TP-rate ≥ THRESHOLDS.minTruePositiveRate AND
 * FP-rate ≤ THRESHOLDS.maxFalsePositiveRate AND every row ran without error.
 * On failure it exits non-zero, so CI turns a detection regression red — the
 * safety net whose absence once let a silent core crash ship green.
 *
 * SAFETY: this installs and executes real npm packages. The corpus is a small,
 * curated, well-known set, but it is still only meant to run inside the dev
 * container or the ephemeral CI VM — never ad hoc on a host.
 *
 * Usage:
 *   node benchmark/run-benchmark.js                 # full run (needs network)
 *   node benchmark/run-benchmark.js --max-iterations 40 --concurrency 2
 *   node benchmark/run-benchmark.js --only lodash,minimist
 *   node benchmark/run-benchmark.js --self-test     # no install; exercise scoring/exit logic
 */

import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { runOrchestratorIsolated } from '../src/orchestrator/mass-runner.js';
import { BENCHMARK_CORPUS, THRESHOLDS } from './corpus.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RESULTS_MD = path.join(__dirname, 'RESULTS.md');
const RESULTS_JSON = path.join(__dirname, 'results.json');

// ─── Classification (pure) ──────────────────────────────────────────────────

/**
 * Derive a chain's proof type the same way the discovery store does
 * (`src/gadget-analysis/discovery-store.js` buildRecord): an explicit
 * `proofType`, else 'rce' for a code-execution proof, else 'pp'.
 * @param {object} chain
 * @returns {'pp'|'rce'}
 */
export function deriveProofType(chain) {
  if (chain?.proofType === 'pp' || chain?.proofType === 'rce') return chain.proofType;
  return chain?.proof?.type === 'code-execution' ? 'rce' : 'pp';
}

/**
 * Did this run confirm a vulnerability of the expected proof type?
 * Any confirmed chain of the matching proof type counts as a detection.
 * @param {object|null} results - orchestrator results (may be null on error).
 * @param {'pp'|'rce'} expectedProofType
 * @returns {{ confirmed: number, matched: number }}
 */
export function summarizeRun(results, expectedProofType) {
  const chains = Array.isArray(results?.confirmedChains) ? results.confirmedChains : [];
  const matched = chains.filter((c) => deriveProofType(c) === expectedProofType).length;
  return { confirmed: chains.length, matched };
}

/**
 * Score a set of finished rows into TP/FN/FP/TN counts, rates, and pass/fail.
 * Pure — the unit-testable heart of the benchmark.
 *
 * A row with an error on either side is `inconclusive`: it cannot count toward a
 * clean rate, and its presence fails the benchmark (green must mean complete).
 *
 * @param {Array<object>} rows
 * @param {{minTruePositiveRate:number, maxFalsePositiveRate:number}} [thresholds]
 * @returns {object}
 */
export function scoreRows(rows, thresholds = THRESHOLDS) {
  let tp = 0, fn = 0, fp = 0, tn = 0, inconclusive = 0;

  for (const row of rows) {
    if (row.vuln.error || row.patched.error) { inconclusive++; continue; }
    if (row.vuln.detected) tp++; else fn++;
    if (row.patched.flagged) fp++; else tn++;
  }

  const vulnEvaluated = tp + fn;
  const patchedEvaluated = fp + tn;
  const tpRate = vulnEvaluated ? tp / vulnEvaluated : null;
  const fpRate = patchedEvaluated ? fp / patchedEvaluated : null;

  const meetsTp = tpRate !== null && tpRate >= thresholds.minTruePositiveRate;
  const meetsFp = fpRate !== null && fpRate <= thresholds.maxFalsePositiveRate;
  const pass = meetsTp && meetsFp && inconclusive === 0;

  return { tp, fn, fp, tn, inconclusive, tpRate, fpRate, meetsTp, meetsFp, pass, thresholds };
}

// ─── Reporting (pure) ───────────────────────────────────────────────────────

function pct(rate) {
  return rate === null ? 'n/a' : `${(rate * 100).toFixed(1)}%`;
}

function rowOutcome(row) {
  if (row.vuln.error || row.patched.error) return '⚠️ INCONCLUSIVE';
  const tp = row.vuln.detected;
  const fp = row.patched.flagged;
  if (tp && !fp) return '✅ TP + TN';
  if (!tp && !fp) return '❌ FN (missed vuln)';
  if (tp && fp) return '❌ FP (flagged patched)';
  return '❌ FN + FP';
}

/**
 * Render the human-facing RESULTS.md.
 * @param {Array<object>} rows
 * @param {object} score
 * @param {object} meta - { generatedAt, maxIterations, mode }
 * @returns {string}
 */
export function renderMarkdown(rows, score, meta) {
  const lines = [];
  lines.push('# UoPFuzz — Ground-Truth Benchmark Results');
  lines.push('');
  lines.push(`> Generated: ${meta.generatedAt} · mode: ${meta.mode} · maxIterations: ${meta.maxIterations}`);
  lines.push('');
  lines.push(
    'Each real npm package is scanned by the full pipeline in two versions: a ' +
    'known-**vulnerable** one (must DETECT) and a **patched** one (must stay SILENT). ' +
    'A "detection" is a reproduction-proven `confirmedChain`, not a heuristic lead.'
  );
  lines.push('');
  lines.push('## Headline');
  lines.push('');
  lines.push(`- **Result:** ${score.pass ? '✅ PASS' : '❌ FAIL'}`);
  lines.push(`- **True-positive rate:** ${pct(score.tpRate)} (${score.tp}/${score.tp + score.fn}) — threshold ≥ ${pct(score.thresholds.minTruePositiveRate)} ${score.meetsTp ? '✅' : '❌'}`);
  lines.push(`- **False-positive rate:** ${pct(score.fpRate)} (${score.fp}/${score.fp + score.tn}) — threshold ≤ ${pct(score.thresholds.maxFalsePositiveRate)} ${score.meetsFp ? '✅' : '❌'}`);
  if (score.inconclusive) {
    lines.push(`- **Inconclusive rows:** ${score.inconclusive} (install/run error — benchmark cannot pass with inconclusive rows)`);
  }
  lines.push('');
  lines.push('## Per-package');
  lines.push('');
  lines.push('| Package | CVE | Vulnerable → detected? | Patched → silent? | Outcome |');
  lines.push('|---|---|---|---|---|');
  for (const row of rows) {
    const vulnCell = row.vuln.error
      ? `${row.vuln.version} · error: ${truncate(row.vuln.error, 40)}`
      : `${row.vuln.version} · ${row.vuln.detected ? `yes (${row.vuln.matched} chain)` : 'NO'}`;
    const patchedCell = row.patched.error
      ? `${row.patched.version} · error: ${truncate(row.patched.error, 40)}`
      : `${row.patched.version} · ${row.patched.flagged ? `NO (${row.patched.confirmed} chain)` : 'yes'}`;
    lines.push(`| ${row.package} | ${row.cve} | ${vulnCell} | ${patchedCell} | ${rowOutcome(row)} |`);
  }
  lines.push('');
  lines.push('## Legend');
  lines.push('');
  lines.push('- **TP** true positive · **FN** false negative (missed a real vuln) · **FP** false positive (flagged a patched version) · **TN** true negative.');
  lines.push('- Vulnerable versions are cross-checked against `src/gadget-analysis/known-gadgets.js` (`PP_SOURCES`); several are also reproduction-proven in `data/discovered-gadgets.jsonl`.');
  lines.push('');
  return lines.join('\n');
}

function truncate(s, n) {
  s = String(s).replace(/\s+/g, ' ');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

// ─── Execution ──────────────────────────────────────────────────────────────

/**
 * Scan one package version through the real pipeline in an isolated child.
 * @returns {Promise<{results: object|null, error: string|null}>}
 */
async function scanVersion(pkg, version, opts) {
  const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), `uopfuzz-bench-${pkg}-`));
  const orchestratorOpts = {
    targetPackage: `${pkg}@${version}`,
    outputDir,
    maxIterations: opts.maxIterations,
    timeout: opts.timeout,
    installTimeout: opts.installTimeout,
    parallelWorkers: 1,
    sandbox: true,
    blockNetwork: true,
    // Offline disclosure labels only: don't telegraph targets to OSV.dev, and
    // don't let network flakiness perturb the verdict. Detection is judged on
    // confirmedChains regardless of CVE label, so this is safe for scoring.
    noOsv: true,
    dryRun: false,
    verbose: opts.verbose,
  };
  const { results, error } = await runOrchestratorIsolated(orchestratorOpts, {
    timeoutMs: opts.perTargetTimeoutMs,
    silent: !opts.verbose,
  });
  // Best-effort cleanup of the temp results dir.
  fs.rm(outputDir, { recursive: true, force: true }).catch(() => {});
  return { results, error };
}

/**
 * Run one corpus entry (both versions) and classify into a row.
 */
async function runEntry(entry, opts) {
  process.stderr.write(`[benchmark] ${entry.package}: vulnerable ${entry.vulnerableVersion} …\n`);
  const vuln = await scanVersion(entry.package, entry.vulnerableVersion, opts);
  process.stderr.write(`[benchmark] ${entry.package}: patched ${entry.patchedVersion} …\n`);
  const patched = await scanVersion(entry.package, entry.patchedVersion, opts);

  const vulnSummary = summarizeRun(vuln.results, entry.proofType);
  const patchedSummary = summarizeRun(patched.results, entry.proofType);

  return {
    package: entry.package,
    cve: entry.cve,
    proofType: entry.proofType,
    vuln: {
      version: entry.vulnerableVersion,
      error: vuln.error,
      confirmed: vulnSummary.confirmed,
      matched: vulnSummary.matched,
      detected: !vuln.error && vulnSummary.matched > 0,
    },
    patched: {
      version: entry.patchedVersion,
      error: patched.error,
      confirmed: patchedSummary.confirmed,
      matched: patchedSummary.matched,
      // Any confirmed chain on a patched version is a false alarm.
      flagged: !patched.error && patchedSummary.confirmed > 0,
    },
  };
}

/** Run rows with bounded concurrency (each row already isolates its own children). */
async function runPool(items, concurrency, fn) {
  const out = new Array(items.length);
  let head = 0;
  async function worker() {
    while (head < items.length) {
      const idx = head++;
      out[idx] = await fn(items[idx], idx);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length || 1) }, worker));
  return out;
}

// ─── Self-test (build-only validation, no install) ──────────────────────────

/**
 * Synthetic rows that exercise every scoring branch without any npm install:
 * one clean TP+TN, one FN (missed vuln), one FP (flagged patch), one error.
 */
function selfTestRows() {
  return [
    { package: 'alpha', cve: 'CVE-A', proofType: 'pp',
      vuln: { version: '1.0.0', error: null, confirmed: 1, matched: 1, detected: true },
      patched: { version: '2.0.0', error: null, confirmed: 0, matched: 0, flagged: false } },
    { package: 'beta', cve: 'CVE-B', proofType: 'pp',
      vuln: { version: '1.0.0', error: null, confirmed: 0, matched: 0, detected: false },
      patched: { version: '2.0.0', error: null, confirmed: 0, matched: 0, flagged: false } },
    { package: 'gamma', cve: 'CVE-C', proofType: 'pp',
      vuln: { version: '1.0.0', error: null, confirmed: 1, matched: 1, detected: true },
      patched: { version: '2.0.0', error: null, confirmed: 1, matched: 1, flagged: true } },
    { package: 'delta', cve: 'CVE-D', proofType: 'pp',
      vuln: { version: '1.0.0', error: 'install failed', confirmed: 0, matched: 0, detected: false },
      patched: { version: '2.0.0', error: null, confirmed: 0, matched: 0, flagged: false } },
  ];
}

/**
 * The verdict the scorer MUST produce for `selfTestRows()`. The self-test passes
 * iff the scorer reproduces this exactly — i.e. the benchmark's PASS/FAIL logic
 * is behaving. (A synthetic benchmark FAIL is the *expected* outcome here; the
 * self-test is checking the scorer, not the fake corpus.)
 */
const SELF_TEST_EXPECTED = { tp: 2, fn: 1, fp: 1, tn: 2, inconclusive: 1, pass: false };

/**
 * Run the self-test: score the synthetic rows and assert the classification and
 * pass/fail verdict match SELF_TEST_EXPECTED. Returns { ok, mismatches, score }.
 * Pure — no I/O — so it is unit-testable and side-effect free.
 */
export function runSelfTest() {
  const score = scoreRows(selfTestRows(), THRESHOLDS);
  const mismatches = [];
  for (const [key, want] of Object.entries(SELF_TEST_EXPECTED)) {
    if (score[key] !== want) mismatches.push(`${key}: expected ${want}, got ${score[key]}`);
  }
  // The synthetic corpus is engineered to fall below thresholds; confirm that
  // the scorer actually reports the breach rather than a vacuous pass.
  if (score.tpRate !== 2 / 3) mismatches.push(`tpRate: expected ${(2 / 3).toFixed(4)}, got ${score.tpRate}`);
  if (score.fpRate !== 1 / 3) mismatches.push(`fpRate: expected ${(1 / 3).toFixed(4)}, got ${score.fpRate}`);
  return { ok: mismatches.length === 0, mismatches, score };
}

// ─── CLI ────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const opts = {
    maxIterations: 40,
    timeout: 20,
    installTimeout: 60,
    perTargetTimeoutMs: 6 * 60 * 1000,
    concurrency: 1,
    only: null,
    selfTest: false,
    verbose: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--self-test') opts.selfTest = true;
    else if (a === '--verbose' || a === '-v') opts.verbose = true;
    else if (a === '--max-iterations') opts.maxIterations = parseInt(argv[++i], 10);
    else if (a === '--timeout') opts.timeout = parseInt(argv[++i], 10);
    else if (a === '--concurrency') opts.concurrency = Math.max(1, parseInt(argv[++i], 10));
    else if (a === '--only') opts.only = String(argv[++i]).split(',').map((s) => s.trim()).filter(Boolean);
  }
  return opts;
}

/**
 * `--self-test`: an assertion on the scorer, not a benchmark run. It passes
 * (exit 0) when the scoring logic classifies the synthetic corpus exactly as
 * expected — including correctly reporting that the engineered corpus would
 * FAIL a real run. It writes nothing.
 */
function runSelfTestMain() {
  const { ok, mismatches, score } = runSelfTest();
  process.stderr.write('[benchmark] self-test — validating scoring/exit-code logic on synthetic data (no install)\n');
  process.stderr.write(
    `[benchmark]   synthetic corpus → TP ${pct(score.tpRate)}, FP ${pct(score.fpRate)}, ` +
    `inconclusive ${score.inconclusive} (this is deliberately below thresholds)\n`,
  );
  if (ok) {
    process.stderr.write('[benchmark] ✅ SELF-TEST PASSED — scorer correctly classifies TP/FN/FP/inconclusive and trips the thresholds.\n');
    process.exit(0);
  }
  process.stderr.write('[benchmark] ❌ SELF-TEST FAILED — scorer did not behave as expected:\n');
  for (const m of mismatches) process.stderr.write(`[benchmark]   - ${m}\n`);
  process.exit(1);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.selfTest) {
    runSelfTestMain();
    return;
  }

  let corpus = BENCHMARK_CORPUS;
  if (opts.only) corpus = corpus.filter((e) => opts.only.includes(e.package));
  if (corpus.length === 0) {
    process.stderr.write('[benchmark] no corpus entries selected\n');
    process.exit(2);
  }
  process.stderr.write(`[benchmark] scanning ${corpus.length} package(s), ${corpus.length * 2} installs total\n`);
  const rows = await runPool(corpus, opts.concurrency, (entry) => runEntry(entry, opts));

  const score = scoreRows(rows, THRESHOLDS);
  const meta = {
    // No Date.now()/new Date() concerns here — this is a normal CLI process.
    generatedAt: new Date().toISOString(),
    maxIterations: opts.maxIterations,
    mode: 'live',
  };

  const md = renderMarkdown(rows, score, meta);
  await fs.writeFile(RESULTS_MD, md);
  await fs.writeFile(RESULTS_JSON, JSON.stringify({ meta, score, rows }, null, 2));

  process.stdout.write('\n' + md + '\n');
  process.stderr.write(`\n[benchmark] wrote ${path.relative(process.cwd(), RESULTS_MD)} and ${path.relative(process.cwd(), RESULTS_JSON)}\n`);
  process.stderr.write(`[benchmark] ${score.pass ? 'PASS' : 'FAIL'} — TP ${pct(score.tpRate)}, FP ${pct(score.fpRate)}, inconclusive ${score.inconclusive}\n`);

  process.exit(score.pass ? 0 : 1);
}

// Only run main() when invoked directly, so the pure functions above can be
// imported by tests without triggering a benchmark run.
const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((err) => {
    process.stderr.write(`[benchmark] fatal: ${err?.stack || err}\n`);
    process.exit(2);
  });
}
