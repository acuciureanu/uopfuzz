/**
 * MassRunner  — fuzz many cdnjs libraries in sequence
 * VersionRunner — fuzz a single library across multiple versions
 */

import fs from 'fs/promises';
import path from 'path';
import { fork } from 'child_process';
import { fileURLToPath } from 'url';
import { fetchLibraries, fetchLibrary, resolveNpmPackage, filterJSLibraries, rankByStars } from '../sources/cdnjs.js';
import { getVersions, selectVersions, resolveInstallable } from '../sources/version-scanner.js';
import { generateMassReport, generateVersionReport } from '../reporting/markdown-report.js';
import { logger } from '../utils/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SUBPROCESS_PATH = path.join(__dirname, 'orchestrator-subprocess.js');

// Wall-clock backstop for a single target. The Orchestrator bounds each
// iteration itself; this only catches a target that hangs the whole run (a
// stuck child never returns and would otherwise stall the entire sweep). 15 min
// is generous for a converging run; a truly hung child is SIGKILLed after it.
const DEFAULT_PER_TARGET_TIMEOUT_MS = 15 * 60 * 1000;

/**
 * Run one target's full Orchestrator in a forked child process and return its
 * results, containing any crash or hang to that child. This is the crash
 * boundary that lets mass/version sweeps survive a target that kills its process
 * (e.g. a browser-only package whose in-process pollution corrupts Node's HTTP
 * internals) — the sweep records a failure for that target and continues.
 *
 * Never rejects: a crash, a spawn error, or a timeout all resolve to
 * `{ results: null, error }`.
 *
 * @param {object} options - Orchestrator options (must be JSON-serializable).
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs] - Per-target wall-clock cap.
 * @param {string} [opts.workerPath] - Override the child script (for tests).
 * @param {boolean} [opts.silent] - Suppress the child's stderr (for tests).
 * @returns {Promise<{results: object|null, error: string|null}>}
 */
export function runOrchestratorIsolated(options, { timeoutMs = DEFAULT_PER_TARGET_TIMEOUT_MS, workerPath = SUBPROCESS_PATH, silent = false } = {}) {
  return new Promise((resolve) => {
    const child = fork(workerPath, [], {
      stdio: ['inherit', 'inherit', silent ? 'ignore' : 'inherit', 'ipc'],
    });

    let settled = false;
    const finish = (r) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      resolve(r);
    };

    const timer = setTimeout(
      () => finish({ results: null, error: `target exceeded ${Math.round(timeoutMs / 1000)}s wall-clock budget (killed)` }),
      timeoutMs,
    );

    child.on('message', (msg) => {
      if (msg?.type === 'success') finish({ results: msg.results, error: null });
      else if (msg?.type === 'error') finish({ results: null, error: msg.error });
    });
    child.on('error', (err) => finish({ results: null, error: `subprocess spawn error: ${err.message}` }));
    child.on('exit', (code, signal) => {
      // A clean success/error arrives via 'message' first and settles us; reaching
      // here unsettled means the child died without reporting — a contained crash.
      finish({ results: null, error: `target process crashed (exit ${code}${signal ? `, ${signal}` : ''})` });
    });

    child.send({ type: 'run', options });
  });
}

// ─── MassRunner ───────────────────────────────────────────────────────────────

/**
 * Run the prototype-pollution fuzzer against the top-N cdnjs JavaScript
 * libraries (ranked by GitHub stars).
 *
 * Supports resumable scans: libraries whose output JSON already exists in
 * `options.outputDir` are skipped automatically.
 *
 * @example
 * const runner = new MassRunner({ search: '', topN: 50, options: { dryRun: true } });
 * const summary = await runner.run();
 */
export class MassRunner {
  /**
   * @param {object} config
   * @param {string}  [config.search='']       - Free-text cdnjs search filter
   * @param {number}  [config.topN=50]         - Number of libraries to test (after star ranking)
   * @param {number}  [config.limit=200]       - How many libraries to fetch from cdnjs before ranking
   * @param {boolean} [config.resume=false]    - Skip libraries that already have results
   * @param {number}  [config.concurrency=1]   - Number of libraries to scan in parallel
   * @param {object}  [config.options={}]      - Options forwarded to each Orchestrator instance
   */
  constructor({ search = '', topN = 50, limit = 200, resume = false, concurrency = 1, options = {} } = {}) {
    this.search = search;
    this.topN = topN;
    this.limit = limit;
    this.resume = resume;
    this.concurrency = Math.max(1, concurrency);
    this.orchestratorOptions = options;
  }

  async run() {
    logger.info(`MassRunner: fetching top ${this.topN} cdnjs libraries (search: "${this.search}")`);

    // 1. Discover libraries
    const rawLibs = await fetchLibraries({
      search: this.search,
      limit: this.limit,
      fields: 'fileType,latest'
    });
    const jsLibs = filterJSLibraries(rawLibs);
    const targets = rankByStars(jsLibs, this.topN);

    logger.info(`MassRunner: ${targets.length} JavaScript libraries selected`);

    const outputDir = path.resolve(this.orchestratorOptions.outputDir || './results');
    await fs.mkdir(outputDir, { recursive: true });

    // allResults is pre-sized so concurrent writes to specific indices are safe
    const allResults = new Array(targets.length).fill(null);

    const scanOne = async (lib, idx) => {
      const npmPackage = resolveNpmPackage(lib);
      const version = lib.version || 'latest';
      const stars = lib.github?.stargazers_count || 0;
      const label = `${lib.name}@${version}`;

      // Resume: skip if a results file already exists for this library
      if (this.resume) {
        const existing = await _findExistingResult(outputDir, lib.name);
        if (existing) {
          logger.info(`[${idx + 1}/${targets.length}] SKIP (resume) ${label}`);
          try {
            const data = JSON.parse(await fs.readFile(existing, 'utf8'));
            allResults[idx] = { library: lib.name, version, stars, results: data, config: null };
          } catch {
            allResults[idx] = { library: lib.name, version, stars, results: null, config: null, error: 'parse error' };
          }
          return;
        }
      }

      logger.info(`[${idx + 1}/${targets.length}] Scanning ${label} (${stars} stars)`);

      const orchestratorOpts = {
        ...this.orchestratorOptions,
        targetPackage: `${npmPackage}@${version}`,
        outputDir: path.join(outputDir, `mass-${_safeName(lib.name)}`),
      };

      // Isolate each library in a child process: a crash/hang on one library
      // (common among the browser-only libs that dominate cdnjs's top ranks) is
      // contained and recorded as a failure instead of killing the whole scan.
      const { results, error } = await runOrchestratorIsolated(orchestratorOpts, {
        timeoutMs: this.orchestratorOptions.perTargetTimeoutMs,
      });

      if (error) {
        logger.warn(`MassRunner: ${label} failed \u2014 ${error}`);
        allResults[idx] = { library: lib.name, version, stars, results: null, config: null, error };
        return;
      }

      allResults[idx] = { library: lib.name, version, stars, results, config: null, error: null };
      const libResultFile = path.join(outputDir, `mass-${_safeName(lib.name)}-${version}.json`);
      await fs.writeFile(libResultFile, JSON.stringify(results, null, 2));
      logger.info(`Saved ${label} results -> ${libResultFile}`);
    };

    await _runPool(targets, this.concurrency, scanOne);
    // Remove any null slots (shouldn't happen, but guard against it)
    const filledResults = allResults.filter(Boolean);

    // 2. Generate mass report
    const report = generateMassReport(filledResults);
    const reportFile = path.join(outputDir, `mass-report-${Date.now()}.md`);
    await fs.writeFile(reportFile, report);
    logger.info(`Mass scan report saved -> ${reportFile}`);

    const summary = {
      total: filledResults.length,
      vulnerable: filledResults.filter(r => (r.results?.confirmedChains?.length || 0) > 0).length,
      failed: filledResults.filter(r => !!r.error).length,
      reportFile,
      results: filledResults
    };

    return summary;
  }
}

// ─── VersionRunner ────────────────────────────────────────────────────────────

/**
 * Run the fuzzer against a single library across multiple versions to find
 * when a vulnerability was introduced or fixed.
 *
 * @example
 * const runner = new VersionRunner({
 *   cdnjsName: 'lodash.js',
 *   strategy: { mode: 'last', count: 5 },
 *   options: { dryRun: true }
 * });
 * const summary = await runner.run();
 */
export class VersionRunner {
  /**
   * @param {object} config
   * @param {string} config.cdnjsName          - cdnjs library name (e.g. 'lodash.js')
   * @param {string} [config.npmPackage]        - npm package name override (auto-resolved if omitted)
   * @param {object} [config.strategy]          - Version selection strategy (default: all)
   * @param {object} [config.options={}]        - Options forwarded to each Orchestrator
   */
  constructor({ cdnjsName, npmPackage = null, strategy = { mode: 'all' }, options = {} } = {}) {
    this.cdnjsName = cdnjsName;
    this.npmPackage = npmPackage;
    this.strategy = strategy;
    this.orchestratorOptions = options;
  }

  async run() {
    logger.info(`VersionRunner: fetching versions for ${this.cdnjsName}`);

    // 1. Resolve npm package if not provided
    if (!this.npmPackage) {
      const lib = await fetchLibrary(this.cdnjsName);
      this.npmPackage = resolveNpmPackage(lib);
    }

    // 2. Enumerate versions
    const allVersions = await getVersions(this.cdnjsName);
    const selectedVersions = selectVersions(allVersions, this.strategy);

    if (selectedVersions.length === 0) {
      throw new Error(`No versions found for ${this.cdnjsName} with strategy ${JSON.stringify(this.strategy)}`);
    }

    logger.info(`VersionRunner: testing ${selectedVersions.length} versions of ${this.cdnjsName}`);

    const outputDir = path.resolve(this.orchestratorOptions.outputDir || './results');
    await fs.mkdir(outputDir, { recursive: true });

    const versionResults = [];

    for (const [idx, version] of selectedVersions.entries()) {
      const installable = resolveInstallable(this.cdnjsName, this.npmPackage, version);
      logger.info(`[${idx + 1}/${selectedVersions.length}] Testing ${installable.installSpec}`);

      const orchestratorOpts = {
        ...this.orchestratorOptions,
        targetPackage: installable.installSpec,
        outputDir: path.join(outputDir, `versions-${_safeName(this.cdnjsName)}`),
      };

      // Run each version in an isolated child process so a crash/hang on one
      // version (e.g. a browser-only lib corrupting Node internals) does not kill
      // the whole sweep — it is recorded as a failure and the sweep continues.
      const { results, error } = await runOrchestratorIsolated(orchestratorOpts, {
        timeoutMs: this.orchestratorOptions.perTargetTimeoutMs,
      });

      let scanResult;
      if (error) {
        logger.warn(`VersionRunner: ${installable.installSpec} failed — ${error}`);
        scanResult = { version, results: null, config: null, error };
      } else {
        scanResult = { version, results, config: null, error: null };
        const versionResultFile = path.join(
          outputDir,
          `version-${_safeName(this.cdnjsName)}-${_safeName(version)}.json`
        );
        await fs.writeFile(versionResultFile, JSON.stringify(results, null, 2));
      }

      versionResults.push(scanResult);
    }

    // 3. Generate version sweep report
    const report = generateVersionReport(versionResults, this.cdnjsName);
    const reportFile = path.join(outputDir, `versions-${_safeName(this.cdnjsName)}-${Date.now()}.md`);
    await fs.writeFile(reportFile, report);
    logger.info(`Version sweep report saved -> ${reportFile}`);

    const summary = {
      library: this.cdnjsName,
      versionsTotal: versionResults.length,
      vulnerable: versionResults.filter(r => (r.results?.confirmedChains?.length || 0) > 0).length,
      failed: versionResults.filter(r => !!r.error).length,
      reportFile,
      results: versionResults
    };

    return summary;
  }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Run `fn(item, index)` for every item in `items`, with at most `concurrency`
 * in-flight at a time. Order of completion is not guaranteed, but results are
 * written back to the pre-allocated array inside `fn` so the caller preserves
 * original ordering.
 *
 * @template T
 * @param {T[]} items
 * @param {number} concurrency
 * @param {(item: T, index: number) => Promise<void>} fn
 * @returns {Promise<void>}
 */
async function _runPool(items, concurrency, fn) {
  const queue = items.map((item, idx) => ({ item, idx }));
  let head = 0;

  async function worker() {
    while (head < queue.length) {
      const { item, idx } = queue[head++];
      await fn(item, idx);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length || 1) }, worker);
  await Promise.allSettled(workers);
}

/**
 * Sanitise a library name for use in file paths.
 * @param {string} name
 * @returns {string}
 */
function _safeName(name) {
  return String(name).replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 80);
}

/**
 * Look for an existing per-library result file produced by a previous mass scan.
 * Returns the file path if found, or null.
 *
 * @param {string} outputDir
 * @param {string} libraryName
 * @returns {Promise<string|null>}
 */
async function _findExistingResult(outputDir, libraryName) {
  try {
    const files = await fs.readdir(outputDir);
    const prefix = `mass-${_safeName(libraryName)}-`;
    const match = files.find(f => f.startsWith(prefix) && f.endsWith('.json'));
    return match ? path.join(outputDir, match) : null;
  } catch {
    return null;
  }
}
