import { logger } from '../utils/logger.js';
import { CoverageTracker } from '../utils/coverage.js';
import { V8CoverageCollector } from '../utils/v8-coverage.js';
import { createTaintProxy, analyzeTaintLog } from '../utils/taint-proxy.js';
import { executeDifferential, executeMultiPropertyDifferential, executeForcedBranchDifferential, discoverUOPProperties, executeMergePPTest, executeURLGadgetTest } from './differential.js';
import { classifyDiff } from './classify-diff.js';
import { SandboxPool } from '../utils/sandbox-pool.js';
import { packageBaseName } from '../utils/package-name.js';
import { isBrowserOnly } from '../utils/browser-env.js';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
let childProcessModule;
try { childProcessModule = require('child_process'); } catch { childProcessModule = null; }

// Browser-only packages (jQuery, Backbone, …) need a jsdom DOM at load time.
// The sandbox worker now stands one up on demand (browserEnv flag), so these run
// in the isolated child like everything else — see ../utils/browser-env.js.

// Per-call timeout for differential tests. Must be short: in-process library
// calls complete in <10ms; anything longer is an infinite loop or hung I/O.
// 1500ms is generous. The CLI --timeout flag controls the *iteration* timeout.
const DIFF_CALL_TIMEOUT_MS = 1500;
const DIFF_URL_SINK_TIMEOUT_MS = 500;

// Cached console references — avoid saving/restoring per call (hot path)
const _origConsoleError = console.error;
const _origConsoleWarn = console.warn;
const _noopFn = () => {};

/**
 * Instrumentation Engine - Real V8 Coverage + Proxy Taint Tracking
 *
 * Three layers of instrumentation, each grounded in research:
 *
 * Layer 1 - V8 Precise Coverage (real):
 *   Uses the V8 Inspector Profiler.takePreciseCoverage API to collect
 *   actual basic-block and branch coverage from the JS engine.
 *   This is the same mechanism used by c8/istanbul/nyc.
 *   Reference: V8 Inspector Protocol, Profiler domain
 *
 * Layer 2 - Proxy-Based Taint Tracking (real):
 *   ES6 Proxy intercepts EVERY property access (.get, .set, .has)
 *   on input objects, creating a complete data-flow trace from
 *   pollution source to sink. Catches the fundamental operation
 *   that prototype pollution exploits.
 *   Reference: Schwartz et al., IEEE S&P 2010
 *
 * Layer 3 - Global Sink Interception:
 *   Replaces dangerous global functions (eval, Function, exec) with
 *   logging wrappers that record sink access without executing.
 *
 * Layer 1 answers: "what code paths did this input exercise?"
 * Layer 2 answers: "how did data flow through the target?"
 * Layer 3 answers: "did the data reach a dangerous function?"
 *
 * Together they close the loop: coverage novelty feeds back to the
 * input generator's power schedule, taint flow feeds into gadget
 * chain analysis, and sink hits confirm exploitability.
 */
export class Instrumentation {
  constructor(options) {
    this.options = options;
    this.traces = [];
    this.propertyAccesses = new Map();
    this.originalConsole = {};
    this.instrumentedFunctions = new Set();

    // The loaded target module (set by orchestrator after setupTarget)
    this.targetModule = null;
    // Track entry points that consistently fail to avoid retrying
    this._entryPointFailures = new Map();

    // Persistent sandbox worker pool for the differential DISCOVERY phase.
    // Lazily created on first sandboxed probe (see _getPool); reproduction stays
    // one-shot in fresh processes and never touches this pool.
    this.sandboxPool = null;

    // Layer 1: AFL-style edge coverage (computed from trace events)
    this.coverageTracker = new CoverageTracker();

    // Layer 1b: Real V8 coverage (from inspector protocol)
    this.v8Collector = new V8CoverageCollector();
    this.v8CoverageEnabled = false;

    // Accumulated V8 metrics across all executions
    this.v8Metrics = {
      totalBlocks: 0,
      coveredBlocks: 0,
      totalBranches: 0,
      coveredBranches: 0,
      totalFunctions: 0,
      coveredFunctions: 0
    };
  }

  /**
   * Set the loaded target module for real execution.
   * Called by the orchestrator after setupTarget() completes.
   */
  setTargetModule(targetModule) {
    this.targetModule = targetModule;
  }

  /**
   * The persistent sandbox worker pool for discovery probes, created on first
   * use. Reproduction never uses it (it stays one-shot in fresh processes).
   */
  _getPool() {
    if (!this.sandboxPool) this.sandboxPool = new SandboxPool();
    return this.sandboxPool;
  }

  /**
   * Tear down the sandbox pool (SIGKILL its workers). Called at run teardown so
   * no worker outlives the session.
   */
  destroy() {
    if (this.sandboxPool) {
      this.sandboxPool.destroy();
      this.sandboxPool = null;
    }
  }

  /**
   * Lazily build and cache O(1) lookups for a config's entry points and
   * sequences, keyed by entry-point name. The differential phase calls
   * `config.entryPoints.find(...)` / `config.sequences.find(...)` hundreds of
   * times per iteration; each was an O(entryPoints) linear scan. Cached on the
   * config object itself (via a WeakMap), so it survives across calls and is
   * garbage-collected with the config.
   */
  _epIndex(config) {
    if (!config) return { epByName: new Map(), seqByEntry: new Map() };
    if (!this._epIndexCache) this._epIndexCache = new WeakMap();
    let idx = this._epIndexCache.get(config);
    if (!idx) {
      const epByName = new Map();
      for (const ep of (config.entryPoints || [])) {
        if (!epByName.has(ep.name)) epByName.set(ep.name, ep);
      }
      const seqByEntry = new Map();
      for (const s of (config.sequences || [])) {
        if (!seqByEntry.has(s.entryPoint)) seqByEntry.set(s.entryPoint, s);
      }
      idx = { epByName, seqByEntry };
      this._epIndexCache.set(config, idx);
    }
    return idx;
  }

  /**
   * Initialize V8 coverage collection.
   * Called once before the fuzzing loop starts.
   */
  async enableV8Coverage() {
    try {
      await this.v8Collector.start();
      this.v8CoverageEnabled = true;
      logger.debug('V8 precise coverage collection enabled');
    } catch (error) {
      logger.warn(`V8 coverage unavailable: ${error.message}. Falling back to trace-based coverage.`);
      this.v8CoverageEnabled = false;
    }
  }

  /**
   * Stop V8 coverage collection.
   */
  async disableV8Coverage() {
    if (this.v8CoverageEnabled) {
      await this.v8Collector.stop();
      this.v8CoverageEnabled = false;
    }
  }

  async executeWithTracing(inputs, config) {
    try {
      logger.debug(`Executing ${inputs.length} inputs with tracing enabled`);

      const traces = [];

      for (const input of inputs) {
        if (this.options.dryRun) {
          const mockTrace = this.createMockTrace(input, config);
          // Compute coverage even for mock traces
          mockTrace.coverage = this.coverageTracker.computeCoverageFromTrace(mockTrace);
          mockTrace.coverageResult = this.coverageTracker.mergeAndCheckNovelty(mockTrace.coverage);
          traces.push(mockTrace);
          continue;
        }

        try {
          const trace = await this.executeInputWithTracing(input, config);
          traces.push(trace);
        } catch (error) {
          logger.debug(`Input execution failed: ${error.message}`);
          traces.push({
            input,
            error: error.message,
            success: false,
            timestamp: new Date()
          });
        }
      }

      return traces;

    } catch (error) {
      throw new Error(`Instrumentation execution failed: ${error.message}`);
    }
  }

  async executeInputWithTracing(input, config) {
    const trace = {
      input,
      propertyAccesses: [],
      functionCalls: [],
      prototypeChanges: [],
      sinkAccesses: [],
      errors: [],
      success: false,
      startTime: Date.now(),
      endTime: null,
      // New: taint analysis results
      taintAnalysis: null,
      // New: V8 coverage metrics for this input
      v8Coverage: null
    };

    try {
      // Layer 3: Set up global sink interception
      this.setupSinkTracing(trace, config.sinks);

      if (this._isBrowserSandbox(config)) {
        // Browser-only targets (jQuery, …) MUST NOT run in-process: a fuzzer
        // input reaching an ajax-family entry point makes jsdom perform a
        // SYNCHRONOUS XHR that blocks the fuzzer's own event loop, freezing the
        // whole run (neither safeExecute's timer nor the iteration timeout can
        // fire on a frozen loop). Run the call in the sandbox pool instead — its
        // parent-side SIGKILL watchdog survives a wedged child, and the main
        // loop stays free so the orchestrator's iteration timeout still works.
        // The in-process taint proxy / V8 snapshot cannot observe a child call,
        // so they are skipped here; UOP discovery for browser targets already
        // runs sandboxed (discoverUOPCandidates) and gadget confirmation is the
        // differential phase, which is sandboxed too.
        await this._executeInputSandboxed(input, config, trace);
      } else {
        // Execute the input with Layer 2 (Proxy taint tracking)
        await this.executeInputWithTaintTracking(input, config, trace);
      }

      // Layer 1b: Collect V8 coverage snapshot for this input
      if (this.v8CoverageEnabled) {
        try {
          const rawCoverage = await this.v8Collector.takeCoverage();
          const metrics = this.v8Collector.extractMetrics(rawCoverage);
          trace.v8Coverage = metrics.summary;

          // Feed V8 block data into the AFL-style bitmap
          this.feedV8CoverageIntoBitmap(metrics, trace);

          // Record V8 metrics as the LATEST cumulative snapshot, not a running
          // sum. V8 precise coverage (Profiler.takePreciseCoverage) is cumulative
          // since collection started, so every snapshot already reports the full
          // covered/total counts for all loaded scripts. Adding successive
          // snapshots together (the previous `+=`) double-counted every block on
          // every input and made the reported Block/Branch/Function coverage %
          // exceed 100% and be meaningless. Assigning the latest snapshot keeps
          // the reported figure a real fraction (covered ≤ total).
          this.v8Metrics.totalBlocks = metrics.summary.totalBlocks;
          this.v8Metrics.coveredBlocks = metrics.summary.coveredBlocks;
          this.v8Metrics.totalBranches = metrics.summary.totalBranches;
          this.v8Metrics.coveredBranches = metrics.summary.coveredBranches;
          this.v8Metrics.totalFunctions = metrics.summary.totalFunctions;
          this.v8Metrics.coveredFunctions = metrics.summary.coveredFunctions;
        } catch (error) {
          logger.debug(`V8 coverage snapshot failed: ${error.message}`);
        }
      }

      trace.success = true;

    } catch (error) {
      trace.errors.push({
        message: error.message,
        stack: error.stack,
        timestamp: Date.now()
      });
    } finally {
      trace.endTime = Date.now();
      this.cleanupTracing();

      // Layer 1: Compute edge coverage from trace events
      // (this always runs, even if V8 coverage is also available)
      trace.coverage = this.coverageTracker.computeCoverageFromTrace(trace);
      trace.coverageResult = this.coverageTracker.mergeAndCheckNovelty(trace.coverage);
    }

    return trace;
  }

  /**
   * Execute an input with Proxy-based taint tracking (Layer 2).
   *
   * Wraps the input value in a recursive Proxy that logs every
   * property access. This catches `.property` reads that the old
   * hasOwnProperty hook completely missed.
   *
   * After execution, analyzes the taint log for:
   * - UOP candidates (undefined property reads)
   * - Prototype chain lookups (values from proto chain)
   * - Read-then-write patterns (common gadget shape)
   */
  async executeInputWithTaintTracking(input, config, trace) {
    const taintLog = [];

    // Wrap input in taint-tracking proxy
    let trackedInput = input.value;
    if (trackedInput && typeof trackedInput === 'object' && !Buffer.isBuffer(trackedInput)) {
      try {
        trackedInput = createTaintProxy(trackedInput, taintLog);
      } catch (error) {
        logger.debug(`Taint proxy creation failed: ${error.message}`);
      }
    }

    // Also set up old-style prototype/property hooks for compatibility
    this.setupPropertyTracing(trace);
    this.setupPrototypeTracing(trace);

    // Execute with the tainted input
    await this.executeInput(
      { ...input, value: trackedInput },
      config,
      trace
    );

    // Analyze taint log
    if (taintLog.length > 0) {
      trace.taintAnalysis = analyzeTaintLog(taintLog);

      // Convert taint events to trace-compatible property accesses
      // so the existing gadget analysis can use them
      for (const event of taintLog) {
        if (event.type === 'get') {
          trace.propertyAccesses.push({
            type: 'taint_proxy',
            object: event.path.split('.').slice(0, -1).join('.') || '$',
            property: event.property,
            timestamp: event.timestamp,
            result: event.isUndefined ? undefined : '[value]',
            isUOPCandidate: event.isUOPCandidate,
            isPrototypeChainLookup: event.isPrototypeChainLookup
          });
        }
        if (event.type === 'setPrototypeOf') {
          trace.prototypeChanges.push({
            type: 'setPrototypeOf',
            target: event.path,
            property: '__proto__',
            timestamp: event.timestamp
          });
        }
      }
    }
  }

  /**
   * True when this target's Phase A coverage-exploration calls must run in the
   * sandbox child rather than in-process: a browser-only package (jQuery, …)
   * under jsdom, with sandboxing enabled. `config.browserEnv` is set at setup
   * time when the target was loaded via jsdom (covers the DOM-detection fallback
   * too); the name check is the shared single-source-of-truth used by every
   * other sandboxed mode. See _executeInputSandboxed for why in-process is unsafe.
   */
  _isBrowserSandbox(config) {
    if (!this.options.sandbox || !config?.package) return false;
    return config.browserEnv === true || isBrowserOnly(packageBaseName(config.package));
  }

  /** True when `config` describes a browser-only target, regardless of sandboxing. */
  _isBrowserTarget(config) {
    if (!config?.package) return false;
    return config.browserEnv === true || isBrowserOnly(packageBaseName(config.package));
  }

  /**
   * Warn once per run when --no-sandbox is combined with a browser-only target.
   * That combination puts the target back in-process, which is exactly where a
   * synchronous jsdom XHR (e.g. `$.ajax({async:false})` reached by a fuzzed
   * input) blocks the fuzzer's own event loop — and a frozen loop cannot fire
   * either the per-call or the per-iteration timeout, so the run wedges until an
   * external kill. It is a legitimate "faster, less safe" opt-in, but a silent
   * one looks like a hang.
   *
   * @returns {boolean} whether a warning was emitted (for callers/tests).
   */
  warnIfUnsandboxedBrowserTarget(config) {
    if (this.options.sandbox) return false;
    if (!this._isBrowserTarget(config)) return false;
    logger.warn(
      `${config.name || config.package} is a browser-only target running with --no-sandbox: ` +
      `it executes in-process, where a synchronous jsdom XHR can freeze the fuzzer's event loop ` +
      `and hang the run (no timeout can fire on a frozen loop). Drop --no-sandbox to run it in ` +
      `an isolated child with a rescue watchdog.`
    );
    return true;
  }

  /**
   * Phase A execution for browser-only targets, routed through the sandbox pool
   * (mode 'execute') instead of the in-process safeExecute path. This keeps a
   * synchronous jsdom XHR (from an ajax-family entry point) contained to the
   * child, where the pool's parent-side SIGKILL watchdog can rescue a wedged
   * loop — the fuzzer's own event loop stays free. Errors/timeouts are contained
   * here (never rethrown), mirroring safeExecute's swallow-into-result contract,
   * and the same 5-consecutive-failure entry-point skip as executeInput().
   */
  async _executeInputSandboxed(input, config, trace) {
    const epKey = input.entryPoint;
    if ((this._entryPointFailures.get(epKey) || 0) > 5) {
      trace.errors.push({ message: `Skipped ${epKey} (too many failures)`, timestamp: Date.now() });
      return;
    }

    const args = input.type === 'template' ? [input.value] : [input.value];
    const callRecord = {
      function: epKey,
      arguments: args.map(a => typeof a === 'string' ? a.substring(0, 200) : '[object]'),
      timestamp: Date.now(),
    };
    trace.functionCalls.push(callRecord);

    try {
      const result = await this._getPool().run(config.package, epKey, args, {
        timeoutMs: DIFF_CALL_TIMEOUT_MS,
        blockNetwork: this.options.blockNetwork !== false,
        mode: 'execute',
        browserEnv: true,
      });

      if (result?.error) {
        // A contained failure (fn threw, timed out, or the worker was SIGKILLed
        // after a sync-XHR freeze). Record it like safeExecute would and count it
        // toward the entry-point failure budget.
        callRecord.result = `[ERROR: ${result.error}]`;
        const count = (this._entryPointFailures.get(epKey) || 0) + 1;
        this._entryPointFailures.set(epKey, count);
        if (count === 5) logger.debug(`Disabling entry point ${epKey} after 5 consecutive failures`);
        return;
      }

      const out = result?.output;
      callRecord.result = typeof out === 'string' ? out.substring(0, 500) : typeof out;
      this._entryPointFailures.set(epKey, 0);
    } catch (error) {
      // The pool itself never rejects for target errors, but guard anyway so a
      // Phase A input can never take the run down.
      callRecord.result = `[ERROR: ${error.message}]`;
      trace.errors.push({ message: error.message, timestamp: Date.now() });
    }
  }

  /**
   * Run the differential oracle on an input with a pollution descriptor.
   *
   * Executes the target twice (clean + polluted) and compares results.
   * This is the core mechanism for confirming real gadgets vs false positives.
   *
   * When sandbox mode is enabled (default), executes in an isolated child
   * process to prevent malicious target code from affecting the fuzzer.
   *
   * @param {object} input - The fuzzer-generated input
   * @param {object} config - Target configuration
   * @param {object} pollutionDescriptor - { property, value }
   * @returns {object} Differential result with gadget confirmation
   */
  async executeDifferentialTracing(input, config, pollutionDescriptor) {
    if (this.options.dryRun) return null;

    const isUrlSink = this._epIndex(config).epByName.get(input.entryPoint)?._isUrlSink;
    const timeoutMs = isUrlSink ? DIFF_URL_SINK_TIMEOUT_MS : DIFF_CALL_TIMEOUT_MS;

    // Sandboxed execution: run in child process.
    // Skip sandbox for browser-only packages — they require jsdom which
    // the sandbox child process doesn't have.
    const canSandbox = this.options.sandbox && config.package;
    if (canSandbox) {
      return this._sandboxedDifferential(config.package, input, pollutionDescriptor, timeoutMs);
    }

    // In-process execution (--no-sandbox)
    if (!this.targetModule) return null;

    const sequence = this._epIndex(config).seqByEntry.get(input.entryPoint);
    const fn = this.buildCallableThunk(input, config, sequence);
    if (!fn) return null;

    const args = sequence
      ? this.buildCallArgs(sequence.steps[0], input, config)
      : (input.type === 'template' ? [input.value] : [input.value]);

    try {
      return await executeDifferential(fn, args, pollutionDescriptor, timeoutMs);
    } catch (error) {
      logger.debug(`Differential execution failed: ${error.message}`);
      return null;
    }
  }

  /**
   * Sandboxed differential execution via child process.
   * The target code runs in a separate V8 instance with:
   * - No network access (blocked at socket level)
   * - No child_process.exec (blocked)
   * - No sensitive env vars
   * - Memory-limited to 512MB
   * - Hard timeout from parent
   */
  async _sandboxedDifferential(packageName, input, descriptor, timeoutMs) {
    try {
      // Only serialize safe values for the pollution descriptor
      const safeDescriptor = {
        property: descriptor.property,
        value: typeof descriptor.value === 'function'
          ? '__UOPFUZZ_MARKER_7f3a__'  // Replace functions with sentinel
          : descriptor.value,
      };

      const args = input.type === 'template' ? [input.value] : [input.value];

      const result = await this._getPool().run(packageName, input.entryPoint, args, {
        timeoutMs,
        blockNetwork: this.options.blockNetwork !== false,
        pollution: safeDescriptor,
        mode: 'differential',
        browserEnv: isBrowserOnly(packageBaseName(packageName)),
      });

      if (result.error && !result.outputChanged && !result.prototypePolluted) {
        logger.debug(`Sandboxed differential failed: ${result.error}`);
        return null;
      }

      return this._reconcileSandboxDiff(descriptor, result);
    } catch (error) {
      logger.debug(`Sandboxed differential error: ${error.message}`);
      return null;
    }
  }

  /**
   * Translate a sandbox worker's raw FACTS into the diff shape gadget-analysis
   * expects, with the tier verdict computed by the SHARED classifyDiff() — the
   * same ladder the in-process oracle uses. This is the single reconciliation
   * point for every sandboxed differential-style mode (single-property, forced
   * branch, multi-property), so none of them can drift on tiering (invariant #4).
   *
   * The sandbox worker already computes pollutionWasRead (getter-trap fired) and
   * newSinkAccesses (eval/Function/vm hooks); those real facts flow straight
   * through. ZERO-FP: classifyDiff only PROPOSES candidates — only a real
   * prototype mutation (Tier 0) is pre-confirmed; every behavioral diff must
   * survive independent reproduction before it is reported.
   *
   * @param {{property:string,value:any}} descriptor - the primary payload descriptor.
   * @param {object} result - raw worker facts.
   * @param {object} [extraDetails] - mode-specific details merged into diff.details
   *   (e.g. { forcedBranch, forcedGates, forcedGatesFired } or { firedProperties }).
   * @param {string} [displayProperty] - property label for the diff (defaults to descriptor.property).
   * @returns {object|null} diffResult, or null when nothing actionable was observed.
   */
  _reconcileSandboxDiff(descriptor, result, extraDetails = {}, displayProperty = null) {
    const newSinkAccesses = result.newSinkAccesses || [];
    const pollutionWasRead = !!result.pollutionWasRead;
    const isPP = !!result.prototypePolluted;
    if (!(result.outputChanged || result.errorChanged || isPP ||
          newSinkAccesses.length > 0 || pollutionWasRead)) {
      return null;
    }
    const property = displayProperty || descriptor.property;
    const payloadReachedOutput = !!(result.polluted?.output?.includes?.(String(descriptor.value)) &&
      !result.clean?.output?.includes?.(String(descriptor.value)));
    const verdict = classifyDiff({
      // Tier ordering keys off the PRIMARY payload property, not the combined
      // label, so a high-risk primary is still recognised in multi-property mode.
      property: descriptor.property,
      prototypePolluted: isPP,
      pollutionWasRead,
      newSinkAccesses,
      payloadInOutput: payloadReachedOutput,
      outputChanged: result.outputChanged || false,
      errorChanged: result.errorChanged || false,
    });
    // Nothing actionable — not even a manual-review lead. Drop it.
    if (!verdict.isConfirmedGadget && !verdict.isCandidate) return null;
    return {
      clean: { output: result.clean?.output, error: result.clean?.error, sinkAccesses: [], taintLog: [] },
      polluted: {
        output: result.polluted?.output,
        error: result.polluted?.error,
        sinkAccesses: newSinkAccesses,
        taintLog: [],
        pollutionWasRead,
        prototypePolluted: isPP,
        pollutedProperties: result.pollutedProperties || [],
      },
      diff: {
        property,
        payload: descriptor.value,
        outputChanged: result.outputChanged || false,
        errorChanged: result.errorChanged || false,
        newSinkAccesses,
        pollutionWasRead,
        prototypePolluted: isPP,
        pollutedProperties: result.pollutedProperties || [],
        ...verdict,
        details: {
          cleanOutput: result.clean?.output?.substring?.(0, 500),
          pollutedOutput: result.polluted?.output?.substring?.(0, 500),
          cleanError: result.clean?.error,
          pollutedError: result.polluted?.error,
          payloadReachedOutput,
          sandboxed: true,
          ...extraDetails,
        },
      },
    };
  }

  /**
   * Forced branch execution: co-pollute boolean gate properties (debug, client,
   * strict, etc.) alongside the payload property to force guarded code paths open.
   * Inspired by Dasty (KTH, WWW 2024) — found 67 additional exploitable packages.
   */
  async executeForcedBranchDifferentialTracing(input, config, pollutionDescriptor) {
    if (this.options.dryRun) return null;

    const canSandbox = this.options.sandbox && config.package;
    if (canSandbox) {
      return this._sandboxedForcedBranch(config.package, input, pollutionDescriptor, DIFF_CALL_TIMEOUT_MS);
    }

    if (!this.targetModule) return null;

    const sequence = this._epIndex(config).seqByEntry.get(input.entryPoint);
    const fn = this.buildCallableThunk(input, config, sequence);
    if (!fn) return null;

    const args = sequence
      ? this.buildCallArgs(sequence.steps[0], input, config)
      : (input.type === 'template' ? [input.value] : [input.value]);

    try {
      return await executeForcedBranchDifferential(fn, args, pollutionDescriptor, DIFF_CALL_TIMEOUT_MS);
    } catch (error) {
      logger.debug(`Forced branch differential failed: ${error.message}`);
      return null;
    }
  }

  /**
   * Sandboxed forced-branch execution via the worker's 'forced_branch' mode.
   * The child co-pollutes the payload property AND every boolean gate property,
   * so guarded sinks (`if (opts.debug) eval(opts.template)`) open in a fresh,
   * isolated process rather than in-process with the fuzzer's privileges.
   */
  async _sandboxedForcedBranch(packageName, input, descriptor, timeoutMs) {
    try {
      const safeDescriptor = {
        property: descriptor.property,
        value: typeof descriptor.value === 'function' ? '__UOPFUZZ_MARKER_7f3a__' : descriptor.value,
      };
      const args = input.type === 'template' ? [input.value] : [input.value];
      const result = await this._getPool().run(packageName, input.entryPoint, args, {
        timeoutMs,
        blockNetwork: this.options.blockNetwork !== false,
        pollution: safeDescriptor,
        mode: 'forced_branch',
        browserEnv: isBrowserOnly(packageBaseName(packageName)),
      });
      if (result?.error && !result.outputChanged && !result.prototypePolluted && !result.pollutionWasRead) {
        logger.debug(`Sandboxed forced-branch failed: ${result.error}`);
        return null;
      }
      return this._reconcileSandboxDiff(descriptor, result, {
        forcedBranch: true,
        forcedGates: result.forcedGates || [],
        forcedGatesFired: result.forcedGatesFired || [],
      });
    } catch (error) {
      logger.debug(`Sandboxed forced-branch error: ${error.message}`);
      return null;
    }
  }


  /**
   * Multi-property co-pollution differential test.
   * Pollutes multiple Object.prototype properties simultaneously to catch
   * conjunctive gadgets that require >1 property to be set.
   */
  async executeMultiPropertyDifferentialTracing(input, config, descriptors) {
    if (this.options.dryRun) return null;

    const canSandbox = this.options.sandbox && config.package;
    if (canSandbox) {
      return this._sandboxedMultiProperty(config.package, input, descriptors, DIFF_CALL_TIMEOUT_MS);
    }

    if (!this.targetModule) return null;

    const sequence = this._epIndex(config).seqByEntry.get(input.entryPoint);
    const fn = this.buildCallableThunk(input, config, sequence);
    if (!fn) return null;

    const args = sequence
      ? this.buildCallArgs(sequence.steps[0], input, config)
      : (input.type === 'template' ? [input.value] : [input.value]);

    try {
      return await executeMultiPropertyDifferential(fn, args, descriptors, DIFF_CALL_TIMEOUT_MS);
    } catch (error) {
      logger.debug(`Multi-property differential failed: ${error.message}`);
      return null;
    }
  }

  /**
   * Sandboxed multi-property co-pollution via the worker's 'multi_property' mode.
   * Co-pollutes every descriptor at once in a fresh isolated process to catch
   * conjunctive gadgets (two properties that only reach a sink together).
   */
  async _sandboxedMultiProperty(packageName, input, descriptors, timeoutMs) {
    try {
      const safeDescriptors = descriptors.map(d => ({
        property: d.property,
        value: typeof d.value === 'function' ? '__UOPFUZZ_MARKER_7f3a__' : d.value,
      }));
      const args = input.type === 'template' ? [input.value] : [input.value];
      const result = await this._getPool().run(packageName, input.entryPoint, args, {
        timeoutMs,
        blockNetwork: this.options.blockNetwork !== false,
        pollution: { descriptors: safeDescriptors },
        mode: 'multi_property',
        browserEnv: isBrowserOnly(packageBaseName(packageName)),
      });
      if (result?.error && !result.outputChanged && !result.prototypePolluted && !result.pollutionWasRead) {
        logger.debug(`Sandboxed multi-property failed: ${result.error}`);
        return null;
      }
      // Primary descriptor drives tier ordering; the combined label is display-only.
      const primary = descriptors[0] || { property: '', value: undefined };
      const combinedName = descriptors.map(d => d.property).join('+');
      return this._reconcileSandboxDiff(
        primary, result,
        { firedProperties: result.firedProperties || [], coPolluteCount: descriptors.length },
        combinedName,
      );
    } catch (error) {
      logger.debug(`Sandboxed multi-property error: ${error.message}`);
      return null;
    }
  }

  async executeMergePPDifferential(input, config, descriptor) {
    if (this.options.dryRun) return null;

    const isUrlSink = this._epIndex(config).epByName.get(input.entryPoint)?._isUrlSink;
    const canSandbox = this.options.sandbox && config.package;

    const timeoutMs = isUrlSink ? DIFF_URL_SINK_TIMEOUT_MS : DIFF_CALL_TIMEOUT_MS;

    if (canSandbox) {
      // Use the worker's dedicated 'merge_pp' mode, which tries the real
      // calling conventions (fn({}, payload), fn(true, {}, payload), path-based
      // set, etc.). Routing this through generic 'differential' mode would call
      // fn(payload) with a single argument, which never triggers merge-based
      // pollution (e.g. lodash.merge needs a target object as arg 0).
      return this._sandboxedMergePP(config.package, input.entryPoint, descriptor, timeoutMs);
    }

    if (!this.targetModule) return null;

    const rawFn = this.getEntryPointFunction(this.targetModule, input.entryPoint, config.package);
    if (!rawFn) return null;

    try {
      logger.debug(`MergePP testing entry point: ${input.entryPoint} (fn=${rawFn?.name || 'anonymous'})`);
      return await executeMergePPTest(rawFn, [{}], descriptor.property, descriptor.value, timeoutMs);
    } catch (error) {
      logger.debug(`Merge PP test failed for ${input.entryPoint}: ${error.message}`);
      return null;
    }
  }

  /**
   * Sandboxed merge-PP test via the worker's 'merge_pp' mode.
   * Translates the worker's { pollutionDetected, pollutedProperties } into the
   * diff shape gadget-analysis expects (mirrors executeMergePPTest's return).
   */
  async _sandboxedMergePP(packageName, entryPoint, descriptor, timeoutMs) {
    try {
      const safeDescriptor = {
        property: descriptor.property,
        value: typeof descriptor.value === 'function' ? '__UOPFUZZ_MARKER_7f3a__' : descriptor.value,
      };

      const result = await this._getPool().run(packageName, entryPoint, [{}], {
        timeoutMs,
        blockNetwork: this.options.blockNetwork !== false,
        pollution: safeDescriptor,
        mode: 'merge_pp',
        browserEnv: isBrowserOnly(packageBaseName(packageName)),
      });

      if (!result?.pollutionDetected) return null;

      const pollutedProperties = result.pollutedProperties || [];
      return {
        clean: { output: null, error: null, sinkAccesses: [], taintLog: [] },
        polluted: {
          output: null, error: result.error || null, sinkAccesses: [], taintLog: [],
          pollutionWasRead: false,
          prototypePolluted: true,
          pollutedProperties,
        },
        diff: {
          property: pollutedProperties[0] || descriptor.property,
          payload: descriptor.value,
          isConfirmedGadget: true,
          proofType: 'pp',
          reproducible: true,
          confidence: 0.95,
          prototypePolluted: true,
          pollutedProperties,
          pollutionWasRead: false,
          outputChanged: false,
          errorChanged: false,
          newSinkAccesses: [],
          details: { payloadType: 'merge_pp', payloadReachedOutput: false, sandboxed: true },
        },
        output: null,
        error: result.error || null,
      };
    } catch (error) {
      logger.debug(`Sandboxed merge-PP error: ${error.message}`);
      return null;
    }
  }

  async executeURLGadgetDifferential(input, config, descriptor) {
    if (this.options.dryRun) return null;

    const isUrlSink = this._epIndex(config).epByName.get(input.entryPoint)?._isUrlSink;
    const canSandbox = this.options.sandbox && config.package;

    if (canSandbox) {
      const urlInput = {
        ...input,
        value: JSON.parse(`{"__proto__":{"${descriptor.property}":${JSON.stringify(descriptor.value)}}}`),
      };
      return this._sandboxedDifferential(config.package, urlInput, descriptor, isUrlSink ? DIFF_URL_SINK_TIMEOUT_MS : DIFF_CALL_TIMEOUT_MS);
    }

    if (!this.targetModule) return null;

    const rawFn = this.getEntryPointFunction(this.targetModule, input.entryPoint, config.package);
    if (!rawFn) return null;

    const timeoutMs = isUrlSink ? DIFF_URL_SINK_TIMEOUT_MS : DIFF_CALL_TIMEOUT_MS;

    try {
      return await executeURLGadgetTest(rawFn, descriptor.property, descriptor.value, timeoutMs);
    } catch (error) {
      logger.debug(`URL gadget test failed: ${error.message}`);
      return null;
    }
  }

  /**
   * Build a callable function from an entry point or call sequence.
   * For sequences, returns a thunk that executes all steps.
   */
  buildCallableThunk(input, config, sequence) {
    if (!sequence) {
      const fn = this.getEntryPointFunction(this.targetModule, input.entryPoint, config.package);
      return fn || null;
    }

    // For multi-step sequences, return a function that executes the full chain
    const self = this;
    return async function sequenceThunk(...firstArgs) {
      let lastResult = null;
      for (let i = 0; i < sequence.steps.length; i++) {
        const step = sequence.steps[i];
        let fn;
        if (step.call === '__result__') {
          if (step.method && lastResult && typeof lastResult[step.method] === 'function') {
            fn = lastResult[step.method].bind(lastResult);
          } else if (typeof lastResult === 'function') {
            fn = lastResult;
          } else {
            return lastResult;
          }
        } else {
          fn = self.getEntryPointFunction(self.targetModule, step.call, config.package);
          if (!fn) return null;
        }
        const args = i === 0 ? firstArgs : self.buildCallArgs(step, input, config);
        lastResult = await Promise.resolve(fn(...args));
      }
      return lastResult;
    };
  }

  /**
   * Discover UOP properties from a clean execution of the target.
   * Returns property names the library tries to read but finds undefined.
   */
  async discoverUOPCandidates(input, config) {
    if (this.options.dryRun) return [];

    const timeoutMs = (this.options.timeout || 5) * 1000;
    const canSandbox = this.options.sandbox && config.package;
    if (canSandbox) {
      try {
        const args = input.type === 'template' ? [input.value] : [input.value];
        const result = await this._getPool().run(config.package, input.entryPoint, args, {
          timeoutMs,
          blockNetwork: this.options.blockNetwork !== false,
          mode: 'discover_uop',
          browserEnv: isBrowserOnly(packageBaseName(config.package)),
        });
        return Array.isArray(result?.uopProperties) ? result.uopProperties : [];
      } catch (error) {
        logger.debug(`Sandboxed UOP discovery failed: ${error.message}`);
        return [];
      }
    }

    if (!this.targetModule) return [];

    const sequence = this._epIndex(config).seqByEntry.get(input.entryPoint);
    const fn = this.buildCallableThunk(input, config, sequence);
    if (!fn) return [];

    const args = sequence
      ? this.buildCallArgs(sequence.steps[0], input, config)
      : (input.type === 'template' ? [input.value] : [input.value]);

    try {
      return await discoverUOPProperties(fn, args, timeoutMs);
    } catch (error) {
      logger.debug(`UOP discovery failed: ${error.message}`);
      return [];
    }
  }

  /**
   * Feed V8 block coverage data into the AFL-style bitmap.
   *
   * Maps V8's (scriptId, startOffset, endOffset) tuples to bitmap
   * positions using the same hash function. This means the power
   * schedule receives REAL coverage feedback from the JS engine,
   * not just our hook-based approximation.
   */
  feedV8CoverageIntoBitmap(metrics, trace) {
    const localBitmap = this.coverageTracker.createLocalBitmap();
    let prevLoc = 0;

    for (const block of metrics.blocks) {
      if (block.count === 0) continue;

      // Use script + offset as the location identifier
      const loc = this.coverageTracker.hashLocation(
        'v8',
        `${block.scriptId}:${block.startOffset}`,
        block.functionName || ''
      );

      // Record as edge: prevBlock -> thisBlock
      this.coverageTracker.recordEdge(localBitmap, prevLoc, loc);
      prevLoc = loc >> 1;
    }

    // For branches: record taken/not-taken edges
    for (const branch of metrics.branches) {
      const loc = this.coverageTracker.hashLocation(
        'v8br',
        `${branch.scriptUrl}:${branch.startOffset}`,
        branch.taken ? 'T' : 'F'
      );
      this.coverageTracker.recordEdge(localBitmap, prevLoc, loc);
      prevLoc = loc >> 1;
    }

    // Merge V8-derived bitmap into global
    const result = this.coverageTracker.mergeAndCheckNovelty(localBitmap);

    // If V8 coverage found new edges, mark in trace
    if (result.isNovel && trace.coverageResult) {
      trace.coverageResult.v8NewEdges = result.newEdges;
      trace.coverageResult.isNovel = true;
    }
  }

  setupPropertyTracing(trace) {
    const originalGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
    const originalHasOwnProperty = Object.prototype.hasOwnProperty;

    Object.getOwnPropertyDescriptor = function(obj, prop) {
      if (obj && typeof obj === 'object') {
        trace.propertyAccesses.push({
          type: 'getOwnPropertyDescriptor',
          object: obj.constructor?.name || 'Object',
          property: prop,
          timestamp: Date.now(),
          result: originalGetOwnPropertyDescriptor.call(this, obj, prop)
        });
      }
      return originalGetOwnPropertyDescriptor.call(this, obj, prop);
    };

    Object.prototype.hasOwnProperty = function(prop) {
      trace.propertyAccesses.push({
        type: 'hasOwnProperty',
        object: this.constructor?.name || 'Object',
        property: prop,
        timestamp: Date.now(),
        result: originalHasOwnProperty.call(this, prop)
      });
      return originalHasOwnProperty.call(this, prop);
    };

    this.originalMethods = {
      getOwnPropertyDescriptor: originalGetOwnPropertyDescriptor,
      hasOwnProperty: originalHasOwnProperty
    };
  }

  setupPrototypeTracing(trace) {
    const originalSetPrototypeOf = Object.setPrototypeOf;
    const originalDefineProperty = Object.defineProperty;

    Object.setPrototypeOf = function(obj, prototype) {
      trace.prototypeChanges.push({
        type: 'setPrototypeOf',
        target: obj.constructor?.name || 'Object',
        prototype: prototype?.constructor?.name || 'Object',
        timestamp: Date.now()
      });
      return originalSetPrototypeOf.call(this, obj, prototype);
    };

    Object.defineProperty = function(obj, prop, descriptor) {
      if (prop === '__proto__' || prop === 'prototype') {
        trace.prototypeChanges.push({
          type: 'defineProperty',
          target: obj.constructor?.name || 'Object',
          property: prop,
          descriptor: descriptor,
          timestamp: Date.now()
        });
      }
      return originalDefineProperty.call(this, obj, prop, descriptor);
    };

    this.originalMethods.setPrototypeOf = originalSetPrototypeOf;
    this.originalMethods.defineProperty = originalDefineProperty;
  }

  setupSinkTracing(trace, sinks) {
    const dangeroursGlobals = ['eval', 'Function', 'setTimeout', 'setInterval'];

    for (const sink of sinks) {
      try {
        if (typeof global[sink] === 'function') {
          const original = global[sink];

          global[sink] = function(...args) {
            trace.sinkAccesses.push({
              sink,
              arguments: args.map(arg =>
                typeof arg === 'string' ? arg : '[object]'
              ),
              timestamp: Date.now(),
              callStack: new Error().stack
            });

            logger.debug(`Sink access detected: ${sink}`);
            return '[SIMULATED_SINK_RESULT]';
          };

          this.instrumentedFunctions.add({ name: sink, original });
        }
      } catch (error) {
        logger.debug(`Failed to instrument sink ${sink}: ${error.message}`);
      }
    }

    try {
      if (childProcessModule && childProcessModule.exec) {
        const originalExec = childProcessModule.exec;
        childProcessModule.exec = function(command, options, callback) {
          trace.sinkAccesses.push({
            sink: 'child_process.exec',
            arguments: [command],
            timestamp: Date.now(),
            callStack: new Error().stack
          });

          logger.warn(`Command execution attempt detected: ${command}`);
          if (callback) callback(null, '[SIMULATED_EXEC_RESULT]', '');
          return { pid: 12345 };
        };
      }
    } catch (error) {
      // child_process not available or not instrumentable
    }
  }

  async executeInput(input, config, trace) {
    if (!this.targetModule || this.options.dryRun) {
      await this.simulateExecution(input, config, trace);
      return;
    }

    // Skip entry points that consistently fail (> 5 consecutive errors)
    const epKey = input.entryPoint;
    if ((this._entryPointFailures.get(epKey) || 0) > 5) {
      trace.errors.push({ message: `Skipped ${epKey} (too many failures)`, timestamp: Date.now() });
      return;
    }

    // Check if config defines call sequences for this entry point
    const sequence = this._epIndex(config).seqByEntry.get(input.entryPoint);

    try {
      if (sequence) {
        await this.executeCallSequence(input, config, trace, sequence);
      } else {
        await this.executeSingleCall(input, config, trace);
      }
      // Reset failure count on success
      this._entryPointFailures.set(epKey, 0);
    } catch (error) {
      const count = (this._entryPointFailures.get(epKey) || 0) + 1;
      this._entryPointFailures.set(epKey, count);
      if (count === 5) {
        logger.debug(`Disabling entry point ${epKey} after 5 consecutive failures`);
      }
      throw error;
    }
  }

  /**
   * Execute a multi-step call sequence (e.g., compile -> render).
   *
   * Many template engine gadgets require: const fn = lib.compile(template, options);
   * then fn(locals) to trigger the sink. Single-call fuzzing misses these entirely.
   */
  async executeCallSequence(input, config, trace, sequence) {
    let lastResult = null;

    for (const step of sequence.steps) {
      let fn;

      if (step.call === '__result__') {
        // Call the result of the previous step (e.g., compiled template function)
        // If step.method is set, call lastResult[method]() instead
        if (step.method && lastResult && typeof lastResult[step.method] === 'function') {
          fn = lastResult[step.method].bind(lastResult);
        } else if (typeof lastResult === 'function') {
          fn = lastResult;
        } else {
          trace.errors.push({ message: 'Previous step did not return callable', timestamp: Date.now() });
          return;
        }
      } else {
        fn = this.getEntryPointFunction(this.targetModule, step.call, config.package);
        if (!fn) {
          trace.errors.push({ message: `Entry point ${step.call} not found`, timestamp: Date.now() });
          return;
        }
      }

      // Build arguments from step definition
      const args = this.buildCallArgs(step, input, config);

      trace.functionCalls.push({
        function: step.call,
        arguments: args.map(a => typeof a === 'string' ? a.substring(0, 200) : '[object]'),
        timestamp: Date.now()
      });

      lastResult = await this.safeExecute(fn, args);

      trace.functionCalls[trace.functionCalls.length - 1].result =
        typeof lastResult === 'string' ? lastResult.substring(0, 500) : typeof lastResult;
    }
  }

  /**
   * Execute a single entry point call (fallback when no sequence defined).
   */
  async executeSingleCall(input, config, trace) {
    const entryPointName = input.entryPoint;
    const entryPoint = this.getEntryPointFunction(this.targetModule, entryPointName, config.package);

    if (!entryPoint) {
      throw new Error(`Entry point ${entryPointName} not found in target module`);
    }

    // Build arguments based on input type
    const args = input.type === 'template'
      ? [input.value]
      : [input.value];

    trace.functionCalls.push({
      function: entryPointName,
      arguments: args.map(a => typeof a === 'string' ? a.substring(0, 200) : '[object]'),
      timestamp: Date.now()
    });

    const result = await this.safeExecute(entryPoint, args);

    trace.functionCalls[trace.functionCalls.length - 1].result =
      typeof result === 'string' ? result.substring(0, 500) : typeof result;
  }

  /**
   * Build call arguments from a sequence step definition and current input.
   */
  buildCallArgs(step, input, config) {
    const args = [];
    for (const argDef of (step.args || ['input'])) {
      switch (argDef) {
        case 'input':
        case 'template':
          args.push(input.value);
          break;
        case 'options':
          // Pass an empty options object - pollution comes from Object.prototype
          args.push(input.options || {});
          break;
        case 'locals':
          args.push(input.locals || { name: 'test', title: 'Test' });
          break;
        default:
          args.push(argDef);
      }
    }
    return args;
  }

  getEntryPointFunction(targetModule, entryPointName, packageName) {
    if (entryPointName.includes('.')) {
      const path = entryPointName.split('.');
      let current = targetModule;

      for (const segment of path) {
        if (current && current[segment]) {
          current = current[segment];
        } else {
          return null;
        }
      }
      return current;
    }

    if (targetModule[entryPointName]) {
      return targetModule[entryPointName];
    }

    if (targetModule.default && targetModule.default[entryPointName]) {
      return targetModule.default[entryPointName];
    }

    // Bare-function module: `module.exports = fn` (merge-deep, deep-extend, …).
    // Only fall back to the module itself when entryPointName IS the package's
    // own name — never as a catch-all for an unrelated or nonexistent name.
    if (entryPointName === packageName) {
      if (typeof targetModule === 'function') return targetModule;
      if (typeof targetModule.default === 'function') return targetModule.default;
    }

    return null;
  }

  async safeExecute(fn, args) {
    let timer;
    // Suppress console.error/warn — frameworks spam stderr on every call
    console.error = _noopFn;
    console.warn = _noopFn;
    try {
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Execution timeout')), 5000);
      });

      const execution = Promise.resolve(fn(...args));

      return await Promise.race([execution, timeout]);

    } catch (error) {
      logger.debug(`Safe execution failed: ${error.message}`);
      return `[ERROR: ${error.message}]`;
    } finally {
      clearTimeout(timer);
      console.error = _origConsoleError;
      console.warn = _origConsoleWarn;
    }
  }

  async simulateExecution(input, config, trace) {
    const delay = Math.random() * 100;
    await new Promise(resolve => setTimeout(resolve, delay));

    // Simulate property accesses
    for (let i = 0; i < Math.floor(Math.random() * 5); i++) {
      trace.propertyAccesses.push({
        type: 'simulated',
        object: 'MockObject',
        property: `prop${i}`,
        timestamp: Date.now(),
        result: undefined
      });
    }

    // Simulate pollution detection with realistic probability
    if (input.metadata?.pollution && Math.random() < 0.3) {
      trace.prototypeChanges.push({
        type: 'simulated_pollution',
        target: 'Object',
        property: '__proto__',
        timestamp: Date.now()
      });
    }

    // Simulate sink access
    if (Math.random() < 0.1) {
      trace.sinkAccesses.push({
        sink: 'eval',
        arguments: ['simulated_code'],
        timestamp: Date.now(),
        callStack: 'Simulated stack trace'
      });
    }
  }

  createMockTrace(input, config) {
    return {
      input,
      propertyAccesses: [
        {
          type: 'mock',
          object: 'MockObject',
          property: 'mockProperty',
          timestamp: Date.now(),
          result: undefined
        }
      ],
      functionCalls: [
        {
          function: input.entryPoint,
          arguments: input.value,
          result: '[MOCK_RESULT]',
          timestamp: Date.now()
        }
      ],
      prototypeChanges: input.metadata?.pollution ? [
        {
          type: 'mock_pollution',
          target: 'Object',
          property: '__proto__',
          timestamp: Date.now()
        }
      ] : [],
      sinkAccesses: [],
      errors: [],
      success: true,
      startTime: Date.now(),
      endTime: Date.now() + Math.random() * 50
    };
  }

  cleanupTracing() {
    if (this.originalMethods) {
      Object.getOwnPropertyDescriptor = this.originalMethods.getOwnPropertyDescriptor;
      Object.prototype.hasOwnProperty = this.originalMethods.hasOwnProperty;
      Object.setPrototypeOf = this.originalMethods.setPrototypeOf;
      Object.defineProperty = this.originalMethods.defineProperty;
    }

    for (const instrumented of this.instrumentedFunctions) {
      try {
        global[instrumented.name] = instrumented.original;
      } catch (error) {
        logger.debug(`Failed to restore ${instrumented.name}: ${error.message}`);
      }
    }

    this.instrumentedFunctions.clear();
  }

  /**
   * Get coverage statistics combining both trace-based and V8 coverage.
   */
  getCoverageStats() {
    const traceStats = this.coverageTracker.getStats();
    return {
      ...traceStats,
      v8CoverageEnabled: this.v8CoverageEnabled,
      v8Metrics: this.v8CoverageEnabled ? { ...this.v8Metrics } : null
    };
  }

  getCoverageTracker() {
    return this.coverageTracker;
  }

  getTracingStats() {
    const coverageStats = this.coverageTracker.getStats();
    return {
      totalTraces: this.traces.length,
      instrumentedFunctions: this.instrumentedFunctions.size,
      propertyAccesses: this.propertyAccesses.size,
      coverageEdges: coverageStats.coveredEdges,
      coverageDensity: coverageStats.bitmapDensity,
      coverageEntropy: this.coverageTracker.getCoverageEntropy(),
      saturationRate: coverageStats.saturationRate,
      v8CoverageEnabled: this.v8CoverageEnabled,
      v8BlockCoverage: this.v8CoverageEnabled
        ? (this.v8Metrics.totalBlocks > 0
          ? this.v8Metrics.coveredBlocks / this.v8Metrics.totalBlocks
          : 0)
        : null,
      v8BranchCoverage: this.v8CoverageEnabled
        ? (this.v8Metrics.totalBranches > 0
          ? this.v8Metrics.coveredBranches / this.v8Metrics.totalBranches
          : 0)
        : null
    };
  }
}
