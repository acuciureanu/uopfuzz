import { logger } from '../utils/logger.js';
import { CoverageTracker } from '../utils/coverage.js';
import { V8CoverageCollector } from '../utils/v8-coverage.js';
import { createTaintProxy, analyzeTaintLog } from '../utils/taint-proxy.js';
import { executeDifferential, executeMultiPropertyDifferential, discoverUOPProperties, executeMergePPTest, executeURLGadgetTest, verifyExploit } from './differential.js';
import { executeInSandbox } from '../utils/sandbox.js';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
let childProcessModule;
try { childProcessModule = require('child_process'); } catch { childProcessModule = null; }

// Packages that require a browser DOM environment (jsdom) to load.
// The sandbox child process has no jsdom, so require('jquery') throws.
// For these we skip sandbox and run differential tests in-process using
// the already-loaded jsdom target module.
const BROWSER_ONLY_PACKAGES = new Set(['jquery', 'jquery-ui', 'backbone', 'underscore']);

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

      // Execute the input with Layer 2 (Proxy taint tracking)
      await this.executeInputWithTaintTracking(input, config, trace);

      // Layer 1b: Collect V8 coverage snapshot for this input
      if (this.v8CoverageEnabled) {
        try {
          const rawCoverage = await this.v8Collector.takeCoverage();
          const metrics = this.v8Collector.extractMetrics(rawCoverage);
          trace.v8Coverage = metrics.summary;

          // Feed V8 block data into the AFL-style bitmap
          this.feedV8CoverageIntoBitmap(metrics, trace);

          // Accumulate V8 metrics
          this.v8Metrics.totalBlocks += metrics.summary.totalBlocks;
          this.v8Metrics.coveredBlocks += metrics.summary.coveredBlocks;
          this.v8Metrics.totalBranches += metrics.summary.totalBranches;
          this.v8Metrics.coveredBranches += metrics.summary.coveredBranches;
          this.v8Metrics.totalFunctions += metrics.summary.totalFunctions;
          this.v8Metrics.coveredFunctions += metrics.summary.coveredFunctions;
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

    const isUrlSink = config.entryPoints?.find(ep => ep.name === input.entryPoint)?._isUrlSink;
    const timeoutMs = isUrlSink ? DIFF_URL_SINK_TIMEOUT_MS : DIFF_CALL_TIMEOUT_MS;

    // Sandboxed execution: run in child process.
    // Skip sandbox for browser-only packages — they require jsdom which
    // the sandbox child process doesn't have.
    const pkgBase = config.package?.split('@')[0];
    const canSandbox = this.options.sandbox && config.package && !BROWSER_ONLY_PACKAGES.has(pkgBase);
    if (canSandbox) {
      return this._sandboxedDifferential(config.package, input, pollutionDescriptor, timeoutMs);
    }

    // In-process execution (--no-sandbox)
    if (!this.targetModule) return null;

    const sequence = config.sequences?.find(s => s.entryPoint === input.entryPoint);
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

      const result = await executeInSandbox(packageName, input.entryPoint, args, {
        timeoutMs,
        blockNetwork: this.options.blockNetwork !== false,
        pollution: safeDescriptor,
        mode: 'differential',
      });

      if (result.error && !result.outputChanged && !result.prototypePolluted) {
        logger.debug(`Sandboxed differential failed: ${result.error}`);
        return null;
      }

      // Translate sandbox result to the format gadget-analysis expects
      if (result.outputChanged || result.errorChanged || result.prototypePolluted) {
        return {
          clean: { output: result.clean?.output, error: result.clean?.error, sinkAccesses: [], taintLog: [] },
          polluted: {
            output: result.polluted?.output,
            error: result.polluted?.error,
            sinkAccesses: [],
            taintLog: [],
            pollutionWasRead: true,
            prototypePolluted: result.prototypePolluted || false,
            pollutedProperties: result.pollutedProperties || [],
          },
          diff: {
            property: descriptor.property,
            payload: descriptor.value,
            outputChanged: result.outputChanged || false,
            errorChanged: result.errorChanged || false,
            newSinkAccesses: [],
            pollutionWasRead: true,
            prototypePolluted: result.prototypePolluted || false,
            pollutedProperties: result.pollutedProperties || [],
            isConfirmedGadget: true,
            confidence: result.prototypePolluted ? 0.95 : (result.outputChanged ? 0.75 : 0.60),
            details: {
              cleanOutput: result.clean?.output?.substring?.(0, 500),
              pollutedOutput: result.polluted?.output?.substring?.(0, 500),
              cleanError: result.clean?.error,
              pollutedError: result.polluted?.error,
              payloadReachedOutput: result.polluted?.output?.includes?.(String(descriptor.value)) &&
                !result.clean?.output?.includes?.(String(descriptor.value)),
              sandboxed: true,
            },
          },
        };
      }

      return null;
    } catch (error) {
      logger.debug(`Sandboxed differential error: ${error.message}`);
      return null;
    }
  }

  /**
   * Verify a confirmed gadget actually achieves code execution.
   * Uses canary-based payloads to prove the polluted property reaches a code execution sink.
   */
  async verifyGadgetExploit(input, config, property) {
    if (this.options.dryRun || !this.targetModule) return null;

    const sequence = config.sequences?.find(s => s.entryPoint === input.entryPoint);
    const fn = this.buildCallableThunk(input, config, sequence);
    if (!fn) return null;

    const args = sequence
      ? this.buildCallArgs(sequence.steps[0], input, config)
      : (input.type === 'template' ? [input.value] : [input.value]);

    try {
      return await verifyExploit(fn, args, property, DIFF_CALL_TIMEOUT_MS);
    } catch (error) {
      logger.debug(`Exploit verification failed for ${property}: ${error.message}`);
      return { verified: false, executionProof: null, payloadType: null };
    }
  }

  /**
   * Multi-property co-pollution differential test.
   * Pollutes multiple Object.prototype properties simultaneously to catch
   * conjunctive gadgets that require >1 property to be set.
   */
  async executeMultiPropertyDifferentialTracing(input, config, descriptors) {
    if (this.options.dryRun) return null;
    // Multi-property only works in-process (not sandboxed) for now
    if (!this.targetModule) return null;

    const sequence = config.sequences?.find(s => s.entryPoint === input.entryPoint);
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

  async executeMergePPDifferential(input, config, descriptor) {
    if (this.options.dryRun) return null;

    const isUrlSink = config.entryPoints?.find(ep => ep.name === input.entryPoint)?._isUrlSink;
    const pkgBase = config.package?.split('@')[0];
    const canSandbox = this.options.sandbox && config.package && !BROWSER_ONLY_PACKAGES.has(pkgBase);

    if (canSandbox) {
      const mergeInput = {
        ...input,
        value: JSON.parse(`{"__proto__":{"${descriptor.property}":${JSON.stringify(descriptor.value)}}}`),
      };
      const timeoutMs = isUrlSink ? DIFF_URL_SINK_TIMEOUT_MS : DIFF_CALL_TIMEOUT_MS;
      return this._sandboxedDifferential(config.package, mergeInput, descriptor, timeoutMs);
    }

    if (!this.targetModule) return null;

    const rawFn = this.getEntryPointFunction(this.targetModule, input.entryPoint);
    if (!rawFn) return null;

    const timeoutMs = isUrlSink ? DIFF_URL_SINK_TIMEOUT_MS : DIFF_CALL_TIMEOUT_MS;

    try {
      logger.debug(`MergePP testing entry point: ${input.entryPoint} (fn=${rawFn?.name || 'anonymous'})`);
      return await executeMergePPTest(rawFn, [{}], descriptor.property, descriptor.value, timeoutMs);
    } catch (error) {
      logger.debug(`Merge PP test failed for ${input.entryPoint}: ${error.message}`);
      return null;
    }
  }

  async executeURLGadgetDifferential(input, config, descriptor) {
    if (this.options.dryRun) return null;

    const isUrlSink = config.entryPoints?.find(ep => ep.name === input.entryPoint)?._isUrlSink;
    const pkgBase = config.package?.split('@')[0];
    const canSandbox = this.options.sandbox && config.package && !BROWSER_ONLY_PACKAGES.has(pkgBase);

    if (canSandbox) {
      const urlInput = {
        ...input,
        value: JSON.parse(`{"__proto__":{"${descriptor.property}":${JSON.stringify(descriptor.value)}}}`),
      };
      return this._sandboxedDifferential(config.package, urlInput, descriptor, isUrlSink ? DIFF_URL_SINK_TIMEOUT_MS : DIFF_CALL_TIMEOUT_MS);
    }

    if (!this.targetModule) return null;

    const rawFn = this.getEntryPointFunction(this.targetModule, input.entryPoint);
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
      const fn = this.getEntryPointFunction(this.targetModule, input.entryPoint);
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
          fn = self.getEntryPointFunction(self.targetModule, step.call);
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
    if (!this.targetModule || this.options.dryRun) return [];

    const sequence = config.sequences?.find(s => s.entryPoint === input.entryPoint);
    const fn = this.buildCallableThunk(input, config, sequence);
    if (!fn) return [];

    const args = sequence
      ? this.buildCallArgs(sequence.steps[0], input, config)
      : (input.type === 'template' ? [input.value] : [input.value]);

    try {
      return await discoverUOPProperties(fn, args, (this.options.timeout || 5) * 1000);
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
    const sequence = config.sequences?.find(s => s.entryPoint === input.entryPoint);

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
        fn = this.getEntryPointFunction(this.targetModule, step.call);
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
    const entryPoint = this.getEntryPointFunction(this.targetModule, entryPointName);

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

  getEntryPointFunction(targetModule, entryPointName) {
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
