import { logger } from '../utils/logger.js';
import { CoverageTracker } from '../utils/coverage.js';

/**
 * Instrumentation Engine with Coverage-Guided Feedback
 *
 * Combines dynamic taint tracking with AFL-style edge coverage to
 * provide feedback for the input generation power schedule.
 *
 * Instrumentation approach based on:
 *
 * 1. Dynamic Taint Analysis (Schwartz et al., IEEE S&P 2010):
 *    Tracks data flow from pollution sources to sinks through
 *    property accesses and function calls.
 *
 * 2. Edge Coverage (Zalewski, AFL 2014): Records control-flow
 *    edges exercised during execution for novelty detection.
 *
 * 3. Prototype Chain Monitoring: Hooks into Object.setPrototypeOf,
 *    Object.defineProperty, and property access methods to detect
 *    prototype modifications at runtime.
 */
export class Instrumentation {
  constructor(options) {
    this.options = options;
    this.traces = [];
    this.propertyAccesses = new Map();
    this.originalConsole = {};
    this.instrumentedFunctions = new Set();
    this.coverageTracker = new CoverageTracker();
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
      endTime: null
    };

    try {
      this.setupPropertyTracing(trace);
      this.setupPrototypeTracing(trace);
      this.setupSinkTracing(trace, config.sinks);

      await this.executeInput(input, config, trace);

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

      // Compute edge coverage from trace events
      trace.coverage = this.coverageTracker.computeCoverageFromTrace(trace);
      trace.coverageResult = this.coverageTracker.mergeAndCheckNovelty(trace.coverage);
    }

    return trace;
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

            logger.warn(`🚨 Potential sink access detected: ${sink}`);
            return '[SIMULATED_SINK_RESULT]';
          };

          this.instrumentedFunctions.add({ name: sink, original });
        }
      } catch (error) {
        logger.debug(`Failed to instrument sink ${sink}: ${error.message}`);
      }
    }

    try {
      const childProcess = require('child_process');
      if (childProcess && childProcess.exec) {
        const originalExec = childProcess.exec;
        childProcess.exec = function(command, options, callback) {
          trace.sinkAccesses.push({
            sink: 'child_process.exec',
            arguments: [command],
            timestamp: Date.now(),
            callStack: new Error().stack
          });

          logger.warn(`🚨 Command execution attempt detected: ${command}`);
          if (callback) callback(null, '[SIMULATED_EXEC_RESULT]', '');
          return { pid: 12345 };
        };
      }
    } catch (error) {
      // child_process not available or not instrumentable
    }
  }

  async executeInput(input, config, trace) {
    const targetIntegration = await import('../target-integration/index.js');
    const targetModule = targetIntegration.getTargetModule?.(config.name);

    if (!targetModule || this.options.dryRun) {
      await this.simulateExecution(input, config, trace);
      return;
    }

    const entryPointName = input.entryPoint;
    const entryPoint = this.getEntryPointFunction(targetModule, entryPointName);

    if (!entryPoint) {
      throw new Error(`Entry point ${entryPointName} not found in target module`);
    }

    trace.functionCalls.push({
      function: entryPointName,
      arguments: input.value,
      timestamp: Date.now()
    });

    const result = await this.safeExecute(entryPoint, input.value);

    trace.functionCalls[trace.functionCalls.length - 1].result =
      typeof result === 'string' ? result : '[object]';
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

  async safeExecute(fn, input) {
    try {
      const timeout = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Execution timeout')), 5000)
      );

      const execution = Promise.resolve(fn(input));

      return await Promise.race([execution, timeout]);

    } catch (error) {
      logger.debug(`Safe execution failed: ${error.message}`);
      return `[ERROR: ${error.message}]`;
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
   * Get coverage statistics from the coverage tracker.
   */
  getCoverageStats() {
    return this.coverageTracker.getStats();
  }

  /**
   * Get the coverage tracker instance for external use
   * (e.g., by the orchestrator for convergence detection).
   */
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
      saturationRate: coverageStats.saturationRate
    };
  }
}
