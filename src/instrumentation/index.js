import { logger } from '../utils/logger.js';

export class Instrumentation {
  constructor(options) {
    this.options = options;
    this.traces = [];
    this.propertyAccesses = new Map();
    this.originalConsole = {};
    this.instrumentedFunctions = new Set();
  }

  async executeWithTracing(inputs, config) {
    try {
      logger.debug(`Executing ${inputs.length} inputs with tracing enabled`);
      
      const traces = [];
      
      for (const input of inputs) {
        if (this.options.dryRun) {
          // Simulate execution in dry-run mode
          const mockTrace = this.createMockTrace(input, config);
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
      // Set up property access tracking
      this.setupPropertyTracing(trace);
      
      // Set up prototype pollution detection
      this.setupPrototypeTracing(trace);
      
      // Set up sink monitoring
      this.setupSinkTracing(trace, config.sinks);
      
      // Execute the input
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
    }

    return trace;
  }

  setupPropertyTracing(trace) {
    // Hook into property access to detect undefined property reads
    const originalGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
    const originalHasOwnProperty = Object.prototype.hasOwnProperty;
    
    // Track property accesses on objects
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

    // Track hasOwnProperty calls
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

    // Store originals for cleanup
    this.originalMethods = {
      getOwnPropertyDescriptor: originalGetOwnPropertyDescriptor,
      hasOwnProperty: originalHasOwnProperty
    };
  }

  setupPrototypeTracing(trace) {
    // Monitor prototype chain modifications
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
    // Monitor dangerous function calls (sinks)
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
            
            // Don't actually execute dangerous functions
            logger.warn(`🚨 Potential sink access detected: ${sink}`);
            return '[SIMULATED_SINK_RESULT]';
          };
          
          this.instrumentedFunctions.add({ name: sink, original });
        }
      } catch (error) {
        logger.debug(`Failed to instrument sink ${sink}: ${error.message}`);
      }
    }

    // Monitor child_process if available
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
          return { pid: 12345 }; // Mock process
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
      // Simulate execution
      await this.simulateExecution(input, config, trace);
      return;
    }

    // Get the entry point function
    const entryPointName = input.entryPoint;
    const entryPoint = this.getEntryPointFunction(targetModule, entryPointName);
    
    if (!entryPoint) {
      throw new Error(`Entry point ${entryPointName} not found in target module`);
    }

    // Record function call
    trace.functionCalls.push({
      function: entryPointName,
      arguments: input.value,
      timestamp: Date.now()
    });

    // Execute the function with the input
    const result = await this.safeExecute(entryPoint, input.value);
    
    trace.functionCalls[trace.functionCalls.length - 1].result = 
      typeof result === 'string' ? result : '[object]';
  }

  getEntryPointFunction(targetModule, entryPointName) {
    // Handle nested entry points (e.g., "compile.render")
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
    
    // Direct export
    if (targetModule[entryPointName]) {
      return targetModule[entryPointName];
    }
    
    // Default export
    if (targetModule.default && targetModule.default[entryPointName]) {
      return targetModule.default[entryPointName];
    }
    
    return null;
  }

  async safeExecute(fn, input) {
    try {
      // Set a timeout for execution
      const timeout = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Execution timeout')), 5000)
      );
      
      const execution = Promise.resolve(fn(input));
      
      return await Promise.race([execution, timeout]);
      
    } catch (error) {
      // Log but don't throw - we want to continue tracing
      logger.debug(`Safe execution failed: ${error.message}`);
      return `[ERROR: ${error.message}]`;
    }
  }

  async simulateExecution(input, config, trace) {
    // Simulate realistic execution behavior for dry-run mode
    const delay = Math.random() * 100; // Random delay 0-100ms
    await new Promise(resolve => setTimeout(resolve, delay));
    
    // Simulate some property accesses
    for (let i = 0; i < Math.floor(Math.random() * 5); i++) {
      trace.propertyAccesses.push({
        type: 'simulated',
        object: 'MockObject',
        property: `prop${i}`,
        timestamp: Date.now(),
        result: undefined
      });
    }
    
    // Randomly simulate pollution detection
    if (input.metadata?.pollution && Math.random() < 0.3) {
      trace.prototypeChanges.push({
        type: 'simulated_pollution',
        target: 'Object',
        property: '__proto__',
        timestamp: Date.now()
      });
    }
    
    // Randomly simulate sink access
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
    // Restore original methods
    if (this.originalMethods) {
      Object.getOwnPropertyDescriptor = this.originalMethods.getOwnPropertyDescriptor;
      Object.prototype.hasOwnProperty = this.originalMethods.hasOwnProperty;
      Object.setPrototypeOf = this.originalMethods.setPrototypeOf;
      Object.defineProperty = this.originalMethods.defineProperty;
    }
    
    // Restore instrumented functions
    for (const instrumented of this.instrumentedFunctions) {
      try {
        global[instrumented.name] = instrumented.original;
      } catch (error) {
        logger.debug(`Failed to restore ${instrumented.name}: ${error.message}`);
      }
    }
    
    this.instrumentedFunctions.clear();
  }

  getTracingStats() {
    return {
      totalTraces: this.traces.length,
      instrumentedFunctions: this.instrumentedFunctions.size,
      propertyAccesses: this.propertyAccesses.size
    };
  }
}