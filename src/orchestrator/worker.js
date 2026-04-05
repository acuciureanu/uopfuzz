import { parentPort, workerData } from 'worker_threads';
import { TargetIntegration } from '../target-integration/index.js';
import { InputGeneration } from '../input-generation/index.js';
import { Instrumentation } from '../instrumentation/index.js';
import { GadgetAnalysis } from '../gadget-analysis/index.js';
import { logger } from '../utils/logger.js';

/**
 * Parallel Fuzzing Worker
 *
 * Each worker maintains its own coverage bitmap and seed corpus,
 * enabling independent exploration of the input space.
 *
 * Workers operate as independent Markov chains in the coverage-guided
 * fuzzing model (Böhme et al., CCS 2016), where each chain converges
 * to its own stationary distribution over the input space.
 */
class FuzzingWorker {
  constructor(data) {
    this.config = data.config;
    this.options = data.options;
    this.startIteration = data.startIteration;
    this.endIteration = data.endIteration;
    this.workerId = data.workerId;

    // Initialize components (each worker has independent state)
    this.targetIntegration = new TargetIntegration(this.options);
    this.inputGeneration = new InputGeneration(this.options);
    this.instrumentation = new Instrumentation(this.options);
    this.gadgetAnalysis = new GadgetAnalysis(this.options);

    // Worker-specific results
    this.results = {
      workerId: this.workerId,
      startTime: null,
      endTime: null,
      iterationsCompleted: 0,
      inputsGenerated: 0,
      potentialChains: [],
      errors: []
    };
  }

  async run() {
    try {
      this.results.startTime = new Date();

      parentPort.postMessage({
        type: 'progress',
        workerId: this.workerId,
        message: `Worker ${this.workerId} starting iterations ${this.startIteration} to ${this.endIteration - 1}`
      });

      await this.executeFuzzingIterations();

      this.results.endTime = new Date();

      parentPort.postMessage({
        type: 'completed',
        workerId: this.workerId,
        results: this.results
      });

    } catch (error) {
      parentPort.postMessage({
        type: 'error',
        workerId: this.workerId,
        error: {
          message: error.message,
          stack: error.stack
        }
      });
    }
  }

  async executeFuzzingIterations() {
    const timeout = this.options.timeout * 1000;
    const totalIterations = this.endIteration - this.startIteration;

    for (let iteration = this.startIteration; iteration < this.endIteration; iteration++) {
      try {
        const iterationStart = Date.now();

        // Generate test inputs
        const inputs = await this.inputGeneration.generateInputs(this.config, iteration);
        this.results.inputsGenerated += inputs.length;

        // Execute instrumented testing with coverage tracking
        const traces = await Promise.race([
          this.instrumentation.executeWithTracing(inputs, this.config),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Iteration timeout')), timeout)
          )
        ]);

        // Feed coverage results back to input generator
        for (const trace of traces) {
          if (trace.coverageResult && trace.input) {
            this.inputGeneration.integrateCoverageFeedback(
              trace.input, trace.coverageResult
            );
          }
        }

        // Analyze for gadget chains
        const chains = await this.gadgetAnalysis.analyzeTraces(traces, this.config);
        this.results.potentialChains.push(...chains);

        const iterationTime = Date.now() - iterationStart;

        // Send progress update every 10 iterations or on last iteration
        const localIteration = iteration - this.startIteration;
        if (localIteration % 10 === 0 || iteration === this.endIteration - 1) {
          const coverageStats = this.instrumentation.getCoverageStats();
          parentPort.postMessage({
            type: 'progress',
            workerId: this.workerId,
            message: `Worker ${this.workerId}: ${localIteration + 1}/${totalIterations} iterations (${chains.length} chains, ${coverageStats.coveredEdges} edges)`,
            progress: {
              completed: localIteration + 1,
              total: totalIterations,
              chainsFound: this.results.potentialChains.length
            }
          });
        }

      } catch (error) {
        this.results.errors.push({
          iteration: iteration,
          error: error.message
        });

        parentPort.postMessage({
          type: 'progress',
          workerId: this.workerId,
          message: `Worker ${this.workerId}: Iteration ${iteration} failed: ${error.message}`
        });
      }

      this.results.iterationsCompleted = (iteration - this.startIteration) + 1;
    }
  }
}

// Start the worker
if (workerData) {
  const worker = new FuzzingWorker(workerData);
  worker.run();
}
