import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { Worker } from 'worker_threads';
import { logger } from '../utils/logger.js';
import { TargetIntegration } from '../target-integration/index.js';
import { InputGeneration } from '../input-generation/index.js';
import { Instrumentation } from '../instrumentation/index.js';
import { GadgetAnalysis } from '../gadget-analysis/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Science-Based Fuzzing Orchestrator
 *
 * Coordinates the fuzzing pipeline with:
 *
 * 1. Coverage-guided feedback loop: Instrumentation produces edge
 *    coverage data that feeds back into input generation power schedules
 *    (Böhme et al., CCS 2016).
 *
 * 2. Statistical convergence detection: Monitors coverage saturation
 *    rate to determine when fuzzing has reached diminishing returns,
 *    following the power law observation of edge discovery.
 *
 * 3. Science-based reporting: Results include CVSS scores, Bayesian
 *    confidence intervals, coverage entropy, and strategy effectiveness.
 */
export class Orchestrator {
  constructor(options) {
    this.config = null;
    this.options = options;
    this.targetIntegration = null;
    this.inputGeneration = null;
    this.instrumentation = null;
    this.gadgetAnalysis = null;
    this.results = {
      startTime: null,
      endTime: null,
      iterationsCompleted: 0,
      inputsGenerated: 0,
      potentialChains: [],
      errors: [],
      // Science-based metrics
      coverageStats: null,
      convergenceInfo: null,
      strategyEffectiveness: null
    };
  }

  async run() {
    try {
      this.results.startTime = new Date();

      logger.info('📋 Loading configuration...');
      await this.loadConfiguration();

      logger.info('🔧 Initializing components...');
      await this.initializeComponents();

      logger.info('🎯 Setting up target environment...');
      await this.setupTarget();

      logger.info('🚀 Starting fuzzing workflow...');
      await this.executeFuzzingWorkflow();

      logger.info('📊 Analyzing results...');
      await this.analyzeResults();

      logger.info('💾 Saving results...');
      await this.saveResults();

      this.results.endTime = new Date();
      return this.results;

    } catch (error) {
      this.results.errors.push({
        timestamp: new Date(),
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  async loadConfiguration() {
    try {
      const configPath = path.resolve(this.options.configPath);
      logger.debug(`Loading config from: ${configPath}`);

      const configContent = await fs.readFile(configPath, 'utf8');
      const YAML = await import('yaml');
      this.config = YAML.parse(configContent);

      logger.info(`Loaded target: ${this.config.name || 'Unknown'}`);

    } catch (error) {
      throw new Error(`Failed to load configuration: ${error.message}`);
    }
  }

  async initializeComponents() {
    this.targetIntegration = new TargetIntegration(this.options);
    this.inputGeneration = new InputGeneration(this.options);
    this.instrumentation = new Instrumentation(this.options);
    this.gadgetAnalysis = new GadgetAnalysis(this.options);

    // Enable real V8 coverage collection when not in dry-run mode
    if (!this.options.dryRun) {
      await this.instrumentation.enableV8Coverage();
    }

    logger.debug('All components initialized');
  }

  async setupTarget() {
    if (this.options.dryRun) {
      logger.info('🏃‍♂️ Dry run mode - skipping actual target setup');
      return;
    }

    await this.targetIntegration.setupTarget(this.config);
    logger.info(`Target ${this.config.name} setup completed`);
  }

  async executeFuzzingWorkflow() {
    const maxIterations = this.options.maxIterations;
    const parallelWorkers = this.options.parallelWorkers || 1;

    logger.info(`Starting ${maxIterations} fuzzing iterations with ${this.options.timeout}s timeout`);

    if (parallelWorkers > 1) {
      logger.info(`🚀 Using ${parallelWorkers} parallel workers for fuzzing`);
      await this.executeParallelFuzzing(maxIterations, parallelWorkers);
    } else {
      logger.info(`🔄 Using sequential execution (single worker)`);
      await this.executeSequentialFuzzing(maxIterations);
    }
  }

  /**
   * Sequential fuzzing with coverage feedback loop.
   *
   * Each iteration:
   * 1. Generate inputs (using power schedule from coverage feedback)
   * 2. Execute with tracing (records edge coverage + taint data)
   * 3. Feed coverage results back to input generator
   * 4. Check convergence (saturation rate)
   * 5. Analyze traces for gadget chains
   */
  async executeSequentialFuzzing(maxIterations) {
    const timeout = this.options.timeout * 1000;
    let consecutiveSaturatedIterations = 0;

    for (let iteration = 0; iteration < maxIterations; iteration++) {
      try {
        const iterationStart = Date.now();

        // Generate test inputs (coverage-guided from iteration 1+)
        const inputs = await this.inputGeneration.generateInputs(this.config, iteration);
        this.results.inputsGenerated += inputs.length;

        // Execute instrumented testing with coverage tracking
        const traces = await Promise.race([
          this.instrumentation.executeWithTracing(inputs, this.config),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Iteration timeout')), timeout)
          )
        ]);

        // Feed coverage results back to input generator (closes the loop)
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
        logger.debug(`Iteration ${iteration + 1}/${maxIterations} completed in ${iterationTime}ms`);

        // Convergence detection: check coverage saturation
        const saturation = this.instrumentation.getCoverageTracker().getSaturationRate();
        if (saturation > 0.98) {
          consecutiveSaturatedIterations++;
          if (consecutiveSaturatedIterations >= 10) {
            logger.info(`📈 Coverage saturated at ${(saturation * 100).toFixed(1)}% after ${iteration + 1} iterations - convergence reached`);
            this.results.convergenceInfo = {
              convergedAt: iteration + 1,
              saturationRate: saturation,
              reason: 'coverage_saturation'
            };
            break;
          }
        } else {
          consecutiveSaturatedIterations = 0;
        }

        if (iteration % 100 === 0) {
          const coverageStats = this.instrumentation.getCoverageStats();
          logger.info(`Progress: ${iteration + 1}/${maxIterations} iterations | ${chains.length} chains | ${coverageStats.coveredEdges} edges | saturation: ${(saturation * 100).toFixed(1)}%`);
        }

      } catch (error) {
        logger.warn(`Iteration ${iteration + 1} failed: ${error.message}`);
        this.results.errors.push({
          iteration: iteration + 1,
          error: error.message
        });
      }

      this.results.iterationsCompleted = iteration + 1;
    }
  }

  async executeParallelFuzzing(maxIterations, parallelWorkers) {
    const iterationsPerWorker = Math.ceil(maxIterations / parallelWorkers);
    const workers = [];
    const workerPromises = [];

    for (let workerId = 0; workerId < parallelWorkers; workerId++) {
      const startIteration = workerId * iterationsPerWorker;
      const endIteration = Math.min(startIteration + iterationsPerWorker, maxIterations);

      if (startIteration >= maxIterations) break;

      const workerData = {
        config: this.config,
        options: this.options,
        startIteration,
        endIteration,
        workerId
      };

      const workerFile = path.join(__dirname, 'worker.js');
      const worker = new Worker(workerFile, { workerData });

      workers.push({ worker, workerId, startIteration, endIteration });

      const workerPromise = new Promise((resolve, reject) => {
        const workerResults = {
          workerId,
          results: null,
          error: null
        };

        worker.on('message', (message) => {
          switch (message.type) {
            case 'progress':
              logger.debug(`Worker ${message.workerId}: ${message.message}`);
              if (message.progress) {
                const totalCompleted = workers.reduce((sum, w) => {
                  return sum + (w.completedIterations || 0);
                }, 0);

                if (totalCompleted % 50 === 0) {
                  logger.info(`Overall progress: ~${totalCompleted}/${maxIterations} iterations across ${parallelWorkers} workers`);
                }
              }
              break;

            case 'completed':
              workerResults.results = message.results;
              logger.info(`✅ Worker ${message.workerId} completed with ${message.results.iterationsCompleted} iterations`);
              resolve(workerResults);
              break;

            case 'error':
              workerResults.error = message.error;
              logger.error(`❌ Worker ${message.workerId} failed: ${message.error.message}`);
              reject(new Error(`Worker ${message.workerId} failed: ${message.error.message}`));
              break;
          }
        });

        worker.on('error', (error) => {
          workerResults.error = error;
          logger.error(`❌ Worker ${workerId} error: ${error.message}`);
          reject(error);
        });

        worker.on('exit', (code) => {
          if (code !== 0 && !workerResults.results && !workerResults.error) {
            const error = new Error(`Worker ${workerId} exited with code ${code}`);
            workerResults.error = error;
            reject(error);
          }
        });
      });

      workerPromises.push(workerPromise);

      logger.info(`Started worker ${workerId} for iterations ${startIteration} to ${endIteration - 1}`);
    }

    try {
      logger.info(`Waiting for ${workers.length} workers to complete...`);
      const workerResults = await Promise.allSettled(workerPromises);

      await this.aggregateWorkerResults(workerResults);

    } finally {
      await Promise.all(workers.map(async ({ worker }) => {
        try {
          await worker.terminate();
        } catch (error) {
          logger.debug(`Error terminating worker: ${error.message}`);
        }
      }));
    }
  }

  async aggregateWorkerResults(workerResults) {
    let totalIterationsCompleted = 0;
    let totalInputsGenerated = 0;
    let allPotentialChains = [];
    let allErrors = [];

    for (const result of workerResults) {
      if (result.status === 'fulfilled' && result.value.results) {
        const workerResult = result.value.results;
        totalIterationsCompleted += workerResult.iterationsCompleted;
        totalInputsGenerated += workerResult.inputsGenerated;
        allPotentialChains.push(...workerResult.potentialChains);
        allErrors.push(...workerResult.errors);

        logger.info(`Worker ${workerResult.workerId}: ${workerResult.iterationsCompleted} iterations, ${workerResult.inputsGenerated} inputs, ${workerResult.potentialChains.length} chains`);
      } else {
        allErrors.push({
          worker: result.value?.workerId || 'unknown',
          error: result.reason?.message || 'Worker failed'
        });
        logger.warn(`Worker failed: ${result.reason?.message}`);
      }
    }

    this.results.iterationsCompleted = totalIterationsCompleted;
    this.results.inputsGenerated = totalInputsGenerated;
    this.results.potentialChains = allPotentialChains;
    this.results.errors.push(...allErrors);

    logger.info(`🎯 Parallel execution completed: ${totalIterationsCompleted} total iterations, ${allPotentialChains.length} potential chains found`);
  }

  async analyzeResults() {
    // Deduplicate and rank potential chains
    const uniqueChains = this.gadgetAnalysis.deduplicateChains(this.results.potentialChains);
    const rankedChains = this.gadgetAnalysis.rankChains(uniqueChains);

    this.results.potentialChains = rankedChains;

    // Collect science-based metrics
    this.results.coverageStats = this.instrumentation.getCoverageStats();
    this.results.strategyEffectiveness = this.inputGeneration.getGenerationStats();

    // Stop V8 coverage collection
    await this.instrumentation.disableV8Coverage();

    logger.info(`Analysis complete: ${rankedChains.length} unique potential chains identified`);
  }

  async saveResults() {
    const outputDir = path.resolve(this.options.outputDir);
    await fs.mkdir(outputDir, { recursive: true });

    const resultsFile = path.join(outputDir, `results-${Date.now()}.json`);
    const reportFile = path.join(outputDir, `report-${Date.now()}.txt`);

    await fs.writeFile(resultsFile, JSON.stringify(this.results, null, 2));

    const report = this.generateReport();
    await fs.writeFile(reportFile, report);

    logger.info(`Results saved to ${outputDir}`);
  }

  /**
   * Generate a science-based analysis report.
   *
   * Includes CVSS-aligned risk scores, Bayesian confidence,
   * coverage metrics, and strategy effectiveness analysis.
   */
  generateReport() {
    const duration = this.results.endTime - this.results.startTime;
    const durationStr = `${Math.round(duration / 1000)}s`;

    let report = `UoPFuzz Analysis Report\n`;
    report += `======================\n\n`;
    report += `Target: ${this.config?.name || 'Unknown'}\n`;
    report += `Duration: ${durationStr}\n`;
    report += `Iterations: ${this.results.iterationsCompleted}\n`;
    report += `Inputs Generated: ${this.results.inputsGenerated}\n`;
    report += `Potential Chains: ${this.results.potentialChains.length}\n`;
    report += `Errors: ${this.results.errors.length}\n\n`;

    // Coverage Analysis
    if (this.results.coverageStats) {
      const cs = this.results.coverageStats;
      report += `Coverage Analysis\n`;
      report += `-----------------\n`;
      report += `  Edge Coverage (AFL-style bitmap):\n`;
      report += `    Edges Discovered: ${cs.coveredEdges}\n`;
      report += `    Bitmap Density: ${(cs.bitmapDensity * 100).toFixed(4)}%\n`;
      report += `    Saturation Rate: ${(cs.saturationRate * 100).toFixed(1)}%\n`;
      report += `    Inputs Processed: ${cs.totalInputsProcessed}\n`;
      if (cs.v8CoverageEnabled && cs.v8Metrics) {
        const v8 = cs.v8Metrics;
        report += `  V8 Precise Coverage (real engine data):\n`;
        report += `    Block Coverage: ${v8.coveredBlocks}/${v8.totalBlocks} (${v8.totalBlocks > 0 ? ((v8.coveredBlocks/v8.totalBlocks)*100).toFixed(1) : 0}%)\n`;
        report += `    Branch Coverage: ${v8.coveredBranches}/${v8.totalBranches} (${v8.totalBranches > 0 ? ((v8.coveredBranches/v8.totalBranches)*100).toFixed(1) : 0}%)\n`;
        report += `    Function Coverage: ${v8.coveredFunctions}/${v8.totalFunctions} (${v8.totalFunctions > 0 ? ((v8.coveredFunctions/v8.totalFunctions)*100).toFixed(1) : 0}%)\n`;
      } else {
        report += `  V8 Precise Coverage: disabled (dry-run mode)\n`;
      }
      report += `\n`;
    }

    // Convergence Info
    if (this.results.convergenceInfo) {
      const ci = this.results.convergenceInfo;
      report += `Convergence Detection\n`;
      report += `---------------------\n`;
      report += `  Converged at iteration: ${ci.convergedAt}\n`;
      report += `  Saturation rate: ${(ci.saturationRate * 100).toFixed(1)}%\n`;
      report += `  Reason: ${ci.reason}\n\n`;
    }

    // Strategy Effectiveness (Thompson Sampling results)
    if (this.results.strategyEffectiveness) {
      const se = this.results.strategyEffectiveness;
      report += `Mutation Strategy Effectiveness (Thompson Sampling)\n`;
      report += `---------------------------------------------------\n`;
      report += `  Seed Corpus Size: ${se.seedCount}\n`;
      report += `  Corpus Entropy: ${se.corpusEntropy.toFixed(3)} bits\n`;
      if (se.strategyEffectiveness) {
        for (const [strategy, stats] of Object.entries(se.strategyEffectiveness)) {
          report += `  ${strategy}: ${(stats.successRate * 100).toFixed(1)}% success (${stats.totalMutations} mutations)\n`;
        }
      }
      report += `\n`;
    }

    // Gadget Chains with CVSS and Bayesian confidence
    if (this.results.potentialChains.length > 0) {
      report += `Potential Gadget Chains (ranked by CVSS score)\n`;
      report += `----------------------------------------------\n`;
      this.results.potentialChains.forEach((chain, index) => {
        report += `${index + 1}. ${chain.description || 'Unknown chain'}\n`;
        report += `   CVSS Score: ${chain.riskLevel || 'N/A'}/10.0\n`;
        report += `   Confidence: ${((chain.confidence || 0) * 100).toFixed(1)}% (Bayesian posterior)\n`;
        if (chain.metadata?.cvssVector) {
          report += `   CVSS Vector: ${chain.metadata.cvssVector}\n`;
        }
        if (chain.metadata?.impactType) {
          report += `   Impact: ${chain.metadata.impactType}\n`;
        }
        report += `   Source: ${typeof chain.source === 'object' ? JSON.stringify(chain.source) : chain.source}\n`;
        report += `   Sink: ${typeof chain.sink === 'object' ? JSON.stringify(chain.sink) : chain.sink}\n\n`;
      });
    }

    report += `\nMethodology\n`;
    report += `===========\n`;
    report += `This analysis uses evidence-based techniques:\n`;
    report += `- Coverage guidance: AFL-style edge coverage bitmap (Böhme et al., CCS 2016)\n`;
    report += `- V8 precise coverage: Real block/branch coverage via Inspector protocol\n`;
    report += `- Taint tracking: ES6 Proxy deep property interception (Schwartz et al., IEEE S&P 2010)\n`;
    report += `- Risk scoring: CVSS v3.1 aligned base metrics (FIRST, 2019)\n`;
    report += `- Confidence: Bayesian inference with empirical priors (Bayes, 1763)\n`;
    report += `- Strategy selection: Thompson Sampling with Beta posteriors (Thompson, 1933)\n`;
    report += `- Diversity: Shannon entropy for corpus and coverage (Shannon, 1948)\n`;
    report += `- Gadget taxonomy: Silent Spring classification (Shcherbakov et al., USENIX 2023)\n`;
    report += `- UOP detection: Proxy-based undefined property access tracking\n`;

    return report;
  }
}
