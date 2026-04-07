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

      logger.info('Loading configuration...');
      await this.loadConfiguration();

      logger.info('Initializing components...');
      await this.initializeComponents();

      logger.info('Setting up target environment...');
      await this.setupTarget();

      logger.info('Starting fuzzing workflow...');
      await this.executeFuzzingWorkflow();

      logger.info('Analyzing results...');
      await this.analyzeResults();

      this.results.endTime = new Date();

      logger.info('Saving results...');
      await this.saveResults();

      return this.results;

    } catch (error) {
      this.results.endTime = this.results.endTime || new Date();
      this.results.errors.push({
        timestamp: new Date(),
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  async loadConfiguration() {
    if (this.options.targetPackage) {
      // Auto-discovery mode: config will be generated after install
      logger.info(`Target package: ${this.options.targetPackage} (auto-discovery mode)`);
      this.config = null; // Will be set in setupTarget
      return;
    }

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
    if (this.options.targetPackage) {
      // Auto-discovery: install, load, inspect, and generate config
      const { config, module: targetModule } = await this.targetIntegration.setupTargetFromPackage(
        this.options.targetPackage
      );
      this.config = config;
      if (!this.options.dryRun) {
        this.instrumentation.setTargetModule(targetModule);
      }
      logger.info(`Target ${config.name}@${config.version} auto-discovered and ready`);
      return;
    }

    if (this.options.dryRun) {
      logger.info('Dry run mode - skipping actual target setup');
      return;
    }

    const targetModule = await this.targetIntegration.setupTarget(this.config);
    this.instrumentation.setTargetModule(targetModule);
    logger.info(`Target ${this.config.name} setup completed`);
  }

  async executeFuzzingWorkflow() {
    const maxIterations = this.options.maxIterations;
    const parallelWorkers = this.options.parallelWorkers || 1;

    logger.info(`Starting ${maxIterations} fuzzing iterations with ${this.options.timeout}s timeout`);

    if (parallelWorkers > 1) {
      logger.info(`Using ${parallelWorkers} parallel workers for fuzzing`);
      await this.executeParallelFuzzing(maxIterations, parallelWorkers);
    } else {
      logger.info('Using sequential execution (single worker)');
      await this.executeSequentialFuzzing(maxIterations);
    }
  }

  /**
   * Sequential fuzzing with coverage feedback loop and differential oracle.
   *
   * Two-phase approach per iteration:
   *
   * Phase A — Coverage exploration (unchanged):
   * 1. Generate inputs with power-scheduled mutations
   * 2. Execute with tracing (V8 coverage + taint proxy)
   * 3. Feed coverage back to input generator
   *
   * Phase B — Differential gadget confirmation (NEW):
   * 4. Discover UOP properties from taint logs
   * 5. Generate pollution descriptors (property + payload pairs)
   * 6. Run differential oracle: clean vs polluted execution
   * 7. Confirmed gadgets are stored with causal evidence
   */
  async executeSequentialFuzzing(maxIterations) {
    const timeout = this.options.timeout * 1000;
    let consecutiveSaturatedIterations = 0;

    // Track confirmed chains separately from candidates
    if (!this.results.confirmedChains) {
      this.results.confirmedChains = [];
    }

    for (let iteration = 0; iteration < maxIterations; iteration++) {
      try {
        const iterationStart = Date.now();

        // === Phase A: Coverage exploration ===
        const inputs = await this.inputGeneration.generateInputs(this.config, iteration);
        this.results.inputsGenerated += inputs.length;

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

        // Standard chain analysis (timestamp-correlation candidates)
        const chains = await this.gadgetAnalysis.analyzeTraces(traces, this.config);
        this.results.potentialChains.push(...chains);

        // === Phase B: Differential gadget confirmation ===
        if (!this.options.dryRun) {
          await this.executeDifferentialPhase(inputs, iteration);
        }

        const iterationTime = Date.now() - iterationStart;
        logger.debug(`Iteration ${iteration + 1}/${maxIterations} completed in ${iterationTime}ms`);

        // Convergence detection — require minimum 20 iterations before early termination
        // This ensures UOP discovery (runs every 5 iterations) gets at least 4 chances,
        // and differential testing explores enough property×payload combinations.
        const saturation = this.instrumentation.getCoverageTracker().getSaturationRate();
        const MIN_ITERATIONS_BEFORE_CONVERGENCE = 20;
        if (saturation > 0.98 && iteration >= MIN_ITERATIONS_BEFORE_CONVERGENCE) {
          consecutiveSaturatedIterations++;
          if (consecutiveSaturatedIterations >= 10) {
            logger.info(`Coverage saturated at ${(saturation * 100).toFixed(1)}% after ${iteration + 1} iterations`);
            this.results.convergenceInfo = {
              convergedAt: iteration + 1,
              saturationRate: saturation,
              reason: 'coverage_saturation'
            };
            break;
          }
        } else if (saturation <= 0.98) {
          consecutiveSaturatedIterations = 0;
        }

        if (iteration % 10 === 0) {
          const coverageStats = this.instrumentation.getCoverageStats();
          const confirmedCount = this.results.confirmedChains.length;
          const uopCount = this.inputGeneration.discoveredUOPProperties.size;
          logger.info(
            `Progress: ${iteration + 1}/${maxIterations} | ` +
            `${confirmedCount} confirmed gadgets | ${uopCount} UOP properties | ` +
            `${coverageStats.coveredEdges} edges | ` +
            `saturation: ${(saturation * 100).toFixed(1)}%`
          );
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

  /**
   * Differential gadget confirmation phase.
   *
   * 1. UOP Discovery: Run a clean execution to find what properties the
   *    library reads as undefined. These are pollution candidates.
   * 2. Pollution Testing: For each candidate property × payload combination,
   *    run the differential oracle (clean vs polluted) and confirm gadgets.
   */
  async executeDifferentialPhase(inputs, iteration) {
    // UOP discovery: probe multiple diverse inputs to find property accesses.
    // Do this every 5 iterations, probing up to 3 different entry points.
    if (iteration % 5 === 0 && inputs.length > 0) {
      // Pick diverse sample inputs — different entry points and types
      const seenEntryPoints = new Set();
      const samples = [];
      for (const inp of inputs) {
        const key = `${inp.entryPoint}:${inp.type}`;
        if (!seenEntryPoints.has(key) && samples.length < 3) {
          seenEntryPoints.add(key);
          samples.push(inp);
        }
      }

      for (const sampleInput of samples) {
        try {
          const uopProps = await this.instrumentation.discoverUOPCandidates(sampleInput, this.config);
          const newCount = this.inputGeneration.integrateUOPDiscovery(uopProps);
          if (newCount > 0) {
            logger.info(`Discovered ${newCount} new UOP properties via ${sampleInput.entryPoint}: ${uopProps.slice(0, 5).join(', ')}${uopProps.length > 5 ? '...' : ''}`);
          }
        } catch (error) {
          logger.debug(`UOP discovery failed for ${sampleInput.entryPoint}: ${error.message}`);
        }
      }
    }

    // Differential testing: generate pollution descriptors and test them
    const descriptors = this.inputGeneration.generatePollutionDescriptors(
      this.config,
      Math.min(10, 3 + Math.floor(iteration / 10))
    );

    // Build test inputs for differential testing.
    // CRITICAL: don't rely on random input generation to include dangerous EPs.
    // Instead, look directly at config.entryPoints to find merge/extend functions
    // and create deterministic test inputs for them.
    const testInputs = [];
    const seenEP = new Set();

    const highPriorityEPs = new Set(['extend', 'merge', 'defaults', 'defaultsDeep', 'deepExtend', 'deepMerge']);
    const medPriorityEPs = new Set(['assign', 'set', 'mergeWith', 'setWith', 'mixin', 'clone', 'cloneDeep']);
    const getBaseName = (name) => name.includes('.') ? name.split('.').pop() : name;

    // Pass 1: Create test inputs directly from config.entryPoints for dangerous EPs.
    // This is deterministic — not dependent on random input generation.
    if (this.config.entryPoints) {
      for (const ep of this.config.entryPoints) {
        if (testInputs.length >= 5) break;
        const base = getBaseName(ep.name);
        if (!highPriorityEPs.has(base)) continue;
        if (seenEP.has(ep.name)) continue;
        seenEP.add(ep.name);
        testInputs.push({
          entryPoint: ep.name,
          type: 'object',
          value: {},
          metadata: { pollution: false, generation: 'differential_probe', energy: 1.0 }
        });
      }
    }

    // Pass 2: Medium-priority from config (only shallow names to avoid noise)
    if (this.config.entryPoints) {
      for (const ep of this.config.entryPoints) {
        if (testInputs.length >= 5) break;
        const base = getBaseName(ep.name);
        const depth = ep.name.split('.').length;
        if (!medPriorityEPs.has(base) || depth > 2) continue;
        if (seenEP.has(ep.name)) continue;
        seenEP.add(ep.name);
        testInputs.push({
          entryPoint: ep.name,
          type: 'object',
          value: {},
          metadata: { pollution: false, generation: 'differential_probe', energy: 1.0 }
        });
      }
    }

    // Pass 3: Fill with diverse entry points from generated inputs
    for (const inp of inputs) {
      if (testInputs.length >= 5) break;
      if (!seenEP.has(inp.entryPoint)) {
        seenEP.add(inp.entryPoint);
        testInputs.push(inp);
      }
    }
    if (testInputs.length === 0 && inputs.length > 0) testInputs.push(inputs[0]);
    if (testInputs.length === 0) return;

    // Track confirmed property+payloadType combos to avoid re-testing
    if (!this._confirmedSignatures) this._confirmedSignatures = new Set();

    for (const descriptor of descriptors) {
      // Skip combos already confirmed — no need to re-verify
      const sig = `${descriptor.property}:${descriptor.payloadType}`;
      if (this._confirmedSignatures.has(sig)) continue;

      // Try each test input until one confirms or all fail
      let confirmed = false;
      for (const testInput of testInputs) {
        try {
          // Mode 1: Standard differential (pre-pollute Object.prototype)
          const diffResult = await this.instrumentation.executeDifferentialTracing(
            testInput, this.config, descriptor
          );

          if (diffResult) {
            const confirmedChain = this.gadgetAnalysis.analyzeDifferentialResult(
              diffResult, testInput, this.config
            );

            if (confirmedChain) {
              this._confirmedSignatures.add(sig);
              this.results.confirmedChains.push(confirmedChain);
              this.inputGeneration.recordConfirmedGadget(descriptor.property, descriptor.value);
              this.inputGeneration.updatePropertyFeedback(descriptor.property, true);

              logger.warn(
                `CONFIRMED GADGET: Object.prototype.${descriptor.property} = ${String(descriptor.value).substring(0, 50)} ` +
                `-> ${confirmedChain.sink?.name || 'behavioral change'} ` +
                `(confidence: ${(confirmedChain.confidence * 100).toFixed(0)}%)`
              );
            }
          }

          // Mode 2: Merge-PP test (crafted input causes Object.prototype mutation)
          const mergeResult = await this.instrumentation.executeMergePPDifferential(
            testInput, this.config, descriptor
          );

          if (mergeResult) {
            const mergeChain = this.gadgetAnalysis.analyzeDifferentialResult(
              mergeResult, testInput, this.config
            );

            if (mergeChain) {
              this._confirmedSignatures.add(sig);
              this.results.confirmedChains.push(mergeChain);
              this.inputGeneration.recordConfirmedGadget(descriptor.property, descriptor.value);
              this.inputGeneration.updatePropertyFeedback(descriptor.property, true);

              logger.warn(
                `CONFIRMED PROTOTYPE POLLUTION: ${descriptor.property} via merge payload ` +
                `-> ${mergeChain.differential?.pollutedProperties?.join(', ') || descriptor.property} ` +
                `(confidence: ${(mergeChain.confidence * 100).toFixed(0)}%)`
              );
            }
          }

          // Mode 3: URL gadget test (URL query string → parser → target function)
          // This is the most important mode — always try it even if Mode 1 or 2 found something
          const urlResult = await this.instrumentation.executeURLGadgetDifferential(
            testInput, this.config, descriptor
          );

          if (urlResult) {
            const urlChain = this.gadgetAnalysis.analyzeDifferentialResult(
              urlResult, testInput, this.config
            );

            if (urlChain) {
              this._confirmedSignatures.add(sig);
              this.results.confirmedChains.push(urlChain);
              this.inputGeneration.recordConfirmedGadget(descriptor.property, descriptor.value);
              this.inputGeneration.updatePropertyFeedback(descriptor.property, true);

              const exploitURL = urlResult.diff?.details?.exploitURL || '';
              logger.warn(
                `CONFIRMED URL GADGET: ${descriptor.property} via ${testInput.entryPoint} ` +
                `-> ${urlChain.differential?.pollutedProperties?.join(', ') || descriptor.property} ` +
                `(confidence: ${(urlChain.confidence * 100).toFixed(0)}%)`
              );
              if (exploitURL) {
                logger.warn(`  Exploit: ${exploitURL}`);
              }
              confirmed = true;
              break;
            }
          }
        } catch (error) {
          logger.debug(`Differential test failed for ${descriptor.property} via ${testInput.entryPoint}: ${error.message}`);
        }
      }
      if (!confirmed) {
        this.inputGeneration.updatePropertyFeedback(descriptor.property, false);
      }
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
              logger.info(`Worker ${message.workerId} completed with ${message.results.iterationsCompleted} iterations`);
              resolve(workerResults);
              break;

            case 'error':
              workerResults.error = message.error;
              logger.error(`Worker ${message.workerId} failed: ${message.error.message}`);
              reject(new Error(`Worker ${message.workerId} failed: ${message.error.message}`));
              break;
          }
        });

        worker.on('error', (error) => {
          workerResults.error = error;
          logger.error(`Worker ${workerId} error: ${error.message}`);
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

    logger.info(`Parallel execution completed: ${totalIterationsCompleted} total iterations, ${allPotentialChains.length} potential chains found`);
  }

  async analyzeResults() {
    // Deduplicate and rank potential chains (timestamp-correlation candidates)
    const uniqueChains = this.gadgetAnalysis.deduplicateChains(this.results.potentialChains);
    const rankedChains = this.gadgetAnalysis.rankChains(uniqueChains);
    this.results.potentialChains = rankedChains;

    // Confirmed chains from differential oracle (causal evidence)
    if (!this.results.confirmedChains) this.results.confirmedChains = [];

    // Collect metrics
    this.results.coverageStats = this.instrumentation.getCoverageStats();
    this.results.strategyEffectiveness = this.inputGeneration.getGenerationStats();

    // Stop V8 coverage collection
    await this.instrumentation.disableV8Coverage();

    const confirmed = this.results.confirmedChains.length;
    const candidates = rankedChains.length;
    logger.info(`Analysis complete: ${confirmed} confirmed gadgets, ${candidates} unconfirmed candidates`);
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
    const end = this.results.endTime || new Date();
    const start = this.results.startTime || new Date();
    const duration = end - start;
    const durationStr = `${Math.round(duration / 1000)}s`;
    const confirmedChains = this.results.confirmedChains || [];

    let report = '';
    report += '================================================================================\n';
    report += '                              UoPFuzz Report\n';
    report += '================================================================================\n\n';
    report += `Target:    ${this.config?.name || 'Unknown'}@${this.config?.version || '?'}\n`;
    report += `Confirmed: ${confirmedChains.length} gadget${confirmedChains.length !== 1 ? 's' : ''} | Unconfirmed: ${this.results.potentialChains?.length || 0} | Errors: ${this.results.errors?.length || 0}\n`;
    report += `Time:     ${durationStr} | Iterations: ${this.results.iterationsCompleted} | Inputs: ${this.results.inputsGenerated}\n`;
    report += '\n';

    if (confirmedChains.length > 0) {
      for (const [index, chain] of confirmedChains.entries()) {
        const poc = chain.poc;
        const isURL = poc?.type === 'url_gadget';

        report += '--------------------------------------------------------------------------------\n';
        report += `GADGET #${index + 1}  [${chain.riskLevel}/10 RISK]  ${(chain.confidence * 100).toFixed(0)}% confidence\n`;
        report += '--------------------------------------------------------------------------------\n';
        report += `Library:     ${this.config?.name}@${this.config?.version}\n`;
        report += `Function:    ${chain.input?.entryPoint}\n`;
        report += `Property:    Object.prototype.${chain.source?.property} = ${chain.source?.payload}\n`;
        if (chain.metadata?.cvssVector) {
          report += `CVSS:       ${chain.metadata.cvssVector}\n`;
        }
        report += '\n';

        if (isURL && poc?.attackerInput?.url) {
          report += 'ATTACKER INPUT\n';
          report += '==============\n';
          report += `  URL:  ${poc.attackerInput.url}\n\n`;
        }

        report += 'PROOF OF CONCEPT\n';
        report += '=================\n';
        if (poc?.exploit?.code) {
          report += '\n' + poc.exploit.code + '\n';
        }

        if (isURL && poc?.vulnerablePattern?.description) {
          report += '\nATTACK CHAIN\n';
          report += '============\n';
          report += '  ' + poc.vulnerablePattern.description + '\n';
        }

        if (chain.differential?.pollutedProperties?.length > 0) {
          report += '\nPOLLUTED PROPERTIES: ' + chain.differential.pollutedProperties.join(', ') + '\n';
        }

        report += '\n';
      }
      report += '================================================================================\n';
      report += `Generated by UoPFuzz | ${new Date().toISOString()}\n`;
    } else {
      report += 'No confirmed gadgets found.\n';
    }

    // UOP Property Discovery
    if (this.results.strategyEffectiveness?.discoveredUOPProperties?.length > 0) {
      const props = this.results.strategyEffectiveness.discoveredUOPProperties;
      report += `UOP Property Discovery\n`;
      report += `----------------------\n`;
      report += `Properties the target reads as undefined (pollution candidates):\n`;
      for (const prop of props.slice(0, 30)) {
        report += `  - ${prop}\n`;
      }
      if (props.length > 30) {
        report += `  ... and ${props.length - 30} more\n`;
      }
      report += `\n`;
    }

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

    // Strategy Effectiveness
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

    // Unconfirmed candidates (timestamp-correlation based)
    if (this.results.potentialChains.length > 0) {
      report += `Unconfirmed Candidates (timestamp correlation)\n`;
      report += `----------------------------------------------\n`;
      this.results.potentialChains.slice(0, 20).forEach((chain, index) => {
        report += `${index + 1}. ${chain.description || 'Unknown chain'}\n`;
        report += `   CVSS Score: ${chain.riskLevel || 'N/A'}/10.0\n`;
        report += `   Confidence: ${((chain.confidence || 0) * 100).toFixed(1)}%\n`;
        report += `   Source: ${typeof chain.source === 'object' ? JSON.stringify(chain.source) : chain.source}\n`;
        report += `   Sink: ${typeof chain.sink === 'object' ? JSON.stringify(chain.sink) : chain.sink}\n\n`;
      });
      if (this.results.potentialChains.length > 20) {
        report += `... and ${this.results.potentialChains.length - 20} more candidates\n\n`;
      }
    }

    report += `\nMethodology\n`;
    report += `===========\n`;
    report += `This analysis uses evidence-based techniques:\n`;
    report += `- Differential oracle: Clean vs polluted execution comparison (causal confirmation)\n`;
    report += `- UOP discovery: Proxy-based detection of undefined property reads (attack surface mapping)\n`;
    report += `- Real Object.prototype pollution: Actual global pollution with cleanup\n`;
    report += `- Multi-step harnesses: Compile-then-render sequences for template engines\n`;
    report += `- Coverage guidance: AFL-style edge coverage bitmap (Böhme et al., CCS 2016)\n`;
    report += `- V8 precise coverage: Real block/branch coverage via Inspector protocol\n`;
    report += `- Taint tracking: ES6 Proxy deep property interception (Schwartz et al., IEEE S&P 2010)\n`;
    report += `- Risk scoring: CVSS v3.1 aligned base metrics (FIRST, 2019)\n`;
    report += `- Strategy selection: Thompson Sampling with Beta posteriors (Thompson, 1933)\n`;
    report += `- Gadget taxonomy: Silent Spring classification (Shcherbakov et al., USENIX 2023)\n`;

    return report;
  }
}
