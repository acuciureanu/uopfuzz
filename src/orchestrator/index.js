import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { logger } from '../utils/logger.js';
import { TargetIntegration } from '../target-integration/index.js';
import { InputGeneration } from '../input-generation/index.js';
import { Instrumentation } from '../instrumentation/index.js';
import { GadgetAnalysis } from '../gadget-analysis/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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
      errors: []
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
      
      // Load config directly since target integration might not be initialized yet
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
    const timeout = this.options.timeout * 1000; // Convert to milliseconds
    
    logger.info(`Starting ${maxIterations} fuzzing iterations with ${timeout/1000}s timeout`);
    
    for (let iteration = 0; iteration < maxIterations; iteration++) {
      try {
        const iterationStart = Date.now();
        
        // Generate test inputs
        const inputs = await this.inputGeneration.generateInputs(this.config, iteration);
        this.results.inputsGenerated += inputs.length;
        
        // Execute instrumented testing
        const traces = await Promise.race([
          this.instrumentation.executeWithTracing(inputs, this.config),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Iteration timeout')), timeout)
          )
        ]);
        
        // Analyze for gadget chains
        const chains = await this.gadgetAnalysis.analyzeTraces(traces, this.config);
        this.results.potentialChains.push(...chains);
        
        const iterationTime = Date.now() - iterationStart;
        logger.debug(`Iteration ${iteration + 1}/${maxIterations} completed in ${iterationTime}ms`);
        
        if (iteration % 100 === 0) {
          logger.info(`Progress: ${iteration + 1}/${maxIterations} iterations (${chains.length} chains found)`);
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

  async analyzeResults() {
    // Deduplicate and rank potential chains
    const uniqueChains = this.gadgetAnalysis.deduplicateChains(this.results.potentialChains);
    const rankedChains = this.gadgetAnalysis.rankChains(uniqueChains);
    
    this.results.potentialChains = rankedChains;
    
    logger.info(`Analysis complete: ${rankedChains.length} unique potential chains identified`);
  }

  async saveResults() {
    const outputDir = path.resolve(this.options.outputDir);
    await fs.mkdir(outputDir, { recursive: true });
    
    const resultsFile = path.join(outputDir, `results-${Date.now()}.json`);
    const reportFile = path.join(outputDir, `report-${Date.now()}.txt`);
    
    // Save detailed JSON results
    await fs.writeFile(resultsFile, JSON.stringify(this.results, null, 2));
    
    // Generate human-readable report
    const report = this.generateReport();
    await fs.writeFile(reportFile, report);
    
    logger.info(`Results saved to ${outputDir}`);
  }

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
    
    if (this.results.potentialChains.length > 0) {
      report += `Potential Gadget Chains:\n`;
      report += `------------------------\n`;
      this.results.potentialChains.forEach((chain, index) => {
        report += `${index + 1}. ${chain.description || 'Unknown chain'}\n`;
        report += `   Risk Level: ${chain.riskLevel || 'Unknown'}\n`;
        report += `   Source: ${chain.source || 'Unknown'}\n`;
        report += `   Sink: ${chain.sink || 'Unknown'}\n\n`;
      });
    }
    
    return report;
  }
}