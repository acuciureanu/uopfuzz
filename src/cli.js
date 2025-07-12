#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { Orchestrator } from './orchestrator/index.js';
import { logger } from './utils/logger.js';

const program = new Command();

program
  .name('uopfuzz')
  .description('UoPFuzz - Prototype pollution gadget hunting framework')
  .version('1.0.0');

program
  .option('-c, --config <path>', 'Target configuration file (YAML)')
  .option('-o, --output <dir>', 'Output directory for results', './results')
  .option('-t, --timeout <seconds>', 'Timeout per iteration in seconds', '60')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--dry-run', 'Simulate execution without running actual tests')
  .option('--max-iterations <num>', 'Maximum fuzzing iterations', '1000')
  .option('--parallel <num>', 'Number of parallel workers', '1');

program.action(async (options) => {
  try {
    if (options.verbose) {
      logger.level = 'debug';
    }

    logger.info(chalk.blue.bold('🔍 UoPFuzz - Prototype Pollution Gadget Hunter'));
    logger.info('Starting fuzzing session...');

    if (!options.config) {
      logger.error(chalk.red('❌ Configuration file is required. Use --config <path>'));
      process.exit(1);
    }

    const orchestrator = new Orchestrator({
      configPath: options.config,
      outputDir: options.output,
      timeout: parseInt(options.timeout),
      dryRun: options.dryRun || false,
      maxIterations: parseInt(options.maxIterations),
      parallelWorkers: parseInt(options.parallel),
      verbose: options.verbose || false
    });

    const results = await orchestrator.run();
    
    logger.info(chalk.green.bold('✅ Fuzzing session completed'));
    logger.info(`Results saved to: ${options.output}`);
    
    if (results.potentialChains.length > 0) {
      logger.warn(chalk.yellow.bold(`⚠️  Found ${results.potentialChains.length} potential gadget chains`));
    }

  } catch (error) {
    logger.error(chalk.red.bold('❌ Fatal error:'), error.message);
    if (options.verbose) {
      logger.error(error.stack);
    }
    process.exit(1);
  }
});

program.parse();